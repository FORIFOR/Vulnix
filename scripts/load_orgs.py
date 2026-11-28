"""Long-running load test: many organizations on one control plane (Linux).

    VULNIX_NO_ENV_LOCAL=1 python3 scripts/load_orgs.py --orgs 500 --minutes 30 --out report.json

Starts the real HTTP control plane (aegis.server.make_handler with tenancy) on a fresh
temporary data directory, signs up one account per organization over HTTP (each sign-up
creates its organization, as in production; only the platform sign-up rate limit is raised
for this in-process server), then drives the main API operations from several client
threads for the given time:

  * reads of the account's own organization (assets, drafts, intelligence)
  * writes (adding a site; creating and revoking an invite)
  * sign-out / sign-in cycles
  * cross-tenant attempts: every one must be refused (403/404); any other answer is a
    tenant-isolation violation

Every interval it records, from /proc: open descriptors, sockets among them, RSS, threads,
loaded organization services, in-flight diagnosis work, and the data directory's size on
disk. The verdict fails on any isolation violation, any unexpected error, descriptor growth
after warm-up beyond --max-fd-growth, or RSS growth in the second half beyond
--max-rss-growth-mb. Nothing leaves the machine: the server listens on 127.0.0.1 only.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("VULNIX_NO_ENV_LOCAL", "1")

from aegis import server as srvmod  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.operators import OperatorStore, hash_password  # noqa: E402
from aegis.server import ControlPlaneHTTPServer, make_handler  # noqa: E402
from aegis.tenancy import OrgStore, TenantRegistry, default_members_from  # noqa: E402

LAB_PORT = 18197


def proc_metrics(data_dir: Path, reg) -> dict:
    fds = os.listdir("/proc/self/fd")
    sockets = 0
    for f in fds:
        try:
            if os.readlink(f"/proc/self/fd/{f}").startswith("socket:"):
                sockets += 1
        except OSError:
            pass
    rss = 0
    for line in open("/proc/self/status"):
        if line.startswith("VmRSS:"):
            rss = int(line.split()[1]) // 1024
    size = 0
    for p in data_dir.rglob("*"):
        try:
            if p.is_file():
                size += p.stat().st_size
        except OSError:
            pass
    services = list(getattr(reg, "_services", {}).values())
    inflight = sum(int(getattr(s, "_inflight", 0) or 0) for s in services)
    return {"fds": len(fds), "sockets": sockets, "rss_mb": rss, "threads": threading.active_count(),
            "loaded_orgs": len(services), "inflight": inflight, "data_mb": round(size / 1e6, 2)}


class Client:
    def __init__(self, root: str):
        self.root = root

    def req(self, who, path, body=None, org=None):
        h = {"Content-Type": "application/json"}
        if body is not None:
            h["X-Aegis-Request"] = "1"
        if who and who.get("cookie"):
            h["Cookie"] = who["cookie"]
        if org:
            h["X-Vulnix-Org"] = org
        r = urllib.request.Request(self.root + path, json.dumps(body).encode() if body is not None else None, h)
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                sc = resp.headers.get("Set-Cookie")
                if sc and who is not None:
                    who["cookie"] = sc.split(";")[0]
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            with e:
                try:
                    return e.code, json.load(e)
                except ValueError:
                    return e.code, {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--orgs", type=int, default=500, help="organizations including the default one")
    ap.add_argument("--minutes", type=float, default=30)
    ap.add_argument("--clients", type=int, default=8)
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--max-fd-growth", type=int, default=10)
    ap.add_argument("--max-rss-growth-mb", type=int, default=64)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    if not sys.platform.startswith("linux"):
        print("Linux only (/proc)", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="vulnix-load-"))
    seed = tmp / "operators.json"
    seed.write_text(json.dumps({"operators": [
        {"name": "padmin", "roles": ["operator", "approver", "admin"], "password_hash": hash_password("padmin-pw-1")}]}))
    with patch.dict(os.environ, {"VULNIX_NO_ENV_LOCAL": "1"}, clear=True):
        svc = AssessmentService(tmp, LAB_PORT, verify_seconds=30)
    ops = OperatorStore(seed)
    store = OrgStore(tmp / "orgs.json", bootstrap_members=lambda: default_members_from(ops), max_orgs=a.orgs)

    def factory(path):
        with patch.dict(os.environ, {"VULNIX_NO_ENV_LOCAL": "1"}, clear=True):
            return AssessmentService(path, LAB_PORT, verify_seconds=30)
    reg = TenantRegistry(store, svc, factory, tmp)
    # the test harness signs up hundreds of accounts: the platform-wide sign-up limit of the
    # in-process server only (accounts, organizations and audit are created as in production)
    srvmod.SIGNUPS_PER_MINUTE = 100000
    srvmod.SIGNUP_ATTEMPTS_PER_MINUTE = 100000
    http = ControlPlaneHTTPServer(("127.0.0.1", 0), make_handler(svc, ops, tenancy=reg, public_signup=True))
    http.daemon_threads = True
    threading.Thread(target=http.serve_forever, daemon=True).start()
    c = Client(f"http://127.0.0.1:{http.server_port}/api")
    report = {"orgs": a.orgs, "minutes": a.minutes, "clients": a.clients, "samples": [], "counts": {},
              "isolation_violations": [], "unexpected": []}
    counts = report["counts"]
    lock = threading.Lock()

    def count(k, n=1):
        with lock:
            counts[k] = counts.get(k, 0) + n

    t_setup = time.monotonic()
    users = []
    for i in range(a.orgs - 1):
        name = f"load{i:04d}"
        who = {"name": name, "pw": f"{name}-Passw0rd!"}
        code, body = c.req(who, "/auth/register", {"name": name, "password": who["pw"]})
        if code != 200 or not body.get("orgs"):
            report["unexpected"].append({"op": "signup", "code": code, "i": i})
            break
        who["org"] = body["orgs"][0]["id"]
        users.append(who)
    report["setup_s"] = round(time.monotonic() - t_setup, 1)
    report["orgs_created"] = len(users)
    report["samples"].append({"t": 0, "phase": "after_setup", **proc_metrics(tmp, reg)})

    stop = threading.Event()

    def worker(seed_):
        rnd = random.Random(seed_)
        while not stop.is_set():
            u = rnd.choice(users)
            op = rnd.random()
            try:
                if op < 0.45:
                    path = rnd.choice(("/assets", "/assets/a2b-drafts", "/assets/intelligence"))
                    code, _ = c.req(u, path, org=u["org"])
                    count("read")
                    if code == 401:                      # signed out by a cycle: sign in again
                        code, _ = c.req(u, "/auth/login", {"name": u["name"], "password": u["pw"]})
                        count("relogin")
                    elif code != 200:
                        report["unexpected"].append({"op": path, "code": code})
                elif op < 0.60:
                    other = rnd.choice(users)
                    if other is u:
                        continue
                    path = rnd.choice(("/assets", "/assets/a2b-drafts", "/assets/intelligence", "/orgs/members"))
                    code, body = c.req(u, path, org=other["org"])
                    count("cross_tenant")
                    if code not in (401, 403, 404):
                        report["isolation_violations"].append({"path": path, "code": code})
                elif op < 0.70:
                    code, _ = c.req(u, "/assets", {"name": f"s{rnd.randrange(10**6)}.lab.test",
                                                    "kind": "Webアプリケーション", "environment": "検証環境",
                                                    "authorization_ref": "LOAD"}, u["org"])
                    count("write_asset")
                    if code not in (200, 401, 409, 429):
                        report["unexpected"].append({"op": "add_asset", "code": code})
                elif op < 0.78:
                    code, body = c.req(u, "/orgs/invites", {"roles": ["viewer"]}, u["org"])
                    count("invite")
                    iid = (body or {}).get("id")
                    if code == 200 and iid:
                        rc, _ = c.req(u, "/orgs/invites/revoke", {"id": iid}, u["org"])
                        if rc not in (200, 401):
                            report["unexpected"].append({"op": "revoke_invite", "code": rc})
                    elif code not in (200, 401, 429):
                        report["unexpected"].append({"op": "invite", "code": code})
                else:
                    c.req(u, "/auth/logout", {})
                    code, _ = c.req(u, "/auth/login", {"name": u["name"], "password": u["pw"]})
                    count("login_cycle")
                    if code not in (200, 429):
                        report["unexpected"].append({"op": "login", "code": code})
            except Exception as e:  # noqa: BLE001
                report["unexpected"].append({"op": "exception", "error": f"{type(e).__name__}: {str(e)[:120]}"})

    threads = [threading.Thread(target=worker, args=(k,), daemon=True) for k in range(a.clients)]
    t0 = time.monotonic()
    for t in threads:
        t.start()
    end = t0 + a.minutes * 60
    while time.monotonic() < end:
        time.sleep(min(a.interval, max(0.0, end - time.monotonic())))
        report["samples"].append({"t": round(time.monotonic() - t0), **proc_metrics(tmp, reg), **{
            k: v for k, v in counts.items()}})
        print(json.dumps(report["samples"][-1]), flush=True)
    stop.set()
    for t in threads:
        t.join(70)
    report["samples"].append({"t": round(time.monotonic() - t0), "phase": "end", **proc_metrics(tmp, reg)})

    # verdict: after warm-up (the first sample past 10% of the run), descriptors flat and
    # memory not still climbing in the second half
    run = [s for s in report["samples"] if "phase" not in s]
    warm = run[max(1, len(run) // 10):] or run
    half = run[len(run) // 2:] or run
    fd_growth = max(s["fds"] for s in warm) - warm[0]["fds"] if warm else 0
    rss_growth = (half[-1]["rss_mb"] - half[0]["rss_mb"]) if half else 0
    report["verdict"] = {
        "orgs_created": report["orgs_created"] == a.orgs - 1,
        "no_isolation_violation": not report["isolation_violations"],
        "no_unexpected_error": not report["unexpected"],
        "fd_growth_after_warmup": fd_growth, "fd_flat": fd_growth <= a.max_fd_growth,
        "rss_growth_second_half_mb": rss_growth, "rss_flat": rss_growth <= a.max_rss_growth_mb,
    }
    report["verdict"]["passed"] = all(v for k, v in report["verdict"].items() if isinstance(v, bool))
    report["unexpected"] = report["unexpected"][:50]
    report["isolation_violations"] = report["isolation_violations"][:50]
    Path(a.out).write_text(json.dumps(report, indent=1, ensure_ascii=False))
    print(json.dumps(report["verdict"]))
    http.shutdown()
    http.server_close()
    reg.close_all()
    svc.close()
    shutil.rmtree(tmp, ignore_errors=True)
    return 0 if report["verdict"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
