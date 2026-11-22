"""Local rehearsal of docs/REAL_SITE_L1_RUNBOOK.md (the first limited real-site L1).

Runs the runbook's steps against a LOCAL mock "real site" only:
  * the site's name is a reserved `.test` name that the service's injected resolver
    maps to 127.0.0.1 (the approach of tests/test_real_service.py);
  * the ownership proof is a DNS TXT answer from an injected lookup (no DNS query);
  * the mock HTTP server on 127.0.0.1 records every request it receives.

Nothing here contacts a real site, a real DNS server, an external LLM or a paid API.
The script refuses to run (exit 2) when any target name is not a `.test` name or maps
to an address that is not loopback, and every in-process DNS lookup or connection to a
non-loopback address is refused while it runs.

Asserted (each step is one entry of the JSON report):
  1. no traffic, no resolution and no scope before the ownership proof;
  2. the L1 run sends exactly the requests listed in the runbook (parsed from the
     runbook's `rehearsal:l1-requests` block) and nothing else;
  3. no L2 / lab attack probe (reproduction_probe idor / cve_2021_41773 / sqli) reaches
     the site, and the L2 / re-check operations are refused;
  4. an emergency stop (after the run, and during an in-flight request) halts the run,
     and further requests are refused;
  5. withdrawing the scope (deleting the site) stops resolution and further requests;
  6. the audit hash chain verifies (and a tampered copy does not), with a local
     anchor helper running in-process (same OS user: "same_user", never "protected").

Usage:
  VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.rehearse_real_l1 [--out DIR]
Exit code: 0 all steps passed, 1 a step failed, 2 refused to run.
"""
from __future__ import annotations

import argparse
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "REAL_SITE_L1_RUNBOOK.md"
HOST = "rehearsal-l1.vulnix.test"
DEFAULT_TARGETS = {HOST: ["127.0.0.1"]}
# headers the L1 worker sends (aegis/workers/http_probe.py:336-340, the gateway passes no --origin)
EXPECTED_UA = "aegis-probe/0.1"
EXPECTED_ORIGIN = "https://untrusted-origin.example"
APPROVER = "rehearsal-approver"
RUN_TIMEOUT_S = 60.0

# Same settings as the runbook's preconditions, fixed BEFORE aegis is imported.
_ENV = {
    "VULNIX_NO_ENV_LOCAL": "1",
    "VULNIX_REAL_SERVICE_DIAGNOSIS": "l1",
    "AEGIS_SEPARATE_L2_APPROVER": "1",
    "VULNIX_EXTERNAL_PROPOSALS": "0",
    "VULNIX_REAL_SITE_LOCAL_ARTEX": "0",
    "VULNIX_REAL_SITE_INITIAL_ARTEX": "0",
    "VULNIX_REAL_SITE_SAFE_AI": "0",
    "VULNIX_ARTEX_LLM_PLANS_PER_HOUR": "0",
}
# anything that could make this process talk to a model, a planner, Google or an anchor
_DROP_PREFIXES = ("VULNIX_ABLITERATION", "AEGIS_MODEL", "VULNIX_MODEL", "VULNIX_ARTEX_",
                  "AEGIS_ARTEX", "VULNIX_GOOGLE_", "VULNIX_AUDIT_ANCHOR_", "VULNIX_TEST_CA_FILE")


class RefuseToRun(Exception):
    """A target is not a loopback-only stand-in: nothing is started."""


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(str(addr).split("%")[0]).is_loopback
    except ValueError:
        return False


def preflight_targets(targets: dict[str, list[str]]) -> None:
    if not targets:
        raise RefuseToRun("no target")
    for host, addrs in targets.items():
        h = str(host).rstrip(".").lower()
        if not h.endswith(".test"):
            raise RefuseToRun(f"{host!r} is not a reserved .test name")
        if not addrs:
            raise RefuseToRun(f"{host!r} has no address")
        bad = [a for a in addrs if not _is_loopback(a)]
        if bad:
            raise RefuseToRun(f"{host!r} resolves to non-loopback address(es) {bad}")


def loopback_resolver(targets: dict[str, list[str]]):
    """The service's injected resolver. Re-checks every answer: a non-loopback address is
    never returned (the call raises; inside a run that fails the run, nothing is sent).
    `resolve.calls` counts the lookups."""
    table = {h.rstrip(".").lower(): list(a) for h, a in targets.items()}

    def resolve(host: str) -> list[str]:
        resolve.calls += 1
        addrs = table.get((host or "").rstrip(".").lower(), [])
        for a in addrs:
            if not _is_loopback(a):
                raise RefuseToRun(f"{host!r} resolved to non-loopback {a}")
        return list(addrs)
    resolve.calls = 0
    return resolve


@contextmanager
def no_outside_network():
    """In this process: no DNS lookup of any name but loopback ones, and no TCP/UDP
    connection to a non-loopback address. (Workers are separate processes; they
    connect only to the gateway-pinned address, which comes from the resolver above.)"""
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    loopback_names = {"localhost", "127.0.0.1", "::1", None, ""}

    def guarded_getaddrinfo(host, *a, **kw):
        h = host.decode() if isinstance(host, bytes) else host
        if h not in loopback_names and not _is_loopback(h or ""):
            raise OSError(f"rehearsal: DNS lookup of {h!r} refused")
        return real_getaddrinfo(host, *a, **kw)

    def _check(sock, address):
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            if not _is_loopback(address[0]):
                raise OSError(f"rehearsal: connection to {address[0]!r} refused")

    def guarded_connect(self, address):
        _check(self, address)
        return real_connect(self, address)

    def guarded_connect_ex(self, address):
        _check(self, address)
        return real_connect_ex(self, address)

    from aegis import ownership

    def no_dns(*_a, **_kw):
        raise OSError("rehearsal: real DNS TXT lookup refused")

    def no_fetch(*_a, **_kw):
        raise OSError("rehearsal: real proof-file fetch refused")
    saved = (ownership.default_dns_txt_lookup, ownership.default_well_known_fetcher,
             ownership.fetch_proof_file_pinned)
    socket.getaddrinfo = guarded_getaddrinfo
    socket.socket.connect = guarded_connect
    socket.socket.connect_ex = guarded_connect_ex
    ownership.default_dns_txt_lookup = no_dns
    ownership.default_well_known_fetcher = no_fetch
    ownership.fetch_proof_file_pinned = no_fetch
    try:
        yield
    finally:
        socket.getaddrinfo = real_getaddrinfo
        socket.socket.connect = real_connect
        socket.socket.connect_ex = real_connect_ex
        (ownership.default_dns_txt_lookup, ownership.default_well_known_fetcher,
         ownership.fetch_proof_file_pinned) = saved


def runbook_l1_requests(path: Path | None = None) -> list[tuple[str, str]]:
    """The `METHOD PATH` lines of the runbook's machine-readable L1 request list."""
    text = (path or RUNBOOK).read_text(encoding="utf-8")
    m = re.search(r"<!-- rehearsal:l1-requests:begin -->(.*?)<!-- rehearsal:l1-requests:end -->", text, re.S)
    if not m:
        raise ValueError("runbook has no rehearsal:l1-requests block")
    out = []
    for line in m.group(1).splitlines():
        line = line.strip()
        if re.fullmatch(r"(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) \S+", line):
            method, p = line.split(" ", 1)
            out.append((method, p))
    if not out:
        raise ValueError("runbook L1 request list is empty")
    return out


class MockSite(http.server.ThreadingHTTPServer):
    """The stand-in "real site". Records every connection and every request."""
    daemon_threads = True

    def __init__(self, *, hang_root: bool = False):
        super().__init__(("127.0.0.1", 0), _MockHandler)
        self.hang_root = hang_root
        self.release = threading.Event()
        self.got_request = threading.Event()
        self.requests: list[dict] = []
        self.connections = 0
        self._rec_lock = threading.Lock()

    def process_request(self, request, client_address):
        with self._rec_lock:
            self.connections += 1
        return super().process_request(request, client_address)

    def record(self, handler) -> None:
        h = handler.headers
        with self._rec_lock:
            self.requests.append({
                "method": handler.command, "path": handler.path,
                "user_agent": h.get("User-Agent"), "origin": h.get("Origin"),
                "has_authorization": h.get("Authorization") is not None,
                "has_cookie": h.get("Cookie") is not None,
                "content_length": int(h.get("Content-Length") or 0),
            })
        self.got_request.set()

    def snapshot(self) -> list[dict]:
        with self._rec_lock:
            return [dict(r) for r in self.requests]

    def method_paths(self) -> list[tuple[str, str]]:
        return [(r["method"], r["path"]) for r in self.snapshot()]


class _MockHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def _answer(self):
        srv: MockSite = self.server
        srv.record(self)
        if srv.hang_root and self.path == "/":
            srv.release.wait(30)
        body = json.dumps({"ok": True, "site": "rehearsal"}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Server", "nginx")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Set-Cookie", "sid=rehearsal-cookie-value; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        except OSError:
            pass          # the worker was killed by an emergency stop

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _answer


class Rehearsal:
    def __init__(self, out_dir: Path | None, targets: dict[str, list[str]], runbook: Path | None = None):
        self.out_dir = out_dir
        self.targets = targets
        self.steps: list[dict] = []
        self.expected = runbook_l1_requests(runbook)
        self._tmp = tempfile.TemporaryDirectory(prefix="vulnix-rehearsal-")
        self.tmp = Path(self._tmp.name)
        # Unix socket paths are limited to ~104 bytes on macOS
        self._sock_tmp = tempfile.TemporaryDirectory(
            prefix="vra-", dir=tempfile.gettempdir() if len(tempfile.gettempdir()) < 60 else "/tmp")
        self._cleanup: list = []

    # ---- bookkeeping -------------------------------------------------------
    def step(self, name: str, ok: bool, **detail) -> bool:
        self.steps.append({"step": name, "ok": bool(ok), **detail})
        return bool(ok)

    @staticmethod
    def _raises(fn, *exc) -> str | None:
        try:
            fn()
        except exc or (Exception,) as e:  # noqa: B030
            return f"{type(e).__name__}: {str(e)[:160]}"
        return None

    # ---- fixtures ----------------------------------------------------------
    def start_anchor(self):
        from aegis.audit_anchor import AnchorClient, AnchorServer, AnchorStore
        store_dir = self.tmp / "anchor"
        store_dir.mkdir()
        sock = Path(self._sock_tmp.name) / "a.sock"
        store = AnchorStore(store_dir)
        srv = AnchorServer(store, sock, allow_sources=("rehearsal",))
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        self._cleanup.append(lambda: (srv.shutdown(), srv.server_close()))
        return store, AnchorClient(sock, expected_uid=os.getuid(), source_name="rehearsal")

    def new_service(self, name: str, anchor=None):
        from aegis.assessment import AssessmentService
        data = self.tmp / name
        svc = AssessmentService(data, _free_port(), verify_seconds=0.05,
                                revocation_marker_dirs=[self.tmp / f"{name}-markers"],
                                real_site_read_only=True, separate_l2_approver=True,
                                audit_anchor=anchor, audit_anchor_root=data if anchor else None)
        svc._custom_resolver = loopback_resolver(self.targets)

        def refuse(*_a, **_kw):
            raise OSError("rehearsal: proof re-check outside the injected lookup refused")
        svc._proof_dns_lookup = refuse
        svc._proof_file_fetch = refuse
        self._cleanup.append(lambda: _close(svc))
        return svc

    def new_site(self, **kw) -> MockSite:
        site = MockSite(**kw)
        threading.Thread(target=site.serve_forever, daemon=True).start()

        def stop():
            site.release.set()
            site.shutdown()
            site.server_close()
        self._cleanup.append(stop)
        return site

    def url_for(self, site: MockSite) -> str:
        return f"http://{HOST}:{site.server_port}"

    def prove_and_scope(self, svc, url: str, txt_queries: list[str] | None = None) -> dict:
        ch = svc.issue_ownership_challenge(url=url, approver=APPROVER)["challenge"]

        def lookup(name):
            if txt_queries is not None:
                txt_queries.append(name)
            return [f'{name} text = "{ch["dns_txt_value"]}"']
        res = svc.verify_asset_ownership(url_or_host=url, method="dns_txt", actor=APPROVER, dns_lookup=lookup)
        if not res["verified"]:
            raise RuntimeError("ownership proof failed")
        # allow_loopback_test exists only at the service level (the HTTP API cannot set it):
        # it is what lets a loopback stand-in play the real site in this rehearsal.
        return svc.confirm_asset_scope(url_or_host=url, approver=APPROVER, activate_workspace=True,
                                       allow_loopback_test=True, allow_status_probe=False)

    @staticmethod
    def wait_state(svc, leave: str = "running", timeout: float = RUN_TIMEOUT_S) -> str:
        end = time.time() + timeout
        while time.time() < end and svc.snapshot()["state"] == leave:
            time.sleep(0.05)
        return svc.snapshot()["state"]

    # ---- the runbook, step by step ---------------------------------------
    def main_flow(self) -> None:
        from aegis import server as srvmod
        from aegis.gateway import State
        from aegis.network import NetworkError

        self.step("0 config: VULNIX_REAL_SERVICE_DIAGNOSIS=l1 means L1-only, legacy L2 switch off",
                  srvmod.REAL_SITE_L1_ONLY and not srvmod.REAL_SERVICE_DIAGNOSIS
                  and srvmod.REAL_SITE_RUNS_PER_ORG_PER_HOUR == 10
                  and srvmod.OWNERSHIP_CHECKS_PER_ORG_PER_HOUR == 20,
                  real_site_l1_only=srvmod.REAL_SITE_L1_ONLY, legacy_l2=srvmod.REAL_SERVICE_DIAGNOSIS)

        store, anchor = self.start_anchor()
        svc = self.new_service("main", anchor=anchor)
        site = self.new_site()
        url = self.url_for(site)

        # 1 register: a challenge, no traffic, no resolution, no workspace, no scope
        issued = svc.issue_ownership_challenge(url=url, approver=APPROVER)
        asset_id = issued["asset"]["id"]
        ch = issued["challenge"]
        refusals = {
            "select_before_proof": self._raises(lambda: svc.select_asset(asset_id), ValueError),
            "scope_before_proof": self._raises(
                lambda: svc.confirm_asset_scope(url_or_host=url, approver=APPROVER), ValueError),
        }
        self.step("1 register: challenge issued, nothing resolved or sent, no scope",
                  issued["asset"]["status"] == "所有確認待ち" and svc._resolve_host(HOST) == []
                  and all(refusals.values()) and site.snapshot() == [] and site.connections == 0,
                  dns_txt_name=ch["dns_txt_name"], refusals=refusals)

        # 2 ownership proof by DNS TXT (the site itself is not contacted)
        queries: list[str] = []
        wrong = svc.verify_asset_ownership(url_or_host=url, method="dns_txt", actor=APPROVER,
                                           dns_lookup=lambda n: (queries.append(n), ['"vulnix-verify=wrong"'])[1])
        ok = svc.verify_asset_ownership(url_or_host=url, method="dns_txt", actor=APPROVER,
                                        dns_lookup=lambda n: (queries.append(n), [f'"{ch["dns_txt_value"]}"'])[1])
        self.step("2 ownership: wrong TXT refused, exact TXT accepted, L2 not auto-approved, site untouched",
                  not wrong["verified"] and ok["verified"] and ok["l2_auto_approved"] is False
                  and set(queries) == {ch["dns_txt_name"]} and svc._resolve_host(HOST) == []
                  and site.snapshot() == [], txt_queries=queries)

        # 3 scope confirmation by the approver (status probe NOT allowed)
        scope = svc.confirm_asset_scope(url_or_host=url, approver=APPROVER, activate_workspace=True,
                                        allow_loopback_test=True, allow_status_probe=False)
        snap = svc.snapshot()
        self.step("3 scope: confirmed for the one host, read-only, no extra probe, no lookup or traffic yet",
                  scope["scope_confirmed"] and scope["allow_status_probe"] is False
                  and snap["is_external_service"] and snap["real_site_read_only"]
                  and snap["authorization"]["scope"]["hosts"] == [HOST] and snap["target_url"] == url + "/"
                  and site.snapshot() == [] and svc._custom_resolver.calls == 0,
                  scope_hosts=snap["authorization"]["scope"]["hosts"], target_url=snap["target_url"],
                  resolver_calls_before_run=svc._custom_resolver.calls)

        # 4 one L1 run
        svc.start()
        state = self.wait_state(svc)
        seen = site.snapshot()
        usage = dict(svc.ledger.scan_usage.get(HOST) or {})
        headers_ok = all(r["user_agent"] == EXPECTED_UA and r["origin"] == EXPECTED_ORIGIN
                         and not r["has_authorization"] and not r["has_cookie"] and r["content_length"] == 0
                         for r in seen)
        self.step("4 one L1 run: exactly the runbook's requests, with the documented headers",
                  state == "completed" and site.method_paths() == self.expected and headers_ok
                  and site.connections == len(self.expected) and usage.get("paths") == ["/"],
                  state=state, expected=self.expected, seen=seen, connections=site.connections,
                  signed_allowance_paths=usage.get("paths"))

        # 5 watch: what the operator checks on the screen / snapshot
        snap = svc.snapshot()
        phases = {p["key"]: p["status"] for p in snap["phases"]}
        events = [e["event"] for e in svc.audit.entries()]
        statuses = {f["id"]: f.get("evidence_status") for f in snap["findings"]}
        # the runbook saves the report HERE too: after the stop drill it reads "中止"
        pre_stop_report = svc.report_markdown()
        if self.out_dir:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            (self.out_dir / "report_before_stop.md").write_text(pre_stop_report, encoding="utf-8")
        self.step("5 watch: L2 phase skipped, no approvals, evidence carries audit hashes",
                  "**診断状態**: 診断済み" in pre_stop_report
                  and phases.get("verification") == "skipped" and snap["approvals"] == []
                  and "scan.request_reserved" in events and events.count("allow") == 1
                  and events.count("result") == 1
                  and any(f.get("evidence") for f in snap["findings"])
                  and all(e.get("audit_hash") for f in snap["findings"] for e in f.get("evidence") or []),
                  phases=phases, findings=statuses)

        # 6 no L2 / lab attack probe, no re-check, no second GET
        finding = next(iter(statuses), "f_headers")
        l2 = {
            "request_l2_run": self._raises(lambda: svc.request_l2_run(finding, "operator-1"), ValueError),
            "verify_finding": self._raises(lambda: svc.verify_finding(finding, APPROVER), ValueError),
            "verify_fix": self._raises(lambda: svc.verify_fix(APPROVER), ValueError),
        }
        self.step("6 L2 and re-check operations refused on the real site; nothing sent",
                  all(l2.values()) and site.method_paths() == self.expected, refusals=l2)

        # 7 emergency stop drill (after the run: no extra traffic is needed for it)
        rep = svc.emergency_stop(APPROVER)
        after = {
            "start": self._raises(svc.start, ValueError),
            "ownership_check": self._raises(
                lambda: svc.verify_asset_ownership(url_or_host=url, method="dns_txt", actor=APPROVER,
                                                   dns_lookup=lambda n: []), ValueError),
            "egress": self._raises(lambda: svc.gateway.egress.check(url, svc.a.engagement.targets["lab"]),
                                   NetworkError),
        }
        time.sleep(0.3)
        self.step("7 emergency stop: confirmed, gateway stopped, egress blocked, new requests refused",
                  rep["confirmed"] and svc.gateway.state is State.STOPPED and svc.gateway.egress.blocked
                  and svc.snapshot()["state"] == "stopped" and all(after.values())
                  and site.method_paths() == self.expected,
                  stop_steps=[s["name"] for s in rep["steps"]], refusals=after)

        # 8 audit chain and anchor
        from aegis.audit import AuditLog
        audit_path = svc.data_dir / "audit.jsonl"
        entries, valid = AuditLog(audit_path).verified_entries()
        anchor_status = svc.audit.anchor_status(max_age=None)
        heads = store._heads
        head = heads.get(svc.audit.anchor_source) if isinstance(heads, dict) else None
        head_seq = (head or {}).get("seq")
        head_matches = bool(head_seq) and entries[head_seq - 1]["hash"] == head.get("hash")
        tampered = self.tmp / "tampered.jsonl"
        lines = audit_path.read_text().splitlines()
        edited = json.loads(lines[1])
        edited["event"] = "edited." + edited["event"]          # one field of one record
        lines[1] = json.dumps(edited, ensure_ascii=False, sort_keys=True)
        tampered.write_text("\n".join(lines) + "\n")
        self.step("8 audit: chain verifies, anchor head matches the chain, a tampered copy fails",
                  valid and svc.audit.verify() and head_matches and not AuditLog(tampered).verify()
                  and anchor_status["enabled"] and anchor_status["error"] in (None, "same_user"),
                  entries=len(entries), anchor=anchor_status, anchor_head_seq=head_seq)

        # 9 report
        report = svc.report_markdown()
        if self.out_dir:
            self.out_dir.mkdir(parents=True, exist_ok=True)
            (self.out_dir / "report.md").write_text(report, encoding="utf-8")
            shutil.copy(audit_path, self.out_dir / "audit.jsonl")
        self.step("9 report: names the proven site, says real-site L2 is not run, no demo wording",
                  "**診断状態**: 中止" in report and HOST in report and "L2はこの公開βで実行しません" in report and "架空" not in report
                  and "rehearsal-cookie-value" not in report,
                  report_bytes=len(report.encode()))

        # 10 withdraw the scope (delete the site)
        svc.delete_asset(asset_id, actor=APPROVER)
        gone = {
            "select": self._raises(lambda: svc.select_asset(asset_id), ValueError),
            "scope_without_new_proof": self._raises(
                lambda: svc.confirm_asset_scope(url_or_host=url, approver=APPROVER), ValueError),
        }
        events = [e["event"] for e in svc.audit.entries()]
        self.step("10 withdraw: scope and proof gone, name no longer resolves, nothing more sent",
                  HOST not in svc._verified_external_hosts and HOST not in svc._ownership_proofs
                  and svc._resolve_host(HOST) == [] and all(gone.values()) and "asset.deleted" in events
                  and site.method_paths() == self.expected and svc.audit.verify(),
                  refusals=gone)

        self.step("11 whole main flow: the site saw only the runbook's L1 requests",
                  site.method_paths() == self.expected and site.connections == len(self.expected),
                  total_requests=len(site.snapshot()))

    def inflight_stop_drill(self) -> None:
        """Emergency stop while the one L1 request is in flight (the site holds it)."""
        svc = self.new_service("inflight")
        site = self.new_site(hang_root=True)
        url = self.url_for(site)
        self.prove_and_scope(svc, url)
        svc.start()
        got = site.got_request.wait(20)
        time.sleep(0.2)
        rep = svc.emergency_stop(APPROVER)
        site.release.set()
        runner = getattr(svc, "_thread", None)
        if runner is not None:
            runner.join(15)            # the runner has finished: a late adoption would be visible
        time.sleep(0.3)
        snap = svc.snapshot()
        adopted = [f["id"] for f in snap["findings"] if f.get("evidence")]
        self.step("12 in-flight stop: worker killed and confirmed, result not adopted, no further request",
                  got and rep["confirmed"] and rep["killed_pids"] and snap["state"] == "stopped"
                  and not adopted and site.method_paths() == self.expected
                  and self._raises(svc.start, ValueError) is not None,
                  killed=len(rep["killed_pids"]), survivors=rep["survivors"], adopted=adopted)

    def lab_probe_refusal(self) -> None:
        """The bundled lab's attack probes, asked for directly, never reach a real site."""
        svc = self.new_service("labprobe")
        site = self.new_site()
        url = self.url_for(site)
        self.prove_and_scope(svc, url)
        results = {}
        for check in ("idor", "cve_2021_41773", "sqli"):
            res, ev = svc._exec("reproduction_probe", "safe_reproduction", {"url": url, "check": check},
                                approval_actor="rehearsal:attempt")
            reasons = [e["fields"].get("reason", "") for e in svc.audit.entries()
                       if e["event"] == "assessment.failed"]
            # refused by the last-line lab-probe guard itself, not by some other failure
            results[check] = res is None and ev is None and bool(reasons) and "模擬ラボ専用" in reasons[-1]
        self.step("13 lab attack probes (idor / cve_2021_41773 / sqli) refused before any worker starts",
                  all(results.values()) and site.snapshot() == [] and site.connections == 0
                  and "allow" not in [e["event"] for e in svc.audit.entries()]
                  and svc.audit.verify(),
                  refused=results)

    def run(self) -> dict:
        try:
            with no_outside_network():
                for phase in (self.main_flow, self.inflight_stop_drill, self.lab_probe_refusal):
                    try:
                        phase()
                    except RefuseToRun:
                        raise
                    except Exception as e:  # noqa: BLE001 - a crashed phase is a failed step
                        self.step(f"{phase.__name__} crashed", False, error=f"{type(e).__name__}: {e}")
        finally:
            for fn in reversed(self._cleanup):
                try:
                    fn()
                except Exception:  # noqa: BLE001
                    pass
            self._tmp.cleanup()
            self._sock_tmp.cleanup()
        return {"ok": bool(self.steps) and all(s["ok"] for s in self.steps),
                "host": HOST, "runbook_l1_requests": [f"{m} {p}" for m, p in self.expected],
                "steps": self.steps}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _close(svc) -> None:
    with svc._lock:
        svc._closed = True
    svc.workers.kill_all()


@contextmanager
def _rehearsal_env():
    """The runbook's settings for this process, restored afterwards."""
    saved = dict(os.environ)
    try:
        for k in list(os.environ):
            if k.startswith(_DROP_PREFIXES):
                del os.environ[k]
        os.environ.update(_ENV)
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def main(argv: list[str] | None = None, targets: dict[str, list[str]] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, default=None, help="directory for report.md and audit.jsonl")
    ap.add_argument("--resolve", action="append", default=[], metavar="HOST=ADDR",
                    help="override the stand-in mapping (only loopback is ever accepted)")
    ap.add_argument("--runbook", type=Path, default=None, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.resolve:
        targets = {}
        for item in a.resolve:
            host, _, addr = item.partition("=")
            targets.setdefault(host, []).append(addr)
    targets = dict(targets or DEFAULT_TARGETS)
    try:
        preflight_targets(targets)
        if HOST not in targets:
            raise RefuseToRun(f"the rehearsal target {HOST} has no mapping")
    except RefuseToRun as e:
        print(json.dumps({"ok": False, "refused": str(e)}, ensure_ascii=False))
        return 2
    try:
        with _rehearsal_env():
            result = Rehearsal(a.out, targets, a.runbook).run()
    except RefuseToRun as e:
        print(json.dumps({"ok": False, "refused": str(e)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
