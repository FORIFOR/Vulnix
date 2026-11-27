"""Open-redirect lab probe (a separate worker, so the frozen reproduction_probe judge is unchanged).

One positive control and two attack values to the pinned (ip, port), GET only, redirects never
followed. The destination is judged from the Location header alone; the proof host is under the
reserved .invalid TLD and is never contacted.
"""
import argparse
import http.client
import json
import os
import socket
import ssl
from urllib.parse import quote, urljoin, urlsplit

PROOF_HOST = "vulnix-redirect-proof.invalid"
REDIRECT_PATH = "/auth/callback?return_to="
REDIRECT_CONTROL = "/dashboard"
REDIRECT_VARIANTS = (f"https://{PROOF_HOST}/landing", f"//{PROOF_HOST}/landing")
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


def _fetch(a, path: str) -> dict:
    sock = socket.create_connection((a.ip, a.port), timeout=10)
    if a.scheme == "https":
        cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
        sock = ssl.create_default_context(cafile=cafile).wrap_socket(sock, server_hostname=a.host)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    try:
        conn.request("GET", path, headers={"Host": a.host, "User-Agent": "vulnix-redirect-probe/1.0"})
        r = conn.getresponse()
        r.read(65536)
        return {"status": r.status, "location": (r.getheader("Location") or "")[:2048]}
    finally:
        conn.close()


def destination_host(location: str, own_host: str) -> str:
    """The host a browser would go to from this Location ("" when it stays on this site)."""
    host = urlsplit(urljoin(f"http://{own_host}/", location.replace("\\", "/"))).hostname or ""
    return "" if host == own_host.split(":")[0] else host


def run(a) -> dict:
    control = _fetch(a, REDIRECT_PATH + quote(REDIRECT_CONTROL, safe=""))
    control_verified = control["status"] in REDIRECT_STATUSES and control["location"] == REDIRECT_CONTROL
    variants = []
    for target in REDIRECT_VARIANTS:
        obs = _fetch(a, REDIRECT_PATH + quote(target, safe=""))
        variants.append({"target": target, "status": obs["status"], "location": obs["location"],
                         "destination_host": destination_host(obs["location"], a.host)})
    hit = next((v for v in variants if v["status"] in REDIRECT_STATUSES and v["destination_host"] == PROOF_HOST), None)
    kept = all(v["status"] in REDIRECT_STATUSES and v["destination_host"] == "" for v in variants)
    if not control_verified:
        verdict, reason = "unverified", "control redirect to a same-site path did not work"
    elif hit:
        verdict, reason = "proven", None
    elif kept:
        verdict, reason = "not_reproduced", None
    else:
        verdict, reason = "unverified", "the response neither left the site nor stayed on it"
    shown = hit or variants[0]
    return {"check": "open_redirect", "request_path": REDIRECT_PATH, "request_headers": {},
            "status": shown["status"], "location": shown["location"],
            "established": verdict == "proven", "verdict": verdict, "unverified_reason": reason,
            "control_status": control["status"], "control_verified": control_verified,
            "control_response": {"location": control["location"]}, "variants": variants,
            "proof_host": PROOF_HOST, "connected_ip": a.ip, "connected_port": a.port,
            "response": {"Check": "open_redirect", "location": shown["location"]}}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", required=True, type=int)
    p.add_argument("--check", required=True, choices=["open_redirect"])
    print(json.dumps(run(p.parse_args()), ensure_ascii=False))


if __name__ == "__main__":
    main()
