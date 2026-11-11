"""Authorized, non-destructive reproduction probe worker.

Runs inside the `egress_sentinel` sandbox and connects ONLY to the Gateway-pinned
(ip, port). Verifies whether a candidate vulnerability (e.g., cross-account IDOR
with dedicated test accounts, CVE-2021-41773 path normalization check, or DeepNote
L2 authorization boundary checks) actually reproduces ("proven") or is blocked by
defenses ("not_reproduced").

DeepNote L2 checks (per-call environment, set by the Gateway for this tool only):
  * `VULNIX_L2_TOKEN`          subject test account (account A / free plan).
  * `VULNIX_L2_CONTROL_TOKEN`  owner test account (account B) for the control request.
  * `VULNIX_L2_PATH`           operator-configured mock resource path for THIS check.

A denial only counts as "not_reproduced" when the status is one of the check's
`deny` codes AND, for owner-controlled checks, the owner control request returned
200 with the mock-data marker. Otherwise a 404 on a mistyped path or a 401 on an
expired token would look like a working defense. Anything else is "unverified".

Tokens are sent over the socket to the pinned target only and are ALWAYS redacted
(`Bearer [REDACTED_SECRET]`) in stdout/evidence.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
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
    "deepnote_idor_notes": {
        "path": "/api/v1/notes/mock_note_user_b",
        "headers": {"X-Test-Account": "user_a"},
        "marker": "DEEPNOTE_MOCK_NOTE_USER_B",
        "deny": (403, 404),
        "control": True,
    },
    "deepnote_share_link": {
        "path": "/api/v1/shares/expired_mock_token",
        "headers": {},
        "marker": "DEEPNOTE_EXPIRED_SHARE_ACCESSIBLE",
        "deny": (403, 404, 410),
        "control": False,
    },
    "deepnote_gcs_acl": {
        "path": "/storage/v1/b/deepnote-stg-mock/o/mock_voice_b.wav",
        "headers": {"X-Test-Account": "user_a"},
        "marker": "DEEPNOTE_GCS_UNAUTHORIZED_READ",
        "deny": (403, 404),
        "control": True,
    },
    "deepnote_ai_chat_isolation": {
        "path": "/api/v1/ai/chat/context?note_id=mock_note_user_b",
        "headers": {"X-Test-Account": "user_a"},
        "marker": "DEEPNOTE_AI_CROSS_TENANT_CONTEXT",
        "deny": (403, 404),
        "control": True,
    },
    "deepnote_billing_plan": {
        "path": "/api/v1/billing/premium-summary-check",
        "headers": {"X-Test-Plan": "free"},
        "marker": "DEEPNOTE_BILLING_BYPASS_PROVEN",
        "deny": (402, 403),
        "control": False,
    },
}


LAB_DENY = (403,)
REDACTED = "[REDACTED_SECRET]"


def _get(a, path: str, headers: dict, secrets_to_redact: list[str]) -> tuple[int, str]:
    """One GET to the pinned (ip, port); never follows redirects."""
    sock = socket.create_connection((a.ip, a.port), timeout=10)
    if a.scheme == "https":
        cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
        sock = ssl.create_default_context(cafile=cafile).wrap_socket(sock, server_hostname=a.host)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    try:
        conn.request("GET", path, headers={
            "Host": a.host, "User-Agent": "vulnix-reproduction-probe/1.0", **headers})
        r = conn.getresponse()
        body = r.read(4096).decode("utf-8", "replace")
    finally:
        conn.close()
    for secret in secrets_to_redact:
        if secret:
            body = body.replace(secret, REDACTED)
    return r.status, body


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--check", required=True, choices=sorted(CHECKS))
    a = p.parse_args()

    spec = CHECKS[a.check]
    is_l2_account_check = "deny" in spec
    deny = tuple(spec.get("deny", LAB_DENY))
    needs_control = bool(spec.get("control"))

    # Lab checks never read credential/path overrides from the environment.
    req_path = spec["path"]
    token = control_token = ""
    if is_l2_account_check:
        req_path = os.environ.get("VULNIX_L2_PATH") or spec["path"]
        token = os.environ.get("VULNIX_L2_TOKEN", "").strip()
        control_token = os.environ.get("VULNIX_L2_CONTROL_TOKEN", "").strip()
    secrets_to_redact = [token, control_token]

    logged_headers = dict(spec["headers"])
    wire_headers = dict(spec["headers"])
    if token:
        wire_headers["Authorization"] = f"Bearer {token}"
        logged_headers["Authorization"] = f"Bearer {REDACTED}"

    # Owner control first: the mock resource must exist and be readable by its
    # owner, otherwise a later denial proves nothing about the access boundary.
    control = None
    if needs_control:
        if not control_token:
            control = {"performed": False, "ok": False, "reason": "control token not provided"}
        else:
            c_status, c_body = _get(a, req_path, {"Authorization": f"Bearer {control_token}"},
                                    secrets_to_redact)
            control = {"performed": True, "status": c_status,
                       "marker_seen": spec["marker"] in c_body,
                       "ok": c_status == 200 and spec["marker"] in c_body}

    status, raw_body = _get(a, req_path, wire_headers, secrets_to_redact)
    try:
        parsed_body = json.loads(raw_body)
    except ValueError:
        parsed_body = None

    established = status == 200 and spec["marker"] in raw_body
    reason = None
    if established:
        verdict = "proven"
    elif status not in deny:
        verdict = "unverified"
        reason = f"HTTP {status} is not an accepted denial for this check {list(deny)}"
    elif needs_control and not (control and control["ok"]):
        verdict = "unverified"
        reason = "owner control request did not return 200 with the mock-data marker"
    else:
        verdict = "not_reproduced"
    print(json.dumps({
        "check": a.check,
        "request_path": req_path,
        "request_headers": logged_headers,
        "status": status,
        "established": established,
        "verdict": verdict,
        "unverified_reason": reason,
        "deny_statuses": list(deny),
        "control": control,
        "response": parsed_body if parsed_body is not None else raw_body,
        "connected_ip": a.ip,
        "connected_port": a.port,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
