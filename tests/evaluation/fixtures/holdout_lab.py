"""Held-out diagnosis lab: one loopback HTTP server driven by a case's declared
behaviour (tests/evaluation/fixtures/holdout_cases.json).

Like tests/fixtures/access_control_lab.py, it imports no Vulnix detector, judge,
planner, Gateway or Worker code, and it never reads the label file
(see the protocol). The case file says only how the server answers whom.
"""
from __future__ import annotations

import http.server
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "holdout_cases.json").read_text())["cases"]
RESOURCE = "/api/accounts/B/secret"
MARKER = "VULNIX_LAB_IDOR_PROVEN"

# What an answer looks like, by name. Accounts: anon (no header), acct_A, acct_B.
BODIES = {
    "owner_record": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
                     "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER},
    "cross_record": {"Check": "idor_cross_account_access", "established": True, "caller_account": "acct_A",
                     "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER},
    "cross_record_extra": {"Check": "idor_cross_account_access", "established": True, "caller_account": "acct_A",
                           "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER,
                           "plan": "team", "updated": "2026-11-01"},
    "caller_own_record": {"Check": "own_resource", "caller_account": "acct_A", "resource_owner": "acct_A",
                          "resource_id": "res_a_001"},
    "identity_ignored": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B",
                         "resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER},
    "marker_in_text": {"message": f"example payload: {MARKER}", "caller_account": "acct_A",
                       "resource_owner": "acct_A"},
    "soft_error": {"error": "forbidden", "ok": False},
    "anon_record": {"owner": "acct_B", "balance_note": "lab-only data"},
    "public_listing": {"directory": "public profile listing", "entries": 3},
    "not_authenticated": {"error": "authentication required"},
    "forbidden": {"error": "forbidden"},
    "not_found": {"error": "not found"},
    "rate_limited": {"error": "slow down"},
    "server_error": {"error": "internal"},
    "docs": {"docs": "public API introduction"},
    "docs_with_link": {"docs": "see /api/accounts/B/secret for your account"},
}
HTML_LOGIN = "<html><body><form>Sign in</form></body></html>"


class HoldoutLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, case_id: str):
        if case_id not in CASES:
            raise ValueError("unknown case")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.case = CASES[case_id]
        self.fixed = False                      # the owner's fix (after_fix) switches the answers
        self.seen: list[tuple[str, str | None]] = []

    def answers(self) -> dict:
        return self.case["after_fix"] if self.fixed and self.case.get("after_fix") else self.case["resource"]


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status: int, body, *, link: bool = False):
        if body == "html_login":
            raw, ctype = HTML_LOGIN.encode(), "text/html"
        else:
            raw, ctype = json.dumps(BODIES[body], ensure_ascii=False).encode(), "application/json"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        if link:
            self.send_header("Link", f'<{RESOURCE}>; rel="account-resource"')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        account = self.headers.get("X-Test-Account")
        self.server.seen.append((self.path, account))
        case = self.server.case
        if self.path == "/":
            root = case["root"]
            return self._send(root["status"], root["body"], link=root.get("link_header", False))
        if self.path != RESOURCE:
            return self._send(404, "not_found")
        who = account if account in ("acct_A", "acct_B") else "anon"
        status, body = self.server.answers()[who]
        return self._send(status, body)
