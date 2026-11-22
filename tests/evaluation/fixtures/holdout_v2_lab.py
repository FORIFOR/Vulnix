"""Second held-out diagnosis lab (tests/evaluation/fixtures/holdout_v2_cases.json).

Same contract as holdout_lab.py: one loopback HTTP server driven by a case's declared
behaviour. It imports no Vulnix detector, judge, planner, Gateway or Worker code and
never reads the label file. Compared with the first set it adds answer layouts the
first set did not have (nested records, partial identifiers, other refusal shapes,
HTML that is not a sign-in page, bodies over 4 KB, text/plain).
"""
from __future__ import annotations

import http.server
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "holdout_v2_cases.json").read_text())["cases"]
RESOURCE = "/api/accounts/B/secret"
MARKER = "VULNIX_LAB_IDOR_PROVEN"
PAD = "x" * 5000

_B = {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}
JSON_BODIES = {
    "owner_record": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B", **_B},
    "cross_record": {"Check": "idor_cross_account_access", "established": True, "caller_account": "acct_A", **_B},
    "b_record_nested": {"caller_account": "acct_A", "data": dict(_B, notes="travel plans")},
    "b_id_only": {"id": "res_b_001", "title": "quarterly notes", "notes": "travel plans"},
    "marker_only": {"message": f"sample value {MARKER}"},
    "owner_a_marker": {"caller_account": "acct_A", "resource_owner": "acct_A", "confidential_marker": MARKER},
    "b_named_no_ids": {"owner": "acct_B", "notes": "travel plans"},
    "b_unlabelled": {"notes": "travel plans", "balance": 1200},
    "own_record_alt": {"caller_account": "acct_A", "resource_owner": "acct_A", "resource_id": "res_a_002",
                       "notes": "mine"},
    "refusal_status": {"status": "denied", "reason": "not permitted"},
    "refusal_errors": {"errors": [{"code": "FORBIDDEN", "detail": "no access"}]},
    "empty_list": [],
    "public_items": {"items": [{"name": "Public team page"}, {"name": "Help center"}]},
    "large_b_record": {"padding": PAD, **_B},
    "large_public": {"padding": PAD, "items": [{"name": "Help center"}]},
    "not_authenticated": {"error": "authentication required"},
    "forbidden": {"error": "forbidden"},
    "not_found": {"error": "not found"},
    "server_error": {"error": "internal"},
    "docs": {"docs": "public API introduction"},
    "docs_with_link": {"docs": "see /api/accounts/B/secret for your account"},
}
TEXT_BODIES = {
    "html_login_pw": ("text/html", "<!DOCTYPE html><html><head><title>Sign in</title></head><body>"
                                   "<form method=\"post\"><input name=\"user\"><input type=\"password\" name=\"pw\">"
                                   "<button>Log in</button></form></body></html>"),
    "html_refusal": ("text/html", "<html><head><title>403 Forbidden</title></head><body><h1>Access denied</h1>"
                                  "</body></html>"),
    "html_landing": ("text/html", "<html><body><h1>Welcome</h1><p>Plans and pricing</p>"
                                  "<a href=\"/login\">Sign in</a></body></html>"),
    "html_b_page": ("text/html", "<html><body><h1>Account settings</h1><p>Notes: travel plans</p>"
                                 "<p>Balance: 1200</p></body></html>"),
    "html_login_named": ("text/html", "<html><body><form><p>Welcome back, acct_B</p>"
                                      "<input type=\"password\"><button>Sign in</button></form></body></html>"),
    "text_denied": ("text/plain", "Forbidden"),
}


class HoldoutV2Lab(http.server.ThreadingHTTPServer):
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

    def _send(self, status: int, body: str, *, link: bool = False):
        if body in TEXT_BODIES:
            ctype, text = TEXT_BODIES[body]
            raw = text.encode()
        else:
            raw, ctype = json.dumps(JSON_BODIES[body], ensure_ascii=False).encode(), "application/json"
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
