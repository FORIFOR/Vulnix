"""Third held-out diagnosis lab (tests/evaluation/fixtures/holdout_v3_cases.json).

Same contract as holdout_lab.py and holdout_v2_lab.py: one loopback HTTP server driven
by a case's declared behaviour. It imports no Vulnix detector, judge, planner, Gateway or
Worker code and never reads the label file. It adds answer layouts neither earlier set
had: data envelopes (data / results lists / base64 payloads), camelCase and JSON-escaped
fields, B's record rendered as an HTML table, refusals and sign-in pages in Japanese,
German and French, bodies cut off mid-JSON, Retry-After answers (429 / 503), and an
owner control that fails as 401 or as a sign-in page.
"""
from __future__ import annotations

import base64
import http.server
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "holdout_v3_cases.json").read_text())["cases"]
RESOURCE = "/api/accounts/B/secret"
MARKER = "VULNIX_LAB_IDOR_PROVEN"

_B = {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}
JSON_BODIES = {
    # B's own request (the owner control) - the same record as the earlier sets
    "owner_record": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B", **_B},
    "cross_record": {"Check": "idor_cross_account_access", "established": True, "caller_account": "acct_A", **_B},
    "env_data_b": {"data": dict(_B), "meta": {"caller": "acct_A", "version": 3}},
    "env_list_b": {"results": [{"id": "res_a_001", "owner": "acct_A", "title": "my notes"}, dict(_B)], "count": 2},
    "camel_b": {"resourceOwner": "acct_B", "resourceId": "res_b_001", "confidentialMarker": MARKER,
                "requestedBy": "acct_A"},
    "b64_b": {"encoding": "base64", "payload": base64.b64encode(json.dumps(_B).encode()).decode()},
    "own_record_env": {"data": {"resource_owner": "acct_A", "resource_id": "res_a_001",
                                "confidential_marker": "VULNIX_LAB_A_ONLY"}},
    "redacted_b": {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": "[REDACTED]",
                   "visibility": "metadata_only"},
    "count_only": {"items_visible": 0, "total_items": 1},
    "field_hint": {"error": "forbidden", "hint": "field confidential_marker is restricted to its owner"},
    "echo_refusal": {"requested_path": RESOURCE, "requested_owner": "acct_B", "message": "not permitted"},
    "json_refusal_ja": {"エラー": "アクセス権限がありません", "コード": 403},
    "json_refusal_nested": {"ok": False, "error": {"type": "permission_denied",
                                                   "message": "You do not have access to this resource"}},
    "rate_limited": {"error": "rate_limited", "retry_after": 60},
    "not_authenticated": {"error": "authentication required"},
    "session_expired": {"error": "session expired"},
    "forbidden": {"error": "forbidden"},
    "not_found": {"error": "not found"},
    "docs": {"docs": "public API introduction"},
    "docs_with_link": {"docs": "see /api/accounts/B/secret for your account"},
}
TEXT_BODIES = {
    "escaped_b": ("application/json",
                  '{"owner": "acct\\u005fB", "id": "res\\u005fb\\u005f001", '
                  '"secret": "VULNIX\\u005fLAB\\u005fIDOR\\u005fPROVEN", "caller": "acct_A"}'),
    "trunc_b_ids": ("application/json",
                    '{"resource_owner": "acct_B", "resource_id": "res_b_001", '
                    '"confidential_marker": "VULNIX_LAB_IDOR_PROVEN", "notes": "trav'),
    "trunc_b_noid": ("application/json", '{"notes": "travel plans", "balance": 1200, "resource_'),
    "trunc_refusal": ("application/json", '{"error": "forbid'),
    "b_html_table": ("text/html; charset=utf-8",
                     "<html><head><title>Account record</title></head><body><table>"
                     "<tr><th>Owner</th><td>acct_B</td></tr><tr><th>ID</th><td>res_b_001</td></tr>"
                     "<tr><th>Secret</th><td>VULNIX_LAB_IDOR_PROVEN</td></tr></table></body></html>"),
    "html_login_ja": ("text/html; charset=utf-8",
                      "<!DOCTYPE html><html lang=\"ja\"><head><title>ログイン</title></head><body>"
                      "<form method=\"post\"><label>メールアドレス<input name=\"email\"></label>"
                      "<label>パスワード<input type=\"password\" name=\"pw\"></label>"
                      "<button>ログイン</button></form></body></html>"),
    "html_denied_de": ("text/html; charset=utf-8",
                       "<html lang=\"de\"><head><title>Zugriff verweigert</title></head><body>"
                       "<h1>403 - Zugriff verweigert</h1><p>Sie haben keine Berechtigung.</p></body></html>"),
    "html_login_fr": ("text/html; charset=utf-8",
                      "<html lang=\"fr\"><head><title>Connexion</title></head><body>"
                      "<form method=\"post\"><input type=\"email\" name=\"email\">"
                      "<button>Recevoir un lien de connexion</button></form></body></html>"),
    "html_spa_redirect": ("text/html", "<!DOCTYPE html><html><body><div id=\"root\"></div>"
                                       "<script>window.location.replace('/login')</script></body></html>"),
    "html_unavailable": ("text/html", "<html><head><title>503 Service Unavailable</title></head><body>"
                                      "<h1>Service temporarily unavailable</h1></body></html>"),
}
EXTRA_HEADERS = {"rate_limited": {"Retry-After": "60"}, "html_unavailable": {"Retry-After": "120"}}


class HoldoutV3Lab(http.server.ThreadingHTTPServer):
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
        for name, value in EXTRA_HEADERS.get(body, {}).items():
            self.send_header(name, value)
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
