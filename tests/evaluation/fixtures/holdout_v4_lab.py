"""Fourth held-out diagnosis lab (tests/evaluation/fixtures/holdout_v4_cases.json).

Same contract as holdout_lab.py, holdout_v2_lab.py and holdout_v3_lab.py: one loopback
HTTP server driven by a case's declared behaviour. It imports no Vulnix detector, judge,
planner, Gateway or Worker code and never reads the label file. It adds answer layouts
none of the earlier sets had: GraphQL (data / errors), JSON:API, HAL, XML and CSV
records, a record serialised inside a JSON string, owner lists, A's own data that names
B (collaborators, foreign keys, activity logs, search results, an HTML page that names A
through entities), documentation served at the resource URL, refusals in Spanish and
Korean, application/problem+json refusals, an SSO-only sign-in page, bodies longer than
the 4 KB the Worker keeps, a soft rate limit answered as 200, and owner controls that fail
as 500, 403 (insufficient scope) or 429.
"""
from __future__ import annotations

import http.server
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "holdout_v4_cases.json").read_text())["cases"]
RESOURCE = "/api/accounts/B/secret"
MARKER = "VULNIX_LAB_IDOR_PROVEN"
A_MARKER = "VULNIX_LAB_A_ONLY"

_B = {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}


def _a_items(n: int) -> list[dict]:
    return [{"id": f"res_a_{i:03d}", "owner": "acct_A", "title": f"my note {i}",
             "updated": "2026-11-20T09:00:00Z"} for i in range(2, 2 + n)]


def _history(n: int) -> list[dict]:
    return [{"at": f"2026-10-{1 + i % 28:02d}T08:{i % 60:02d}:00Z", "event": "viewed", "by": "acct_B"}
            for i in range(n)]


JSON_BODIES = {
    # B's own request (the owner control) - the same record as the earlier sets
    "owner_record": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B", **_B},
    "gql_account": {"data": {"viewer": {"id": "acct_A"},
                             "node": {"__typename": "Secret", "id": "res_b_001",
                                      "owner": {"__typename": "Account", "id": "acct_B", "handle": "b-user"},
                                      "confidentialMarker": MARKER}}},
    "jsonapi_secret": {"data": {"type": "secrets", "id": "res_b_001",
                                "attributes": {"confidential_marker": MARKER, "label": "tax documents"},
                                "relationships": {"owner": {"data": {"type": "accounts", "id": "acct_B"}}}},
                       "meta": {"requested_by": "acct_A"}},
    "hal_secret": {"_links": {"self": {"href": RESOURCE}, "owner": {"href": "/api/accounts/B"}},
                   "resource_id": "res_b_001", "owner_account": "acct_B", "confidential_marker": MARKER},
    "record_in_string": {"status": "ok", "format": "json", "record": json.dumps(_B)},
    "paged_items": {"page": 1, "per_page": 20,
                    "items": [{"resourceId": "res_b_001", "ownerId": "acct_B", "secretValue": MARKER,
                               "updatedAt": "2026-11-20T09:12:00Z"}], "next_cursor": None},
    "owners_array": {"id": "res_b_001", "owners": ["acct_B"], "secret": MARKER, "shared": False},
    "pii_profile": {"account": "acct_B", "resource_id": "res_b_001", "email": "b@lab.test",
                    "phone": "+81-00-0000-0000", "confidential_marker": MARKER},
    # A's own data that names B somewhere
    "own_collab": {"id": "res_a_001", "owner": {"account_id": "acct_A", "display": "A"},
                   "collaborators": [{"account_id": "acct_B", "role": "viewer"}], "confidential_marker": A_MARKER},
    "activity_log": {"entries": [
        json.dumps({"at": "2026-11-21T10:00:00Z", "actor": "acct_A", "action": "read",
                    "resource_id": "res_a_001", "result": "ok"}),
        json.dumps({"at": "2026-11-21T10:00:05Z", "actor": "acct_A", "action": "read",
                    "resource_id": "res_b_001", "owner": "acct_B", "result": "denied"})]},
    "path_parts_refusal": {"error": "not_permitted", "path": ["api", "accounts", "B", "secret"],
                           "id_parts": ["res", "b", "001"]},
    "invoices_fk": {"invoices": [{"id": "inv_a_0042", "owner": "acct_A", "resource_id": "res_b_001",
                                  "amount_jpy": 1200, "memo": "shared storage fee"}], "total": 1},
    "search_echo": {"query": "res_b_001", "results": [], "total": 0, "took_ms": 3},
    "search_a_only": {"query": "acct_B", "results": [{"id": "res_a_001", "owner": "acct_A",
                                                       "snippet": "meeting notes mentioning acct_B"}], "total": 1},
    "own_items": {"items": [{"id": "res_a_001", "owner": "acct_A", "label": "my notes",
                             "confidential_marker": A_MARKER}], "total": 1},
    # refusals and errors
    "json_refusal_es": {"error": {"código": 403,
                                  "mensaje": "Acceso denegado: no tiene permiso para ver este recurso"}},
    "gql_errors": {"data": {"node": None}, "errors": [{"message": "Not authorised to access Secret",
                                                       "path": ["node"], "extensions": {"code": "FORBIDDEN"}}]},
    "soft_rate_limit": {"ok": False, "message": "Too many requests. Please slow down.", "retry_in_seconds": 30},
    "owner_scope": {"error": "insufficient_scope", "scope_required": "secrets:read"},
    "gone": {"error": "gone"},
    "not_authenticated": {"error": "authentication required"},
    "forbidden": {"error": "forbidden"},
    "not_found": {"error": "not found"},
    "docs": {"docs": "public API introduction"},
}
TEXT_BODIES = {
    "xml_secret": ("application/xml",
                   '<?xml version="1.0" encoding="UTF-8"?><secret><id>res_b_001</id><owner>acct_B</owner>'
                   f"<marker>{MARKER}</marker></secret>"),
    "csv_export": ("text/csv; charset=utf-8",
                   f"resource_id,owner,confidential_marker,created\r\nres_b_001,acct_B,{MARKER},2026-10-01\r\n"),
    "html_profile_b": ("text/html; charset=utf-8",
                       "<html><head><title>Secret settings</title></head><body><h1>Secret</h1><dl>"
                       "<dt>Owner</dt><dd>acct_B</dd><dt>Resource</dt><dd>res_b_001</dd>"
                       f"<dt>Value</dt><dd>{MARKER}</dd></dl></body></html>"),
    "html_a_escaped": ("text/html; charset=utf-8",
                       "<html><head><title>Your secrets</title></head><body>"
                       "<header>Signed in as acct&#95;A</header><h1>Your secrets</h1>"
                       f"<ul><li>res&#95;a&#95;001 - {A_MARKER}</li></ul>"
                       "<p>The item res_b_001 belongs to acct_B.</p><button>Request access</button></body></html>"),
    "html_api_docs": ("text/html; charset=utf-8",
                      "<html><head><title>API reference - GET /api/accounts/{id}/secret</title></head><body>"
                      "<h1>Read a secret</h1><p>Returns the secret of the account in the path.</p>"
                      "<pre>GET /api/accounts/B/secret\n200 OK\n{\"resource_id\": \"res_b_001\", "
                      "\"resource_owner\": \"acct_B\", \"confidential_marker\": \"&lt;string&gt;\"}</pre>"
                      "</body></html>"),
    "problem_json": ("application/problem+json",
                     json.dumps({"type": "https://lab.test/problems/forbidden", "title": "Forbidden", "status": 403,
                                 "detail": "Account acct_A may not read res_b_001", "instance": RESOURCE})),
    "rate_limit_problem": ("application/problem+json",
                           json.dumps({"title": "Too Many Requests", "status": 429, "detail": "quota exceeded"})),
    "html_denied_ko": ("text/html; charset=utf-8",
                       "<html lang=\"ko\"><head><title>접근 거부</title></head><body>"
                       "<h1>403 접근이 거부되었습니다</h1><p>이 리소스를 볼 권한이 없습니다.</p></body></html>"),
    "html_signin_pt": ("text/html; charset=utf-8",
                       "<html lang=\"pt-BR\"><head><title>Entrar</title></head><body><h1>Entrar</h1>"
                       "<form method=\"post\" action=\"/sso\"><button name=\"idp\" value=\"google\">"
                       "Entrar com Google</button><button name=\"idp\" value=\"microsoft\">Entrar com Microsoft"
                       "</button></form></body></html>"),
    "html_error_500": ("text/html", "<html><head><title>500 Internal Server Error</title></head><body>"
                                    "<h1>Internal Server Error</h1></body></html>"),
    "trunc_html_b": ("text/html; charset=utf-8",
                     "<html><head><title>Secret</title></head><body><table><tr><td>acct_B</td><td>res_b_001</td>"
                     f"<td>{MARKER}</td><td>note: renew pas"),
    # longer than the 4096 characters the Worker keeps
    "long_list_b_late": ("application/json",
                         json.dumps({"items": _a_items(70) + [dict(_B)], "total": 71})),
    "long_b_first": ("application/json", json.dumps({**_B, "history": _history(80)})),
    "long_a_only": ("application/json", json.dumps({"items": _a_items(80), "total": 80})),
}
EXTRA_HEADERS = {"rate_limit_problem": {"Retry-After": "90"}}


class HoldoutV4Lab(http.server.ThreadingHTTPServer):
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
