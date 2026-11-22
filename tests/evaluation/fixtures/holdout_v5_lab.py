"""Fifth held-out diagnosis lab (tests/evaluation/fixtures/holdout_v5_cases.json).

Same contract as holdout_lab.py and holdout_v2_lab.py .. holdout_v4_lab.py: one loopback
HTTP server driven by a case's declared behaviour. It imports no Vulnix detector, judge,
planner, Gateway or Worker code and never reads the label file. The owner control
(owner_record) and the resource URL are the ones of the earlier sets. The answer layouts
are new: OData entities, collections and errors, JSON:API compound documents (included),
GraphQL Relay connections and partial data with errors, HAL collections, NDJSON exports,
a record as a base64 data: URI, B's record nested inside B's account tree, HTML cards and
pages with an embedded state blob, an OpenAPI document with template placeholders,
notifications, support tickets, refusals in Japanese, Italian, French (SOAP fault), Chinese
(OData error) and an API envelope with success=false, a GraphQL rate limit, an nginx 429
page, owner controls that fail as 503 and 401 (expired token), and bodies longer than the
65536 characters the lab IDOR check keeps.
"""
from __future__ import annotations

import base64
import http.server
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = json.loads((HERE / "holdout_v5_cases.json").read_text())["cases"]
RESOURCE = "/api/accounts/B/secret"
MARKER = "VULNIX_LAB_IDOR_PROVEN"
A_MARKER = "VULNIX_LAB_A_ONLY"

_B = {"resource_owner": "acct_B", "resource_id": "res_b_001", "confidential_marker": MARKER}
_A = {"resource_owner": "acct_A", "resource_id": "res_a_001", "confidential_marker": A_MARKER}


def _b64(obj: dict) -> str:
    return base64.b64encode(json.dumps(obj).encode()).decode()


def _a_note(i: int) -> dict:
    return {"id": f"res_a_{i:04d}", "owner": "acct_A", "title": f"grocery list {i}",
            "tags": ["personal", "weekly"], "updated_at": f"2026-11-{1 + i % 20:02d}T07:{i % 60:02d}:00Z"}


def _revisions(n: int) -> list[dict]:
    return [{"rev": n - i, "edited_at": f"2026-{1 + i % 11:02d}-{1 + i % 27:02d}T12:{i % 60:02d}:00Z",
             "editor": "acct_B", "change": "updated label and rotated value", "client": "web/4.18.2"}
            for i in range(n)]


def _nav_html(n: int) -> str:
    return "".join(f'<li class="nav-item"><a href="/help/topic-{i}">Help topic {i}</a></li>' for i in range(n))


JSON_BODIES = {
    # B's own request (the owner control) - the same record as the earlier sets
    "owner_record": {"Check": "idor_cross_account_access", "established": False, "caller_account": "acct_B", **_B},
    # B's record in standard envelopes
    "odata_entity": {"@odata.context": "https://lab.test/odata/$metadata#Secrets/$entity",
                     "@odata.etag": "W/\"7\"", "Id": "res_b_001", "OwnerAccount": "acct_B",
                     "ConfidentialMarker": MARKER, "CreatedAt": "2026-09-14T03:11:00Z"},
    "odata_collection": {"@odata.context": "https://lab.test/odata/$metadata#Secrets",
                         "@odata.count": 1,
                         "value": [{"Id": "res_b_001", "OwnerAccount": "acct_B", "ConfidentialMarker": MARKER}]},
    "jsonapi_included": {"data": {"type": "shares", "id": "shr_9001",
                                  "attributes": {"created": "2026-11-02T10:00:00Z", "permission": "read"},
                                  "relationships": {"secret": {"data": {"type": "secrets", "id": "res_b_001"}}}},
                         "included": [{"type": "secrets", "id": "res_b_001",
                                       "attributes": {"owner_account": "acct_B", "confidential_marker": MARKER}}]},
    "gql_connection": {"data": {"secrets": {
        "edges": [{"cursor": "Y3Vyc29yOjA=", "node": {"id": "res_b_001", "owner": "acct_B",
                                                       "confidentialMarker": MARKER}}],
        "pageInfo": {"hasNextPage": False, "endCursor": "Y3Vyc29yOjA="}}}},
    "gql_partial_leak": {"data": {"secret": {"id": "res_b_001", "owner": "acct_B", "confidentialMarker": MARKER,
                                             "auditTrail": None}},
                         "errors": [{"message": "Not authorised to read field auditTrail",
                                     "path": ["secret", "auditTrail"], "extensions": {"code": "FORBIDDEN"}}]},
    "hal_collection": {"_links": {"self": {"href": RESOURCE}},
                       "_embedded": {"secrets": [{"_links": {"self": {"href": RESOURCE}},
                                                  "resource_id": "res_b_001", "owner": "acct_B",
                                                  "confidential_marker": MARKER}]},
                       "page": {"size": 20, "totalElements": 1, "number": 0}},
    "account_tree": {"account": {"id": "acct_B", "plan": "family",
                                 "folders": [{"name": "tax", "secrets": [
                                     {"resource_id": "res_b_001", "confidential_marker": MARKER,
                                      "label": "2025 return"}]}]}},
    "data_uri_export": {"export": {"filename": "secret-res_b_001.json", "content_type": "application/json",
                                   "data": "data:application/json;base64," + _b64(_B)}},
    "public_profile": {"profile": {"account": "acct_B", "resource_id": "res_b_001",
                                   "confidential_marker": MARKER, "visibility": "public"}},
    # A's own data, or no record, that names B somewhere
    "related_items": {"id": "res_a_001", "owner": "acct_A", "confidential_marker": A_MARKER,
                      "related": [{"id": "res_b_001", "owner": "acct_B", "title": "shared tax folder"}],
                      "previous_version": {"id": "res_a_001", "rev": 3, "owner": "acct_A"}},
    "notifications": {"notifications": [{"id": "ntf_77", "kind": "access_request_declined",
                                         "subject": {"type": "secret", "id": "res_b_001", "owner": "acct_B"},
                                         "recipient": "acct_A", "read": False,
                                         "created_at": "2026-11-21T08:30:00Z"}], "unread": 1},
    "jsonapi_own_deep": {"data": {"type": "secrets", "id": "res_a_001",
                                  "attributes": {"confidential_marker": A_MARKER,
                                                 "meta": {"audit": {"created_by": {"account": "acct_A"}}}},
                                  "relationships": {"shared_with": {"data": [{"type": "accounts",
                                                                              "id": "acct_B"}]}}}},
    "denied_echo": {"status": "denied",
                    "request": {"resource_id": "res_b_001", "resource_owner": "acct_B",
                                "fields": ["confidential_marker"]},
                    "reason": "caller acct_A is not a member of acct_B"},
    "support_ticket": {"ticket": {"id": "tkt_501", "opened_by": "acct_A", "status": "open",
                                  "body": "I can't open res_b_001 (owner acct_B), it says forbidden. "
                                          "Expected fields: resource_id, resource_owner, confidential_marker."}},
    "b64_own_record": {"requested": "res_b_001", "served": "res_a_001",
                       "payload": _b64(_A), "encoding": "base64"},
    "paged_own_cursor": {"meta": {"filter": {"owner": "acct_B"}, "page": {"size": 2}},
                         "data": [_a_note(1), _a_note(2)],
                         "links": {"next": "/api/accounts/B/secret?page[after]=res_b_001&filter[owner]=acct_B"}},
    "odata_own_entity": {"@odata.context": "https://lab.test/odata/$metadata#Secrets/$entity",
                         "Id": "res_a_001", "OwnerAccount": "acct_A", "ConfidentialMarker": A_MARKER},
    # refusals, errors and limits
    "gql_denied_ja": {"data": {"viewer": {"id": "acct_A", "displayName": "A"}, "secret": None},
                      "errors": [{"message": "このリソースへのアクセス権がありません",
                                  "path": ["secret"], "locations": [{"line": 3, "column": 5}],
                                  "extensions": {"code": "PERMISSION_DENIED", "requiredScope": "secrets:read"}}]},
    "gql_denied_partial": {"data": {"viewer": {"id": "acct_A", "name": "A"}, "secret": None},
                           "errors": [{"message": "Not authorised to access Secret res_b_001",
                                       "path": ["secret"], "extensions": {"code": "UNAUTHORIZED"}}]},
    "gql_rate_limited": {"data": None,
                         "errors": [{"message": "Query cost limit exceeded, retry in 60 seconds",
                                     "extensions": {"code": "RATE_LIMITED", "cost": 1200, "limit": 1000}}]},
    "odata_error_zh": {"error": {"code": "403", "message": {"lang": "zh-CN", "value": "拒绝访问：您无权查看此资源"},
                                 "innererror": {"resource": "res_b_001"}}},
    "odata_error_en": {"error": {"code": "Forbidden", "message": "The caller is not allowed to read this entity."}},
    "envelope_failure": {"success": False, "result": None,
                         "errors": [{"code": 10000, "message": "Authentication error"}], "messages": []},
    "problem_not_found": {"type": "about:blank", "title": "Not Found", "status": 404},
    "invalid_token": {"error": "invalid_token", "error_description": "The access token expired"},
    "not_authenticated": {"error": "authentication required"},
    "not_found": {"error": "not found"},
    "docs": {"docs": "public API introduction"},
}

_OPENAPI = {
    "openapi": "3.1.0", "info": {"title": "Secrets API", "version": "2.4.0"},
    "paths": {"/api/accounts/{account}/secret": {"get": {
        "summary": "Read the secret of an account",
        "responses": {"200": {"description": "The secret", "content": {"application/json": {
            "example": {"resource_id": "res_b_001", "resource_owner": "acct_B",
                        "confidential_marker": "{{confidential_marker}}"}}}},
                      "403": {"description": "The caller does not own the account"}}}}}}

_STATE = {"viewer": "acct_A", "secrets": [{"id": "res_a_001", "marker": A_MARKER}],
          "redirectFrom": RESOURCE, "deniedResource": {"id": "res_b_001", "owner": "acct_B"}}

TEXT_BODIES = {
    "openapi_doc": ("application/vnd.oai.openapi+json", json.dumps(_OPENAPI)),
    "ndjson_export": ("application/x-ndjson", json.dumps(_B) + "\n"),
    "html_card_b": ("text/html; charset=utf-8",
                    "<!doctype html><html><head><title>Secret</title></head><body>"
                    "<header>Signed in as acct_A</header>"
                    "<article class=\"secret\" data-resource=\"res_b_001\"><h2>Secret</h2>"
                    f"<p>Owner: acct_B</p><code>{MARKER}</code></article></body></html>"),
    "html_card_masked": ("text/html; charset=utf-8",
                         "<!doctype html><html><head><title>Secret</title></head><body>"
                         "<header>Signed in as acct_A</header>"
                         "<article class=\"secret\" data-resource=\"res_b_001\"><h2>Secret</h2>"
                         "<p>Owner: acct_B</p><code>&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;</code>"
                         "<p>Only the owner can reveal this value.</p></article></body></html>"),
    "html_state_blob": ("text/html; charset=utf-8",
                        "<!doctype html><html><head><title>My secrets</title></head><body><div id=\"app\"></div>"
                        f"<script id=\"__STATE__\" type=\"application/json\">{json.dumps(_STATE)}</script>"
                        "</body></html>"),
    "html_denied_it": ("text/html; charset=utf-8",
                       "<!doctype html><html lang=\"it\"><head><title>Accesso negato</title></head><body>"
                       "<main class=\"error-page\"><h1>Accesso negato</h1>"
                       "<p>Non disponi dei permessi necessari per visualizzare questa risorsa.</p>"
                       "<a href=\"/\">Torna alla home</a></main></body></html>"),
    "soap_fault_fr": ("text/xml; charset=utf-8",
                      '<?xml version="1.0" encoding="UTF-8"?>'
                      '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
                      "<soap:Fault><faultcode>soap:Client</faultcode>"
                      "<faultstring>Accès refusé : vous n'êtes pas autorisé à consulter cette ressource"
                      "</faultstring></soap:Fault></soap:Body></soap:Envelope>"),
    "html_nginx_429": ("text/html", "<html><head><title>429 Too Many Requests</title></head><body>"
                                    "<center><h1>429 Too Many Requests</h1></center><hr><center>nginx</center>"
                                    "</body></html>"),
    "html_maintenance_503": ("text/html; charset=utf-8",
                             "<!doctype html><html><head><title>Down for maintenance</title></head><body>"
                             "<h1>We'll be back soon</h1><p>Scheduled maintenance until 04:00 UTC.</p>"
                             "</body></html>"),
    # longer than the 65536 characters the lab IDOR check keeps
    "long_hal_b_first": ("application/hal+json",
                         json.dumps({"_links": {"self": {"href": RESOURCE}}, **_B,
                                     "_embedded": {"revisions": _revisions(520)}})),
    "long_ndjson_b_last": ("application/x-ndjson",
                           "".join(json.dumps(_a_note(i)) + "\n" for i in range(1, 801)) + json.dumps(_B) + "\n"),
    "long_odata_a_only": ("application/json",
                          json.dumps({"@odata.context": "https://lab.test/odata/$metadata#Secrets",
                                      "@odata.count": 760, "value": [_a_note(i) for i in range(1, 761)]})),
    # longer than 4 KB but well inside the 65536 characters kept
    "html_long_b_middle": ("text/html; charset=utf-8",
                           "<!doctype html><html><head><title>Secret</title></head><body><nav><ul>"
                           + _nav_html(150) + "</ul></nav><main><table class=\"secret\"><tr><th>Owner</th>"
                           "<td>acct_B</td></tr><tr><th>Resource</th><td>res_b_001</td></tr><tr><th>Value</th>"
                           f"<td>{MARKER}</td></tr></table></main><footer><ul>" + _nav_html(150)
                           + "</ul></footer></body></html>"),
}
EXTRA_HEADERS = {"html_nginx_429": {"Retry-After": "120"}, "html_maintenance_503": {"Retry-After": "3600"},
                 "invalid_token": {"WWW-Authenticate": 'Bearer error="invalid_token"'}}


class HoldoutV5Lab(http.server.ThreadingHTTPServer):
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
