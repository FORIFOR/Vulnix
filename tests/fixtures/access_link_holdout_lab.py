"""Independent loopback targets with previously unseen Link header layouts."""
from __future__ import annotations

import http.server
import json


RESOURCE = "/api/accounts/B/secret"
LINKS = {
    "spaced_parameters_allowed": '</api/accounts/B/secret> ; type="application/json" ; rel="account-resource"',
    "multiple_values_denied": '</api/help>; rel="documentation", </api/accounts/B/secret>; rel="account-resource"',
    "near_relation_public": '</api/accounts/B/secret>; rel="account-resource-preview"',
    "foreign_target_public": '<https://other.test/api/accounts/B/secret>; rel="account-resource"',
    "quoted_comma_decoy": '<https://other.test/api/help>; title="see, </api/accounts/B/secret>; rel=account-resource"',
    "repeated_headers_allowed": [
        '</api/accounts/B/secret>; rel="account-resource"',
        '</api/help>; rel="documentation"',
    ],
    "repeated_headers_decoy": [
        '</api/accounts/B/secret>; rel="account-resource-preview"',
        '<https://other.test/api/accounts/B/secret>; rel="account-resource"',
    ],
}
MODES = frozenset(LINKS)


class AccessLinkHoldoutLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError("unknown link holdout mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[tuple[str, str | None]] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: dict, *, link: str | list[str] | None = None):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for value in ([link] if isinstance(link, str) else link or []):
            self.send_header("Link", value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        mode = self.server.mode
        account = self.headers.get("X-Test-Account")
        self.server.seen.append((self.path, account))
        if self.path == "/":
            return self._send(200, {"documentation": "public account API"}, link=LINKS[mode])
        if self.path != RESOURCE:
            return self._send(404, {"error": "unknown resource"})
        if mode in ("near_relation_public", "foreign_target_public", "quoted_comma_decoy",
                    "repeated_headers_decoy"):
            return self._send(200, {"directory": "public account list"})
        if account == "acct_B":
            return self._send(200, {
                "Check": "idor_cross_account_access", "established": False,
                "caller_account": "acct_B", "resource_owner": "acct_B",
                "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if account == "acct_A" and mode in ("spaced_parameters_allowed", "repeated_headers_allowed"):
            return self._send(200, {
                "Check": "idor_cross_account_access", "established": True,
                "caller_account": "acct_A", "resource_owner": "acct_B",
                "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if account == "acct_A":
            return self._send(200, {"error": "access denied", "caller_account": "acct_A",
                                    "resource_owner": "acct_B"})
        return self._send(403, {"error": "forbidden"})
