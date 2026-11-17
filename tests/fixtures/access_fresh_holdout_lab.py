"""Independent loopback target for new owner-contract and response combinations.

This server imports no diagnosis, planner, Gateway, Worker, or truth labels.
"""
from __future__ import annotations

import http.server
import json


MODES = frozenset({"protected_root_denial_200", "public_root_personal_shape",
                   "account_link_denied_404", "account_link_allowed_200"})
RESOURCE = "/api/accounts/B/secret"


class AccessFreshHoldoutLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError("unknown holdout mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[tuple[str, str | None]] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: dict, *, account_link: bool = False):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if account_link:
            self.send_header("Link", f'<{RESOURCE}>; rel="account-resource"')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        mode = self.server.mode
        account = self.headers.get("X-Test-Account")
        self.server.seen.append((self.path, account))
        if self.path == "/":
            if mode == "protected_root_denial_200":
                return self._send(200, {"error": "authentication required",
                                        "request_id": "public-denial-message"})
            if mode == "public_root_personal_shape":
                return self._send(200, {"owner": "acct_B", "private": "published profile field"})
            return self._send(200, {"service": "account gateway", "version": 2},
                              account_link=True)
        if self.path != RESOURCE or mode not in {"account_link_denied_404", "account_link_allowed_200"}:
            return self._send(404, {"error": "unknown resource"})
        if account == "acct_B":
            return self._send(200, {"Check": "idor_cross_account_access",
                                    "established": False, "caller_account": "acct_B",
                                    "resource_owner": "acct_B", "resource_id": "res_b_001",
                                    "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if mode == "account_link_denied_404":
            return self._send(404, {"error": "resource unavailable"})
        if account == "acct_A":
            return self._send(200, {"Check": "idor_cross_account_access",
                                    "established": True, "caller_account": "acct_A",
                                    "resource_owner": "acct_B", "resource_id": "res_b_001",
                                    "confidential_marker": "VULNIX_LAB_IDOR_PROVEN",
                                    "note": "extra field in independent target"})
        return self._send(403, {"error": "forbidden"})
