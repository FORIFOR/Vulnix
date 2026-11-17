"""Independent loopback access target for withheld response combinations.

This target imports no Vulnix detector, planner, Gateway, Worker or truth table.
"""
from __future__ import annotations

import http.server
import json


MODES = frozenset({"private_root_200", "public_root_200", "cross_account_allowed",
                   "cross_account_denied_200", "account_directory_public",
                   "owner_resource_missing", "auth_root_403"})
ACCOUNT_SURFACE = frozenset({"cross_account_allowed", "cross_account_denied_200",
                             "account_directory_public", "owner_resource_missing"})
RESOURCE = "/api/accounts/B/secret"


class AccessHoldoutLab(http.server.ThreadingHTTPServer):
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

    def _send(self, status: int, body: dict, *, link: bool = False):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if link:
            self.send_header("Link", '<' + RESOURCE + '>; rel="account-resource"')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        account = self.headers.get("X-Test-Account")
        mode = self.server.mode
        self.server.seen.append((self.path, account))
        if self.path == "/":
            if mode == "private_root_200":
                return self._send(200, {"owner": "acct_B", "private": "holdout-only record"})
            if mode == "auth_root_403":
                return self._send(403, {"error": "login required"})
            return self._send(200, {"documentation": "public API overview"},
                              link=mode in ACCOUNT_SURFACE)
        if self.path != RESOURCE:
            return self._send(404, {"error": "unknown resource"})
        if mode == "owner_resource_missing" and account == "acct_B":
            return self._send(404, {"error": "record removed"})
        if mode == "account_directory_public":
            return self._send(200, {"directory": "public account list"})
        if account == "acct_B" and mode in ACCOUNT_SURFACE:
            return self._send(200, {
                "Check": "idor_cross_account_access", "established": False,
                "caller_account": "acct_B", "resource_owner": "acct_B",
                "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if account == "acct_A" and mode == "cross_account_allowed":
            return self._send(200, {
                "Check": "idor_cross_account_access", "established": True,
                "caller_account": "acct_A", "resource_owner": "acct_B",
                "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if account == "acct_A" and mode == "owner_resource_missing":
            return self._send(200, {
                "Check": "idor_cross_account_access", "established": True,
                "caller_account": "acct_A", "resource_owner": "acct_B",
                "resource_id": "res_b_001", "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if account == "acct_A" and mode == "cross_account_denied_200":
            return self._send(200, {"error": "access denied", "caller_account": "acct_A",
                                    "resource_owner": "acct_B"})
        return self._send(403, {"error": "forbidden"})
