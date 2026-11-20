"""Independent loopback access-control target with fixed, labelled modes.

The target imports no Vulnix detector, planner, Gateway or Worker code.
"""
from __future__ import annotations

import http.server
import json


MODES = frozenset({"public_json", "auth_required_json", "unauth_exposure",
                   "idor_vulnerable", "denied_403", "denied_404", "confusing_200",
                   "public_json_marker", "protected_json_decoy", "auth_required_account_api",
                   "public_account_directory", "idor_owner_missing", "idor_decoy_marker",
                   "unknown_json"})
ACCOUNT_SURFACE = frozenset({"unauth_exposure", "idor_vulnerable", "denied_403", "denied_404",
                             "confusing_200", "auth_required_account_api", "public_account_directory",
                             "idor_owner_missing", "idor_decoy_marker"})


class AccessControlLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in MODES:
            raise ValueError("unknown fixture mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[tuple[str, str | None]] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: dict, *, account_surface: bool = False):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if account_surface:
            self.send_header("Link", '</api/accounts/B/secret>; rel="account-resource"')
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        account = self.headers.get("X-Test-Account")
        self.server.seen.append((self.path, account))
        mode = self.server.mode
        if self.path == "/":
            if mode in {"auth_required_json", "auth_required_account_api"}:
                return self._send(401, {"error": "authentication required"},
                                  account_surface=mode in ACCOUNT_SURFACE)
            if mode == "unauth_exposure":
                return self._send(200, {"owner": "acct_B", "private": "lab-only note"},
                                  account_surface=True)
            if mode == "public_json_marker":
                return self._send(200, {"docs": "VULNIX_LAB_IDOR_PROVEN is a public example"})
            return self._send(200, {"docs": "public API introduction"},
                              account_surface=mode in ACCOUNT_SURFACE)
        if self.path != "/api/accounts/B/secret":
            return self._send(404, {"error": "not found"})
        if mode in {"denied_404", "idor_owner_missing"} and account == "acct_B":
            return self._send(404, {"error": "not found"})
        if mode == "denied_404":
            return self._send(404, {"error": "not found"})
        if account == "acct_B" and mode in ACCOUNT_SURFACE and mode != "public_account_directory":
            return self._send(200, {"Check": "idor_cross_account_access", "established": False,
                                    "caller_account": "acct_B", "resource_owner": "acct_B",
                                    "resource_id": "res_b_001",
                                    "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        if mode in {"confusing_200", "idor_decoy_marker"}:
            return self._send(200, {"message": "VULNIX_LAB_IDOR_PROVEN is a sample string",
                                    "caller_account": "acct_A", "resource_owner": "acct_A"})
        if mode == "public_account_directory":
            return self._send(200, {"directory": "public account listing"})
        if mode in {"idor_vulnerable", "unauth_exposure", "idor_owner_missing"} and account == "acct_A":
            return self._send(200, {"Check": "idor_cross_account_access", "established": True,
                                    "caller_account": "acct_A", "resource_owner": "acct_B",
                                    "resource_id": "res_b_001",
                                    "confidential_marker": "VULNIX_LAB_IDOR_PROVEN"})
        return self._send(403, {"error": "forbidden"})
