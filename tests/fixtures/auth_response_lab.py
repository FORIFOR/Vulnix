"""Independent loopback responses for HTTP 200 authentication ambiguity."""
from __future__ import annotations

import http.server
import json


BODIES = {
    "protected_data_200": {"owner": "acct_B", "private": "owner-only value"},
    "auth_error_200": {"error": "authentication required"},
    "auth_error_with_code_200": {"error": "authentication required", "code": "AUTH_REQUIRED"},
    "auth_error_no_length_200": {"error": "authentication required"},
    "error_with_data_200": {"error": "authentication required", "private": "owner-only value"},
    "error_string_with_data_200": {"error": "authentication required; owner-only value: 123456"},
}


class AuthResponseLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in BODIES:
            raise ValueError("unknown mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[str] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.seen.append(self.path)
        if self.path != "/":
            self.send_error(404)
            return
        raw = json.dumps(BODIES[self.server.mode]).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if self.server.mode != "auth_error_no_length_200":
            self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
