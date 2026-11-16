"""Independent loopback cookie responses; imports no detector or Gateway code."""
from __future__ import annotations

import http.server


COOKIES = {
    "language_plain": "lang=ja; SameSite=Lax",
    "theme_plain": "theme=dark; SameSite=Lax",
    "csrf_js_readable": "csrf=token; Secure; SameSite=Lax",
    "session_no_httponly": "auth=opaque; Secure; SameSite=Lax",
    "session_no_secure": "auth=opaque; HttpOnly; SameSite=Lax",
    "session_no_samesite": "auth=opaque; Secure; HttpOnly",
    "session_full": "auth=opaque; Secure; HttpOnly; SameSite=Lax",
    "session_samesite_none_mismatch": "auth=opaque; Secure; HttpOnly; SameSite=None",
    "session_samesite_none_policy": "auth=opaque; Secure; HttpOnly; SameSite=None",
    "session_like_unknown": "session_theme=dark; SameSite=Lax",
}


class CookiePurposeLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in COOKIES:
            raise ValueError("unknown cookie mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[str] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.server.seen.append(self.path)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", COOKIES[self.server.mode])
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")
