"""Independent loopback CORS policy target; no Vulnix detector imports."""
from __future__ import annotations

import http.server


class CorsPolicyLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str):
        if mode not in {"reflected_credentials", "reflected_public", "public_wildcard", "patched", "generic_200"}:
            raise ValueError("unknown fixture mode")
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
        body = b"public documentation\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        if self.server.mode == "reflected_credentials":
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
        elif self.server.mode == "public_wildcard":
            self.send_header("Access-Control-Allow-Origin", "*")
        elif self.server.mode == "reflected_public":
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        elif self.server.mode == "patched":
            self.send_header("Access-Control-Allow-Origin", "https://trusted.example.test")
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)
