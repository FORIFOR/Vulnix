"""Independent loopback target for a proposed public mod_status L1 check.

The vulnerable and patched modes share the same root response and Apache banner.
Only the fixed status endpoint differs. No Vulnix detector code is imported.
"""
from __future__ import annotations

import http.server


class StatusExposureLab(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, mode: str, *, cors_credentials: bool = False):
        if mode not in {"vulnerable", "patched", "generic_200", "non_apache"}:
            raise ValueError("unknown fixture mode")
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.cors_credentials = cors_credentials
        self.banner = "nginx" if mode == "non_apache" else "Apache/2.4.62"
        self.seen: list[str] = []


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.62"
    sys_version = ""

    def version_string(self):
        return self.server.banner

    def log_message(self, *_args):
        pass

    def _send(self, status: int, body: bytes):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.path == "/" and self.server.cors_credentials:
            self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.seen.append(self.path)
        if self.path == "/":
            return self._send(200, b"status lab root\n")
        if self.path == "/server-status?auto":
            if self.server.mode == "vulnerable":
                return self._send(200, b"Total Accesses: 12\nServerUptimeSeconds: 300\n"
                                       b"Client: 203.0.113.1 /private-example\n")
            if self.server.mode == "generic_200":
                return self._send(200, b"This page says server status but is not mod_status.\n")
            return self._send(403, b"Forbidden\n")
        return self._send(404, b"Not found\n")
