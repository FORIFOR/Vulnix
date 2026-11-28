"""A tiny Flask-compatible stand-in (stdlib WSGI) for running fixture apps in tests.

Only what the fixtures use: Flask.route, request.args, redirect. Vulnix does not depend
on Flask; this exists so a Flask-style sample can run on loopback without installing it.
"""
import threading
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, make_server

_local = threading.local()


class _Args(dict):
    def get(self, key, default=None):
        values = dict.get(self, key)
        return values[0] if values else default

    def __getitem__(self, key):
        return dict.__getitem__(self, key)[0]


class _Request:
    @property
    def args(self):
        return _local.args


request = _Request()


class _Response:
    def __init__(self, body="", status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}


def redirect(location, code=302):
    return _Response("", code, {"Location": str(location)})


class Flask:
    def __init__(self, name):
        self.routes = {}

    def route(self, path, **_):
        def register(fn):
            self.routes[path] = fn
            return fn
        return register

    def __call__(self, environ, start_response):
        fn = self.routes.get(environ.get("PATH_INFO", "/"))
        _local.args = _Args(parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True))
        out = fn() if fn else _Response("not found", 404)
        out = out if isinstance(out, _Response) else _Response(str(out))
        reason = {200: "OK", 302: "Found", 404: "Not Found"}.get(out.status, "OK")
        start_response(f"{out.status} {reason}", [("Content-Type", "text/plain"), *out.headers.items()])
        return [out.body.encode()]

    def run(self, host="127.0.0.1", port=5000):
        class Quiet(WSGIRequestHandler):
            def log_message(self, *a):
                pass
        make_server(host, port, self, handler_class=Quiet).serve_forever()
