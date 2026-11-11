"""Non-destructive L1 HTTP & TLS probe worker.

Connects ONLY to the gateway-pinned IP (no DNS lookup), sends one HEAD/GET with
the original Host header / SNI, and never follows redirects.
Collects:
  * HTTP status, headers, redirect_location, body_prefix (4 KB cap)
  * TLS protocol version, cipher suite, and certificate metadata (for HTTPS)
  * All `Set-Cookie` headers (for Secure / HttpOnly / SameSite inspection)
  * CORS response headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`)
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl


def _extract_tls_info(sock: socket.socket, scheme: str) -> dict | None:
    if scheme != "https" or not isinstance(sock, ssl.SSLSocket):
        return None
    cipher = sock.cipher()
    cert = sock.getpeercert() or {}
    subject = dict(x[0] for x in cert.get("subject", ()) if x)
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    return {
        "version": sock.version(),
        "cipher": cipher[0] if cipher else None,
        "bits": cipher[2] if cipher and len(cipher) > 2 else None,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_after": cert.get("notAfter"),
        "verified": True,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--method", default="HEAD", choices=["HEAD", "GET"])
    p.add_argument("--origin", default="https://untrusted-origin.example")
    a = p.parse_args()

    sock = socket.create_connection((a.ip, a.port), timeout=10)
    tls_info = None
    if a.scheme == "https":
        cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
        ctx = ssl.create_default_context(cafile=cafile)
        sock = ctx.wrap_socket(sock, server_hostname=a.host)
        tls_info = _extract_tls_info(sock, a.scheme)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    req_headers = {
        "Host": a.host,
        "User-Agent": "aegis-probe/0.1",
        "Origin": a.origin,
    }
    conn.request(a.method, a.path, headers=req_headers)
    r = conn.getresponse()
    body = r.read(4096) if a.method == "GET" else b""
    raw_cookies = r.msg.get_all("Set-Cookie") or []
    headers_dict = dict(r.getheaders())
    print(json.dumps({
        "status": r.status,
        "headers": headers_dict,
        "set_cookies": raw_cookies,
        "tls": tls_info,
        "cors_probe_origin": a.origin,
        "redirect_location": r.getheader("Location"),  # reported, NOT followed
        "body_prefix": body.decode("utf-8", "replace"),
        "connected_ip": a.ip,
        "connected_port": a.port,
        "scheme": a.scheme,
    }))


if __name__ == "__main__":
    main()
