"""Non-destructive HTTP probe worker.

Connects ONLY to the gateway-pinned IP (no DNS lookup), sends one HEAD/GET with
the original Host header / SNI, and never follows redirects.
"""
import argparse
import http.client
import json
import socket
import ssl


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--method", default="HEAD", choices=["HEAD", "GET"])
    a = p.parse_args()

    sock = socket.create_connection((a.ip, a.port), timeout=10)
    if a.scheme == "https":
        sock = ssl.create_default_context().wrap_socket(sock, server_hostname=a.host)
    conn = http.client.HTTPConnection(a.host, a.port, timeout=10)
    conn.sock = sock
    conn.request(a.method, a.path, headers={"Host": a.host, "User-Agent": "aegis-probe/0.1"})
    r = conn.getresponse()
    body = r.read(4096) if a.method == "GET" else b""
    print(json.dumps({
        "status": r.status,
        "headers": dict(r.getheaders()),
        "redirect_location": r.getheader("Location"),  # reported, NOT followed
        "body_prefix": body.decode("utf-8", "replace"),
        "connected_ip": a.ip,
    }))


if __name__ == "__main__":
    main()
