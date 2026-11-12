"""Non-destructive L1 HTTP & TLS probe worker.

Connects ONLY to the gateway-pinned IP (no DNS lookup), sends one HEAD/GET with
the original Host header / SNI, and never follows redirects.
Collects:
  * HTTP status, headers, redirect_location, body_prefix (4 KB cap)
  * TLS protocol version, cipher suite, and certificate metadata (for HTTPS)
  * All `Set-Cookie` headers (for Secure / HttpOnly / SameSite inspection)
  * CORS response headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials`)
  * per-stage timings (connect, TLS, send, first byte, body)

Timeouts are per stage and share one overall deadline. The time to the first
response byte gets the longest budget: a scale-to-zero service (Cloud Run, App
Engine, Functions...) may need tens of seconds to start an instance, while the
TCP and TLS stages are answered by its front end at once. On failure the worker
prints a JSON object naming the stage and the kind of error (exit code 3)
instead of a traceback, so the control plane can record why it failed.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
import signal
import socket
import ssl
import sys
import time

CONNECT_TIMEOUT_S = 8.0       # TCP connect, and separately the TLS handshake
FIRST_BYTE_TIMEOUT_S = 30.0   # request sent -> status line (cold starts live here)
OVERALL_DEADLINE_S = 45.0     # whole run; the gateway's own limit is above this
MAX_STAGE_TIMEOUT_S = 60.0


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
        "alpn": sock.selected_alpn_protocol(),
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "not_after": cert.get("notAfter"),
        "verified": True,
    }


class DeadlineExceeded(Exception):
    """Raised by SIGALRM when the overall deadline passes, whatever the worker is blocked in.

    Per-recv socket timeouts alone do not bound a run: a target that sends one
    byte at a time resets them on every byte."""


def _on_alarm(signum, frame):  # noqa: ARG001
    raise DeadlineExceeded("overall deadline reached")


class StageError(Exception):
    def __init__(self, stage: str, kind: str, timeout_s: float | None, detail: str):
        super().__init__(detail)
        self.stage, self.kind, self.timeout_s, self.detail = stage, kind, timeout_s, detail


def _kind(e: BaseException) -> str:
    if type(e).__name__ == "EgressBlocked":
        return "egress_blocked"          # the sentinel stopped a connection outside the pinned ip:port
    if isinstance(e, (socket.timeout, TimeoutError, DeadlineExceeded)):
        return "timeout"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "tls_verify_failed"
    if isinstance(e, ssl.SSLError):
        return "tls_error"
    if isinstance(e, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(e, ConnectionResetError):
        return "connection_reset"
    if isinstance(e, http.client.HTTPException):
        return "bad_http_response"
    if isinstance(e, OSError):
        return "network_error"
    return "error"


def probe(a: argparse.Namespace, clock=time.monotonic) -> dict:
    t0 = clock()
    timings: dict[str, int] = {}
    deadline = t0 + min(a.overall_timeout, MAX_STAGE_TIMEOUT_S)

    def budget(stage_timeout: float) -> float:
        left = deadline - clock()
        if left <= 0:
            raise TimeoutError("overall deadline reached")
        return max(0.001, min(stage_timeout, left))

    def stage(name: str, stage_timeout: float, fn):
        start = clock()
        limit = None
        try:
            limit = budget(stage_timeout)
            return fn(limit)
        except DeadlineExceeded:
            raise StageError(name, "timeout", round(min(a.overall_timeout, MAX_STAGE_TIMEOUT_S), 3), "DeadlineExceeded") from None
        except Exception as e:  # noqa: BLE001 - every failure is reported with its stage
            raise StageError(name, _kind(e), None if limit is None else round(limit, 3), type(e).__name__) from None
        finally:
            timings[f"{name}_ms"] = round((clock() - start) * 1000)

    sock = None
    overall = min(a.overall_timeout, MAX_STAGE_TIMEOUT_S)
    use_alarm = hasattr(signal, "setitimer")
    if use_alarm:
        previous = signal.signal(signal.SIGALRM, _on_alarm)
        signal.setitimer(signal.ITIMER_REAL, overall)
    try:
        sock = stage("connect", a.connect_timeout,
                     lambda lim: socket.create_connection((a.ip, a.port), timeout=lim))
        tls_info = None
        if a.scheme == "https":
            cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
            ctx = ssl.create_default_context(cafile=cafile)
            ctx.set_alpn_protocols(["http/1.1"])       # this worker speaks HTTP/1.1 only

            def handshake(lim: float):
                s = ctx.wrap_socket(sock, server_hostname=a.host, do_handshake_on_connect=False)
                s.settimeout(lim)
                s.do_handshake()
                return s, _extract_tls_info(s, a.scheme)
            sock, tls_info = stage("tls", a.connect_timeout, handshake)
        conn = http.client.HTTPConnection(a.host, a.port)
        conn.sock = sock
        req_headers = {
            "Host": a.host,
            "User-Agent": "aegis-probe/0.1",
            "Origin": a.origin,
        }

        def send(lim: float):
            sock.settimeout(lim)
            conn.request(a.method, a.path, headers=req_headers)
        stage("send", a.connect_timeout, send)

        def first_byte(lim: float):
            sock.settimeout(lim)
            return conn.getresponse()
        r = stage("first_byte", a.read_timeout, first_byte)

        def body(lim: float):
            sock.settimeout(lim)
            return r.read(4096) if a.method == "GET" else b""
        raw_body = stage("body", a.read_timeout, body)
        timings["total_ms"] = round((clock() - t0) * 1000)
        return {
            "status": r.status,
            "headers": dict(r.getheaders()),
            "set_cookies": r.msg.get_all("Set-Cookie") or [],
            "tls": tls_info,
            "cors_probe_origin": a.origin,
            "redirect_location": r.getheader("Location"),  # reported, NOT followed
            "body_prefix": raw_body.decode("utf-8", "replace"),
            "connected_ip": a.ip,
            "connected_port": a.port,
            "scheme": a.scheme,
            "timings_ms": timings,
        }
    except StageError as e:
        timings["total_ms"] = round((clock() - t0) * 1000)
        return {
            "error": {"stage": e.stage, "kind": e.kind, "timeout_s": e.timeout_s, "exception": e.detail},
            "connected_ip": a.ip,
            "connected_port": a.port,
            "scheme": a.scheme,
            "timings_ms": timings,
        }
    finally:
        if use_alarm:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _seconds(v: str) -> float:
    x = float(v)
    if not 0 < x <= MAX_STAGE_TIMEOUT_S:
        raise argparse.ArgumentTypeError(f"must be in (0, {MAX_STAGE_TIMEOUT_S}]")
    return x


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--scheme", required=True, choices=["http", "https"])
    p.add_argument("--host", required=True)
    p.add_argument("--ip", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--path", required=True)
    p.add_argument("--method", default="HEAD", choices=["HEAD", "GET"])
    p.add_argument("--origin", default="https://untrusted-origin.example")
    p.add_argument("--connect-timeout", type=_seconds, default=CONNECT_TIMEOUT_S)
    p.add_argument("--read-timeout", type=_seconds, default=FIRST_BYTE_TIMEOUT_S)
    p.add_argument("--overall-timeout", type=_seconds, default=OVERALL_DEADLINE_S)
    a = p.parse_args()
    out = probe(a)
    print(json.dumps(out))
    sys.exit(3 if "error" in out else 0)


if __name__ == "__main__":
    main()
