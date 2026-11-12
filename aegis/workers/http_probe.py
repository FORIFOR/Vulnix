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

The overall deadline is enforced with SIGALRM, because per-recv socket timeouts
reset on every byte of a target that drips its answer. `probe()` therefore
belongs to this worker process's main thread: it replaces any SIGALRM timer for
its run. The alarm raises at most once and is caught wherever it lands, also while
a stage error is being reported. Afterwards a previous Python handler is restored;
a default one (SIG_DFL) is not, because a late alarm would then kill the worker
before it prints: a disarmed no-op handler stays installed instead.
Where `signal.setitimer` does not exist (Windows), only the per-stage
timeouts apply and the gateway's own limit is what ends a dripping target; such a
run ends without the structured stage report, so Windows is not equivalent here.
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


class _Alarm:
    """One-shot SIGALRM handler: raises DeadlineExceeded at most once per run, and never
    after disarm(). A second delivery, or one that is still pending when the timer is
    cancelled, is swallowed instead of interrupting the error handling or cleanup.

    It starts disarmed and is armed only inside the protected region, right before its own
    timer is set: a SIGALRM still in flight from an earlier run (macOS can deliver one after
    setitimer(0)) must not raise while the handler is being installed."""

    def __init__(self) -> None:
        self.armed = False
        self.fired = False

    def arm(self) -> None:
        self.armed = True

    def __call__(self, signum, frame):  # noqa: ARG002
        if self.armed and not self.fired:
            self.fired = True
            raise DeadlineExceeded("overall deadline reached")

    def disarm(self) -> None:
        self.armed = False


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


def _stop_alarm(alarm: _Alarm, previous) -> None:
    """Cancel the timer and restore the previous handler without dying of a late alarm.

    A timer that expires around setitimer(0) can still deliver SIGALRM after it: blocking
    and unblocking the signal while the disarmed handler is installed catches one that is
    already pending, but on macOS the expiry was also seen to arrive later than that. With
    SIG_DFL back in place such a late alarm kills the worker (exit 142) before it prints
    anything, so SIG_DFL is not restored: the disarmed handler stays installed and
    swallows a late alarm. (Swapping in SIG_IGN instead races the same way: CPython then
    prints "Signal 14 ignored due to race condition" to stderr.) A previous Python
    handler is restored as it was."""
    alarm.disarm()
    can_mask = hasattr(signal, "pthread_sigmask")
    if can_mask:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        if can_mask:
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    if previous not in (signal.SIG_DFL, None):
        signal.signal(signal.SIGALRM, previous)


def probe(a: argparse.Namespace, clock=time.monotonic) -> dict:
    t0 = clock()
    timings: dict[str, int] = {}
    overall = min(a.overall_timeout, MAX_STAGE_TIMEOUT_S)
    deadline = t0 + overall
    current = {"stage": None}      # the stage being run, for a deadline that lands in its bookkeeping
    held = {"sock": None}          # every socket is recorded here as soon as it exists, and closed at the end

    def budget(stage_timeout: float) -> float:
        left = deadline - clock()
        if left <= 0:
            raise TimeoutError("overall deadline reached")
        return max(0.001, min(stage_timeout, left))

    def stage(name: str, stage_timeout: float, fn):
        current["stage"] = name
        start = clock()
        limit = None
        try:
            limit = budget(stage_timeout)
            value = fn(limit)
        except DeadlineExceeded:
            raise StageError(name, "timeout", round(overall, 3), "DeadlineExceeded") from None
        except Exception as e:  # noqa: BLE001 - every failure is reported with its stage
            raise StageError(name, _kind(e), None if limit is None else round(limit, 3), type(e).__name__) from None
        finally:
            timings[f"{name}_ms"] = round((clock() - start) * 1000)
        # cleared only once the stage has finished: a deadline that lands while its failure
        # is being turned into a StageError, or in this bookkeeping, keeps the stage's name
        current["stage"] = None
        return value

    def error_result(e: StageError) -> dict:
        timings["total_ms"] = round((clock() - t0) * 1000)
        return {
            "error": {"stage": e.stage, "kind": e.kind, "timeout_s": e.timeout_s, "exception": e.detail},
            "connected_ip": a.ip,
            "connected_port": a.port,
            "scheme": a.scheme,
            "timings_ms": timings,
        }

    def deadline_error() -> StageError:
        # a deadline can land outside a stage's own handlers: between two stages, or in the
        # bookkeeping of one (then it is named after that stage)
        return StageError(current["stage"] or "between_stages", "timeout", round(overall, 3), "DeadlineExceeded")

    def run() -> dict:
        sock = stage("connect", a.connect_timeout, lambda lim: _hold(held, socket.create_connection((a.ip, a.port), timeout=lim)))
        tls_info = None
        if a.scheme == "https":
            def handshake(lim: float):
                cafile = os.environ.get("VULNIX_TEST_CA_FILE") or None
                ctx = ssl.create_default_context(cafile=cafile)
                ctx.set_alpn_protocols(["http/1.1"])       # this worker speaks HTTP/1.1 only
                s = _hold(held, ctx.wrap_socket(sock, server_hostname=a.host, do_handshake_on_connect=False))
                s.settimeout(lim)
                s.do_handshake()
                return s, _extract_tls_info(s, a.scheme)
            sock, tls_info = stage("tls", a.connect_timeout, handshake)
        req_headers = {
            "Host": a.host,
            "User-Agent": "aegis-probe/0.1",
            "Origin": a.origin,
        }

        def send(lim: float):
            conn = http.client.HTTPConnection(a.host, a.port)
            conn.sock = sock
            sock.settimeout(lim)
            conn.request(a.method, a.path, headers=req_headers)
            return conn
        conn = stage("send", a.connect_timeout, send)

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

    alarm = _Alarm()
    use_alarm = hasattr(signal, "setitimer")
    previous = None
    result = None
    previous_hook = sys.unraisablehook

    def rearm():
        # the 5 ms timer may itself expire before we return: then it raises right here,
        # and is caught and re-armed again (bounded), so the deadline is never lost
        for _ in range(5):
            try:
                if not alarm.armed:
                    return
                alarm.fired = False
                signal.setitimer(signal.ITIMER_REAL, 0.005)
                return
            except DeadlineExceeded:
                continue

    def swallowed(unraisable):
        # The alarm can land in code whose exceptions Python only reports, e.g. an object's
        # finalizer ("Exception ignored while finalizing file ..."). The deadline would then be
        # lost and the noise would go to stderr: let it fire again a moment later instead.
        # The alarm can also land inside this hook, or inside the previous hook while it
        # handles an unrelated report: caught here too, never raised out of the hook.
        try:
            if isinstance(unraisable.exc_value, DeadlineExceeded):
                rearm()
                return
            previous_hook(unraisable)
        except DeadlineExceeded:
            rearm()

    if use_alarm:
        previous = signal.signal(signal.SIGALRM, alarm)
        sys.unraisablehook = swallowed
    try:
        # The one-shot alarm raises at most once, and only inside this outer try: wherever
        # it lands (a stage, between stages, the handlers below), it is caught here, and
        # the handlers of the outer except cannot be interrupted again.
        try:
            try:
                if use_alarm:
                    alarm.arm()
                    signal.setitimer(signal.ITIMER_REAL, overall)
                result = run()
            except StageError as e:
                result = error_result(e)
            except DeadlineExceeded:
                result = error_result(deadline_error())
            except Exception as e:  # noqa: BLE001 - outside any stage, still no traceback
                result = error_result(StageError(current["stage"] or "between_stages", _kind(e), None, type(e).__name__))
            alarm.disarm()
        except DeadlineExceeded:
            alarm.disarm()
            if result is None:            # a finished result (success or a stage error) is kept as is
                result = error_result(deadline_error())
        return result
    finally:
        if use_alarm:
            _stop_alarm(alarm, previous)
            sys.unraisablehook = previous_hook
        if held["sock"] is not None:
            try:
                held["sock"].close()
            except OSError:
                pass


def _hold(held: dict, s):
    held["sock"] = s
    return s


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
