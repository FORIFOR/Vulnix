"""The L1 HTTP probe worker against a local HTTPS stand-in (loopback only).

Reproduces the failure seen against a scale-to-zero service: TCP and TLS are
answered at once by the front end, the first response byte arrives only after
an instance has started. With one 10 s socket timeout the worker died with a
traceback in that wait; it now gives the first byte its own budget and, when a
stage does time out, reports which stage it was.
"""
import json
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER = ROOT / "aegis" / "workers" / "http_probe.py"
HOST = "probe.test"


def _make_cert(d: Path) -> tuple[Path, Path]:
    key, crt = d / "k.pem", d / "c.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(crt),
                    "-days", "1", "-subj", f"/CN={HOST}", "-addext", f"subjectAltName=DNS:{HOST}"],
                   check=True, capture_output=True)
    return crt, key


class _Server:
    """HTTPS (or silent TCP) listener on 127.0.0.1 with a configurable delay before the status line."""

    def __init__(self, crt: Path | None, key: Path | None, delay: float = 0.0, speak_tls: bool = True):
        self.delay, self.speak_tls = delay, speak_tls
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.ctx = None
        if speak_tls:
            self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ctx.load_cert_chain(str(crt), str(key))
            self.ctx.set_alpn_protocols(["http/1.1"])
        self.requests: list[bytes] = []
        self._stop = False
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while not self._stop:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            if not self.speak_tls:
                time.sleep(5)          # accepts TCP, never answers the TLS ClientHello
                return
            s = self.ctx.wrap_socket(c, server_side=True)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = s.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.requests.append(data)
            time.sleep(self.delay)     # "instance starting"
            body = b'{"ok":true}'
            s.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nStrict-Transport-Security: max-age=31536000\r\n"
                      b"Server: Google Frontend\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            s.close()
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self._stop = True
        self.sock.close()


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed to make a test certificate")
class TestHttpProbeStages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.crt, cls.key = _make_cert(Path(cls.tmp.name))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_worker(self, port: int, *extra: str, method: str = "GET"):
        env = {"PATH": "/usr/bin:/bin", "VULNIX_TEST_CA_FILE": str(self.crt)}
        t0 = time.monotonic()
        p = subprocess.run([sys.executable, "-I", str(WORKER), "--scheme", "https", "--host", HOST, "--ip", "127.0.0.1",
                            "--port", str(port), "--path", "/", "--method", method, *extra],
                           capture_output=True, text=True, env=env, timeout=60)
        return p, json.loads(p.stdout), time.monotonic() - t0

    def test_slow_first_byte_within_its_budget_is_a_normal_response(self):
        srv = _Server(self.crt, self.key, delay=1.2)
        try:
            p, out, _ = self.run_worker(srv.port, "--read-timeout", "5")
        finally:
            srv.close()
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(out["status"], 200)
        self.assertEqual(out["tls"]["alpn"], "http/1.1")
        self.assertGreaterEqual(out["timings_ms"]["first_byte_ms"], 1000)
        self.assertGreater(out["timings_ms"]["first_byte_ms"], out["timings_ms"]["tls_ms"])
        self.assertEqual(p.stderr, "")
        self.assertEqual(len(srv.requests), 1)                 # one request, no retry

    def test_first_byte_timeout_is_reported_with_its_stage_not_a_traceback(self):
        srv = _Server(self.crt, self.key, delay=3)
        try:
            p, out, took = self.run_worker(srv.port, "--read-timeout", "0.6")
        finally:
            srv.close()
        self.assertEqual(p.returncode, 3)
        self.assertNotIn("Traceback", p.stderr)
        self.assertEqual(out["error"]["stage"], "first_byte")
        self.assertEqual(out["error"]["kind"], "timeout")
        self.assertAlmostEqual(out["error"]["timeout_s"], 0.6, places=2)
        self.assertIn("tls_ms", out["timings_ms"])
        self.assertLess(took, 5)
        self.assertEqual(len(srv.requests), 1)

    def test_tls_stall_is_a_tls_stage_timeout(self):
        srv = _Server(None, None, speak_tls=False)
        try:
            p, out, _ = self.run_worker(srv.port, "--connect-timeout", "0.5")
        finally:
            srv.close()
        self.assertEqual(p.returncode, 3)
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("tls", "timeout"))

    def test_refused_connection_is_a_connect_stage_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()                                              # nothing listens there now
        p, out, _ = self.run_worker(port)
        self.assertEqual(p.returncode, 3)
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("connect", "connection_refused"))

    def test_overall_deadline_bounds_the_run(self):
        srv = _Server(self.crt, self.key, delay=4)
        try:
            p, out, took = self.run_worker(srv.port, "--read-timeout", "30", "--overall-timeout", "1")
        finally:
            srv.close()
        self.assertEqual(p.returncode, 3)
        self.assertEqual(out["error"]["stage"], "first_byte")
        self.assertLess(took, 4)

    def test_untrusted_certificate_still_fails_verification(self):
        srv = _Server(self.crt, self.key)
        try:
            env = {"PATH": "/usr/bin:/bin"}                    # no test CA: the certificate is not trusted
            p = subprocess.run([sys.executable, "-I", str(WORKER), "--scheme", "https", "--host", HOST, "--ip", "127.0.0.1",
                                "--port", str(srv.port), "--path", "/"], capture_output=True, text=True, env=env, timeout=30)
        finally:
            srv.close()
        out = json.loads(p.stdout)
        self.assertEqual(p.returncode, 3)
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("tls", "tls_verify_failed"))

    def test_redirect_is_reported_not_followed(self):
        srv = _Server(self.crt, self.key)
        orig = srv._serve

        def redirect(c):
            s = srv.ctx.wrap_socket(c, server_side=True)
            s.recv(4096)
            srv.requests.append(b"x")
            s.sendall(b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            s.close()
        srv._serve = redirect
        try:
            p, out, _ = self.run_worker(srv.port)
        finally:
            srv.close()
        self.assertEqual(p.returncode, 0)
        self.assertEqual(out["status"], 302)
        self.assertEqual(out["redirect_location"], "https://elsewhere.example/")
        self.assertEqual(len(srv.requests), 1)
        del orig

    def test_bad_timeout_values_are_refused(self):
        for v in ("0", "-1", "61"):
            p = subprocess.run([sys.executable, "-I", str(WORKER), "--scheme", "https", "--host", HOST, "--ip", "127.0.0.1",
                                "--port", "1", "--path", "/", "--read-timeout", v], capture_output=True, text=True, timeout=30)
            self.assertEqual(p.returncode, 2, v)


class _Drip:
    """Plain-HTTP listener that answers one byte every 0.3 s, in the headers or in the body."""

    def __init__(self, where: str):
        self.where = where
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            c, _ = self.sock.accept()
            c.recv(4096)
            if self.where == "headers":
                head, rest = b"HTTP/1.1 200 OK\r\nX-Slow: ", b"a" * 400
            else:
                head, rest = b"HTTP/1.1 200 OK\r\nContent-Length: 400\r\n\r\n", b"b" * 400
            c.sendall(head)
            for i in range(len(rest)):
                c.sendall(rest[i:i + 1])
                time.sleep(0.3)
        except OSError:
            pass

    def close(self):
        self.sock.close()


SENTINEL = ROOT / "aegis" / "workers" / "egress_sentinel.py"


class TestOverallDeadlineAgainstADrippingTarget(unittest.TestCase):
    """Per-recv timeouts reset on every byte; the overall deadline must still end the run."""

    def run_via_sentinel(self, port: int, allow_port: int | None = None, *extra: str):
        argv = [sys.executable, "-I", str(SENTINEL), "--allow", f"127.0.0.1/{allow_port or port}", "--",
                str(WORKER), "--scheme", "http", "--host", "drip.test", "--ip", "127.0.0.1", "--port", str(port),
                "--path", "/", "--method", "GET", *extra]
        t0 = time.monotonic()
        p = subprocess.run(argv, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"}, timeout=30)
        return p, json.loads(p.stdout), time.monotonic() - t0

    def test_dripping_headers_and_body_end_at_the_deadline_with_a_stage(self):
        for where, stage in (("headers", "first_byte"), ("body", "body")):
            srv = _Drip(where)
            try:
                p, out, took = self.run_via_sentinel(srv.port, None, "--read-timeout", "1", "--overall-timeout", "2")
            finally:
                srv.close()
            self.assertEqual(p.returncode, 3, where)                       # exit code survives the sentinel
            self.assertEqual((out["error"]["stage"], out["error"]["kind"]), (stage, "timeout"), where)
            self.assertLess(took, 4, where)

    def test_a_blocked_destination_is_reported_as_egress_blocked(self):
        srv = _Drip("body")
        try:
            # the sentinel allows another port than the one the worker is told to use
            p, out, _ = self.run_via_sentinel(srv.port, srv.port + 1)
        finally:
            srv.close()
        self.assertEqual(p.returncode, 3)
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("connect", "egress_blocked"))


def _ns(**kw):
    import argparse
    d = dict(scheme="http", host="x.test", ip="127.0.0.1", port=1, path="/", method="GET",
             origin="https://untrusted-origin.example", connect_timeout=1, read_timeout=1, overall_timeout=1)
    d.update(kw)
    return argparse.Namespace(**d)


class _RaisingClock:
    """monotonic() stand-in that raises DeadlineExceeded on its n-th call, as SIGALRM would there."""

    def __init__(self, n: int):
        self.n, self.calls = n, 0

    def __call__(self):
        from aegis.workers import http_probe as hp
        self.calls += 1
        if self.calls == self.n:
            raise hp.DeadlineExceeded("x")
        return time.monotonic()


class TestDeadlineOutsideAStage(unittest.TestCase):
    def test_a_failure_building_the_request_belongs_to_the_send_stage(self):
        from unittest.mock import patch
        from aegis.workers import http_probe as hp
        sock = socket.socket()
        with patch.object(hp.socket, "create_connection", return_value=sock), \
                patch.object(hp.http.client, "HTTPConnection", side_effect=hp.DeadlineExceeded("x")):
            out = hp.probe(_ns())
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("send", "timeout"))

    def test_a_deadline_in_a_stage_bookkeeping_is_named_after_that_stage(self):
        from unittest.mock import patch
        from aegis.workers import http_probe as hp
        sock = socket.socket()
        # calls: t0, connect start, connect budget, connect finally -> raise there, after the socket exists
        with patch.object(hp.socket, "create_connection", return_value=sock):
            out = hp.probe(_ns(), clock=_RaisingClock(4))
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("connect", "timeout"))
        self.assertEqual(sock.fileno(), -1)          # the socket created in that stage is still closed

    def test_a_deadline_while_reporting_a_stage_error_is_still_structured(self):
        from aegis.workers import http_probe as hp
        # port 1 is refused at once; calls: t0, start, budget, finally, then error_result's total -> raise
        out = hp.probe(_ns(), clock=_RaisingClock(5))
        self.assertEqual((out["error"]["stage"], out["error"]["kind"], out["error"]["exception"]),
                         ("connect", "timeout", "DeadlineExceeded"))

    def test_a_deadline_while_a_stage_failure_is_classified_keeps_the_stage(self):
        from unittest.mock import patch
        from aegis.workers import http_probe as hp
        # the alarm lands in stage()'s own except handler, after the socket timeout fired
        with patch.object(hp, "_kind", side_effect=hp.DeadlineExceeded("x")):
            out = hp.probe(_ns())
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("connect", "timeout"))

    @unittest.skipUnless(hasattr(__import__("signal"), "setitimer"), "needs setitimer")
    def test_a_deadline_outside_every_stage_is_between_stages(self):
        from unittest.mock import patch
        from aegis.workers import http_probe as hp
        # the alarm lands right after the timer is armed, before the first stage is entered;
        # the second setitimer call is the cancel in _stop_alarm
        with patch.object(hp.signal, "setitimer", side_effect=[hp.DeadlineExceeded("x"), None]):
            out = hp.probe(_ns())
        self.assertEqual((out["error"]["stage"], out["error"]["kind"]), ("between_stages", "timeout"))

    def test_an_unreadable_test_ca_file_is_a_tls_stage_error(self):
        from unittest.mock import patch
        from aegis.workers import http_probe as hp
        sock = socket.socket()
        with patch.object(hp.socket, "create_connection", return_value=sock), \
                patch.dict("os.environ", {"VULNIX_TEST_CA_FILE": "/nonexistent/ca.pem"}):
            out = hp.probe(_ns(scheme="https"))
        self.assertEqual(out["error"]["stage"], "tls")


_LATE_ALARM = r"""
import os, signal, sys, time, argparse
sys.path.insert(0, sys.argv[1])
from aegis.workers import http_probe as hp
a = argparse.Namespace(scheme="http", host="x.test", ip="127.0.0.1", port=1, path="/", method="GET",
                       origin="o", connect_timeout=1, read_timeout=1, overall_timeout=1)
print(hp.probe(a)["error"]["stage"])
os.kill(os.getpid(), signal.SIGALRM)          # an expiry that arrives after the timer was cancelled
time.sleep(0.05)
print("alive")
"""

_RACE = r"""
import argparse, signal, socket, sys, threading
sys.path.insert(0, sys.argv[1])
from aegis.workers import http_probe as hp
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(512)
held = []
def accept():
    while True:
        try:
            held.append(srv.accept()[0])     # accepts and never answers
        except OSError:
            return
threading.Thread(target=accept, daemon=True).start()
bad = 0
for i in range(int(sys.argv[2])):
    a = argparse.Namespace(scheme="http", host="x.test", ip="127.0.0.1", port=srv.getsockname()[1], path="/",
                           method="GET", origin="o", connect_timeout=5, read_timeout=30, overall_timeout=float(sys.argv[3]))
    try:
        out = hp.probe(a)
        if "error" not in out or out["error"]["kind"] not in ("timeout", "network_error"):
            bad += 1
    except BaseException as e:
        print("ESCAPED", type(e).__name__); bad += 1
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        bad += 1
    while len(held) > 200:
        held.pop(0).close()
print("bad", bad)
"""


@unittest.skipUnless(hasattr(__import__("signal"), "setitimer"), "the SIGALRM deadline exists only where setitimer does")
class TestAlarmRaces(unittest.TestCase):
    """The socket timeout of a stage is cut to the time left, so near the deadline it and SIGALRM
    fire together. Whatever order they land in, the worker must print a result, not die."""

    def py(self, script: str, *args: str):
        return subprocess.run([sys.executable, "-I", "-c", script, str(ROOT), *args],
                              capture_output=True, text=True, timeout=120)

    def test_an_alarm_after_the_run_does_not_kill_the_worker(self):
        p = self.py(_LATE_ALARM)
        self.assertEqual(p.returncode, 0, p.stderr)          # was 142 (killed by SIGALRM) with SIG_DFL restored
        self.assertEqual(p.stdout.split(), ["connect", "alive"])
        self.assertEqual(p.stderr, "")

    def test_deadline_and_socket_timeout_landing_together(self):
        for overall in ("0.001", "0.003"):
            p = self.py(_RACE, "400", overall)
            self.assertEqual(p.returncode, 0, (overall, p.returncode, p.stderr[-2000:]))
            self.assertEqual(p.stdout.strip().splitlines()[-1], "bad 0", (overall, p.stdout[-2000:]))
            self.assertEqual(p.stderr, "", overall)

    def test_a_previous_python_handler_is_restored(self):
        import signal
        from aegis.workers import http_probe as hp
        mine = lambda s, f: None  # noqa: E731
        old = signal.signal(signal.SIGALRM, mine)
        try:
            hp.probe(_ns())
            self.assertIs(signal.getsignal(signal.SIGALRM), mine)
        finally:
            signal.signal(signal.SIGALRM, old)


class TestDowngradedVerdictIsRescored(unittest.TestCase):
    def test_score_and_rationale_follow_the_detected_factor(self):
        from aegis.evidence import enforce_verdict
        from aegis.service_diag import compute_finding_risk_score
        old = {"verdict": "proven", "severity": "high", "risk_score": 80, "risk_rationale": "検証状態係数(proven=1.0)",
               "evidence": [{"audit_hash": "h", "saved_at": 1, "tool": "http_probe", "target_url": "https://svc.example/"}]}
        new = enforce_verdict(old)
        self.assertEqual((new["risk_score"], new["risk_rationale"]),
                         compute_finding_risk_score("high", "detected", internet_facing=True))
        self.assertLess(new["risk_score"], 80)
        self.assertNotIn("proven", new["risk_rationale"])


class TestGatewayLimitCoversWorkerDeadline(unittest.TestCase):
    def test_gateway_kills_only_after_the_worker_could_report(self):
        from aegis.gateway import http_probe_tool
        from aegis.workers import http_probe
        self.assertGreater(http_probe_tool().timeout_s, http_probe.OVERALL_DEADLINE_S)


class TestWorkerFailureIsRecordedWithItsStage(unittest.TestCase):
    def test_failure_text_names_stage_kind_and_limit(self):
        from aegis.assessment import AssessmentService
        from aegis.runtime import WorkerResult
        out = json.dumps({"error": {"stage": "first_byte", "kind": "timeout", "timeout_s": 30.0, "exception": "TimeoutError"}})
        text = AssessmentService._worker_failure_text("http_probe", WorkerResult(3, out, "", False, 31.0))
        self.assertIn("応答の最初のバイト待ち", text)
        self.assertIn("タイムアウト", text)
        self.assertIn("30 秒", text)
        killed = AssessmentService._worker_failure_text("http_probe", WorkerResult(-9, "", "", True, 50.0))
        self.assertIn("停止", killed)
        plain = AssessmentService._worker_failure_text("http_probe", WorkerResult(1, "not json", "", False, 1.0))
        self.assertIn("rc=1", plain)


class TestManagedEdgeServerHeader(unittest.TestCase):
    def analyze(self, headers):
        from aegis.service_diag import analyze_l1_service_response
        res = {"status": 200, "headers": {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
                                          "X-Content-Type-Options": "nosniff", **headers},
               "set_cookies": [], "tls": {"version": "TLSv1.3"}, "cors_probe_origin": "https://untrusted-origin.example"}
        return {f["id"]: f for f in analyze_l1_service_response(res, {"evidence_id": "ev_t"}, "https://svc.example/")}

    def test_platform_front_end_without_version_is_not_reported(self):
        for v in ("Google Frontend", "cloudflare", "Vercel", "AmazonS3"):
            self.assertNotIn("f_powered", self.analyze({"Server": v}), v)

    def test_versions_and_powered_by_are_still_reported_as_detected(self):
        for h in ({"Server": "Apache/2.4.49"}, {"Server": "nginx/1.18.0"}, {"Server": "Google Frontend", "X-Powered-By": "Express"}):
            found = self.analyze(h)
            self.assertIn("f_powered", found, h)
            self.assertEqual(found["f_powered"]["verdict"], "detected")

    def test_no_l1_finding_is_ever_proven(self):
        from aegis.service_diag import analyze_l1_service_response
        res = {"status": 200, "headers": {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4", "Access-Control-Allow-Origin": "*"},
               "set_cookies": ["sid=1; Path=/"], "tls": {"version": "TLSv1.1"}, "cors_probe_origin": "https://untrusted-origin.example"}
        for url in ("https://svc.example/", "http://svc.example/"):
            fs = analyze_l1_service_response(res, {"evidence_id": "ev_t"}, url)
            self.assertTrue(fs)
            self.assertEqual({f["verdict"] for f in fs}, {"detected"}, url)


class TestProvenIsOnlyAnL2Reproduction(unittest.TestCase):
    def test_enforce_verdict(self):
        from aegis.evidence import enforce_verdict
        rec = {"audit_hash": "h", "saved_at": 1}
        self.assertEqual(enforce_verdict({"verdict": "proven", "evidence": [{**rec, "tool": "http_probe"}]})["verdict"], "detected")
        self.assertEqual(enforce_verdict({"verdict": "proven", "evidence": [{**rec, "tool": "reproduction_probe"}]})["verdict"], "proven")
        self.assertEqual(enforce_verdict({"verdict": "not_reproduced", "evidence": []})["verdict"], "not_reproduced")
        self.assertEqual(enforce_verdict({"verdict": "proven", "demo_fixture": True})["verdict"], "proven")   # shown as 架空データ


if __name__ == "__main__":
    unittest.main()
