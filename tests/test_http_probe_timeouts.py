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
        self.assertLess(out["timings_ms"]["tls_ms"], 1000)
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
