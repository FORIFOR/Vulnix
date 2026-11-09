"""Worker egress confinement: allow the pinned destination, block everything else."""
import errno
import json
import socket
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from aegis.workers import egress_sentinel as es


class TestPermitted(unittest.TestCase):
    def test_permitted_logic(self):
        allow = {("10.0.0.5", 80)}
        self.assertTrue(es._permitted(socket.AF_INET, ("10.0.0.5", 80), allow))
        self.assertFalse(es._permitted(socket.AF_INET, ("10.0.0.5", 81), allow))   # wrong port
        self.assertFalse(es._permitted(socket.AF_INET, ("10.0.0.6", 80), allow))   # wrong ip
        self.assertFalse(es._permitted(socket.AF_INET, ("evil.example", 80), allow))  # unresolved host
        # Non-IP sockets (e.g. AF_UNIX) are not the thing we confine here.
        self.assertTrue(es._permitted(socket.AF_UNIX, "/tmp/x.sock", allow))

    def test_parse_allow(self):
        self.assertEqual(es._parse_allow(["127.0.0.1/8080"]), {("127.0.0.1", 8080)})
        self.assertEqual(es._parse_allow(["::1/443"]), {("::1", 443)})   # IPv6 keeps colons
        with self.assertRaises(SystemExit):
            es._parse_allow(["127.0.0.1"])        # missing port
        with self.assertRaises(SystemExit):
            es._parse_allow(["127.0.0.1/xx"])     # non-numeric port


class TestInstall(unittest.TestCase):
    def setUp(self):
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(2)
        self.ip, self.port = self.srv.getsockname()
        self._orig = (socket.socket.connect, socket.socket.connect_ex)

    def tearDown(self):
        socket.socket.connect, socket.socket.connect_ex = self._orig
        self.srv.close()

    def test_install_allows_pinned_blocks_others(self):
        es.install({(self.ip, self.port)})
        # Allowed destination connects normally.
        s = socket.socket(); s.settimeout(2)
        s.connect((self.ip, self.port)); s.close()
        # A different port is blocked before any packet leaves.
        with self.assertRaises(PermissionError):
            socket.socket().connect((self.ip, self.port + 1))
        # connect_ex reports EACCES rather than raising.
        self.assertEqual(socket.socket().connect_ex((self.ip, self.port + 1)), errno.EACCES)


class TestBootstrap(unittest.TestCase):
    def test_bootstrap_confines_worker_under_isolated_mode(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(("127.0.0.1", 0)); srv.listen(2)
        _, port = srv.getsockname()
        self.addCleanup(srv.close)

        with tempfile.TemporaryDirectory() as d:
            worker = Path(d) / "probe.py"
            worker.write_text(textwrap.dedent('''
                import socket, sys, json
                allowed, blocked = int(sys.argv[1]), int(sys.argv[2])
                out = {}
                for key, port in (("allowed", allowed), ("blocked", blocked)):
                    try:
                        s = socket.socket(); s.settimeout(2)
                        s.connect(("127.0.0.1", port)); s.close()
                        out[key] = "ok"
                    except Exception as e:
                        out[key] = type(e).__name__
                print(json.dumps(out))
            '''))
            sentinel = Path(es.__file__)
            r = subprocess.run(
                [sys.executable, "-I", str(sentinel), "--allow", f"127.0.0.1/{port}",
                 "--", str(worker), str(port), str(port + 1)],
                capture_output=True, text=True, timeout=20)
            self.assertEqual(r.returncode, 0, r.stderr)
            data = json.loads(r.stdout)
            self.assertEqual(data["allowed"], "ok")             # pinned destination works
            self.assertEqual(data["blocked"], "EgressBlocked")  # everything else is stopped


if __name__ == "__main__":
    unittest.main()
