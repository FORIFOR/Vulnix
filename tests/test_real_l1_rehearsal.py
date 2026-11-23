"""The local rehearsal of docs/REAL_SITE_L1_RUNBOOK.md (scripts/rehearse_real_l1.py).

Everything runs against loopback stand-ins: the rehearsal maps a reserved `.test`
name to 127.0.0.1 through the service's injected resolver and refuses any other
mapping. The full runs go through a subprocess so the runbook's environment settings
never leak into the rest of the suite.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import rehearse_real_l1 as reh

ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> tuple[int, dict]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(reh._DROP_PREFIXES)}
    env["VULNIX_NO_ENV_LOCAL"] = "1"
    proc = subprocess.run([sys.executable, "-m", "scripts.rehearse_real_l1", *args],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
    return proc.returncode, json.loads(proc.stdout)


class TestRehearsalEndToEnd(unittest.TestCase):
    def test_every_runbook_step_passes_against_the_local_mock(self):
        with tempfile.TemporaryDirectory() as out:
            code, result = _run("--out", out)
            self.assertEqual(code, 0, json.dumps([s for s in result.get("steps", []) if not s["ok"]],
                                                 ensure_ascii=False))
            self.assertTrue(result["ok"])
            self.assertEqual(result["runbook_l1_requests"], ["GET /"])
            names = [s["step"].split(" ", 1)[0] for s in result["steps"]]
            self.assertEqual(names, [str(i) for i in range(14)])
            run = next(s for s in result["steps"] if s["step"].startswith("4 "))
            self.assertEqual([(r["method"], r["path"]) for r in run["seen"]], [("GET", "/")])
            self.assertTrue((Path(out) / "report.md").is_file())

    def test_a_request_list_that_drifts_from_the_code_fails_the_rehearsal(self):
        text = (ROOT / "docs" / "REAL_SITE_L1_RUNBOOK.md").read_text(encoding="utf-8")
        drifted = text.replace("<!-- rehearsal:l1-requests:begin -->",
                               "<!-- rehearsal:l1-requests:begin -->\nGET /robots.txt", 1)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "runbook.md"
            path.write_text(drifted, encoding="utf-8")
            code, result = _run("--runbook", str(path))
        self.assertEqual(code, 1)
        failed = [s["step"] for s in result["steps"] if not s["ok"]]
        self.assertTrue(any(name.startswith("4 ") for name in failed), failed)


class TestRefusesAnythingButLoopback(unittest.TestCase):
    def test_non_loopback_mapping_is_refused_before_anything_starts(self):
        # 192.0.2.0/24 is TEST-NET-1 (documentation only); nothing is contacted either way
        code, result = _run("--resolve", f"{reh.HOST}=192.0.2.10")
        self.assertEqual(code, 2)
        self.assertIn("non-loopback", result["refused"])
        self.assertNotIn("steps", result)

    def test_names_outside_the_reserved_test_domain_are_refused(self):
        with self.assertRaises(reh.RefuseToRun):
            reh.preflight_targets({"example.com": ["127.0.0.1"]})
        with self.assertRaises(reh.RefuseToRun):
            reh.preflight_targets({reh.HOST: ["127.0.0.1", "::ffff:192.0.2.1"]})
        reh.preflight_targets({reh.HOST: ["127.0.0.1", "::1"]})

    def test_resolver_rechecks_every_answer(self):
        with self.assertRaises(reh.RefuseToRun):
            reh.loopback_resolver({reh.HOST: ["192.0.2.1"]})(reh.HOST)
        self.assertEqual(reh.loopback_resolver(reh.DEFAULT_TARGETS)(reh.HOST.upper() + "."), ["127.0.0.1"])
        self.assertEqual(reh.loopback_resolver(reh.DEFAULT_TARGETS)("other.test"), [])

    def test_in_process_dns_and_connections_are_confined_to_loopback(self):
        from aegis import ownership
        with reh.no_outside_network():
            with self.assertRaises(OSError):
                socket.getaddrinfo("example.com", 443)
            with socket.socket() as s, self.assertRaises(OSError):
                s.connect(("192.0.2.1", 443))
            with self.assertRaises(OSError):
                ownership.default_dns_txt_lookup("_vulnix-verify.example.com")
            self.assertTrue(socket.getaddrinfo("127.0.0.1", 80))
        self.assertIsNot(socket.socket.connect, None)
        self.assertEqual(ownership.default_dns_txt_lookup.__name__, "default_dns_txt_lookup")


class TestRunbookRequestList(unittest.TestCase):
    def test_runbook_lists_exactly_the_one_root_get(self):
        self.assertEqual(reh.runbook_l1_requests(), [("GET", "/")])


if __name__ == "__main__":
    unittest.main()
