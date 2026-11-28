"""Open redirect in the lab: a real 3xx, judged from Location only, never followed."""
import tests  # noqa: F401
import argparse
import socket
import unittest

from aegis.lab import set_lab_mode, start_lab
from aegis.redirect_evidence import open_redirect_verdict
from aegis.workers.redirect_probe import PROOF_HOST, run as run_lab_check


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestOpenRedirectLab(unittest.TestCase):
    def setUp(self):
        self.lab = start_lab(_free_port())
        self.port = self.lab.server_address[1]

    def tearDown(self):
        self.lab.shutdown()
        self.lab.server_close()

    def probe(self):
        args = argparse.Namespace(check="open_redirect", ip="127.0.0.1", port=self.port,
                                  host="127.0.0.1", scheme="http")
        return run_lab_check(args)

    def test_vulnerable_lab_redirects_off_site_and_is_proven_without_following(self):
        set_lab_mode("vulnerable", self.lab)
        result = self.probe()
        self.assertEqual(result["verdict"], "proven")
        self.assertTrue(result["control_verified"])
        self.assertIn(result["status"], (301, 302, 303, 307, 308))
        self.assertIn(PROOF_HOST, result["location"])
        self.assertEqual(open_redirect_verdict(result), "proven")

    def test_patched_lab_keeps_both_absolute_and_protocol_relative_targets_on_site(self):
        set_lab_mode("patched", self.lab)
        result = self.probe()
        self.assertEqual(result["verdict"], "not_reproduced")
        self.assertTrue(result["control_verified"])
        self.assertTrue(all(PROOF_HOST not in v["location"] for v in result["variants"]))
        self.assertEqual(len(result["variants"]), 2)
        self.assertEqual(open_redirect_verdict(result), "not_reproduced")

    def test_a_forged_or_incomplete_result_is_never_proven(self):
        set_lab_mode("vulnerable", self.lab)
        result = self.probe()
        for change in ({"control_verified": False}, {"location": "/dashboard"},
                       {"status": 200}, {"check": "sqli"}):
            with self.subTest(change=change):
                self.assertEqual(open_redirect_verdict({**result, **change}), "unverified")


if __name__ == "__main__":
    unittest.main()


class TestOpenRedirectChain(unittest.TestCase):
    """candidate -> approved proof (evidence) -> fix applied -> the same check re-run: not reproduced."""

    def test_proof_then_fix_then_reverification_in_the_lab(self):
        import tempfile
        import time
        from pathlib import Path
        from aegis.assessment import AssessmentService
        lab = start_lab(_free_port())
        try:
            set_lab_mode("vulnerable", lab)
            with tempfile.TemporaryDirectory() as tmp:
                svc = AssessmentService(Path(tmp), lab.server_address[1], verify_seconds=0.01)
                svc._may_switch_lab = True
                try:
                    svc.start("operator")
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        snap = svc.snapshot()
                        pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
                        if pending:
                            before = {f["id"]: f for f in snap["findings"]}["f_open_redirect"]
                            self.assertEqual(before["evidence_status"], "candidate")
                            svc.decide_approval(pending["id"], "approve", "audit")   # a separate approver
                            break
                        time.sleep(0.01)
                    while svc.snapshot()["state"] not in ("completed", "failed") and time.monotonic() < deadline:
                        time.sleep(0.01)
                    found = {f["id"]: f for f in svc.snapshot()["findings"]}["f_open_redirect"]
                    self.assertEqual(found["evidence_status"], "proven")
                    proof = [e for e in found["evidence"] if e.get("tool") == "reproduction_probe" and e.get("audit_hash")]
                    self.assertTrue(proof)
                    self.assertIn("同一サイト", " ".join(found["remediation"]["steps"]))
                    svc.verify_fix("audit", approver_class="security")
                    after = {f["id"]: f for f in svc.snapshot()["findings"]}["f_open_redirect"]
                    self.assertEqual(lab.lab_state.mode, "patched")
                    self.assertEqual(after["evidence_status"], "not_reproduced")
                    self.assertGreater(len(after["evidence"]), len(proof))
                finally:
                    svc.close()
        finally:
            lab.shutdown()
            lab.server_close()
