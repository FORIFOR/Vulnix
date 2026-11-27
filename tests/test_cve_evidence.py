"""CVE impact chain: a version match is a candidate; only a lab reproduction confirms impact."""
import tempfile
import time
import unittest
from pathlib import Path

from aegis.cve import CVE
from aegis.cve_evidence import impact_chain, with_reproduction

APACHE = CVE(id="CVE-2021-41773", product="http_server", title="t", severity="critical", cwe="CWE-22",
             affected=({"eq": "2.4.49"}, {"ge": "2.4.49", "lt": "2.4.50"}),
             description="d", remediation="r")


class TestImpactChain(unittest.TestCase):
    def chain(self, version="2.4.49", **kw):
        return impact_chain(APACHE, product="http_server", version=version, version_source="Server ヘッダー", **kw)

    def test_each_link_moves_the_status_only_as_far_as_its_evidence(self):
        self.assertEqual(self.chain("2.4.62")["status"], "not_affected")
        self.assertEqual(self.chain()["status"], "version_match")
        self.assertEqual(self.chain(configuration=True)["status"], "version_match")     # reachability unknown
        self.assertEqual(self.chain(configuration=True, reachable=True)["status"], "conditions_met")
        self.assertEqual(self.chain(configuration=False, reachable=True)["status"], "conditions_unmet")
        self.assertEqual(self.chain(reproduction="proven")["status"], "reproduced")
        self.assertTrue(self.chain(reproduction="proven")["confirmed_impact"])
        for kw in ({}, {"configuration": True, "reachable": True}, {"reproduction": "not_reproduced"}):
            self.assertFalse(self.chain(**kw)["confirmed_impact"])
        c = self.chain()
        self.assertEqual(c["fixed_in"], ["2.4.50"])
        self.assertIn("Require all denied", c["configuration"]["required"])
        self.assertEqual(c["lab_check"], "cve_2021_41773")

    def test_only_a_proof_or_its_failure_changes_the_reproduction_link(self):
        c = self.chain()
        self.assertEqual(with_reproduction(c, "proven")["status"], "reproduced")
        self.assertEqual(with_reproduction(c, "not_reproduced")["status"], "not_reproduced")
        for weak in ("detected", "candidate", "unverified", None):
            self.assertEqual(with_reproduction(c, weak)["status"], "version_match")
        self.assertEqual(with_reproduction(self.chain("2.4.62"), "proven")["status"], "not_affected")

    def test_a_fix_after_a_reproduction_keeps_both_results(self):
        after = with_reproduction(with_reproduction(self.chain("2.4.49"), "proven"), "not_reproduced")
        self.assertEqual(after["lab_history"], ["proven", "not_reproduced"])
        self.assertTrue(after["fixed_after_reproduction"])
        self.assertFalse(with_reproduction(self.chain("2.4.49"), "not_reproduced")["fixed_after_reproduction"])


class TestLabChain(unittest.TestCase):
    """The lab's banner finding carries the chain; the approved reproduction completes it."""

    def test_detected_then_reproduced_then_fixed_in_the_lab(self):
        from aegis.assessment import AssessmentService
        from aegis.lab import set_lab_mode, start_lab
        import socket
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            port = sk.getsockname()[1]
        lab = start_lab(port)
        set_lab_mode("vulnerable", lab)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                svc = AssessmentService(Path(tmp), port, verify_seconds=0.01)
                svc._may_switch_lab = True
                try:
                    svc.start("operator")
                    deadline = time.monotonic() + 15
                    first = None
                    while time.monotonic() < deadline:
                        snap = svc.snapshot()
                        pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
                        if pending:
                            first = {f["id"]: f for f in snap["findings"]}["f_banner"]["cve_evidence"]
                            svc.decide_approval(pending["id"], "approve", "audit")
                            break
                        time.sleep(0.01)
                    while svc.snapshot()["state"] not in ("completed", "failed") and time.monotonic() < deadline:
                        time.sleep(0.01)
                    proven = {f["id"]: f for f in svc.snapshot()["findings"]}["f_banner"]["cve_evidence"]
                    svc.verify_fix("audit", approver_class="security")
                    fixed = {f["id"]: f for f in svc.snapshot()["findings"]}["f_banner"]["cve_evidence"]
                finally:
                    svc.close()
        finally:
            lab.shutdown()
            lab.server_close()
        by = lambda chain: {e["cve"]: e["status"] for e in chain}
        self.assertEqual(by(first).get("CVE-2021-41773"), "version_match")
        self.assertEqual(by(proven).get("CVE-2021-41773"), "reproduced")
        self.assertEqual(by(fixed).get("CVE-2021-41773"), "not_reproduced")
        self.assertTrue(all(e["status"] != "reproduced" for e in proven if e["lab_check"] is None))


if __name__ == "__main__":
    unittest.main()
