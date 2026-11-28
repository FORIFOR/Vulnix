"""Measure lab findings against behavior in both independently running lab modes."""
import tests  # noqa: F401  (hermetic revocation-marker directory)
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.lab import set_lab_mode, start_lab


LAB_PORT = 18194
PATCHED_LAB_PORT = 18195
CHECKS = ("f_banner", "f_idor", "f_sqli", "f_open_redirect")
ALL_CHECKS = CHECKS + ("f_headers", "f_powered")


class TestLabAccuracy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)
        cls.patched_lab = start_lab(PATCHED_LAB_PORT)
        set_lab_mode("vulnerable", cls.lab)
        set_lab_mode("patched", cls.patched_lab)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()
        cls.patched_lab.shutdown()
        cls.patched_lab.server_close()

    def run_mode(self, mode, approve):
        lab_port = LAB_PORT if mode == "vulnerable" else PATCHED_LAB_PORT
        lab = self.lab if mode == "vulnerable" else self.patched_lab
        self.assertEqual(lab.lab_state.mode, mode)
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), lab_port, verify_seconds=0.01)
            svc._may_switch_lab = False
            try:
                svc.start("operator")      # the requester; "audit" approves its L2
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    snap = svc.snapshot()
                    pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
                    if pending:
                        l1 = snap
                        svc.decide_approval(pending["id"], "approve" if approve else "reject", "audit")
                        break
                    if snap["state"] == "failed":
                        self.fail(f"lab run failed before approval: {snap['failure']}")
                    time.sleep(0.01)
                else:
                    self.fail("lab run did not request its approval")
                while time.monotonic() < deadline:
                    final = svc.snapshot()
                    if final["state"] in ("completed", "failed"):
                        self.assertEqual(final["state"], "completed", final["failure"])
                        return l1, final
                    time.sleep(0.01)
                self.fail("lab run did not complete")
            finally:
                svc.close()

    def test_l1_candidates_do_not_create_false_positives_on_patched_lab(self):
        vulnerable_l1, vulnerable = self.run_mode("vulnerable", approve=False)
        patched_l1, patched = self.run_mode("patched", approve=False)
        self.assertEqual(vulnerable["state"], "completed")
        self.assertEqual(patched["state"], "completed")
        for snap in (vulnerable_l1, vulnerable, patched_l1, patched):
            by_id = {f["id"]: f for f in snap["findings"]}
            self.assertEqual(by_id["f_idor"]["evidence_status"], "candidate")
            self.assertEqual(by_id["f_sqli"]["evidence_status"], "candidate")
            self.assertEqual(by_id["f_open_redirect"]["evidence_status"], "candidate")
        by_id = {f["id"]: f for f in patched["findings"]}
        self.assertEqual(by_id["f_banner"]["evidence_status"], "candidate")
        self.assertEqual(patched["risk"]["score"], 0)
        patched_analysis = next(p for p in patched_l1["phases"] if p["key"] == "analysis")
        self.assertIn("検出 0 件", patched_analysis["detail"])
        self.assertIn("候補 4 件", patched_analysis["detail"])
        self.assertEqual({f["id"] for f in vulnerable["findings"] if f["evidence_status"] == "detected"},
                         {"f_banner", "f_headers", "f_powered"})

    def test_approved_probes_separate_vulnerable_and_patched_lab(self):
        _, vulnerable = self.run_mode("vulnerable", approve=True)
        _, patched = self.run_mode("patched", approve=True)
        for mode, snap, expected in (("vulnerable", vulnerable, "proven"),
                                     ("patched", patched, "not_reproduced")):
            by_id = {f["id"]: f for f in snap["findings"]}
            for fid in CHECKS:
                with self.subTest(mode=mode, finding=fid):
                    self.assertEqual(by_id[fid]["evidence_status"], expected)
                    self.assertTrue(any(e.get("tool") == "reproduction_probe" and e.get("audit_hash")
                                        for e in by_id[fid]["evidence"]))
        self.assertEqual(patched["risk"]["score"], 0)
        self.assertGreater(vulnerable["risk"]["score"], patched["risk"]["score"])
        patched_verification = next(p for p in patched["phases"] if p["key"] == "verification")
        self.assertNotIn("侵入成立を実証", patched_verification["detail"])
        self.assertIn("再現せず", patched_verification["detail"])

    def test_shared_lab_without_switch_permission_refuses_fix_comparison(self):
        set_lab_mode("vulnerable", self.lab)
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), LAB_PORT)
            svc._may_switch_lab = False
            svc.a.state = "completed"
            try:
                with patch.object(svc, "_exec") as execute:
                    with self.assertRaisesRegex(ValueError, "共有"):
                        svc.verify_fix("audit")
                    execute.assert_not_called()
                self.assertIsNone(svc.a.defense_comparison)
                svc.a.defense_comparison = {"lab_mode": "vulnerable", "before_score": 94, "after_score": 94}
                self.assertIsNone(svc.snapshot()["defense_comparison"])
                svc.a.defense_comparison["lab_mode"] = "patched"
                self.assertIsNone(svc.snapshot()["defense_comparison"])
            finally:
                svc.close()
        self.assertEqual("vulnerable", self.lab.lab_state.mode)

    def test_measured_accuracy_for_the_five_known_lab_conditions(self):
        self.assertIsNot(self.lab, self.patched_lab)
        self.assertNotEqual(self.lab.server_port, self.patched_lab.server_port)
        # six conditions: banner CVE, IDOR, SQLi, open redirect, headers, X-Powered-By
        for approve, expected in ((False, (3, 0, 3, 2, 4)),
                                  (True, (6, 0, 0, 6, 0))):
            vulnerable_l1, vulnerable = self.run_mode("vulnerable", approve)
            patched_l1, patched = self.run_mode("patched", approve)
            positive = vulnerable if approve else vulnerable_l1
            negative = patched if approve else patched_l1
            positive_by_id = {f["id"]: f["evidence_status"] for f in positive["findings"]}
            negative_by_id = {f["id"]: f["evidence_status"] for f in negative["findings"]}
            tp = sum(positive_by_id.get(fid) in ("detected", "proven") for fid in ALL_CHECKS)
            fn = sum(positive_by_id.get(fid) not in ("detected", "proven") for fid in ALL_CHECKS)
            fp = sum(negative_by_id.get(fid) in ("detected", "proven") for fid in ALL_CHECKS)
            tn = sum(negative_by_id.get(fid) in (None, "not_reproduced") for fid in ALL_CHECKS)
            unverified = sum(negative_by_id.get(fid) == "candidate" for fid in ALL_CHECKS)
            self.assertEqual((tp, fp, fn, tn, unverified), expected)
            precision = tp / (tp + fp)
            recall = tp / (tp + fn)
            false_positive_rate = fp / (fp + tn)
            self.assertEqual(precision, 1.0)
            self.assertEqual(recall, 1.0 if approve else 0.5)
            self.assertEqual(false_positive_rate, 0.0)
