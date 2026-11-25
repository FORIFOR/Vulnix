import json
import shutil
import tempfile
import unittest
from pathlib import Path
from xml.etree.ElementTree import fromstring

from aegis.local_defense import PROFILE, build_snapshot, classify_result, junit_report, reviewed_plan, run
from aegis.runtime import WorkerResult


class TestLocalDefense(unittest.TestCase):
    def test_run_rejects_changed_plan_before_reading_source(self):
        with self.assertRaisesRegex(ValueError, "execution plan differs"):
            run(Path("/nonexistent"), {**reviewed_plan(), "timeout_seconds": 60})

    def test_snapshot_rejects_changes_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            snapshot = Path(tmp) / "snapshot"
            for name in PROFILE["files"]:
                dest = root / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(Path(__file__).resolve().parents[1] / name, dest)
            source = root / "tests/test_operators.py"
            source.write_bytes(source.read_bytes() + b"\n")
            with self.assertRaises(ValueError):
                build_snapshot(root, snapshot)
            source.unlink()
            source.symlink_to(Path(__file__))
            with self.assertRaises(ValueError):
                build_snapshot(root, snapshot)

    def test_requires_complete_observations_in_a_live_sandbox(self):
        expected = {"valid_factor": "session", "missing_factor": "mfa_required",
                    "invalid_factor": "mfa_required"}

        def observation(conditions, regression="passed"):
            return WorkerResult(0, json.dumps({"observation": "operator_mfa", "conditions": conditions,
                                               "regression": regression}),
                                "", False, 1)

        passed = observation(expected)
        self.assertEqual(classify_result(passed, True), "passed")
        for condition, unexpected in (("valid_factor", "mfa_required"), ("missing_factor", "session"),
                                      ("invalid_factor", "session")):
            with self.subTest(condition=condition):
                self.assertEqual(classify_result(observation({**expected, condition: unexpected}), True), "failed")
        self.assertEqual(classify_result(observation({"valid_factor": "session"}), True), "unverified")
        self.assertEqual(classify_result(observation({**expected, "invalid_factor": True}), True), "unverified")
        self.assertEqual(classify_result(observation(expected, "unverified"), True), "unverified")
        self.assertEqual(classify_result(observation(expected, "failed"), True), "unverified")
        self.assertEqual(classify_result(WorkerResult(0, '{"outcome":"passed"}', "", False, 1), True),
                         "unverified")
        self.assertEqual(classify_result(passed, False), "unverified")
        passed.output_truncated = True
        self.assertEqual(classify_result(passed, True), "unverified")

    def test_junit_distinguishes_failed_assertions_and_absent_evidence(self):
        for verdict, node in (("passed", None), ("failed", "failure"), ("unverified", "skipped")):
            report = {"plan": PROFILE, "verdict": verdict, "plan_sha256": "1" * 64, "report_sha256": "2" * 64}
            parsed = fromstring(junit_report(report))
            case = parsed.find("testcase")
            self.assertEqual([child.tag for child in case], [node] if node else [])
            self.assertEqual(parsed.find("./properties/property[@name='vulnix.commit']").get("value"),
                             PROFILE["review_revision"])
