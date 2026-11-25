import shutil
import tempfile
import unittest
from pathlib import Path
from xml.etree.ElementTree import fromstring

from aegis.local_defense import PROFILE, build_snapshot, classify_result, junit_report
from aegis.runtime import WorkerResult


class TestLocalDefense(unittest.TestCase):
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
        passed = WorkerResult(0, '{"observation":"completed","outcome":"passed"}', "", False, 1)
        failed = WorkerResult(0, '{"observation":"completed","outcome":"failed"}', "", False, 1)
        absent = WorkerResult(0, '{"observation":"completed","outcome":"unverified"}', "", False, 1)
        self.assertEqual(classify_result(passed, True), "passed")
        self.assertEqual(classify_result(failed, True), "failed")
        self.assertEqual(classify_result(absent, True), "unverified")
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
