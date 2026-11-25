import json
import os
import shutil
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from xml.etree.ElementTree import fromstring

from aegis.local_defense import PROFILE, build_snapshot, classify_result, junit_report, reviewed_plan, run
from aegis.local_defense_node import NODE_PROFILE, observation_summary, stage_node_snapshot
from aegis.artex_bridge import planner_hidden_paths
from aegis.confinement import KernelConfinement
from aegis.runtime import WorkerPool, WorkerResult


class TestLocalDefense(unittest.TestCase):
    def test_node_bundle_requires_the_reviewed_manifest_before_staging(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reviewed").mkdir()
            (root / "reviewed" / "snapshot-manifest.json").write_text("{}")
            snapshot = root / "snapshot"
            with self.assertRaisesRegex(ValueError, "digest"):
                stage_node_snapshot(root, snapshot)
            self.assertFalse(snapshot.exists())

    def test_node_summary_requires_the_complete_selected_test_set_and_isolation(self):
        raw = {"success": True, "numPassedTests": 10, "numFailedTests": 0,
               "numPendingTests": 6, "numTotalTests": 16}
        worker = WorkerResult(0, json.dumps(raw), "", False, 1)
        self.assertEqual(observation_summary(worker, True), {"passed": 10, "excluded": 6})
        self.assertIsNone(observation_summary(worker, False))
        self.assertEqual(NODE_PROFILE["automatic_verdict"], False)
        worker.stdout = json.dumps({**raw, "numPassedTests": 9, "numTotalTests": 15})
        self.assertIsNone(observation_summary(worker, True))

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


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("VULNIX_TEST_LOCAL_DEFENSE_KERNEL") == "1",
                     "requires explicit Linux kernel test execution")
class TestLocalDefenseOnLinux(unittest.TestCase):
    def test_real_isolated_observations_for_healthy_blocked_and_missing(self):
        fixture = """
import json, sys
mode = sys.argv[1]

def try_open_fixture(valid_factor):
    if mode == "blocked" or not valid_factor:
        return "mfa_required"
    return "session"

conditions = {"missing_factor": try_open_fixture(False), "valid_factor": try_open_fixture(True)}
if mode != "missing":
    conditions["invalid_factor"] = try_open_fixture(False)
print(json.dumps({"observation": "operator_mfa", "conditions": conditions, "regression": "passed"}))
"""
        confinement = KernelConfinement()
        pool = WorkerPool(max_concurrent=1, cpu_seconds=10)
        self.addCleanup(pool.kill_all)
        try:
            for mode, expected in (("healthy", "passed"), ("blocked", "failed"), ("missing", "unverified")):
                with self.subTest(mode=mode), socket.socket() as reserved:
                    reserved.bind(("127.0.0.1", 0))
                    session = confinement.session("127.0.0.1", reserved.getsockname()[1],
                                                  namespaces={"hide": planner_hidden_paths(), "keep": []})
                    with session:
                        outcome = pool.run([sys.executable, "-I", "-c", fixture, mode], 10, session=session)
                        self.assertTrue(session.still_enforced())
                    self.assertTrue(session.empty())
                    self.assertFalse(session.leftover or session.netns_left or session.files_left)
                    self.assertEqual(classify_result(outcome, True), expected)
        finally:
            if confinement._staged:
                shutil.rmtree(confinement._staged)
