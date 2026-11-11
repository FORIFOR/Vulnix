"""Trust labels must not promote sample candidates to measured results."""
import tests  # noqa: F401  (hermetic revocation-marker directory)
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.evidence import evidence_status, evidence_summary, reproduction_verdict


class TestEvidenceStatus(unittest.TestCase):
    def test_empty_or_unattached_evidence_never_proves_a_finding(self):
        for verdict in ("detected", "proven", "not_reproduced"):
            for evidence in ([], [{"content": "sample"}], [{"audit_hash": "hash"}]):
                with self.subTest(verdict=verdict, evidence=evidence):
                    self.assertEqual(evidence_status({"verdict": verdict, "evidence": evidence}), "candidate")

    def test_recorded_verdicts_and_interrupted_checks_remain_distinct(self):
        evidence = [{"audit_hash": "hash", "saved_at": 0}]
        for verdict in ("detected", "proven", "not_reproduced"):
            self.assertEqual(evidence_status({"verdict": verdict, "evidence": evidence}), verdict)
        for verdict in ("unverified", "aborted"):
            self.assertEqual(evidence_status({"verdict": verdict, "evidence": evidence}), "incomplete")
        self.assertEqual(evidence_status({"demo_fixture": True, "verdict": "proven", "evidence": evidence}), "fixture")

    def test_summary_is_exhaustive_and_separates_fixtures(self):
        findings = [{"verdict": "detected"}, {"verdict": "aborted"}, {"demo_fixture": True}]
        result = evidence_summary(findings)
        self.assertEqual(sum(result.values()), len(findings))
        self.assertEqual(result["candidate"], 1)
        self.assertEqual(result["proven"], 0)
        self.assertEqual(result["incomplete"], 1)
        self.assertEqual(result["fixture"], 1)


class TestTrustSnapshot(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict("os.environ", {}, clear=True)
        self.env.start()
        self.svc = AssessmentService(Path(self.tmp.name), 18199)

    def tearDown(self):
        self.svc.workers.kill_all()
        self.env.stop()
        self.tmp.cleanup()

    def test_snapshot_and_report_use_actual_runtime_and_scope(self):
        snap = self.svc.snapshot()
        self.assertEqual(snap["lab_endpoint"], "127.0.0.1:18199")
        self.assertEqual(snap["planner"]["mode"], "builtin")
        self.assertFalse(snap["planner"]["external_model_configured"])
        self.assertFalse(snap["planner"]["connection_verified"])
        self.assertEqual(snap["evidence_summary"]["candidate"], 3)
        self.assertTrue(all(f["evidence_status"] == "candidate" for f in snap["findings"]))
        report = self.svc.report_markdown()
        for text in ("未診断（安全性は未評価）", "ローカル模擬ラボ", "未計測の候補 3 件", "架空のデモ履歴", "外部 AI モデルは未設定"):
            self.assertIn(text, report)
        self.assertNotIn("改ざんなし", report)

    def test_configured_endpoint_is_not_reported_connected_and_never_exposed(self):
        # No network request is made, and status reflects the loaded service,
        # not a new environment read that could disagree with its router.
        with patch.dict("os.environ", {"AEGIS_MODEL_URL": "https://example.invalid/private?secret=hidden", "AEGIS_MODEL_KEY": "do-not-expose"}):
            service = AssessmentService(Path(self.tmp.name), 18199)
        status = service.planner_status()
        self.assertEqual(status["mode"], "external_configured")
        self.assertTrue(status["external_model_configured"])
        self.assertFalse(status["connection_verified"])
        self.assertEqual(status["backends"], ["artex-planner", "model"])
        self.assertNotIn("hidden", str(status))
        self.assertNotIn("do-not-expose", str(status))
        self.assertFalse(status["connected"])

    def test_sse_finding_event_carries_the_same_labels_and_counts_as_snapshot(self):
        finding = {**self.svc.a.findings["f_banner"], "verdict": "proven",
                   "evidence": [{"audit_hash": "recorded", "saved_at": 1}]}
        self.svc._upsert_finding(finding)
        event = self.svc.bus.since(0)[-1]
        snap = self.svc.snapshot()
        self.assertEqual(event["type"], "finding.upserted")
        self.assertEqual(event["finding"]["evidence_status"], "proven")
        self.assertEqual(event["evidence_summary"], snap["evidence_summary"])
        self.assertEqual(event["evidence_summary"]["candidate"], 2)
        self.assertEqual(event["evidence_summary"]["proven"], 1)


class TestReproductionVerdict(unittest.TestCase):
    def test_unknown_or_contradictory_responses_never_mean_fixed(self):
        for result in (None, {}, {"check": "idor", "status": 500, "established": False, "verdict": "not_reproduced"},
                       {"check": "idor", "status": 200, "established": False, "verdict": "not_reproduced"},
                       {"check": "idor", "status": 403, "established": True, "verdict": "not_reproduced"},
                       {"check": "idor", "status": 200, "established": True, "verdict": "proven", "response": {}},
                       {"check": "sqli", "status": 403, "established": False, "verdict": "not_reproduced"}):
            with self.subTest(result=result):
                self.assertEqual(reproduction_verdict(result, "idor"), "unverified")

    def test_agreeing_marker_and_http_results(self):
        self.assertEqual(reproduction_verdict({"check": "idor", "status": 200, "established": True,
                         "verdict": "proven", "response": {"marker": "VULNIX_LAB_IDOR_PROVEN"}}, "idor"), "proven")
        self.assertEqual(reproduction_verdict({"check": "idor", "status": 403, "established": False,
                         "verdict": "not_reproduced"}, "idor"), "not_reproduced")
