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
        # A page observation accidentally attached to a candidate does not
        # establish the unrelated endpoint named by that candidate.
        self.assertEqual(evidence_status({"verdict": "candidate", "evidence": evidence}), "candidate")
        l2 = [{"audit_hash": "hash", "saved_at": 0, "tool": "reproduction_probe"}]
        for verdict in ("detected", "not_reproduced"):
            self.assertEqual(evidence_status({"verdict": verdict, "evidence": evidence}), verdict)
        # "proven" needs a recorded L2 reproduction; an L1 observation stays "detected"
        self.assertEqual(evidence_status({"verdict": "proven", "evidence": l2}), "proven")
        self.assertEqual(evidence_status({"verdict": "proven", "evidence": evidence}), "detected")
        self.assertEqual(evidence_status({"verdict": "proven", "evidence": [{"audit_hash": "h", "saved_at": 0, "tool": "http_probe"}]}),
                         "detected")
        # an L2 entry without an audit record is not a recorded reproduction
        self.assertEqual(evidence_status({"verdict": "proven", "evidence": evidence + [{"tool": "reproduction_probe"}]}), "detected")
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
        self.assertEqual(status["backends"], ["vulnix-builtin", "model"])
        self.assertNotIn("hidden", str(status))
        self.assertNotIn("do-not-expose", str(status))
        self.assertFalse(status["connected"])

    def test_sse_finding_event_carries_the_same_labels_and_counts_as_snapshot(self):
        finding = {**self.svc.a.findings["f_banner"], "verdict": "proven",
                   "evidence": [{"audit_hash": "recorded", "saved_at": 1, "tool": "reproduction_probe"}]}
        self.svc._upsert_finding(finding)
        event = self.svc.bus.since(0)[-1]
        snap = self.svc.snapshot()
        self.assertEqual(event["type"], "finding.upserted")
        self.assertEqual(event["finding"]["evidence_status"], "proven")
        self.assertEqual(event["evidence_summary"], snap["evidence_summary"])
        self.assertEqual(event["evidence_summary"]["candidate"], 2)
        self.assertEqual(event["evidence_summary"]["proven"], 1)

    def test_inconclusive_record_does_not_add_risk(self):
        finding = {**self.svc.a.findings["f_sqli"], "verdict": "unverified",
                   "evidence": [{"audit_hash": "attempted", "saved_at": 1, "tool": "reproduction_probe"}]}
        self.svc._upsert_finding(finding)
        snap = self.svc.snapshot()
        self.assertEqual(snap["evidence_summary"]["incomplete"], 1)
        self.assertEqual(snap["risk"]["score"], 0)
        self.assertEqual(snap["risk"]["label"], "未計測項目あり")


class TestLabL1Evidence(unittest.TestCase):
    """A root-page observation must not become proof of unrelated API boundaries."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.svc = AssessmentService(Path(self.tmp.name), 18199)

    def tearDown(self):
        self.svc.close()
        self.tmp.cleanup()

    def observe(self, headers):
        self.svc._analyze(
            {"status": 200, "headers": headers, "body_prefix": "<h1>lab</h1>"},
            {"evidence_id": "ev_root", "audit_hash": "root-hash", "saved_at": 1,
             "tool": "http_probe", "target_url": self.svc.a.target_url},
        )
        return {f["id"]: f for f in self.svc.snapshot()["findings"]}

    def test_patched_root_has_no_unobserved_idor_or_sqli_detection(self):
        findings = self.observe({
            "Server": "Apache/2.4.62", "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff", "Strict-Transport-Security": "max-age=63072000",
            "X-Custom-Site": "search and account routes may exist",
        })
        for fid in ("f_idor", "f_sqli"):
            with self.subTest(fid=fid):
                self.assertEqual(findings[fid]["verdict"], "candidate")
                self.assertEqual(findings[fid]["evidence_status"], "candidate")
                self.assertEqual(findings[fid]["evidence"], [])
                self.assertNotIn("ARTEX", findings[fid]["why_detected"])
        self.assertEqual(self.svc.snapshot()["risk"]["score"], 0)

    def test_vulnerable_banner_detects_only_what_the_root_observed(self):
        findings = self.observe({"Server": "Apache/2.4.49", "X-Powered-By": "PHP/8.1.0"})
        self.assertEqual(findings["f_banner"]["evidence_status"], "detected")
        self.assertEqual(findings["f_idor"]["evidence_status"], "candidate")
        self.assertEqual(findings["f_sqli"]["evidence_status"], "candidate")
        measured = [f for f in findings.values() if f["evidence_status"] == "detected"]
        self.assertEqual(self.svc._risk()["score"],
                         round(sum({"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}[f["severity"]] * .6
                                   for f in measured)))


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
