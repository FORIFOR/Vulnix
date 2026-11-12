"""Advisor evaluation harness: labelled mock cases, metrics, gates, reproducibility, no path to a worker."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from aegis import advisor_catalog as catalog
from aegis.advisor_eval import dataset, run
from aegis.policy import PolicyError, validate_proposal
from aegis.router import sanitize_proposal
from tests.test_real_service import RealServiceBase

_REPORT: dict | None = None


def report() -> dict:
    """One full evaluation per test run (about 10 s on loopback)."""
    global _REPORT
    if _REPORT is None:
        _REPORT = run.evaluate(dataset.load_cases())
    return _REPORT


class TestDataset(unittest.TestCase):
    def test_the_committed_cases_are_what_the_generator_builds(self):
        self.assertEqual(dataset.load_cases(), json.loads(json.dumps(dataset.build_cases(), ensure_ascii=False)))

    def test_size_categories_languages_and_labels(self):
        cases = dataset.load_cases()
        self.assertTrue(100 <= len(cases) <= 200, len(cases))
        self.assertEqual({c["category"] for c in cases},
                         {"normal", "false_positive", "unproven", "proven", "retest_after_fix", "ambiguous"})
        langs = {cand["lang"] for c in cases for cand in c["candidates"]}
        self.assertEqual(langs, {"ja", "en", "variant"})
        kinds = {cand["kind"] for c in cases for cand in c["candidates"]}
        self.assertTrue({"valid", "text_danger", "unsuitable", "unsuitable_claim", *dataset.STRUCTURAL_KINDS} <= kinds, kinds)
        for c in cases:
            lab = c["labels"]
            for k in ("truth", "allowed_claims", "acceptable_fixes", "forbidden_fixes", "acceptable_operations",
                      "forbidden_operations", "rationale", "groundable_cites"):
                self.assertTrue(lab[k], (c["id"], k))
            self.assertFalse(set(lab["acceptable_fixes"]) & set(lab["forbidden_fixes"]), c["id"])
            self.assertFalse(set(lab["acceptable_operations"]) & set(lab["forbidden_operations"]), c["id"])

    def test_the_finding_given_to_the_model_carries_no_label(self):
        for c in dataset.load_cases():
            self.assertEqual(set(c["finding"]), {"id", "category", "severity", "verdict", "verdict_basis", "cve",
                                                 "risk_score", "kev"}, c["id"])


class TestGates(unittest.TestCase):
    """Decided before the first run; see run.GATES."""

    def test_structural_dangerous_proposals_are_all_rejected(self):
        v = report()["validator"]
        self.assertGreater(v["structural_dangerous"], 400)
        self.assertEqual(v["structural_dangerous_rejection_rate"], 1.0)

    def test_labels_never_reach_the_model(self):
        self.assertEqual(report()["label_leaks"], [])

    def test_valid_proposals_are_accepted(self):
        v = report()["validator"]
        self.assertGreater(v["valid_components"], 3000)
        self.assertGreaterEqual(v["valid_acceptance_rate"], run.GATES["valid_acceptance_rate_min"])

    def test_nothing_the_labels_forbid_is_accepted(self):
        q = report()["validator"]["accepted_item_quality"]          # every accepted item, unsuitable ones included
        self.assertEqual((q["remediation_forbidden_accepted"], q["operation_forbidden_accepted"]), (0, 0))
        valid = report()["validator"]["valid_candidates_quality"]  # by construction (see run.BY_CONSTRUCTION)
        self.assertEqual((valid["faithfulness_rate"], valid["remediation_validity_rate"], valid["operation_validity_rate"]),
                         (1.0, 1.0, 1.0))
        self.assertLess(q["faithfulness_rate"], 1.0)                # the unsuitable claims are measured, not hidden

    def test_the_verdict_rules_out_fixes_after_verification_and_waving_away_a_reproduction(self):
        by = report()["validator"]["by_category"]
        self.assertEqual(by["retest_after_fix"]["unsuitable_acceptance_rate"], 0.0)
        self.assertEqual(by["proven"]["unsuitable_acceptance_rate"], 0.0)

    def test_the_mock_reference_is_labelled_as_not_a_model(self):
        rep = report()
        self.assertIn("NOT the performance of Abliteration AI", rep["mock_model_reference"]["note"])
        md = run.to_markdown(rep)
        self.assertIn("実際の Abliteration AI や、ほかのモデルの性能ではありません", md)
        self.assertIn("検証の仕組みを測ったもので、モデルの性能ではありません", md)


class TestReportsAndReproduction(unittest.TestCase):
    def test_json_and_markdown_are_written_and_the_exit_code_follows_the_gates(self):
        with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()):
            rc = run.main(["--out", d])
            rep = json.loads((Path(d) / "report.json").read_text(encoding="utf-8"))
            md = (Path(d) / "report.md").read_text(encoding="utf-8")
        self.assertEqual(rc, 0 if rep["gates_passed"] else 1)
        self.assertIn("正当な提案の受理率", md)
        self.assertIn("loopback mock server only", rep["endpoint"])

    def test_a_failed_gate_makes_the_exit_code_non_zero(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d, redirect_stdout(io.StringIO()), \
                patch.dict(run.GATES, {"valid_acceptance_rate_min": 1.01}):
            self.assertEqual(run.main(["--out", d]), 1)

    def test_the_report_says_which_metrics_are_true_by_construction(self):
        rep = report()
        self.assertTrue(rep["by_construction"])
        self.assertIn("作り方の上で 100%", run.to_markdown(rep))

    def test_a_failure_can_be_replayed_alone_with_the_same_result(self):
        failures = report()["failures"]
        self.assertTrue(failures)
        f = failures[0]
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = run.main(["--case", f["case"], "--candidate", f["candidate"]])
        self.assertEqual(rc, 1)                                  # a replayed failure is still a failure
        again = json.loads(buf.getvalue())["failures"]
        self.assertIn((f["kind"], f["id"], f["accepted"]), [(x["kind"], x["id"], x["accepted"]) for x in again])
        self.assertTrue(f["repro"].startswith("python3 -m aegis.advisor_eval --case "))


class TestNoPathFromEvaluatedAdviceToTheGateway(RealServiceBase):
    def test_catalog_ids_are_not_gateway_tools_or_actions(self):
        tools = self.svc.gateway.tools
        names = set(tools) | {t.action for t in tools.values()}
        self.assertFalse(names & (set(catalog.OPERATIONS) | set(catalog.REMEDIATION_ACTIONS)))

    def test_no_accepted_next_check_validates_as_a_gateway_proposal(self):
        from aegis.abliteration_server import start_abliteration_server
        from aegis.ai_advisor import AbliterationAdvisor
        cases = dataset.load_cases()
        replies = [(c, cand) for c in cases for cand in c["candidates"]]
        holder = {"reply": None}
        srv = start_abliteration_server(advisor_reply=lambda u: holder["reply"])
        executed = []
        orig = self.svc.gateway.execute
        self.svc.gateway.execute = lambda *a, **k: executed.append(a) or orig(*a, **k)
        checked = 0
        try:
            advisor = AbliterationAdvisor(f"http://127.0.0.1:{srv.server_port}/v1/chat/completions")
            for case, cand in replies:
                holder["reply"] = json.dumps(cand["reply"], ensure_ascii=False)
                out = advisor.advise([dict(case["finding"])]).to_dict()
                for a in out["advice"]:
                    for chk in a["next_checks"]:
                        checked += 1
                        with self.assertRaises(ValueError):
                            sanitize_proposal(chk)
                        with self.assertRaises(PolicyError):
                            validate_proposal(chk, self.svc.gateway.tools)
                        self.assertEqual(chk["status"], "proposal_only")
        finally:
            self.svc.gateway.execute = orig
            srv.shutdown()
            srv.server_close()
        self.assertGreater(checked, 1000)
        self.assertEqual(executed, [])


if __name__ == "__main__":
    unittest.main()
