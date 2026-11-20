"""The plan contract: a planner names the check by id (docs/DIAGNOSIS_LOOP_PLAN.md, stage 3)."""
import tests  # noqa: F401
import unittest

from aegis.diagnosis_state import DiagnosisState
from aegis.plan_contract import parse_steps


class TestPlanContract(unittest.TestCase):
    def setUp(self):
        self.s = DiagnosisState()
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 200}, source="l1", evidence_id="E1")
        self.h = self.s.propose(claim="other_account_read", target_ref="T1", basis=["E1"])
        self.ok = {"hypothesis_id": self.h, "catalog_id": "l2_idor", "target_ref": "T1",
                   "evidence_refs": ["E1"], "reason": "test_hypothesis"}

    def parse(self, raw, **kw):
        kw.setdefault("targets", {"T1"})
        kw.setdefault("allowed_levels", {"L1", "L2"})
        return parse_steps(raw, self.s, **kw)

    def test_a_well_formed_step_is_accepted(self):
        accepted, rejected = self.parse([self.ok])
        self.assertEqual(rejected, [])
        self.assertEqual(accepted, [self.ok])

    def test_each_kind_of_bad_step_is_rejected_with_a_reason(self):
        bad = {
            "extra_key": {**self.ok, "url": "https://evil.example/"},
            "missing_key": {k: v for k, v in self.ok.items() if k != "reason"},
            "unknown_hypothesis": {**self.ok, "hypothesis_id": "H9"},
            "unknown_check": {**self.ok, "catalog_id": "l3_exploit"},
            "unknown_target": {**self.ok, "target_ref": "T2"},
            "target_mismatch": {**self.ok, "target_ref": "T3"},
            "unknown_evidence": {**self.ok, "evidence_refs": ["E7"]},
            "no_evidence": {**self.ok, "evidence_refs": []},
            "free_text_reason": {**self.ok, "reason": "because the model said so"},
            "not_an_object": "run l2_idor on T1",
        }
        accepted, rejected = self.parse(list(bad.values()), targets={"T1", "T3"})
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), len(bad))
        self.assertTrue(all(r["reason"] for r in rejected))

    def test_a_level_not_allowed_here_is_rejected(self):
        accepted, rejected = self.parse([self.ok], allowed_levels={"L1"})
        self.assertEqual(accepted, [])
        self.assertEqual(rejected[0]["reason"], "level_not_allowed")

    def test_a_settled_hypothesis_gets_no_more_checks(self):
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 403}, source="check", evidence_id="E2")
        self.s.update(self.h, "contradicted", evidence=["E2"])
        accepted, rejected = self.parse([self.ok])
        self.assertEqual((accepted, rejected[0]["reason"]), ([], "hypothesis_settled"))

    def test_the_same_check_on_the_same_evidence_is_not_repeated(self):
        done = {("l2_idor", "T1", frozenset({"E1"}))}
        accepted, rejected = self.parse([self.ok], executed=done)
        self.assertEqual((accepted, rejected[0]["reason"]), ([], "repeat"))
        # new evidence makes the same check worth running again
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 200}, source="check", evidence_id="E3")
        accepted, _ = self.parse([{**self.ok, "evidence_refs": ["E1", "E3"]}], executed=done)
        self.assertEqual(len(accepted), 1)

    def test_a_reply_that_is_not_a_list_yields_nothing(self):
        for raw in (None, {}, "x", 3):
            accepted, rejected = self.parse(raw)
            self.assertEqual(accepted, [])
            self.assertEqual(rejected[0]["reason"], "not_a_list")


if __name__ == "__main__":
    unittest.main()
