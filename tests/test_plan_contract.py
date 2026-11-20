"""The plan contract: a planner names the check by id (docs/DIAGNOSIS_LOOP_PLAN.md, stage 3)."""
import tests  # noqa: F401
import json
import unittest

from aegis.artex_bridge import diagnosis_observations, reconstruct_contract
from aegis.diagnosis_judge import _verdict
from aegis.diagnosis_state import DiagnosisState
from aegis.plan_contract import parse_steps, step_from_summary

H = "b" * 64


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

    def reason(self, step, **kw):
        accepted, rejected = self.parse([step], **kw)
        self.assertEqual(accepted, [], step)
        return rejected[0]["reason"]

    def test_a_well_formed_step_is_accepted(self):
        accepted, rejected = self.parse([self.ok])
        self.assertEqual(rejected, [])
        self.assertEqual(accepted, [self.ok])

    def test_each_kind_of_bad_step_is_rejected_with_a_reason(self):
        bad = {
            "unexpected_keys": {**self.ok, "url": "https://evil.example/"},
            "missing_keys": {k: v for k, v in self.ok.items() if k != "reason"},
            "unknown_hypothesis": {**self.ok, "hypothesis_id": "H9"},
            "unknown_check": {**self.ok, "catalog_id": "l3_exploit"},
            "unknown_target": {**self.ok, "target_ref": "T2"},
            "target_mismatch": {**self.ok, "target_ref": "T3"},
            "unknown_evidence": {**self.ok, "evidence_refs": ["E7"]},
            "no_evidence": {**self.ok, "evidence_refs": []},
            "duplicate_evidence": {**self.ok, "evidence_refs": ["E1", "E1"]},
            "unknown_reason": {**self.ok, "reason": "because_the_model_said_so"},
            "reason_mismatch": {**self.ok, "reason": "confirm_fix"},
        }
        for want, step in bad.items():
            self.assertEqual(self.reason(step, targets={"T1", "T3"}), want)
        accepted, rejected = self.parse(["run l2_idor on T1"])
        self.assertEqual((accepted, rejected[0]["reason"]), ([], "not_an_object"))

    def test_every_field_has_exactly_its_type(self):
        for key, value in (("hypothesis_id", ["H1"]), ("hypothesis_id", 1), ("catalog_id", None),
                           ("catalog_id", {"id": "l2_idor"}), ("target_ref", ["T1"]), ("target_ref", True),
                           ("evidence_refs", "E1"), ("evidence_refs", [1]), ("evidence_refs", [["E1"]]),
                           ("evidence_refs", {"E1": 1}), ("reason", ["test_hypothesis"]), ("reason", 0),
                           ("hypothesis_id", "H1 OR 1=1"), ("catalog_id", "l2_idor\n"),
                           ("target_ref", "x" * 40), ("evidence_refs", ["E1", "../E2"])):
            self.assertEqual(self.reason({**self.ok, key: value}), "bad_type", (key, value))

    def test_evidence_must_be_about_the_same_target(self):
        self.s.observe(kind="response", target_ref="T2", attrs={}, source="l1", evidence_id="E2")
        self.assertEqual(self.reason({**self.ok, "evidence_refs": ["E1", "E2"]}, targets={"T1", "T2"}),
                         "evidence_other_target")

    def test_evidence_must_be_from_the_current_generation(self):
        self.s.observe(kind="response", target_ref="T1", attrs={}, source="check", evidence_id="E2",
                       audit_hash=H, step_id="S1", catalog_id="l2_idor")
        self.s.apply(_verdict(self.h, "supported", ["E2"], "t"))
        self.s.begin_generation()
        new = self.s.observe(kind="response", target_ref="T1", attrs={}, source="l1")
        h2 = self.s.reopen_for_fix(self.h, basis=[new])
        fix = {**self.ok, "hypothesis_id": h2, "reason": "confirm_fix"}
        self.assertEqual(self.reason({**fix, "evidence_refs": ["E1"]}), "stale_evidence")
        self.assertEqual(self.reason({**fix, "evidence_refs": [new, "E1"]}), "stale_evidence")
        self.assertEqual(self.reason({**fix, "reason": "test_hypothesis", "evidence_refs": [new]}),
                         "reason_mismatch")
        self.assertEqual(self.reason({**self.ok, "evidence_refs": [new]}), "hypothesis_settled")
        accepted, _ = self.parse([{**fix, "evidence_refs": [new]}])
        self.assertEqual(len(accepted), 1)

    def test_a_level_not_allowed_here_is_rejected(self):
        self.assertEqual(self.reason(self.ok, allowed_levels={"L1"}), "level_not_allowed")

    def test_a_settled_or_owner_waiting_hypothesis_gets_no_more_checks(self):
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 403}, source="check",
                       evidence_id="E2", audit_hash=H, step_id="S1", catalog_id="l2_idor")
        self.s.apply(_verdict(self.h, "needs_spec", ["E2"], "spec_missing"))
        self.assertEqual(self.reason(self.ok), "hypothesis_waits_for_owner")
        self.s.apply(_verdict(self.h, "contradicted", ["E2"], "denied"))
        self.assertEqual(self.reason(self.ok), "hypothesis_settled")

    def test_the_same_check_on_the_same_evidence_is_not_repeated(self):
        done = {("l2_idor", "T1", frozenset({"E1"}))}
        self.assertEqual(self.reason(self.ok, executed=done), "repeat")
        # the check's own result is not new evidence for running it again ...
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 200}, source="check",
                       evidence_id="E3", audit_hash=H, step_id="S1", catalog_id="l2_idor")
        self.assertEqual(self.reason({**self.ok, "evidence_refs": ["E1", "E3"]}, executed=done), "repeat")
        # ... but what another check or the owner added is
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 403}, source="check",
                       evidence_id="E4", audit_hash=H, step_id="S2", catalog_id="l1_http_probe")
        accepted, _ = self.parse([{**self.ok, "evidence_refs": ["E1", "E3", "E4"]}], executed=done)
        self.assertEqual(len(accepted), 1)
        accepted, rejected = self.parse([self.ok, dict(self.ok)])
        self.assertEqual((len(accepted), rejected[0]["reason"]), (1, "duplicate_step"))

    def test_older_evidence_in_another_combination_is_still_a_repeat(self):
        self.s.observe(kind="owner_spec", target_ref="T1", attrs={"requirement": "public"},
                       source="owner_spec", evidence_id="E2")
        done = {("l2_idor", "T1", frozenset({"E1"}), self.s.count())}     # ran after E2 existed
        for refs in (["E2"], ["E1", "E2"]):
            self.assertEqual(self.reason({**self.ok, "evidence_refs": refs}, executed=done), "repeat")
        self.s.observe(kind="owner_spec", target_ref="T1", attrs={"requirement": "unspecified"},
                       source="owner_spec", evidence_id="E5")             # measured afterwards
        accepted, _ = self.parse([{**self.ok, "evidence_refs": ["E1", "E5"]}], executed=done)
        self.assertEqual(len(accepted), 1)

    def test_a_reply_that_is_not_a_list_yields_nothing(self):
        for raw in (None, {}, "x", 3):
            accepted, rejected = self.parse(raw)
            self.assertEqual(accepted, [])
            self.assertEqual(rejected[0]["reason"], "not_a_list")
        self.assertEqual(self.parse([self.ok] * 21)[1][0]["reason"], "too_many_steps")


class TestArtexContractTransport(unittest.TestCase):
    """The planner view goes to ARTEX as facts; a step comes back as one JSON intent summary."""

    def setUp(self):
        self.s = DiagnosisState()
        self.s.observe(kind="root_response", target_ref="T1", attrs={"status": 200, "cookie": "sid=abc123"},
                       source="l1")
        self.s.observe(kind="account_resource_link", target_ref="T2", attrs={"present": True}, source="l1",
                       audit_hash=H)
        self.h = self.s.propose(claim="other_account_read", target_ref="T2", basis=["E2"])
        self.targets = [{"asset_id": 1, "target_id": "T1", "url": "http://lab.test:1/"},
                        {"asset_id": 2, "target_id": "T2", "url": "http://lab.test:1/api/accounts/B/secret"}]

    def intent(self, summary, iid=1, **kw):
        return {"id": iid, "summary": summary, "asset_ids": [2], "priority": 5, "unmapped": False, **kw}

    def test_facts_carry_ids_and_states_but_no_raw_values(self):
        facts = diagnosis_observations(self.s.planner_view(), self.targets, {"L1", "L2"})
        text = json.dumps(facts)
        self.assertIn("Vulnix plan contract", text)
        self.assertIn('\\"state\\": \\"open\\"', text)
        for raw in ("abc123", H, "sid="):
            self.assertNotIn(raw, text)

    def test_only_a_contract_step_becomes_an_item(self):
        good = json.dumps({"hypothesis_id": self.h, "catalog_id": "l2_idor", "target_ref": "T2",
                           "evidence_refs": ["E2"], "reason": "test_hypothesis"})
        intents = [self.intent("IDOR cross-account authorization verification", 1),   # free text
                   self.intent(good, 2),
                   self.intent(good.replace('"T2"', '"T1"'), 3),                     # wrong target
                   self.intent(good, 4, unmapped=True),
                   self.intent(good, 5, asset_ids=[99])]
        rec, rejected = reconstruct_contract(intents, self.targets, "ax1", self.s,
                                             allowed_levels=frozenset({"L1", "L2"}))
        self.assertEqual([(i.catalog_id, i.target_id, i.step["hypothesis_id"]) for i in rec.items],
                         [("l2_idor", "T2", self.h)])
        item = rec.items[0]
        self.assertEqual(item.status, "awaiting_approval")
        self.assertEqual(item.proposal["target_id"], "lab")          # the Gateway's engagement target
        self.assertEqual(item.proposal["args"], {"url": "http://lab.test:1/api/accounts/B/secret",
                                                 "check": "idor"})
        self.assertEqual(len(rec.advisories), 4)
        self.assertEqual({r["reason"] for r in rejected}, {"target_mismatch", "unmapped_asset"})

    def test_summary_parsing_is_strict(self):
        for s in ("", "{", "[1]", '{"a": NaN}', "x" * 3000, None, 1, '{"a":1} trailing'):
            self.assertIsNone(step_from_summary(s), s)
        self.assertEqual(step_from_summary(' {"a": 1} '), {"a": 1})


if __name__ == "__main__":
    unittest.main()
