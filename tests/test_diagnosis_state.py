"""Observations and hypotheses kept apart from findings (docs/DIAGNOSIS_LOOP_PLAN.md, stage 2)."""
import tests  # noqa: F401
import unittest

from aegis.diagnosis_state import DiagnosisState, StateError


class TestObservations(unittest.TestCase):
    def setUp(self):
        self.s = DiagnosisState()

    def test_an_observation_needs_a_known_source_and_evidence(self):
        with self.assertRaises(StateError):
            self.s.observe(kind="status", target_ref="T1", attrs={"status": 200}, source="model", evidence_id="E1")
        with self.assertRaises(StateError):
            self.s.observe(kind="status", target_ref="T1", attrs={"status": 200}, source="l1", evidence_id="")

    def test_the_planner_view_carries_no_raw_values(self):
        self.s.observe(kind="response", target_ref="T1", source="l1", evidence_id="E1",
                       attrs={"status": 200, "content_kind": "json", "has_marker": True,
                              "cookie": "session=abcdef0123456789", "url": "https://shop.example.com/a?x=1",
                              "body": "顧客 山田 太郎 090-0000-0000"})
        view = self.s.planner_view()
        text = repr(view)
        for raw in ("abcdef0123456789", "shop.example.com", "山田", "090-0000-0000", "https://"):
            self.assertNotIn(raw, text)
        attrs = view["observations"][0]["attrs"]
        self.assertEqual(attrs, {"status": 200, "content_kind": "json", "has_marker": True})

    def test_a_bare_token_value_is_not_passed_on(self):
        # a session id or API key can look like a harmless lowercase token
        self.s.observe(kind="response", target_ref="T1", source="l1", evidence_id="E1",
                       attrs={"session": "abcdef0123456789", "key": "sk_live_51h2k3", "kind2": "json"})
        attrs = self.s.planner_view()["observations"][0]["attrs"]
        self.assertEqual(attrs, {"kind2": "json"})


class TestHypotheses(unittest.TestCase):
    def setUp(self):
        self.s = DiagnosisState()
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 200}, source="l1", evidence_id="E1")
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 403}, source="check", evidence_id="E2")
        self.h = self.s.propose(claim="other_account_read", target_ref="T1", basis=["E1"])

    def test_a_hypothesis_starts_open_and_cites_existing_evidence(self):
        self.assertEqual(self.s.hypothesis(self.h)["state"], "open")
        with self.assertRaises(StateError):
            self.s.propose(claim="other_account_read", target_ref="T1", basis=["E9"])
        with self.assertRaises(StateError):
            self.s.propose(claim="free text from a model", target_ref="T1", basis=["E1"])

    def test_support_and_contradiction_need_evidence_that_was_observed(self):
        with self.assertRaises(StateError):
            self.s.update(self.h, "supported", evidence=[])
        with self.assertRaises(StateError):
            self.s.update(self.h, "contradicted", evidence=["E7"])
        self.s.update(self.h, "contradicted", evidence=["E2"])
        h = self.s.hypothesis(self.h)
        self.assertEqual((h["state"], h["contradicting"]), ("contradicted", ["E2"]))

    def test_a_settled_hypothesis_is_not_reopened(self):
        self.s.update(self.h, "contradicted", evidence=["E2"])
        for to in ("open", "supported", "inconclusive"):
            with self.assertRaises(StateError):
                self.s.update(self.h, to, evidence=["E1"])

    def test_inconclusive_and_needs_spec_stay_open_to_new_evidence(self):
        self.s.update(self.h, "inconclusive", evidence=["E2"])
        self.assertIn(self.h, [h["id"] for h in self.s.unresolved()])
        self.s.update(self.h, "needs_spec", evidence=[])
        self.assertEqual(self.s.hypothesis(self.h)["state"], "needs_spec")
        self.s.update(self.h, "supported", evidence=["E1"])
        self.assertEqual(self.s.unresolved(), [])

    def test_only_supported_hypotheses_can_become_findings(self):
        self.assertEqual(self.s.finding_candidates(), [])
        self.s.update(self.h, "supported", evidence=["E1"])
        self.assertEqual([c["id"] for c in self.s.finding_candidates()], [self.h])

    def test_history_keeps_every_change_with_its_evidence(self):
        self.s.update(self.h, "inconclusive", evidence=["E2"])
        self.s.update(self.h, "supported", evidence=["E1"])
        hist = [(e["to"], e["evidence"]) for e in self.s.history if e["hypothesis"] == self.h]
        self.assertEqual(hist, [("open", ["E1"]), ("inconclusive", ["E2"]), ("supported", ["E1"])])


if __name__ == "__main__":
    unittest.main()
