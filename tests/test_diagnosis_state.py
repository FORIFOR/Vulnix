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


H = "a" * 64


def verdict(hid, to, evidence, rule="test_rule"):
    from aegis.diagnosis_judge import _verdict
    return _verdict(hid, to, evidence, rule)


class TestHypotheses(unittest.TestCase):
    def setUp(self):
        self.s = DiagnosisState()
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 200}, source="l1", evidence_id="E1")
        self.s.observe(kind="response", target_ref="T1", attrs={"status": 403}, source="check",
                       evidence_id="E2", audit_hash=H, step_id="S1", catalog_id="l2_idor")
        self.h = self.s.propose(claim="other_account_read", target_ref="T1", basis=["E1"])

    def test_a_hypothesis_starts_open_and_cites_existing_evidence(self):
        self.assertEqual(self.s.hypothesis(self.h)["state"], "open")
        with self.assertRaises(StateError):
            self.s.propose(claim="other_account_read", target_ref="T2", basis=["E9"])
        with self.assertRaises(StateError):
            self.s.propose(claim="free text from a model", target_ref="T1", basis=["E1"])
        with self.assertRaises(StateError):              # the same claim twice
            self.s.propose(claim="other_account_read", target_ref="T1", basis=["E1"])

    def test_a_hypothesis_cites_evidence_about_its_own_target(self):
        self.s.observe(kind="response", target_ref="T2", attrs={}, source="l1", evidence_id="E3")
        with self.assertRaises(StateError):
            self.s.propose(claim="unauthenticated_exposure", target_ref="T1", basis=["E3"])

    def test_a_check_observation_names_its_audit_hash_and_step(self):
        for kw in ({}, {"audit_hash": H}, {"step_id": "S1"}, {"audit_hash": H, "step_id": "S1"},
                   {"audit_hash": "zz", "step_id": "S1", "catalog_id": "l2_idor"}):
            with self.assertRaises(StateError):
                self.s.observe(kind="response", target_ref="T1", attrs={}, source="check", **kw)
        eid = self.s.observe(kind="response", target_ref="T1", attrs={}, source="check",
                             audit_hash=H, step_id="S2", catalog_id="l2_idor")
        o = self.s.observation(eid)
        self.assertEqual((o["audit_hash"], o["step_id"], o["generation"]), (H, "S2", 1))
        self.assertNotIn(H, repr(self.s.planner_view()))   # hashes never reach a planner

    def test_only_the_fixed_judge_changes_a_state(self):
        from aegis.diagnosis_judge import Verdict
        forged = [Verdict(self.h, "supported", ("E2",), "model_said_so"),
                  Verdict(self.h, "supported", ("E2",), "x", object())]

        class DuckVerdict:
            hypothesis_id, to, evidence, rule = self.h, "supported", ("E2",), "duck"

            def issued_by_judge(self):
                return True
        for v in forged + [DuckVerdict(), {"hypothesis_id": self.h, "to": "supported"}]:
            with self.assertRaises(StateError):
                self.s.apply(v)
        self.assertEqual(self.s.hypothesis(self.h)["state"], "open")
        self.assertFalse(hasattr(self.s, "update"))

    def test_support_and_contradiction_need_evidence_that_was_observed(self):
        with self.assertRaises(StateError):
            self.s.apply(verdict(self.h, "supported", []))
        with self.assertRaises(StateError):
            self.s.apply(verdict(self.h, "contradicted", ["E7"]))
        self.s.apply(verdict(self.h, "contradicted", ["E2"]))
        h = self.s.hypothesis(self.h)
        self.assertEqual((h["state"], h["contradicting"]), ("contradicted", ["E2"]))

    def test_a_settled_verdict_needs_a_measurement_not_only_the_owner_spec(self):
        spec = self.s.observe(kind="owner_spec", target_ref="T1", attrs={"requirement": "public"},
                              source="owner_spec")
        with self.assertRaises(StateError):
            self.s.apply(verdict(self.h, "contradicted", [spec]))
        self.s.apply(verdict(self.h, "needs_spec", [spec]))

    def test_a_settled_hypothesis_is_not_reopened(self):
        self.s.apply(verdict(self.h, "contradicted", ["E2"]))
        for to in ("open", "supported", "inconclusive"):
            with self.assertRaises(StateError):
                self.s.apply(verdict(self.h, to, ["E1"]))

    def test_inconclusive_stays_testable_and_needs_spec_waits_for_the_owner(self):
        self.s.apply(verdict(self.h, "inconclusive", ["E2"]))
        self.assertIn(self.h, [h["id"] for h in self.s.testable()])
        self.s.apply(verdict(self.h, "needs_spec", ["E2"]))
        self.assertEqual(self.s.hypothesis(self.h)["state"], "needs_spec")
        self.assertEqual(self.s.testable(), [])
        self.assertEqual([h["id"] for h in self.s.unresolved()], [self.h])
        self.s.apply(verdict(self.h, "supported", ["E2"]))
        self.assertEqual(self.s.unresolved(), [])

    def test_only_supported_hypotheses_can_become_findings(self):
        self.assertEqual(self.s.finding_candidates(), [])
        with self.assertRaises(StateError):          # the initial L1 alone never supports
            self.s.apply(verdict(self.h, "supported", ["E1"]))
        self.s.apply(verdict(self.h, "supported", ["E2"]))
        self.assertEqual([c["id"] for c in self.s.finding_candidates()], [self.h])

    def test_history_keeps_every_change_with_its_evidence_and_rule(self):
        self.s.apply(verdict(self.h, "inconclusive", ["E2"], "control_failed"))
        self.s.apply(verdict(self.h, "supported", ["E2"], "cross_account_read"))
        hist = [(e["to"], e["evidence"], e["rule"]) for e in self.s.history if e.get("hypothesis") == self.h]
        self.assertEqual(hist, [("open", ["E1"], None), ("inconclusive", ["E2"], "control_failed"),
                                ("supported", ["E2"], "cross_account_read")])


class TestGenerations(unittest.TestCase):
    def setUp(self):
        self.s = DiagnosisState()
        self.s.observe(kind="link", target_ref="T2", attrs={}, source="l1", evidence_id="E1")
        self.s.observe(kind="r", target_ref="T2", attrs={}, source="check", evidence_id="E2",
                       audit_hash=H, step_id="S1", catalog_id="l2_idor")
        self.h = self.s.propose(claim="other_account_read", target_ref="T2", basis=["E1"])

    def test_after_a_fix_old_evidence_is_stale_and_only_a_supported_claim_is_rechecked(self):
        with self.assertRaises(StateError):          # not supported
            self.s.reopen_for_fix(self.h, basis=["E1"])
        self.s.apply(verdict(self.h, "supported", ["E2"]))
        with self.assertRaises(StateError):          # no fix (new generation) yet
            self.s.reopen_for_fix(self.h, basis=["E1"])
        self.s.begin_generation()
        new = self.s.observe(kind="link", target_ref="T2", attrs={}, source="l1")
        with self.assertRaises(StateError):          # built on stale evidence
            self.s.reopen_for_fix(self.h, basis=["E1"])
        h2 = self.s.reopen_for_fix(self.h, basis=[new])
        h = self.s.hypothesis(h2)
        self.assertEqual((h["purpose"], h["supersedes"], h["generation"], h["state"]),
                         ("confirm_fix", self.h, 2, "open"))
        with self.assertRaises(StateError):          # a verdict citing the old generation
            self.s.apply(verdict(h2, "contradicted", ["E2"]))
        self.assertEqual([c["id"] for c in self.s.finding_candidates()], [self.h])


if __name__ == "__main__":
    unittest.main()
