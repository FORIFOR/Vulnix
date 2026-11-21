"""The evaluation runner end to end on held-out cases, with LOCAL stand-in transports
only (no provider is ever contacted; every non-loopback connection is refused)."""
import tests  # noqa: F401
import json
import tempfile
import unittest
from pathlib import Path

from aegis.diagnosis_judge import fixed_rule_steps
from aegis.evaluation.budget_ledger import BudgetLedger, LedgerLimits
from aegis.evaluation.evaluation_runner import Harness, run_case
from aegis.evaluation.network_guard import ExternalConnectionRefused, no_external_connections
from tests import TEST_CONFINEMENT
from tests.artex_mock_llm import MockLLM
from tests.diagnosis_planner import intents_from_facts
from tests.evaluation.fixtures.holdout_lab import CASES, HoldoutLab
from tests.test_artex_bridge import FAKE

TRUTH = json.loads((Path(__file__).parent / "fixtures/holdout_truth.json").read_text())["cases"]
H = Harness(lab_factory=HoldoutLab, confinement=TEST_CONFINEMENT, artex_stand_in=FAKE,
            mock_llm=lambda sel: MockLLM(intent_selector=sel), scripted_intents=intents_from_facts)


def case(category, other):
    return next(c for c, t in sorted(TRUTH.items()) if t["category"] == category and t["other_account_read"] == other)


class _Transport:
    """An in-process stand-in for a provider: reads the body it would have been sent."""
    local = True

    def __init__(self, answer):
        self.answer, self.bodies = answer, []

    def __call__(self, body: bytes, model):
        self.bodies.append(body)
        req = json.loads(body)
        user = req["messages"][-1]["content"]
        steps = self.answer(json.loads(user))
        text = json.dumps({"steps": steps}) if not isinstance(steps, str) else steps
        if model.provider == "anthropic":
            return json.dumps({"content": [{"type": "text", "text": text}], "stop_reason": "end_turn",
                               "usage": {"input_tokens": 900, "output_tokens": 60}}).encode()
        return json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                           "usage": {"prompt_tokens": 900, "completion_tokens": 60}}).encode()


def good_model(payload):
    return fixed_rule_steps(payload)


class TestEvaluationRunner(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.ledger = BudgetLedger(Path(tmp.name) / "ledger.jsonl")

    def test_a_dry_run_previews_and_runs_nothing(self):
        cid = case("authorization_idor", "supported")
        with no_external_connections() as attempts:
            r = run_case(cid, CASES[cid], "model:claude-sonnet-5-5", H)
        self.assertEqual((r["status"], r["other_account_read"], attempts), ("not_run_dry_run", "not_run", []))
        self.assertEqual(len(r["previews"]), 1)
        self.assertEqual((r["worker_launches"], r["model_requests"]), (1, 0))   # the fixed root L1 only
        self.assertEqual(r["planner_input_leaked"], [])

    def test_every_model_runs_the_same_loop_through_the_contract_gateway_and_judge(self):
        cid = case("fix_recheck", "supported")
        for key in ("abliterated-model", "abliterated-model-large-v2", "claude-sonnet-5-5"):
            t = _Transport(good_model)
            with no_external_connections() as attempts:
                r = run_case(cid, CASES[cid], f"model:{key}", H, truth=TRUTH[cid], transport=t, ledger=self.ledger)
            self.assertEqual(attempts, [])
            self.assertEqual(r["other_account_read"], "supported", key)
            self.assertTrue(r["fix_check"]["confirmed_fixed"], key)
            self.assertTrue(r["audit_chain_valid"] and r["every_judgement_cites_an_audited_result"])
            self.assertEqual(r["invalid_replies"], 0)
            self.assertTrue(r["plan_useful"])
            self.assertGreater(r["reserved_usd"], 0)
            self.assertEqual(len(t.bodies), r["model_requests"])
        self.assertLessEqual(self.ledger.summary()["counted_usd"], 5.0)

    def test_a_model_cannot_declare_a_result_or_run_what_the_contract_refuses(self):
        cid = case("decoy_200", "contradicted")

        def liar(payload):
            h = next(h for h in payload["hypotheses"] if h["claim"] == "other_account_read")
            return [{**s, "verdict": "proven"} for s in fixed_rule_steps(payload)] + [
                {"hypothesis_id": h["id"], "catalog_id": "l2_sqli", "target_ref": "T2", "evidence_refs": ["E2"],
                 "reason": "test_hypothesis"}]
        r = run_case(cid, CASES[cid], "model:abliterated-model", H, truth=TRUTH[cid], transport=_Transport(liar),
                     ledger=self.ledger)
        self.assertEqual(r["steps"], [])                   # nothing the model sent passed the contract
        self.assertNotEqual(r["other_account_read"], "supported")
        self.assertGreater(r["steps_rejected"], 0)

    def test_invalid_json_and_timeouts_are_recorded_never_retried(self):
        cid = case("authorization_idor", "supported")
        bad = _Transport(lambda p: "not json at all")
        r = run_case(cid, CASES[cid], "model:abliterated-model", H, transport=bad, ledger=self.ledger)
        self.assertEqual((r["model_requests"], r["invalid_replies"], r["worker_launches"]), (1, 1, 1))

        def timeout(body, model):
            raise TimeoutError()
        timeout.local = True
        r = run_case(cid, CASES[cid], "model:claude-sonnet-5-5", H, transport=timeout, ledger=self.ledger)
        self.assertEqual((r["model_requests"], r["invalid_replies"]), (1, 1))
        self.assertEqual(self.ledger.summary()["reservations"], 2)   # both kept, no refund, no retry

    def test_a_non_local_transport_needs_an_approved_live_ledger(self):
        cid = case("authorization_idor", "supported")
        called = []

        def remote(body, model):
            called.append(body)
            return b"{}"
        r = run_case(cid, CASES[cid], "model:claude-sonnet-5-5", H, transport=remote, ledger=self.ledger)
        self.assertEqual(called, [])                       # the dry-run ledger refused before sending
        self.assertEqual(r["plans"][0]["state"], "FAILED")
        self.assertEqual(r["worker_launches"], 1)          # the fixed root L1 only

    def test_no_real_model_run_before_a_human_label_review(self):
        import hashlib
        from aegis.evaluation.budget_ledger import LedgerError
        from aegis.evaluation.evaluation_runner import LABELS_FILE, require_label_signoff
        digest = hashlib.sha256(LABELS_FILE.read_bytes()).hexdigest()
        good = {"reviewer_kind": "human", "reviewer": "owner", "completed": "2026-11-22",
                "labels_sha256": digest, "disagreements_resolved": True}
        require_label_signoff(good)
        for bad in (None, {**good, "reviewer_kind": "ai"}, {**good, "labels_sha256": "0" * 64},
                    {**good, "reviewer": " "}, {**good, "disagreements_resolved": False}):
            with self.assertRaises(LedgerError):
                require_label_signoff(bad)
        # and the runner refuses a non-local transport without it, before the ledger is asked
        cid = case("authorization_idor", "supported")
        called = []

        def remote(body, model):
            called.append(body)
            return b"{}"
        live = BudgetLedger(self.ledger.path.with_name("live.jsonl"), dry_run=False, external_calls_enabled=True)
        r = run_case(cid, CASES[cid], "model:abliterated-model", H, transport=remote, ledger=live)
        self.assertEqual((called, r["plans"][0]["state"]), ([], "FAILED"))
        self.assertNotIn("send", (live.path.read_text() if live.path.exists() else ""))

    def test_the_budget_cap_stops_requests_before_sending(self):
        tiny = BudgetLedger(self.ledger.path.with_name("tiny.jsonl"), LedgerLimits(max_total_cost_usd=0.03))
        cid = case("replan_contradiction", "supported")
        t = _Transport(good_model)
        r = run_case(cid, CASES[cid], "model:claude-sonnet-5-5", H, transport=t, ledger=tiny)
        self.assertEqual(len(t.bodies), 1)                 # the second round did not fit
        self.assertIn("ledger_over_budget", [x.get("error") for x in r["model_rounds"]])

    def test_the_guard_refuses_external_connections(self):
        import socket
        with no_external_connections() as attempts:
            with self.assertRaises(ExternalConnectionRefused):
                socket.create_connection(("203.0.113.5", 443), timeout=1)
        self.assertEqual(len(attempts), 1)


if __name__ == "__main__":
    unittest.main()
