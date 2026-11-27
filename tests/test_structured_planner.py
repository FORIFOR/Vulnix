"""Structured / hybrid planner engines: the schema holds only Vulnix ids, the fixed rule goes
first in hybrid mode, and any model failure leaves the fixed result (nothing is invented)."""
import json
import unittest
from unittest.mock import patch

from aegis import structured_planner as sp

VIEW = {"generation": 1,
        "hypotheses": [{"id": "H1", "claim": "unauthenticated_exposure", "target_ref": "T2", "state": "open",
                        "purpose": "diagnose", "generation": 1, "basis": ["E2"], "supporting": [],
                        "contradicting": [], "inconclusive": []},
                       {"id": "H2", "claim": "other_account_read", "target_ref": "T2", "state": "contradicted",
                        "purpose": "diagnose", "generation": 1, "basis": ["E2"], "supporting": [],
                        "contradicting": ["E4"], "inconclusive": []}],
        "observations": [{"evidence_id": "E2", "kind": "account_resource_link", "target_ref": "T2", "source": "l1",
                          "generation": 1, "attrs": {"present": True}},
                         {"evidence_id": "E4", "kind": "check_result", "target_ref": "T2", "source": "check",
                          "generation": 1, "attrs": {"auth": "none", "status": 404}}]}
TARGETS = [{"target_id": "T2", "asset_id": 7, "checks": ["l1_http_probe", "l2_idor"]}]


class _State:
    def seq(self, _ref):
        return 0

    def observation(self, ref):
        return next(o for o in VIEW["observations"] if o["evidence_id"] == ref) | {"catalog_id": None}


def run(hybrid, answer=None, error=None, executed=frozenset()):
    def fake(view, schema, tried, **kw):
        fake.schema, fake.view = schema, view
        return (None, {"model_calls": 1, "error": error}) if error else (answer, {"model_calls": 1, "format_ok": True})
    fake.schema = None
    with patch.object(sp, "_ask_model", side_effect=fake):
        out = sp.run_structured_planner(VIEW, _State(), TARGETS, executed, llm_url="http://127.0.0.1:9/v1",
                                        llm_key="k", llm_model="qwen3:8b", hybrid=hybrid)
    return out, fake.schema


class TestStructuredPlanner(unittest.TestCase):
    def test_the_schema_holds_only_testable_ids_and_the_targets_checks(self):
        _, schema = run(False, answer=[])
        step = schema["properties"]["steps"]["items"]["properties"]
        self.assertEqual(step["hypothesis_id"]["enum"], ["H1"])                     # H2 is settled
        self.assertEqual(step["catalog_id"]["enum"], ["l1_http_probe", "l2_idor"])  # T2's checks only
        self.assertEqual(step["target_ref"]["enum"], ["T2"])
        self.assertEqual(step["evidence_refs"]["items"]["enum"], ["E2", "E4"])
        self.assertNotIn("confirm_fix", step["reason"]["enum"])
        self.assertEqual(schema["properties"]["steps"]["maxItems"], sp.MAX_STEPS)

    def test_hybrid_uses_the_fixed_rule_first_without_a_model_call(self):
        out, schema = run(True, answer=[{"hypothesis_id": "H1"}])
        self.assertIsNone(schema)
        self.assertEqual(out.provenance["step_source"], "fixed_rule")
        self.assertEqual(out.provenance["model_calls"], 0)
        self.assertEqual(json.loads(out.intents[0]["summary"])["hypothesis_id"], "H1")
        self.assertEqual(out.intents[0]["asset_ids"], [7])

    def test_a_model_failure_or_a_repeat_yields_no_step_never_an_invented_one(self):
        executed = frozenset({("l1_http_probe", "T2", frozenset({"E2", "E4"}), 0)})
        for kwargs in ({"error": "TimeoutError"}, {"answer": []},
                       {"answer": [{"hypothesis_id": "H1", "catalog_id": "l1_http_probe", "target_ref": "T2",
                                    "evidence_refs": ["E2"], "reason": "test_hypothesis"}]},   # a repeat
                       {"answer": [{"free": "text"}]}):
            with self.subTest(kwargs=str(kwargs)[:50]):
                out, _ = run(True, executed=executed, **kwargs)
                self.assertEqual(out.intents, [])
                self.assertEqual(out.provenance["step_source"], "none")

    def test_credential_named_attributes_are_renamed_not_dropped_before_the_gateway(self):
        sent = {}

        class Resp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, _n):
                return json.dumps({"choices": [{"finish_reason": "stop",
                                                "message": {"content": '{"steps": []}'}}]}).encode()

        def opener(req, timeout):
            sent.update(json.loads(req.data))
            return Resp()
        schema = sp.plan_schema(VIEW, ["l1_http_probe"], ["test_hypothesis"])
        with patch("urllib.request.urlopen", side_effect=opener):
            steps, meta = sp._ask_model(VIEW, schema, [], llm_url="http://127.0.0.1:9/v1", llm_key="k",
                                        llm_model="qwen3:8b", no_think=True, timeout_s=5)
        self.assertEqual(steps, [])
        user = json.loads(sent["messages"][1]["content"])
        self.assertEqual(user["observations"][1]["attrs"], {"auth_kind": "none", "status": 404})
        self.assertEqual(sent["response_format"]["type"], "json_schema")
        self.assertEqual(sent["reasoning_effort"], "none")


if __name__ == "__main__":
    unittest.main()
