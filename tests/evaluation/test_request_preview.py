"""Request previews and the common payload (aegis/evaluation/request_builder.py, request_preview.py)."""
import tests  # noqa: F401
import dataclasses
import json
import unittest
from unittest.mock import patch

from aegis.evaluation import request_preview
from aegis.evaluation.model_adapter import MODELS
from aegis.evaluation.request_builder import canonical, common_payload, sha256
from aegis.evaluation.request_preview import config_sha256, cost_estimate, preview
from aegis.diagnosis_state import DiagnosisState


def _payload():
    s = DiagnosisState()
    s.observe(kind="root_response", target_ref="T1", attrs={"status": 200, "account_link": True,
                                                             "cookie": "sid=secret123"}, source="l1")
    s.observe(kind="account_resource_link", target_ref="T2", attrs={"present": True}, source="l1")
    s.observe(kind="owner_spec", target_ref="T2", attrs={"requirement": "authentication_required"},
              source="owner_spec")
    s.propose(claim="other_account_read", target_ref="T2", basis=["E2"])
    return common_payload(s.planner_view(), ["T1", "T2"])


class TestRequestPreview(unittest.TestCase):
    def test_every_model_gets_the_same_common_payload(self):
        p = _payload()
        pvs = [preview(evaluation_id="e", case_id="holdout-001", round_no=1, payload=p, model_key=k) for k in MODELS]
        self.assertEqual(len({v["common_sha256"] for v in pvs}), 1)
        self.assertEqual(len({v["body_sha256"] for v in pvs}), 3)     # only the envelope differs
        for v in pvs:
            self.assertEqual(v["body_sha256"], sha256(v["body"].encode("utf-8")))
            self.assertIn(canonical(p).decode("utf-8"), json.loads(v["body"])["messages"][-1]["content"])
            self.assertFalse(v["sendable"])

    def test_the_payload_has_no_answer_label_url_or_secret(self):
        text = canonical(_payload()).decode("utf-8")
        for bad in ("secret123", "holdout", "supported", "http://", "idor_vulnerable", "acct_"):
            self.assertNotIn(bad, text)
        self.assertNotIn("output_contract", text)      # the schema is in the prompt, never an answer

    def test_changing_a_setting_changes_the_config_hash(self):
        before = config_sha256("claude-sonnet-5-5")
        changed = {**MODELS, "claude-sonnet-5-5": dataclasses.replace(MODELS["claude-sonnet-5-5"],
                                                                      max_output_tokens=4096)}
        with patch.dict(request_preview.MODELS, changed):
            self.assertNotEqual(config_sha256("claude-sonnet-5-5"), before)

    def test_the_worst_case_estimate(self):
        e = cost_estimate(cases=30, rounds=2)
        self.assertEqual(e["total_max_usd"], 3.41184)
        self.assertTrue(e["fits_cap"])
        with_fix = cost_estimate(cases=30, rounds=2, fix_cases=3)
        self.assertEqual(with_fix["total_max_usd"], 3.753024)
        self.assertTrue(with_fix["fits_cap"])


if __name__ == "__main__":
    unittest.main()
