"""Blind, sendable selection fixture; no external model is called by these tests."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts import eval_selection_model as evaluation
from aegis.audit import AuditLog


class TestSelectionModelEval(unittest.TestCase):
    def test_request_contains_only_approved_structural_fields(self):
        request, mapping = evaluation.build_request()
        self.assertEqual(len(mapping), 14)
        self.assertEqual(request["model"], "abliterated-model")
        self.assertEqual(request["max_tokens"], 384)
        self.assertEqual(len(request["messages"]), 2)
        cases = json.loads(request["messages"][1]["content"])["cases"]
        self.assertEqual(len(cases), 14)
        self.assertEqual(set(cases[0]), {"id", "root_access_requirement",
                                         "account_resource_requirement", "account_resource_link_observed"})
        sent = json.dumps(request, ensure_ascii=False)
        for forbidden in ("lab.test", "http://", "https://", "acct_A", "acct_B", "VULNIX_LAB_IDOR_PROVEN",
                          "cross_account_access", "idor_check_appropriate", '"truth":', '"mode":',
                          '"password":', '"token":'):
            self.assertNotIn(forbidden, sent)
        for mode in mapping.values():
            self.assertNotIn(mode, sent)

    def test_untrusted_answer_must_be_exact_and_complete(self):
        _, mapping = evaluation.build_request()
        ids = list(mapping)
        selected = ids[:2]
        valid = {"selected": selected}
        self.assertEqual(evaluation.validate_answer(json.dumps(valid), mapping), set(selected))
        for bad in ({"selected": [ids[0], ids[0]]}, {"selected": ["C99"]},
                    {"selected": "all"}, {"selected": selected, "explanation": "safe"},
                    {"selected": selected, "tool": "run"}):
            with self.assertRaises(ValueError):
                evaluation.validate_answer(json.dumps(bad), mapping)
        with self.assertRaises(ValueError):
            evaluation.validate_answer("```json\n" + json.dumps(valid) + "\n```", mapping)
        with self.assertRaises(ValueError):
            evaluation.validate_answer('{"selected":["C01"],"selected":["C02"]}', mapping)

    def test_preview_is_one_local_gateway_call_and_labels_are_separate(self):
        report = evaluation.run_preview()
        self.assertEqual(report["gateway"]["mode"], "preview")
        self.assertEqual(report["gateway"]["calls"], 1)
        self.assertEqual(report["gateway"]["first_request_sha256"],
                         "52c4598a8c7563a3dc9e9d4a61c89bd6157a0e2bb0faa98a5f015c03931e6c62")
        self.assertEqual(report["gateway"]["budget"]["max_cost_usd"], 0.01)
        self.assertEqual(report["gateway"]["refused"], 0)
        self.assertEqual(report["paid_model_cost_usd"], 0)
        self.assertEqual(report["mock_selection"]["fp"], 0)
        self.assertEqual(report["mock_selection"]["fn"], 0)
        self.assertEqual(report["mock_selection"]["tp"], 8)
        self.assertEqual(len(report["preview_request"]["messages"]), 2)

    def test_approved_path_uses_same_hash_one_call_and_durable_audit(self):
        expected = evaluation.run_preview()["gateway"]["first_request_sha256"]
        seen = []

        def local_transport(url, headers, body):
            seen.append((url, headers, json.loads(body)))
            ids = [c["id"] for c in json.loads(seen[-1][2]["messages"][1]["content"])["cases"][:2]]
            return json.dumps({"choices": [{"message": {"role": "assistant",
                                                      "content": json.dumps({"selected": ids})}}],
                               "usage": {"prompt_tokens": 900, "completion_tokens": 30}}).encode()

        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            with self.assertRaises(ValueError):
                evaluation.run_approved(approval_sha256="0" * 64, api_key="test-only-key",
                                        audit=audit, transport=local_transport)
            self.assertEqual(seen, [])
            result = evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                             audit=audit, transport=local_transport)
            self.assertTrue(audit.verify())
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], "https://api.abliteration.ai/v1/chat/completions")
        self.assertEqual(result["gateway"]["calls"], 1)
        self.assertEqual(result["selection"]["tp"] + result["selection"]["fp"], 2)
        self.assertEqual(result["usage"], {"prompt_tokens": 900, "completion_tokens": 30})
        self.assertNotIn("test-only-key", json.dumps(result))
        self.assertEqual(result["response_adoption_rate"], 1.0)
        self.assertEqual(len(result["selection_errors"]), result["selection"]["fp"] + result["selection"]["fn"])

    def test_unusable_model_answer_is_counted_without_a_finding(self):
        expected = evaluation.run_preview()["gateway"]["first_request_sha256"]
        calls = []

        def bad_transport(*args):
            calls.append(args)
            return json.dumps({"choices": [{"message": {"role": "assistant", "content": "maybe"}}]}).encode()

        with tempfile.TemporaryDirectory() as tmp:
            result = evaluation.run_approved(
                approval_sha256=expected, api_key="test-only-key",
                audit=AuditLog(Path(tmp) / "audit.jsonl"), transport=bad_transport)
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["accepted"])
        self.assertIsNone(result["selection"])
        self.assertEqual(result["selected_case_ids"], [])
        self.assertEqual(result["response_adoption_rate"], 0.0)
        self.assertEqual(result["reject_reason"], "invalid_json")

    def test_wrong_choices_name_false_positive_and_missed_cases(self):
        _, mapping = evaluation.build_request()
        truth = evaluation.truth_ids(mapping)
        chosen = {next(iter(truth)), next(case for case in mapping if case not in truth)}
        errors = evaluation.selection_errors(chosen, mapping)
        self.assertEqual(sum(e["kind"] == "false_positive" for e in errors), 1)
        self.assertEqual(sum(e["kind"] == "missed" for e in errors), len(truth) - 1)
        self.assertEqual({e["case_id"] for e in errors}, (chosen - truth) | (truth - chosen))


if __name__ == "__main__":
    unittest.main()
