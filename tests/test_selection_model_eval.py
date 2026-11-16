"""Blind, sendable selection fixture; no external model is called by these tests."""
import json
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

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

        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluation, "APPROVAL_DIR", Path(tmp) / "approvals"):
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            with self.assertRaises(ValueError):
                evaluation.run_approved(approval_sha256="0" * 64, api_key="test-only-key",
                                        audit=audit, transport=local_transport)
            self.assertEqual(seen, [])
            result = evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                             audit=audit, transport=local_transport)
            self.assertTrue(audit.verify())
            with self.assertRaisesRegex(ValueError, "already consumed"):
                evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                        audit=audit, transport=local_transport)
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
            return json.dumps({"choices": [{"message": {"role": "assistant", "content": "maybe"},
                                            "finish_reason": "length"}],
                               "usage": {"prompt_tokens": 900, "completion_tokens": 384,
                                         "completion_tokens_details": {"reasoning_tokens": 384}}}).encode()

        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluation, "APPROVAL_DIR", Path(tmp) / "approvals"):
            result = evaluation.run_approved(
                approval_sha256=expected, api_key="test-only-key",
                audit=AuditLog(Path(tmp) / "audit.jsonl"), transport=bad_transport)
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["accepted"])
        self.assertIsNone(result["selection"])
        self.assertEqual(result["selected_case_ids"], [])
        self.assertEqual(result["response_adoption_rate"], 0.0)
        self.assertEqual(result["reject_reason"], "invalid_json")
        self.assertEqual(result["finish_reason"], "length")
        self.assertEqual(result["usage"]["reasoning_tokens"], 384)

    def test_upstream_failure_still_returns_a_single_call_report(self):
        expected = evaluation.run_preview()["gateway"]["first_request_sha256"]
        sent = []

        def broken(*args):
            sent.append(args)
            raise TimeoutError("synthetic timeout")

        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluation, "APPROVAL_DIR", Path(tmp) / "approvals"):
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            result = evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                             audit=audit, transport=broken)
            self.assertTrue(audit.verify())
            with self.assertRaisesRegex(ValueError, "already consumed"):
                evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                        audit=audit, transport=broken)
        self.assertEqual(len(sent), 1)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reject_reason"], "upstream_exchange_failed")
        self.assertEqual(result["gateway"]["calls"], 1)
        self.assertEqual(result["gateway"]["failed"], 1)
        self.assertIsNone(result["selection"])
        self.assertGreaterEqual(result["elapsed_s"], 0)

    def test_missing_content_is_reported_after_the_only_model_call(self):
        expected = evaluation.run_preview()["gateway"]["first_request_sha256"]
        def no_content(*_args):
            return json.dumps({"choices": [{"message": {"role": "assistant"},
                                            "finish_reason": "length"}]}).encode()
        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluation, "APPROVAL_DIR", Path(tmp) / "approvals"):
            result = evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                             audit=AuditLog(Path(tmp) / "audit.jsonl"), transport=no_content)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reject_reason"], "missing_content")
        self.assertEqual(result["finish_reason"], "length")
        self.assertEqual(result["gateway"]["calls"], 1)

    def test_concurrent_consumers_cannot_send_twice(self):
        expected = evaluation.run_preview()["gateway"]["first_request_sha256"]
        ready = threading.Barrier(2)
        sent = []

        def local_transport(*args):
            sent.append(args)
            return json.dumps({"choices": [{"message": {"role": "assistant",
                                                      "content": '{"selected":[]}'}}]}).encode()

        with tempfile.TemporaryDirectory() as tmp, patch.object(evaluation, "APPROVAL_DIR", Path(tmp) / "approvals"):
            audit = AuditLog(Path(tmp) / "audit.jsonl")

            def attempt():
                ready.wait(timeout=2)
                try:
                    return evaluation.run_approved(approval_sha256=expected, api_key="test-only-key",
                                                   audit=audit, transport=local_transport)
                except ValueError as exc:
                    return str(exc)

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: attempt(), range(2)))
            self.assertTrue(audit.verify())
        self.assertEqual(len(sent), 1)
        self.assertEqual(sum(isinstance(outcome, dict) for outcome in outcomes), 1)
        self.assertIn("approval already consumed", outcomes)

    def test_wrong_choices_name_false_positive_and_missed_cases(self):
        _, mapping = evaluation.build_request()
        truth = evaluation.truth_ids(mapping)
        chosen = {next(iter(truth)), next(case for case in mapping if case not in truth)}
        errors = evaluation.selection_errors(chosen, mapping)
        self.assertEqual(sum(e["kind"] == "false_positive" for e in errors), 1)
        self.assertEqual(sum(e["kind"] == "missed" for e in errors), len(truth) - 1)
        self.assertEqual({e["case_id"] for e in errors}, (chosen - truth) | (truth - chosen))

    def test_unnecessary_rate_is_among_selected_checks(self):
        _, mapping = evaluation.build_request()
        not_needed = next(case for case in mapping if case not in evaluation.truth_ids(mapping))
        metrics = evaluation.score({not_needed}, mapping)
        self.assertEqual(metrics["fp"], 1)
        self.assertEqual(metrics["unnecessary_check_rate"], 1.0)
        self.assertAlmostEqual(metrics["unnecessary_case_rate"], 1 / 14)
        self.assertIsNone(evaluation.score(set(), mapping)["unnecessary_check_rate"])


if __name__ == "__main__":
    unittest.main()
