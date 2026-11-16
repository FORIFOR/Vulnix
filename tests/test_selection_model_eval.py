"""Blind, sendable selection fixture; no external model is called by these tests."""
import json
import unittest

from scripts import eval_selection_model as evaluation


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

    def test_preview_is_one_local_gateway_call_and_labels_are_separate(self):
        report = evaluation.run_preview()
        self.assertEqual(report["gateway"]["mode"], "preview")
        self.assertEqual(report["gateway"]["calls"], 1)
        self.assertEqual(report["gateway"]["budget"]["max_cost_usd"], 0.01)
        self.assertEqual(report["gateway"]["refused"], 0)
        self.assertEqual(report["paid_model_cost_usd"], 0)
        self.assertEqual(report["mock_selection"]["fp"], 0)
        self.assertEqual(report["mock_selection"]["fn"], 0)
        self.assertEqual(report["mock_selection"]["tp"], 8)
        self.assertEqual(len(report["preview_request"]["messages"]), 2)


if __name__ == "__main__":
    unittest.main()
