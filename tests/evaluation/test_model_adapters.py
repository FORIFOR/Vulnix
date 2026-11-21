"""Provider envelopes and reply parsing (aegis/evaluation/model_adapter.py). No network."""
import tests  # noqa: F401
import json
import unittest

from aegis.evaluation.model_adapter import (AbliterationAdapter, AbliterationLargeV2Adapter, AdapterError,
                                            ClaudeAdapter, FixedRuleBaseline)

STEP = {"hypothesis_id": "H1", "catalog_id": "l2_idor", "target_ref": "T2", "evidence_refs": ["E2"],
        "reason": "test_hypothesis"}
PAYLOAD = {"schema_version": 1, "observations": [], "hypotheses": []}


def openai_reply(text, finish="stop"):
    return json.dumps({"choices": [{"message": {"content": text}, "finish_reason": finish}],
                       "usage": {"prompt_tokens": 600, "completion_tokens": 40}}).encode()


def claude_reply(text, stop="end_turn"):
    return json.dumps({"content": [{"type": "text", "text": text}], "stop_reason": stop,
                       "usage": {"input_tokens": 700, "output_tokens": 50}}).encode()


class TestModelAdapters(unittest.TestCase):
    def test_request_bodies(self):
        a = json.loads(AbliterationAdapter().request_body(PAYLOAD))
        self.assertEqual((a["model"], a["reasoning_effort"], a["response_format"], a["max_tokens"]),
                         ("abliterated-model", "none", {"type": "json_object"}, 2048))
        b = json.loads(AbliterationLargeV2Adapter().request_body(PAYLOAD))
        self.assertEqual((b["model"], b["reasoning_effort"]), ("abliterated-model-large-v2", "low"))
        c = json.loads(ClaudeAdapter().request_body(PAYLOAD))
        self.assertEqual((c["model"], c["max_tokens"], c["output_config"]["effort"]), ("claude-sonnet-5-5", 2048, "low"))
        self.assertEqual(c["output_config"]["format"]["type"], "json_schema")
        self.assertNotIn("fallbacks", c)                   # a fallback would answer with another model
        for body in (a, b, c):
            self.assertNotIn("api_key", json.dumps(body))

    def test_valid_replies_become_steps(self):
        text = json.dumps({"steps": [STEP]})
        self.assertEqual(AbliterationAdapter().parse_reply(openai_reply(text))[0], [STEP])
        steps, usage = ClaudeAdapter().parse_reply(claude_reply(text))
        self.assertEqual((steps, usage["input_tokens"]), ([STEP], 700))

    def test_bad_replies_are_rejected_with_a_reason(self):
        cases = [(openai_reply("not json"), "invalid_json"), (openai_reply('{"steps": NaN}'), "invalid_json"),
                 (openai_reply(json.dumps([STEP])), "not_the_answer_shape"),
                 (openai_reply(json.dumps({"steps": [STEP], "verdict": "proven"})), "not_the_answer_shape"),
                 (openai_reply(json.dumps({"steps": [STEP]}), finish="length"), "finish_length"),
                 (openai_reply(""), "empty_or_oversized_answer"), (b"<html>", "unreadable_reply")]
        for raw, code in cases:
            with self.assertRaises(AdapterError) as e:
                AbliterationAdapter().parse_reply(raw)
            self.assertEqual(e.exception.code, code)
        with self.assertRaises(AdapterError) as e:
            ClaudeAdapter().parse_reply(claude_reply("{}", stop="refusal"))
        self.assertEqual(e.exception.code, "finish_refusal")

    def test_the_baseline_uses_the_fixed_table(self):
        view = {"generation": 1, "observations": [{"evidence_id": "E1", "target_ref": "T2", "generation": 1}],
                "hypotheses": [{"id": "H1", "claim": "other_account_read", "target_ref": "T2", "state": "open",
                                "purpose": "diagnose", "generation": 1}]}
        self.assertEqual(FixedRuleBaseline().steps(view)[0]["catalog_id"], "l2_idor")


if __name__ == "__main__":
    unittest.main()
