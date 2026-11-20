"""The committed DRY RUN artefacts agree with each other and with the model specs:
docs/evaluation/requests.jsonl (81 previews), manifest.json and cost_estimate.json."""
import tests  # noqa: F401
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

from aegis.evaluation.model_adapter import MODELS
from aegis.evaluation.request_builder import canonical
from aegis.evaluation.request_preview import config_sha256

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs/evaluation"


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class TestDryRunIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (DOCS / "requests.jsonl").read_bytes()
        cls.rows = [json.loads(line) for line in cls.raw.splitlines()]
        cls.manifest = json.loads((DOCS / "manifest.json").read_text())
        cls.cost = json.loads((DOCS / "cost_estimate.json").read_text())
        cls.truth = json.loads((ROOT / "tests/evaluation/fixtures/holdout_truth.json").read_text())["cases"]

    def test_the_file_is_the_one_the_manifest_names(self):
        self.assertEqual(sha(self.raw), self.manifest["previews"]["requests_jsonl_sha256"])
        self.assertEqual(len(self.rows), self.manifest["previews"]["requests"])
        self.assertTrue(self.manifest["dry_run"])
        self.assertFalse(self.manifest["external_calls_enabled"])
        self.assertEqual(self.manifest["external_connection_attempts"], 0)

    def test_81_previews_27_cases_per_model_none_for_out_of_scope_cases(self):
        self.assertEqual(len(self.rows), 81)
        self.assertEqual(Counter(r["model"] for r in self.rows), {k: 27 for k in MODELS})
        cases = {r["case_id"] for r in self.rows}
        out_of_scope = {c for c, t in self.truth.items() if t["other_account_read"] == "not_applicable"}
        self.assertEqual(cases | out_of_scope, set(self.truth))
        self.assertFalse(cases & out_of_scope)
        self.assertEqual(len({(r["case_id"], r["model"], r["round"]) for r in self.rows}), 81)   # no duplicates

    def test_every_hash_model_price_cap_and_cost_is_consistent(self):
        for r in self.rows:
            spec = MODELS[r["model"]]
            body = r["body"].encode("utf-8")
            sent = json.loads(body)
            with self.subTest(case=r["case_id"], model=r["model"]):
                self.assertEqual(r["body_sha256"], sha(body))
                self.assertEqual(r["body_bytes"], len(body))
                self.assertEqual(r["common_sha256"], sha(canonical(json.loads(sent["messages"][-1]["content"]))))
                self.assertEqual((sent["model"], r["model_id"]), (spec.model_id, spec.model_id))
                self.assertEqual(sent["max_tokens"], spec.max_output_tokens)
                self.assertEqual((r["max_input_tokens"], r["max_output_tokens"]),
                                 (spec.max_input_tokens, spec.max_output_tokens))
                self.assertEqual((r["price_in_per_m"], r["price_out_per_m"]), (spec.price_in_per_m, spec.price_out_per_m))
                self.assertEqual(r["max_cost_usd"], round((spec.max_input_tokens * spec.price_in_per_m
                                                           + spec.max_output_tokens * spec.price_out_per_m) / 1e6, 6))
                self.assertEqual(r["config_sha256"], config_sha256(r["model"]))
                self.assertEqual(r["config_sha256"], self.manifest["models"][r["model"]]["config_sha256"])
                self.assertTrue(r["within_input_cap"])
                self.assertFalse(r["sendable"])
                self.assertNotIn("api_key", r["body"].lower())
                self.assertNotIn("authorization", r["body"].lower())

    def test_the_same_common_input_for_every_model(self):
        by_case = {}
        for r in self.rows:
            by_case.setdefault(r["case_id"], set()).add(r["common_sha256"])
        self.assertTrue(all(len(v) == 1 for v in by_case.values()))

    def test_reservations_add_up_and_stay_under_the_cap(self):
        totals = {k: 0.0 for k in MODELS}
        for r in self.rows:
            totals[r["model"]] = round(totals[r["model"]] + r["max_cost_usd"], 6)
            self.assertEqual(r["cumulative_model_reserve_usd"], totals[r["model"]])
            self.assertEqual(r["cumulative_total_reserve_usd"], round(sum(totals.values()), 6))
        reserve = self.cost["round1_previews_reserve_usd"]
        self.assertEqual({k: reserve[k] for k in MODELS}, totals)
        self.assertEqual(reserve["total"], 1.535328)
        self.assertEqual(self.cost["total_max_usd"], 3.753024)
        self.assertLessEqual(self.cost["total_max_usd"], 5.0)
        for k, m in self.cost["per_model"].items():
            self.assertEqual(m["per_request_usd"], MODELS[k].max_cost_usd())


if __name__ == "__main__":
    unittest.main()
