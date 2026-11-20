"""The held-out set and the frozen regression set (docs/evaluation/EVALUATION_PROTOCOL.md)."""
import tests  # noqa: F401
import hashlib
import json
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/evaluation/fixtures"


class TestHoldoutSet(unittest.TestCase):
    def setUp(self):
        self.cases = json.loads((FIX / "holdout_cases.json").read_text())["cases"]
        self.truth = json.loads((FIX / "holdout_truth.json").read_text())["cases"]
        self.second = json.loads((FIX / "holdout_truth_independent.json").read_text())["cases"]

    def test_thirty_cases_in_the_agreed_mix(self):
        self.assertEqual(len(self.cases), 30)
        self.assertEqual(set(self.cases), set(self.truth))
        self.assertEqual(Counter(t["category"] for t in self.truth.values()),
                         {"authorization_idor": 8, "auth_public_spec": 5, "decoy_200": 5,
                          "replan_contradiction": 5, "spec_missing_or_no_check": 4, "fix_recheck": 3})

    def test_case_ids_and_behaviour_carry_no_answer(self):
        text = json.dumps(self.cases)
        for word in ("supported", "contradicted", "needs_spec", "vulnerable", "idor", "category", "fixed\""):
            self.assertNotIn(word, text.lower().replace("idor_cross_account_access", ""))
        self.assertTrue(all(c.startswith("holdout-") and c[8:].isdigit() for c in self.cases))

    def test_two_labellers_agree(self):
        for c, t in self.truth.items():
            for k in ("other_account_read", "unauthenticated_exposure", "fix", "withhold_ok"):
                self.assertEqual(t[k], self.second[c][k], (c, k))

    def test_no_diagnosis_code_reads_the_labels(self):
        for path in (ROOT / "aegis").rglob("*.py"):
            self.assertNotIn("holdout_truth", path.read_text(), path)
        self.assertNotIn("holdout_truth", (FIX / "holdout_lab.py").read_text())

    def test_the_regression_conditions_are_frozen(self):
        manifest = json.loads((ROOT / "docs/evaluation/regression_manifest.json").read_text())
        self.assertEqual(manifest["conditions"], 16)
        for path, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)


if __name__ == "__main__":
    unittest.main()
