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
            if path.parent.name != "evaluation":
                self.assertNotIn("holdout_truth", path.read_text(), path)
        # the evaluation package only hashes the label file for the human sign-off gate
        for path in (ROOT / "aegis/evaluation").glob("*.py"):
            text = path.read_text()
            if "holdout_truth" in text:
                self.assertEqual(path.name, "evaluation_runner.py")
                self.assertIn("hashlib.sha256(LABELS_FILE.read_bytes())", text)
                self.assertNotIn("json.loads(LABELS_FILE", text)
        self.assertNotIn("holdout_truth", (FIX / "holdout_lab.py").read_text())

    def test_the_sign_off_template_does_not_open_the_gate(self):
        from aegis.evaluation.budget_ledger import LedgerError
        from aegis.evaluation.evaluation_runner import require_label_signoff
        template = json.loads((ROOT / "docs/evaluation/label_signoff.template.json").read_text())
        with self.assertRaises(LedgerError):
            require_label_signoff(template)
        self.assertFalse((ROOT / "docs/evaluation/label_signoff.json").exists(),
                         "the sign-off is written by a human reviewer, never generated")

    def test_the_regression_conditions_are_frozen(self):
        manifest = json.loads((ROOT / "docs/evaluation/regression_manifest.json").read_text())
        self.assertEqual(manifest["conditions"], 16)
        for path, digest in manifest["files"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)


if __name__ == "__main__":
    unittest.main()
