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
        names = ("holdout_truth", "holdout_v2_truth")
        for path in (ROOT / "aegis").rglob("*.py"):
            if path.parent.name != "evaluation":
                for name in names:
                    self.assertNotIn(name, path.read_text(), path)
        # the evaluation package only hashes the label files for the human sign-off gate
        for path in (ROOT / "aegis/evaluation").glob("*.py"):
            text = path.read_text()
            if any(name in text for name in names):
                self.assertEqual(path.name, "evaluation_runner.py")
                self.assertIn("hashlib.sha256(labels_file.read_bytes())", text)
                for reader in ("json.loads(LABELS_FILE", "json.loads(labels_file", "LABELS_FILE.read_text",
                               "labels_file.read_text", "open(labels_file", "open(LABELS_FILE"):
                    self.assertNotIn(reader, text)
        for lab in ("holdout_lab.py", "holdout_v2_lab.py"):
            for name in names:
                self.assertNotIn(name, (FIX / lab).read_text())

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

    def test_the_cases_the_judge_change_came_from_are_development_cases(self):
        """FAILURE_ANALYSIS.md (公正さ): the cases the owner-record rules were derived from
        are frozen as development / regression cases, with the first set's files unchanged."""
        dev = json.loads((ROOT / "docs/evaluation/regression_manifest.json").read_text())["development_cases"]
        self.assertEqual(dev["case_ids"], ["holdout-001", "holdout-007", "holdout-010", "holdout-013",
                                           "holdout-014", "holdout-017", "holdout-029", "holdout-030"])
        self.assertTrue(set(dev["case_ids"]) <= set(self.cases))
        for path, digest in dev["files"].items():
            self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)


class TestHoldoutV2Set(unittest.TestCase):
    """The second held-out set (docs/evaluation/HOLDOUT_V2.md)."""

    def setUp(self):
        self.cases = json.loads((FIX / "holdout_v2_cases.json").read_text())["cases"]
        self.truth = json.loads((FIX / "holdout_v2_truth.json").read_text())["cases"]

    def test_thirty_new_cases(self):
        self.assertEqual(len(self.cases), 30)
        self.assertEqual(set(self.cases), set(self.truth))
        self.assertEqual(Counter(t["category"] for t in self.truth.values()),
                         {"near_miss": 12, "decoy_200": 6, "authorization_idor": 5, "auth_public_spec": 2,
                          "spec_missing_or_no_check": 2, "fix_recheck": 3})
        old = json.loads((FIX / "holdout_cases.json").read_text())["cases"]
        self.assertFalse(set(self.cases) & set(old))

    def test_the_files_are_the_ones_recorded_at_creation(self):
        doc = (ROOT / "docs/evaluation/HOLDOUT_V2.md").read_text()
        for name in ("holdout_v2_cases.json", "holdout_v2_truth.json", "holdout_v2_lab.py"):
            digest = hashlib.sha256((FIX / name).read_bytes()).hexdigest()
            self.assertIn(f"`tests/evaluation/fixtures/{name}` | `{digest}`", doc, name)

    def test_case_ids_and_behaviour_carry_no_answer(self):
        text = json.dumps(self.cases).lower()
        for word in ("supported", "contradicted", "needs_spec", "vulnerable", "idor", "category", "fixed\"",
                     "near_miss", "decoy"):
            self.assertNotIn(word, text)
        self.assertTrue(all(c.startswith("holdout-v2-") and c[11:].isdigit() for c in self.cases))

    def test_every_answer_the_cases_name_exists(self):
        from tests.evaluation.fixtures.holdout_v2_lab import JSON_BODIES, TEXT_BODIES
        for cid, c in self.cases.items():
            for answers in (c["resource"], c.get("after_fix") or {}):
                for who, (status, body) in answers.items():
                    self.assertIn(body, {**JSON_BODIES, **TEXT_BODIES}, (cid, who))
            self.assertIn(c["root"]["body"], JSON_BODIES, cid)

    def test_a_separate_human_sign_off_is_required(self):
        from aegis.evaluation.budget_ledger import LedgerError
        from aegis.evaluation.evaluation_runner import require_label_signoff
        template = json.loads((ROOT / "docs/evaluation/label_signoff_holdout_v2.template.json").read_text())
        self.assertEqual(template["label_set"], "holdout_v2")
        with self.assertRaises(LedgerError):
            require_label_signoff(template, "holdout_v2")
        self.assertFalse((ROOT / "docs/evaluation/label_signoff_holdout_v2.json").exists(),
                         "the sign-off is written by a human reviewer, never generated")
        v1 = hashlib.sha256((FIX / "holdout_truth.json").read_bytes()).hexdigest()
        v2 = hashlib.sha256((FIX / "holdout_v2_truth.json").read_bytes()).hexdigest()
        first = {"reviewer_kind": "human", "reviewer": "owner", "completed": "2026-11-22",
                 "labels_sha256": v1, "disagreements_resolved": True}
        require_label_signoff(first)                              # the first set's own gate is unchanged
        for bad in (first, {**first, "label_set": "holdout_v2"}, {**first, "labels_sha256": v2}):
            with self.assertRaises(LedgerError):                  # one set's sign-off never opens another
                require_label_signoff(bad, "holdout_v2")
        require_label_signoff({**first, "labels_sha256": v2, "label_set": "holdout_v2"}, "holdout_v2")
        with self.assertRaises(LedgerError):
            require_label_signoff({**first, "labels_sha256": v2, "label_set": "holdout_v2"})

    def test_a_second_set_case_is_gated_by_its_own_set(self):
        from aegis.evaluation.evaluation_runner import run_case
        with self.assertRaises(ValueError):
            run_case("holdout-v2-001", self.cases["holdout-v2-001"], "fixed_rule", None, label_set="holdout")


if __name__ == "__main__":
    unittest.main()
