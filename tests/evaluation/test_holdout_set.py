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
        names = ("holdout_truth", "holdout_v2_truth", "holdout_v3_truth", "holdout_v4_truth")
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
        for lab in ("holdout_lab.py", "holdout_v2_lab.py", "holdout_v3_lab.py", "holdout_v4_lab.py"):
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


class TestHoldoutV3Set(unittest.TestCase):
    """The third held-out set, made after the judge was frozen (docs/evaluation/HOLDOUT_V3.md)."""

    FROZEN_JUDGE = ("aegis/diagnosis_judge.py", "aegis/workers/reproduction_probe.py",
                    "aegis/diagnosis_loop.py", "aegis/adaptive_plan_runner.py")

    def setUp(self):
        self.cases = json.loads((FIX / "holdout_v3_cases.json").read_text())["cases"]
        self.truth = json.loads((FIX / "holdout_v3_truth.json").read_text())["cases"]
        self.doc = (ROOT / "docs/evaluation/HOLDOUT_V3.md").read_text()

    def test_thirty_new_cases(self):
        self.assertEqual(len(self.cases), 30)
        self.assertEqual(set(self.cases), set(self.truth))
        self.assertEqual(Counter(t["category"] for t in self.truth.values()),
                         {"fix_recheck": 5, "authorization_idor": 2, "near_miss": 5, "decoy_200": 6,
                          "truncated_body": 3, "rate_limited": 2, "no_owner_control": 2,
                          "auth_public_spec": 2, "spec_missing_or_no_check": 3})
        for other in ("holdout_cases.json", "holdout_v2_cases.json"):
            self.assertFalse(set(self.cases) & set(json.loads((FIX / other).read_text())["cases"]))

    def test_the_files_are_the_ones_recorded_at_creation(self):
        for name in ("holdout_v3_cases.json", "holdout_v3_truth.json", "holdout_v3_lab.py"):
            digest = hashlib.sha256((FIX / name).read_bytes()).hexdigest()
            self.assertIn(f"`tests/evaluation/fixtures/{name}` | `{digest}`", self.doc, name)

    # The judge v3 was measured with (HOLDOUT_V3.md §1). The judge changed afterwards (案2,
    # docs/evaluation/JUDGE_IDENTITY_MATCH.md), so v3 no longer measures the current judge; the
    # record of what it did measure must stay as written.
    V3_JUDGE = {"aegis/diagnosis_judge.py": "8aae15f94b5d71537867de505209b982432f02e5528af248faf9d7fdc254ebea",
                "aegis/workers/reproduction_probe.py":
                    "2602c97f5ba5e682ffc0254d96cecb65554d30c4518b126fc60fc5e12a90075d",
                "aegis/diagnosis_loop.py": "d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5",
                "aegis/adaptive_plan_runner.py": "1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1"}

    def test_the_judge_is_the_frozen_one(self):
        """The v3 record is unchanged, and the current judge is the one recorded as frozen
        (JUDGE_IDENTITY_MATCH.md): any unrecorded change to the judge still fails here."""
        self.assertEqual(set(self.V3_JUDGE), set(self.FROZEN_JUDGE))
        for path, digest in self.V3_JUDGE.items():
            self.assertIn(f"`{path}` | `{digest}`", self.doc, path)
        frozen = (ROOT / "docs/evaluation/JUDGE_IDENTITY_MATCH.md").read_text()
        for path in self.FROZEN_JUDGE + ("aegis/evidence.py",):
            digest = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            self.assertIn(f"`{path}` | `{digest}`", frozen, path)

    def test_case_ids_and_behaviour_carry_no_answer(self):
        text = json.dumps(self.cases).lower()
        for word in ("supported", "contradicted", "needs_spec", "vulnerable", "idor", "category", "fixed\"",
                     "near_miss", "decoy"):
            self.assertNotIn(word, text)
        self.assertTrue(all(c.startswith("holdout-v3-") and c[11:].isdigit() for c in self.cases))

    def test_every_answer_the_cases_name_exists(self):
        from tests.evaluation.fixtures.holdout_v3_lab import JSON_BODIES, TEXT_BODIES
        for cid, c in self.cases.items():
            for answers in (c["resource"], c.get("after_fix") or {}):
                for who, (status, body) in answers.items():
                    self.assertIn(body, {**JSON_BODIES, **TEXT_BODIES}, (cid, who))
            self.assertIn(c["root"]["body"], JSON_BODIES, cid)

    def test_a_separate_human_sign_off_is_required(self):
        from aegis.evaluation.budget_ledger import LedgerError
        from aegis.evaluation.evaluation_runner import require_label_signoff
        template = json.loads((ROOT / "docs/evaluation/label_signoff_holdout_v3.template.json").read_text())
        self.assertEqual(template["label_set"], "holdout_v3")
        with self.assertRaises(LedgerError):
            require_label_signoff(template, "holdout_v3")
        self.assertFalse((ROOT / "docs/evaluation/label_signoff_holdout_v3.json").exists(),
                         "the sign-off is written by a human reviewer, never generated")
        v1 = hashlib.sha256((FIX / "holdout_truth.json").read_bytes()).hexdigest()
        v2 = hashlib.sha256((FIX / "holdout_v2_truth.json").read_bytes()).hexdigest()
        v3 = hashlib.sha256((FIX / "holdout_v3_truth.json").read_bytes()).hexdigest()
        first = {"reviewer_kind": "human", "reviewer": "owner", "completed": "2026-11-22",
                 "labels_sha256": v1, "disagreements_resolved": True}
        second = {**first, "labels_sha256": v2, "label_set": "holdout_v2"}
        require_label_signoff(first)                              # the earlier gates are unchanged
        require_label_signoff(second, "holdout_v2")
        for bad in (first, second, {**first, "label_set": "holdout_v3"}, {**second, "label_set": "holdout_v3"},
                    {**first, "labels_sha256": v3}, {**second, "labels_sha256": v3}):
            with self.assertRaises(LedgerError):                  # a v1 / v2 sign-off never opens v3
                require_label_signoff(bad, "holdout_v3")
        third = {**first, "labels_sha256": v3, "label_set": "holdout_v3"}
        require_label_signoff(third, "holdout_v3")
        for other in ("holdout", "holdout_v2"):                   # and the v3 sign-off opens nothing else
            with self.assertRaises(LedgerError):
                require_label_signoff(third, other)

    def test_a_third_set_case_is_gated_by_its_own_set(self):
        from aegis.evaluation.evaluation_runner import run_case
        for wrong in ("holdout", "holdout_v2"):
            with self.assertRaises(ValueError):
                run_case("holdout-v3-001", self.cases["holdout-v3-001"], "fixed_rule", None, label_set=wrong)


class TestHoldoutV4Set(unittest.TestCase):
    """The fourth held-out set, made after the judge with 案2 was frozen (docs/evaluation/HOLDOUT_V4.md).
    Nothing here runs the judge, a Worker or a planner on the v4 cases."""

    def setUp(self):
        self.cases = json.loads((FIX / "holdout_v4_cases.json").read_text())["cases"]
        self.truth = json.loads((FIX / "holdout_v4_truth.json").read_text())["cases"]
        self.doc = (ROOT / "docs/evaluation/HOLDOUT_V4.md").read_text()

    def test_forty_new_cases(self):
        self.assertEqual(len(self.cases), 40)
        self.assertEqual(set(self.cases), set(self.truth))
        self.assertEqual(Counter(t["category"] for t in self.truth.values()),
                         {"authorization_idor": 5, "fix_recheck": 6, "near_miss": 8, "decoy_200": 5,
                          "truncated_body": 4, "auth_public_spec": 3, "spec_missing_or_no_check": 4,
                          "no_owner_control": 2, "rate_limited": 3})
        for other in ("holdout_cases.json", "holdout_v2_cases.json", "holdout_v3_cases.json"):
            self.assertFalse(set(self.cases) & set(json.loads((FIX / other).read_text())["cases"]))

    def test_the_files_are_the_ones_recorded_at_creation(self):
        for name in ("holdout_v4_cases.json", "holdout_v4_truth.json", "holdout_v4_lab.py"):
            digest = hashlib.sha256((FIX / name).read_bytes()).hexdigest()
            self.assertIn(f"`tests/evaluation/fixtures/{name}` | `{digest}`", self.doc, name)

    def test_the_record_names_the_frozen_judge_and_retires_v2_v3(self):
        frozen = (ROOT / "docs/evaluation/FROZEN_JUDGE_V4.md").read_text(encoding="utf-8")
        import re
        rows = re.findall(r"\| `([^`]+)` \| `([0-9a-f]{64})` \|", frozen)
        self.assertGreaterEqual(len(rows), 7)
        for path, digest in rows:
            self.assertIn(f"`{path}` | `{digest}`", self.doc, path)
        self.assertIn("v2 と v3 は、この時点から開発・回帰用のセットです", self.doc)

    def test_case_ids_and_behaviour_carry_no_answer(self):
        text = json.dumps(self.cases).lower()
        for word in ("supported", "contradicted", "needs_spec", "vulnerable", "idor", "category", "fixed\"",
                     "near_miss", "decoy", "withhold"):
            self.assertNotIn(word, text)
        self.assertTrue(all(c.startswith("holdout-v4-") and c[11:].isdigit() for c in self.cases))

    def test_every_answer_the_cases_name_exists(self):
        from tests.evaluation.fixtures.holdout_v4_lab import JSON_BODIES, TEXT_BODIES
        for cid, c in self.cases.items():
            for answers in (c["resource"], c.get("after_fix") or {}):
                for who, (status, body) in answers.items():
                    self.assertIn(body, {**JSON_BODIES, **TEXT_BODIES}, (cid, who))
            self.assertIn(c["root"]["body"], JSON_BODIES, cid)

    def test_a_separate_human_sign_off_is_required(self):
        from aegis.evaluation.budget_ledger import LedgerError
        from aegis.evaluation.evaluation_runner import require_label_signoff
        template = json.loads((ROOT / "docs/evaluation/label_signoff_holdout_v4.template.json").read_text())
        self.assertEqual(template["label_set"], "holdout_v4")
        with self.assertRaises(LedgerError):
            require_label_signoff(template, "holdout_v4")
        self.assertFalse((ROOT / "docs/evaluation/label_signoff_holdout_v4.json").exists(),
                         "the sign-off is written by a human reviewer, never generated")
        digests = {s: hashlib.sha256((FIX / f).read_bytes()).hexdigest() for s, f in (
            ("holdout", "holdout_truth.json"), ("holdout_v2", "holdout_v2_truth.json"),
            ("holdout_v3", "holdout_v3_truth.json"), ("holdout_v4", "holdout_v4_truth.json"))}
        base = {"reviewer_kind": "human", "reviewer": "owner", "completed": "2026-11-22",
                "disagreements_resolved": True}
        earlier = [{**base, "labels_sha256": digests["holdout"]}] + [
            {**base, "labels_sha256": digests[s], "label_set": s} for s in ("holdout_v2", "holdout_v3")]
        require_label_signoff(earlier[0])                         # the earlier gates are unchanged
        require_label_signoff(earlier[1], "holdout_v2")
        require_label_signoff(earlier[2], "holdout_v3")
        for old in earlier:                                       # a v1 / v2 / v3 sign-off never opens v4
            for bad in (old, {**old, "label_set": "holdout_v4"}, {**old, "labels_sha256": digests["holdout_v4"]}):
                with self.assertRaises(LedgerError):
                    require_label_signoff(bad, "holdout_v4")
        fourth = {**base, "labels_sha256": digests["holdout_v4"], "label_set": "holdout_v4"}
        require_label_signoff(fourth, "holdout_v4")
        for other in ("holdout", "holdout_v2", "holdout_v3"):    # and the v4 sign-off opens nothing else
            with self.assertRaises(LedgerError):
                require_label_signoff(fourth, other)

    def test_a_fourth_set_case_is_gated_by_its_own_set(self):
        """The label set check fails before any lab, Worker or judge is started (harness None)."""
        from aegis.evaluation.evaluation_runner import run_case
        for wrong in ("holdout", "holdout_v2", "holdout_v3"):
            with self.assertRaises(ValueError):
                run_case("holdout-v4-001", self.cases["holdout-v4-001"], "fixed_rule", None, label_set=wrong)

    def test_the_compare_command_knows_the_set_without_running_it(self):
        text = (ROOT / "scripts/run_model_evaluation.py").read_text()
        self.assertIn('"holdout_v4": {"cases": holdout_v4_lab.CASES', text)
        self.assertIn('"out": "comparison_holdout_v4.json"', text)
        # v4 was run once, after the freeze: the stored result is that run (a rerun that
        # overwrote it would change its hash and must be recorded as a new evaluation)
        import hashlib
        out = ROOT / "docs/evaluation/comparison_holdout_v4.json"
        doc = (ROOT / "docs/evaluation/HOLDOUT_V4.md").read_text(encoding="utf-8")
        self.assertIn(f"`comparison_holdout_v4.json`：`{hashlib.sha256(out.read_bytes()).hexdigest()}`", doc)



class TestHoldoutV4SecondLabeller(unittest.TestCase):
    def test_the_blind_second_labels_are_the_recorded_ones(self):
        import hashlib
        f = ROOT / "tests/evaluation/fixtures/holdout_v4_truth_independent.json"
        doc = (ROOT / "docs/evaluation/HOLDOUT_V4.md").read_text(encoding="utf-8")
        self.assertIn(hashlib.sha256(f.read_bytes()).hexdigest(), doc)


if __name__ == "__main__":
    unittest.main()
