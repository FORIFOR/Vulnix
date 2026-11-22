"""v1.0 gate: an undecided result is never presented as safe (docs/V1_COMPLETION.md).

The words for undecided states (open, inconclusive, needs owner spec, unmeasured or
incomplete findings) on the screen and in the report never claim safety, the report's
"could not be decided" section says it is not a safety statement, and an assessment that
has not run shows "未診断（安全とは判定していません）"."""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SAFE_WORDS = ("安全です", "安全と判定", "問題なし", "問題ありません", "脆弱性なし", "対策済み")


class TestUndecidedIsNeverSafe(unittest.TestCase):
    def test_undecided_state_words_claim_no_safety(self):
        words = json.loads((ROOT / "aegis/report_labels.json").read_text(encoding="utf-8"))
        undecided = [words["DIAG_STATE"][k] for k in ("open", "inconclusive", "needs_spec")]
        undecided += [words["DIAG_FINDING_STATUS"][k] for k in ("incomplete", "candidate", "detected")]
        undecided += [words["DIAG_FIX_RESULT"]["pending"]]
        for w in undecided:
            with self.subTest(w):
                self.assertFalse(any(s in w for s in SAFE_WORDS), w)

    def test_the_report_says_undecided_is_not_safe(self):
        src = (ROOT / "aegis/report_diagnosis.py").read_text(encoding="utf-8")
        self.assertIn("「安全」という意味ではありません", src)

    def test_an_assessment_that_has_not_run_is_not_called_safe(self):
        risk = (ROOT / "web/src/components/findings/RiskScore.tsx").read_text(encoding="utf-8")
        self.assertIn("未診断（安全とは判定していません）", risk)
        report = (ROOT / "aegis/assessment.py").read_text(encoding="utf-8")
        self.assertIn("未診断（安全性は未評価）", report)

    def test_the_judge_never_turns_a_missing_observation_into_not_vulnerable(self):
        """On the unseen sets v4 and v5 the frozen judges made no wrong "not vulnerable"."""
        for f in ("comparison_holdout_v4.json", "comparison_holdout_v5.json"):
            d = json.loads((ROOT / "docs/evaluation" / f).read_text(encoding="utf-8"))
            for method, s in d["summary"].items():
                with self.subTest(f"{f}:{method}"):
                    self.assertEqual(s["outcomes"]["wrong_decision"], 0)
                    self.assertEqual(s["fp"], 0)
                    self.assertEqual(d["external_connection_attempts"], 0)

    def test_screen_labels_for_undecided_states_claim_no_safety(self):
        labels = (ROOT / "web/src/lib/labels.ts").read_text(encoding="utf-8")
        for key in ("inconclusive", "needs_spec", "open"):
            m = re.search(rf"  {key}: \{{ label: \"([^\"]+)\"", labels)
            self.assertIsNotNone(m, key)
            self.assertFalse(any(s in m.group(1) for s in SAFE_WORDS), m.group(1))


if __name__ == "__main__":
    unittest.main()
