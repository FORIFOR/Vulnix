"""The human review sheets are generated from the fixtures (never hand-edited), list every
case with both labellers' labels, flag disagreements, and never create a sign-off."""
import json
import unittest
from pathlib import Path

from scripts.make_label_review_sheet import FIELDS, build

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests/evaluation/fixtures"


def _cases(name):
    d = json.loads((FIX / name).read_text(encoding="utf-8"))
    return d.get("cases", d)


class TestLabelReviewSheet(unittest.TestCase):
    def test_the_stored_sheets_are_the_generated_ones(self):
        for st in ("holdout_v2", "holdout_v3", "holdout_v4", "holdout_v5"):
            with self.subTest(st):
                stored = (ROOT / f"docs/evaluation/LABEL_REVIEW_SHEET_{st.replace('holdout_', '').upper()}.md")
                self.assertEqual(stored.read_text(encoding="utf-8"), build(st) + "\n",
                                 "regenerate: python3 -m scripts.make_label_review_sheet --set " + st)

    def test_every_case_and_every_disagreement_is_listed(self):
        for st in ("holdout_v4", "holdout_v5"):
            sheet = build(st)
            author, second = _cases(f"{st}_truth.json"), _cases(f"{st}_truth_independent.json")
            for cid in author:
                self.assertIn(f"| {cid} |", sheet)
            differ = sum(1 for c in author if any(author[c].get(f) != second.get(c, {}).get(f) for f in FIELDS))
            self.assertIn(f"不一致の行：{differ} 件。", sheet)
            self.assertEqual(sheet.count("| **不一致** |"), differ)

    def test_no_sign_off_is_created(self):
        before = sorted(p.name for p in (ROOT / "docs/evaluation").glob("label_signoff_*.json")
                        if not p.name.endswith(".template.json"))
        build("holdout_v5")
        after = sorted(p.name for p in (ROOT / "docs/evaluation").glob("label_signoff_*.json")
                       if not p.name.endswith(".template.json"))
        self.assertEqual(before, after)
        self.assertEqual(after, [])


if __name__ == "__main__":
    unittest.main()
