"""The judge, its normalisation and thresholds, the Worker's limits, the scoring and the protocol
are the ones recorded in docs/evaluation/FROZEN_JUDGE_V5.md (frozen before holdout v5 is
authored), and the development sets listed there are unchanged."""
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/evaluation/FROZEN_JUDGE_V5.md"
ROW = r"\| `([^`]+)` \| `([0-9a-f]{64})` \|"


def _section(doc: str, heading: str) -> str:
    return doc.split(f"## {heading}", 1)[1].split("\n## ", 1)[0]


class TestFrozenJudgeV5(unittest.TestCase):
    def setUp(self):
        self.doc = DOC.read_text(encoding="utf-8")

    def test_every_frozen_file_matches_its_recorded_hash(self):
        rows = re.findall(ROW, _section(self.doc, "凍結したファイル"))
        v4 = re.findall(ROW, (ROOT / "docs/evaluation/FROZEN_JUDGE_V4.md").read_text(encoding="utf-8"))
        self.assertEqual([p for p, _ in rows], [p for p, _ in v4])         # the same 7 files as v4
        for path, digest in rows:
            with self.subTest(path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest,
                                 f"{path} changed after the v5 freeze: move v5 to development and use a new unseen set")

    def test_the_development_sets_are_unchanged(self):
        rows = re.findall(ROW, _section(self.doc, "開発・回帰用のセット"))
        names = {Path(p).name for p, _ in rows}
        for s in ("holdout", "holdout_v2", "holdout_v3", "holdout_v4"):
            for kind in ("cases.json", "lab.py", "truth.json"):
                self.assertIn(f"{s}_{kind}", names)
        for path, digest in rows:
            with self.subTest(path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest, path)

    def test_v4_is_recorded_as_a_development_set(self):
        self.assertIn("v1〜v3 と同じく開発・回帰用のセットです",
                      (ROOT / "docs/evaluation/HOLDOUT_V4.md").read_text(encoding="utf-8"))

    def test_the_development_runs_are_the_recorded_ones(self):
        for name in ("comparison_holdout_v5judge.json", "comparison_holdout_v2_v5judge.json",
                     "comparison_holdout_v3_v5judge.json", "comparison_holdout_v4_v5judge.json"):
            with self.subTest(name):
                digest = hashlib.sha256((ROOT / "docs/evaluation" / name).read_bytes()).hexdigest()
                self.assertIn(f"`{name}`：`{digest}`", self.doc)


if __name__ == "__main__":
    unittest.main()
