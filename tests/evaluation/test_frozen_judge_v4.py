"""The v4 freeze record (docs/evaluation/FROZEN_JUDGE_V4.md) after the v5 judge change.

holdout v4 was evaluated once with the files recorded there. The v5 change
(docs/evaluation/FROZEN_JUDGE_V5.md) then changed exactly three of them, and v4 became a
development set. The git history cannot be read offline here, so this test keeps the v4
record meaningful in the only way it can: the record still exists unchanged, the files the
v5 change touched differ from it (and are recorded in the v5 freeze), and every other file
is still byte-for-byte the one v4 was measured with.
"""
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# the files the v5 change touched (FROZEN_JUDGE_V5.md "v4 の凍結から変えたファイル")
CHANGED_FOR_V5 = frozenset({"aegis/diagnosis_judge.py", "aegis/evidence.py", "aegis/workers/reproduction_probe.py"})


def _rows(doc: str) -> list[tuple[str, str]]:
    return re.findall(r"\| `([^`]+)` \| `([0-9a-f]{64})` \|", doc)


class TestFrozenJudgeV4(unittest.TestCase):
    def setUp(self):
        self.rows = _rows((ROOT / "docs/evaluation/FROZEN_JUDGE_V4.md").read_text(encoding="utf-8"))

    def test_the_v4_record_still_lists_the_seven_files(self):
        self.assertEqual(len(self.rows), 7)
        self.assertTrue(CHANGED_FOR_V5 <= {p for p, _ in self.rows})

    def test_only_the_files_the_v5_change_touched_differ(self):
        for path, digest in self.rows:
            with self.subTest(path):
                now = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
                if path in CHANGED_FOR_V5:
                    self.assertNotEqual(now, digest, f"{path} is listed as changed for v5 but is the v4 file")
                else:
                    self.assertEqual(now, digest, f"{path} changed after the v4 freeze without being recorded")

    def test_the_changed_files_are_the_ones_the_v5_freeze_names(self):
        v5 = (ROOT / "docs/evaluation/FROZEN_JUDGE_V5.md").read_text(encoding="utf-8")
        for path in CHANGED_FOR_V5:
            with self.subTest(path):
                self.assertIn(f"`{path}`", v5.split("## v4 の凍結から変えたファイル", 1)[1].split("\n## ", 1)[0])


if __name__ == "__main__":
    unittest.main()
