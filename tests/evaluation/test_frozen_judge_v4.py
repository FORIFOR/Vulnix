"""The judge, its normalisation and thresholds, the scoring and the protocol are the ones
recorded in docs/evaluation/FROZEN_JUDGE_V4.md (frozen before holdout v4 was authored)."""
import hashlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class TestFrozenJudgeV4(unittest.TestCase):
    def test_every_frozen_file_matches_its_recorded_hash(self):
        doc = (ROOT / "docs/evaluation/FROZEN_JUDGE_V4.md").read_text(encoding="utf-8")
        rows = re.findall(r"\| `([^`]+)` \| `([0-9a-f]{64})` \|", doc)
        self.assertGreaterEqual(len(rows), 7)
        for path, digest in rows:
            with self.subTest(path):
                self.assertEqual(hashlib.sha256((ROOT / path).read_bytes()).hexdigest(), digest,
                                 f"{path} changed after the v4 freeze: move v4 to development and use a new unseen set")


if __name__ == "__main__":
    unittest.main()
