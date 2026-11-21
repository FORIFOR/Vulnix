"""The read-only check of the human label sign-off (scripts/run_model_evaluation.py
signoff-check). It says what is missing; it never writes or completes a sign-off."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aegis.evaluation.budget_ledger import LedgerError
from aegis.evaluation.evaluation_runner import labels_sha256, require_label_signoff, signoff_problems
from scripts.run_model_evaluation import SIGNOFF, main

ROOT = Path(__file__).resolve().parents[2]


def run(*argv) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = main(list(argv))
    return code, out.getvalue()


class TestSignoffCheck(unittest.TestCase):
    def candidate(self, **over) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        good = {"reviewer_kind": "human", "reviewer": "Test Reviewer", "completed": "2026-11-22",
                "labels_sha256": labels_sha256(), "disagreements_resolved": True, "notes": ""}
        path = Path(tmp.name) / "label_signoff.json"
        path.write_text(json.dumps({**good, **over}))
        return path

    def test_the_template_lists_every_missing_part(self):
        template = json.loads((ROOT / "docs/evaluation/label_signoff.template.json").read_text())
        problems = signoff_problems(template)
        self.assertEqual(len(problems), 4)             # reviewer, completed, sha, disagreements
        code, out = run("signoff-check", "--file", str(ROOT / "docs/evaluation/label_signoff.template.json"))
        self.assertEqual(code, 1)
        self.assertIn(labels_sha256(), out)
        self.assertIn("署名はまだ有効ではありません", out)

    def test_a_complete_human_signoff_passes_the_same_gate_as_a_real_run(self):
        path = self.candidate()
        code, out = run("signoff-check", "--file", str(path))
        self.assertEqual(code, 0, out)
        require_label_signoff(json.loads(path.read_text()))         # the runner's gate agrees

    def test_an_ai_signoff_or_an_old_label_hash_is_refused(self):
        for over in ({"reviewer_kind": "ai"}, {"labels_sha256": "0" * 64}, {"disagreements_resolved": False},
                     {"reviewer": "  "}):
            path = self.candidate(**over)
            self.assertEqual(run("signoff-check", "--file", str(path))[0], 1, over)
            with self.assertRaises(LedgerError):
                require_label_signoff(json.loads(path.read_text()))

    def test_the_check_never_writes_a_signoff(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        missing = Path(tmp.name) / "label_signoff.json"      # never the real file
        code, out = run("signoff-check", "--file", str(missing))
        self.assertEqual(code, 1)
        self.assertIn("署名のファイルがありません", out)
        self.assertFalse(missing.exists(), "the check must not create the sign-off")
        self.assertEqual(list(Path(tmp.name).iterdir()), [])
        self.assertEqual(SIGNOFF.name, "label_signoff.json")


if __name__ == "__main__":
    unittest.main()
