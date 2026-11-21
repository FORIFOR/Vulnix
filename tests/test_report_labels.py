"""The report says exactly what the screen says: aegis/report_labels.json is the
diagnosis words of web/src/lib/labels.ts (scripts/sync_report_labels.py)."""
import json
import unittest
from pathlib import Path

from scripts.sync_report_labels import LABELS, OUT, TABLES, extract


class TestReportLabels(unittest.TestCase):
    def test_the_report_words_equal_the_screen_words(self):
        expected = extract(LABELS.read_text(encoding="utf-8"))
        stored = json.loads(OUT.read_text(encoding="utf-8"))
        self.assertEqual(stored, expected, "run: python3 -m scripts.sync_report_labels")

    def test_every_table_is_read_and_none_is_empty(self):
        data = extract(LABELS.read_text(encoding="utf-8"))
        self.assertEqual(set(data), set(TABLES) | {"REPRODUCTION"})
        for name, table in data.items():
            self.assertTrue(table, name)
            self.assertTrue(all(isinstance(v, str) for v in table.values()), name)
        # constants are resolved, objects read by their word field
        self.assertEqual(data["DIAG_END"]["audit_failed"], "記録の整合を確かめられなかったため、結果は採用していません")
        self.assertEqual(data["DIAG_STATE"]["inconclusive"], "判断不能")

    def test_a_value_wrapped_onto_the_next_line_is_an_error_not_a_gap(self):
        src = LABELS.read_text(encoding="utf-8").replace(
            '  denied_without_auth: "認証なしの要求は拒否された",',
            '  denied_without_auth:\n    "認証なしの要求は拒否された",', 1)
        with self.assertRaises(ValueError):
            extract(src)

    def test_a_changed_screen_word_is_noticed(self):
        src = LABELS.read_text(encoding="utf-8").replace('"判断不能"', '"判定できない"', 1)
        self.assertNotEqual(extract(src), json.loads(Path(OUT).read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
