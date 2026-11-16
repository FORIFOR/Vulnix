"""Macro scoring must not hide missing classes or invent AI results."""
import unittest

from scripts.bench_multiclass import summarize


class TestMulticlassMacro(unittest.TestCase):
    def test_paired_comparison_requires_same_truth_sequence(self):
        with self.assertRaises(ValueError):
            summarize({"idor": {"fixed": [(True, False), (False, False)],
                                "artex": [(False, True), (True, True)]}})

    def test_undefined_precision_and_unpaired_artex_are_explicit(self):
        classes = {
            "cors": {"fixed": [(True, True), (False, True), (False, False)],
                     "artex": None},
            "cookie": {"fixed": [(False, False), (False, False)],
                       "artex": None},
            "idor": {"fixed": [(True, True), (True, False)],
                     "artex": [(True, True), (True, True)]},
        }
        result = summarize(classes)
        self.assertEqual(result["classes"]["cors"]["fixed"]["fp"], 1)
        self.assertIsNone(result["classes"]["cookie"]["fixed"]["precision"])
        self.assertIsNone(result["classes"]["cors"]["artex"])
        self.assertEqual(result["macro_fixed"]["precision"], 0.75)
        self.assertEqual(result["macro_fixed"]["precision_classes"], 2)
        self.assertEqual(result["macro_fixed"]["recall"], 0.75)
        self.assertEqual(result["macro_artex_paired"]["class_count"], 1)
        self.assertEqual(result["macro_artex_paired"]["precision"], 1.0)
        self.assertEqual(result["paired_classes"], ["idor"])
