"""Scoring definitions (aegis/evaluation/metrics.py): exclusive outcomes vs the confusion matrix."""
import tests  # noqa: F401
import unittest

from aegis.evaluation.metrics import OUTCOMES, final_outcome, score, wilson

TRUTH = {
    "c1": {"category": "x", "other_account_read": "supported", "unauthenticated_exposure": "contradicted",
           "withhold_ok": False, "expected_checks": ["l2_idor"], "forbidden_checks": []},
    "c2": {"category": "x", "other_account_read": "supported", "unauthenticated_exposure": "contradicted",
           "withhold_ok": True, "expected_checks": ["l2_idor"], "forbidden_checks": []},
    "c3": {"category": "x", "other_account_read": "contradicted", "unauthenticated_exposure": "contradicted",
           "withhold_ok": False, "expected_checks": ["l2_idor"], "forbidden_checks": []},
    "c4": {"category": "x", "other_account_read": "contradicted", "unauthenticated_exposure": "contradicted",
           "withhold_ok": False, "expected_checks": ["l2_idor"], "forbidden_checks": []},
    "c5": {"category": "x", "other_account_read": "needs_spec", "unauthenticated_exposure": "contradicted",
           "withhold_ok": False, "expected_checks": ["l2_idor"], "forbidden_checks": []},
    "c6": {"category": "x", "other_account_read": "supported", "unauthenticated_exposure": "contradicted",
           "withhold_ok": False, "expected_checks": ["l2_idor"], "forbidden_checks": []},
}


def row(case, got):
    return {"case_id": case, "other_account_read": got, "unauthenticated_exposure": "contradicted", "steps": []}


class TestMetrics(unittest.TestCase):
    def test_exclusive_outcomes_add_up_and_the_matrix_is_separate(self):
        rows = [row("c1", "inconclusive"), row("c2", "inconclusive"), row("c3", "supported"),
                row("c4", "inconclusive"), row("c5", "contradicted"), row("c6", "supported")]
        s = score(rows, TRUTH)
        self.assertEqual(s["outcomes"], {"correct": 1, "false_positive": 1, "wrong_decision": 1,
                                         "withheld_appropriately": 1, "withheld_missing_vuln": 1,
                                         "withheld_otherwise": 1})
        self.assertEqual(sum(s["outcomes"].values()), 6)
        # positives: c1, c2, c6 -> tp c6; fn c1 (withheld) and c2 (appropriately withheld)
        self.assertEqual((s["tp"], s["fp"], s["fn"], s["tn"]), (1, 1, 2, 2))
        self.assertEqual((s["precision"], s["recall"]), (0.5, 0.3333))
        # the old "undecided" count overlaps fn: c1 and c2 are in both
        self.assertEqual(s["undecided"], 3)

    def test_outcome_order(self):
        self.assertEqual(final_outcome("supported", "supported", True), "correct")
        self.assertEqual(final_outcome("supported", "needs_spec", False), "false_positive")
        self.assertEqual(final_outcome("untested", "not_applicable", False), "withheld_otherwise")
        self.assertEqual(set(OUTCOMES), {final_outcome(g, w, ok) for g, w, ok in (
            ("a", "a", 0), ("supported", "x", 0), ("contradicted", "x", 0), ("inconclusive", "x", 1),
            ("inconclusive", "supported", 0), ("inconclusive", "contradicted", 0))})

    def test_wilson(self):
        self.assertEqual(wilson(25, 30), [0.6644, 0.9266])
        self.assertEqual(wilson(0, 20), [0.0, 0.1611])
        self.assertIsNone(wilson(0, 0))


if __name__ == "__main__":
    unittest.main()
