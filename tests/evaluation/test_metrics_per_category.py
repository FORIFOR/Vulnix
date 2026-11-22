"""per_category counts each case once (the "correct" outcome was counted twice before)."""
import unittest

from aegis.evaluation.metrics import score


class TestPerCategory(unittest.TestCase):
    def test_each_case_counts_once(self):
        truth = {"c1": {"category": "x", "other_account_read": "supported", "unauthenticated_exposure": "contradicted"},
                 "c2": {"category": "x", "other_account_read": "contradicted", "unauthenticated_exposure": "contradicted"},
                 "c3": {"category": "x", "other_account_read": "supported", "unauthenticated_exposure": "contradicted",
                        "withhold_ok": False}}
        rows = [{"case_id": "c1", "other_account_read": "supported", "unauthenticated_exposure": "contradicted", "steps": []},
                {"case_id": "c2", "other_account_read": "contradicted", "unauthenticated_exposure": "contradicted", "steps": []},
                {"case_id": "c3", "other_account_read": "inconclusive", "unauthenticated_exposure": "contradicted", "steps": []}]
        cat = score(rows, truth)["per_category"]["x"]
        self.assertEqual(cat["cases"], 3)
        self.assertEqual(cat["correct"], 2)
        self.assertEqual(sum(v for k, v in cat.items() if k != "cases"), 3)   # one outcome per case


if __name__ == "__main__":
    unittest.main()
