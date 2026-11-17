"""Blind access holdouts are scored against an independent target and labels."""

import unittest

from scripts.bench_access_holdout import measure_holdout, TRUTH, OWNER_SPECS
from tests.fixtures.access_holdout_lab import MODES


class AccessHoldoutTests(unittest.TestCase):
    def test_truth_and_owner_contract_cover_each_independent_mode(self):
        self.assertEqual(MODES, set(TRUTH))
        self.assertEqual(MODES, set(OWNER_SPECS))

    def test_protected_root_requires_owner_contract_to_be_detected(self):
        row = measure_holdout("private_root_200", "fixed_l1")
        self.assertTrue(row["root_exposure_detected"])
        self.assertFalse(row["idor_proven"])
        self.assertEqual(len(row["target_requests"]), 1)

    def test_cross_account_proof_requires_both_accounts(self):
        row = measure_holdout("cross_account_allowed", "adaptive")
        self.assertTrue(row["idor_proven"])
        self.assertTrue(row["plan_adopted"])
        self.assertGreaterEqual(len(row["target_requests"]), 3)

    def test_public_directory_is_not_proven_idor(self):
        row = measure_holdout("account_directory_public", "adaptive")
        self.assertFalse(row["idor_proven"])


if __name__ == "__main__":
    unittest.main()
