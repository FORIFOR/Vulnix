"""Blind access holdouts are scored against an independent target and labels."""

import os
import unittest
from unittest.mock import patch

from scripts.bench_access_holdout import measure_holdout, TRUTH, OWNER_SPECS
from scripts.bench_five_class_holdout import _require_complete_rows
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
        self.assertEqual(row["planner_calls"], 0)

    def test_cross_account_proof_requires_both_accounts(self):
        row = measure_holdout("cross_account_allowed", "adaptive")
        self.assertTrue(row["idor_proven"])
        self.assertTrue(row["plan_adopted"])
        self.assertGreaterEqual(len(row["target_requests"]), 3)
        self.assertEqual(row["planner_calls"], 1)
        self.assertEqual([account for _path, account in row["target_requests"][-2:]],
                         ["acct_B", "acct_A"])

    def test_public_directory_is_not_proven_idor(self):
        row = measure_holdout("account_directory_public", "adaptive")
        self.assertFalse(row["idor_proven"])

    def test_aggregate_refuses_missing_or_duplicate_conditions(self):
        rows = [{"case_id": case_id, "strategy": strategy}
                for case_id in ("a", "b") for strategy in ("fixed", "always", "observed")]
        _require_complete_rows(rows, {"a", "b"}, ("fixed", "always", "observed"), "case_id")
        for invalid in (rows[:-1], rows + [rows[0]],
                        [{**rows[0], "strategy": "unexpected"}] + rows[1:]):
            with self.assertRaises(ValueError):
                _require_complete_rows(invalid, {"a", "b"},
                                       ("fixed", "always", "observed"), "case_id")

    def test_local_stand_in_does_not_claim_the_ci_real_binary_hash(self):
        with patch.dict(os.environ, {"VULNIX_ARTEX_REAL_BIN": "",
                                     "VULNIX_ARTEX_CI_BINARY_SHA256": "0" * 64}):
            row = measure_holdout("cross_account_allowed", "adaptive")
        self.assertTrue(row["idor_proven"])


if __name__ == "__main__":
    unittest.main()
