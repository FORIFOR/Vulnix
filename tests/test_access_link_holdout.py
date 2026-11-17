"""Previously unseen Link layouts, with target-owned labels outside the planner."""
from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import bench_access_control as baseline
from tests.fixtures.access_link_holdout_lab import AccessLinkHoldoutLab, MODES


FIXTURES = Path(__file__).parent / "fixtures"
TRUTH = json.loads((FIXTURES / "access_link_holdout_truth.json").read_text())
OWNER_SPECS = json.loads((FIXTURES / "access_link_holdout_owner_specs.json").read_text())


def measure(mode: str, strategy: str) -> dict:
    with patch.object(baseline, "AccessControlLab", AccessLinkHoldoutLab), \
            patch.object(baseline, "TRUTH", TRUTH), \
            patch.object(baseline, "OWNER_SPECS", OWNER_SPECS):
        return baseline._measure(mode, strategy)


class AccessLinkHoldoutTests(unittest.TestCase):
    def test_target_and_owner_labels_cover_each_condition(self):
        self.assertEqual(MODES, set(TRUTH))
        self.assertEqual(MODES, set(OWNER_SPECS))

    def test_equivalent_link_syntax_preserves_selection_and_proof_standard(self):
        for mode in ("spaced_parameters_allowed", "multiple_values_denied",
                     "repeated_headers_allowed"):
            with self.subTest(mode=mode):
                row = measure(mode, "adaptive_one_pass")
                self.assertTrue(row["plan_adopted"])
                self.assertEqual(row["idor_proven"], TRUTH[mode]["cross_account_access"])
                self.assertEqual(row["observed_account_link"], True)

    def test_near_relation_and_foreign_target_do_not_trigger_idor(self):
        for mode in ("near_relation_public", "foreign_target_public", "quoted_comma_decoy",
                     "repeated_headers_decoy"):
            with self.subTest(mode=mode):
                row = measure(mode, "adaptive_one_pass")
                self.assertFalse(row["plan_adopted"])
                self.assertFalse(row["idor_proven"])
                self.assertEqual(len(row["target_requests"]), 1)


if __name__ == "__main__":
    unittest.main()
