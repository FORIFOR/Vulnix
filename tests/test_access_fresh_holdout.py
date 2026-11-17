"""New independent labels expose overconfident 200-JSON and IDOR verdicts."""
from __future__ import annotations

import json
import unittest

from aegis.service_diag import analyze_l1_service_response
from scripts.bench_access_fresh_holdout import OWNER_SPECS, TRUTH, run
from tests.fixtures.access_fresh_holdout_lab import MODES


class TestAccessFreshHoldout(unittest.TestCase):
    def test_truth_and_owner_contracts_cover_the_independent_target(self):
        self.assertEqual(set(TRUTH), set(OWNER_SPECS))
        self.assertEqual(set(TRUTH), MODES)

    def test_200_denial_metadata_cannot_hide_a_returned_private_field(self):
        access = {"requirement": "authentication_required", "spec_status": "confirmed",
                  "spec_evidence": ["owner API contract v2"]}
        for payload, expected in (
                ({"error": "authentication required", "request_id": "req-123"}, "candidate"),
                ({"error": "authentication required", "request_id": "req-123",
                  "private": "owner record"}, "detected")):
            with self.subTest(expected=expected):
                body = json.dumps(payload)
                observed = {"status": 200,
                            "headers": {"Content-Type": "application/json",
                                        "Content-Length": str(len(body.encode()))},
                            "body_prefix": body}
                findings = analyze_l1_service_response(
                    observed, {"audit_hash": "lab-proof", "saved_at": 1},
                    "http://owned-access.example.test/", root_access=access)
                finding = next(f for f in findings if f["id"] == "f_l1_unauth_api")
                self.assertEqual(finding["verdict"], expected)

    def test_fixed_always_and_observed_use_the_same_four_targets(self):
        report = run()
        strategies = report["strategies"]
        self.assertEqual(strategies["fixed_l1"]["selection"]["fn"], 2)
        self.assertEqual(strategies["always"]["selection"]["fp"], 2)
        self.assertEqual(strategies["adaptive"]["selection"]["tp"], 2)
        self.assertEqual(strategies["adaptive"]["selection"]["fp"], 0)
        self.assertEqual(strategies["adaptive"]["classes"]["cross_account_idor"]["tp"], 1)
        self.assertEqual(strategies["adaptive"]["classes"]["unauthenticated_protected_json"]["fp"], 0)
        self.assertEqual([strategies[k]["target_get"] for k in ("fixed_l1", "always", "adaptive")],
                         [4, 10, 8])


if __name__ == "__main__":
    unittest.main()
