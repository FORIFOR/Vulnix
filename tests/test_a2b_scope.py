"""A2B findings never become permission: ownership first, real-site L2 never, no auto contact."""
import json
import unittest
from pathlib import Path

from aegis.a2b.manifest import record_upload
from aegis.a2b.report import analyze_app

APP = Path(__file__).resolve().parent / "fixtures" / "a2b" / "sample_app"


def analyze(verified=()):
    rec = record_upload(b"s", filename="src", org_id="org_a", uploaded_by="alice", owner_attested=True,
                        kind="source_tree")
    return analyze_app(record=rec, source_dir=APP, verified_hosts=verified)


class TestScopeGates(unittest.TestCase):
    def test_unverified_hosts_lead_to_nothing(self):
        r = analyze()
        self.assertTrue(r["risk_candidates"])
        for c in r["risk_candidates"]:
            self.assertEqual(c["gate"], "ownership_verification_required")
            self.assertEqual(c["allowed_followup"], "none")
            self.assertFalse(c["auto_contact"])
        self.assertTrue(all(not h["ownership_verified"] for h in r["owner_hosts"]))

    def test_verified_host_allows_only_existing_l1_or_lab_l2(self):
        r = analyze(verified=["api.shop-a2b.test"])
        follow = {c["allowed_followup"] for c in r["risk_candidates"]}
        self.assertLessEqual(follow, {"existing_l1_read_only_get", "isolated_lab_l2_idor_only", "none"})
        for c in r["risk_candidates"]:
            if c["class"] in ("ssrf_candidate", "injection_candidate"):
                self.assertEqual((c["gate"], c["allowed_followup"]), ("manual_review_only", "none"))
            if c["endpoint"]["host"] == "legacy.shop-a2b.test":
                self.assertEqual(c["gate"], "ownership_verification_required")
        self.assertNotIn("real_site_l2", json.dumps(r))

    def test_nothing_is_called_vulnerable(self):
        r = analyze(verified=["api.shop-a2b.test"])
        self.assertTrue(all(c["status"] == "candidate" for c in r["risk_candidates"]))
        text = json.dumps(r, ensure_ascii=False)
        for word in ("vulnerable", "脆弱です", "proven", "confirmed"):
            self.assertNotIn(word, text)

    def test_verified_hosts_do_not_change_the_inventory(self):
        a, b = analyze(), analyze(verified=["api.shop-a2b.test"])
        self.assertEqual(a["endpoints"], b["endpoints"])
        self.assertEqual(a["secret_findings"], b["secret_findings"])


if __name__ == "__main__":
    unittest.main()
