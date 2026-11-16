"""Independent cookie purpose labels versus observed read-only response."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from aegis.assessment import AssessmentService
from aegis.service_diag import analyze_l1_service_response
from aegis.l2_rules import L2RuleSet, RuleError, validate_profile
from tests import TEST_CONFINEMENT
from tests.fixtures.cookie_purpose_lab import CookiePurposeLab, COOKIES


FIXTURES = Path(__file__).parent / "fixtures"
TRUTH = json.loads((FIXTURES / "cookie_purpose_truth.json").read_text())
OWNER = json.loads((FIXTURES / "cookie_owner_specs.json").read_text())


class TestCookiePurposeLab(unittest.TestCase):
    def test_independent_conditions_and_owner_specs_match(self):
        self.assertEqual(set(COOKIES), set(TRUTH))
        self.assertEqual(set(COOKIES), set(OWNER))

    def test_owner_cookie_spec_requires_exact_admin_acceptance(self):
        raw = json.loads((FIXTURES / "l2_profiles/example.json").read_text())
        raw["cookie_policy"] = OWNER["session_no_httponly"]
        normalized = validate_profile(raw)
        self.assertEqual(normalized["cookie_policy"]["session"], ["auth"])
        rules = L2RuleSet([normalized])
        rules.sources = {"example": {"site": True, "sha256": "cookie-contract-v1"}}
        self.assertEqual(rules.hold_unaccepted({}), ["example"])
        self.assertEqual(rules.profiles["example"]["cookie_policy"]["status"], "unaccepted")
        accepted = L2RuleSet([validate_profile(raw)])
        accepted.sources = {"example": {"site": True, "sha256": "cookie-contract-v1"}}
        self.assertEqual(accepted.hold_unaccepted({"example": "cookie-contract-v1"}), [])
        self.assertEqual(accepted.profiles["example"]["cookie_policy"]["status"], "confirmed")
        for invalid in [
            {**raw["cookie_policy"], "evidence": []},
            {**raw["cookie_policy"], "non_session": ["auth"]},
            {**raw["cookie_policy"], "session": ["auth*"]},
        ]:
            with self.subTest(invalid=invalid):
                raw["cookie_policy"] = invalid
                with self.assertRaises(RuleError):
                    validate_profile(raw)

    def test_cookie_name_alone_never_confirms_session_purpose(self):
        observed = {"status": 200, "headers": {}, "set_cookies": ["session=opaque; Secure; SameSite=Lax"]}
        findings = analyze_l1_service_response(
            observed, {"audit_hash": "cookie-lab-proof", "saved_at": 1},
            "https://owned-cookie.example.test/")
        cookie = next(f for f in findings if f["id"] == "f_l1_cookies")
        self.assertEqual(cookie["verdict"], "candidate")
        self.assertIsNone(cookie["what_was_established"])
        self.assertIn("用途を確認", cookie["remediation"]["steps"][0])

    def test_assessment_passes_only_the_accepted_site_cookie_spec(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), 1, l2_confinement=TEST_CONFINEMENT)
            try:
                svc.a.target_url = "https://owned-cookie.example.test/"
                observed = {"status": 200, "headers": {},
                            "set_cookies": [COOKIES["session_no_httponly"]]}
                ev = {"audit_hash": "cookie-lab-proof", "saved_at": 1}
                profile = {"cookie_policy": OWNER["session_no_httponly"]}
                with patch.object(svc, "_is_external_service_asset", return_value=True), \
                     patch.object(svc, "_l2_profile", return_value=profile), \
                     patch.object(svc, "_l2_candidates", return_value=[]):
                    svc._analyze(observed, ev)
                self.assertEqual(svc.a.findings["f_l1_cookies"]["verdict"], "detected")
                svc.a.findings.clear()
                profile["cookie_policy"] = {**profile["cookie_policy"], "status": "unaccepted"}
                with patch.object(svc, "_is_external_service_asset", return_value=True), \
                     patch.object(svc, "_l2_profile", return_value=profile), \
                     patch.object(svc, "_l2_candidates", return_value=[]):
                    svc._analyze(observed, ev)
                self.assertEqual(svc.a.findings["f_l1_cookies"]["verdict"], "candidate")
            finally:
                svc.close()

    def test_cookie_finding_requires_confirmed_purpose_and_observed_flag_gap(self):
        for mode, expected in TRUTH.items():
            with self.subTest(mode=mode):
                lab = CookiePurposeLab(mode)
                thread = threading.Thread(target=lab.serve_forever, daemon=True)
                thread.start()
                try:
                    with urlopen(f"http://127.0.0.1:{lab.server_port}/", timeout=3) as response:
                        observed = {"status": response.status, "headers": dict(response.headers),
                                    "set_cookies": response.headers.get_all("Set-Cookie"),
                                    "body_prefix": response.read().decode()}
                    findings = analyze_l1_service_response(
                        observed, {"audit_hash": "cookie-lab-proof", "saved_at": 1},
                        "https://owned-cookie.example.test/", cookie_policy=OWNER[mode])
                    cookie_findings = [f for f in findings if f["id"] == "f_l1_cookies"]
                    actual = cookie_findings[0]["verdict"] if cookie_findings else "none"
                    self.assertEqual(actual, expected)
                    if cookie_findings:
                        self.assertNotEqual(cookie_findings[0]["verdict"], "proven")
                    if mode == "session_samesite_none_mismatch":
                        self.assertIn("SameSite=Lax", cookie_findings[0]["remediation"]["steps"][0])
                        self.assertIn("仕様不一致", cookie_findings[0]["title"])
                    self.assertEqual(lab.seen, ["/"])
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)
