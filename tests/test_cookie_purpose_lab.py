"""Independent cookie purpose labels versus observed read-only response."""
from __future__ import annotations

import json
import tempfile
import threading
import time
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
    def test_fix_recheck_preserves_owner_cookie_purpose(self):
        host = "owned-cookie.example.test"
        lab = CookiePurposeLab("session_no_httponly")
        thread = threading.Thread(target=lab.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT,
                                        real_site_read_only=False)
                svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
                url = f"http://{host}:{lab.server_port}/"
                try:
                    challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                    svc.verify_asset_ownership(
                        url_or_host=url, method="dns_txt",
                        dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
                    )
                    svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                            activate_workspace=True, allow_loopback_test=True)
                    profile = validate_profile({
                        **json.loads((FIXTURES / "l2_profiles/example.json").read_text()),
                        "cookie_policy": OWNER["session_no_httponly"],
                    })
                    profile["checks"] = []
                    with patch.object(svc, "_l2_profile", return_value=profile):
                        svc.start()
                        deadline = time.monotonic() + 20
                        while time.monotonic() < deadline:
                            snap = svc.snapshot()
                            if snap["state"] in ("completed", "failed"):
                                break
                            time.sleep(0.02)
                        self.assertEqual(snap["state"], "completed", snap.get("failure"))
                        self.assertEqual(next(f for f in snap["findings"] if f["id"] == "f_l1_cookies")["verdict"],
                                         "detected")
                        lab.mode = "language_plain"
                        rerun = svc.verify_fix("approver")
                        item = next(i for i in rerun["defense_comparison"]["items"]
                                    if i["id"] == "f_l1_cookies")
                        self.assertEqual(item["after_verdict"], "not_reproduced")
                        current = next(f for f in rerun["findings"] if f["id"] == "f_l1_cookies")
                        self.assertEqual(current["cookie_checks"], [])
                        self.assertEqual(current["risk_score"], 0)
                        self.assertEqual(current["why_detected"], current["verdict_note"])
                        lab.mode = "session_like_unknown"
                        rerun = svc.verify_fix("approver")
                        item = next(i for i in rerun["defense_comparison"]["items"]
                                    if i["id"] == "f_l1_cookies")
                        self.assertEqual(item["after_verdict"], "candidate")
                        finding = next(f for f in rerun["findings"] if f["id"] == "f_l1_cookies")
                        self.assertIsNone(finding["what_was_established"])
                        self.assertEqual(finding["cookie_checks"][0]["purpose"], "unknown")
                        # A later recheck must use the current owner approval,
                        # even when the same unsafe session attribute returns.
                        lab.mode = "session_no_httponly"
                        profile["cookie_policy"] = {**profile["cookie_policy"],
                                                    "status": "unaccepted"}
                        rerun = svc.verify_fix("approver")
                        finding = next(f for f in rerun["findings"] if f["id"] == "f_l1_cookies")
                        self.assertEqual(finding["verdict"], "candidate")
                        self.assertIsNone(finding["what_was_established"])
                        self.assertEqual(finding["risk_score"], 0)
                        self.assertEqual(lab.seen, ["/", "/", "/", "/"])
                finally:
                    svc.close()
        finally:
            lab.shutdown()
            lab.server_close()
            thread.join(timeout=2)

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

    def test_session_same_site_policy_does_not_apply_to_unknown_cookie(self):
        observed = {"status": 200, "headers": {}, "set_cookies": [
            "auth=opaque; Secure; HttpOnly; SameSite=Lax",
            "aux=opaque; Secure; HttpOnly; SameSite=None",
        ]}
        findings = analyze_l1_service_response(
            observed, {"audit_hash": "cookie-lab-proof", "saved_at": 1},
            "https://owned-cookie.example.test/", cookie_policy=OWNER["session_no_httponly"])
        self.assertFalse([f for f in findings if f["id"] == "f_l1_cookies"])

    def test_mixed_cookies_keep_individual_verdicts_without_values(self):
        observed = {"status": 200, "headers": {}, "set_cookies": [
            "auth=secret-token; Secure; SameSite=Lax",
            "lang=ja; SameSite=Lax",
            "unknown=private-value; SameSite=Lax",
        ]}
        findings = analyze_l1_service_response(
            observed, {"audit_hash": "cookie-lab-proof", "saved_at": 1},
            "https://owned-cookie.example.test/", cookie_policy=OWNER["session_no_httponly"])
        cookie = next(f for f in findings if f["id"] == "f_l1_cookies")
        self.assertEqual(cookie["verdict"], "detected")
        self.assertEqual(cookie["cookie_checks"], [
            {"name": "auth", "purpose": "session", "verdict": "detected", "gaps": ["HttpOnly"]},
            {"name": "lang", "purpose": "non_session", "verdict": "none", "gaps": []},
            {"name": "unknown", "purpose": "unknown", "verdict": "candidate", "gaps": ["Secure", "HttpOnly"]},
        ])
        self.assertNotIn("secret-token", json.dumps(cookie, ensure_ascii=False))
        self.assertNotIn("private-value", json.dumps(cookie, ensure_ascii=False))
        self.assertIn("未確認", cookie["summary"])
        self.assertNotIn("unknown", cookie["what_was_established"])

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
                public = next(f for f in svc.snapshot()["findings"] if f["id"] == "f_l1_cookies")
                self.assertEqual(public["cookie_checks"][0]["name"], "auth")
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
