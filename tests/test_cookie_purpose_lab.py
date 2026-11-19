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

    def test_newly_issued_set_cookie_secret_is_never_persisted_in_evidence_audit_or_exports(self):
        import http.server
        import ssl
        import subprocess

        canary = "CANARY_SECRET_VALUE_9f8e7d6c5b4a"
        quoted_canary = 'CANARY_QUOTED_"SECRET;Secure"_VALUE'
        host = "owned-cookie-canary.example.test"

        class _CanaryHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header(
                    "Set-Cookie",
                    f"session={canary}; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax",
                )
                self.send_header(
                    "Set-Cookie",
                    f'auth="{quoted_canary}"; Path=/; Secure; SameSite=Lax',
                )
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            cert = tmp_path / "cert.pem"
            key = tmp_path / "key.pem"
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(cert),
                    "-subj", f"/CN={host}",
                    "-addext", f"subjectAltName=DNS:{host},IP:127.0.0.1",
                    "-days", "1",
                ],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert), str(key))
            srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _CanaryHandler)
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            thread = threading.Thread(target=srv.serve_forever, daemon=True)
            thread.start()
            try:
                with patch.dict("os.environ", {"VULNIX_TEST_CA_FILE": str(cert)}):
                    svc = AssessmentService(tmp_path / "data", 18081, l2_confinement=TEST_CONFINEMENT,
                                            real_site_read_only=False)
                    svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
                    url = f"https://{host}:{srv.server_port}/"
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

                        snap_json = json.dumps(snap, ensure_ascii=False)
                        report_md = svc.report_markdown()
                        audit_json = json.dumps(svc.logs(), ensure_ascii=False)
                        remotion_anon = json.dumps(svc.remotion_export(anonymize=True), ensure_ascii=False)
                        remotion_full = json.dumps(svc.remotion_export(anonymize=False), ensure_ascii=False)
                        state_disk = (tmp_path / "data" / "state.json").read_text(encoding="utf-8")
                        audit_disk = (tmp_path / "data" / "audit.jsonl").read_text(encoding="utf-8")

                        for secret in (canary, quoted_canary):
                            self.assertNotIn(secret, snap_json)
                            self.assertNotIn(secret, report_md)
                            self.assertNotIn(secret, audit_json)
                            self.assertNotIn(secret, remotion_anon)
                            self.assertNotIn(secret, remotion_full)
                            self.assertNotIn(secret, state_disk)
                            self.assertNotIn(secret, audit_disk)

                        cookie_finding = next(f for f in snap["findings"] if f["id"] == "f_l1_cookies")
                        self.assertEqual(cookie_finding["verdict"], "detected")
                        checks_by_name = {c["name"]: c for c in cookie_finding["cookie_checks"]}
                        self.assertEqual(checks_by_name["session"], {
                            "name": "session", "purpose": "unknown", "verdict": "none", "gaps": [],
                        })
                        self.assertEqual(checks_by_name["auth"], {
                            "name": "auth", "purpose": "session", "verdict": "detected", "gaps": ["HttpOnly"],
                        })
                    finally:
                        svc.close()
            finally:
                srv.shutdown()
                srv.server_close()
                thread.join(timeout=2)

    def test_set_cookie_edge_cases_and_boundary_defenses(self):
        from aegis.evidence import enforce_verdict
        from aegis.service_diag import sanitize_http_probe_payload
        from aegis.workers.http_probe import sanitize_set_cookie_header
        from aegis.runtime import WorkerResult

        # 1. Quoted semicolons, Expires commas, case insensitivity, empty value, malformed attributes
        raw_1 = 'auth="VAL_1;HttpOnly;Secure"; Expires=Wed, 21 Oct 2026 07:28:00 GMT; sEcUrE; SameSite=lAx; Domain=secret.internal.example; Path=/admin/secret'
        s_1 = sanitize_set_cookie_header(raw_1)
        self.assertNotIn("VAL_1", s_1)
        self.assertNotIn("secret.internal.example", s_1)
        self.assertNotIn("/admin/secret", s_1)
        self.assertIn("auth=[REDACTED]", s_1)
        self.assertIn("Secure", s_1)
        self.assertIn("SameSite=lAx", s_1)

        # Empty value and missing '='
        self.assertEqual(sanitize_set_cookie_header("empty_val=; HttpOnly; Secure; SameSite=Strict"),
                         "empty_val=[REDACTED]; HttpOnly; Secure; SameSite=Strict")
        self.assertEqual(sanitize_set_cookie_header("bare_token_without_equals; Secure"),
                         "cookie=[REDACTED]; Secure")

        # Huge header and oversized cookie name
        huge_secret = "SECRET_HUGE_" + ("X" * 20000)
        huge_name = "N" * 200
        s_huge = sanitize_set_cookie_header(f"{huge_name}={huge_secret}; Secure; HttpOnly; SameSite=Lax")
        self.assertNotIn("SECRET_HUGE_", s_huge)
        self.assertTrue(s_huge.startswith(("N" * 64) + "=[REDACTED]"))

        # Duplicate Set-Cookie headers & conflicting duplicate attributes in a single header
        observed = sanitize_http_probe_payload({
            "status": 200,
            "headers": {"Set-Cookie": "auth=LEAK_HEADER_VAL; Secure"},
            "set_cookies": [
                'auth="VAL_1;HttpOnly"; Secure; SameSite=Lax',
                "auth=VAL_2; Secure; HttpOnly; SameSite=Lax; SameSite=None",
                "other=VAL_3; sEcUrE; hTtPoNlY; sAmEsItE=sTrIcT",
            ],
        })
        self.assertNotIn("Set-Cookie", observed["headers"])
        self.assertEqual(len(observed["set_cookies"]), 3)
        for leaked in ("LEAK_HEADER_VAL", "VAL_1", "VAL_2", "VAL_3"):
            self.assertNotIn(leaked, json.dumps(observed))

        findings = analyze_l1_service_response(
            observed, {"audit_hash": "edge-proof", "saved_at": 1},
            "https://owned-cookie.example.test/", cookie_policy=OWNER["session_no_httponly"])
        cookie_f = next(f for f in findings if f["id"] == "f_l1_cookies")
        self.assertEqual(cookie_f["verdict"], "detected")
        self.assertEqual(cookie_f["cookie_checks"], [
            {"name": "auth", "purpose": "session", "verdict": "detected", "gaps": ["HttpOnly"]},
            {"name": "auth", "purpose": "session", "verdict": "candidate", "gaps": ["SameSite=Lax", "属性の重複・不一致"]},
            {"name": "other", "purpose": "unknown", "verdict": "none", "gaps": []},
        ])

        # Legacy persisted evidence is scrubbed when loaded via enforce_verdict
        legacy_finding = {
            "id": "f_headers",
            "verdict": "detected",
            "evidence": [{
                "evidence_id": "ev_legacy",
                "tool": "http_probe",
                "audit_hash": "h",
                "saved_at": 1.0,
                "content": json.dumps({
                    "status": 200,
                    "headers": {"Set-Cookie": "sid=LEGACY_RAW_COOKIE_SECRET; Path=/"},
                    "set_cookies": ["sid=LEGACY_RAW_COOKIE_SECRET; Path=/"],
                }),
            }],
        }
        cleaned_finding = enforce_verdict(legacy_finding)
        self.assertNotIn("LEGACY_RAW_COOKIE_SECRET", json.dumps(cleaned_finding))

        # Fail-closed when secret redaction fails in Gateway or AssessmentService
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT)
            try:
                with patch.object(svc.workers, "run", return_value=WorkerResult(
                    0, json.dumps({"status": 200, "headers": {}, "set_cookies": []}), "", False, 0.01
                )):
                    with patch.object(svc.gateway, "secret_redactor", side_effect=RuntimeError("boom")):
                        res, ev = svc._exec("http_probe", "read_only_probe", {"url": "http://lab.test:18081/"})
                        self.assertIsNone(res)
                        self.assertIsNone(ev)
                        self.assertEqual(svc.a.state, "failed")
            finally:
                svc.close()
