"""Regressions for the final pre-merge reviews (core controls + planner / CVE /
L1 analysis / export). Loopback only; no real model, feed or DNS is contacted."""
import json
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from aegis import cve, operators as ops_mod, router as router_mod
from aegis.assessment import ApproverRequired, AssessmentService
from aegis.network import NetworkError
from aegis.operators import AuthError, LockedOut, OperatorStore, totp_code
from aegis.remotion_export import build_remotion_export
from aegis.service_diag import analyze_l1_service_response, clean_target_text
from tests.test_access_control import ApiBase
from tests.test_attack_regressions import Clock
from tests.test_real_service import HOST, LAB_PORT, NOTE_B, PROFILE_DIRS, TOKEN_A, TOKEN_B, RealServiceBase


class Ready(ApiBase):
    def setUp(self):
        super().setUp()
        self.onboard()
        self.run_l1()
        self.set_secrets()
        self.fake.seen.clear()
        self.base = f"/assessments/{self.svc.a.id}"

    def authed_requests(self):
        return [p for p, a in self.fake.seen if a]


# ------------------------------------------------------------------ core controls
class TestApproverDecisionCannotBeRacedAround(Ready):
    def test_service_refuses_an_operator_even_when_no_http_check_ran_first(self):
        with self.assertRaises(ApproverRequired):
            self.svc.verify_finding("f_ex_idor", "op", roles=("operator",))
        self.assertEqual(self.fake.seen, [])
        denied = self.events("l2.run_denied")[-1]
        self.assertEqual((denied["actor"], denied["check"]), ("op", "ex_idor_notes"))
        self.assertEqual(self.events("approval.approved"), [])
        # an approver is unaffected
        self.svc.verify_finding("f_ex_idor", "appr", roles=("operator", "approver"))
        self.assertTrue(self.authed_requests())

    def test_operator_switching_assets_while_hammering_l2_never_gets_a_token_sent(self):
        real_id = self.svc.a.asset["id"]
        stop = threading.Event()
        codes: list[int] = []

        def switcher():
            while not stop.is_set():
                for target in ("lab", real_id):
                    self.call("/assets/select", {"id": target}, "op")

        def hammer():
            while not stop.is_set():
                codes.append(self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, "op")[0])
        self.session("op")
        threads = [threading.Thread(target=switcher, daemon=True)] + [
            threading.Thread(target=hammer, daemon=True) for _ in range(3)]
        for t in threads:
            t.start()
        time.sleep(2.5)
        stop.set()
        for t in threads:
            t.join(timeout=20)
        self.assertGreater(len(codes), 20)
        self.assertEqual(self.authed_requests(), [])            # no bearer token ever reached the service
        self.assertEqual([e for e in self.events("approval.approved") if e.get("risk_level") == "L2"], [])
        self.assertNotIn(200, [c for c in codes if c == 200 and self.authed_requests()])

    def test_failed_reverification_by_an_operator_is_decided_when_it_is_applied(self):
        with self.assertRaises(ApproverRequired):
            self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [], roles=("operator",))
        self.assertTrue(self.svc._is_external_service_asset(HOST))
        self.assertTrue(self.svc.secrets.has_any_token(HOST))

    def test_no_route_activates_another_asset_during_a_verification(self):
        self.svc._begin_operation()
        try:
            with self.assertRaises(ValueError):
                self.svc.register_asset(name="other.lab.test", kind="API", environment="x",
                                        authorization_ref="SOW-9", ownership_verified=True, activate_workspace=True)
            self.assertEqual(self.svc.a.asset["name"], HOST)
        finally:
            self.svc._end_operation()


class TestPersistenceCannotBeWedgedQuietly(Ready):
    def test_unstorable_input_is_refused_at_the_door(self):
        raw = b'{"name": "wedge.example", "kind": "\\ud800", "environment": "x"}'
        req = urllib.request.Request(self.api + "/assets", raw, {
            "Content-Type": "application/json", "X-Aegis-Request": "1", "Cookie": self.session("op")})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(req)
        self.assertEqual(cm.exception.code, 400)
        with self.assertRaises(ValueError):
            self.svc.register_asset(name="wedge.example", kind="\ud800", environment="x")
        with self.assertRaises(ValueError):
            self.svc.register_asset(name="bad name<script>", kind="API", environment="x")

    def test_any_save_failure_is_noticed_and_stops_real_service_work(self):
        self.svc._extra_assets.append({"id": "x", "name": "x.lab.test", "kind": "\ud800", "environment": "e"})
        self.svc._save_state_locked()                           # not an OSError, still a failed save
        self.assertIsNotNone(self.svc._persist_error)
        self.assertIsNotNone(self.svc.snapshot()["persistence_error"])
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", "appr", roles=("operator", "approver"))
        self.assertEqual(self.fake.seen, [])


class TestPathOverridesStayInsideTheAcceptedProfile(Ready):
    def test_an_approver_cannot_point_a_token_bearing_request_at_an_arbitrary_path(self):
        for key, value in (("note_b_path", "/api/admin/export?all=1"),      # outside the allowed pattern
                           ("note_b_path", "/api/notes/../admin"),
                           ("note_a_path", "/api/notes/other")):            # no pattern: not overridable
            with self.subTest(key=key, value=value):
                code, body = self.call("/assets/secrets", {"host": HOST, "mock_paths": {key: value}}, "appr")
                self.assertEqual(code, 409)
        self.assertEqual(self.call("/assets/secrets", {"host": HOST, "mock_paths": {
            "note_b_path": "/api/notes/b1"}}, "appr")[0], 200)
        self.svc.verify_finding("f_ex_idor", "appr")
        self.assertEqual(set(self.authed_requests()), {NOTE_B, "/api/notes/a1"})

    def test_a_stored_override_that_no_longer_fits_releases_no_tokens(self):
        self.svc.secrets._cache[HOST]["note_b_path"] = "/api/admin/export"       # e.g. saved under an older profile
        self.assertEqual(self.svc._ephemeral_worker_env("reproduction_probe", {"check": "ex_idor_notes"}), {})
        shown = self.svc._describe_rule(self.svc._l2_profile(), self.svc._active_l2_check("ex_idor_notes"))
        self.assertEqual(shown["request"]["path_override_pattern"], "/api/notes/[A-Za-z0-9_-]{1,64}")
        self.assertEqual(shown["request"]["headers"], {"X-Probe": "vulnix"})     # values, not only names


class TestScopeEndpointMismatch(RealServiceBase):
    def test_confirming_a_different_endpoint_than_the_proven_one_is_refused(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=self._token_lookup(ch))
        for other in (f"https://{HOST}/", f"http://{HOST}:{self.fake.server_port + 1}/"):
            with self.assertRaises(ValueError):
                self.svc.confirm_asset_scope(url_or_host=other, approver="appr", allow_loopback_test=True)
        self.assertNotIn(HOST, self.svc._verified_external_hosts)
        self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", allow_loopback_test=True)


class TestSignInEdgeCases(ApiBase):
    def test_a_correct_current_password_is_never_counted_as_a_guess(self):
        for _ in range(ops_mod.MAX_AUTH_FAILURES + 2):
            with self.assertRaises(AuthError) as cm:
                self.ops.change_password("op", "op-password", "short")
            self.assertNotIsInstance(cm.exception, LockedOut)
        self.assertEqual(self.ops.login("op", "op-password").operator, "op")

    def test_a_used_totp_code_stays_used_after_a_restart(self):
        clock = Clock()
        store = OperatorStore(self.dir / "operators.json", clock=clock)
        secret, _ = store.begin_totp_enroll("appr")
        store.confirm_totp("appr", totp_code(secret, clock.t))
        clock.t += 60
        code = totp_code(secret, clock.t)
        store.login("appr", "appr-password", code)
        again = OperatorStore(self.dir / "operators.json", clock=clock)
        with self.assertRaises(AuthError):
            again.login("appr", "appr-password", code)

    def test_a_broken_unlock_request_does_not_break_sign_in(self):
        request = self.dir / "unlock.request"
        request.write_bytes(b"\xff\xfe\x00root")
        request.chmod(0o600)
        self.assertEqual(self.ops.login("op", "op-password").operator, "op")
        self.assertFalse(request.exists())
        request.mkdir()
        for _ in range(3):
            self.assertEqual(self.ops.login("op", "op-password").operator, "op")
        self.assertLessEqual(len(self.ops.recovery_events), 1)
        request.rmdir()
        target = self.dir / "elsewhere.txt"
        target.write_text("root\n")
        request.symlink_to(target)
        self.ops.login("op", "op-password")
        self.assertTrue(target.exists())                         # the link target is untouched and not honoured
        self.assertNotIn({"event": "auth.unlocked_by_file", "name": "root", "was_locked": False},
                         self.ops.recovery_events)

    def test_a_full_lock_table_never_shuts_out_a_real_account(self):
        with patch("aegis.operators._MAX_TRACKED_NAMES", 10), \
                patch("aegis.operators.verify_password", return_value=False):
            for i in range(10):
                for _ in range(ops_mod.MAX_AUTH_FAILURES + 1):
                    try:
                        self.ops.login(f"made-up-{i}", "x")
                    except AuthError:
                        pass
        self.assertEqual(self.ops.login("root", "root-password").operator, "root")


# ------------------------------------------------------------------ planner / model
class RecordingBackend:
    name = "external-recorder"
    _model = "stub-model"

    def __init__(self, proposals=()):
        self.contexts, self.chats = [], []
        self._proposals = list(proposals)

    def propose(self, context):
        self.contexts.append(context)
        return [dict(p) for p in self._proposals]

    def chat(self, question, context):
        self.chats.append((question, context))
        return "external answer"


class TestNothingAboutARealServiceLeavesTheMachine(RealServiceBase):
    def test_external_planner_and_chat_are_not_used_for_a_real_service(self):
        external = RecordingBackend()
        self.svc.router.register(external)
        self.svc._chat_backend = external
        self.onboard()
        snap = self.run_l1()
        self.assertEqual(snap["state"], "completed")
        self.assertEqual(external.contexts, [])                  # the URL was not sent to the external planner
        fid = next(f["id"] for f in snap["findings"] if f.get("evidence"))
        reply = self.svc.ask_chat("この問題を説明して", "appr", finding_id=fid)
        self.assertEqual(external.chats, [])                     # evidence, cookies, challenge stayed local
        self.assertNotEqual(reply["message"]["source"], "external_model")
        asked = [e["fields"] for e in self.svc.audit.entries() if e["event"] == "chat.asked"][-1]
        self.assertFalse(asked["sent_to_external_model"])
        # the lab is where the external model may be used, and that is recorded
        self.svc.select_asset("lab")
        self.svc.ask_chat("IDORとは", "appr")
        self.assertEqual(len(external.chats), 1)
        asked = [e["fields"] for e in self.svc.audit.entries() if e["event"] == "chat.asked"][-1]
        self.assertTrue(asked["sent_to_external_model"])

    def test_proposals_that_were_not_executed_are_not_reported_as_executed(self):
        lab_url = self.svc.a.target_url
        rogue = RecordingBackend([
            {"tool": "http_probe", "target_id": "lab", "action": "read_only_probe",
             "args": {"url": "http://169.254.169.254/latest/meta-data/", "method": "POST"},
             "rationale": "fetch metadata"},
            {"tool": "reproduction_probe", "target_id": "lab", "action": "safe_reproduction",
             "args": {"url": lab_url, "check": "sqli"}, "rationale": "try injection"}])
        self.svc.router.register(rogue)
        self.svc.start()
        end = time.time() + 20
        while time.time() < end and not any(t.phase == "config" for t in self.svc.artex.tasks):
            time.sleep(0.05)
        time.sleep(0.5)
        config_tasks = [t for t in self.svc.artex.tasks if t.phase == "config"]
        executed = [t for t in config_tasks if t.status == "completed"]
        self.assertTrue(config_tasks)
        for t in executed:                                       # only the fixed read-only GET counts as executed
            p = t.routed.proposal
            self.assertEqual((p["tool"], p["args"].get("url"), str(p["args"].get("method", "GET")).upper()),
                             ("http_probe", lab_url, "GET"))
        self.assertTrue(any(t.status == "not_executed" for t in config_tasks))
        self.svc.emergency_stop("appr")


class TestModelEndpointTransport(unittest.TestCase):
    def test_key_is_not_sent_in_cleartext_or_across_a_redirect(self):
        for url in ("http://model.example.org/v1/chat", "ftp://model.example.org/x", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                router_mod._http_transport(url, {"Authorization": "Bearer k"}, b"{}")
        self.assertIsNone(router_mod._NoRedirect().redirect_request(None, None, 302, "Found", {}, "http://other/"))
        with patch("aegis.router._open_model_url") as opened:
            opened.return_value.__enter__.return_value.read.return_value = b"x" * (router_mod.MAX_MODEL_RESPONSE_BYTES + 1)
            with self.assertRaises(ValueError):
                router_mod._http_transport("https://model.example.org/v1", {}, b"{}")
            opened.return_value.__enter__.return_value.read.return_value = b"{}"
            self.assertEqual(router_mod._http_transport("http://127.0.0.1:9/v1", {}, b"{}"), b"{}")


# ------------------------------------------------------------------ hostile target responses
EV = {"evidence_id": "ev_1", "audit_hash": "h", "saved_at": 1.0, "content": "{}"}


def analyze(headers=None, *, url="https://x.example/", status=200, cookies=None, tls=True):
    res = {"status": status, "headers": headers or {}, "set_cookies": cookies or [],
           "cors_probe_origin": "https://untrusted-origin.example"}
    if tls:
        res["tls"] = {"version": "TLSv1.3"}
    return {f["id"]: f for f in analyze_l1_service_response(res, EV, url)}


GOOD = {"Strict-Transport-Security": "max-age=31536000", "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff", "Content-Type": "text/html"}


class TestHostileResponses(unittest.TestCase):
    def test_huge_or_malicious_headers_neither_stall_nor_fail_nor_inject(self):
        started = time.time()
        self.assertEqual(cve.detect_from_banner("a/" * 60000 + "1." * 60000), [])
        self.assertEqual(cve.detect_from_banner("Apache/2.4." + "9" * 5000), [])
        self.assertIsInstance(cve.parse_version("1." + "9" * 5000), tuple)
        hostile = {**GOOD, "Server": "nginx/1.25.3 <img src=x onerror=alert(1)> [click](http://evil) `code`" + "A" * 60000,
                   "X-Powered-By": "PHP/8.1 \x00\x1b[31m\r\nInjected: 1"}
        found = analyze(hostile)
        self.assertLess(time.time() - started, 5)
        text = json.dumps(found, ensure_ascii=False)
        for bad in ("<img", "](http", "`code`", "\\u0000", "\\u001b", "\\r\\n"):
            self.assertNotIn(bad, text)
        self.assertLess(max(len(f["title"]) for f in found.values()), 800)
        self.assertEqual(clean_target_text("a<b>[c](d)`e`\x07" + "z" * 9999, 20), "abc(d)e" + "z" * 13)

    def test_report_does_not_carry_markup_from_a_target(self):
        class Probe(RealServiceBase):
            def runTest(self):
                pass
        t = Probe()
        Probe.setUpClass()
        t.setUp()
        try:
            with patch("tests.test_real_service._FakeHandler.version_string",
                       return_value="nginx <script>alert(1)</script> [x](http://evil)"):
                t.onboard()
                t.run_l1()
            report = t.svc.report_markdown()
            self.assertNotIn("<script>", report)
            self.assertNotIn("](http://evil)", report)
        finally:
            t.tearDown()
            Probe.tearDownClass()


class TestL1AnalyzerSaysOnlyWhatTheResponseShows(unittest.TestCase):
    def test_clean_response_has_no_findings(self):
        self.assertEqual(analyze(GOOD, cookies=["sid=1; Secure; HttpOnly; SameSite=Lax"]), {})

    def test_cookie_attributes_are_parsed_not_substring_matched(self):
        found = analyze(GOOD, cookies=["__Secure-sid=abc", "pref=httponly_samesite_secure"])
        self.assertIn("f_l1_cookies", found)
        summary = json.dumps(found["f_l1_cookies"], ensure_ascii=False)
        self.assertIn("__Secure-sid", summary)
        self.assertIn("pref", summary)
        self.assertNotIn("f_l1_cookies", analyze(GOOD, cookies=["a=1; secure; HTTPONLY; SameSite=Strict"]))

    def test_hsts_with_zero_max_age_is_not_a_protection(self):
        self.assertIn("f_headers", analyze({**GOOD, "Strict-Transport-Security": "max-age=0"}))
        self.assertIn("f_headers", analyze({**GOOD, "Strict-Transport-Security": "includeSubDomains"}))
        self.assertNotIn("f_headers", analyze({**GOOD, "Strict-Transport-Security": 'max-age="63072000"; preload'}))

    def test_cors_null_origin_with_credentials_is_high(self):
        found = analyze({**GOOD, "Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"})
        self.assertEqual(found["f_l1_cors"]["severity"], "high")

    def test_a_redirect_is_not_blamed_for_missing_document_headers(self):
        found = analyze({"Location": "https://x.example/app", "Strict-Transport-Security": "max-age=31536000"},
                        status=301)
        self.assertNotIn("f_headers", found)
        self.assertIn("f_headers", analyze({"Location": "https://x.example/app"}, status=301))   # HSTS still applies

    def test_structured_json_media_types_are_recognised(self):
        self.assertIn("f_l1_unauth_api", analyze({**GOOD, "Content-Type": "application/vnd.api+json; charset=utf-8"}))
        self.assertNotIn("f_l1_unauth_api", analyze({**GOOD, "Content-Type": "text/html; note=application/json"}))

    def test_plain_http_is_reported(self):
        found = analyze({"Content-Type": "text/html"}, url="http://x.example/", tls=False)
        self.assertEqual((found["f_l1_no_tls"]["severity"], found["f_l1_no_tls"]["verdict"]), ("high", "proven"))
        self.assertNotIn("f_l1_no_tls", analyze(GOOD))


class TestCveMatchingIsNotCrossWired(unittest.TestCase):
    def test_a_multi_product_cve_does_not_flag_the_other_products_versions(self):
        obj = {"vulnerabilities": [{"cve": {
            "id": "CVE-2099-0001", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:venda:producta:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0"},
                {"vulnerable": True, "criteria": "cpe:2.3:a:vendb:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "9.0"},
            ]}]}]}}]}
        catalog = tuple(cve.load_nvd(obj))
        self.assertEqual(cve.match("nginx", "1.25.3", catalog), [])
        self.assertEqual([c.id for c in cve.match("producta", "1.5", catalog)], ["CVE-2099-0001"])
        self.assertEqual(cve.match("producta", "5.0", catalog), [])           # nginx's range is not producta's


# ------------------------------------------------------------------ export
class TestExport(Ready):
    def test_l1_observations_are_not_labelled_as_l2_and_identifiers_are_removed(self):
        self.svc.a.findings["f_headers"]["title"] += f" seen at {HOST.upper()}:8443 and 203.0.113.9 / 2001:db8::1"
        out = self.svc.remotion_export()
        text = json.dumps(out, ensure_ascii=False)
        for leak in (HOST, HOST.upper(), "203.0.113.9", "2001:db8::1", ":8443"):
            self.assertNotIn(leak, text)
        l1 = [f for f in out["confirmed_findings"] if f["verification_status"] == "proven"]
        self.assertTrue(l1)
        self.assertTrue(all("L2" not in f["verification_badge"] for f in l1))
        self.svc.verify_finding("f_ex_idor", "appr")
        proven_l2 = next(f for f in self.svc.remotion_export()["confirmed_findings"] if f["id"] == "f_ex_idor")
        self.assertIn("L2", proven_l2["verification_badge"])
        self.assertNotIn(TOKEN_A, text)

    def test_the_identifying_export_needs_authority_and_is_recorded(self):
        path = self.base + "/remotion?anonymize=0"
        self.assertEqual(self.call(path, who="op")[0], 403)
        self.assertEqual(self.call(self.base + "/remotion", who="op")[0], 200)
        code, body = self.call(path, who="appr")
        self.assertEqual(code, 200)
        self.assertIn(HOST, json.dumps(body))
        self.assertEqual(self.events("export.remotion_identified")[-1]["actor"], "appr")


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------------------------ verification-review follow-ups
class TestVerificationReviewFollowUps(Ready):
    def test_a_refused_operator_recheck_leaves_the_asset_usable_and_is_audited(self):
        with self.assertRaises(ApproverRequired):
            self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [], roles=("operator",), actor="op")
        self.assertTrue(self.svc.a.asset.get("ownership_verified", True))
        self.assertEqual(self.events("asset.reverification_denied")[-1]["actor"], "op")
        real_id = self.svc.a.asset["id"]
        self.svc.select_asset("lab")
        self.svc.select_asset(real_id)                            # still selectable by the approver
        self.assertTrue(self.svc._is_external_service_asset())

    def test_text_from_a_model_cannot_make_state_unsaveable(self):
        class Model:
            _model = "stub"

            def chat(self, q, ctx):
                return "answer with a lone surrogate \ud800 and more"
        self.svc.select_asset("lab")
        self.svc._chat_backend = Model()
        self.svc.ask_chat("IDORとは", "appr")
        self.svc._save_state_locked()
        self.assertIsNone(self.svc._persist_error)
        json.loads((self.dir / "state.json").read_text(encoding="utf-8"))

    def test_scheme_less_host_with_another_port_is_refused_too(self):
        with self.assertRaises(ValueError):
            self.svc.confirm_asset_scope(url_or_host=f"{HOST}:{self.fake.server_port + 1}", approver="appr",
                                         allow_loopback_test=True)
        self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", allow_loopback_test=True)   # no port named

    def test_verification_is_refused_while_paused_instead_of_blocking_asset_switches(self):
        from aegis.gateway import State
        self.svc.gateway._state = State.PAUSED
        try:
            with self.assertRaises(ValueError):
                self.svc.verify_finding("f_headers", "appr")
            self.assertEqual(self.svc._inflight, 0)
        finally:
            self.svc.gateway._state = State.RUNNING if hasattr(State, "RUNNING") else list(State)[0]


class TestOverridePatternsAreASafeSubset(unittest.TestCase):
    def test_wildcards_groups_and_negated_classes_are_rejected_at_load(self):
        from aegis.l2_rules import RuleError, validate_profile
        base = json.loads((Path(__file__).parent / "fixtures" / "l2_profiles" / "example.json").read_text(encoding="utf-8"))
        validate_profile(base)
        for bad in (".*", "/.*", "a|/.*", "/(a+)+b", "/api/notes/[^/]+", "/api/notes/.+", "/api/notes/[A-Za-z0-9%]{1,9}",
                    "/api/notes/[A-Za-z0-9_-]{1,9999}", "/api/notes/[a-z.]{1,9}"):
            raw = json.loads(json.dumps(base))
            raw["paths"]["note_b_path"]["override_pattern"] = bad
            with self.subTest(pattern=bad):
                with self.assertRaises(RuleError):
                    validate_profile(raw)


class TestAnalyzerFollowUps(unittest.TestCase):
    def test_http_endpoint_that_only_redirects_to_https_is_not_reported_as_plain_http(self):
        ok = analyze({"Location": "https://x.example/"}, url="http://x.example/", status=301, tls=False)
        self.assertNotIn("f_l1_no_tls", ok)
        self.assertIn("f_l1_no_tls", analyze({"Location": "http://x.example/login"}, url="http://x.example/",
                                             status=302, tls=False))

    def test_lookalike_hsts_directive_and_invisible_characters(self):
        self.assertIn("f_headers", analyze({**GOOD, "Strict-Transport-Security": "xmax-age=600"}))
        self.assertEqual(clean_target_text("a‮b c\x85d"), "abcd")
