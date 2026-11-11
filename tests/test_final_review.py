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
        public = self.svc.remotion_export()
        self.assertEqual([f["title"] for f in public["confirmed_findings"] if "L2" in f["verification_badge"]],
                         ["認可・アクセス制御の検証項目"])
        self.assertNotIn("f_ex_idor", json.dumps(public))          # profile-defined ids are not published either
        self.assertNotIn(TOKEN_A, text)

    def test_the_identifying_export_needs_authority_and_is_recorded(self):
        path = self.base + "/remotion?anonymize=0"
        self.assertEqual(self.call(path, who="op")[0], 403)
        self.assertEqual(self.call(self.base + "/remotion", who="op")[0], 200)
        code, body = self.call(path, who="appr")
        self.assertEqual(code, 200)
        self.assertIn(HOST, json.dumps(body))
        self.assertEqual(self.events("export.remotion_identified")[-1]["actor"], "appr")



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


# ------------------------------------------------------------------ publishable export: allow-list
class TestPublicExportIsAnAllowList(unittest.TestCase):
    MARK = "LEAK-MARKER"

    def snapshot(self):
        m = self.MARK
        ev = {"evidence_id": f"ev_{m}", "audit_hash": "ab12cd34ef56ab12cd34", "saved_at": 1.0, "tool": "http_probe",
              "target_url": f"https://{m}.internal.example:8443/{m}", "content": f"Set-Cookie: sid={m}"}
        def finding(fid, status, level="L1", **extra):
            return {"id": fid, "title": f"{m} title", "severity": "high", "risk_score": 71, "risk_level": level,
                    "risk_rationale": f"{m} rationale", "evidence_status": status, "summary": f"{m} summary",
                    "impact": f"{m} impact", "category": f"{m} category", "verdict_note": f"{m} note",
                    "why_detected": f"{m} why", "remediation": {"steps": [f"{m} step"], "how_to_verify": f"{m} how"},
                    "executor": {"tool": "http_probe", "agent": f"{m} agent"}, "evidence": [ev], **extra}
        return {
            "id": f"scan_{m}", "demo": False, "is_external_service": True, "state": "completed",
            "target_url": f"https://{m}.internal.example:8443/", "risk": {"score": 64, "label": "中リスク", "basis": f"{m} basis"},
            "asset": {"id": f"asset_{m}", "name": f"{m}.internal.example", "display_name": f"{m} display",
                      "approver": f"{m}-approver", "challenge": {"token": f"vulnix-verify={m}"}, "environment": f"{m} env"},
            "authorization": {"ref": f"SOW-{m}"},
            "findings": [finding("f_headers", "proven"), finding(f"f_{m}_custom", "detected"),
                         finding(f"f_{m}_l2", "proven", "L2", executor={"tool": "reproduction_probe"}),
                         finding("f_l1_cors", "candidate"), finding(f"f_{m}_sev", "detected", severity=f"{m}-sev")],
            "artex_tasks": [{"id": f"t_{m}", "phase": "config", "title": f"{m} model rationale", "tool": "http_probe",
                             "status": "completed"},
                            {"id": "t2", "phase": f"{m}-phase", "title": "x", "tool": f"{m}-tool", "status": "completed"},
                            {"id": "t3", "title": f"{m} unsupported", "tool": "x", "status": "unsupported"}],
            "defense_comparison": {"actor": f"{m}-actor", "items": [
                {"id": f"f_{m}_l2", "title": f"{m} cmp", "severity": "high", "before_verdict": "proven",
                 "after_verdict": f"{m}-verdict", "latest_evidence_id": f"ev_{m}"}]},
            "secrets_status": {"host": f"{m}.internal.example"}, "chat_messages": [{"text": m}],
        }

    def test_no_text_from_the_assessment_reaches_the_public_export(self):
        from aegis import remotion_export as rx
        out = build_remotion_export(self.snapshot(), [{"event": "auth.login", "fields": {"actor": self.MARK}}])
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(self.MARK, text)
        self.assertNotIn("internal.example", text)
        self.assertNotIn("8443", text)
        allowed = rx.public_strings()
        seen: list[str] = []

        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    self.assertIsInstance(k, str)
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
            elif isinstance(node, str):
                seen.append(node)
            else:
                self.assertTrue(node is None or isinstance(node, (bool, int, float)), node)
        walk(out)
        for s in seen:
            ok = (s in allowed or s == "" or rx._HEX.fullmatch(s) is not None
                  or __import__("re").fullmatch(r"(finding|check)-\d{1,4}", s) is not None)
            self.assertTrue(ok, f"string not on the allow-list: {s!r}")
        # still useful: counts, statuses, badges and evidence digests survive
        self.assertEqual(out["summary"]["confirmed_findings_count"], 4)
        self.assertEqual(out["summary"]["proven_count"], 2)
        badges = [f["verification_badge"] for f in out["confirmed_findings"]]
        self.assertIn("実証済み（L2再現確認）", badges)
        self.assertIn("実測で確認（L1読み取り専用の観測）", badges)
        self.assertEqual(out["confirmed_findings"][0]["title"], "セキュリティヘッダーの未設定")
        self.assertEqual(out["confirmed_findings"][0]["audit_hash"], "ab12cd34ef56ab12")
        self.assertEqual(out["confirmed_findings"][-1]["severity"], "medium")        # unknown value -> default
        self.assertEqual(out["service"]["target_url"], "https://verified-service.example/")
        self.assertEqual(out["before_after_comparisons"][0]["after_status"], "unverified")
        self.assertNotIn("exported_at", out)

    def test_the_identifying_export_is_unchanged_and_opt_in(self):
        out = build_remotion_export(self.snapshot(), anonymize=False)
        self.assertIn(self.MARK, json.dumps(out, ensure_ascii=False))
        self.assertFalse(out["anonymized"])


# ------------------------------------------------------------------ fail closed when state cannot be saved
class TestNothingIsSentWhileStateCannotBeSaved(Ready):
    def broken_disk(self):
        return patch("aegis.assessment.os.replace", side_effect=OSError("read-only file system"))

    def test_every_entry_point_sends_nothing(self):
        real_id = self.svc.a.asset["id"]
        with self.broken_disk():
            for name, call in (
                ("verify L1 item", lambda: self.svc.verify_finding("f_headers", "appr")),
                ("verify L2 item", lambda: self.svc.verify_finding("f_ex_idor", "appr", roles=("approver",))),
                ("verify all", lambda: self.svc.verify_finding("all", "appr")),
                ("verify fix", lambda: self.svc.verify_fix("appr")),
                ("restart", lambda: self.svc.restart("appr")),
                ("direct exec", lambda: self.svc._exec("http_probe", "read_only_probe",
                                                       {"url": self.svc.a.target_url, "method": "GET"},
                                                       approval_actor="verify:appr")),
            ):
                with self.subTest(entry=name):
                    try:
                        result = call()
                    except (ValueError, NetworkError):
                        result = None
                    time.sleep(0.3)
                    self.assertEqual(self.fake.seen, [], name)
                    if name == "direct exec":
                        self.assertEqual(result, (None, None))
            self.assertIsNotNone(self.svc.snapshot()["persistence_error"])
        self.assertTrue(self.events("state.persist_failed"))
        self.assertEqual(self.svc.a.asset["id"], real_id)

    def test_a_run_already_in_progress_stops_before_its_next_request(self):
        # saving breaks AFTER the run was allowed to start: the request inside the run is still refused
        self.svc._reset_workspace_locked()
        self.fake.seen.clear()
        real_ensure = self.svc._ensure_active_window_locked
        state = {"armed": False}

        def ensure_then_break():
            real_ensure()
            state["armed"] = True
        real_replace = __import__("os").replace

        def flaky_replace(src, dst):
            if state["armed"] and str(dst).endswith("state.json"):
                raise OSError("disk full")
            return real_replace(src, dst)
        with patch.object(self.svc, "_ensure_active_window_locked", side_effect=ensure_then_break), \
                patch("aegis.assessment.os.replace", side_effect=flaky_replace):
            self.svc.start()
            end = time.time() + 15
            while time.time() < end and self.svc.snapshot()["state"] == "running":
                time.sleep(0.05)
        self.assertEqual(self.svc.snapshot()["state"], "failed")
        self.assertEqual(self.fake.seen, [])                      # not even the read-only GET went out

    def test_proof_recheck_is_not_attempted_either(self):
        lookups = []
        self.svc._proof_dns_lookup = lambda n: lookups.append(n) or []
        self.svc._verified_external_hosts[HOST]["allow_loopback_test"] = False
        self.svc._custom_resolver = lambda h: ["93.184.216.34"]
        self.svc._persist_error = "OSError"
        with self.assertRaises(NetworkError):
            self.svc._resolve_host(HOST)
        self.assertEqual(lookups, [])
        self.assertIn(HOST, self.svc._verified_external_hosts)    # and nothing was revoked on a guess

    def test_work_resumes_once_saving_works_again(self):
        with self.broken_disk():
            try:
                self.svc.verify_finding("f_headers", "appr")       # refused or recorded as failed - never sent
            except ValueError:
                pass
        self.assertEqual(self.fake.seen, [])
        self.svc.verify_finding("f_headers", "appr")
        self.assertEqual([p for p, _ in self.fake.seen], ["/"])
        self.assertIsNone(self.svc.snapshot()["persistence_error"])


# ------------------------------------------------------------------ sixth review: workspace residue, epoch, patterns
class TestNoResidueAcrossAssets(Ready):
    def external(self):
        ext = RecordingBackend()
        self.svc._chat_backend = ext
        return ext

    def test_registering_and_activating_a_lab_alias_does_not_carry_real_evidence_along(self):
        ext = self.external()
        real_findings = [f["id"] for f in self.svc.snapshot()["findings"] if f.get("evidence")]
        self.assertTrue(real_findings)
        self.svc.register_asset(name="alias.lab.test", kind="API", environment="x", authorization_ref="SOW-1",
                                ownership_verified=True, activate_workspace=True, actor="op")
        snap = self.svc.snapshot()
        self.assertEqual(snap["asset"]["name"], "alias.lab.test")
        self.assertFalse([f for f in snap["findings"] if any(HOST in json.dumps(e) for e in f.get("evidence", []))])
        for fid in real_findings + [f["id"] for f in snap["findings"]]:
            self.svc.ask_chat("説明して", "op", finding_id=fid)
        sent = json.dumps(ext.chats, ensure_ascii=False)
        for leak in (HOST, "sid=abc", str(self.fake.server_port)):
            self.assertNotIn(leak, sent)

    def test_the_active_asset_cannot_change_while_a_run_is_paused_or_running(self):
        from aegis.gateway import State
        for state, gw in (("paused", State.PAUSED), ("running", State.RUNNING)):
            self.svc.a.state = state
            self.svc.gateway._state = gw
            for call in (lambda: self.svc.select_asset("lab"),
                         lambda: self.svc.register_asset(name="alias2.lab.test", kind="API", environment="x",
                                                         authorization_ref="S", ownership_verified=True,
                                                         activate_workspace=True),
                         lambda: self.svc.delete_asset(self.svc.a.asset["id"])):
                with self.subTest(state=state):
                    try:
                        call()                                   # refused, or done without activating
                    except ValueError:
                        pass
                    self.assertEqual(self.svc.a.asset["name"], HOST)
                    self.assertIn("f_headers", self.svc.a.findings)   # the workspace was not replaced
        self.svc.a.state = "completed"
        self.svc.gateway._state = State.RUNNING

    def test_evidence_from_a_real_host_is_never_sent_out_even_under_a_lab_asset(self):
        ext = self.external()
        real = next(f for f in self.svc.snapshot()["findings"] if f.get("evidence"))
        self.svc.select_asset("lab")
        self.svc.a.findings["planted"] = {**real, "id": "planted"}      # residue, however it got there
        self.svc.ask_chat("説明して", "op", finding_id="planted")
        self.assertEqual(ext.chats, [])
        self.svc.ask_chat("IDORとは", "op")                              # ordinary lab chat still uses the model
        self.assertEqual(len(ext.chats), 1)


class TestRevocationThatCannotBeSavedIsNotUndoneByARestart(RealServiceBase):
    def test_stale_authority_on_disk_is_made_unacceptable(self):
        self.onboard()
        self.set_secrets()
        self.assertTrue((self.dir / "authority.epoch").exists())
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            # an approver's failed re-check revokes scope and proof in memory; the save fails
            self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])
        self.assertFalse(self.svc._is_external_service_asset(HOST))
        self.assertIsNotNone(self.svc._persist_error)
        self.assertFalse((self.dir / "authority.epoch").exists())     # the stale state.json can no longer be honoured
        self.svc.workers.kill_all()
        again = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS)
        self.assertFalse(again._is_external_service_asset(HOST))      # not restored
        self.assertEqual(again._ownership_proofs, {})
        self.assertIn("state.authority_rejected", [e["event"] for e in again.audit.entries()])
        again.workers.kill_all()

    def test_a_failed_save_without_an_authority_change_keeps_the_epoch(self):
        self.onboard()
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            self.svc._save_state_locked()                              # nothing about authority changed
        self.assertTrue((self.dir / "authority.epoch").exists())
        self.svc.workers.kill_all()
        again = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS)
        self.assertTrue(again._is_external_service_asset(HOST))        # a transient error does not cost the scope
        again.workers.kill_all()


class TestEpochCannotBeReplayedByCounting(RealServiceBase):
    def restart(self):
        self.svc.workers.kill_all()
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS)
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        return self.svc

    def test_deleting_state_json_does_not_restart_the_sequence(self):
        self.onboard()
        old_state = (self.dir / "state.json").read_bytes()               # signed, scope confirmed
        old_epoch = self.svc._authority_epoch
        self.svc.delete_asset(self.svc.a.asset["id"])                    # authority revoked
        for variant in ("missing", "truncated"):
            with self.subTest(variant=variant):
                if variant == "missing":
                    (self.dir / "state.json").unlink()
                else:
                    (self.dir / "state.json").write_text("{")
                svc = self.restart()
                counter = int(svc._authority_epoch.split(":")[0])
                self.assertGreater(counter, int(old_epoch.split(":")[0]))  # the sequence continued
                # make ordinary authority changes; no number of them can re-create the old epoch
                for i in range(3):
                    svc.issue_ownership_challenge(url=f"https://count-{variant}-{i}.example.org", approver="appr")
                    self.assertNotEqual(svc._authority_epoch, old_epoch)
                (self.dir / "state.json").write_bytes(old_state)
                svc = self.restart()
                self.assertFalse(svc._is_external_service_asset(HOST))
                self.assertEqual(svc._verified_external_hosts, {})

    def test_epoch_tokens_are_unpredictable(self):
        a = self.svc.issue_ownership_challenge(url="https://one.example.org", approver="appr")
        first = self.svc._authority_epoch
        self.svc.issue_ownership_challenge(url="https://two.example.org", approver="appr")
        self.assertRegex(first, r"^\d+:[0-9a-f]{32}$")
        self.assertNotEqual(first.split(":")[1], self.svc._authority_epoch.split(":")[1])
        self.assertTrue(a)


class TestOverridePatternLanguage(unittest.TestCase):
    def check(self, pattern):
        from aegis.l2_rules import RuleError, validate_profile
        base = json.loads((Path(__file__).parent / "fixtures" / "l2_profiles" / "example.json").read_text(encoding="utf-8"))
        base["paths"]["note_b_path"]["override_pattern"] = pattern
        try:
            validate_profile(base)
            return True
        except RuleError:
            return False

    def test_only_the_deterministic_mini_language_is_accepted(self):
        self.assertTrue(self.check("/api/notes/[A-Za-z0-9_-]{1,64}"))
        started = time.time()
        for bad in ("[0-z]{1,60}", "/api/notes/[A-z]{1,9}", "/\\.?\\./\\.?\\./[a-z]{1,20}", "/api/notes/?",
                    "/api/notes/\\??", "a?" * 30 + "a" * 30, "/api/notes/" + "[a]{0,99}" * 20 + "b",
                    "/api/notes/[a-z]{999}", "/api/notes/[a-z]{9,2}", "/api/notes/[a-z]{1,9}[0-9]{1,9}",
                    "/api/notes/[a-z]{1,9}a", "/api/notes/[a-z]", "/api/notes/[a-z]{1,3};y", "/api/notes/[a-z]{1,3}@y",
                    "/api/notes/\\.\\./[a-z]{1,3}", "/api/notes/[a-z ]{1,3}", "/api/notes/[a-z]{1,3}#x"):
            with self.subTest(pattern=bad):
                self.assertFalse(self.check(bad))
        self.assertLess(time.time() - started, 5)                 # validation itself cannot be made slow

    def test_values_an_accepted_pattern_admits_stay_inside_the_path(self):
        import re
        pattern = "/api/notes/[A-Za-z0-9_-]{1,64}"
        for value in ("/api/notes/b1?admin=1", "/api/notes/b1;x=1", "/api/notes/x@y", "/api/notes/..",
                      "/api/notes/a/b", "/api/notes/a%2fb", "/api/notes/a b", "/api/notes/a\nb", "/api/notes/"):
            self.assertIsNone(re.fullmatch(pattern, value), value)
        self.assertIsNotNone(re.fullmatch(pattern, "/api/notes/b1"))


class TestAnalyzerAndTransportFollowUps2(unittest.TestCase):
    def test_redirect_to_https_must_stay_on_the_same_host(self):
        for location in ("https://other.example/", "https://", "//x.example/", "/login"):
            found = analyze({"Location": location}, url="http://x.example/", status=301, tls=False)
            self.assertIn("f_l1_no_tls", found, location)
        self.assertIn("f_l1_no_tls", analyze({"Location": "https://x.example/"}, url="http://x.example/",
                                             status=304, tls=False))
        self.assertNotIn("f_l1_no_tls", analyze({"Location": "https://X.example/app"}, url="http://x.example/",
                                                status=308, tls=False))

    def test_invisible_characters_and_surrogates_are_removed(self):
        self.assertEqual(clean_target_text("a\u200bb\u200dc\ufeffd\u061ce\u2060f\u00adg\ud800h"), "abcdefgh")

    def test_worker_output_that_is_not_valid_utf8_does_not_raise(self):
        import sys
        from aegis.runtime import WorkerPool
        pool = WorkerPool(max_concurrent=1)
        try:
            code = "import sys; sys.stdout.buffer.write(bytes([123,34,120,34,58,34,237,178,128,255,34,125]))"
            result = pool.run([sys.executable, "-c", code], 10)
            self.assertEqual(result.returncode, 0)
            self.assertIn("x", result.stdout)
        finally:
            pool.kill_all()


class TestScopeEndpointMismatch2(RealServiceBase):
    def test_port_named_in_odd_forms_is_still_compared(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=self._token_lookup(ch))
        wrong = self.fake.server_port + 1
        for form in (f"{HOST}:{wrong}?x=1", f"{HOST}:{wrong}#f", f"{HOST}:{wrong} ", f"{HOST}:{wrong}/a"):
            with self.subTest(form=form):
                with self.assertRaises(ValueError):
                    self.svc.confirm_asset_scope(url_or_host=form, approver="appr", allow_loopback_test=True)
        self.assertNotIn(HOST, self.svc._verified_external_hosts)


if __name__ == "__main__":
    unittest.main()
