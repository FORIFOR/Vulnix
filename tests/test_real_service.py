"""Real-service flow: ownership proof -> scope confirmation -> L1 read-only
diagnosis -> per-item, human-approved L2 checks with encrypted test accounts.

No test here talks to the internet. The "real service" is a loopback HTTP
server reached through the injected resolver and the service-level-only
`allow_loopback_test` switch (which the HTTP API cannot set).
"""
import http.server
import importlib.util
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis import evidence, l2_rules
from aegis.assessment import AssessmentService
from aegis.evidence import reproduction_verdict
from aegis.l2_rules import BUILTIN_PROFILE_DIR, L2RuleSet, RuleError, validate_profile
from aegis.lab import set_lab_mode, start_lab
from aegis.network import NetworkError
from aegis.ownership import parse_service_target, verify_ownership_challenge
from aegis.remotion_export import build_remotion_export
from aegis.secrets_store import EncryptedSecretStore
from aegis.service_diag import analyze_l1_service_response

LAB_PORT = 18097
HOST = "svc.example.test"                 # bound to tests/fixtures/l2_profiles/example.json
FIXTURE_PROFILE_DIR = Path(__file__).parent / "fixtures" / "l2_profiles"
PROFILE_DIRS = [BUILTIN_PROFILE_DIR, FIXTURE_PROFILE_DIR]
RULES = L2RuleSet.load(PROFILE_DIRS)
EXAMPLE = RULES.profiles["example"]
EX_CHECKS = {c["id"]: c for c in EXAMPLE["checks"]}
TOKEN_A = "tok-A-0123456789abcdef"
TOKEN_B = "tok-B-fedcba9876543210"
TOKEN_FREE = "tok-FREE-55aa55aa55aa"
TOKEN_PREMIUM = "tok-PREM-aa55aa55aa55"
ALL_TOKENS = (TOKEN_A, TOKEN_B, TOKEN_FREE, TOKEN_PREMIUM)
NOTE_B = "/api/notes/b1"
NOTE_A = "/api/notes/a1"
SHARE_VALID = "/api/shares/valid"
SHARE_EXPIRED = "/api/shares/expired"
PREMIUM_PATH = "/api/premium/summary"
PLAN_PATH = "/api/plan"
NOTE_B_BODY = {"owner": "user_b", "body": "EX_NOTE_B_CONTENT"}


class FakeService(http.server.ThreadingHTTPServer):
    """Loopback stand-in for an owned staging service.

    mode:
      vulnerable       boundaries are not enforced
      patched          boundaries enforced, clean error bodies
      missing          B's mock note does not exist (404 for everyone)
      token_expired    every token is rejected with 401
      a_token_invalid  account A's token is rejected with 403 everywhere
      leaky_denial     A gets 403 on B's note, but the body still carries B's content
      odd_denial       A gets 403 on B's note with an unexpected error body
    """
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _FakeHandler)
        self.mode = "vulnerable"
        self.seen: list[tuple[str, str | None]] = []


class _FakeHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, headers=()):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        srv: FakeService = self.server
        auth = self.headers.get("Authorization")
        srv.seen.append((self.path, auth))
        token = (auth or "").removeprefix("Bearer ")
        mode = srv.mode
        if self.path == "/":
            return self._send(200, {"ok": True}, [
                ("Server", "nginx"), ("Set-Cookie", "sid=abc; Path=/"),
                ("Access-Control-Allow-Origin", self.headers.get("Origin", "")),
                ("Access-Control-Allow-Credentials", "true")])
        if mode == "token_expired" or not token:
            return self._send(401, {"error": "token expired"})
        if mode == "a_token_invalid" and token == TOKEN_A:
            return self._send(403, {"error": "forbidden"})
        if self.path == NOTE_B:
            if mode == "missing":
                return self._send(404, {"error": "forbidden"})
            if token == TOKEN_B:
                return self._send(200, {**NOTE_B_BODY, "echo": auth})
            if token == TOKEN_A and mode == "vulnerable":
                return self._send(200, NOTE_B_BODY)
            if mode == "leaky_denial":
                return self._send(403, {"error": "forbidden", "debug": NOTE_B_BODY})
            if mode == "odd_denial":
                return self._send(403, {"error": "waf_blocked"})
            return self._send(403, {"error": "forbidden"})
        if self.path == NOTE_A:
            if token == TOKEN_A:
                return self._send(200, {"owner": "user_a", "body": "EX_NOTE_A_CONTENT"})
            return self._send(403, {"error": "forbidden"})
        if self.path == SHARE_VALID:
            return self._send(200, {"note": "EX_SHARED_NOTE"})
        if self.path == SHARE_EXPIRED:
            if mode == "vulnerable":
                return self._send(200, {"note": "EX_SHARED_NOTE"})
            return self._send(410, {"error": "gone"})
        if self.path == PLAN_PATH:
            plan = {TOKEN_FREE: "free", TOKEN_PREMIUM: "premium"}.get(token)
            return self._send(200, {"plan": plan}) if plan else self._send(403, {"error": "forbidden"})
        if self.path == PREMIUM_PATH:
            if token == TOKEN_PREMIUM or (token == TOKEN_FREE and mode == "vulnerable"):
                return self._send(200, {"summary": "EX_PREMIUM_SUMMARY"})
            return self._send(402, {"error": "upgrade required"})
        return self._send(404, {"error": "not found"})


def _load_worker():
    spec = importlib.util.spec_from_file_location(
        "reproduction_probe_under_test",
        Path(__file__).parent.parent / "aegis" / "workers" / "reproduction_probe.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestRulesAreConfigurationNotCode(unittest.TestCase):
    ENGINE_FILES = ("l2_rules.py", "evidence.py", "gateway.py", "secrets_store.py", "service_diag.py",
                    "assessment.py", "ownership.py", "server.py", "runtime.py", "remotion_export.py",
                    "workers/reproduction_probe.py")

    def test_engine_and_worker_carry_no_service_specific_names(self):
        root = Path(__file__).parent.parent / "aegis"
        for name in self.ENGINE_FILES:
            with self.subTest(file=name):
                text = (root / name).read_text(encoding="utf-8").lower()
                for word in ("deepnote", "mopita", "classnote", "ex_note_b"):
                    self.assertNotIn(word, text)

    def test_worker_and_lab_verdict_tables_stay_in_sync(self):
        checks = _load_worker().CHECKS
        self.assertEqual(set(checks), set(evidence.REPRODUCTION_MARKERS))
        self.assertEqual(set(checks), set(evidence.REPRODUCTION_DENY_STATUSES))
        for name, spec in checks.items():
            self.assertEqual(spec["marker"], evidence.REPRODUCTION_MARKERS[name])

    def test_builtin_profile_defines_each_category_as_an_independent_rule(self):
        builtin = L2RuleSet.load([BUILTIN_PROFILE_DIR])
        (profile,) = builtin.profiles.values()
        self.assertEqual(sorted(c["category"] for c in profile["checks"]),
                         ["ai_chat_isolation", "billing_plan", "idor", "share_link", "storage_acl"])
        self.assertEqual(profile["spec_status"], "placeholder")      # not yet matched against the real API
        for c in profile["checks"]:
            with self.subTest(check=c["id"]):
                self.assertTrue(c["preconditions"])
                for pre in c["preconditions"]:
                    self.assertTrue({"body_contains", "json_fields"} & set(pre["expect"]))
                self.assertTrue(set(c["exposed"]["body_contains"]) <= set(c["denied"]["body_not_contains"]))
                self.assertFalse(set(c["denied"]["status"]) & {401, 429})

    def test_a_rule_that_could_fake_a_defense_is_rejected_at_load(self):
        base = json.loads((FIXTURE_PROFILE_DIR / "example.json").read_text(encoding="utf-8"))
        validate_profile(base)

        def broken(mutate):
            raw = json.loads(json.dumps(base))
            mutate(raw["checks"][0], raw)
            with self.assertRaises(RuleError):
                validate_profile(raw)

        broken(lambda c, p: c.update(preconditions=[]))                              # status-only denial
        broken(lambda c, p: c["preconditions"][0].update(expect={"status": [200]}))   # control ignores content
        broken(lambda c, p: c["denied"].update(status=[401, 403]))                   # rejected token as a defense
        broken(lambda c, p: c["denied"].update(status=[200]))
        broken(lambda c, p: c["denied"].pop("body_not_contains"))                    # owner data allowed in a denial
        broken(lambda c, p: c["preconditions"][0].update(token="user_a_token"))      # control == subject request
        broken(lambda c, p: p.update(distinct_tokens=[]))                            # A may equal B
        broken(lambda c, p: c["subject"].update(headers={"Authorization": "Bearer x"}))
        broken(lambda c, p: p["paths"]["note_b_path"].update(default="/a b"))
        with self.assertRaises(RuleError):                                             # one host, two profiles
            L2RuleSet([validate_profile(base), {**validate_profile(base), "id": "other", "checks": []}])


class TestL2VerdictNeverFakesADefense(unittest.TestCase):
    """Control-plane judgement of a worker result, without any network."""
    CHECK = "ex_idor_notes"

    def setUp(self):
        self.rule = RULES.worker_rule(self.CHECK)
        self.digest = l2_rules.rule_digest(RULES.worker_rule_json(self.CHECK))

    def _pre(self, name, status=200, ok=True, **over):
        expect = next(p["expect"] for p in self.rule["preconditions"] if p["name"] == name)
        return {"name": name, "performed": True, "status": status, "ok": ok,
                "checks": {k: ok for k in expect}, **over}

    def _result(self, status=403, verdict="not_reproduced", established=False, pres=None, **subject):
        subj = {"performed": True, "identical_to_control": False, "truncated": False,
                "denied_checks": {k: True for k in self.rule["denied"]},
                "exposed_checks": {"status": False, "body_contains": False}, **subject}
        return {"check": self.CHECK, "rule_digest": self.digest, "status": status,
                "established": established, "verdict": verdict, "response_text": '{"error": "forbidden"}',
                "preconditions": pres if pres is not None
                else [self._pre("owner_access"), self._pre("subject_authenticated")],
                "subject": subj}

    def verdict(self, result):
        return reproduction_verdict(result, self.CHECK, worker_rule=self.rule)

    def test_full_evidence_is_required_for_not_reproduced(self):
        self.assertEqual(self.verdict(self._result()), "not_reproduced")
        self.assertEqual(self.verdict(self._result(status=404)), "not_reproduced")

    def test_status_alone_is_never_enough(self):
        cases = {
            "no preconditions reported": self._result(pres=[]),
            "owner control missing": self._result(pres=[self._pre("subject_authenticated")]),
            "owner control failed": self._result(pres=[self._pre("owner_access", status=404, ok=False),
                                                       self._pre("subject_authenticated")]),
            "owner control 200 but content mismatch": self._result(pres=[
                self._pre("owner_access", ok=False), self._pre("subject_authenticated")]),
            "owner control not performed": self._result(pres=[
                {"name": "owner_access", "performed": False, "ok": False}, self._pre("subject_authenticated")]),
            "subject account not authenticated": self._result(pres=[
                self._pre("owner_access"), self._pre("subject_authenticated", status=403, ok=False)]),
            "control skipped a declared condition": self._result(pres=[
                {**self._pre("owner_access"), "checks": {"status": True}}, self._pre("subject_authenticated")]),
            "denial body mismatch": self._result(denied_checks={"status": True, "body_not_contains": True,
                                                                "json_fields": False}),
            "same body as owner": self._result(identical_to_control=True),
            "truncated body": self._result(truncated=True),
            "subject request not sent": self._result(performed=False),
            "worker disagrees": self._result(verdict="unverified"),
        }
        for name, result in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.verdict(result), "unverified")
        for status in (401, 402, 410, 429, 500, 302, 200):
            with self.subTest(status=status):
                self.assertEqual(self.verdict(self._result(status=status)), "unverified")
        leaky = self._result()
        leaky["response_text"] = json.dumps({"error": "forbidden", "debug": NOTE_B_BODY})
        self.assertEqual(self.verdict(leaky), "unverified")

    def test_result_must_come_from_the_configured_rule(self):
        tampered = self._result()
        tampered["rule_digest"] = "0" * 64
        self.assertEqual(self.verdict(tampered), "unverified")
        self.assertEqual(self.verdict(None), "unverified")
        self.assertEqual(self.verdict({**self._result(), "check": "ex_share_link"}), "unverified")
        # a profile-defined check is never judged by the lab table
        self.assertEqual(reproduction_verdict(self._result(), self.CHECK), "unverified")

    def test_exposure_is_proven_only_with_owner_content(self):
        hit = self._result(status=200, verdict="proven", established=True,
                           exposed_checks={"status": True, "body_contains": True})
        self.assertEqual(self.verdict(hit), "proven")
        empty_200 = self._result(status=200, verdict="proven", established=True,
                                 exposed_checks={"status": True, "body_contains": False})
        self.assertEqual(self.verdict(empty_200), "unverified")


class TestOwnershipPrimitives(unittest.TestCase):
    def test_target_parsing(self):
        t = parse_service_target("Stg.Example.com/some/path?x=1")
        self.assertEqual((t["host"], t["scheme"], t["port"]), ("stg.example.com", "https", 443))
        self.assertEqual(t["target_url"], "https://stg.example.com/")
        for bad in ("", "ftp://example.com", "https://exa mple.com", "https://user:pw@/"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    parse_service_target(bad)

    def test_challenge_must_match_exact_token(self):
        res = verify_ownership_challenge("example.com", "dns_txt", expected_token="vulnix-verify=abc",
                                         txt_lookup=lambda name: ['"vulnix-verify=zzz"'])
        self.assertFalse(res["verified"])
        self.assertIsNone(res["verified_at"])
        res = verify_ownership_challenge("example.com", "well_known", expected_token="vulnix-verify=abc",
                                         http_fetcher=lambda url: "vulnix-verify=abc\n")
        self.assertTrue(res["verified"])

        def boom(url):
            raise OSError("connection refused")
        self.assertFalse(verify_ownership_challenge(
            "example.com", "well_known", expected_token="x", http_fetcher=boom)["verified"])
        with self.assertRaises(ValueError):
            verify_ownership_challenge("example.com", "email")

    def test_proof_file_is_never_fetched_from_a_non_public_address(self):
        from aegis.ownership import default_well_known_fetcher
        with patch("urllib.request.OpenerDirector.open") as opened:
            for host in ("localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5"):
                with self.subTest(host=host):
                    with self.assertRaises(ValueError):
                        default_well_known_fetcher(f"https://{host}/.well-known/vulnix-verify.txt")
                    res = verify_ownership_challenge(host, "well_known", expected_token="t")
                    self.assertFalse(res["verified"])
            opened.assert_not_called()


class TestSecretStore(unittest.TestCase):
    def test_encrypted_at_rest_tamper_evident_and_never_public(self):
        with tempfile.TemporaryDirectory() as d:
            store = EncryptedSecretStore(Path(d))
            status = store.set_credentials(HOST, {"user_a_token": TOKEN_A, "user_b_token": TOKEN_B},
                                           profile=EXAMPLE)
            self.assertTrue(status["l2_ready"])
            blob = (Path(d) / "secrets.enc.json").read_text()
            for tok in (TOKEN_A, TOKEN_B):
                self.assertNotIn(tok, blob)
                self.assertNotIn(tok, json.dumps(status))
            self.assertEqual(oct((Path(d) / "secrets.enc.json").stat().st_mode & 0o777), "0o600")
            self.assertEqual(oct((Path(d) / ".secrets.key").stat().st_mode & 0o777), "0o600")
            # survives restart; a worker run gets only the tokens its rule uses
            again = EncryptedSecretStore(Path(d))
            self.assertEqual(again.worker_env_for_check(HOST, EX_CHECKS["ex_idor_notes"]),
                             {"VULNIX_L2_TOKENS": json.dumps({"user_a_token": TOKEN_A, "user_b_token": TOKEN_B})})
            self.assertEqual(again.worker_env_for_check(HOST, EX_CHECKS["ex_share_link"]),
                             {"VULNIX_L2_TOKENS": json.dumps({"user_a_token": TOKEN_A})})
            self.assertEqual(again.redact(f"x {TOKEN_A} y {TOKEN_B}"),
                             "x [REDACTED_SECRET] y [REDACTED_SECRET]")
            # billing needs the free AND the premium (control) account
            self.assertEqual(again.missing_for_check(HOST, EX_CHECKS["ex_billing_plan"]),
                             ["free_plan_token", "premium_plan_token"])
            self.assertEqual(again.worker_env_for_check(HOST, EX_CHECKS["ex_billing_plan"]), {})
            again.set_credentials(HOST, {"free_plan_token": TOKEN_FREE}, profile=EXAMPLE)
            self.assertEqual(again.public_status(HOST, EXAMPLE)["checks"]["ex_billing_plan"]["missing"],
                             ["premium_plan_token"])
            # tampering is detected instead of yielding garbage credentials
            env = json.loads(blob)
            env["ct"] = env["ct"][:-4] + ("AAA=" if not env["ct"].endswith("AAA=") else "BBB=")
            (Path(d) / "secrets.enc.json").write_text(json.dumps(env))
            self.assertFalse(EncryptedSecretStore(Path(d)).has_any_token(HOST))

    def test_rejects_same_account_in_two_roles_bad_paths_and_undeclared_keys(self):
        with tempfile.TemporaryDirectory() as d:
            store = EncryptedSecretStore(Path(d))
            for payload in ({"user_a_token": TOKEN_A, "user_b_token": TOKEN_A},
                            {"free_plan_token": TOKEN_FREE, "premium_plan_token": TOKEN_FREE},
                            {"note_b_path": "/a b\r\nX-Evil: 1"},
                            {"admin_token": "tok-ADMIN-0123456789"},
                            {"mock_note_path": "/api/x"}):
                with self.subTest(payload=sorted(payload)):
                    with self.assertRaises(ValueError):
                        store.set_credentials(HOST, payload, profile=EXAMPLE)
            self.assertFalse(store.has_any_token(HOST))
            st = store.set_credentials(HOST, {"note_b_path": "api/notes/n1"}, profile=EXAMPLE)
            self.assertEqual({p["key"]: p["value"] for p in st["paths"] if p["value"]},
                             {"note_b_path": "/api/notes/n1"})
            self.assertIsNone(store.public_status(HOST, None)["profile"])
            self.assertEqual(store.public_status(HOST, None)["checks"], {})


class TestL1Analyzer(unittest.TestCase):
    def test_findings_follow_the_observed_response_only(self):
        ev = {"evidence_id": "ev_1", "audit_hash": "h", "saved_at": 1.0, "content": "{}"}
        res = {"status": 200, "tls": {"version": "TLSv1.3"}, "cors_probe_origin": "https://untrusted-origin.example",
               "headers": {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
                           "X-Content-Type-Options": "nosniff", "Content-Type": "text/html"},
               "set_cookies": ["sid=1; Secure; HttpOnly; SameSite=Lax"]}
        self.assertEqual(analyze_l1_service_response(res, ev, "https://x.example/"), [])
        bad = {**res, "headers": {"Content-Type": "text/html",
                                  "Access-Control-Allow-Origin": "https://untrusted-origin.example",
                                  "Access-Control-Allow-Credentials": "true"},
               "set_cookies": ["sid=1"], "tls": {"version": "TLSv1.1"}}
        got = {f["id"]: f for f in analyze_l1_service_response(bad, ev, "https://x.example/")}
        self.assertEqual(set(got), {"f_l1_tls", "f_headers", "f_l1_cookies", "f_l1_cors"})
        self.assertEqual(got["f_l1_cors"]["severity"], "high")
        for f in got.values():
            self.assertFalse(f["demo_fixture"])
            self.assertEqual(f["evidence"][0]["audit_hash"], "h")


class RealServiceBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()

    def setUp(self):
        set_lab_mode("vulnerable")
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS)
        self.fake = FakeService()
        threading.Thread(target=self.fake.serve_forever, daemon=True).start()
        self.url = f"http://{HOST}:{self.fake.server_port}"
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []

    def tearDown(self):
        self.svc.workers.kill_all()
        self.fake.shutdown()
        self.fake.server_close()
        self.tmp.cleanup()

    def _token_lookup(self, challenge):
        return lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"']

    def onboard(self, *, loopback=True):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        res = self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                              dns_lookup=self._token_lookup(ch))
        self.assertTrue(res["verified"])
        return self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr",
                                            activate_workspace=True, allow_loopback_test=loopback)

    def run_l1(self):
        self.svc.start()
        end = time.time() + 20
        while time.time() < end and self.svc.snapshot()["state"] == "running":
            time.sleep(0.05)
        return self.svc.snapshot()

    def set_secrets(self, *, billing=False, mock_paths=None):
        tokens = {"user_a_token": TOKEN_A, "user_b_token": TOKEN_B}
        if billing:
            tokens.update(free_plan_token=TOKEN_FREE, premium_plan_token=TOKEN_PREMIUM)
        return self.svc.configure_asset_secrets(host=HOST, tokens=tokens, mock_paths=mock_paths, actor="appr")

    def finding(self, fid):
        return next(f for f in self.svc.snapshot()["findings"] if f["id"] == fid)

    def assert_no_token_anywhere(self):
        haystacks = {
            "state.json": (self.dir / "state.json").read_text(),
            "audit.jsonl": (self.dir / "audit.jsonl").read_text(),
            "secrets.enc.json": (self.dir / "secrets.enc.json").read_text(),
            "snapshot": json.dumps(self.svc.snapshot(), ensure_ascii=False),
            "report": self.svc.report_markdown(),
            "remotion": json.dumps(self.svc.remotion_export(anonymize=False), ensure_ascii=False),
        }
        for name, text in haystacks.items():
            for tok in ALL_TOKENS:
                self.assertNotIn(tok, text, f"token leaked into {name}")


class TestOwnershipGate(RealServiceBase):
    def test_no_traffic_and_no_scope_until_ownership_and_scope_are_both_confirmed(self):
        issued = self.svc.issue_ownership_challenge(url=self.url, approver="appr")
        asset, ch = issued["asset"], issued["challenge"]
        self.assertEqual(asset["status"], "所有確認待ち")
        self.assertFalse(asset["ownership_verified"])
        self.assertEqual(self.svc._resolve_host(HOST), [])
        with self.assertRaises(ValueError):          # cannot be opened as a workspace
            self.svc.select_asset(asset["id"])
        with self.assertRaises(ValueError):          # cannot skip the proof
            self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr")
        with self.assertRaises(ValueError):          # the SOW checkbox is not a bypass
            self.svc.register_asset(name=HOST, kind="API", environment="stg",
                                    authorization_ref="SOW-1", ownership_verified=True)

        wrong = self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt",
                                                dns_lookup=lambda n: ['"vulnix-verify=not-the-token"'])
        self.assertFalse(wrong["verified"])
        with self.assertRaises(ValueError):
            self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr")

        ok = self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt",
                                             dns_lookup=self._token_lookup(ch))
        self.assertTrue(ok["verified"])
        self.assertFalse(ok["l2_auto_approved"])
        self.assertEqual(self.svc._resolve_host(HOST), [])      # verified but scope not confirmed
        with self.assertRaises(ValueError):
            self.svc.confirm_asset_scope(url_or_host=self.url, confirmed_prohibited=False)
        self.assertEqual(self.fake.seen, [])                      # nothing was sent so far

        res = self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr",
                                           activate_workspace=True, allow_loopback_test=True)
        self.assertTrue(res["scope_confirmed"])
        snap = self.svc.snapshot()
        self.assertTrue(snap["is_external_service"])
        self.assertFalse(snap["demo"])
        self.assertEqual(snap["target_url"], self.url + "/")
        self.assertEqual(snap["authorization"]["scope"]["hosts"], [HOST])
        self.assertTrue(snap["asset"]["scope_confirmed"])
        events = [e["event"] for e in self.svc.audit.entries()]
        for want in ("asset.challenge_issued", "asset.ownership_failed",
                     "asset.ownership_verified", "asset.scope_confirmed"):
            self.assertIn(want, events)

    def test_challenge_token_is_installation_specific(self):
        ch = self.svc.issue_ownership_challenge(url=self.url)["challenge"]
        with tempfile.TemporaryDirectory() as d:
            other = AssessmentService(Path(d), LAB_PORT)
            self.assertNotEqual(other.issue_ownership_challenge(url=self.url)["challenge"]["token"],
                                ch["token"])
            other.workers.kill_all()

    def test_private_address_blocked_and_failed_reverification_revokes_scope(self):
        self.onboard(loopback=False)
        with self.assertRaises(NetworkError):        # real mode: loopback/private is refused
            self.svc._resolve_host(HOST)
        snap = self.run_l1()
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(self.fake.seen, [])

        self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", dns_lookup=lambda n: [])
        self.assertFalse(self.svc._is_external_service_asset())
        self.assertEqual(self.svc._resolve_host(HOST), [])       # not downgraded to the local lab
        with self.assertRaises(ValueError):
            self.set_secrets()

    def test_scope_window_expiry_stops_resolution(self):
        self.onboard()
        self.assertEqual(self.svc._resolve_host(HOST), ["127.0.0.1"])
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        self.assertEqual(self.svc._resolve_host(HOST), [])
        self.assertFalse(self.svc._is_external_service_asset())

    def test_verified_scope_survives_restart_and_delete_revokes_it(self):
        self.onboard()
        self.set_secrets()
        self.svc.workers.kill_all()
        again = AssessmentService(self.dir, LAB_PORT, l2_profile_dirs=PROFILE_DIRS)
        self.assertTrue(again._is_external_service_asset())
        self.assertEqual(again.snapshot()["target_url"], self.url + "/")
        self.assertTrue(again.secrets_status()["l2_ready"])
        again.delete_asset(again.a.asset["id"])
        self.assertNotIn(HOST, again._verified_external_hosts)
        self.assertFalse(again.secrets.has_any_token(HOST))
        self.assertFalse(again._is_external_service_asset())
        again.workers.kill_all()


class TestL1Diagnosis(RealServiceBase):
    def test_l1_run_is_read_only_and_leaves_l2_as_unmeasured_candidates(self):
        self.onboard()
        self.set_secrets()                           # even WITH credentials, L1 sends none
        snap = self.run_l1()
        self.assertEqual(snap["state"], "completed")
        self.assertEqual([p for p, _ in self.fake.seen], ["/"])
        self.assertIsNone(self.fake.seen[0][1])
        by_id = {f["id"]: f for f in snap["findings"]}
        for fid in ("f_headers", "f_l1_cookies", "f_l1_cors", "f_powered", "f_l1_unauth_api"):
            self.assertIn(fid, by_id)
            self.assertIn(by_id[fid]["evidence_status"], ("proven", "detected"))
            self.assertTrue(by_id[fid]["evidence"][0]["audit_hash"])
        l2 = [by_id[c["finding"]["id"]] for c in EXAMPLE["checks"]]
        self.assertEqual({f["evidence_status"] for f in l2}, {"candidate"})
        self.assertFalse(any(f.get("demo_fixture") for f in snap["findings"]))
        self.assertEqual(next(p for p in snap["phases"] if p["key"] == "verification")["status"], "skipped")
        self.assertEqual(snap["approvals"], [])
        # unmeasured candidates do not move the score in either direction
        measured = [f for f in snap["findings"] if f["evidence_status"] != "candidate"]
        only_measured = self.svc._risk()["score"]
        for f in l2:
            del self.svc.a.findings[f["id"]]
        self.assertEqual(self.svc._risk()["score"], only_measured)
        self.assertGreater(only_measured, 0)
        self.assertTrue(measured)
        report = self.svc.report_markdown()
        self.assertIn("所有確認済みの実サービス", report)
        self.assertNotIn("架空", report)
        self.assertIsNone(snap["history"])                       # no fictional history on a real service
        primary = self.svc.assets()[0]
        self.assertEqual((primary["name"], primary["previous_risk_score"]), (HOST, None))
        self.assertNotIn("ローカル模擬ラボ", report)

    def test_bulk_verify_never_runs_l2_on_a_real_service(self):
        self.onboard()
        self.set_secrets(billing=True)
        self.run_l1()
        self.fake.seen.clear()
        self.svc.verify_finding("all", actor="appr")
        self.assertEqual([p for p, _ in self.fake.seen], ["/"])
        self.assertEqual(self.finding("f_ex_idor")["evidence_status"], "candidate")


class TestL2HumanApprovedChecks(RealServiceBase):
    def setUp(self):
        super().setUp()
        self.onboard()
        self.assertEqual(self.run_l1()["state"], "completed")
        self.fake.seen.clear()

    def run_check(self, fid, mode=None):
        if mode:
            self.fake.mode = mode
        self.fake.seen.clear()
        self.svc.verify_finding(fid, actor="appr")
        return self.finding(fid)

    def test_l2_requires_credentials_and_a_human(self):
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="appr")          # no credentials
        self.set_secrets()
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="policy:auto-L1")  # not a human
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="")
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_billing", actor="appr")       # plan accounts missing
        self.assertEqual(self.fake.seen, [])
        self.assertTrue(self.svc.finding_requires_human_l2_approval("f_ex_idor"))
        self.assertFalse(self.svc.finding_requires_human_l2_approval("f_headers"))
        self.assertTrue(self.finding("f_ex_idor")["requires_l2_approval"])
        # a rule of another service's profile cannot be run against this asset
        self.svc.a.findings["f_ex_idor"]["reproduce_check"] = "deepnote_idor_notes"
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="appr")
        self.assertEqual(self.fake.seen, [])
        self.assertEqual(self.svc._ephemeral_worker_env("reproduction_probe", {"check": "deepnote_idor_notes"}), {})
        self.assertEqual(self.svc._ephemeral_worker_env("http_probe", {"check": "ex_idor_notes"}), {})

    def test_broken_boundary_is_proven_and_tokens_never_leak(self):
        self.set_secrets()
        f = self.run_check("f_ex_idor")
        self.assertEqual(f["evidence_status"], "proven")
        # owner control (B), A's own-resource control, then the cross-account request; nothing else
        self.assertEqual(self.fake.seen, [(NOTE_B, f"Bearer {TOKEN_B}"), (NOTE_A, f"Bearer {TOKEN_A}"),
                                          (NOTE_B, f"Bearer {TOKEN_A}")])
        content = json.loads(f["evidence"][-1]["content"])
        self.assertEqual(content["request_headers"]["Authorization"], "Bearer [REDACTED_SECRET]")
        self.assertEqual([p["ok"] for p in content["preconditions"]], [True, True])
        self.assertEqual(content["rule_digest"], l2_rules.rule_digest(RULES.worker_rule_json("ex_idor_notes")))
        approval = [e for e in self.svc.audit.entries() if e["event"] == "approval.approved"][-1]["fields"]
        self.assertEqual((approval["actor"], approval["check"], approval["risk_level"]),
                         ("appr", "ex_idor_notes", "L2"))
        self.assert_no_token_anywhere()

    def test_enforced_boundary_needs_owner_success_subject_denial_and_clean_content(self):
        self.set_secrets(billing=True)
        f = self.run_check("f_ex_idor", "patched")
        self.assertEqual(f["evidence_status"], "not_reproduced")
        self.assertIn("所有者Bがノートを取得できる", f["verdict_note"])
        content = json.loads(f["evidence"][-1]["content"])
        self.assertEqual(content["subject"]["denied_checks"],
                         {"status": True, "body_not_contains": True, "json_fields": True})
        self.assertFalse(content["subject"]["identical_to_control"])

        f = self.run_check("f_ex_billing")
        self.assertEqual(f["evidence_status"], "not_reproduced")
        self.assertEqual(self.fake.seen, [(PREMIUM_PATH, f"Bearer {TOKEN_PREMIUM}"), (PLAN_PATH, f"Bearer {TOKEN_FREE}"),
                                          (PREMIUM_PATH, f"Bearer {TOKEN_FREE}")])
        f = self.run_check("f_ex_share")
        self.assertEqual(f["evidence_status"], "not_reproduced")
        self.assertEqual([p for p, _ in self.fake.seen], [SHARE_VALID, SHARE_EXPIRED])
        self.assertEqual(self.run_check("f_ex_share", "vulnerable")["evidence_status"], "proven")
        self.assertEqual(self.run_check("f_ex_billing")["evidence_status"], "proven")
        self.assert_no_token_anywhere()

    def test_insufficient_conditions_are_unverified_and_stop_before_the_cross_account_request(self):
        self.set_secrets()
        for mode, sent in (("missing", [NOTE_B, NOTE_A]),           # mock data absent: 404 for the owner too
                           ("token_expired", [NOTE_B, NOTE_A]),     # 401 everywhere
                           ("a_token_invalid", [NOTE_B, NOTE_A])):  # A's 403 is authentication, not authorization
            with self.subTest(mode=mode):
                f = self.run_check("f_ex_idor", mode)
                self.assertEqual(f["verdict"], "unverified")
                self.assertEqual(f["evidence_status"], "incomplete")
                self.assertIn("再現せずとは判定しません", f["verdict_note"])
                self.assertEqual([p for p, _ in self.fake.seen], sent)
                content = json.loads(f["evidence"][-1]["content"])
                self.assertFalse(content["subject"]["performed"])

    def test_denial_status_with_wrong_content_is_unverified(self):
        self.set_secrets()
        for mode, reason in (("leaky_denial", "所有者側のデータ"), ("odd_denial", "拒否応答の内容")):
            with self.subTest(mode=mode):
                f = self.run_check("f_ex_idor", mode)
                content = json.loads(f["evidence"][-1]["content"])
                self.assertEqual(content["status"], 403)             # the status alone looks like a defense
                self.assertEqual(f["evidence_status"], "incomplete")
                self.assertIn("再現せずとは判定しません", f["verdict_note"])
                if mode == "leaky_denial":
                    self.assertFalse(content["subject"]["denied_checks"]["body_not_contains"])
                else:
                    self.assertFalse(content["subject"]["denied_checks"]["json_fields"])
                self.assertIn(reason, f["verdict_note"])

    def test_operator_configured_mock_path_is_used_for_that_path_key_only(self):
        self.set_secrets(billing=True, mock_paths={"note_b_path": "/api/notes/custom-b-note"})
        self.fake.mode = "patched"
        f = self.run_check("f_ex_idor")
        # custom path does not exist on the service -> owner control fails -> not a defense
        self.assertEqual([p for p, _ in self.fake.seen], ["/api/notes/custom-b-note", NOTE_A])
        self.assertEqual(f["evidence_status"], "incomplete")
        self.run_check("f_ex_billing")
        self.assertEqual([p for p, _ in self.fake.seen], [PREMIUM_PATH, PLAN_PATH, PREMIUM_PATH])

    def test_fix_reverification_reruns_only_previously_approved_l2_items(self):
        self.set_secrets(billing=True)
        self.assertEqual(self.run_check("f_ex_idor")["evidence_status"], "proven")
        self.fake.mode = "patched"
        self.fake.seen.clear()
        with patch("aegis.assessment.set_lab_mode") as lab_switch:
            snap = self.svc.verify_fix("appr")
        lab_switch.assert_not_called()                # a real service is never "patched" by us
        self.assertEqual({p for p, _ in self.fake.seen}, {"/", NOTE_B, NOTE_A})
        items = {i["id"]: i for i in snap["defense_comparison"]["items"]}
        self.assertEqual((items["f_ex_idor"]["before_verdict"], items["f_ex_idor"]["after_verdict"]),
                         ("proven", "not_reproduced"))
        self.assertNotIn("f_ex_billing", items)      # never approved -> never run, never listed
        self.assertEqual(self.finding("f_ex_billing")["evidence_status"], "candidate")
        # a re-verification that cannot establish its preconditions never reports "fixed"
        self.fake.mode = "token_expired"
        snap = self.svc.verify_fix("appr")
        items = {i["id"]: i for i in snap["defense_comparison"]["items"]}
        self.assertNotEqual(items["f_ex_idor"]["after_verdict"], "not_reproduced")
        self.assertEqual(self.finding("f_ex_idor")["evidence_status"], "incomplete")


class TestNoServiceIsRegisteredImplicitly(RealServiceBase):
    PRESET_HOSTS = tuple(L2RuleSet.load([BUILTIN_PROFILE_DIR]).profiles["deepnote"]["hosts"])

    def test_fresh_install_lists_no_real_service(self):
        names = {a["name"] for a in self.svc.assets()}
        self.assertFalse(names & set(self.PRESET_HOSTS))
        self.assertFalse(any(a.get("challenge") for a in self.svc.assets()))

    def test_saved_registrations_are_kept_and_deleted_ones_stay_deleted(self):
        keep, drop = self.PRESET_HOSTS[0], self.PRESET_HOSTS[1]
        for host in (keep, drop):                       # only issues a challenge: no traffic
            self.svc.issue_ownership_challenge(url=f"https://{host}", approver="appr")
        self.svc.workers.kill_all()
        again = AssessmentService(self.dir, LAB_PORT, l2_profile_dirs=PROFILE_DIRS)
        by_name = {a["name"]: a for a in again.assets()}
        self.assertEqual(by_name[keep]["status"], "所有確認待ち")       # existing data survives a restart
        self.assertIn(drop, by_name)
        again.delete_asset(by_name[drop]["id"])
        again.workers.kill_all()
        third = AssessmentService(self.dir, LAB_PORT, l2_profile_dirs=PROFILE_DIRS)
        names = {a["name"] for a in third.assets()}
        self.assertIn(keep, names)
        self.assertNotIn(drop, names)                    # not re-created at startup
        self.assertNotIn(self.PRESET_HOSTS[2], names)    # never registered -> never appears
        third.workers.kill_all()
        self.assertEqual(self.fake.seen, [])

    def test_service_without_a_profile_gets_l1_only(self):
        self.svc.workers.kill_all()
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1,
                                     l2_profile_dirs=[BUILTIN_PROFILE_DIR])   # example profile not loaded
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        self.onboard()
        snap = self.run_l1()
        self.assertEqual(snap["state"], "completed")
        self.assertFalse([f for f in snap["findings"] if f.get("requires_l2_approval")])
        self.assertIsNone(snap["secrets_status"]["profile"])
        with self.assertRaises(ValueError):
            self.set_secrets()
        self.assertEqual([p for p, _ in self.fake.seen], ["/"])


class TestRemotionExport(RealServiceBase):
    def test_lab_export_never_claims_ownership_verification(self):
        out = self.svc.remotion_export()
        self.assertFalse(out["service"]["ownership_and_scope_confirmed"])
        self.assertTrue(out["service"]["local_lab_demo"])
        self.assertNotIn("ownership_verified", [e["scene"] for e in out["remotion_timeline"]["events"]])
        self.assertEqual(out["confirmed_findings"], [])          # fixtures are excluded

    def test_real_service_export_is_anonymized_and_evidence_backed(self):
        self.onboard()
        self.run_l1()
        out = self.svc.remotion_export()
        text = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(HOST, text)
        self.assertTrue(out["service"]["ownership_and_scope_confirmed"])
        self.assertEqual(out["remotion_timeline"]["events"][0]["scene"], "ownership_verified")
        self.assertTrue(out["confirmed_findings"])
        self.assertTrue(all(f["audit_hash"] for f in out["confirmed_findings"]))
        self.assertEqual(out["summary"]["unverified_candidate_count"], len(EXAMPLE["checks"]))
        self.assertEqual(out["summary"]["proven_count"] + out["summary"]["detected_count"]
                         + out["summary"]["not_reproduced_count"], len(out["confirmed_findings"]))
        self.assertIn(HOST, json.dumps(self.svc.remotion_export(anonymize=False)))

    def test_pure_builder_tolerates_minimal_snapshot(self):
        out = build_remotion_export({"findings": [{"id": "x", "title": "t", "demo_fixture": True}]})
        self.assertEqual(out["summary"]["confirmed_findings_count"], 0)
        self.assertGreaterEqual(out["remotion_timeline"]["total_frames"], 90)


class TestRealServiceApi(RealServiceBase):
    """HTTP surface: role gating and no secret echo."""

    def setUp(self):
        super().setUp()
        from http.server import ThreadingHTTPServer
        from aegis.operators import OperatorStore, hash_password
        from aegis.server import make_handler
        seed = self.dir / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "op", "display": "操作者", "roles": ["operator"], "password_hash": hash_password("op-pw")},
            {"name": "appr", "display": "承認者", "roles": ["operator", "approver"],
             "password_hash": hash_password("appr-pw")}]}))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, OperatorStore(seed)))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.srv.server_port}/api"

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def call(self, path, body=None, cookie=None):
        import urllib.error
        import urllib.request
        headers = {"Content-Type": "application/json"}
        if body is not None:
            headers["X-Aegis-Request"] = "1"
        if cookie:
            headers["Cookie"] = cookie
        req = urllib.request.Request(self.api + path, json.dumps(body).encode() if body is not None else None, headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r), (r.headers.get("Set-Cookie") or "").split(";")[0]
        except urllib.error.HTTPError as e:
            return e.code, json.load(e), ""

    def login(self, name):
        return self.call("/auth/login", {"name": name, "password": f"{name}-pw"})[2]

    def test_flow_over_http_with_role_gate_and_no_secret_echo(self):
        op, appr = self.login("op"), self.login("appr")
        self.assertEqual(self.call("/assets/challenge", {"url": self.url})[0], 401)   # login required

        code, body, _ = self.call("/assets/challenge", {"url": self.url}, appr)
        self.assertEqual(code, 200)
        ch = body["challenge"]
        self.assertTrue(ch["dns_txt_name"].startswith("_vulnix-verify."))

        # the API cannot enable loopback targets, so scope is confirmed at service level here
        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[]):
            code, body, _ = self.call("/assets/verify-ownership", {"url": self.url, "method": "dns_txt"}, appr)
        self.assertEqual((code, body["verified"]), (200, False))
        code, body, _ = self.call("/assets/confirm-scope", {"url": self.url, "activate_workspace": True}, appr)
        self.assertEqual(code, 409)
        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[ch["dns_txt_value"]]):
            code, body, _ = self.call("/assets/verify-ownership", {"url": self.url, "method": "dns_txt"}, appr)
        self.assertEqual((code, body["verified"], body["l2_auto_approved"]), (200, True, False))
        code, body, _ = self.call("/assets/confirm-scope", {"url": self.url, "confirmed_prohibited": False}, appr)
        self.assertEqual(code, 409)
        code, body, _ = self.call("/assets/confirm-scope", {"url": self.url, "activate_workspace": True}, appr)
        self.assertEqual(code, 200)
        self.assertTrue(body["snapshot"]["is_external_service"])
        self.assertFalse(self.svc._verified_external_hosts[HOST]["allow_loopback_test"])
        self.svc._verified_external_hosts[HOST]["allow_loopback_test"] = True   # test-only switch

        code, body, _ = self.call("/assets/secrets", {
            "host": HOST, "user_a_token": TOKEN_A, "user_b_token": TOKEN_B}, appr)
        self.assertEqual(code, 200)
        raw = json.dumps(body)
        self.assertNotIn(TOKEN_A, raw)
        self.assertNotIn(TOKEN_B, raw)
        self.assertTrue(body["secrets_status"]["checks"]["ex_idor_notes"]["ready"])
        self.assertEqual(body["secrets_status"]["checks"]["ex_billing_plan"]["missing"],
                         ["free_plan_token", "premium_plan_token"])
        self.assertEqual(body["secrets_status"]["profile"]["id"], "example")
        code, body, _ = self.call("/assets/secrets", {
            "host": HOST, "tokens": {"premium_plan_token": TOKEN_PREMIUM}}, appr)   # nested form
        self.assertEqual(code, 200)
        self.assertEqual(body["secrets_status"]["checks"]["ex_billing_plan"]["missing"], ["free_plan_token"])
        self.assertNotIn(TOKEN_PREMIUM, json.dumps(body))
        code, body, _ = self.call(f"/assets/secrets-status?host={HOST}", cookie=appr)
        self.assertEqual((code, body["has_l2_credentials"]), (200, True))
        code, body, _ = self.call("/assets/secrets", {
            "host": HOST, "user_a_token": TOKEN_B}, appr)                      # A == B
        self.assertEqual(code, 409)

        # L2 on a real service: operator role is refused before anything is sent
        code, body, _ = self.call("/assessments/scan_001/verify-finding", {"finding_id": "f_ex_idor"}, op)
        self.assertEqual(code, 403)
        self.assertEqual(self.fake.seen, [])
        code, body, _ = self.call("/assessments/scan_001/verify-finding", {"finding_id": "f_ex_idor"}, appr)
        self.assertEqual(code, 200)
        f = next(x for x in body["findings"] if x["id"] == "f_ex_idor")
        self.assertEqual(f["evidence_status"], "proven")
        self.assertNotIn(TOKEN_A, json.dumps(body))

        code, body, _ = self.call("/assessments/scan_001/remotion", cookie=appr)
        self.assertEqual(code, 200)
        self.assertTrue(body["anonymized"])
        self.assertNotIn(HOST, json.dumps(body))
        self.assertEqual(body["summary"]["proven_count"], 1)
        self.assert_no_token_anywhere()


if __name__ == "__main__":
    unittest.main()
