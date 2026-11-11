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

from aegis import evidence
from aegis.assessment import AssessmentService
from aegis.evidence import reproduction_verdict
from aegis.lab import set_lab_mode, start_lab
from aegis.network import NetworkError
from aegis.ownership import parse_service_target, verify_ownership_challenge
from aegis.remotion_export import build_remotion_export
from aegis.secrets_store import CHECK_SECRET_MAP, EncryptedSecretStore
from aegis.service_diag import DEEPNOTE_L2_SPECS, analyze_l1_service_response

LAB_PORT = 18097
HOST = "svc.example.test"
TOKEN_A = "tok-A-0123456789abcdef"
TOKEN_B = "tok-B-fedcba9876543210"
TOKEN_FREE = "tok-FREE-55aa55aa55aa"
NOTE_PATH = "/api/v1/notes/mock_note_user_b"
BILLING_PATH = "/api/v1/billing/premium-summary-check"


class FakeService(http.server.ThreadingHTTPServer):
    """Loopback stand-in for an owned staging service."""
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _FakeHandler)
        self.mode = "vulnerable"      # vulnerable | patched | missing | token_expired
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
        if self.path == "/":
            return self._send(200, {"ok": True}, [
                ("Server", "nginx"), ("Set-Cookie", "sid=abc; Path=/"),
                ("Access-Control-Allow-Origin", self.headers.get("Origin", "")),
                ("Access-Control-Allow-Credentials", "true")])
        if srv.mode == "token_expired":
            return self._send(401, {"error": "token expired"})
        if self.path == NOTE_PATH:
            if srv.mode == "missing":
                return self._send(404, {"error": "no such note"})
            if token == TOKEN_B:
                return self._send(200, {"note": "DEEPNOTE_MOCK_NOTE_USER_B", "echo": auth})
            if token == TOKEN_A and srv.mode == "vulnerable":
                return self._send(200, {"note": "DEEPNOTE_MOCK_NOTE_USER_B"})
            return self._send(403 if token else 401, {"error": "forbidden"})
        if self.path == BILLING_PATH:
            if token == TOKEN_FREE and srv.mode == "vulnerable":
                return self._send(200, {"summary": "DEEPNOTE_BILLING_BYPASS_PROVEN"})
            return self._send(402 if token else 401, {"error": "upgrade required"})
        return self._send(404, {"error": "not found"})


def _load_worker():
    spec = importlib.util.spec_from_file_location(
        "reproduction_probe_under_test",
        Path(__file__).parent.parent / "aegis" / "workers" / "reproduction_probe.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTablesStayInSync(unittest.TestCase):
    def test_worker_checks_match_verdict_tables_and_candidate_specs(self):
        checks = _load_worker().CHECKS
        self.assertEqual(set(checks), set(evidence.REPRODUCTION_MARKERS))
        for name, spec in checks.items():
            with self.subTest(check=name):
                self.assertEqual(spec["marker"], evidence.REPRODUCTION_MARKERS[name])
                self.assertEqual(tuple(spec.get("deny", (403,))), evidence.REPRODUCTION_DENY_STATUSES[name])
                self.assertEqual(bool(spec.get("control")), name in evidence.OWNER_CONTROL_CHECKS)
        self.assertEqual({s["check"] for s in DEEPNOTE_L2_SPECS}, evidence.DEEPNOTE_L2_CHECKS)
        self.assertEqual(set(CHECK_SECRET_MAP), evidence.DEEPNOTE_L2_CHECKS)
        for s in DEEPNOTE_L2_SPECS:
            self.assertEqual(s["path"], checks[s["check"]]["path"])
        for name, (_, _, control_key) in CHECK_SECRET_MAP.items():
            self.assertEqual(bool(control_key), name in evidence.OWNER_CONTROL_CHECKS)


class TestL2VerdictNeverFakesADefense(unittest.TestCase):
    CHECK = "deepnote_idor_notes"

    def _r(self, status, control, verdict="not_reproduced"):
        return {"check": self.CHECK, "status": status, "established": False,
                "verdict": verdict, "control": control}

    def test_denial_without_a_passing_owner_control_is_unverified(self):
        ok = {"performed": True, "status": 200, "ok": True}
        for control in (None, {}, {"performed": False, "ok": False},
                        {"performed": True, "status": 404, "ok": False},
                        {"performed": True, "status": 200, "ok": False}):
            with self.subTest(control=control):
                self.assertEqual(reproduction_verdict(self._r(403, control), self.CHECK), "unverified")
        self.assertEqual(reproduction_verdict(self._r(403, ok), self.CHECK), "not_reproduced")
        self.assertEqual(reproduction_verdict(self._r(404, ok), self.CHECK), "not_reproduced")

    def test_rejected_test_token_or_server_error_is_never_a_defense(self):
        ok = {"performed": True, "status": 200, "ok": True}
        for status in (401, 402, 410, 500, 302, 200):
            with self.subTest(status=status):
                self.assertEqual(reproduction_verdict(self._r(status, ok), self.CHECK), "unverified")
        # billing: only 402/403 count; a missing endpoint (404) or 401 does not
        for status, want in ((402, "not_reproduced"), (403, "not_reproduced"),
                             (404, "unverified"), (401, "unverified")):
            r = {"check": "deepnote_billing_plan", "status": status,
                 "established": False, "verdict": "not_reproduced"}
            self.assertEqual(reproduction_verdict(r, "deepnote_billing_plan"), want)


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
            status = store.set_credentials(HOST, {"user_a_token": TOKEN_A, "user_b_token": TOKEN_B})
            self.assertTrue(status["l2_ready"])
            blob = (Path(d) / "secrets.enc.json").read_text()
            for tok in (TOKEN_A, TOKEN_B):
                self.assertNotIn(tok, blob)
                self.assertNotIn(tok, json.dumps(status))
            self.assertEqual(oct((Path(d) / "secrets.enc.json").stat().st_mode & 0o777), "0o600")
            self.assertEqual(oct((Path(d) / ".secrets.key").stat().st_mode & 0o777), "0o600")
            # survives restart
            again = EncryptedSecretStore(Path(d))
            self.assertEqual(again.worker_env_for_check(HOST, "deepnote_idor_notes"),
                             {"VULNIX_L2_TOKEN": TOKEN_A, "VULNIX_L2_CONTROL_TOKEN": TOKEN_B})
            self.assertEqual(again.redact(f"x {TOKEN_A} y {TOKEN_B}"),
                             "x [REDACTED_SECRET] y [REDACTED_SECRET]")
            # billing needs the free-plan account, which is not set yet
            self.assertEqual(again.missing_for_check(HOST, "deepnote_billing_plan"), ["free_plan_token"])
            self.assertEqual(again.worker_env_for_check(HOST, "deepnote_billing_plan"), {})
            # tampering is detected instead of yielding garbage credentials
            env = json.loads(blob)
            env["ct"] = env["ct"][:-4] + ("AAA=" if not env["ct"].endswith("AAA=") else "BBB=")
            (Path(d) / "secrets.enc.json").write_text(json.dumps(env))
            self.assertFalse(EncryptedSecretStore(Path(d)).is_ready_for_l2(HOST))

    def test_rejects_same_account_on_both_sides_and_bad_paths(self):
        with tempfile.TemporaryDirectory() as d:
            store = EncryptedSecretStore(Path(d))
            with self.assertRaises(ValueError):
                store.set_credentials(HOST, {"user_a_token": TOKEN_A, "user_b_token": TOKEN_A})
            with self.assertRaises(ValueError):
                store.set_credentials(HOST, {"mock_note_path": "/a b\r\nX-Evil: 1"})
            self.assertFalse(store.is_ready_for_l2(HOST))
            st = store.set_credentials(HOST, {"mock_note_path": "api/v1/notes/n1"})
            self.assertEqual(st["mock_paths"], {"mock_note_path": "/api/v1/notes/n1"})


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
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1)
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

    def set_secrets(self, **kw):
        return self.svc.configure_asset_secrets(
            host=HOST, user_a_token=TOKEN_A, user_b_token=TOKEN_B, actor="appr", **kw)

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
            for tok in (TOKEN_A, TOKEN_B, TOKEN_FREE):
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
        again = AssessmentService(self.dir, LAB_PORT)
        self.assertTrue(again._is_external_service_asset())
        self.assertEqual(again.snapshot()["target_url"], self.url + "/")
        self.assertTrue(again.secrets_status()["l2_ready"])
        again.delete_asset(again.a.asset["id"])
        self.assertNotIn(HOST, again._verified_external_hosts)
        self.assertFalse(again.secrets.is_ready_for_l2(HOST))
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
        l2 = [by_id[s["id"]] for s in DEEPNOTE_L2_SPECS]
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
        self.set_secrets(free_plan_token=TOKEN_FREE)
        self.run_l1()
        self.fake.seen.clear()
        self.svc.verify_finding("all", actor="appr")
        self.assertEqual([p for p, _ in self.fake.seen], ["/"])
        self.assertEqual(self.finding("f_dn_idor")["evidence_status"], "candidate")


class TestL2HumanApprovedChecks(RealServiceBase):
    def setUp(self):
        super().setUp()
        self.onboard()
        self.assertEqual(self.run_l1()["state"], "completed")
        self.fake.seen.clear()

    def test_l2_requires_credentials_and_a_human(self):
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_dn_idor", actor="appr")          # no credentials
        self.set_secrets()
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_dn_idor", actor="policy:auto-L1")  # not a human
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_dn_billing", actor="appr")       # free-plan token missing
        self.assertEqual(self.fake.seen, [])
        self.assertTrue(self.svc.finding_requires_human_l2_approval("f_dn_idor"))
        self.assertFalse(self.svc.finding_requires_human_l2_approval("f_headers"))

    def test_broken_boundary_is_proven_and_tokens_never_leak(self):
        self.set_secrets()
        self.svc.verify_finding("f_dn_idor", actor="appr")
        f = self.finding("f_dn_idor")
        self.assertEqual(f["evidence_status"], "proven")
        # owner control with B first, then the cross-account request with A; nothing else
        self.assertEqual(self.fake.seen, [(NOTE_PATH, f"Bearer {TOKEN_B}"), (NOTE_PATH, f"Bearer {TOKEN_A}")])
        content = json.loads(f["evidence"][-1]["content"])
        self.assertEqual(content["request_headers"]["Authorization"], "Bearer [REDACTED_SECRET]")
        self.assertTrue(content["control"]["ok"])
        approval = [e for e in self.svc.audit.entries() if e["event"] == "approval.approved"][-1]["fields"]
        self.assertEqual((approval["actor"], approval["check"], approval["risk_level"]),
                         ("appr", "deepnote_idor_notes", "L2"))
        self.assert_no_token_anywhere()

    def test_enforced_boundary_is_not_reproduced_only_with_passing_owner_control(self):
        self.set_secrets(free_plan_token=TOKEN_FREE)
        self.fake.mode = "patched"
        self.svc.verify_finding("f_dn_idor", actor="appr")
        f = self.finding("f_dn_idor")
        self.assertEqual(f["evidence_status"], "not_reproduced")
        self.assertIn("所有者アカウント", f["verdict_note"])
        self.svc.verify_finding("f_dn_billing", actor="appr")
        self.assertEqual(self.finding("f_dn_billing")["evidence_status"], "not_reproduced")
        self.assertEqual(self.fake.seen[-1], (BILLING_PATH, f"Bearer {TOKEN_FREE}"))
        self.assert_no_token_anywhere()

    def test_missing_mock_data_or_expired_token_is_never_reported_as_defended(self):
        self.set_secrets()
        for mode in ("missing", "token_expired"):
            with self.subTest(mode=mode):
                self.fake.mode = mode
                self.svc.verify_finding("f_dn_idor", actor="appr")
                f = self.finding("f_dn_idor")
                self.assertEqual(f["verdict"], "unverified")
                self.assertEqual(f["evidence_status"], "incomplete")
                self.assertIn("再現せずとは判定しません", f["verdict_note"])

    def test_operator_configured_mock_path_is_used_for_that_check_only(self):
        self.set_secrets(free_plan_token=TOKEN_FREE,
                         mock_paths={"mock_note_path": "/api/v1/notes/custom-b-note"})
        self.fake.mode = "patched"
        self.svc.verify_finding("f_dn_idor", actor="appr")
        self.svc.verify_finding("f_dn_billing", actor="appr")
        paths = [p for p, _ in self.fake.seen]
        self.assertEqual(paths, ["/api/v1/notes/custom-b-note"] * 2 + [BILLING_PATH])
        # custom path does not exist on the service -> control fails -> not a defense
        self.assertEqual(self.finding("f_dn_idor")["evidence_status"], "incomplete")

    def test_fix_reverification_reruns_only_previously_approved_l2_items(self):
        self.set_secrets(free_plan_token=TOKEN_FREE)
        self.svc.verify_finding("f_dn_idor", actor="appr")
        self.assertEqual(self.finding("f_dn_idor")["evidence_status"], "proven")
        self.fake.mode = "patched"
        self.fake.seen.clear()
        with patch("aegis.assessment.set_lab_mode") as lab_switch:
            snap = self.svc.verify_fix("appr")
        lab_switch.assert_not_called()                # a real service is never "patched" by us
        self.assertEqual({p for p, _ in self.fake.seen}, {"/", NOTE_PATH})
        items = {i["id"]: i for i in snap["defense_comparison"]["items"]}
        self.assertEqual((items["f_dn_idor"]["before_verdict"], items["f_dn_idor"]["after_verdict"]),
                         ("proven", "not_reproduced"))
        self.assertNotIn("f_dn_billing", items)      # never approved -> never run, never listed
        self.assertEqual(self.finding("f_dn_billing")["evidence_status"], "candidate")


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
        self.assertEqual(out["summary"]["unverified_candidate_count"], len(DEEPNOTE_L2_SPECS))
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
        self.assertTrue(body["secrets_status"]["checks"]["deepnote_idor_notes"]["ready"])
        self.assertEqual(body["secrets_status"]["checks"]["deepnote_billing_plan"]["missing"], ["free_plan_token"])
        code, body, _ = self.call(f"/assets/secrets-status?host={HOST}", cookie=appr)
        self.assertEqual((code, body["has_l2_credentials"]), (200, True))
        code, body, _ = self.call("/assets/secrets", {
            "host": HOST, "user_a_token": TOKEN_B}, appr)                      # A == B
        self.assertEqual(code, 409)

        # L2 on a real service: operator role is refused before anything is sent
        code, body, _ = self.call("/assessments/scan_001/verify-finding", {"finding_id": "f_dn_idor"}, op)
        self.assertEqual(code, 403)
        self.assertEqual(self.fake.seen, [])
        code, body, _ = self.call("/assessments/scan_001/verify-finding", {"finding_id": "f_dn_idor"}, appr)
        self.assertEqual(code, 200)
        f = next(x for x in body["findings"] if x["id"] == "f_dn_idor")
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
