"""Who may do what: role assignment, read authentication, separation of duties
for real-service L2, and keeping traffic on addresses an ownership proof covers.

No test here talks to the internet (loopback stand-in + injected resolvers/lookups).
"""
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from aegis import ownership
from aegis.network import NetworkError
from aegis.operators import AuthError, OperatorStore, hash_password
from aegis.server import make_handler
from tests.test_real_service import (HOST, NOTE_A, NOTE_B, PROFILE_DIRS, TOKEN_A, TOKEN_B,
                                     LAB_PORT, RealServiceBase)
from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService

PUBLIC_1, PUBLIC_2 = "93.184.216.34", "93.184.216.35"


def seed(dir_: Path) -> Path:
    p = dir_ / "operators.json"
    p.write_text(json.dumps({"operators": [
        {"name": n, "display": n, "roles": r, "password_hash": hash_password(f"{n}-password")}
        for n, r in (("op", ["operator"]), ("op2", ["operator"]),
                     ("appr", ["operator", "approver"]), ("appr2", ["operator", "approver"]),
                     ("root", ["operator", "admin"]))]}))
    return p


class ApiBase(RealServiceBase):
    SEPARATE = False

    def setUp(self):
        super().setUp()
        self.svc.workers.kill_all()
        self.svc = AssessmentService(self.dir, LAB_PORT, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                                     separate_l2_approver=self.SEPARATE)
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        self.ops = OperatorStore(seed(self.dir))
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.api = f"http://127.0.0.1:{self.srv.server_port}/api"
        self.cookies: dict[str, str] = {}

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def call(self, path, body=None, who=None):
        headers = {"Content-Type": "application/json"}
        if body is not None:
            headers["X-Aegis-Request"] = "1"
        if who:
            headers["Cookie"] = self.session(who)
        req = urllib.request.Request(self.api + path, json.dumps(body).encode() if body is not None else None, headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def session(self, name):
        if name not in self.cookies:
            req = urllib.request.Request(self.api + "/auth/login", json.dumps(
                {"name": name, "password": f"{name}-password"}).encode(),
                {"Content-Type": "application/json", "X-Aegis-Request": "1"})
            with urllib.request.urlopen(req) as r:
                self.cookies[name] = r.headers["Set-Cookie"].split(";")[0]
        return self.cookies[name]

    def events(self, name):
        return [e["fields"] for e in self.svc.audit.entries() if e["event"] == name]


class TestRolesAreGrantedByAnAdminOnly(ApiBase):
    def test_accounts_are_created_by_an_admin_and_never_with_extra_roles(self):
        new = {"name": "newcomer", "password": "long-enough-password", "roles": ["operator", "approver", "admin"]}
        # anonymous, operator and approver callers cannot create accounts in production mode
        for who in (None, "op", "appr"):
            self.assertEqual(self.call("/auth/register", new, who)[0], 403)
        self.assertNotIn("newcomer", [o.name for o in self.ops.operators()])
        self.assertEqual(len(self.events("auth.registration_refused")), 3)
        self.assertFalse(self.call("/auth/me")[1]["self_registration"])
        # an admin creates it: operator only, no session handed out, on the record
        code, body = self.call("/auth/register", new, "root")
        self.assertEqual((code, body), (200, {"created": {"name": "newcomer", "display": "newcomer", "roles": ["operator"]}}))
        created = self.events("operator.created")[-1]
        self.assertEqual((created["actor"], created["target"], created["requested_roles_ignored"]),
                         ("root", "newcomer", ["approver", "admin"]))
        self.assertFalse(self.ops.is_self_registered("newcomer"))
        # development mode: self-registration exists, still operator only, and is marked as such
        with patch.dict("os.environ", {"AEGIS_ENV": "development"}):
            code, body = self.call("/auth/register", {**new, "name": "devuser"})
        self.assertEqual((code, body["session"]["roles"]), (200, ["operator"]))
        self.assertEqual(self.events("auth.registered")[-1]["requested_roles_ignored"], ["approver", "admin"])
        self.assertTrue(self.ops.is_self_registered("devuser"))
        with self.assertRaises(TypeError):                     # the store has no way to self-assign either
            self.ops.register("x-user", "long-enough-password", roles=("approver",))

    def test_only_an_admin_changes_roles_and_every_change_is_audited(self):
        for who in ("op", "appr"):                             # an approver is not an admin
            code, _ = self.call("/operators/roles", {"name": "op", "roles": ["operator", "approver"]}, who)
            self.assertEqual(code, 403)
            self.assertEqual(self.call("/operators", who=who)[0], 403)
        self.assertEqual(len(self.events("operator.roles_change_denied")), 2)
        self.assertEqual(self.call("/operators/roles", {"name": "op", "roles": ["approver"]})[0], 401)

        code, listing = self.call("/operators", who="root")
        self.assertEqual(code, 200)
        self.assertEqual({o["name"]: o["roles"] for o in listing["operators"]}["op"], ["operator"])
        self.assertNotIn("password_hash", json.dumps(listing))

        code, body = self.call("/operators/roles", {"name": "op", "roles": ["approver"]}, "root")
        self.assertEqual((code, body["roles"]), (200, ["operator", "approver"]))
        change = self.events("operator.roles_changed")[-1]
        self.assertEqual((change["actor"], change["target"], change["before"], change["after"]),
                         ("root", "op", ["operator"], ["operator", "approver"]))
        self.assertEqual(self.call("/operators/roles", {"name": "op", "roles": ["superuser"]}, "root")[0], 409)
        self.assertEqual(self.call("/operators/roles", {"name": "ghost", "roles": ["approver"]}, "root")[0], 409)

    def test_a_revoked_role_stops_working_on_the_existing_session(self):
        self.session("appr")                                    # logged in while still an approver
        self.assertEqual(self.call(f"/assessments/{self.svc.a.id}/verify-fix", {}, "appr")[0], 200)
        self.call("/operators/roles", {"name": "appr", "roles": ["operator"]}, "root")
        self.assertEqual(self.call(f"/assessments/{self.svc.a.id}/verify-fix", {}, "appr")[0], 403)
        # and it survives a restart of the store: stored sessions do not carry roles
        again = OperatorStore(self.dir / "operators.json")
        self.assertEqual(again.resolve(self.cookies["appr"].split("=", 1)[1]).roles, ("operator",))

    def test_no_self_service_and_the_last_admin_cannot_be_removed(self):
        for roles in (["operator", "admin", "approver"], ["operator"]):
            self.assertEqual(self.call("/operators/roles", {"name": "root", "roles": roles}, "root")[0], 409)
        with self.assertRaises(AuthError):                      # the store re-checks the actor itself
            self.ops.set_roles("op", ["approver"], actor="appr")
        self.ops.set_roles("op", ["admin"], actor="root")
        self.ops.set_roles("root", ["operator"], actor="op")    # a second admin may do it
        with self.assertRaises(AuthError):
            self.ops.set_roles("op", ["operator"], actor="op")

    def test_installation_from_before_the_admin_role_gets_an_admin_without_promoting_anyone(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "operators.json"
            p.write_text(json.dumps({"operators": [
                {"name": "old-appr", "display": "x", "roles": ["operator", "approver"],
                 "password_hash": hash_password("old-password-1")}]}))
            store = OperatorStore(p)
            roles = {o.name: o.roles for o in store.operators()}
            self.assertEqual(roles["old-appr"], ("operator", "approver"))        # unchanged
            self.assertEqual(roles["admin"], ("operator", "admin"))
            cred = Path(d) / "operators.admin-credentials.txt"
            self.assertEqual(oct(cred.stat().st_mode & 0o777), "0o600")
            pw = [l.split(": ", 1)[1] for l in cred.read_text().splitlines() if l.startswith("パスワード")][0]
            self.assertEqual(store.login("admin", pw).roles, ("operator", "admin"))
            self.assertNotIn(pw, p.read_text())
            self.assertEqual(len(OperatorStore(p).operators()), 2)               # created once, not per start


class TestLegacyApproversAreFlaggedForReview(ApiBase):
    def test_approver_without_a_grant_on_record_is_flagged_until_an_admin_decides(self):
        def review():
            return {o["name"]: o["needs_role_review"] for o in self.call("/operators", who="root")[1]["operators"]}
        # `appr`/`appr2` come from the seed file: no admin ever granted them the role
        self.assertEqual(review(), {"op": False, "op2": False, "appr": True, "appr2": True, "root": False})
        # the admin attests one (same roles re-submitted) and revokes the other
        self.assertEqual(self.call("/operators/roles", {"name": "appr", "roles": ["operator", "approver"]}, "root")[0], 200)
        self.assertTrue(self.events("operator.roles_changed")[-1]["attested_unchanged"])
        self.call("/operators/roles", {"name": "appr2", "roles": ["operator"]}, "root")
        self.call("/operators/roles", {"name": "op", "roles": ["approver"]}, "root")       # a fresh grant
        self.assertEqual(review(), {"op": False, "op2": False, "appr": False, "appr2": False, "root": False})
        # granted, then revoked, then present again without a record would be flagged again
        self.call("/operators/roles", {"name": "op", "roles": ["operator"]}, "root")
        self.ops._ops["op"].roles = ("operator", "approver")          # e.g. an edited seed file
        self.assertTrue(review()["op"])


class TestOpenReadsAreDevelopmentOnly(ApiBase):
    def handler_allows_anonymous_read(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{srv.server_port}/api/assets")
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status == 200
            except urllib.error.HTTPError as e:
                return e.code != 401
        finally:
            srv.shutdown()
            srv.server_close()

    def test_environment_opt_out_is_ignored_outside_development_mode(self):
        with patch.dict("os.environ", {"AEGIS_REQUIRE_READ_AUTH": "0"}, clear=False):
            with patch.dict("os.environ", {"AEGIS_ENV": "production"}):
                self.assertFalse(self.handler_allows_anonymous_read())
            with patch.dict("os.environ", {"AEGIS_ENV": ""}):
                self.assertFalse(self.handler_allows_anonymous_read())          # unmarked = production
            self.assertEqual(self.events("config.read_auth_disabled"), [])
            with patch.dict("os.environ", {"AEGIS_ENV": "development"}):
                self.assertTrue(self.handler_allows_anonymous_read())
            self.assertEqual(len(self.events("config.read_auth_disabled")), 1)   # and it is on the record

    def test_server_refuses_to_start_with_open_reads_in_production(self):
        from aegis import server
        for argv, env in ((["aegis", "--no-read-auth"], {"AEGIS_ENV": "production"}),
                          (["aegis", "--no-read-auth"], {"AEGIS_ENV": ""}),
                          (["aegis"], {"AEGIS_ENV": "", "AEGIS_REQUIRE_READ_AUTH": "0"})):
            with self.subTest(argv=argv, env=env):
                with patch("sys.argv", argv), patch.dict("os.environ", {**env, "VULNIX_NO_ENV_LOCAL": "1"}), \
                        patch("aegis.server.start_lab") as lab, patch("aegis.server.ThreadingHTTPServer") as http_srv:
                    with self.assertRaises(SystemExit) as cm:
                        server.main()
                    self.assertIn("開発モード", str(cm.exception))
                    lab.assert_not_called()                                     # nothing was started
                    http_srv.assert_not_called()


class TestAuthorityBearingActionsNeedAnApprover(ApiBase):
    def test_scope_confirmation_and_test_accounts_are_approver_only(self):
        code, body = self.call("/assets/challenge", {"url": self.url}, "op")
        self.assertEqual(code, 200)
        ch = body["challenge"]
        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[ch["dns_txt_value"]]):
            self.assertEqual(self.call("/assets/verify-ownership", {"url": self.url, "method": "dns_txt"}, "op")[0], 200)
        confirm = {"url": self.url, "activate_workspace": True, "confirmed_prohibited": True}
        self.assertEqual(self.call("/assets/confirm-scope", confirm, "op")[0], 403)
        self.assertNotIn(HOST, self.svc._verified_external_hosts)
        self.assertEqual(self.call("/assets/confirm-scope", confirm, "appr")[0], 200)
        tokens = {"host": HOST, "tokens": {"user_a_token": TOKEN_A, "user_b_token": TOKEN_B}}
        self.assertEqual(self.call("/assets/secrets", tokens, "op")[0], 403)
        self.assertFalse(self.svc.secrets.has_any_token(HOST))
        self.assertEqual(self.call("/assets/secrets", tokens, "appr")[0], 200)
        self.assertEqual(self.call(f"/assets/secrets-status?host={HOST}")[0], 401)   # reads need a session
        # an operator can neither delete the verified service nor re-point it (both drop scope and tokens)
        asset_id = self.svc.a.asset["id"]
        self.assertEqual(self.call("/assets/delete", {"id": asset_id}, "op")[0], 403)
        self.assertEqual(self.call("/assets/challenge", {"url": f"http://{HOST}:1"}, "op")[0], 403)
        self.assertTrue(self.svc._is_external_service_asset(HOST))
        self.assertTrue(self.svc.secrets.has_any_token(HOST))
        self.assertEqual(self.call("/assets/delete", {"id": asset_id}, "appr")[0], 200)
        self.assertFalse(self.svc.secrets.has_any_token(HOST))
        self.assertEqual(self.fake.seen, [])

    def test_no_lookup_is_made_for_a_name_that_was_never_registered(self):
        with patch("aegis.ownership.default_dns_txt_lookup") as txt, \
                patch("aegis.ownership.default_well_known_fetcher") as fetch:
            for method in ("dns_txt", "well_known"):
                code, _ = self.call("/assets/verify-ownership",
                                    {"url": "https://someone-else.example.org", "method": method}, "appr")
                self.assertEqual(code, 409)
            txt.assert_not_called()
            fetch.assert_not_called()

    def test_oversized_or_non_object_bodies_are_rejected(self):
        def raw(payload: bytes, length=None):
            req = urllib.request.Request(self.api + "/auth/login", payload, {
                "Content-Type": "application/json", "X-Aegis-Request": "1",
                "Content-Length": str(len(payload) if length is None else length)})
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code
        self.assertEqual(raw(b"[1, 2, 3]"), 400)
        self.assertEqual(raw(b'"text"'), 400)
        self.assertEqual(raw(b"{}", length=5_000_000), 413)


class TestSeparationOfDutiesForL2(ApiBase):
    SEPARATE = True

    def setUp(self):
        super().setUp()
        self.onboard()
        self.assertEqual(self.run_l1()["state"], "completed")
        self.set_secrets()
        self.fake.seen.clear()
        self.base = f"/assessments/{self.svc.a.id}"

    def run_l2(self, who):
        return self.call(self.base + "/verify-finding", {"finding_id": "f_ex_idor"}, who)

    def test_an_approver_alone_cannot_run_l2(self):
        code, body = self.run_l2("appr")
        self.assertEqual(code, 409)
        self.assertIn("依頼", body["error"])
        # requesting it oneself does not help
        self.assertEqual(self.call(self.base + "/request-l2", {"finding_id": "f_ex_idor"}, "appr")[0], 200)
        code, body = self.run_l2("appr")
        self.assertEqual(code, 409)
        self.assertIn("本人", body["error"])
        self.assertEqual(self.fake.seen, [])

    def test_request_by_one_person_approval_by_another_then_the_request_is_spent(self):
        code, snap = self.call(self.base + "/request-l2", {"finding_id": "f_ex_idor"}, "op")
        self.assertEqual(code, 200)
        self.assertTrue(snap["l2_separation_required"])
        f = next(x for x in snap["findings"] if x["id"] == "f_ex_idor")
        self.assertEqual(f["l2_request"]["requested_by"], "op")
        self.assertEqual(self.fake.seen, [])                    # a request sends nothing
        self.assertEqual(self.run_l2("op")[0], 403)             # the requester is not an approver
        code, snap = self.run_l2("appr")
        self.assertEqual(code, 200)
        self.assertEqual(next(x for x in snap["findings"] if x["id"] == "f_ex_idor")["evidence_status"], "proven")
        approval = self.events("approval.approved")[-1]
        self.assertEqual((approval["actor"], approval["requested_by"], approval["separation_of_duties"]),
                         ("appr", "op", True))
        self.assertEqual(self.events("l2.run_requested")[-1]["actor"], "op")
        self.assertEqual([p for p, _ in self.fake.seen], [NOTE_B, NOTE_A, NOTE_B])
        self.fake.seen.clear()
        self.assertEqual(self.run_l2("appr2")[0], 409)          # one request, one run
        # re-verification does not re-run L2 on its own under separation of duties
        self.assertEqual(self.call(self.base + "/verify-fix", {}, "appr2")[0], 200)
        self.assertEqual({p for p, _ in self.fake.seen}, {"/"})

    def test_a_self_registered_second_identity_cannot_satisfy_the_separation(self):
        # the approver mints a second account for themselves (only possible in development mode at all)
        with patch.dict("os.environ", {"AEGIS_ENV": "development"}):
            code, _ = self.call("/auth/register", {"name": "sock", "password": "sock-password"})
            self.assertEqual(code, 200)
        self.cookies["sock"] = None
        req = urllib.request.Request(self.api + "/auth/login", json.dumps(
            {"name": "sock", "password": "sock-password"}).encode(),
            {"Content-Type": "application/json", "X-Aegis-Request": "1"})
        with urllib.request.urlopen(req) as r:
            self.cookies["sock"] = r.headers["Set-Cookie"].split(";")[0]
        code, body = self.call(self.base + "/request-l2", {"finding_id": "f_ex_idor"}, "sock")
        self.assertEqual(code, 403)
        self.assertEqual(self.run_l2("appr")[0], 409)
        self.assertEqual(self.fake.seen, [])

    def test_requests_expire_are_not_restored_and_cover_only_runnable_items(self):
        self.call(self.base + "/request-l2", {"finding_id": "f_ex_idor"}, "op")
        self.svc._l2_requests["f_ex_idor"]["requested_at"] = time.time() - 25 * 3600
        self.assertEqual(self.run_l2("appr")[0], 409)
        self.call(self.base + "/request-l2", {"finding_id": "f_ex_idor"}, "op")
        self.assertNotIn("l2_requests", json.loads((self.dir / "state.json").read_text()))
        for fid in ("f_ex_unconfirmed", "f_headers", "nope"):
            self.assertEqual(self.call(self.base + "/request-l2", {"finding_id": fid}, "op")[0], 409, fid)
        self.assertEqual(self.fake.seen, [])


class TestTrafficStaysOnProvenAddresses(RealServiceBase):
    """Ownership is proven for a name; whenever that name resolves to an address
    no proof has covered, the proof is checked again before anything is sent."""

    def prepare(self, method="dns_txt"):
        ch = self.svc.issue_ownership_challenge(url=f"https://{HOST}", approver="appr")["challenge"]
        self.token = ch["token"]
        self.txt = [ch["dns_txt_value"]]
        self.svc._proof_dns_lookup = lambda name: list(self.txt)
        self.fetched = []

        def fetch(host, address):
            self.fetched.append((host, address))
            return self.file_body
        self.file_body = ch["well_known_content"]
        self.svc._proof_file_fetch = fetch
        if method == "dns_txt":
            self.svc.verify_asset_ownership(url_or_host=HOST, method="dns_txt", dns_lookup=lambda n: list(self.txt))
        else:
            self.svc.verify_asset_ownership(url_or_host=HOST, method="well_known", http_fetch=lambda u: self.file_body)
        self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", activate_workspace=True)
        self.addrs = [PUBLIC_1]
        self.svc._custom_resolver = lambda h: list(self.addrs)

    def events(self, name):
        return [e["fields"] for e in self.svc.audit.entries() if e["event"] == name]

    def test_new_address_is_accepted_only_while_the_dns_proof_still_holds(self):
        self.prepare()
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_1])
        self.assertEqual(self.svc._verified_external_hosts[HOST]["verified_addresses"], [PUBLIC_1])
        self.assertEqual(len(self.events("asset.addresses_reverified")), 1)
        self.svc._resolve_host(HOST)
        self.assertEqual(len(self.events("asset.addresses_reverified")), 1)      # known address: no re-check
        self.addrs = [PUBLIC_1, PUBLIC_2]                                          # owner added a frontend
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_1, PUBLIC_2])
        self.assertEqual(self.events("asset.addresses_reverified")[-1]["new_addresses"], [PUBLIC_2])
        # the record was dropped and the name now points somewhere else: scope is revoked
        self.txt = []
        self.addrs = ["151.101.1.69"]
        with self.assertRaises(NetworkError):
            self.svc._resolve_host(HOST)
        self.assertNotIn(HOST, self.svc._verified_external_hosts)
        self.assertEqual(self.svc._resolve_host(HOST), [])
        self.assertFalse(self.svc.snapshot()["asset"]["scope_confirmed"])
        self.assertEqual(self.events("asset.scope_revoked_address_change")[-1]["new_addresses"], ["151.101.1.69"])
        with self.assertRaises(ValueError):
            self.svc.start()
        self.assertEqual(self.fake.seen, [])

    def test_proof_file_is_fetched_from_the_new_address_itself(self):
        self.prepare("well_known")
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_1])
        self.assertEqual(self.fetched, [(HOST, PUBLIC_1)])
        self.file_body = "someone else's server"
        self.addrs = [PUBLIC_2]
        with self.assertRaises(NetworkError):
            self.svc._resolve_host(HOST)
        self.assertEqual(self.fetched[-1], (HOST, PUBLIC_2))                     # pinned to the address in question
        self.assertNotIn(HOST, self.svc._verified_external_hosts)

    def test_rebinding_to_a_non_public_address_is_refused_before_any_proof_check(self):
        self.prepare()
        self.svc._resolve_host(HOST)
        for bad in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:10.0.0.5", "64:ff9b::a00:5",
                    "2002:a00:5::1"):
            with self.subTest(address=bad):
                self.addrs = [PUBLIC_1, bad]
                with self.assertRaises(NetworkError):
                    self.svc._resolve_host(HOST)
        self.assertIn(HOST, self.svc._verified_external_hosts)                   # refused, not revoked
        self.assertEqual(len(self.events("asset.addresses_reverified")), 1)

    def test_restart_keeps_the_proven_addresses_and_an_edited_list_is_rejected(self):
        self.prepare()
        self.svc._resolve_host(HOST)
        self.svc.workers.kill_all()
        again = AssessmentService(self.dir, LAB_PORT, l2_confinement=TEST_CONFINEMENT, l2_profile_dirs=PROFILE_DIRS)
        self.assertEqual(again._verified_external_hosts[HOST]["verified_addresses"], [PUBLIC_1])
        again.workers.kill_all()
        ledger = json.loads((self.dir / "authority.ledger").read_text())     # where authority lives
        ledger["tables"]["verified_external_hosts"][HOST]["verified_addresses"] = [PUBLIC_1, "151.101.1.69"]
        (self.dir / "authority.ledger").write_text(json.dumps(ledger))
        forged = AssessmentService(self.dir, LAB_PORT, l2_confinement=TEST_CONFINEMENT, l2_profile_dirs=PROFILE_DIRS)
        self.assertEqual(forged._verified_external_hosts, {})
        forged.workers.kill_all()


class TestProofFileFetchIsPinned(unittest.TestCase):
    def test_the_validated_address_is_the_one_contacted(self):
        with patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", (PUBLIC_1, 443))]) as resolve, \
                patch("socket.create_connection", side_effect=OSError("stop here")) as connect:
            with self.assertRaises(OSError):
                ownership.default_well_known_fetcher("https://stg.example.org/.well-known/vulnix-verify.txt")
            resolve.assert_called_once()                                          # resolved exactly once
            self.assertEqual(connect.call_args[0][0], (PUBLIC_1, 443))            # connected by address, not by name

    def test_any_non_public_address_in_the_answer_refuses_the_fetch(self):
        answers = [(2, 1, 6, "", (PUBLIC_1, 443)), (2, 1, 6, "", ("10.0.0.5", 443))]
        with patch("socket.getaddrinfo", return_value=answers), patch("socket.create_connection") as connect:
            with self.assertRaises(ValueError):
                ownership.default_well_known_fetcher("https://stg.example.org/.well-known/vulnix-verify.txt")
            with self.assertRaises(ValueError):
                ownership.fetch_proof_file_pinned("stg.example.org", "127.0.0.1")
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()


class TestSecondReviewFindingsStayFixed(RealServiceBase):
    """Regressions for the second independent review."""

    def restart(self):
        self.svc.workers.kill_all()
        self.svc = AssessmentService(self.dir, LAB_PORT, l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS)
        self.svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        return self.svc

    def events(self, name):
        return [e["fields"] for e in self.svc.audit.entries() if e["event"] == name]

    def test_a_proof_written_into_the_state_file_is_not_a_proof(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]   # never verified
        state = json.loads((self.dir / "state.json").read_text())
        import hashlib
        forged_proof = {"verified": True, "method": "dns_txt", "host": HOST, "verified_at": time.time(),
                        "token_sha256": hashlib.sha256(ch["token"].encode()).hexdigest()}
        for rec in state["extra_assets"]:
            if rec["name"] == HOST:
                rec.update(ownership_verified=True, ownership_proof=forged_proof)
        # (a) only the display record is edited: the signed tables still load, the record is corrected
        (self.dir / "state.json").write_text(json.dumps(state))
        svc = self.restart()
        with self.assertRaises(ValueError):
            svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True)
        self.assertFalse(next(a for a in svc.assets() if a["name"] == HOST)["ownership_verified"])
        # (b) a proof table written into state.json is not read at all: authority lives in the ledger
        state["ownership_proofs"] = {HOST: forged_proof}
        (self.dir / "state.json").write_text(json.dumps(state))
        svc = self.restart()
        self.assertEqual(svc._ownership_proofs, {})
        self.assertIn("state.authority_fields_ignored", [e["event"] for e in svc.audit.entries()])
        with self.assertRaises(ValueError):
            svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True)
        # (c) the ledger's proof table itself is edited: the whole authority state is refused
        svc.workers.kill_all()
        ledger = json.loads((self.dir / "authority.ledger").read_text())
        ledger["tables"]["ownership_proofs"] = {HOST: forged_proof}
        (self.dir / "authority.ledger").write_text(json.dumps(ledger))
        svc = self.restart()
        self.assertEqual(svc._ownership_proofs, {})
        self.assertIn("state.authority_rejected", [e["event"] for e in svc.audit.entries()])
        with self.assertRaises(ValueError):
            svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True)
        self.assertEqual(self.fake.seen, [])

    def test_an_older_signed_ledger_does_not_bring_back_revoked_authority(self):
        self.onboard()
        self.set_secrets()
        old = ("state.json", "authority.ledger")                     # validly signed, scope confirmed
        before = {n: (self.dir / n).read_bytes() for n in old}
        for revoke in (lambda s: s.delete_asset(s.a.asset["id"]),
                       lambda s: s.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])):
            with self.subTest():
                svc = self.restart()
                if not svc._is_external_service_asset(HOST):         # re-onboard for the second variant
                    self.onboard()
                    before = {n: (self.dir / n).read_bytes() for n in old}
                    svc = self.svc
                revoke(svc)
                self.assertFalse(svc._is_external_service_asset(HOST))
                for n in old:                                        # put the old copies back
                    (self.dir / n).write_bytes(before[n])
                svc = self.restart()
                self.assertFalse(svc._is_external_service_asset(HOST))
                self.assertEqual(svc._verified_external_hosts, {})
                self.assertIn("older copy", self.events("state.authority_rejected")[-1]["reason"])
                self.assertEqual(svc._resolve_host(HOST), [])
        # removing the epoch record does not help either
        self.onboard()
        (self.dir / "authority.epoch").unlink()
        self.assertFalse(self.restart()._is_external_service_asset(HOST))
        self.assertEqual(oct((self.dir / "audit.jsonl").stat().st_mode & 0o777), "0o600")

    def test_active_and_inactive_assets_are_treated_alike_when_re_registered(self):
        self.onboard()                                               # HOST is the ACTIVE asset
        self.set_secrets()
        with self.assertRaises(ValueError):                          # lab names never enter the ownership flow
            self.svc.issue_ownership_challenge(url="http://lab.test:18097", approver="appr")
        self.svc.issue_ownership_challenge(url=f"http://{HOST}:{self.fake.server_port + 1}", approver="appr")
        self.assertFalse(self.svc._is_external_service_asset(HOST))
        self.assertNotIn(HOST, self.svc._ownership_proofs)
        self.assertFalse(self.svc.secrets.has_any_token(HOST))
        self.assertEqual([a["name"] for a in self.svc.assets()].count(HOST), 1)      # no hidden duplicate
        self.assertEqual(len([x for x in (self.svc.a.asset, *self.svc._extra_assets) if x["name"] == HOST]), 1)
        with self.assertRaises(ValueError):
            self.svc.start()
        self.assertEqual(self.fake.seen, [])

    def test_a_real_service_never_becomes_a_lab_alias(self):
        self.onboard()
        active_id = self.svc.a.asset["id"]
        self.svc.select_asset("lab")                                 # HOST becomes an inactive, verified asset
        for _ in range(4):                                           # delete lab aliases until HOST is promoted
            if self.svc.a.asset["id"] == active_id:
                break
            self.svc.delete_asset(self.svc.a.asset["id"])
        self.assertEqual(self.svc.a.asset["id"], active_id)
        self.assertTrue(self.svc.a.asset.get("challenge"))           # registration metadata survives promotion
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])   # proof now fails
        for svc in (self.svc, self.restart()):
            with self.assertRaises(ValueError):                      # the legacy checkbox cannot adopt the name
                svc.register_asset(name=HOST, kind="API", environment="stg",
                                   authorization_ref="SOW-1", ownership_verified=True, activate_workspace=True)
            self.assertNotIn(HOST, svc._allowed_hosts)
            self.assertEqual(svc._resolve_host(HOST), [])            # not 127.0.0.1
            self.assertFalse(svc.snapshot()["target_url"].startswith(f"http://{HOST}:{LAB_PORT}"))

    def test_dns_txt_must_equal_the_token(self):
        token = "vulnix-verify=abc"
        def check(records):
            return ownership.verify_ownership_challenge("example.org", "dns_txt", expected_token=token,
                                                        txt_lookup=lambda n: records)["verified"]
        self.assertTrue(check([token]))
        self.assertTrue(check([f'_vulnix-verify.example.org\\ttext = "{token}"']))
        for bad in ([f'text = "note: {token} was requested"'], [f"{token}-extra"], [f'text = "x{token}"'],
                    ["Server: 10.0.0.1\\n** server can't find _vulnix-verify.example.org: NXDOMAIN"], []):
            self.assertFalse(check(bad), bad)
        for addr in ("::127.0.0.1", "fec0::1", "::ffff:10.0.0.1"):
            self.assertIsNone(ownership.public_address(addr))


class TestAddressChangeWithholdsTokens(TestTrafficStaysOnProvenAddresses):
    def test_after_a_dns_proven_host_moves_l2_waits_for_an_approver(self):
        self.prepare()                                               # dns_txt proof, https
        self.svc._resolve_host(HOST)
        self.assertIsNone(self.svc._l2_block_reason())
        self.addrs = [PUBLIC_2]                                      # the name now points elsewhere; TXT still there
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_2])   # read-only L1 may follow the name
        self.assertEqual(self.svc._verified_external_hosts[HOST]["address_change_pending"], [PUBLIC_2])
        self.assertIn(PUBLIC_2, self.svc._l2_block_reason())
        self.assertEqual(self.svc._ephemeral_worker_env("reproduction_probe", {"check": "ex_idor_notes"}), {})
        # an approver re-confirming the scope (which needs a fresh proof) lifts it
        self.svc.verify_asset_ownership(url_or_host=HOST, method="dns_txt", dns_lookup=lambda n: list(self.txt))
        self.svc.confirm_asset_scope(url_or_host=HOST, approver="appr", activate_workspace=True)
        self.svc._resolve_host(HOST)
        self.assertIsNone(self.svc._l2_block_reason())

    def test_a_file_proven_host_that_moves_is_bound_by_the_file_and_needs_no_pause(self):
        self.prepare("well_known")
        self.svc._resolve_host(HOST)
        self.addrs = [PUBLIC_2]
        self.svc._resolve_host(HOST)                                 # the new address itself served the token
        self.assertFalse(self.svc._verified_external_hosts[HOST].get("address_change_pending"))
        self.assertIsNone(self.svc._l2_block_reason())

    def test_known_addresses_are_re_checked_against_the_proof_periodically(self):
        self.prepare()
        self.svc._resolve_host(HOST)
        self.txt = []                                                # the record is removed later
        self.assertEqual(self.svc._resolve_host(HOST), [PUBLIC_1])   # still fresh: no lookup
        self.svc._verified_external_hosts[HOST]["addresses_verified_at"] = time.time() - 25 * 3600
        with self.assertRaises(NetworkError):
            self.svc._resolve_host(HOST)
        self.assertNotIn(HOST, self.svc._verified_external_hosts)
