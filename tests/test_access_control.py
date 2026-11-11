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
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
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
    def test_self_registration_cannot_grant_roles(self):
        code, body = self.call("/auth/register", {"name": "newcomer", "password": "long-enough-password",
                                                  "roles": ["operator", "approver", "admin"]})
        self.assertEqual((code, body["session"]["roles"]), (200, ["operator"]))
        self.assertEqual(self.events("auth.registered")[-1]["requested_roles_ignored"], ["approver", "admin"])
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
        self.assertEqual(self.fake.seen, [])


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
        state = json.loads((self.dir / "state.json").read_text())
        again = AssessmentService(self.dir, LAB_PORT, l2_profile_dirs=PROFILE_DIRS)
        self.assertEqual(again._verified_external_hosts[HOST]["verified_addresses"], [PUBLIC_1])
        again.workers.kill_all()
        state["verified_external_hosts"][HOST]["verified_addresses"] = [PUBLIC_1, "151.101.1.69"]
        (self.dir / "state.json").write_text(json.dumps(state))
        forged = AssessmentService(self.dir, LAB_PORT, l2_profile_dirs=PROFILE_DIRS)
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
