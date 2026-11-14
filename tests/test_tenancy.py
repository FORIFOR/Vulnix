"""Organizations (tenancy): one AssessmentService per organization, membership roles,
invitations, and that one account can never read or act on another organization."""
import tests  # noqa: F401  (hermetic revocation-marker directory)
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.operators import OperatorStore, hash_password
from aegis.server import make_handler
from aegis.tenancy import (DEFAULT_ORG, MAX_ORGS_PER_ACCOUNT, OrgStore, TenancyError, TenantRegistry,
                           default_members_from, service_roles)

LAB_PORT = 18097


class TestOrgStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = [1000.0]
        self.st = OrgStore(Path(self.tmp.name) / "orgs.json", clock=lambda: self.now[0])

    def test_creator_is_the_only_owner_and_roles_map_to_service_roles(self):
        oid = self.st.create_org("A社", "alice")
        self.assertEqual(self.st.roles_in(oid, "alice"), ("owner",))
        self.assertEqual(service_roles(["owner"]), ("admin", "operator", "approver"))
        self.assertEqual(service_roles(["viewer"]), ())
        self.assertEqual(self.st.roles_in(oid, "bob"), ())

    def test_the_file_survives_a_reload_and_holds_no_invite_token(self):
        oid = self.st.create_org("A社", "alice")
        _, token = self.st.create_invite(oid, "alice", ["viewer"])
        again = OrgStore(Path(self.tmp.name) / "orgs.json")
        self.assertEqual(again.roles_in(oid, "alice"), ("owner",))
        raw = (Path(self.tmp.name) / "orgs.json").read_text()
        self.assertNotIn(token, raw)
        self.assertEqual(oct(os.stat(Path(self.tmp.name) / "orgs.json").st_mode & 0o777), "0o600")

    def test_invites_are_single_use_and_expire(self):
        oid = self.st.create_org("A社", "alice")
        _, token = self.st.create_invite(oid, "alice", ["runner"], ttl_s=3600)
        self.assertEqual(self.st.accept_invite(token, "bob"), (oid, ["runner"]))
        self.assertEqual(self.st.roles_in(oid, "bob"), ("runner",))
        with self.assertRaises(TenancyError):
            self.st.accept_invite(token, "carol")          # used
        _, token2 = self.st.create_invite(oid, "alice", ["viewer"], ttl_s=3600)
        self.now[0] += 3601
        with self.assertRaises(TenancyError):
            self.st.accept_invite(token2, "carol")         # expired
        self.assertEqual(self.st.roles_in(oid, "carol"), ())
        with self.assertRaises(TenancyError):
            self.st.accept_invite("inv_guess", "carol")

    def test_only_managers_invite_and_only_owners_grant_owner(self):
        oid = self.st.create_org("A社", "alice")
        _, t = self.st.create_invite(oid, "alice", ["admin"])
        self.st.accept_invite(t, "adam")
        _, t = self.st.create_invite(oid, "alice", ["runner"])
        self.st.accept_invite(t, "rita")
        with self.assertRaises(TenancyError):
            self.st.create_invite(oid, "rita", ["viewer"])            # runner cannot invite
        with self.assertRaises(TenancyError):
            self.st.create_invite(oid, "adam", ["owner"])             # admin cannot mint owners
        with self.assertRaises(TenancyError):
            self.st.set_roles(oid, "adam", "rita", ["owner"])
        with self.assertRaises(TenancyError):
            self.st.set_roles(oid, "adam", "alice", ["viewer"])       # admin cannot demote an owner
        self.st.set_roles(oid, "adam", "rita", ["approver"])
        self.assertEqual(self.st.roles_in(oid, "rita"), ("approver",))
        with self.assertRaises(TenancyError):
            self.st.set_roles(oid, "alice", "rita", ["superuser"])

    def test_the_last_owner_stays(self):
        oid = self.st.create_org("A社", "alice")
        with self.assertRaises(TenancyError):
            self.st.set_roles(oid, "alice", "alice", ["admin"])
        with self.assertRaises(TenancyError):
            self.st.remove_member(oid, "alice", "alice")

    def test_organizations_per_account_are_capped(self):
        for i in range(MAX_ORGS_PER_ACCOUNT):
            self.st.create_org(f"org{i}", "alice")
        with self.assertRaises(TenancyError):
            self.st.create_org("one more", "alice")

    def test_pre_tenancy_accounts_join_the_default_org(self):
        d = Path(self.tmp.name)
        seed = d / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "boss", "roles": ["operator", "approver", "admin"], "password_hash": hash_password("x")},
            {"name": "op", "roles": ["operator"], "password_hash": hash_password("x")}]}))
        ops = OperatorStore(seed)
        st = OrgStore(d / "orgs2.json", bootstrap_members=lambda: default_members_from(ops))
        self.assertEqual(st.roles_in(DEFAULT_ORG, "boss"), ("owner", "runner", "approver"))
        self.assertEqual(st.roles_in(DEFAULT_ORG, "op"), ("runner",))


class TestTenantIsolationOverHttp(unittest.TestCase):
    """Two people sign up publicly; neither can see or touch the other's data."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        seed = d / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "padmin", "roles": ["operator", "approver", "admin"], "password_hash": hash_password("padmin-pw-1")}]}))
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(d, LAB_PORT, verify_seconds=30)
        self.ops = OperatorStore(seed)
        store = OrgStore(d / "orgs.json", bootstrap_members=lambda: default_members_from(self.ops))

        def factory(path):
            with patch.dict(os.environ, {}, clear=True):
                return AssessmentService(path, LAB_PORT, verify_seconds=30)
        self.reg = TenantRegistry(store, self.svc, factory, d)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops, tenancy=self.reg,
                                                                      public_signup=True))
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.root = f"http://127.0.0.1:{self.srv.server_port}/api"
        self.addCleanup(self._down)

    def _down(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.reg.close_all()
        self.svc.close()
        self.tmp.cleanup()

    def req(self, who, path, body=None, org=None):
        h = {"Content-Type": "application/json"}
        if body is not None:
            h["X-Aegis-Request"] = "1"
        if who and who.get("cookie"):
            h["Cookie"] = who["cookie"]
        if org:
            h["X-Vulnix-Org"] = org
        r = urllib.request.Request(self.root + path, json.dumps(body).encode() if body is not None else None, h)
        try:
            with urllib.request.urlopen(r) as resp:
                sc = resp.headers.get("Set-Cookie")
                if sc and who is not None:
                    who["cookie"] = sc.split(";")[0]
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def signup(self, name, **extra):
        who = {}
        code, body = self.req(who, "/auth/register", {"name": name, "password": f"{name}-Passw0rd!", **extra})
        self.assertEqual(code, 200, body)
        who["orgs"] = body["orgs"]
        return who

    def login(self, name, pw):
        who = {}
        self.assertEqual(self.req(who, "/auth/login", {"name": name, "password": pw})[0], 200)
        return who

    def add_site(self, who, name, org=None):
        return self.req(who, "/assets", {"name": name, "kind": "Webアプリケーション", "environment": "検証環境",
                                         "authorization_ref": "SOW-T", "ownership_verified": True}, org)

    def test_each_signup_gets_its_own_org_and_sees_only_its_own_data(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org, b_org = a["orgs"][0]["id"], b["orgs"][0]["id"]
        self.assertNotEqual(a_org, b_org)
        self.assertEqual(a["orgs"][0]["roles"], ["owner"])
        self.assertEqual(self.add_site(a, "alice-site.lab.test")[0], 200)
        names = lambda who, org=None: {x["name"] for x in self.req(who, "/assets", org=org)[1]}
        self.assertIn("alice-site.lab.test", names(a))
        self.assertNotIn("alice-site.lab.test", names(b))
        # the pre-existing workspace (default org) is invisible to both
        self.assertEqual(self.req(a, "/assets", org="default")[0], 403)
        # naming the other organization is refused, for reads and writes, and audited
        for path, body in (("/assets", None), ("/assessments/scan_001", None), ("/assessments/scan_001/logs", None),
                           ("/assessments/scan_001/events", None),
                           ("/assets", {"name": "x.lab.test", "authorization_ref": "S", "ownership_verified": True}),
                           ("/assessments/scan_001/start", {}), ("/assessments/scan_001/emergency-stop", {}),
                           ("/orgs/members", None)):
            self.assertEqual(self.req(b, path, body, org=a_org)[0], 403, path)
        self.assertEqual(self.req(b, "/assets", org="org_000000000000")[0], 403)
        self.assertEqual(self.req(b, "/assets", org="../../etc")[0], 403)
        denied = [e for e in self.svc.audit.entries() if e["event"] == "tenancy.access_denied"]
        who = [(e["fields"].get("actor"), e["fields"].get("org")) for e in denied]
        self.assertIn(("alice", "default"), who)
        self.assertGreaterEqual(sum(1 for actor, org in who if actor == "bobby"), 9)
        # separate audit logs: alice's org records her actions, bob's does not
        a_logs = json.dumps(self.req(a, "/assessments/scan_001/logs")[1], ensure_ascii=False)
        b_logs = json.dumps(self.req(b, "/assessments/scan_001/logs")[1], ensure_ascii=False)
        self.assertIn("alice-site.lab.test", a_logs)
        self.assertNotIn("alice-site.lab.test", b_logs)

    def test_the_ui_cookie_selects_the_org_and_is_still_membership_checked(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        self.add_site(a, "alice-site.lab.test")
        a2 = {"cookie": a["cookie"] + f"; vulnix_org={a_org}"}
        self.assertIn("alice-site.lab.test", {x["name"] for x in self.req(a2, "/assets")[1]})
        b2 = {"cookie": b["cookie"] + f"; vulnix_org={a_org}"}
        self.assertEqual(self.req(b2, "/assets")[0], 403)

    def test_ownership_challenges_differ_per_org(self):
        a, b = self.signup("alice"), self.signup("bobby")
        url = {"url": "https://shop.example.com/"}
        ca = self.req(a, "/assets/challenge", url)[1]["challenge"]["dns_txt_value"]
        cb = self.req(b, "/assets/challenge", url)[1]["challenge"]["dns_txt_value"]
        self.assertNotEqual(ca, cb)           # one org's proof can never satisfy another's

    def test_invite_roles_viewer_read_only_and_promotion(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        self.add_site(a, "alice-site.lab.test")
        code, inv = self.req(a, "/orgs/invites", {"roles": ["viewer"]})
        self.assertEqual(code, 200)
        self.assertTrue(inv["token"].startswith("inv_"))
        self.assertNotIn("token", json.dumps(self.req(a, "/orgs/invites")[1]))   # listed without the token
        self.assertEqual(self.req(b, "/invites/accept", {"token": inv["token"]})[0], 200)
        # bob now reads alice's org...
        self.assertIn("alice-site.lab.test", {x["name"] for x in self.req(b, "/assets", org=a_org)[1]})
        # ...but as a viewer cannot change anything, except stopping
        self.assertEqual(self.add_site(b, "bob-in-a.lab.test", org=a_org)[0], 403)
        self.assertEqual(self.req(b, "/assessments/scan_001/start", {}, org=a_org)[0], 403)
        self.assertEqual(self.req(b, "/assessments/scan_001/chat", {"question": "x"}, org=a_org)[0], 403)
        self.assertNotEqual(self.req(b, "/assessments/scan_001/emergency-stop", {}, org=a_org)[0], 403)
        self.assertEqual(self.req(b, "/orgs/invites", {"roles": ["viewer"]}, org=a_org)[0], 403)
        self.assertEqual(self.req(b, "/orgs/members/roles", {"name": "bobby", "roles": ["owner"]}, org=a_org)[0], 403)
        # alice promotes bob to runner: now he may register sites in her org
        self.assertEqual(self.req(a, "/orgs/members/roles", {"name": "bobby", "roles": ["runner"]})[0], 200)
        self.assertEqual(self.add_site(b, "bob-in-a.lab.test", org=a_org)[0], 200)
        # a runner cannot approve L2: the service sees no approver role
        self.assertEqual(self.req(b, "/assets/confirm-scope", {"host": "x"}, org=a_org)[0], 403)
        # removal ends access
        self.assertEqual(self.req(a, "/orgs/members/remove", {"name": "bobby"})[0], 200)
        self.assertEqual(self.req(b, "/assets", org=a_org)[0], 403)

    def test_signup_with_an_invite_joins_that_org_only(self):
        a = self.signup("alice")
        token = self.req(a, "/orgs/invites", {"roles": ["approver"]})[1]["token"]
        c = self.signup("carol", invite=token)
        self.assertEqual([(o["id"], o["roles"]) for o in c["orgs"]], [(a["orgs"][0]["id"], ["approver"])])

    def test_platform_functions_keep_global_roles(self):
        a = self.signup("alice")              # owner of her org, but no platform role
        self.assertEqual(self.req(a, "/operators")[0], 403)
        self.assertEqual(self.req(a, "/l2-profiles")[0], 403)
        self.assertEqual(self.req(a, "/system/verify-controls", {})[0], 403)
        self.assertEqual(self.req(a, "/operators/roles", {"name": "alice", "roles": ["admin"]})[0], 403)
        p = self.login("padmin", "padmin-pw-1")
        self.assertEqual(self.req(p, "/operators")[0], 200)

    def test_pre_existing_accounts_keep_the_existing_workspace(self):
        p = self.login("padmin", "padmin-pw-1")
        self.assertEqual(self.add_site(p, "legacy.lab.test")[0], 200)
        self.assertIn("legacy.lab.test", {x["name"] for x in self.svc.assets()})   # the default service
        me = self.req(p, "/auth/me")[1]
        self.assertEqual(me["orgs"][0]["id"], DEFAULT_ORG)

    def test_an_account_without_an_org_is_told_so(self):
        a = self.signup("alice")
        oid = a["orgs"][0]["id"]
        # (an account whose only org removed it): simulate with a fresh store entry
        self.reg.store._data["orgs"][oid]["members"]["zed"] = ["viewer"]
        self.reg.store.remove_member(oid, "zed", "zed")
        self.ops.register("zed", "zed-Passw0rd!", _issue_session=False)
        z = self.login("zed", "zed-Passw0rd!")
        code, body = self.req(z, "/assets")
        self.assertEqual(code, 403)
        self.assertTrue(body.get("no_org"))
        self.assertEqual(self.req(z, "/orgs", {"name": "Z社"})[0], 200)
        self.assertEqual(self.req(z, "/assets")[0], 200)


if __name__ == "__main__":
    unittest.main()
