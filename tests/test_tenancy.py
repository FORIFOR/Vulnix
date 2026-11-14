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
        denied = [e for e in self.reg.platform_audit.entries() if e["event"] == "tenancy.access_denied"]
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


class TestReviewFixes(unittest.TestCase):
    """Independent review of the tenancy branch (store level)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = [1000.0]
        self.st = OrgStore(Path(self.tmp.name) / "orgs.json", clock=lambda: self.now[0])
        self.oid = self.st.create_org("A社", "alice")
        _, t = self.st.create_invite(self.oid, "alice", ["admin"])
        self.st.accept_invite(t, "adam")

    def test_nobody_adds_roles_to_themselves(self):
        with self.assertRaises(TenancyError):
            self.st.set_roles(self.oid, "adam", "adam", ["admin", "approver"])
        self.st.set_roles(self.oid, "adam", "adam", ["runner"])          # lowering one's own roles is fine
        self.assertEqual(self.st.roles_in(self.oid, "adam"), ("runner",))

    def test_active_invites_per_org_are_capped_and_expired_ones_purged(self):
        from aegis.tenancy import MAX_ACTIVE_INVITES
        for _ in range(MAX_ACTIVE_INVITES):
            self.st.create_invite(self.oid, "alice", ["viewer"], ttl_s=600)
        with self.assertRaises(TenancyError):
            self.st.create_invite(self.oid, "alice", ["viewer"])
        self.now[0] += 601                                               # all expired: purged on the next create
        self.st.create_invite(self.oid, "alice", ["viewer"])
        self.assertEqual(len(self.st.invites(self.oid)), 1)

    def test_total_orgs_are_capped(self):
        st = OrgStore(Path(self.tmp.name) / "o2.json", max_orgs=3)
        st.create_org("a", "u1")
        st.create_org("b", "u2")                                         # + the default org = 3
        with self.assertRaises(TenancyError):
            st.create_org("c", "u3")

    def test_a_failed_save_changes_nothing(self):
        _, token = self.st.create_invite(self.oid, "alice", ["viewer"])
        with patch.object(OrgStore, "_save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.st.accept_invite(token, "bob")
        self.assertEqual(self.st.roles_in(self.oid, "bob"), ())
        self.assertEqual(self.st.accept_invite(token, "bob")[0], self.oid)   # still usable after the failure

    def test_an_invite_can_be_checked_without_using_it(self):
        _, token = self.st.create_invite(self.oid, "alice", ["viewer"])
        self.assertTrue(self.st.invite_valid(token))
        self.assertFalse(self.st.invite_valid("inv_nope"))
        self.st.accept_invite(token, "bob")
        self.assertFalse(self.st.invite_valid(token))


class TestReviewFixesOverHttp(TestTenantIsolationOverHttp):
    """Independent review of the tenancy branch (server level)."""

    def test_a_removed_member_loses_the_event_stream(self):
        import http.client
        a, b = self.signup("alice"), self.signup("bobby")
        token = self.req(a, "/orgs/invites", {"roles": ["viewer"]})[1]["token"]
        a_org = self.req(b, "/invites/accept", {"token": token})[1]["org"]["id"]
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=30)
        conn.request("GET", "/api/assessments/scan_001/events", headers={"Cookie": b["cookie"], "X-Vulnix-Org": a_org})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertEqual(self.req(a, "/orgs/members/remove", {"name": "bobby"})[0], 200)
        import time as _t
        start = _t.time()
        data = resp.read()                      # returns when the server ends the stream
        self.assertLess(_t.time() - start, 25)
        conn.close()
        self.assertNotIn(b"bobby", data.split(b"tenancy.member_removed")[-1] if b"tenancy.member_removed" in data else b"")

    def test_the_shared_lab_mode_is_platform_admin_only(self):
        a = self.signup("alice")                                   # owner of her own org
        self.assertEqual(self.req(a, "/assessments/scan_001/lab-mode", {"mode": "patched"})[0], 403)
        p = self.login("padmin", "padmin-pw-1")
        self.assertNotEqual(self.req(p, "/assessments/scan_001/lab-mode", {"mode": "vulnerable"})[0], 403)

    def test_system_status_is_the_callers_own_org(self):
        p = self.login("padmin", "padmin-pw-1")
        self.svc._authority_notice = {"text": "legacy-secret-host.example の診断許可の期限が切れました"} \
            if hasattr(self.svc, "_authority_notice") else None
        a = self.signup("alice")
        st = json.dumps(self.req(a, "/system/status")[1], ensure_ascii=False)
        self.assertNotIn("legacy-secret-host", st)
        self.assertEqual(self.req(p, "/system/status")[0], 200)

    def test_account_events_go_to_the_platform_audit_not_the_default_org(self):
        self.signup("alice")
        default_events = {e["event"] for e in self.svc.audit.entries()}
        self.assertNotIn("auth.registered", default_events)
        self.assertIn("auth.registered", {e["event"] for e in self.reg.platform_audit.entries()})

    def test_signup_with_a_bad_invite_creates_nothing(self):
        code, body = self.req({}, "/auth/register", {"name": "mallory", "password": "mallory-Passw0rd!", "invite": "inv_bogus"})
        self.assertEqual(code, 400)
        self.assertEqual(self.req({}, "/auth/login", {"name": "mallory", "password": "mallory-Passw0rd!"})[0], 401)

    def test_public_signups_are_rate_limited(self):
        from aegis import server as srvmod
        with patch.object(srvmod, "SIGNUPS_PER_MINUTE", 2):
            self.signup("user01")
            self.signup("user02")
            code, body = self.req({}, "/auth/register", {"name": "user03", "password": "user03-Passw0rd!"})
        self.assertEqual(code, 429)

    def test_chat_is_rate_limited_per_org(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "CHAT_PER_ORG_PER_HOUR", 1):
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "なぜ？"})[0], 200)
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "なぜ？"})[0], 429)

    def test_event_streams_per_account_are_capped(self):
        import http.client
        from aegis import server as srvmod
        a = self.signup("alice")
        conns = []
        with patch.object(srvmod, "SSE_PER_ACCOUNT", 2):
            codes = []
            for _ in range(3):
                c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=10)
                c.request("GET", "/api/assessments/scan_001/events", headers={"Cookie": a["cookie"]})
                r = c.getresponse()
                codes.append(r.status)
                conns.append((c, r))
        for c, _ in conns:
            c.close()
        self.assertEqual(codes, [200, 200, 429])


class TestSecondReviewFixes(TestTenantIsolationOverHttp):
    """Second independent review: what the first round of fixes left open."""

    def test_other_orgs_never_switch_the_shared_lab(self):
        from unittest.mock import MagicMock
        import aegis.assessment as am
        a = self.signup("alice")
        sw = MagicMock()
        with patch.object(am, "set_lab_mode", sw):
            for path in ("/assessments/scan_001/restart", "/assessments/scan_001/verify-fix"):
                self.req(a, path, {})
            self.req(a, "/assessments/scan_001/emergency-stop", {})
            self.req(a, "/assessments/scan_001/start", {})
            self.req(a, "/assessments/scan_001/emergency-stop", {})
        sw.assert_not_called()

    def test_accepting_your_own_invite_is_refused(self):
        a = self.signup("alice")
        token = self.req(a, "/orgs/invites", {"roles": ["approver"]})[1]["token"]
        self.assertEqual(self.req(a, "/invites/accept", {"token": token})[0], 403)
        self.assertEqual(a["orgs"][0]["roles"], ["owner"])
        self.assertEqual(self.reg.store.roles_in(a["orgs"][0]["id"], "alice"), ("owner",))

    def test_failed_signup_attempts_do_not_use_up_the_limit(self):
        from aegis import server as srvmod
        with patch.object(srvmod, "SIGNUPS_PER_MINUTE", 1):
            for _ in range(5):
                self.assertEqual(self.req({}, "/auth/register", {"name": "x", "password": "short"})[0], 400)
            self.signup("realuser")

    def test_signup_is_refused_before_the_account_exists_when_orgs_are_full(self):
        self.reg.store._max_orgs = len(self.reg.store._data["orgs"])
        code, _ = self.req({}, "/auth/register", {"name": "late", "password": "late-Passw0rd!"})
        self.assertEqual(code, 503)
        self.assertEqual(self.req({}, "/auth/login", {"name": "late", "password": "late-Passw0rd!"})[0], 401)

    def test_platform_wide_ai_cap(self):
        from aegis import server as srvmod
        a, b = self.signup("alice"), self.signup("bobby")
        with patch.object(srvmod, "CHAT_PLATFORM_PER_HOUR", 1):
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "なぜ？"})[0], 200)
            self.assertEqual(self.req(b, "/assessments/scan_001/chat", {"question": "なぜ？"})[0], 429)

    def test_platform_wide_stream_cap(self):
        import http.client
        from aegis import server as srvmod
        a, b = self.signup("alice"), self.signup("bobby")
        held = []
        with patch.object(srvmod, "SSE_PLATFORM", 1):
            codes = []
            for who in (a, b):
                c = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=10)
                c.request("GET", "/api/assessments/scan_001/events", headers={"Cookie": who["cookie"]})
                r = c.getresponse()
                codes.append(r.status)
                held.append((c, r))
        for c, _ in held:
            c.close()
        self.assertEqual(codes, [200, 429])


class TestThirdReviewFixes(TestTenantIsolationOverHttp):
    """Third independent review."""

    def test_the_real_model_plan_cap_sees_the_mode_the_service_will_use(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "ARTEX_LLM_PLANS_PER_ORG_PER_HOUR", 0):
            appr = {"llm_approval": {"preview_id": "pv_x", "max_calls": 1, "first_request_sha256": "0" * 64}}
            for body in ({"llm_mode": " gateway-forward", **appr}, {"llm_mode": "GATEWAY-FORWARD ", **appr}):
                self.assertEqual(self.req(a, "/assessments/scan_001/artex/plan", body)[0], 429, body)
            with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_MODE": "gateway-forward"}):
                self.assertEqual(self.req(a, "/assessments/scan_001/artex/plan", appr)[0], 429)

    def test_parallel_signups_cannot_exceed_the_limit(self):
        from aegis import server as srvmod
        import concurrent.futures as cf
        with patch.object(srvmod, "SIGNUPS_PER_MINUTE", 3):
            with cf.ThreadPoolExecutor(10) as ex:
                codes = list(ex.map(lambda i: self.req({}, "/auth/register", {"name": f"burst{i:02d}", "password": f"burst{i:02d}-Passw0rd!"})[0], range(10)))
        self.assertEqual(codes.count(200), 3, codes)
        self.assertTrue(all(c in (200, 429) for c in codes), codes)

    def test_signup_attempts_are_capped_too(self):
        from aegis import server as srvmod
        with patch.object(srvmod, "SIGNUP_ATTEMPTS_PER_MINUTE", 3):
            codes = [self.req({}, "/auth/register", {"name": "padmin", "password": "x-Passw0rd!xx"})[0] for _ in range(5)]
        self.assertEqual(codes[:3], [400, 400, 400])                 # existing name: each costs a hash
        self.assertEqual(codes[3:], [429, 429])

    def test_a_platform_refusal_does_not_use_the_orgs_ai_quota(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "CHAT_PLATFORM_PER_HOUR", 0), patch.object(srvmod, "CHAT_PER_ORG_PER_HOUR", 1):
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "x"})[0], 429)
        with patch.object(srvmod, "CHAT_PER_ORG_PER_HOUR", 1):
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "x"})[0], 200)

    def test_the_default_orgs_fix_check_puts_the_shared_lab_back(self):
        import aegis.assessment as am
        from aegis.lab import get_lab_mode, set_lab_mode
        set_lab_mode("vulnerable")
        self.assertTrue(getattr(self.svc, "_restore_lab_after_fix", False))

        def body(actor):                 # stands in for the real check: it switches the lab
            am.set_lab_mode("patched")
            return {"defense_comparison": {"lab_mode": get_lab_mode()}}
        with patch.object(self.svc, "_verify_fix_body", side_effect=body):
            out = self.svc._verify_fix("padmin")
        self.assertEqual(out["defense_comparison"]["lab_mode"], "patched")   # recorded during the check
        self.assertEqual(get_lab_mode(), "vulnerable")                       # shared lab put back


class TestFourthReviewLows(TestTenantIsolationOverHttp):
    def test_a_forward_plan_without_an_approval_uses_no_quota(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "ARTEX_LLM_PLANS_PER_ORG_PER_HOUR", 1):
            for _ in range(3):        # refused by the service (no approval): never 429
                self.assertNotEqual(self.req(a, "/assessments/scan_001/artex/plan", {"llm_mode": "gateway-forward"})[0], 429)

    def test_the_report_shows_the_lab_state_the_fix_check_used(self):
        self.svc.a.defense_comparison = {"lab_mode": "patched", "items": [], "before_score": 1, "after_score": 0}
        from aegis.lab import set_lab_mode
        set_lab_mode("vulnerable")
        self.assertIn("ラボ防御状態: `patched`", self.svc.report_markdown())


class TestPublicDeploymentSwitches(TestTenantIsolationOverHttp):
    """Switches for the public beta: no traffic to real sites, bounded AI spending."""

    def test_real_site_traffic_is_refused_when_switched_off(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "REAL_SERVICE_DIAGNOSIS", False):
            code, body = self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
            self.assertEqual(code, 200)                                   # registering and the proof value: allowed
            code, body = self.req(a, "/assets/verify-ownership", {"host": "shop.example.com", "method": "dns_txt"})
            self.assertEqual(code, 403)
            self.assertIn("実サイト", body["error"])
            # the lab still works
            self.assertEqual(self.add_site(a, "alice-shop.lab.test")[0], 200)

    def test_a_daily_ai_cap(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "CHAT_PLATFORM_PER_DAY", 1):
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "x"})[0], 200)
            self.assertEqual(self.req(a, "/assessments/scan_001/chat", {"question": "x"})[0], 429)

    def test_limits_come_from_the_environment(self):
        import importlib
        from aegis import server as srvmod
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_PLANS_PER_HOUR": "0", "VULNIX_CHAT_PER_DAY": "7",
                                     "VULNIX_REAL_SERVICE_DIAGNOSIS": "0"}):
            m = importlib.reload(srvmod)
            self.assertEqual((m.ARTEX_LLM_PLANS_PLATFORM_PER_HOUR, m.CHAT_PLATFORM_PER_DAY, m.REAL_SERVICE_DIAGNOSIS), (0, 7, False))
        importlib.reload(srvmod)

    def test_all_artex_plans_are_capped_per_org(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "ARTEX_PLANS_PER_ORG_PER_HOUR", 1):
            first = self.req(a, "/assessments/scan_001/artex/plan", {"llm_mode": "gateway-preview"})[0]
            self.assertNotEqual(first, 429)
            self.assertEqual(self.req(a, "/assessments/scan_001/artex/plan", {"llm_mode": "gateway-preview"})[0], 429)


class TestRunHistory(unittest.TestCase):
    """Real diagnosis history: every completed run is recorded, survives a restart and
    belongs to its organization only (each org has its own service and state file)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(Path(self.tmp.name), LAB_PORT, verify_seconds=30)
        self.addCleanup(self.svc.close)

    def complete(self):
        with self.svc._lock:
            self.svc.a.state = "running"
            self.svc._set_state("completed")

    def test_a_completed_run_is_recorded_and_kept(self):
        self.assertEqual(self.svc.snapshot()["run_history"], [])
        self.complete()
        self.complete()
        hist = self.svc.snapshot()["run_history"]
        self.assertEqual(len(hist), 2)
        for k in ("at", "asset", "score", "label", "counts"):
            self.assertIn(k, hist[0])
        self.assertGreaterEqual(hist[0]["at"], hist[1]["at"])                # newest first
        self.svc.close()
        with patch.dict(os.environ, {}, clear=True):
            again = AssessmentService(Path(self.tmp.name), LAB_PORT, verify_seconds=30)
        self.addCleanup(again.close)
        self.assertEqual(len(again.snapshot()["run_history"]), 2)

    def test_history_is_bounded(self):
        from aegis.assessment import MAX_RUN_HISTORY
        for _ in range(MAX_RUN_HISTORY + 5):
            self.complete()
        self.assertEqual(len(self.svc.snapshot()["run_history"]), MAX_RUN_HISTORY)



class TestFifthReviewFixes(TestTenantIsolationOverHttp):
    def test_switching_to_a_real_site_is_refused_and_the_switch_is_visible(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "REAL_SERVICE_DIAGNOSIS", False):
            self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
            real = next(x for x in self.req(a, "/assets")[1] if x.get("name") == "shop.example.com")
            self.assertEqual(self.req(a, "/assets/select", {"id": real["id"]})[0], 403)
            me = self.req(a, "/auth/me")[1]
            self.assertIs(me["real_service_diagnosis"], False)
            self.assertIs(me["development"], False)
