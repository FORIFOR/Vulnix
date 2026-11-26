"""Organizations (tenancy): one AssessmentService per organization, membership roles,
invitations, and that one account can never read or act on another organization."""
import tests  # noqa: F401  (hermetic revocation-marker directory)
import json
import http.client
import os
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.lab import start_lab
from aegis.local_defense import _canonical
from aegis.workers.local_defense import sha256
from aegis.operators import OperatorStore, hash_password, totp_code
from aegis.server import ControlPlaneHTTPServer, make_handler
from aegis.tenancy import (DEFAULT_ORG, MAX_ORGS_PER_ACCOUNT, OrgStore, TenancyError, TenantRegistry,
                           default_members_from, service_roles)
from tests.test_local_defense import synthetic_bundle

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
        self.srv = ControlPlaneHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops, tenancy=self.reg,
                                                                      public_signup=True,
                                                                      local_defense_python_root=Path(__file__).resolve().parents[1]))
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

    def test_intelligence_history_is_bound_to_the_authenticated_org(self):
        alice, bob = self.signup("historyalice"), self.signup("historybob")
        org = alice["orgs"][0]["id"]
        svc = self.reg.service(org)
        with svc._lock:
            svc._set_state("running")
            svc._set_state("completed")
        before = svc.a.asset["id"]
        code, view = self.req(alice, "/assets/intelligence", org=org)
        self.assertEqual(code, 200)
        self.assertEqual(len(view["runs"]), 1)
        self.assertEqual(view["runs"][0]["org_id"], org)
        self.assertEqual(self.req(bob, "/assets/intelligence", org=org)[0], 403)
        self.assertEqual(self.req(bob, "/assets/intelligence")[1]["runs"], [])
        self.assertEqual(svc.a.asset["id"], before)

    def test_project_label_is_org_scoped_and_grants_no_diagnosis_authority(self):
        alice, bob = self.signup("projectalice"), self.signup("projectbob")
        org = alice["orgs"][0]["id"]
        code, response = self.req(alice, "/assets/challenge", {"url": "https://project.lab.example/"}, org)
        self.assertEqual(code, 200)
        aid = response["asset"]["id"]
        path = "/assets/project"
        payload = {"id": aid, "project_label": "Synthetic STG"}
        self.assertEqual(self.req(bob, path, payload, org)[0], 403)
        self.assertNotEqual(self.req(bob, path, payload)[0], 200)
        self.assertNotEqual(self.req(alice, path, {**payload, "ownership_verified": True}, org)[0], 200)
        code, response = self.req(alice, path, payload, org)
        self.assertEqual(code, 200)
        grouped = next(a for a in response["assets"] if a["id"] == aid)
        self.assertEqual(grouped["project_label"], "Synthetic STG")
        self.assertFalse(grouped["ownership_verified"])
        self.assertFalse(grouped["scope_confirmed"])
        self.assertFalse(grouped["assessment_id"])
        self.assertNotEqual(self.req(alice, "/assets/select", {"id": aid}, org)[0], 200)

    def test_ownership_traffic_approval_is_bound_to_org_target_method_and_requester(self):
        runner, outsider = self.signup("proofrunner"), self.signup("proofoutsider")
        admin = self.login("padmin", "padmin-pw-1")
        _, invite = self.reg.store.create_invite(DEFAULT_ORG, "padmin", ["runner"])
        self.reg.store.accept_invite(invite, "proofrunner")
        url = "https://ownership.lab.example"
        request = {"url": url, "method": "dns_txt"}
        endpoint = "/assets/ownership-traffic"
        with patch.dict(os.environ, {"VULNIX_OWNERSHIP_TRAFFIC": "approved"}), \
                patch("aegis.server.REAL_SITE_L1_ONLY", False), \
                patch("aegis.server.REAL_SERVICE_DIAGNOSIS", False), \
                patch("aegis.assessment.verify_ownership_challenge", return_value={
                    "verified": True, "method": "dns_txt", "verified_at": time.time(), "detail": "fixture",
                }) as check:
            self.assertEqual(self.req(runner, "/assets/challenge", {"url": url}, DEFAULT_ORG)[0], 200)
            self.assertEqual(self.req(runner, "/assets/verify-ownership", request, DEFAULT_ORG)[0], 403)
            code, pending = self.req(runner, endpoint, {**request, "action": "request"}, DEFAULT_ORG)
            self.assertEqual((code, pending.get("status")), (200, "pending"))
            approve = {**request, "action": "approve", "id": pending["id"]}
            self.assertEqual(self.req(outsider, endpoint, approve, DEFAULT_ORG)[0], 403)
            self.assertEqual(self.req(runner, endpoint, approve, DEFAULT_ORG)[0], 403)
            reject = {**approve, "action": "reject"}
            self.assertEqual(self.req(admin, endpoint, reject, DEFAULT_ORG)[1]["status"], "rejected")
            self.assertEqual(self.req(runner, "/assets/verify-ownership", request, DEFAULT_ORG)[0], 403)
            code, pending = self.req(runner, endpoint, {**request, "action": "request"}, DEFAULT_ORG)
            self.assertEqual((code, pending.get("status")), (200, "pending"))
            approve["id"] = pending["id"]
            self.assertEqual(self.req(admin, endpoint, approve, DEFAULT_ORG)[1]["status"], "approved")
            self.assertEqual(self.req(admin, "/assets/verify-ownership", request, DEFAULT_ORG)[0], 403)
            self.assertEqual(self.req(runner, "/assets/verify-ownership", {**request, "method": "well_known"}, DEFAULT_ORG)[0], 403)
            self.assertEqual(self.req(runner, "/assets/verify-ownership", {**request, "url": url + ":8443"}, DEFAULT_ORG)[0], 409)
            check.assert_not_called()
            self.assertTrue(self.req(runner, "/assets/verify-ownership", request, DEFAULT_ORG)[1]["verified"])
            check.assert_called_once()
            self.assertIsNone(self.svc._external_entry("ownership.lab.example"))
            future = time.time() + 901
            with patch("aegis.server.time.time", return_value=future):
                self.assertEqual(self.req(admin, endpoint, {**request, "action": "status"}, DEFAULT_ORG)[1]["status"], "expired")
            self.svc.emergency_stop("padmin")
            self.assertEqual(self.req(admin, endpoint, {**request, "action": "status"}, DEFAULT_ORG)[1]["status"], "expired")
            self.assertEqual(self.req(runner, "/assets/verify-ownership", request, DEFAULT_ORG)[0], 403)
            check.assert_called_once()

    def test_cloud_inventory_binds_single_use_oauth_to_active_session_and_org(self):
        from urllib.parse import parse_qs, urlsplit
        from aegis import cloud_inventory

        alice = self.signup("cloudreader")
        bob = self.signup("cloudoutsider")
        alt = self.reg.store.create_org("Other Cloud Workspace", "cloudreader")
        org = alice["orgs"][0]["id"]
        path = "/assets/cloud-inventory"
        settings = {
            "VULNIX_CLOUD_CLIENT_ID": "synthetic",
            "VULNIX_CLOUD_CLIENT_SECRET": "fixture-only",
            "VULNIX_CLOUD_REDIRECT_URI": "https://vulnix.lab.test/verify/cloud",
        }
        projects = {"projects": [{"id": "lab-project", "number": "123", "label": "Lab"}], "incomplete": False}
        with patch.dict("os.environ", settings), patch.object(cloud_inventory, "fetch_projects", return_value=projects) as fetch:
            self.assertEqual(self.req(bob, path, {"action": "start"}, org)[0], 403)
            status, response = self.req(alice, path, {"action": "start"}, org)
            self.assertEqual(status, 200)
            query = parse_qs(urlsplit(response["url"]).query)
            self.assertEqual(query["scope"], [cloud_inventory.SCOPE])
            self.assertEqual(query["code_challenge_method"], ["S256"])
            finish = {"action": "finish", "code": "synthetic", "state": query["state"][0]}
            self.assertEqual(self.req(bob, path, finish, org)[0], 403)
            self.assertEqual(self.req(alice, path, finish, alt)[0], 400)
            other_session = self.login("cloudreader", "cloudreader-Passw0rd!")
            self.assertEqual(self.req(other_session, path, finish, org)[0], 400)
            fetch.assert_not_called()
            self.assertEqual(self.req(alice, path, finish, org)[0], 200)
            self.assertEqual(self.req(alice, path, finish, org)[0], 400)
            fetch.assert_called_once()
            self.assertEqual(self.req(alice, path, {"action": "projects"}, org)[1]["projects"], projects["projects"])
            self.assertNotIn("projects", self.req(other_session, path, {"action": "projects"}, org)[1])
            self.assertNotIn("projects", self.req(alice, path, {"action": "projects"}, alt)[1])
            self.assertEqual(self.req(alice, path, {"action": "clear"}, org)[0], 200)
            self.assertNotIn("projects", self.req(alice, path, {"action": "projects"}, org)[1])

    def test_reviewed_defense_bound_to_review_and_live_distinct_approver(self):
        owner = self.login("padmin", "padmin-pw-1")
        runner, outsider = self.signup("reviewrunner"), self.signup("reviewoutsider")
        _, invite = self.reg.store.create_invite(DEFAULT_ORG, "padmin", ["runner"])
        self.reg.store.accept_invite(invite, "reviewrunner")
        endpoint = "/assets/local-defense"
        self.assertEqual(self.req(outsider, endpoint, org=DEFAULT_ORG)[0], 403)
        self.assertEqual(self.req(outsider, endpoint, {"action": "start", "id": "req_a"}, DEFAULT_ORG)[0], 403)
        self.assertEqual(self.req(outsider, endpoint, org=outsider["orgs"][0]["id"])[0], 404)
        status, view = self.req(runner, endpoint, org=DEFAULT_ORG)
        self.assertEqual(status, 200, view)
        profile = view["profiles"][0]
        request = {"action": "request", "profile": profile["plan"]["id"],
                   "plan_sha256": profile["plan_sha256"], "folder_sha256": sha256(_canonical(profile["files"]))}
        self.assertEqual(self.req(runner, endpoint, {**request, "folder_sha256": "0" * 64}, DEFAULT_ORG)[0], 409)
        self.assertEqual(self.req(runner, endpoint, {**request, "path": "/tmp"}, DEFAULT_ORG)[0], 400)
        status, result = self.req(runner, endpoint, request, DEFAULT_ORG)
        self.assertEqual(status, 200, result)
        aid = result["job"]["id"]
        decide = f"/assessments/{view['assessment']}/approvals/{aid}"
        self.assertEqual(self.req(runner, decide, {"decision": "approve"}, DEFAULT_ORG)[0], 403)
        start = {"action": "start", "id": aid, "folder_sha256": request["folder_sha256"]}
        self.assertEqual(self.req(runner, endpoint, start, DEFAULT_ORG)[0], 409)
        approved = self.req(owner, decide, {"decision": "approve"}, DEFAULT_ORG)
        self.assertEqual(approved[0], 200, approved)
        self.assertEqual(self.req(runner, endpoint, {**start, "folder_sha256": "1" * 64}, DEFAULT_ORG)[0], 409)
        self.ops.logout(owner["cookie"].split("=", 1)[1])
        self.assertEqual(self.req(runner, endpoint, start, DEFAULT_ORG)[0], 409)
        self.svc.emergency_stop("padmin")
        self.assertEqual(self.req(runner, endpoint, request, DEFAULT_ORG)[0], 409)

    def test_portable_profiles_and_approvals_are_scoped_to_the_registered_organization(self):
        owner = self.login("padmin", "padmin-pw-1")
        outsider = self.signup("portfoliooutsider")
        org = self.reg.store.create_org("Review registry tenant", "padmin")
        parent = Path(self.tmp.name) / "review-fixtures"
        parent.mkdir(mode=0o700)
        digest = synthetic_bundle(parent / "reviewed", "python")
        registry = parent / "registry.json"
        registry.write_text(json.dumps([{"org": org, "bundle": "reviewed", "sha256": digest, "node": None}]))
        registry.chmod(0o600)
        handler = make_handler(self.svc, self.ops, tenancy=self.reg, local_defense_registry=registry)
        alternate = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=alternate.serve_forever, daemon=True).start()
        self.root = f"http://127.0.0.1:{alternate.server_port}/api"
        try:
            endpoint = "/assets/local-defense"
            self.assertEqual(self.req(outsider, endpoint, org=org)[0], 403)
            self.assertEqual(self.req(owner, endpoint, org=DEFAULT_ORG)[0], 404)
            status, view = self.req(owner, endpoint, org=org)
            self.assertEqual(status, 200, view)
            profile = view["profiles"][0]
            self.assertEqual(profile["plan"]["id"], "profile-synthetic-python")
            request = {"action": "request", "profile": profile["plan"]["id"], "plan_sha256": profile["plan_sha256"],
                       "folder_sha256": sha256(_canonical(profile["files"]))}
            status, job = self.req(owner, endpoint, request, org)
            self.assertEqual(status, 200, job)
            aid = job["job"]["id"]
            approval = f"/assessments/{view['assessment']}/approvals/{aid}"
            self.assertEqual(self.req(outsider, approval, {"decision": "approve"}, org)[0], 403)
            self.assertEqual(self.req(owner, approval, {"decision": "approve"}, DEFAULT_ORG)[0], 409)
            self.assertEqual(self.req(owner, approval, {"decision": "approve"}, org)[0], 403)
        finally:
            alternate.shutdown()
            alternate.server_close()

    def test_cloud_run_routes_are_scoped_to_member_and_admin(self):
        a, b = self.signup("cloudalice"), self.signup("cloudbob")
        a_org, b_org = a["orgs"][0]["id"], b["orgs"][0]["id"]
        host = "cloud.example.com"
        self.assertEqual(self.req(a, "/assets/challenge", {"url": f"https://{host}/"}, a_org)[0], 200)
        code, binding = self.req(a, "/assets/cloud-run/register", {"host": host, "subject": "sub-a"}, a_org)
        self.assertEqual(code, 200, binding)
        self.assertTrue(binding["configured"])
        issued_code, issued = self.req(a, "/assets/cloud-run/issue", {"host": host}, a_org)
        self.assertEqual(issued_code, 200, issued)
        for path, body in (("/assets/cloud-run/binding?host=" + host, None),
                           ("/assets/cloud-run/register", {"host": host, "subject": "sub-b"}),
                           ("/assets/cloud-run/issue", {"host": host}),
                           ("/assets/cloud-run/finish", {"host": host, "challenge": issued["challenge"],
                                                           "id_token": "fake"}),
                           ("/assets/cloud-run/revoke", {"host": host})):
            with self.subTest(path=path):
                self.assertEqual(self.req(b, path, body, a_org)[0], 403)
        self.assertEqual(self.req(b, "/assets/cloud-run/issue", {"host": host}, b_org)[0], 409)
        self.assertEqual(self.req(a, "/assets/cloud-run/binding?host=" + host, org=a_org)[1]["subject"], "sub-a")
        _, invite = self.reg.store.create_invite(a_org, "cloudalice", ["runner"])
        self.reg.store.accept_invite(invite, "cloudbob")
        self.assertEqual(self.req(b, "/assets/cloud-run/register",
                                  {"host": host, "subject": "sub-b"}, a_org)[0], 403)
        self.assertEqual(self.req(b, "/assets/cloud-run/revoke", {"host": host}, a_org)[0], 403)
        wrong_requester = self.req(b, "/assets/cloud-run/finish",
                                   {"host": host, "challenge": issued["challenge"], "id_token": "fake"}, a_org)
        self.assertEqual(wrong_requester[0], 200)
        self.assertFalse(wrong_requester[1]["verified"])
        binding_version = self.reg.service(a_org).cloud_run_store.binding(a_org, host)[1]
        self.assertIsNotNone(self.reg.service(a_org).cloud_run_store.consume(
            issued["challenge"], a_org, host, "cloudalice", binding_version, time.time()))
        self.assertEqual(self.req(a, "/assets/cloud-run/revoke", {"host": host}, a_org)[0], 200)
        self.assertFalse(self.req(a, "/assets/cloud-run/binding?host=" + host, org=a_org)[1]["configured"])

    def test_logout_after_org_binding_cannot_start_a_scan(self):
        who = self.signup("latebinding")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, started = threading.Event(), threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/assessments/scan_001/start":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("binding test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind), patch.object(svc, "start", side_effect=lambda *_a, **_k: started.set()):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/start", {}, org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertFalse(started.is_set())

    def test_logout_after_asset_selection_cannot_receive_snapshot(self):
        who = self.signup("lateselect")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_assets = svc.assets

        def delayed_assets():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("asset selection response did not release")
            return original_assets()

        with patch.object(svc, "assets", side_effect=delayed_assets):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assets/select", {"id": svc.a.asset["id"]}, org=org_id)))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("snapshot", response[0][1])

    def test_logout_after_asset_registration_cannot_receive_asset_list(self):
        who = self.signup("lateregisterasset")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_assets = svc.assets

        def delayed_assets():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("asset registration response did not release")
            return original_assets()

        with patch.object(svc, "register_asset", return_value={"id": "mock_asset"}), \
                patch.object(svc, "assets", side_effect=delayed_assets):
            thread = threading.Thread(target=lambda: response.append(self.req(
                who, "/assets", {"name": "lab.test", "authorization_ref": "lab-only"}, org=org_id)))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("assets", response[0][1])

    def test_logout_after_asset_secret_or_delete_commit_cannot_receive_snapshot(self):
        cases = (
            ("secrets", "configure_asset_secrets", {"configured": True}, {"host": "lab.test"}),
            ("delete", "delete_asset", [], {"id": "asset_001"}),
        )
        for suffix, method, result, body in cases:
            with self.subTest(suffix=suffix):
                who = self.signup(f"late{suffix}")
                org_id = who["orgs"][0]["id"]
                svc = self.reg.service(org_id)
                entered, release = threading.Event(), threading.Event()
                response = []
                original_snapshot = svc.snapshot

                def delayed_snapshot():
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("asset mutation response did not release")
                    return original_snapshot()

                with patch.object(svc, method, return_value=result), \
                        patch.object(svc, "snapshot", side_effect=delayed_snapshot):
                    thread = threading.Thread(target=lambda: response.append(
                        self.req(who, f"/assets/{suffix}", body, org=org_id)))
                    thread.start()
                    try:
                        self.assertTrue(entered.wait(5))
                        self.ops.logout(who["cookie"].split("=", 1)[1])
                    finally:
                        release.set()
                        thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(response[0][0], 401)
                self.assertNotIn("snapshot", response[0][1])

    def test_logout_during_diagnostic_post_cannot_receive_result(self):
        cases = (
            ("verify-finding", "verify_finding", {"finding_id": "f_mock"}),
            ("artex/plan", "plan_with_artex", {}),
            ("artex/items/mock/execute", "execute_artex_item", {}),
            ("verify-fix", "verify_fix", {}),
            ("chat", "ask_chat", {"question": "結果を説明してください"}),
        )
        for index, (suffix, method, body) in enumerate(cases):
            with self.subTest(suffix=suffix):
                who = self.signup(f"latepost{index}")
                org_id = who["orgs"][0]["id"]
                svc = self.reg.service(org_id)
                entered, release = threading.Event(), threading.Event()
                response = []

                def delayed_result(*args, **kwargs):
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("diagnostic response did not release")
                    return {"private_result": "must-not-be-returned"}

                with patch.object(svc, method, side_effect=delayed_result):
                    thread = threading.Thread(target=lambda: response.append(self.req(
                        who, f"/assessments/scan_001/{suffix}", body, org=org_id)))
                    thread.start()
                    try:
                        self.assertTrue(entered.wait(5))
                        self.ops.logout(who["cookie"].split("=", 1)[1])
                    finally:
                        release.set()
                        thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(response[0][0], 401)
                self.assertNotIn("private_result", response[0][1])

    def test_logout_during_diagnostic_error_hides_exception_detail(self):
        who = self.signup("lateerror")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []

        def delayed_error(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("diagnostic error test did not release")
            raise ValueError("PRIVATE_DIAGNOSTIC_ERROR_DETAIL")

        with patch.object(svc, "ask_chat", side_effect=delayed_error):
            thread = threading.Thread(target=lambda: response.append(self.req(
                who, "/assessments/scan_001/chat", {"question": "説明"}, org=org_id)))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("PRIVATE_DIAGNOSTIC_ERROR_DETAIL", response[0][1])

    def test_logout_during_platform_verification_hides_result(self):
        cases = (
            ("/router/verify", self.svc, "verify_planner_connections"),
            ("/l2-profiles/accept", self.svc, "accept_l2_profile"),
            ("/cve/sync", self.svc.cve_monitor, "ingest_payloads"),
            ("/system/verify-controls", "aegis.server.run_live_control_verification", None),
            ("/cve/real-software-verify", "aegis.server.run_real_software_cve_comparison", None),
        )
        for path, target, method in cases:
            with self.subTest(path=path):
                admin = self.login("padmin", "padmin-pw-1")
                entered, release = threading.Event(), threading.Event()
                response = []

                def delayed_report(*args, **kwargs):
                    entered.set()
                    if not release.wait(5):
                        raise TimeoutError("platform verification test did not release")
                    return {"private_platform_report": "must-not-be-returned", "all_passed": True,
                            "cve_count": 0, "kev_count": 0}

                patcher = (patch.object(target, method, side_effect=delayed_report) if method else
                           patch(target, side_effect=delayed_report))
                with patcher:
                    thread = threading.Thread(target=lambda: response.append(self.req(admin, path, {})))
                    thread.start()
                    try:
                        self.assertTrue(entered.wait(5))
                        self.ops.logout(admin["cookie"].split("=", 1)[1])
                    finally:
                        release.set()
                        thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(response[0][0], 401)
                self.assertNotIn("private_platform_report", response[0][1])

    def test_logout_during_platform_verification_error_returns_401(self):
        admin = self.login("padmin", "padmin-pw-1")
        entered, release = threading.Event(), threading.Event()
        response = []

        def delayed_error(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("platform error test did not release")
            raise RuntimeError("PRIVATE_PLATFORM_ERROR")

        with patch.object(self.svc, "verify_planner_connections", side_effect=delayed_error):
            thread = threading.Thread(target=lambda: response.append(self.req(admin, "/router/verify", {})))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(admin["cookie"].split("=", 1)[1])
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("PRIVATE_PLATFORM_ERROR", response[0][1])

    def test_logout_after_binding_invokes_stop_without_returning_protected_data(self):
        for suffix, method in (("pause", "pause"), ("emergency-stop", "emergency_stop")):
            with self.subTest(suffix=suffix):
                who = self.signup(f"late{method}")
                org_id = who["orgs"][0]["id"]
                svc = self.reg.service(org_id)
                entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
                response = []
                handler = self.srv.RequestHandlerClass
                original_bind = handler._bind
                path = f"/api/assessments/scan_001/{suffix}"

                def paused_bind(request, *args, **kwargs):
                    bound = original_bind(request, *args, **kwargs)
                    if bound and request.path == path:
                        entered.set()
                        if not release.wait(5):
                            raise TimeoutError("stop binding test did not release the request")
                    return bound

                def record_stop(*_):
                    stopped.set()
                    return {"target_url": "https://private.lab.test"} if method == "emergency_stop" else None

                with patch.object(handler, "_bind", paused_bind), \
                        patch.object(svc, method, side_effect=record_stop), \
                        patch.object(svc, "snapshot", return_value={"target_url": "https://private.lab.test"}):
                    thread = threading.Thread(target=lambda: response.append(
                        self.req(who, f"/assessments/scan_001/{suffix}", {}, org=org_id)))
                    thread.start()
                    self.assertTrue(entered.wait(5))
                    self.ops.logout(who["cookie"].split("=", 1)[1])
                    release.set()
                    thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertTrue(stopped.is_set(), "revocation must not prevent the stop handler")
                self.assertEqual(response[0][0], 401)
                self.assertNotIn("target_url", response[0][1])

    def test_membership_removal_after_binding_invokes_stop_without_returning_protected_data(self):
        owner, member = self.signup("stopowner"), self.signup("stopmember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "stopowner", ["runner"])
        self.reg.store.accept_invite(invite, "stopmember")
        svc = self.reg.service(org_id)
        for suffix, method in (("pause", "pause"), ("emergency-stop", "emergency_stop")):
            with self.subTest(suffix=suffix):
                entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
                response = []
                handler = self.srv.RequestHandlerClass
                original_bind = handler._bind
                path = f"/api/assessments/scan_001/{suffix}"

                def paused_bind(request, *args, **kwargs):
                    bound = original_bind(request, *args, **kwargs)
                    if bound and request.path == path:
                        entered.set()
                        if not release.wait(5):
                            raise TimeoutError("stop binding test did not release the request")
                    return bound

                def record_stop(*_):
                    stopped.set()
                    return {"target_url": "https://private.lab.test"} if method == "emergency_stop" else None

                with patch.object(handler, "_bind", paused_bind), \
                        patch.object(svc, method, side_effect=record_stop), \
                        patch.object(svc, "snapshot", return_value={"target_url": "https://private.lab.test"}):
                    thread = threading.Thread(target=lambda: response.append(
                        self.req(member, f"/assessments/scan_001/{suffix}", {}, org=org_id)))
                    thread.start()
                    self.assertTrue(entered.wait(5))
                    self.reg.store.remove_member(org_id, "stopowner", "stopmember")
                    release.set()
                    thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertTrue(stopped.is_set(), "revocation must not prevent the stop handler")
                self.assertEqual(response[0][0], 403)
                self.assertNotIn("target_url", response[0][1])
                if suffix == "pause":
                    _, invite = self.reg.store.create_invite(org_id, "stopowner", ["runner"])
                    self.reg.store.accept_invite(invite, "stopmember")

    def test_logout_after_org_binding_cannot_read_logs(self):
        who = self.signup("latereadlogout")
        org_id = who["orgs"][0]["id"]
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/assessments/scan_001/logs":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("GET binding test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/logs", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_logout_during_cve_status_generation_cannot_read_platform_status(self):
        who = self.signup("cvestatuslogout")
        entered, release = threading.Event(), threading.Event()
        response = []

        def delayed_status():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("CVE status test did not release generation")
            return {"cve_count": 12345}

        with patch.object(self.svc.cve_monitor, "status", side_effect=delayed_status):
            thread = threading.Thread(target=lambda: response.append(self.req(who, "/cve/status")))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("cve_count", response[0][1])

    def test_membership_removal_after_org_binding_cannot_read_report(self):
        owner, member = self.signup("reportowner"), self.signup("reportmember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "reportowner", ["runner"])
        self.reg.store.accept_invite(invite, "reportmember")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/assessments/scan_001/report":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("GET membership test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind):
            thread = threading.Thread(target=lambda: response.append(
                self.req(member, "/assessments/scan_001/report", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.reg.store.remove_member(org_id, "reportowner", "reportmember")
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 403)

    def test_approver_revocation_after_binding_cannot_read_planner_preview(self):
        owner, member = self.signup("previewowner"), self.signup("previewmember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "previewowner", ["approver"])
        self.reg.store.accept_invite(invite, "previewmember")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/assessments/scan_001/artex/llm-preview":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("preview role test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind):
            thread = threading.Thread(target=lambda: response.append(
                self.req(member, "/assessments/scan_001/artex/llm-preview", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.reg.store.set_roles(org_id, "previewowner", "previewmember", ["viewer"])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 403)

    def test_membership_removal_after_binding_cannot_read_system_status(self):
        owner, member = self.signup("statusowner"), self.signup("statusmember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "statusowner", ["viewer"])
        self.reg.store.accept_invite(invite, "statusmember")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/system/status":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("system status test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind):
            thread = threading.Thread(target=lambda: response.append(
                self.req(member, "/system/status", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.reg.store.remove_member(org_id, "statusowner", "statusmember")
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 403)

    def test_logout_before_platform_role_change_cannot_grant_approver(self):
        admin = self.login("padmin", "padmin-pw-1")
        target = self.signup("lateplatformrole")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_change = handler._set_roles

        def paused_change(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("role change test did not release the request")
            return original_change(request, *args, **kwargs)

        with patch.object(handler, "_set_roles", paused_change):
            thread = threading.Thread(target=lambda: response.append(
                self.req(admin, "/operators/roles",
                         {"name": "lateplatformrole", "roles": ["operator", "approver"]})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(admin["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("approver", self.ops.roles_of("lateplatformrole"))

    def test_logout_before_platform_account_creation_creates_nothing(self):
        admin = self.login("padmin", "padmin-pw-1")
        entered, release = threading.Event(), threading.Event()
        response = []
        original_create = self.ops.create_account

        def paused_create(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("account creation test did not release the request")
            return original_create(*args, **kwargs)

        with patch.object(self.ops, "create_account", side_effect=paused_create):
            thread = threading.Thread(target=lambda: response.append(self.req(
                admin, "/auth/register", {"name": "latecreated", "password": "latecreated-Passw0rd!"})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(admin["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertEqual(self.req({}, "/auth/login",
                                  {"name": "latecreated", "password": "latecreated-Passw0rd!"})[0], 401)

    def test_logout_before_platform_mfa_recovery_cannot_reset(self):
        admin = self.login("padmin", "padmin-pw-1")
        target = self.signup("laterecovery")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_recovery = handler._admin_recovery

        def paused_recovery(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("MFA recovery test did not release the request")
            return original_recovery(request, *args, **kwargs)

        with patch.object(handler, "_admin_recovery", paused_recovery):
            thread = threading.Thread(target=lambda: response.append(
                self.req(admin, "/operators/reset-mfa", {"name": "laterecovery"})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(admin["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertEqual(self.req(target, "/auth/me")[0], 200)

    def test_logout_before_org_creation_cannot_create_an_org(self):
        who = self.signup("lateorgcreate")
        before = len(self.reg.store.orgs_of("lateorgcreate"))
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_session = handler._session

        def paused_session(request):
            sess = original_session(request)
            if request.path == "/api/orgs":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("org creation test did not release the request")
            return sess

        with patch.object(handler, "_session", paused_session):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/orgs", {"name": "late org"})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertEqual(len(self.reg.store.orgs_of("lateorgcreate")), before)

    def test_logout_before_password_change_keeps_the_old_password(self):
        who = self.signup("latepassword")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_change = handler._change_password

        def paused_change(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("password test did not release the request")
            return original_change(request, *args, **kwargs)

        with patch.object(handler, "_change_password", paused_change):
            thread = threading.Thread(target=lambda: response.append(self.req(
                who, "/auth/password", {"current": "latepassword-Passw0rd!",
                                        "new": "latepassword-NewPassw0rd!"})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertEqual(self.req({}, "/auth/login",
                                  {"name": "latepassword", "password": "latepassword-Passw0rd!"})[0], 200)

    def test_logout_before_totp_enrollment_cannot_receive_a_secret(self):
        who = self.signup("latetotp")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_enroll = handler._totp_enroll

        def paused_enroll(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("TOTP test did not release the request")
            return original_enroll(request, *args, **kwargs)

        with patch.object(handler, "_totp_enroll", paused_enroll):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/auth/totp/enroll", {})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("secret", response[0][1])

    def test_logout_before_totp_confirmation_does_not_enable_mfa(self):
        who = self.signup("lateconfirm")
        secret, _ = self.ops.begin_totp_enroll("lateconfirm")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_confirm = handler._totp_confirm

        def paused_confirm(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("TOTP confirm test did not release")
            return original_confirm(request, *args, **kwargs)

        with patch.object(handler, "_totp_confirm", paused_confirm):
            thread = threading.Thread(target=lambda: response.append(self.req(
                who, "/auth/totp/confirm", {"code": totp_code(secret, time.time())})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertFalse(self.ops.totp_enabled("lateconfirm"))

    def test_logout_before_totp_disable_does_not_remove_mfa(self):
        who = self.signup("latedisable")
        secret, _ = self.ops.begin_totp_enroll("latedisable")
        self.ops.confirm_totp("latedisable", totp_code(secret, time.time()))
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_disable = handler._totp_disable

        def paused_disable(request, *args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("TOTP disable test did not release")
            return original_disable(request, *args, **kwargs)

        with patch.object(handler, "_totp_disable", paused_disable):
            thread = threading.Thread(target=lambda: response.append(self.req(
                who, "/auth/totp/disable", {"current": "latedisable-Passw0rd!",
                                             "code": totp_code(secret, time.time())})))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertTrue(self.ops.totp_enabled("latedisable"))

    def test_logout_before_org_list_cannot_read_membership(self):
        who = self.signup("lateorglist")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_session = handler._session

        def paused_session(request):
            sess = original_session(request)
            if request.path == "/api/orgs":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("org list test did not release")
            return sess

        with patch.object(handler, "_session", paused_session):
            thread = threading.Thread(target=lambda: response.append(self.req(who, "/orgs")))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_logout_before_admin_account_list_cannot_read_accounts(self):
        admin = self.login("padmin", "padmin-pw-1")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_session = handler._session

        def paused_session(request):
            sess = original_session(request)
            if request.path == "/api/operators":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("admin account list test did not release")
            return sess

        with patch.object(handler, "_session", paused_session):
            thread = threading.Thread(target=lambda: response.append(self.req(admin, "/operators")))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(admin["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_logout_before_session_probe_does_not_return_an_old_session(self):
        who = self.signup("lateprobe")
        entered, release = threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_session = handler._session

        def paused_session(request):
            sess = original_session(request)
            if request.path == "/api/auth/me":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("session probe test did not release")
            return sess

        with patch.object(handler, "_session", paused_session):
            thread = threading.Thread(target=lambda: response.append(self.req(who, "/auth/me")))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.ops.logout(who["cookie"].split("=", 1)[1])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 200)
        self.assertIsNone(response[0][1]["session"])

    def test_org_owner_can_read_planner_preview(self):
        owner = self.signup("previewowner")
        org_id = owner["orgs"][0]["id"]
        self.assertEqual(self.req(owner, "/assessments/scan_001/artex/llm-preview", org=org_id)[0], 200)

    def test_every_organization_shares_one_platform_advisor_cap(self):
        a, b = self.signup("capone"), self.signup("captwo")
        sa, sb = self.reg.service(a["orgs"][0]["id"]), self.reg.service(b["orgs"][0]["id"])
        self.assertIsNotNone(sa._platform_advisor_cap)
        self.assertEqual({str(x._platform_advisor_cap.path) for x in (sa, sb, self.reg.default_svc)},
                         {str(sa._platform_advisor_cap.path)})
        sa._platform_advisor_cap.reserve(5, cap_micro_usd=10)
        self.assertEqual(sb._platform_advisor_cap.spent(), 5)

    def test_report_generation_does_not_block_logout(self):
        who = self.signup("slowreport")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
        response = []
        original_report = svc.report_markdown

        def paused_report():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("report test did not release")
            return original_report()

        with patch.object(svc, "report_markdown", side_effect=paused_report):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/report", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            logout_thread = threading.Thread(target=lambda: (
                self.ops.logout(who["cookie"].split("=", 1)[1]), logged_out.set()))
            logout_thread.start()
            try:
                self.assertTrue(logged_out.wait(0.5), "report held the global account lock")
            finally:
                release.set()
                thread.join(5)
                logout_thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(logout_thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_a_slow_reader_does_not_hold_the_account_lock_while_its_response_is_written(self):
        # one tenant's slow client must not delay logins or emergency stops elsewhere
        import socketserver
        who = self.signup("slowreader")
        other = self.signup("someoneelse")      # before the stall: signing up needs the lock too
        org_id, other_org = who["orgs"][0]["id"], other["orgs"][0]["id"]
        entered, release = threading.Event(), threading.Event()
        original_write = socketserver._SocketWriter.write
        armed = [True]

        def stalled_write(self_, b):
            if armed[0] and threading.current_thread() is not threading.main_thread() and len(b) > 0:
                armed[0] = False
                entered.set()
                release.wait(5)
            return original_write(self_, b)

        response, done = [], {}

        def timed(name, fn):
            t0 = time.monotonic()
            done[name] = (fn(), time.monotonic() - t0)

        with patch.object(socketserver._SocketWriter, "write", stalled_write):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/logs", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            do_login = lambda: self.login("someoneelse", "someoneelse-Passw0rd!")   # noqa: E731
            do_stop = lambda: self.req(other, "/assessments/scan_001/emergency-stop", {}, org=other_org)[0]  # noqa: E731
            workers = [threading.Thread(target=timed, args=("login", do_login)),
                       threading.Thread(target=timed, args=("stop", do_stop))]
            for w in workers:
                w.start()
            for w in workers:
                w.join(0.5)
            try:
                self.assertIn("login", done, "a slow reader delayed another account's login")
                self.assertIn("stop", done, "a slow reader delayed another organization's emergency stop")
            finally:
                release.set()
                thread.join(5)
                for w in workers:
                    w.join(5)
        self.assertEqual(done["stop"][0], 200)
        self.assertEqual(response[0][0], 200)

    def test_snapshot_generation_does_not_block_logout(self):
        who = self.signup("slowsnapshot")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
        response = []
        original_snapshot = svc.snapshot

        def paused_snapshot():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("snapshot test did not release")
            return original_snapshot()

        with patch.object(svc, "snapshot", side_effect=paused_snapshot):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            logout_thread = threading.Thread(target=lambda: (
                self.ops.logout(who["cookie"].split("=", 1)[1]), logged_out.set()))
            logout_thread.start()
            try:
                self.assertTrue(logged_out.wait(0.5), "snapshot held the global account lock")
            finally:
                release.set()
                thread.join(5)
                logout_thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(logout_thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_system_status_generation_does_not_block_logout(self):
        who = self.signup("slowstatus")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
        response = []
        original_status = svc.system_status

        def paused_status():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("status test did not release")
            return original_status()

        with patch.object(svc, "system_status", side_effect=paused_status):
            thread = threading.Thread(target=lambda: response.append(self.req(who, "/system/status", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            logout_thread = threading.Thread(target=lambda: (
                self.ops.logout(who["cookie"].split("=", 1)[1]), logged_out.set()))
            logout_thread.start()
            try:
                self.assertTrue(logged_out.wait(0.5), "status held the global account lock")
            finally:
                release.set()
                thread.join(5)
                logout_thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(logout_thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_remotion_generation_does_not_block_logout(self):
        who = self.signup("slowexport")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
        response = []
        original_export = svc.remotion_export

        def paused_export(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("export test did not release")
            return original_export(*args, **kwargs)

        with patch.object(svc, "remotion_export", side_effect=paused_export):
            thread = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/remotion", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            logout_thread = threading.Thread(target=lambda: (
                self.ops.logout(who["cookie"].split("=", 1)[1]), logged_out.set()))
            logout_thread.start()
            try:
                self.assertTrue(logged_out.wait(0.5), "export held the global account lock")
            finally:
                release.set()
                thread.join(5)
                logout_thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertFalse(logout_thread.is_alive())
        self.assertEqual(response[0][0], 401)

    def test_identified_export_rechecks_approver_and_does_not_audit_a_denial(self):
        owner, approver = self.signup("exportowner"), self.signup("exportapprover")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "exportowner", ["approver"])
        self.reg.store.accept_invite(invite, "exportapprover")
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_export = svc.remotion_export

        def paused_export(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("identified export test did not release")
            return original_export(*args, **kwargs)

        with patch.object(svc, "remotion_export", side_effect=paused_export):
            thread = threading.Thread(target=lambda: response.append(self.req(
                approver, "/assessments/scan_001/remotion?anonymize=0", org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.reg.store.set_roles(org_id, "exportowner", "exportapprover", ["viewer"])
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 403)
        self.assertFalse(any(e["event"] == "export.remotion_identified" for e in svc.audit.entries()))

    def test_member_removal_waits_for_an_inflight_event_write(self):
        owner, member = self.signup("streamowner"), self.signup("streammember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "streamowner", ["viewer"])
        self.reg.store.accept_invite(invite, "streammember")
        svc = self.reg.service(org_id)
        entered, release, removed = threading.Event(), threading.Event(), threading.Event()
        marker = b"PRIVATE_EVENT_DURING_REMOVAL"
        original_write = socketserver._SocketWriter.write

        def paused_write(writer, data):
            if marker in data:
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("event write test did not release")
            return original_write(writer, data)

        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=10)
        try:
            with patch.object(socketserver._SocketWriter, "write", paused_write):
                conn.request("GET", "/api/assessments/scan_001/events",
                             headers={"Cookie": member["cookie"], "X-Vulnix-Org": org_id})
                resp = conn.getresponse()
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.fp.readline(), b"retry: 2000\n")
                resp.fp.readline()
                svc.bus.publish(svc.a.id, "test.private", marker=marker.decode())
                self.assertTrue(entered.wait(5))
                remove_thread = threading.Thread(target=lambda: (
                    self.reg.store.remove_member(org_id, "streamowner", "streammember"), removed.set()))
                remove_thread.start()
                self.assertFalse(removed.wait(0.1), "revocation completed before the event write")
                release.set()
                seen = b""
                for _ in range(40):
                    seen += resp.fp.readline()
                    if marker in seen:
                        break
                self.assertIn(marker, seen)
                remove_thread.join(5)
                self.assertFalse(remove_thread.is_alive())
                self.assertTrue(removed.is_set())
        finally:
            release.set()
            conn.close()

    def test_membership_removal_after_org_binding_cannot_start_a_scan(self):
        owner, member = self.signup("lateowner"), self.signup("latemember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "lateowner", ["runner"])
        self.reg.store.accept_invite(invite, "latemember")
        svc = self.reg.service(org_id)
        entered, release, started = threading.Event(), threading.Event(), threading.Event()
        response = []
        handler = self.srv.RequestHandlerClass
        original_bind = handler._bind

        def paused_bind(request, *args, **kwargs):
            bound = original_bind(request, *args, **kwargs)
            if bound and request.path == "/api/assessments/scan_001/start":
                entered.set()
                if not release.wait(5):
                    raise TimeoutError("membership test did not release the request")
            return bound

        with patch.object(handler, "_bind", paused_bind), patch.object(svc, "start", side_effect=lambda *_a, **_k: started.set()):
            thread = threading.Thread(target=lambda: response.append(
                self.req(member, "/assessments/scan_001/start", {}, org=org_id)))
            thread.start()
            self.assertTrue(entered.wait(5))
            self.reg.store.remove_member(org_id, "lateowner", "latemember")
            release.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(response[0][0], 403)
        self.assertFalse(started.is_set())

    def test_org_owner_role_does_not_become_platform_admin_on_one_connection(self):
        who = self.signup("sameconnection")
        org_id = who["orgs"][0]["id"]
        accepted = threading.Event()
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=5)
        try:
            conn.request("GET", "/api/assets", headers={"Cookie": who["cookie"], "X-Vulnix-Org": org_id})
            first = conn.getresponse()
            first.read()
            self.assertEqual(first.status, 200)
            with patch.object(self.svc, "accept_l2_profile", side_effect=lambda *a: accepted.set()):
                conn.request("POST", "/api/l2-profiles/accept", body=b'{}', headers={
                    "Cookie": who["cookie"], "Content-Type": "application/json", "X-Aegis-Request": "1",
                })
                second = conn.getresponse()
                second.read()
            self.assertEqual(second.status, 403)
            self.assertFalse(accepted.is_set())
        finally:
            conn.close()

    def test_logout_cannot_pass_between_authorization_and_scan_start(self):
        who = self.signup("atomicstart")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release, logged_out = threading.Event(), threading.Event(), threading.Event()
        response_waiting, release_response = threading.Event(), threading.Event()
        response = []
        original_snapshot = svc.snapshot

        def paused_start(*_args, **_kwargs):
            entered.set()
            if not release.wait(5):
                raise TimeoutError("start test did not release the request")

        def logout():
            self.ops.logout(who["cookie"].split("=", 1)[1])
            logged_out.set()

        def paused_snapshot(*args, **kwargs):
            # between the start (audited first, inside the service) and its response
            if entered.is_set():
                response_waiting.set()
                if not release_response.wait(5):
                    raise TimeoutError("start response test did not release")
            return original_snapshot(*args, **kwargs)

        with patch.object(svc, "start", side_effect=paused_start), \
                patch.object(svc, "snapshot", side_effect=paused_snapshot):
            request = threading.Thread(target=lambda: response.append(
                self.req(who, "/assessments/scan_001/start", {}, org=org_id)))
            request.start()
            revocation = None
            try:
                self.assertTrue(entered.wait(5))
                revocation = threading.Thread(target=logout)
                revocation.start()
                self.assertFalse(logged_out.wait(0.1))
                release.set()
                self.assertTrue(response_waiting.wait(5))
                self.assertTrue(logged_out.wait(5))
            finally:
                release.set()
                release_response.set()
                request.join(5)
                if revocation is not None:
                    revocation.join(5)
        self.assertFalse(request.is_alive() or revocation.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertTrue(logged_out.is_set())

    def test_long_plan_receives_live_request_authority(self):
        who = self.signup("liveplanner")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        guards = []

        def capture_plan(*args, **kwargs):
            guards.append(kwargs["request_authorized"])
            return svc.snapshot()

        with patch.object(svc, "plan_with_artex", side_effect=capture_plan):
            self.assertEqual(self.req(who, "/assessments/scan_001/artex/plan", {}, org=org_id)[0], 200)
        self.assertTrue(guards[0]())
        self.ops.logout(who["cookie"].split("=", 1)[1])
        self.assertFalse(guards[0]())

    def test_chat_receives_live_request_authority(self):
        who = self.signup("livechat")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        guards = []

        def capture_chat(*args, **kwargs):
            guards.append(kwargs["request_authorized"])
            return {"message": {}, "chat_messages": [], "planner": {}}

        with patch.object(svc, "ask_chat", side_effect=capture_chat):
            self.assertEqual(self.req(who, "/assessments/scan_001/chat",
                                      {"question": "説明して"}, org=org_id)[0], 200)
        self.assertTrue(guards[0]())
        logged_out = threading.Event()

        def logout():
            self.ops.logout(who["cookie"].split("=", 1)[1])
            logged_out.set()

        with guards[0].lease():
            revocation = threading.Thread(target=logout)
            revocation.start()
            self.assertFalse(logged_out.wait(0.05))
        revocation.join(5)
        self.assertFalse(revocation.is_alive())
        self.assertTrue(logged_out.is_set())
        self.assertFalse(guards[0]())

    def test_foreground_worker_routes_receive_live_request_authority(self):
        who = self.signup("liveworker")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        guards = []

        def capture(*args, **kwargs):
            guards.append(kwargs["request_authorized"])
            return svc.snapshot()

        with patch.object(svc, "verify_finding", side_effect=capture), \
                patch.object(svc, "execute_artex_item", side_effect=capture):
            self.assertEqual(self.req(who, "/assessments/scan_001/verify-finding",
                                      {"finding_id": "f_banner"}, org=org_id)[0], 200)
            self.assertEqual(self.req(who, "/assessments/scan_001/artex/items/item123/execute",
                                      {}, org=org_id)[0], 200)
        self.assertEqual(len(guards), 2)
        self.assertTrue(all(guard() for guard in guards))
        logged_out = threading.Event()

        def logout():
            self.ops.logout(who["cookie"].split("=", 1)[1])
            logged_out.set()

        with guards[0].lease():
            revocation = threading.Thread(target=logout)
            revocation.start()
            self.assertFalse(logged_out.wait(0.05))
        revocation.join(2)
        self.assertFalse(revocation.is_alive())
        self.assertTrue(logged_out.is_set())
        self.assertTrue(all(not guard() for guard in guards))

    def test_logout_before_gateway_worker_launch_starts_no_process(self):
        lab = start_lab(LAB_PORT)
        self.addCleanup(lab.server_close)
        self.addCleanup(lab.shutdown)
        who = self.signup("logoutbeforeworker")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_guard = svc.gateway.late_launch_guard
        before_evidence = sum(len(f.get("evidence") or []) for f in svc.snapshot()["findings"])

        def pause_before_launch():
            entered.set()
            if not release.wait(5):
                raise TimeoutError("worker launch test did not release the request")
            return original_guard()

        with patch.object(svc.gateway, "late_launch_guard", side_effect=pause_before_launch), \
                patch("aegis.runtime.subprocess.Popen") as popen:
            request = threading.Thread(target=lambda: response.append(self.req(
                who, "/assessments/scan_001/verify-finding", {"finding_id": "all"}, org=org_id)))
            request.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.req(who, "/auth/logout", {})[0], 200)
            finally:
                release.set()
                request.join(5)
            self.assertFalse(request.is_alive())
            popen.assert_not_called()
        self.assertEqual(response[0][0], 401)
        self.assertFalse([e for e in svc.audit.entries() if e["event"] == "result"])
        self.assertEqual(sum(len(f.get("evidence") or []) for f in svc.snapshot()["findings"]),
                         before_evidence)
        denials = [e for e in svc.audit.entries() if e["event"] == "deny"]
        self.assertTrue(any("権限" in str(e.get("fields", {})) for e in denials), denials)

    def test_logout_waits_for_gateway_worker_launch_registration(self):
        lab = start_lab(LAB_PORT)
        self.addCleanup(lab.server_close)
        self.addCleanup(lab.shutdown)
        who = self.signup("logoutduringworker")
        old_cookie = who["cookie"]
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        at_popen, release_popen = threading.Event(), threading.Event()
        logout_entered, logout_called, logout_done = threading.Event(), threading.Event(), threading.Event()
        response, logout_response = [], []
        real_popen = subprocess.Popen
        handler = self.srv.RequestHandlerClass
        real_session = handler._session
        real_logout = self.ops.logout

        def paused_popen(*args, **kwargs):
            at_popen.set()
            if not release_popen.wait(5):
                raise TimeoutError("worker launch test did not release Popen")
            return real_popen(*args, **kwargs)

        def observed_session(request, *args, **kwargs):
            if request.path == "/api/auth/logout":
                logout_entered.set()
            return real_session(request, *args, **kwargs)

        def observed_logout(token):
            logout_called.set()
            return real_logout(token)

        def logout_request():
            try:
                logout_response.append(self.req(who, "/auth/logout", {}))
            finally:
                logout_done.set()

        with patch("aegis.runtime.subprocess.Popen", side_effect=paused_popen) as popen, \
                patch.object(handler, "_session", observed_session), \
                patch.object(self.ops, "logout", side_effect=observed_logout):
            request = threading.Thread(target=lambda: response.append(self.req(
                who, "/assessments/scan_001/verify-finding", {"finding_id": "all"}, org=org_id)))
            request.start()
            revocation = None
            try:
                self.assertTrue(at_popen.wait(5))
                revocation = threading.Thread(target=logout_request)
                revocation.start()
                self.assertTrue(logout_entered.wait(5))
                # The logout may be called, but the revocation must not take effect while
                # the worker launch still holds the grant: the session stays valid and the
                # logout does not complete until the launch is registered.
                self.assertFalse(logout_done.wait(0.1), "logout completed before worker registration")
                self.assertIsNotNone(self.ops.resolve(old_cookie.split("=", 1)[1]),
                                     "the session was revoked before worker registration")
            finally:
                release_popen.set()
                request.join(10)
                if revocation is not None:
                    revocation.join(10)
            self.assertFalse(request.is_alive())
            self.assertFalse(revocation and revocation.is_alive())
            popen.assert_called_once()
        self.assertEqual(logout_response[0][0], 200)
        self.assertTrue(logout_called.is_set())
        self.assertEqual(response[0][0], 403)
        self.assertIn("権限", str(response[0][1]))
        self.assertTrue(any(e["event"] == "result" for e in svc.audit.entries()))
        self.assertEqual(self.req({"cookie": old_cookie}, "/assessments/scan_001", org=org_id)[0], 401)

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
            with e:
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

    def test_safe_ai_explanation_cannot_be_requested_for_another_org(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        code, _ = self.req(b, "/assessments/scan_001/chat",
                           {"question": "AIで解説", "safe_advice": True, "finding_id": "f_headers"}, org=a_org)
        self.assertEqual(code, 403)

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

    def test_the_shared_lab_mode_cannot_be_changed_while_tenants_share_it(self):
        a = self.signup("alice")                                   # owner of her own org
        self.assertEqual(self.req(a, "/assessments/scan_001/lab-mode", {"mode": "patched"})[0], 403)
        p = self.login("padmin", "padmin-pw-1")
        self.assertEqual(self.req(p, "/assessments/scan_001/lab-mode", {"mode": "patched"})[0], 403)

    def test_system_status_is_the_callers_own_org(self):
        p = self.login("padmin", "padmin-pw-1")
        self.svc._authority_notice = {"text": "legacy-secret-host.example の診断許可の期限が切れました"} \
            if hasattr(self.svc, "_authority_notice") else None
        a = self.signup("alice")
        st = json.dumps(self.req(a, "/system/status")[1], ensure_ascii=False)
        self.assertNotIn("legacy-secret-host", st)
        self.assertEqual(self.req(p, "/system/status")[0], 200)

    def test_planner_status_is_the_callers_own_org(self):
        a, b = self.signup("planstatusa"), self.signup("planstatusb")
        a_org, b_org = a["orgs"][0]["id"], b["orgs"][0]["id"]
        a_svc, b_svc = self.reg.service(a_org), self.reg.service(b_org)
        with patch.object(self.svc, "planner_status", return_value={"model_name": "default-only"}), \
                patch.object(a_svc, "planner_status", return_value={"model_name": "a-only"}), \
                patch.object(b_svc, "planner_status", return_value={"model_name": "b-only"}):
            self.assertEqual(self.req(a, "/router/status"), (200, {"model_name": "a-only"}))
            self.assertEqual(self.req(b, "/router/status"), (200, {"model_name": "b-only"}))
            self.assertEqual(self.req(a, "/router/status", org=b_org)[0], 403)
            self.assertEqual(self.req(b, "/router/status", org="default")[0], 403)
            self.ops.logout(a["cookie"].split("=", 1)[1])
            self.assertEqual(self.req(a, "/router/status")[0], 401)

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


class TestPasswordResetRoute(TestTenantIsolationOverHttp):
    """/api/operators/reset-password (docs/PASSWORD_CHANGE_DURABILITY.md): platform admins only."""

    def test_other_org_owner_cannot_reset_a_password(self):
        a, b = self.signup("alice"), self.signup("bobby")
        self.assertEqual(self.req({}, "/operators/reset-password",
                                  {"name": "bobby", "password": "taken-over-Passw0rd!"})[0], 401)
        code, _ = self.req(a, "/operators/reset-password", {"name": "bobby", "password": "taken-over-Passw0rd!"})
        self.assertEqual(code, 403)                      # owning an organization is not platform admin
        self.assertEqual(self.req({}, "/auth/login", {"name": "bobby", "password": "taken-over-Passw0rd!"})[0], 401)
        self.assertEqual(self.req(b, "/auth/me")[1]["session"]["operator"], "bobby")

    def test_platform_admin_reset_is_recorded_first_and_signs_the_target_out(self):
        b = self.signup("bobby")
        admin = self.login("padmin", "padmin-pw-1")
        code, body = self.req(admin, "/operators/reset-password", {"name": "bobby", "password": "reset-Passw0rd!77"})
        self.assertEqual(code, 200, body)
        self.assertIsNone(self.req(b, "/auth/me")[1]["session"])     # signed out everywhere
        self.assertEqual(self.req({}, "/auth/login", {"name": "bobby", "password": "bobby-Passw0rd!"})[0], 401)
        self.assertEqual(self.req({}, "/auth/login", {"name": "bobby", "password": "reset-Passw0rd!77"})[0], 200)
        rec = [e["fields"] for e in self.reg.platform_audit.entries() if e["event"] == "operator.password_reset"][-1]
        self.assertEqual((rec["account"], rec["credential_generation"]), ("bobby", 1))
        self.assertIn("hash_digest", rec)
        org_logs = [e["event"] for e in self.reg.service(b["orgs"][0]["id"]).audit.entries()]
        self.assertNotIn("operator.password_reset", org_logs)


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

    def test_the_default_org_cannot_claim_a_patched_comparison_on_a_shared_lab(self):
        from aegis.lab import get_lab_mode, set_lab_mode
        set_lab_mode("vulnerable")
        self.assertFalse(getattr(self.svc, "_may_switch_lab", True))
        self.svc.a.state = "completed"
        with self.assertRaisesRegex(ValueError, "共有"):
            self.svc.verify_fix("padmin")
        self.assertIsNone(self.svc.a.defense_comparison)
        self.assertEqual(get_lab_mode(), "vulnerable")


class TestFourthReviewLows(TestTenantIsolationOverHttp):
    def test_a_forward_plan_without_an_approval_uses_no_quota(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.object(srvmod, "ARTEX_LLM_PLANS_PER_ORG_PER_HOUR", 1):
            for _ in range(3):        # refused by the service (no approval): never 429
                self.assertNotEqual(self.req(a, "/assessments/scan_001/artex/plan", {"llm_mode": "gateway-forward"})[0], 429)

    def test_report_does_not_trust_old_shared_lab_comparison(self):
        self.svc.a.defense_comparison = {"lab_mode": "patched", "items": [], "before_score": 1, "after_score": 0}
        from aegis.lab import set_lab_mode
        set_lab_mode("vulnerable")
        self.assertNotIn("ラボ防御状態: `patched`", self.svc.report_markdown())
        self.assertIn("ラボ防御状態: `vulnerable`", self.svc.report_markdown())


class TestPublicDeploymentSwitches(TestTenantIsolationOverHttp):
    """Switches for the public beta: no traffic to real sites, bounded AI spending."""

    def test_multi_tenant_real_site_stays_read_only_under_legacy_broad_switch(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.multiple(srvmod, REAL_SERVICE_DIAGNOSIS=True, REAL_SITE_L1_ONLY=False):
            me = self.req(a, "/auth/me")[1]
            self.assertIs(me["real_site_read_only"], True)
            self.assertIs(me["real_service_diagnosis"], True)
            code, _ = self.req(a, "/assets/challenge", {"url": "https://owned.example.test/"})
            self.assertEqual(code, 200)
            osvc = self.reg.service(a["orgs"][0]["id"])
            self.assertTrue(osvc.real_site_read_only)
            from aegis.ownership import challenge_for_host
            token = challenge_for_host("owned.example.test", osvc._ownership_secret)["token"]
            with patch("aegis.ownership.default_dns_txt_lookup", return_value=[f'"{token}"']):
                self.assertEqual(self.req(a, "/assets/verify-ownership", {
                    "host": "owned.example.test", "method": "dns_txt"})[0], 200)
            self.assertEqual(self.req(a, "/assets/confirm-scope", {
                "host": "owned.example.test", "confirmed_prohibited": True,
                "activate_workspace": True})[0], 200)
            for route, body in (("/request-l2", {"finding_id": "f_x"}),
                                ("/verify-finding", {"finding_id": "f_x"}),
                                ("/approvals/req_0a", {"decision": "approve"}),
                                ("/verify-fix", {})):
                code, out = self.req(a, f"/assessments/{osvc.a.id}{route}", body)
                self.assertEqual(code, 403, route)
                self.assertIn("読み取り", out["error"], route)

    def test_real_site_traffic_is_refused_when_switched_off(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        with patch.multiple(srvmod, REAL_SERVICE_DIAGNOSIS=False, REAL_SITE_L1_ONLY=False):
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

    def test_real_site_mode_defaults_to_read_only_and_typos_fail_closed(self):
        import importlib
        from aegis import server as srvmod
        try:
            with patch.dict(os.environ, {"VULNIX_NO_ENV_LOCAL": "1"}, clear=True):
                m = importlib.reload(srvmod)
                self.assertEqual((m.REAL_SERVICE_DIAGNOSIS, m.REAL_SITE_L1_ONLY), (False, True))
                os.environ["VULNIX_REAL_SERVICE_DIAGNOSIS"] = "ll"
                m = importlib.reload(srvmod)
                self.assertEqual((m.REAL_SERVICE_DIAGNOSIS, m.REAL_SITE_L1_ONLY), (False, False))
        finally:
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
        with patch.multiple(srvmod, REAL_SERVICE_DIAGNOSIS=False, REAL_SITE_L1_ONLY=False):
            self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
            real = next(x for x in self.req(a, "/assets")[1] if x.get("name") == "shop.example.com")
            self.assertEqual(self.req(a, "/assets/select", {"id": real["id"]})[0], 403)
            me = self.req(a, "/auth/me")[1]
            self.assertIs(me["real_service_diagnosis"], False)
            self.assertIs(me["development"], False)



class TestRunHistoryPerSite(TestRunHistory):
    def test_history_shows_only_the_open_sites_runs(self):
        self.complete()
        with self.svc._lock:
            self.svc.a.asset = {**self.svc.a.asset, "id": "other", "name": "other.lab.test"}
        self.assertEqual(self.svc.snapshot()["run_history"], [])
        self.complete()
        self.assertEqual([h["asset"] for h in self.svc.snapshot()["run_history"]], ["other.lab.test"])


class TestRealModelDailyCap(TestTenantIsolationOverHttp):
    def test_real_model_plans_have_a_daily_platform_cap(self):
        from aegis import server as srvmod
        a, b = self.signup("alice"), self.signup("bobby")
        appr = {"llm_mode": "gateway-forward",
                "llm_approval": {"preview_id": "pv_x", "max_calls": 1, "first_request_sha256": "0" * 64}}
        with patch.object(srvmod, "ARTEX_LLM_PLANS_PER_DAY", 1), \
                patch.object(srvmod, "ARTEX_LLM_PLANS_PER_ORG_PER_HOUR", 5), \
                patch.object(srvmod, "ARTEX_LLM_PLANS_PLATFORM_PER_HOUR", 5):
            self.assertNotEqual(self.req(a, "/assessments/scan_001/artex/plan", appr)[0], 429)
            self.assertEqual(self.req(b, "/assessments/scan_001/artex/plan", appr)[0], 429)

    def test_the_caps_come_from_the_environment(self):
        import importlib
        from aegis import server as srvmod
        with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_PLANS_PER_DAY": "10", "VULNIX_ARTEX_LLM_PLANS_PER_ORG_PER_HOUR": "1"}):
            m = importlib.reload(srvmod)
            self.assertEqual((m.ARTEX_LLM_PLANS_PER_DAY, m.ARTEX_LLM_PLANS_PER_ORG_PER_HOUR), (10, 1))
        importlib.reload(srvmod)


class TestArtexFreshDatabase(unittest.TestCase):
    """Every ARTEX run starts from an empty working database (VULNIX_ARTEX_RESET_DB=1): the
    preview and the approved forward then send the same first request. Runs that share the
    database are serialised, and the DSN (with its password) never appears on a command line."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(Path(self.tmp.name), LAB_PORT, verify_seconds=30)
        self.addCleanup(self.svc.close)
        self.svc._artex_pg_dsn = "postgres://artex_planner:SECRET-PW@127.0.0.1:5432/artex_planner_public?sslmode=disable"

    def test_reset_runs_psql_with_the_dsn_in_the_environment_only(self):
        import aegis.assessment as am
        calls = []

        class P:
            returncode = 0
            stdout = stderr = ""

        def fake_run(argv, **kw):
            calls.append((argv, kw))
            return P()
        with patch.dict(os.environ, {"VULNIX_ARTEX_RESET_DB": "1"}), \
                patch.object(am.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(am.subprocess, "run", side_effect=fake_run):
            self.svc._reset_artex_db()
        argv, kw = calls[0]
        self.assertEqual(argv[0], "/usr/bin/psql")
        self.assertNotIn("SECRET-PW", " ".join(argv))
        env = kw["env"]
        # libpq does not expand a URI held in PGDATABASE: the parts go in their own variables
        self.assertEqual((env["PGHOST"], env["PGPORT"], env["PGUSER"], env["PGDATABASE"], env["PGSSLMODE"]),
                         ("127.0.0.1", "5432", "artex_planner", "artex_planner_public", "disable"))
        self.assertEqual(env["PGPASSWORD"], "SECRET-PW")
        self.assertIn("DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;", argv)

    def test_off_by_default(self):
        import aegis.assessment as am
        with patch.dict(os.environ, {}, clear=False), patch.object(am.subprocess, "run") as run:
            os.environ.pop("VULNIX_ARTEX_RESET_DB", None)
            self.svc._reset_artex_db()
        run.assert_not_called()

    def test_a_failed_reset_stops_the_run_without_showing_the_dsn(self):
        import aegis.assessment as am

        class P:
            returncode = 2
            stdout = ""
            stderr = "psql: error: connection to postgres://artex_planner:SECRET-PW@... failed"
        with patch.dict(os.environ, {"VULNIX_ARTEX_RESET_DB": "1"}), \
                patch.object(am.shutil, "which", return_value="/usr/bin/psql"), \
                patch.object(am.subprocess, "run", return_value=P()):
            with self.assertRaises(ValueError) as e:
                self.svc._reset_artex_db()
        self.assertNotIn("SECRET-PW", str(e.exception))


class TestPublicReadOnlyRealSites(TestTenantIsolationOverHttp):
    """VULNIX_REAL_SERVICE_DIAGNOSIS=l1 (public beta): anyone may register a site, prove
    ownership and run the read-only diagnosis on it. Nothing beyond that reaches a real
    site, and nothing is allowed before ownership is proven."""

    def setUp(self):
        super().setUp()
        from aegis import server as srvmod
        for name, value in (("REAL_SERVICE_DIAGNOSIS", False), ("REAL_SITE_L1_ONLY", True)):
            p = patch.object(srvmod, name, value)
            p.start()
            self.addCleanup(p.stop)

    def _verify(self, who, host):
        from aegis.ownership import challenge_for_host
        osvc = self.reg.service(who["orgs"][0]["id"])
        token = challenge_for_host(host, osvc._ownership_secret)["token"]
        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[f'"{token}"']):
            return self.req(who, "/assets/verify-ownership", {"host": host, "method": "dns_txt"})

    def test_logout_after_challenge_commit_cannot_receive_ownership_token(self):
        who = self.signup("latechallenge")
        org_id = who["orgs"][0]["id"]
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_assets = svc.assets

        def delayed_assets():
            entered.set()
            if not release.wait(5):
                raise AssertionError("challenge response did not release")
            return original_assets()

        with patch.object(svc, "assets", side_effect=delayed_assets):
            worker = threading.Thread(target=lambda: response.append(self.req(
                who, "/assets/challenge", {"url": "https://owned.example/"})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("dns_txt", response[0][1])

    def test_role_downgrade_after_challenge_commit_hides_ownership_token(self):
        owner, member = self.signup("lateowner"), self.signup("latemember")
        org_id = owner["orgs"][0]["id"]
        _, invite = self.reg.store.create_invite(org_id, "lateowner", ["runner"])
        self.reg.store.accept_invite(invite, "latemember")
        svc = self.reg.service(org_id)
        entered, release = threading.Event(), threading.Event()
        response = []
        original_assets = svc.assets

        def delayed_assets():
            entered.set()
            if not release.wait(5):
                raise AssertionError("role downgrade response did not release")
            return original_assets()

        with patch.object(svc, "assets", side_effect=delayed_assets):
            worker = threading.Thread(target=lambda: response.append(self.req(
                member, "/assets/challenge", {"url": "https://owned.example/"}, org=org_id)), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.reg.store.set_roles(org_id, "lateowner", "latemember", ["viewer"])
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(response[0][0], 403)
        self.assertNotIn("dns_txt", response[0][1])

    def test_logout_after_proof_commit_cannot_receive_ownership_result(self):
        who = self.signup("lateproof")
        host = "owned.example"
        self.assertEqual(self.req(who, "/assets/challenge", {"url": f"https://{host}/"})[0], 200)
        svc = self.reg.service(who["orgs"][0]["id"])
        from aegis.ownership import challenge_for_host
        token = challenge_for_host(host, svc._ownership_secret)["token"]
        entered, release = threading.Event(), threading.Event()
        response = []
        original_assets = svc.assets

        def delayed_assets():
            entered.set()
            if not release.wait(5):
                raise AssertionError("proof response did not release")
            return original_assets()

        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[f'"{token}"']), \
                patch.object(svc, "assets", side_effect=delayed_assets):
            worker = threading.Thread(target=lambda: response.append(self.req(
                who, "/assets/verify-ownership", {"host": host, "method": "dns_txt"})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("verified", response[0][1])

    def test_logout_after_scope_commit_cannot_receive_snapshot(self):
        who = self.signup("latescope")
        host = "owned.example"
        self.assertEqual(self.req(who, "/assets/challenge", {"url": f"https://{host}/"})[0], 200)
        self.assertTrue(self._verify(who, host)[1]["verified"])
        svc = self.reg.service(who["orgs"][0]["id"])
        entered, release = threading.Event(), threading.Event()
        response = []
        original_snapshot = svc.snapshot

        def delayed_snapshot():
            entered.set()
            if not release.wait(5):
                raise AssertionError("scope response did not release")
            return original_snapshot()

        with patch.object(svc, "snapshot", side_effect=delayed_snapshot):
            worker = threading.Thread(target=lambda: response.append(self.req(
                who, "/assets/confirm-scope", {"host": host, "confirmed_prohibited": True})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(who["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(response[0][0], 401)
        self.assertNotIn("snapshot", response[0][1])

    def test_logout_during_dns_lookup_cannot_grant_ownership(self):
        a = self.signup("alice")
        host = "next-standards.com"
        self.req(a, "/assets/challenge", {"url": f"https://{host}"})
        from aegis.ownership import challenge_for_host
        osvc = self.reg.service(a["orgs"][0]["id"])
        token = challenge_for_host(host, osvc._ownership_secret)["token"]
        entered, release = threading.Event(), threading.Event()
        result = []

        def blocked_lookup(_name):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test did not release DNS lookup")
            return [f'"{token}"']

        with patch("aegis.ownership.default_dns_txt_lookup", side_effect=blocked_lookup):
            worker = threading.Thread(target=lambda: result.append(self.req(
                a, "/assets/verify-ownership", {"host": host, "method": "dns_txt"})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(a["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 401)
        self.assertNotIn(host, osvc.ledger.ownership_proofs)

    def test_logout_during_proof_file_fetch_cannot_grant_ownership(self):
        a = self.signup("alice")
        host = "next-standards.com"
        self.req(a, "/assets/challenge", {"url": f"https://{host}"})
        from aegis.ownership import challenge_for_host
        osvc = self.reg.service(a["orgs"][0]["id"])
        token = challenge_for_host(host, osvc._ownership_secret)["token"]
        entered, release = threading.Event(), threading.Event()
        result = []

        def blocked_fetch(_url):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test did not release proof file fetch")
            return token

        with patch("aegis.ownership.default_well_known_fetcher", side_effect=blocked_fetch):
            worker = threading.Thread(target=lambda: result.append(self.req(
                a, "/assets/verify-ownership", {"host": host, "method": "well_known"})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(a["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 401)
        self.assertNotIn(host, osvc.ledger.ownership_proofs)

    def test_logout_before_scope_commit_cannot_grant_diagnosis(self):
        a = self.signup("alice")
        host = "next-standards.com"
        self.req(a, "/assets/challenge", {"url": f"https://{host}"})
        self.assertTrue(self._verify(a, host)[1]["verified"])
        osvc = self.reg.service(a["orgs"][0]["id"])
        entered, release = threading.Event(), threading.Event()
        result = []
        original = AssessmentService.confirm_asset_scope

        def delayed_scope(service, **kwargs):
            entered.set()
            if not release.wait(5):
                raise AssertionError("test did not release scope confirmation")
            return original(service, **kwargs)

        with patch.object(AssessmentService, "confirm_asset_scope", delayed_scope):
            worker = threading.Thread(target=lambda: result.append(self.req(
                a, "/assets/confirm-scope", {"host": host, "confirmed_prohibited": True})), daemon=True)
            worker.start()
            try:
                self.assertTrue(entered.wait(5))
                self.ops.logout(a["cookie"].split("=", 1)[1])
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][0], 401)
        self.assertNotIn(host, osvc.ledger.verified_external_hosts)

    def test_register_prove_and_start_on_a_proven_site(self):
        a = self.signup("alice")
        self.assertEqual(self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})[0], 200)
        code, body = self._verify(a, "next-standards.com")
        self.assertEqual(code, 200, body)
        self.assertTrue(body.get("verified"), body)
        code, body = self.req(a, "/assets/confirm-scope", {"host": "next-standards.com", "confirmed_prohibited": True,
                                                          "activate_workspace": True})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["snapshot"]["is_external_service"])
        aid = body["snapshot"]["id"]
        with patch("aegis.assessment.AssessmentService.start", return_value={"ok": True}) as start:
            self.assertEqual(self.req(a, f"/assessments/{aid}/start", {})[0], 200)
        start.assert_called_once()

    def test_optional_status_consent_is_explicit_and_tenant_bound(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        self.assertFalse(self.req(a, "/auth/me")[1].get("optional_status_check", False))
        self.assertEqual(self.req(a, "/assets/confirm-scope", {
            "host": "next-standards.com", "confirmed_prohibited": True,
            "allow_status_probe": True})[0], 409)
        osvc = self.reg.service(a_org)
        osvc._real_site_local_artex = True
        osvc._artex_real_cmd = ["mock-artex"]
        config = {"VULNIX_REAL_SITE_LOCAL_ARTEX": "1",
                  "VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                  "VULNIX_ARTEX_REAL_CMD": "mock-artex",
                  "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                  "VULNIX_ARTEX_LLM_UPSTREAM_URL": "http://127.0.0.1:19991/v1/chat/completions"}
        with patch.dict(os.environ, config):
            self.assertTrue(self.req(a, "/auth/me")[1]["optional_status_check"])
            with patch.dict(os.environ, {"VULNIX_ARTEX_LLM_UPSTREAM_URL": "https://external-model.example/v1"}):
                self.assertFalse(self.req(a, "/auth/me")[1]["optional_status_check"])
            self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
            self._verify(a, "next-standards.com")
            scope = {"host": "next-standards.com", "confirmed_prohibited": True,
                     "activate_workspace": True, "allow_status_probe": "true"}
            self.assertEqual(self.req(a, "/assets/confirm-scope", scope)[0], 200)
            self.assertFalse(osvc._verified_external_hosts["next-standards.com"]["allow_status_probe"])
            scope["allow_status_probe"] = True
            self.assertEqual(self.req(b, "/assets/confirm-scope", scope, org=a_org)[0], 403)
            self.assertEqual(self.req(a, "/assets/confirm-scope", scope)[0], 200)
            self.assertTrue(osvc._verified_external_hosts["next-standards.com"]["allow_status_probe"])

    def test_a_subdomain_can_be_registered_too(self):
        a = self.signup("alice")
        for url in ("https://next-standards.com", "https://wonder.next-standards.com"):
            code, body = self.req(a, "/assets/challenge", {"url": url})
            self.assertEqual(code, 200, body)
        names = {x.get("name") for x in self.req(a, "/assets")[1]}
        self.assertTrue({"next-standards.com", "wonder.next-standards.com"} <= names)

    def test_nothing_runs_on_an_unproven_site(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
        real = next(x for x in self.req(a, "/assets")[1] if x.get("name") == "shop.example.com")
        self.assertNotEqual(self.req(a, "/assets/select", {"id": real["id"]})[0], 200)
        code, _ = self.req(a, "/assets/confirm-scope", {"host": "shop.example.com", "confirmed_prohibited": True})
        self.assertNotEqual(code, 200)

    def test_only_the_read_only_diagnosis_reaches_a_real_site(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        self._verify(a, "next-standards.com")
        aid = self.req(a, "/assets/confirm-scope", {"host": "next-standards.com", "confirmed_prohibited": True,
                                                   "activate_workspace": True})[1]["snapshot"]["id"]
        for route, body in (("/request-l2", {"finding_id": "f_x"}), ("/artex/plan", {}), ("/verify-fix", {}),
                            ("/verify-finding", {"finding_id": "f_x"}), ("/approvals/req_0a", {"decision": "approve"})):
            code, out = self.req(a, f"/assessments/{aid}{route}", body)
            self.assertEqual(code, 403, route)
            self.assertIn("読み取り", out["error"], route)

    def test_ownership_checks_are_rate_limited_per_org(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
        with patch.object(srvmod, "OWNERSHIP_CHECKS_PER_ORG_PER_HOUR", 2), \
                patch("aegis.ownership.default_dns_txt_lookup", return_value=[]):
            codes = [self.req(a, "/assets/verify-ownership", {"host": "shop.example.com"})[0] for _ in range(3)]
        self.assertEqual(codes[-1], 429)

    def test_another_org_cannot_use_my_proof(self):
        a, b = self.signup("alice"), self.signup("bobby")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        self._verify(a, "next-standards.com")
        self.req(b, "/assets/challenge", {"url": "https://next-standards.com"})
        from aegis.ownership import challenge_for_host
        a_token = challenge_for_host("next-standards.com", self.reg.service(a["orgs"][0]["id"])._ownership_secret)["token"]
        with patch("aegis.ownership.default_dns_txt_lookup", return_value=[f'"{a_token}"']):
            code, body = self.req(b, "/assets/verify-ownership", {"host": "next-standards.com"})
        self.assertFalse(body.get("verified"), body)

    def test_the_mode_is_visible_and_read_from_the_environment(self):
        import importlib
        from aegis import server as srvmod
        a = self.signup("alice")
        me = self.req(a, "/auth/me")[1]
        self.assertIs(me["real_service_diagnosis"], False)
        self.assertIs(me["real_site_read_only"], True)
        with patch.dict(os.environ, {"VULNIX_REAL_SERVICE_DIAGNOSIS": "l1"}):
            m = importlib.reload(srvmod)
            self.assertEqual((m.REAL_SERVICE_DIAGNOSIS, m.REAL_SITE_L1_ONLY), (False, True))
        importlib.reload(srvmod)


class TestPublicReadOnlyRealSitesReview(TestPublicReadOnlyRealSites):
    """Review of the L1-only mode: quotas, the service-level guard, the other modes."""

    def _proven(self, who, host="next-standards.com"):
        self.req(who, "/assets/challenge", {"url": f"https://{host}"})
        self._verify(who, host)
        return self.req(who, "/assets/confirm-scope", {"host": host, "confirmed_prohibited": True,
                                                      "activate_workspace": True})[1]["snapshot"]["id"]

    def test_the_run_and_its_controls_stay_open_on_a_proven_site(self):
        a = self.signup("alice")
        aid = self._proven(a)
        with patch("aegis.assessment.AssessmentService.restart", return_value={"ok": True}), \
                patch("aegis.assessment.AssessmentService.resume", return_value={"ok": True}):
            for route in ("/restart", "/resume"):
                self.assertNotEqual(self.req(a, f"/assessments/{aid}{route}", {})[0], 403, route)
        self.assertNotEqual(self.req(a, f"/assessments/{aid}/chat", {"question": "x"})[0], 403)

    def test_opted_in_anonymous_artex_plan_and_l1_item_reach_only_their_organization(self):
        a, b = self.signup("alice"), self.signup("bobby")
        aid = self._proven(a)
        osvc = self.reg.service(a["orgs"][0]["id"])
        osvc._real_site_local_artex = True
        plan = f"/assessments/{aid}/artex/plan"
        item = f"/assessments/{aid}/artex/items/ax_test_1/execute"
        with patch.object(osvc, "plan_with_artex", return_value={"ok": True}) as planned, \
                patch.object(osvc, "execute_artex_item", return_value={"ok": True}) as executed:
            self.assertEqual(self.req(a, plan, {})[0], 200)
            self.assertEqual(self.req(a, item, {})[0], 200)
            a_org = a["orgs"][0]["id"]
            self.assertEqual(self.req(b, plan, {}, org=a_org)[0], 403)
            self.assertEqual(self.req(b, item, {}, org=a_org)[0], 403)
        planned.assert_called_once()
        executed.assert_called_once()

    def test_opted_in_artex_l1_item_is_counted_against_real_site_run_limit(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        aid = self._proven(a)
        osvc = self.reg.service(a["orgs"][0]["id"])
        osvc._real_site_local_artex = True
        item = f"/assessments/{aid}/artex/items/ax_test_1/execute"
        with patch.object(srvmod, "REAL_SITE_RUNS_PER_ORG_PER_HOUR", 1), \
                patch.object(osvc, "execute_artex_item", return_value={"ok": True}) as executed:
            self.assertEqual(self.req(a, item, {})[0], 200)
            self.assertEqual(self.req(a, item, {})[0], 429)
        executed.assert_called_once()

    def test_real_site_runs_are_capped_per_org(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        aid = self._proven(a)
        with patch.object(srvmod, "REAL_SITE_RUNS_PER_ORG_PER_HOUR", 1), \
                patch("aegis.assessment.AssessmentService.restart", return_value={"ok": True}):
            codes = [self.req(a, f"/assessments/{aid}/restart", {})[0] for _ in range(2)]
        self.assertEqual(codes, [200, 429])

    def test_ownership_checks_have_a_platform_cap(self):
        from aegis import server as srvmod
        a, b = self.signup("alice"), self.signup("bobby")
        for who in (a, b):
            self.req(who, "/assets/challenge", {"url": "https://shop.example.com/"})
        with patch.object(srvmod, "OWNERSHIP_CHECKS_PLATFORM_PER_HOUR", 1), \
                patch("aegis.ownership.default_dns_txt_lookup", return_value=[]):
            self.assertNotEqual(self.req(a, "/assets/verify-ownership", {"host": "shop.example.com"})[0], 429)
            self.assertEqual(self.req(b, "/assets/verify-ownership", {"host": "shop.example.com"})[0], 429)

    def test_the_service_refuses_under_its_lock_too(self):
        a = self.signup("alice")
        self._proven(a)
        osvc = self.reg.service(a["orgs"][0]["id"])
        self.assertTrue(osvc.real_site_read_only)
        for call in (lambda: osvc.verify_fix("alice"), lambda: osvc.verify_finding("all", "alice"),
                     lambda: osvc.request_l2_run("f_x", "alice"), lambda: osvc.decide_approval("req_0", "approve", "alice")):
            with self.assertRaises(ValueError) as cm:
                call()
            self.assertIn("読み取り専用", str(cm.exception))

    def test_the_service_refuses_on_a_real_site_whose_scope_lapsed(self):
        # the refusal must follow "registered as a real site", not "scope valid right now":
        # a lapsed scope that is confirmed again mid-call would otherwise let an L2 re-check through
        a = self.signup("alice")
        self._proven(a)
        osvc = self.reg.service(a["orgs"][0]["id"])
        with osvc._lock:
            osvc._verified_external_hosts["next-standards.com"]["not_after"] = time.time() - 1
        self.assertFalse(osvc._is_external_service_asset())
        for call in (lambda: osvc.verify_fix("alice"), lambda: osvc.verify_finding("all", "alice"),
                     lambda: osvc.request_l2_run("f_x", "alice"), lambda: osvc.decide_approval("req_0", "approve", "alice")):
            with self.assertRaises(ValueError) as cm:
                call()
            self.assertIn("読み取り専用", str(cm.exception))

    def test_a_run_started_from_the_lab_counts_when_the_org_has_a_proven_site(self):
        # the workspace can be switched to the proven site between the server's check and
        # the run itself, so every run of an org with a proven real site is counted
        from aegis import server as srvmod
        a = self.signup("alice")
        self._proven(a)
        osvc = self.reg.service(a["orgs"][0]["id"])
        lab = next(x for x in self.req(a, "/assets")[1] if not osvc.asset_is_real_service(asset_id=x["id"]))
        self.assertEqual(self.req(a, "/assets/select", {"id": lab["id"]})[0], 200)
        self.assertFalse(osvc._is_external_service_asset())
        with patch.object(srvmod, "REAL_SITE_RUNS_PER_ORG_PER_HOUR", 1), \
                patch("aegis.assessment.AssessmentService.restart", return_value={"ok": True}):
            codes = [self.req(a, f"/assessments/{osvc.a.id}/restart", {})[0] for _ in range(2)]
        self.assertEqual(codes, [200, 429])

    def test_lab_only_orgs_are_not_counted_as_real_site_runs(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        osvc = self.reg.service(a["orgs"][0]["id"])
        with patch.object(srvmod, "REAL_SITE_RUNS_PER_ORG_PER_HOUR", 1), \
                patch("aegis.assessment.AssessmentService.restart", return_value={"ok": True}):
            codes = [self.req(a, f"/assessments/{osvc.a.id}/restart", {})[0] for _ in range(2)]
        self.assertEqual(codes, [200, 200])

    def test_switched_off_still_refuses_the_ownership_check(self):
        from aegis import server as srvmod
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://shop.example.com/"})
        with patch.object(srvmod, "REAL_SITE_L1_ONLY", False):
            self.assertEqual(self.req(a, "/assets/verify-ownership", {"host": "shop.example.com"})[0], 403)


class TestDiagnosisReadApiOverHttp(unittest.TestCase):
    """GET /api/assessments/{id}/diagnosis and its SSE event (docs/DIAGNOSIS_READ_API.md):
    login required, the caller's own organization only, membership re-checked, 404 on a
    real service."""
    setUp = TestTenantIsolationOverHttp.setUp
    _down = TestTenantIsolationOverHttp._down
    req = TestTenantIsolationOverHttp.req
    signup = TestTenantIsolationOverHttp.signup

    PATH = "/assessments/scan_001/diagnosis"

    def _diagnose(self, org_id, actor):
        from aegis.diagnosis_loop import record_owner_spec
        state = self.reg.service(org_id).diagnosis_state()
        record_owner_spec(state, "T2", "public", actor=actor)
        return state.diag_id

    def _stream(self, who, org, until: bytes, deadline=20.0) -> bytes:
        conn = http.client.HTTPConnection("127.0.0.1", self.srv.server_port, timeout=deadline)
        try:
            conn.request("GET", "/api/assessments/scan_001/events?after=0",
                         headers={"Cookie": who["cookie"], "X-Vulnix-Org": org})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            data, end = b"", time.time() + deadline
            while until not in data and time.time() < end:
                line = resp.fp.readline()
                if not line:
                    break
                data += line
            return data
        finally:
            conn.close()

    def test_the_view_needs_a_login_and_stays_in_its_organization(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org, b_org = a["orgs"][0]["id"], b["orgs"][0]["id"]
        self.assertEqual(self.req({}, self.PATH, org=a_org)[0], 401)
        code, view = self.req(a, self.PATH)
        self.assertEqual((code, view["status"], view["lab_only"]), (200, "not_started", True))
        diag_id = self._diagnose(a_org, "alice")
        code, view = self.req(a, self.PATH)
        self.assertEqual((code, view["status"], view["diag_id"]), (200, "ok", diag_id))
        self.assertEqual([e["recorded_by"] for e in view["evidence"]], ["alice"])
        # another organization's member: refused (and audited), never the data
        code, body = self.req(b, self.PATH, org=a_org)
        self.assertEqual(code, 403)
        self.assertNotIn(diag_id, json.dumps(body))
        code, own = self.req(b, self.PATH, org=b_org)
        self.assertEqual((code, own["status"]), (200, "not_started"))
        self.assertIn(("bobby", a_org), [(e["fields"].get("actor"), e["fields"].get("org"))
                                         for e in self.reg.platform_audit.entries()
                                         if e["event"] == "tenancy.access_denied"])
        # a member reads it; once removed, no longer
        token = self.req(a, "/orgs/invites", {"roles": ["viewer"]})[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        self.assertEqual(self.req(b, self.PATH, org=a_org)[1]["diag_id"], diag_id)
        self.assertEqual(self.req(a, "/orgs/members/remove", {"name": "bobby"})[0], 200)
        self.assertEqual(self.req(b, self.PATH, org=a_org)[0], 403)
        # logout ends it too
        old = dict(a)
        self.assertEqual(self.req(a, "/auth/logout", {})[0], 200)
        self.assertEqual(self.req(old, self.PATH, org=a_org)[0], 401)

    def test_a_real_service_has_no_diagnosis_view(self):
        a = self.signup("alice")
        a_org = a["orgs"][0]["id"]
        svc = self.reg.service(a_org)
        with patch.object(svc, "_is_external_service_asset", return_value=True):
            code, body = self.req(a, self.PATH)
        self.assertEqual(code, 404)
        self.assertNotIn("hypotheses", body)

    def test_diagnosis_updates_reach_only_the_organizations_own_stream(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org, b_org = a["orgs"][0]["id"], b["orgs"][0]["id"]
        diag_id = self._diagnose(a_org, "alice")
        mine = self._stream(a, a_org, b"diagnosis.updated")
        self.assertIn(b"diagnosis.updated", mine)
        self.assertIn(diag_id.encode(), mine)
        theirs = self._stream(b, b_org, b"event: heartbeat")
        self.assertIn(b"event: heartbeat", theirs)        # the whole backlog was delivered first
        self.assertNotIn(b"diagnosis.updated", theirs)
        self.assertNotIn(diag_id.encode(), theirs)


class TestDiagnosisActionsOverHttp(unittest.TestCase):
    """PR-C (docs/DIAGNOSIS_ACTIONS.md): the four diagnosis operations need a login, the
    caller's own organization, the operation's permission and an Idempotency-Key; on a
    real service they do not exist (404). The service-level cases are in
    tests/test_diagnosis_actions.py."""
    setUp = TestTenantIsolationOverHttp.setUp
    _down = TestTenantIsolationOverHttp._down
    req = TestTenantIsolationOverHttp.req
    signup = TestTenantIsolationOverHttp.signup
    BASE = "/assessments/scan_001/diagnosis"

    def post(self, who, op, body=None, org=None, key="http-test-key-0000001"):
        h = {"Content-Type": "application/json", "X-Aegis-Request": "1"}
        if who and who.get("cookie"):
            h["Cookie"] = who["cookie"]
        if org:
            h["X-Vulnix-Org"] = org
        if key:
            h["Idempotency-Key"] = key
        r = urllib.request.Request(f"{self.root}{self.BASE}/{op}", json.dumps(body or {}).encode(), h)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def accepted(self, org_id):
        return [e for e in self.reg.service(org_id).audit.entries() if e["event"] == "diagnosis.request_accepted"]

    def test_login_organization_permission_and_key(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        svc = self.reg.service(a_org)
        self.assertEqual(self.post({}, "start", org=a_org)[0], 401)
        # another organization's member reaches nothing in this one
        for op in ("start", "owner-spec", "fix-check", "approve"):
            self.assertEqual(self.post(b, op, org=a_org)[0], 403, op)
        with svc._lock:
            self.assertIsNone(svc.diagnosis_ops.job_view_locked())
        self.assertEqual(self.accepted(a_org), [])
        # a viewer of this organization: may read, may not operate
        token = self.req(a, "/orgs/invites", {"roles": ["viewer"]})[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        code, view = self.req(b, self.BASE, org=a_org)
        self.assertEqual((code, view["viewer"]["permissions"]), (200, ["diagnosis:read"]))
        self.assertEqual(self.post(b, "start", org=a_org)[0], 403)
        # the owner: every permission, and every operation needs its key
        code, view = self.req(a, self.BASE)
        self.assertEqual(view["viewer"], {"actor": "alice", "permissions": [
            "asset:specify", "diagnosis:approve_l2", "diagnosis:read", "diagnosis:request"]})
        code, body = self.post(a, "start", key=None)
        self.assertEqual((code, body["reason"]), (400, "idempotency_key_required"))
        code, body = self.post(a, "owner-spec", {"target_ref": "T2", "requirement": "public"})
        self.assertEqual((code, body["reason"]), (409, "not_started"))
        code, body = self.post(a, "approve", {"item_id": "x1"}, key="http-test-key-0000002")
        if svc.separate_l2_approver:
            self.assertEqual((code, body["reason"]), (403, "self_registered"))
        else:
            self.assertEqual((code, body["reason"]), (409, "not_waiting"))
        self.assertEqual(self.post(a, "nothing")[0], 404)

    def test_the_start_route_hands_over_the_live_authority(self):
        a = self.signup("alice")
        a_org = a["orgs"][0]["id"]
        svc = self.reg.service(a_org)
        seen = {}

        def fake_start(**kw):
            seen.update(kw)
            return 202, {"job": None}
        with patch.object(svc.diagnosis_ops, "_start", side_effect=fake_start):
            self.assertEqual(self.post(a, "start")[0], 202)
        self.assertEqual(seen["actor"], "alice")
        self.assertIn("operator", seen["roles"])
        self.assertTrue(seen["request_authorized"]())
        self.assertEqual(self.req(a, "/auth/logout", {})[0], 200)
        self.assertFalse(seen["request_authorized"]())           # checked again at every step

    def test_a_real_service_has_no_diagnosis_operations(self):
        a = self.signup("alice")
        a_org = a["orgs"][0]["id"]
        svc = self.reg.service(a_org)
        with patch.object(svc, "_is_external_service_asset", return_value=True):
            for op in ("start", "owner-spec", "fix-check", "approve"):
                code, body = self.post(a, op, {"item_id": "x1"} if op == "approve" else None)
                self.assertEqual(code, 404, (op, body))
        self.assertEqual(self.accepted(a_org), [])

    def test_artex_items_cannot_run_beside_the_loop(self):
        a = self.signup("alice")
        svc = self.reg.service(a["orgs"][0]["id"])
        with svc._lock:
            svc._exec_owner = "dj_test"            # a diagnosis job holds the execution right
        try:
            code, body = self.req(a, "/assessments/scan_001/artex/items/ax1_1/execute", {})
            self.assertEqual(code, 409, body)
            self.assertIn("診断ループ", body["error"])
            code, body = self.req(a, "/assessments/scan_001/artex/plan", {})
            self.assertEqual(code, 409, body)
            self.assertIn("診断ループ", body["error"])
        finally:
            with svc._lock:
                svc._exec_owner = None

    def test_authority_lost_right_after_the_operation_withholds_the_result_and_never_reruns(self):
        a, b = self.signup("alice"), self.signup("bobby")
        a_org = a["orgs"][0]["id"]
        svc = self.reg.service(a_org)
        token = self.req(a, "/orgs/invites", {"roles": ["runner"]})[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        ran = []
        ops = svc.diagnosis_ops

        def start_then_lose_membership(*, key, actor, roles, body, **kw):
            with svc._lock:
                rec, replay = ops._accept("start", key, actor, {}, None)
                if replay:
                    return ops._replay(rec)
                ops._finish_request_locked(rec, "done", {"job": {"id": "dj_secret_result"}})
            ran.append(actor)
            # removed by the owner right after the operation was stored, before the answer
            self.assertEqual(self.req(a, "/orgs/members/remove", {"name": "bobby"})[0], 200)
            return 202, {"job": {"id": "dj_secret_result"}}
        k = "http-revoked-after-0001"
        with patch.object(ops, "_start", side_effect=start_then_lose_membership):
            code, body = self.post(b, "start", org=a_org, key=k)
            self.assertEqual(code, 403, body)
            self.assertTrue(body["committed"])
            self.assertNotIn("dj_secret_result", json.dumps(body))
            # the retry with the same key: not a member any more, nothing runs again
            self.assertEqual(self.post(b, "start", org=a_org, key=k)[0], 403)
            self.assertEqual(ran, ["bobby"])
            # member again: the same key returns what was stored, still without running
            token = self.req(a, "/orgs/invites", {"roles": ["runner"]})[1]["token"]
            self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
            code, body = self.post(b, "start", org=a_org, key=k)
        self.assertEqual(code, 200, body)
        self.assertTrue(body["replayed"])
        self.assertEqual(ran, ["bobby"])
        self.assertEqual(len(self.accepted(a_org)), 1)
