"""Audit before state (security review O5).

A change that grants authority or starts work is recorded in the audit log FIRST;
if the record cannot be written, nothing changes and the caller gets an error
(the pattern of aegis/diagnosis_ops.py). A change that removes authority or stops
work is never blocked by a failing audit log: it is applied, and the missing record
is reported to the caller.

Each test makes AuditLog.record fail for exactly one event and checks what changed.
No test here talks to the internet (the "real service" is a loopback stand-in).
"""
import tests  # noqa: F401  (hermetic revocation-marker directory, no .env.local)
import contextlib
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
from aegis.audit import AuditLog, AuditWriteFailed
from aegis.gateway import State
from aegis.operators import OperatorStore, hash_password
from aegis.server import make_handler
from aegis.tenancy import OrgStore, TenantRegistry, default_members_from
from tests import test_real_service as rs

LAB_PORT = 18097


@contextlib.contextmanager
def audit_fails(*events):
    """AuditLog.record raises for these events (a full disk, a broken chain or anchor)."""
    real = AuditLog.record

    def record(self, event, **fields):
        if event in events:
            raise OSError(f"injected audit failure for {event}")
        return real(self, event, **fields)

    with patch.object(AuditLog, "record", record):
        yield


def events(svc, name):
    return [e["fields"] for e in svc.audit.entries() if e["event"] == name]


class LabServiceCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1)
        self.svc._may_switch_lab = False

    def tearDown(self):
        self.svc.workers.kill_all()
        self.svc.close()
        self.tmp.cleanup()


class TestLabGrantsAreAuditedFirst(LabServiceCase):
    def test_registering_an_authorized_asset_changes_nothing_without_its_record(self):
        with audit_fails("asset.registered"), self.assertRaises(AuditWriteFailed):
            self.svc.register_asset(name="staging.lab-alias", kind="Webアプリケーション", environment="検証環境",
                                    authorization_ref="SOW-1", ownership_verified=True)
        self.assertNotIn("staging.lab-alias", self.svc._allowed_hosts)
        self.assertNotIn("staging.lab-alias", [a["name"] for a in self.svc.assets()])

    def test_selecting_an_asset_changes_nothing_without_its_record(self):
        a = self.svc.register_asset(name="other.lab-alias", kind="Webアプリケーション", environment="検証環境",
                                    authorization_ref="SOW-2", ownership_verified=True)
        before = self.svc.snapshot()["asset"]["id"]
        with audit_fails("asset.selected"), self.assertRaises(AuditWriteFailed):
            self.svc.select_asset(a["id"], actor="op")
        self.assertEqual(self.svc.snapshot()["asset"]["id"], before)

    def test_a_run_does_not_start_without_its_record(self):
        with audit_fails("assessment.start_requested"), self.assertRaises(AuditWriteFailed):
            self.svc.start(actor="op")
        self.assertEqual(self.svc.a.state, "idle")
        self.assertIsNone(getattr(self.svc, "_thread", None))
        self.assertEqual(events(self.svc, "assessment.start_requested"), [])

    def test_a_restart_does_not_start_without_its_record(self):
        with audit_fails("assessment.restarted"), self.assertRaises(AuditWriteFailed):
            self.svc.restart("op")
        self.assertEqual(self.svc.a.state, "idle")
        self.assertIsNone(getattr(self.svc, "_thread", None))

    def test_resume_does_not_resume_the_gateway_without_its_record(self):
        self.svc.gateway.pause("op")
        self.assertIs(self.svc.gateway.state, State.PAUSED)
        with audit_fails("resume"), self.assertRaises(OSError):
            self.svc.gateway.resume("op")
        self.assertIs(self.svc.gateway.state, State.PAUSED)

    def test_an_approval_is_not_given_without_its_record(self):
        # already audit-first before O5; kept here as a regression test
        self.svc.a.approvals["req_t"] = {"id": "req_t", "status": "pending", "action": "safe_reproduction",
                                         "risk_level": "L2"}
        with audit_fails("approval.approved"), self.assertRaises(OSError):
            self.svc.decide_approval("req_t", "approve", "appr")
        self.assertEqual(self.svc.a.approvals["req_t"]["status"], "pending")


class TestLabReductionsAreNeverBlocked(LabServiceCase):
    def test_pause_holds_when_its_record_cannot_be_written(self):
        with self.svc._lock:
            self.svc.a.state = "running"
        with audit_fails("pause"), self.assertRaises(AuditWriteFailed):
            self.svc.pause("op")
        self.assertIs(self.svc.gateway.state, State.PAUSED)
        self.assertEqual(self.svc.a.state, "paused")

    def test_emergency_stop_completes_when_rejections_cannot_be_recorded(self):
        with self.svc._lock:
            self.svc.a.state = "running"
        self.svc.a.approvals["req_t"] = {"id": "req_t", "status": "pending", "action": "safe_reproduction",
                                         "risk_level": "L2"}
        with audit_fails("approval.rejected", "emergency_stop"):
            report = self.svc.emergency_stop("op")
        self.assertEqual(self.svc.a.state, "stopped")
        self.assertIs(self.svc.gateway.state, State.STOPPED)
        self.assertEqual(self.svc.a.approvals["req_t"]["status"], "rejected")
        self.assertFalse(report["confirmed"])          # surfaced: not a confirmed (fully audited) stop
        self.assertTrue(report.get("audit_incomplete"))

    def test_a_rejection_stands_when_its_record_cannot_be_written(self):
        self.svc.a.approvals["req_t"] = {"id": "req_t", "status": "pending", "action": "safe_reproduction",
                                         "risk_level": "L2"}
        with audit_fails("approval.rejected"), self.assertRaises(AuditWriteFailed):
            self.svc.decide_approval("req_t", "reject", "appr")
        self.assertEqual(self.svc.a.approvals["req_t"]["status"], "rejected")


class TestRealServiceGrantsAreAuditedFirst(rs.RealServiceBase):
    def challenge(self):
        return self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]

    def verify(self, ch):
        return self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                               dns_lookup=self._token_lookup(ch))

    def confirm(self):
        return self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                            allow_loopback_test=True)

    def ledger(self):
        return json.loads((self.dir / "authority.ledger").read_text())["tables"]

    def test_a_registration_changes_nothing_without_its_record(self):
        with audit_fails("asset.challenge_issued"), self.assertRaises(AuditWriteFailed):
            self.challenge()
        self.assertNotIn(rs.HOST, self.svc._real_service_hosts)
        self.assertNotIn(rs.HOST, [a["name"] for a in self.svc.assets()])

    def test_an_ownership_proof_is_not_kept_without_its_record(self):
        ch = self.challenge()
        with audit_fails("asset.ownership_verified"), self.assertRaises(AuditWriteFailed):
            self.verify(ch)
        self.assertNotIn(rs.HOST, self.svc._ownership_proofs)
        self.assertNotIn(rs.HOST, self.ledger().get("ownership_proofs", {}))

    def test_a_scope_is_not_granted_without_its_record(self):
        self.verify(self.challenge())
        with audit_fails("asset.scope_confirmed"), self.assertRaises(AuditWriteFailed):
            self.confirm()
        self.assertNotIn(rs.HOST, self.svc._verified_external_hosts)
        self.assertNotIn(rs.HOST, self.ledger()["verified_external_hosts"])
        self.assertNotEqual(self.svc.snapshot()["asset"]["name"], rs.HOST)

    def test_a_scope_whose_commit_fails_after_its_record_is_marked_not_granted(self):
        self.verify(self.challenge())
        with patch("aegis.authority_ledger.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(ValueError):
                self.confirm()
        self.assertNotIn(rs.HOST, self.svc._verified_external_hosts)
        self.assertEqual(events(self.svc, "grant.not_committed")[-1]["grant"], "asset.scope_confirmed")

    def test_test_accounts_are_not_stored_without_their_record(self):
        self.onboard()
        with audit_fails("secrets.configured"), self.assertRaises(AuditWriteFailed):
            self.svc.configure_asset_secrets(host=rs.HOST, tokens={"user_a_token": rs.TOKEN_A,
                                                                   "user_b_token": rs.TOKEN_B}, actor="appr")
        self.assertFalse(self.svc.secrets.has_any_token(rs.HOST))

    def test_an_l2_request_is_not_kept_without_its_record(self):
        self.onboard()
        with audit_fails("l2.run_requested"), self.assertRaises(AuditWriteFailed):
            self.svc.request_l2_run("f_ex_idor", "op")
        self.assertNotIn("f_ex_idor", self.svc._l2_requests)

    def test_a_failed_recheck_revokes_even_when_its_record_cannot_be_written(self):
        self.onboard()
        with audit_fails("asset.ownership_failed"), self.assertRaises(AuditWriteFailed):
            self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                            dns_lookup=lambda n: [])
        self.assertNotIn(rs.HOST, self.svc._verified_external_hosts)
        self.assertNotIn(rs.HOST, self.svc._ownership_proofs)

    def test_deleting_an_asset_revokes_even_when_its_record_cannot_be_written(self):
        self.onboard()
        aid = self.svc.snapshot()["asset"]["id"]
        with audit_fails("asset.deleted"), self.assertRaises(AuditWriteFailed):
            self.svc.delete_asset(aid, actor="appr")
        self.assertNotIn(rs.HOST, self.svc._verified_external_hosts)
        self.assertNotIn(rs.HOST, [a["name"] for a in self.svc.assets()])


class TestProfileAcceptanceIsAuditedFirst(rs.RealServiceBase):
    def test_a_profile_is_not_accepted_without_its_record(self):
        site = json.loads((rs.BUILTIN_PROFILE_DIR / "sample_api.json").read_text(encoding="utf-8"))
        site["applies_to"]["hosts"] = [rs.HOST]
        d = self.dir / "l2_profiles"
        d.mkdir(mode=0o700)
        (d / "sample_api.json").write_text(json.dumps(site), encoding="utf-8")
        (d / "sample_api.json").chmod(0o600)
        self.svc.workers.kill_all()
        self.svc.close()
        self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, real_site_read_only=False)
        sha = self.svc.l2_profiles_status()["profiles"][0]["sha256"]
        with audit_fails("l2.profile_accepted"), self.assertRaises(AuditWriteFailed):
            self.svc.accept_l2_profile("sample_api", sha, "root")
        self.assertNotIn("sample_api", self.svc._accepted_profiles)
        self.assertNotIn("sample_api", self.svc.ledger.snapshot().get("accepted_profiles", {}))


class TestHttpMembershipAndRoles(unittest.TestCase):
    """Organization and account roles over HTTP (no new routes)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        seed = d / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "padmin", "roles": ["operator", "approver", "admin"],
             "password_hash": hash_password("padmin-pw-1")},
            {"name": "padmin2", "roles": ["operator", "admin"], "password_hash": hash_password("padmin-pw-2")},
            {"name": "plain", "roles": ["operator"], "password_hash": hash_password("plain-pw-12")}]}))
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
            with e:
                return e.code, json.load(e)

    def signup(self, name):
        who = {}
        code, body = self.req(who, "/auth/register", {"name": name, "password": f"{name}-Passw0rd!"})
        self.assertEqual(code, 200, body)
        who["orgs"] = body["orgs"]
        return who

    def login(self, name, pw):
        who = {}
        code, body = self.req(who, "/auth/login", {"name": name, "password": pw})
        self.assertEqual(code, 200, body)
        return who

    def test_an_invitation_is_not_created_without_its_record(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        with audit_fails("tenancy.invite_created"):
            code, body = self.req(a, "/orgs/invites", {"roles": ["approver"]}, org=org)
        self.assertEqual(code, 503, body)
        self.assertNotIn("token", body)
        self.assertEqual(self.reg.store.invites(org), [])

    def test_an_invitation_is_not_accepted_without_its_record(self):
        a, b = self.signup("alice"), self.signup("bobby")
        org = a["orgs"][0]["id"]
        token = self.req(a, "/orgs/invites", {"roles": ["approver"]}, org=org)[1]["token"]
        with audit_fails("tenancy.invite_accepted"):
            code, body = self.req(b, "/invites/accept", {"token": token})
        self.assertEqual(code, 503, body)
        self.assertEqual(self.reg.store.roles_in(org, "bobby"), ())
        self.assertTrue(self.reg.store.invite_valid(token))     # not used up: nothing happened

    def test_an_org_role_grant_is_not_applied_without_its_record(self):
        a, b = self.signup("alice"), self.signup("bobby")
        org = a["orgs"][0]["id"]
        token = self.req(a, "/orgs/invites", {"roles": ["viewer"]}, org=org)[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        with audit_fails("tenancy.member_roles_changed"):
            code, body = self.req(a, "/orgs/members/roles", {"name": "bobby", "roles": ["approver"]}, org=org)
        self.assertEqual(code, 503, body)
        self.assertEqual(self.reg.store.roles_in(org, "bobby"), ("viewer",))

    def test_an_org_role_removal_is_applied_and_the_missing_record_reported(self):
        a, b = self.signup("alice"), self.signup("bobby")
        org = a["orgs"][0]["id"]
        token = self.req(a, "/orgs/invites", {"roles": ["approver", "runner"]}, org=org)[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        with audit_fails("tenancy.member_roles_changed"):
            code, body = self.req(a, "/orgs/members/roles", {"name": "bobby", "roles": ["viewer"]}, org=org)
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), True)
        self.assertEqual(self.reg.store.roles_in(org, "bobby"), ("viewer",))

    def test_removing_a_member_is_applied_and_the_missing_record_reported(self):
        a, b = self.signup("alice"), self.signup("bobby")
        org = a["orgs"][0]["id"]
        token = self.req(a, "/orgs/invites", {"roles": ["runner"]}, org=org)[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        with audit_fails("tenancy.member_removed"):
            code, body = self.req(a, "/orgs/members/remove", {"name": "bobby"}, org=org)
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), True)
        self.assertEqual(self.reg.store.roles_in(org, "bobby"), ())

    def test_an_account_role_grant_is_not_applied_without_its_record(self):
        admin = self.login("padmin", "padmin-pw-1")
        with audit_fails("operator.roles_changed"):
            code, body = self.req(admin, "/operators/roles", {"name": "plain", "roles": ["operator", "approver"]})
        self.assertEqual(code, 503, body)
        self.assertEqual(set(self.ops.roles_of("plain")), {"operator"})

    def test_an_account_role_removal_is_applied_and_the_missing_record_reported(self):
        admin = self.login("padmin", "padmin-pw-1")
        with audit_fails("operator.roles_changed"):
            code, body = self.req(admin, "/operators/roles", {"name": "padmin2", "roles": ["operator"]})
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), True)
        self.assertEqual(set(self.ops.roles_of("padmin2")), {"operator"})

    def test_a_scan_start_over_http_is_refused_without_its_record(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        osvc = self.reg.service(org)
        with audit_fails("assessment.start_requested"):
            code, body = self.req(a, "/assessments/scan_001/start", {}, org=org)
        self.assertNotEqual(code, 200, body)
        self.assertEqual(osvc.a.state, "idle")


if __name__ == "__main__":
    unittest.main()
