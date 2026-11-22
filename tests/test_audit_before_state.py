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
import io
import json
import os
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
from aegis.audit import AuditLog, AuditWriteFailed
from aegis.gateway import State
from aegis.operators import AuthError, OperatorStore, generate_totp_secret, hash_password, totp_code
from aegis.server import make_handler
from aegis.tenancy import OrgStore, TenantRegistry, default_members_from
from tests import test_real_service as rs

LAB_PORT = 18097
MFA_SECRET = generate_totp_secret()


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
        with audit_fails("resume"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.gateway.resume("op")
        self.assertIs(cm.exception.applied, False)
        self.assertIs(self.svc.gateway.state, State.PAUSED)

    def test_an_approval_is_not_given_without_its_record(self):
        # already audit-first before O5; kept here as a regression test
        self.svc.a.approvals["req_t"] = {"id": "req_t", "status": "pending", "action": "safe_reproduction",
                                         "risk_level": "L2"}
        self.svc.a.started_by = "op"            # separation of duties: a different person started it
        with audit_fails("approval.approved"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.decide_approval("req_t", "approve", "appr")
        self.assertIs(cm.exception.applied, False)
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
        with audit_fails("approval.rejected"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.decide_approval("req_t", "reject", "appr")
        self.assertIs(cm.exception.applied, True)
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
        with audit_fails("asset.ownership_failed"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                            dns_lookup=lambda n: [])
        self.assertIs(cm.exception.applied, True)
        self.assertNotIn(rs.HOST, self.svc._verified_external_hosts)
        self.assertNotIn(rs.HOST, self.svc._ownership_proofs)

    def test_deleting_an_asset_revokes_even_when_its_record_cannot_be_written(self):
        self.onboard()
        aid = self.svc.snapshot()["asset"]["id"]
        with audit_fails("asset.deleted"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.delete_asset(aid, actor="appr")
        self.assertIs(cm.exception.applied, True)
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


class HttpCase(unittest.TestCase):
    """A control plane with organizations, over HTTP (no new routes)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        seed = d / "operators.json"
        seed.write_text(json.dumps({"operators": [
            {"name": "padmin", "roles": ["operator", "approver", "admin"],
             "password_hash": hash_password("padmin-pw-1")},
            {"name": "padmin2", "roles": ["operator", "admin"], "password_hash": hash_password("padmin-pw-2")},
            {"name": "plain", "roles": ["operator"], "password_hash": hash_password("plain-pw-12")},
            {"name": "mfauser", "roles": ["operator"], "password_hash": hash_password("mfauser-pw-1"),
             "totp_secret": MFA_SECRET}]}))
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



class TestHttpMembershipAndRoles(HttpCase):
    """Organization and account roles over HTTP."""

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
        self.assertEqual([(g["event"], g["log"]) for g in self.svc.platform_audit_gaps()],
                         [("operator.roles_changed", "platform")])
        self.assertEqual(self.svc.system_status()["audit_gaps"], [])     # not in the org's status

    def test_a_scan_start_over_http_is_refused_without_its_record(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        osvc = self.reg.service(org)
        with audit_fails("assessment.start_requested"):
            code, body = self.req(a, "/assessments/scan_001/start", {}, org=org)
        self.assertNotEqual(code, 200, body)
        self.assertEqual(osvc.a.state, "idle")


# ---- review follow-up (O5 second round) ------------------------------------------------
class TestFollowUpLab(LabServiceCase):
    def gaps(self, svc=None):
        return [g["event"] for g in (svc or self.svc).system_status()["audit_gaps"]]

    def test_a_restart_refused_after_its_record_is_marked_not_started(self):
        with patch.object(self.svc, "_new_scan_usage_locked", side_effect=ValueError("refused late")):
            with self.assertRaises(ValueError):
                self.svc.restart("op")
        self.assertEqual(self.svc.a.state, "idle")
        self.assertEqual(events(self.svc, "grant.not_committed")[-1]["grant"], "assessment.restarted")

    def test_a_start_refused_after_its_record_is_marked_not_started(self):
        with patch.object(self.svc, "_new_scan_usage_locked", side_effect=ValueError("refused late")):
            with self.assertRaises(ValueError):
                self.svc.start(actor="op")
        self.assertEqual(self.svc.a.state, "idle")
        self.assertEqual(events(self.svc, "grant.not_committed")[-1]["grant"], "assessment.start_requested")

    def test_a_missing_pause_record_is_kept_until_it_can_be_written(self):
        with self.svc._lock:
            self.svc.a.state = "running"
        with audit_fails("pause"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.pause("op")
        self.assertIs(cm.exception.applied, True)
        self.assertEqual(self.gaps(), ["pause"])
        self.assertEqual([g["event"] for g in self.svc.snapshot()["audit_gaps"]], ["pause"])
        # survives a restart of the control plane
        self.svc.workers.kill_all()
        self.svc.close()
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1)
        self.svc._may_switch_lab = False
        self.assertEqual(self.gaps(), ["pause"])
        # the next record that can be written also writes the deferred one
        self.svc.register_asset(name="later.lab-alias", kind="Webアプリケーション", environment="検証環境")
        self.assertEqual(self.gaps(), [])
        deferred = events(self.svc, "audit.gap_recorded")
        self.assertEqual(deferred[-1]["gap_event"], "pause")
        self.assertEqual(deferred[-1]["fields"]["actor"], "op")

    def test_a_stop_whose_record_cannot_be_written_leaves_a_gap(self):
        with self.svc._lock:
            self.svc.a.state = "running"
        with audit_fails("emergency_stop"):
            report = self.svc.emergency_stop("op")
        self.assertEqual(self.svc.a.state, "stopped")
        self.assertFalse(report["confirmed"])
        self.assertTrue(report["audit_incomplete"])
        self.assertIn("emergency_stop", self.gaps())

    def test_an_automatic_approval_is_withdrawn_when_its_record_fails(self):
        with audit_fails("approval.auto"), self.assertRaises(Exception):
            self.svc._exec("reproduction_probe", "safe_reproduction",
                           {"url": self.svc.a.target_url, "check": "idor"})
        self.assertEqual(self.svc.approval_store._approvals, {})


    def test_a_preview_is_not_used_up_without_its_record(self):
        with self.svc._lock:
            pv = self.svc._load_previews_locked()
            pv["pv_test"] = {"id": "pv_test", "run_by": "op", "at": time.time(),
                             "first_request_sha256": "b" * 64, "budget_max_calls": 6, "used": False}
            self.svc._save_previews_locked(pv)
        with audit_fails("planner_llm.approved"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc._take_preview_approval("appr", {"preview_id": "pv_test", "max_calls": 2}, ("approver",))
        self.assertIs(cm.exception.applied, False)
        with self.svc._lock:
            self.assertFalse(self.svc._load_previews_locked()["pv_test"]["used"])


class TestFollowUpAuditLog(unittest.TestCase):
    def test_a_record_whose_anchor_cannot_be_published_is_marked(self):
        from aegis.audit_anchor import AnchorError
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog(Path(d) / "audit.jsonl")
            log._anchor = object()                     # an anchor is configured ...
            with patch.object(AuditLog, "_anchor_verify_locked", return_value=0), \
                    patch.object(AuditLog, "_anchor_publish_locked", side_effect=AnchorError("anchor_unavailable")):
                with self.assertRaises(AnchorError):     # ... but cannot take the new head
                    log.record("approval.approved", request="req_x", actor="appr")
            log._anchor = None
            names = [e["event"] for e in log.entries()]
            self.assertEqual(names[-2:], ["approval.approved", "audit.record_not_anchored"])
            self.assertEqual(log.entries()[-1]["fields"]["event"], "approval.approved")


class TestFollowUpRealService(rs.RealServiceBase):
    def test_test_accounts_do_not_stay_live_when_they_cannot_be_saved(self):
        self.onboard()
        with patch.object(self.svc.secrets, "_save_all", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.svc.configure_asset_secrets(host=rs.HOST, tokens={"user_a_token": rs.TOKEN_A,
                                                                       "user_b_token": rs.TOKEN_B}, actor="appr")
        self.assertFalse(self.svc.secrets.has_any_token(rs.HOST))
        self.assertEqual(events(self.svc, "grant.not_committed")[-1]["grant"], "secrets.configured")

    def test_new_addresses_are_not_accepted_without_their_record(self):
        from aegis.ownership import challenge_for_host
        self.onboard()
        ch = challenge_for_host(rs.HOST, self.svc._ownership_secret)
        self.svc._proof_dns_lookup = self._token_lookup(ch)
        ext = self.svc._verified_external_hosts[rs.HOST]
        before = list(ext.get("verified_addresses") or [])
        with audit_fails("asset.addresses_reverified"), self.assertRaises(Exception):
            self.svc._require_addresses_covered_by_proof(rs.HOST, ext, ["203.0.113.9"])
        self.assertEqual(list(self.svc._verified_external_hosts[rs.HOST].get("verified_addresses") or []), before)

    def test_no_ownership_record_for_an_asset_removed_during_the_lookup(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        token = self._token_lookup(ch)

        def lookup_while_removed(name):
            with self.svc._lock:
                self.svc._extra_assets = [x for x in self.svc._extra_assets if x.get("name") != rs.HOST]
            return token(name)
        with self.assertRaises(ValueError):
            self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                            dns_lookup=lookup_while_removed)
        self.assertEqual(events(self.svc, "asset.ownership_verified"), [])
        self.assertNotIn(rs.HOST, self.svc._ownership_proofs)

    def test_a_missing_delete_record_is_kept_until_it_can_be_written(self):
        self.onboard()
        aid = self.svc.snapshot()["asset"]["id"]
        with audit_fails("asset.deleted"), self.assertRaises(AuditWriteFailed) as cm:
            self.svc.delete_asset(aid, actor="appr")
        self.assertIs(cm.exception.applied, True)
        self.assertEqual([g["event"] for g in self.svc.system_status()["audit_gaps"]], ["asset.deleted"])


class TestFollowUpHttp(HttpCase):
    def org_svc(self, who):
        return self.reg.service(who["orgs"][0]["id"])

    def test_pause_over_http_reports_503_applied(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        osvc = self.org_svc(a)
        with osvc._lock:
            osvc.a.state = "running"
        with audit_fails("pause"):
            code, body = self.req(a, "/assessments/scan_001/pause", {}, org=org)
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), True)
        self.assertEqual(osvc.a.state, "paused")

    def test_a_grant_refused_over_http_reports_503_not_applied(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        with audit_fails("assessment.start_requested"):
            code, body = self.req(a, "/assessments/scan_001/start", {}, org=org)
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), False)

    def test_a_member_removal_without_record_leaves_a_gap(self):
        a, b = self.signup("alice"), self.signup("bobby")
        org = a["orgs"][0]["id"]
        token = self.req(a, "/orgs/invites", {"roles": ["runner"]}, org=org)[1]["token"]
        self.assertEqual(self.req(b, "/invites/accept", {"token": token})[0], 200)
        with audit_fails("tenancy.member_removed"):
            self.assertEqual(self.req(a, "/orgs/members/remove", {"name": "bobby"}, org=org)[0], 503)
        self.assertEqual([g["event"] for g in self.org_svc(a).system_status()["audit_gaps"]],
                         ["tenancy.member_removed"])

    def test_an_invitation_whose_store_save_fails_is_marked_not_committed(self):
        a = self.signup("alice")
        org = a["orgs"][0]["id"]
        with patch.object(OrgStore, "_save", side_effect=OSError("disk full")):
            code, body = self.req(a, "/orgs/invites", {"roles": ["viewer"]}, org=org)
        self.assertEqual(code, 500, body)
        self.assertEqual(self.reg.store.invites(org), [])
        self.assertEqual(events(self.org_svc(a), "grant.not_committed")[-1]["grant"], "tenancy.invite_created")

    def test_mfa_reset_is_refused_without_its_record(self):
        admin = self.login("padmin", "padmin-pw-1")
        with audit_fails("operator.mfa_reset"):
            code, body = self.req(admin, "/operators/reset-mfa", {"name": "mfauser"})
        self.assertEqual(code, 503, body)
        self.assertIs(body.get("applied"), False)
        self.assertTrue(self.ops.totp_enabled("mfauser"))

    def test_unlock_is_refused_without_its_record(self):
        with self.ops._lock:
            _, key = self.ops._slot_locked("plain", assign=True)
            self.ops._locked_until[key] = time.time() + 600
        admin = self.login("padmin", "padmin-pw-1")
        with audit_fails("operator.unlocked"):
            code, body = self.req(admin, "/operators/unlock", {"name": "plain"})
        self.assertEqual(code, 503, body)
        self.assertGreater(self.ops._locked_until.get(key, 0), time.time())

    def test_mfa_disable_is_refused_without_its_record(self):
        who = {}
        code, body = self.req(who, "/auth/login", {"name": "mfauser", "password": "mfauser-pw-1",
                                                   "code": totp_code(MFA_SECRET)})
        self.assertEqual(code, 200, body)
        with audit_fails("auth.mfa_disabled"):
            code, body = self.req(who, "/auth/totp/disable", {"current": "mfauser-pw-1",
                                                               "code": totp_code(MFA_SECRET, time.time() + 30)})
        self.assertEqual(code, 503, body)
        self.assertTrue(self.ops.totp_enabled("mfauser"))

    def test_a_password_change_is_refused_without_its_record(self):
        who = self.login("plain", "plain-pw-12")
        with audit_fails("auth.password_changed"):
            code, body = self.req(who, "/auth/password", {"current": "plain-pw-12", "new": "plain-pw-NEW-34"})
        self.assertEqual(code, 503, body)
        self.login("plain", "plain-pw-12")              # the old password still works

    def test_an_org_is_not_created_without_its_record(self):
        a = self.signup("alice")
        before = len(self.reg.store.orgs_of("alice"))
        with audit_fails("tenancy.org_created"):
            code, body = self.req(a, "/orgs", {"name": "B社"})
        self.assertEqual(code, 503, body)
        self.assertEqual(len(self.reg.store.orgs_of("alice")), before)

    def test_sign_up_answers_cleanly_when_its_records_cannot_be_written(self):
        with audit_fails("tenancy.org_created", "auth.registered"):
            who = {}
            code, body = self.req(who, "/auth/register", {"name": "carol", "password": "carol-Passw0rd!"})
        self.assertEqual(code, 200, body)
        self.assertEqual(body["orgs"], [])               # no organization without its record
        self.assertIn("warning", body)
        self.assertIs(body.get("audit_failed"), True)
        self.assertIn("auth.registered", [g["event"] for g in self.svc.platform_audit_gaps()])


# ---- second review follow-up -----------------------------------------------------------
class TestAccountChangesNotSavedAreNotInForce(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.seed = Path(self.tmp.name) / "operators.json"
        self.seed.write_text(json.dumps({"operators": [
            {"name": "padmin", "roles": ["operator", "approver", "admin"],
             "password_hash": hash_password("padmin-pw-1")},
            {"name": "plain", "roles": ["operator"], "password_hash": hash_password("plain-pw-12")},
            {"name": "appr", "roles": ["operator", "approver"], "password_hash": hash_password("appr-pw-123")},
            {"name": "mfauser", "roles": ["operator"], "password_hash": hash_password("mfauser-pw-1"),
             "totp_secret": MFA_SECRET}]}))
        self.ops = OperatorStore(self.seed)

    @contextlib.contextmanager
    def accounts_file_unwritable(self, after: int = 0):
        """Writes of the accounts file fail (after the first `after` of them)."""
        real = self.ops._atomic_write
        seen = [0]

        def write(path, data):
            if Path(path) == self.seed:
                seen[0] += 1
                if seen[0] > after:
                    return False
            return real(path, data)
        with patch.object(self.ops, "_atomic_write", side_effect=write):
            yield

    def test_a_password_that_cannot_be_saved_signs_nobody_in_until_it_is(self):
        # kept (it protects the account) and retried; nobody signs in with either password meanwhile
        with self.accounts_file_unwritable():
            with self.assertRaises(AuthError):
                self.ops.change_password("plain", "plain-pw-12", "plain-pw-NEW-34")
            self.assertFalse(self.ops.trusted())
            for pw in ("plain-pw-12", "plain-pw-NEW-34"):
                with self.assertRaises(AuthError):
                    self.ops.login("plain", pw)

    def test_an_mfa_reset_that_cannot_be_saved_is_not_in_force(self):
        with self.accounts_file_unwritable(), self.assertRaises(AuthError):
            self.ops.reset_totp("mfauser", actor="padmin")
        self.assertTrue(self.ops.totp_enabled("mfauser"))

    def test_an_mfa_disable_that_cannot_be_saved_is_not_in_force(self):
        # the code's use is saved (first write); the switch-off is not
        with self.accounts_file_unwritable(after=1), self.assertRaises(AuthError):
            self.ops.disable_totp("mfauser", "mfauser-pw-1", totp_code(MFA_SECRET))
        self.assertTrue(self.ops.totp_enabled("mfauser"))

    def test_a_role_grant_that_cannot_be_saved_is_not_in_force(self):
        with self.accounts_file_unwritable(), self.assertRaises(AuthError):
            self.ops.set_roles("plain", ["operator", "approver"], actor="padmin")
        self.assertEqual(set(self.ops.roles_of("plain")), {"operator"})

    def test_a_role_removal_that_cannot_be_saved_stays_in_force(self):
        with self.accounts_file_unwritable(), self.assertRaises(AuthError):
            self.ops.set_roles("appr", ["operator"], actor="padmin")
        self.assertEqual(set(self.ops.roles_of("appr")), {"operator"})


class TestAuditGapFile(LabServiceCase):
    def reopen(self):
        self.svc.workers.kill_all()
        self.svc.close()
        with patch.dict(os.environ, {}, clear=True):
            self.svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1)
        self.svc._may_switch_lab = False

    def test_a_gap_that_cannot_be_saved_is_marked_and_reported(self):
        (self.dir / "audit-gaps.json").mkdir()          # the file cannot be written
        with self.svc._lock:
            self.svc.a.state = "running"
        err = io.StringIO()
        with audit_fails("pause"), contextlib.redirect_stderr(err), self.assertRaises(AuditWriteFailed):
            self.svc.pause("op")
        gaps = self.svc.system_status()["audit_gaps"]
        self.assertEqual([(g["event"], g["persisted"]) for g in gaps], [("pause", False)])
        self.assertIn("AUDIT GAP NOT PERSISTED", err.getvalue())

    def test_a_corrupt_gap_file_is_moved_aside_and_reported(self):
        for content in ("{not json", '{"event": "pause"}'):
            path = self.dir / "audit-gaps.json"
            path.write_text(content, encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()):
                self.reopen()
            aside = [p for p in self.dir.iterdir() if p.name.startswith("audit-gaps.json.corrupt-")]
            self.assertTrue(aside, content)
            self.assertIn(content, [p.read_text(encoding="utf-8") for p in aside])
            gaps = self.svc.system_status()["audit_gaps"]
            self.assertIn(("audit_gaps.corrupt", True), [(g["event"], g["invalid"]) for g in gaps])
            for p in aside:
                p.unlink()
            self.svc.register_asset(name="flush.lab-alias", kind="Webアプリケーション", environment="検証環境")

    def test_entries_without_an_event_are_kept_and_flagged(self):
        (self.dir / "audit-gaps.json").write_text(json.dumps(
            [{"no_event": 1}, {"event": "pause", "fields": {"actor": "op"}, "at": 1.0, "log": "org"}]))
        with contextlib.redirect_stderr(io.StringIO()):
            self.reopen()
        gaps = self.svc.system_status()["audit_gaps"]
        self.assertEqual([(g["event"], g["invalid"]) for g in gaps],
                         [("audit_gaps.invalid_entry", True), ("pause", False)])


class TestPlatformGaps(HttpCase):
    def platform_gap(self):
        with audit_fails("auth.registered"):
            self.assertEqual(self.req({}, "/auth/register", {"name": "carol", "password": "carol-Passw0rd!"})[0],
                             200)
        self.assertEqual([g["event"] for g in self.svc.platform_audit_gaps()], ["auth.registered"])

    def test_platform_gaps_are_shown_to_platform_admins_only(self):
        self.platform_gap()
        # the deferred record stays unwritable here, so the gap is still open while it is looked at
        hold = audit_fails("audit.gap_recorded")
        hold.__enter__()
        self.addCleanup(hold.__exit__, None, None, None)
        member = self.login("plain", "plain-pw-12")         # a member of the default organization
        for path in ("/system/status", "/assessments/scan_001"):
            code, body = self.req(member, path, org="default")
            self.assertEqual(code, 200, body)
            self.assertNotIn("auth.registered", json.dumps(body))
        admin = self.login("padmin", "padmin-pw-1")
        code, body = self.req(admin, "/system/status", org="default")
        self.assertEqual(code, 200, body)
        self.assertEqual([g["event"] for g in body["platform_audit_gaps"]], ["auth.registered"])

    def test_platform_gaps_are_written_after_the_next_platform_record(self):
        self.platform_gap()
        self.login("plain", "plain-pw-12")                  # auth.login: a platform record
        deadline = time.time() + 5
        while self.svc.platform_audit_gaps() and time.time() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.svc.platform_audit_gaps(), [])
        self.assertIn("auth.registered", [e["fields"]["gap_event"] for e in self.reg.platform_audit.entries()
                                          if e["event"] == "audit.gap_recorded"])


if __name__ == "__main__":
    unittest.main()
