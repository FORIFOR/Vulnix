"""Separation of duties for L2 is ON by default (owner decision 2026-11-23, option A).

- the requester never approves their own L2: the legacy run's approvals (whoever
  started the run) and manual ARTEX L2 items (whoever asked for the plan);
- a self-registered identity never approves L2;
- one person alone leaves the L2 pending: nothing relaxes the rule on its own;
- switching it off (AEGIS_SEPARATE_L2_APPROVER=0) is for an authorized-lab-only setup
  and is refused anywhere else; a real site requires it whatever the setting says.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import (ApproverRequired, AssessmentService, SeparationConfigError,
                              separate_l2_approver_from_env)
from tests import TEST_CONFINEMENT

LAB_ONLY = {"AEGIS_SEPARATE_L2_APPROVER": "0", "VULNIX_REAL_SERVICE_DIAGNOSIS": "0"}


class TestSetting(unittest.TestCase):
    def test_on_unless_switched_off(self):
        self.assertTrue(separate_l2_approver_from_env({}))
        for v in ("1", "", "true", "off", "no", " 1 "):
            self.assertTrue(separate_l2_approver_from_env({"AEGIS_SEPARATE_L2_APPROVER": v}), v)

    def test_switching_off_is_for_an_authorized_lab_only_setup(self):
        self.assertFalse(separate_l2_approver_from_env(LAB_ONLY))
        refused = {
            "real-site diagnosis on by default": {"AEGIS_SEPARATE_L2_APPROVER": "0"},
            "real-site L1": {**LAB_ONLY, "VULNIX_REAL_SERVICE_DIAGNOSIS": "l1"},
            "real-site L2": {**LAB_ONLY, "VULNIX_REAL_SERVICE_DIAGNOSIS": "1"},
            "public sign-up": {**LAB_ONLY, "VULNIX_PUBLIC_SIGNUP": "1"},
            "public site": {**LAB_ONLY, "VULNIX_PUBLIC_MODE": "1"},
            "production": {**LAB_ONLY, "AEGIS_ENV": "production"},
        }
        for name, env in refused.items():
            with self.subTest(name), self.assertRaises(SeparationConfigError):
                separate_l2_approver_from_env(env)

    def test_the_service_refuses_to_start_with_it_switched_off_outside_a_lab(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.dict(os.environ, {"AEGIS_SEPARATE_L2_APPROVER": "0",
                                        "VULNIX_REAL_SERVICE_DIAGNOSIS": "l1"}), \
                self.assertRaises(SeparationConfigError):
            AssessmentService(Path(tmp), 1, l2_confinement=TEST_CONFINEMENT)

    def test_the_server_refuses_to_start_with_it_switched_off_outside_a_lab(self):
        from aegis import server
        # VULNIX_NO_ENV_LOCAL=1 (tests/__init__.py) keeps main() from reading .env.local
        with patch.dict(os.environ, {"AEGIS_SEPARATE_L2_APPROVER": "0", "VULNIX_PUBLIC_SIGNUP": "1",
                                     "VULNIX_REAL_SERVICE_DIAGNOSIS": "0", "VULNIX_NO_ENV_LOCAL": "1"}), \
                patch("sys.argv", ["aegis.server"]), \
                patch.object(server, "start_lab", side_effect=AssertionError("must not get this far")), \
                self.assertRaises(SystemExit) as cm:
            server.main()
        self.assertIn("認可ラボ専用", str(cm.exception))


class TestEnvLocal(unittest.TestCase):
    """Only the operator's real environment may switch separation off (.env.local is
    writable by the service user), judged against the real-site mode the server runs with."""

    def test_env_local_cannot_switch_it_off(self):
        from aegis import server
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / ".env.local"
            f.write_text("AEGIS_SEPARATE_L2_APPROVER=0\nVULNIX_TEST_MARKER_SEP=1\n")
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("AEGIS_SEPARATE_L2_APPROVER", None)
                os.environ.pop("VULNIX_TEST_MARKER_SEP", None)
                server._load_env_local(f)                    # an explicit file (never the real one)
                self.assertEqual(os.environ.get("VULNIX_TEST_MARKER_SEP"), "1")   # the file was read
                self.assertNotIn("AEGIS_SEPARATE_L2_APPROVER", os.environ)

    def test_the_check_uses_the_mode_the_server_runs_with(self):
        # the process runs with real-site L1 (read at import); a later "0" in the
        # environment (e.g. from .env.local) does not make it a lab-only setup
        from aegis import server
        with patch.dict(os.environ, {"AEGIS_SEPARATE_L2_APPROVER": "0", "VULNIX_REAL_SERVICE_DIAGNOSIS": "0",
                                     "VULNIX_NO_ENV_LOCAL": "1"}), \
                patch.object(server, "_REAL_SITE_MODE", "l1"), patch("sys.argv", ["aegis.server"]), \
                patch.object(server, "start_lab", side_effect=AssertionError("must not get this far")), \
                self.assertRaises(SystemExit):
            server.main()


class TestLegacyApproval(unittest.TestCase):
    """The legacy run raises its L2 approvals itself; the requester is who started it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AEGIS_SEPARATE_L2_APPROVER", None)
            self.svc = AssessmentService(Path(self._tmp.name), 1, l2_confinement=TEST_CONFINEMENT)

    def tearDown(self):
        self.svc.workers.kill_all()
        self._tmp.cleanup()

    def _pending(self, started_by):
        self.svc.a.started_by = started_by
        self.svc.a.state = "running"
        self.svc.a.approvals["req_0000abcd"] = {
            "id": "req_0000abcd", "action": "safe_reproduction", "risk_level": "L2",
            "title": "t", "description": "d", "status": "pending", "decided_by": None,
            "decided_at": None, "approval_ref": None}
        return "req_0000abcd"

    def _denials(self):
        return [e["fields"] for e in self.svc.audit.entries() if e["event"] == "approval.denied"]

    def test_on_by_default(self):
        self.assertTrue(self.svc.separate_l2_approver)

    def test_who_started_the_run_cannot_approve_its_l2(self):
        aid = self._pending("alice")
        with self.assertRaises(ApproverRequired):
            self.svc.decide_approval(aid, "approve", "alice")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "pending")     # stays waiting
        self.assertEqual(self._denials()[-1]["reason"], "separation of duties")
        self.svc.decide_approval(aid, "approve", "bob")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "approved")

    def test_a_rejection_is_always_possible(self):
        aid = self._pending("alice")
        self.svc.decide_approval(aid, "reject", "alice")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "rejected")

    def test_an_unknown_requester_is_not_a_second_person(self):
        aid = self._pending(None)
        with self.assertRaises(ApproverRequired):
            self.svc.decide_approval(aid, "approve", "bob")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "pending")

    def test_a_self_registered_identity_cannot_approve(self):
        aid = self._pending("alice")
        with self.assertRaises(ApproverRequired):
            self.svc.decide_approval(aid, "approve", "mallory", approver_class="self")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "pending")
        self.assertEqual(self._denials()[-1]["reason"], "self-registered approver")

    def test_a_self_registered_approver_with_a_second_factor_may_approve_on_the_lab_only(self):
        # owner decision 2026-11-23: refused on real sites; on the bundled lab allowed
        # only with the second factor on; the requester is refused in every case
        self.assertFalse(self.svc._approver_refused(None))
        self.assertFalse(self.svc._approver_refused("registered"))
        self.assertFalse(self.svc._approver_refused("self_mfa"))           # the lab
        self.assertTrue(self.svc._approver_refused("self"))
        self.assertTrue(self.svc._approver_refused("anything else"))
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            self.assertTrue(self.svc._approver_refused("self_mfa"))        # a real site
            self.assertFalse(self.svc._approver_refused("registered"))
        with patch.object(self.svc, "_in_ownership_flow", return_value=True):
            self.assertTrue(self.svc._approver_refused("self_mfa"))
        aid = self._pending("alice")
        self.svc.decide_approval(aid, "approve", "bob", approver_class="self_mfa")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "approved")

    def test_a_self_registered_approver_with_a_second_factor_is_still_not_the_requester(self):
        aid = self._pending("alice")
        with self.assertRaises(ApproverRequired):
            self.svc.decide_approval(aid, "approve", "alice", approver_class="self_mfa")
        self.assertEqual(self.svc.a.approvals[aid]["status"], "pending")

    def test_the_requester_survives_a_restart_of_the_control_plane(self):
        self.svc.a.started_by = "alice"
        with self.svc._lock:
            self.svc._save_state_locked()
        again = AssessmentService(Path(self._tmp.name), 1, l2_confinement=TEST_CONFINEMENT)
        try:
            self.assertEqual(again.a.started_by, "alice")
        finally:
            again.workers.kill_all()

    def test_switched_off_in_a_lab_only_setup_the_old_behaviour_returns(self):
        with patch.dict(os.environ, LAB_ONLY):
            svc = AssessmentService(Path(self._tmp.name) / "lab", 1, l2_confinement=TEST_CONFINEMENT)
        try:
            self.assertFalse(svc.separate_l2_approver)
            svc.a.started_by, svc.a.state = "alice", "running"
            svc.a.approvals["req_0000beef"] = {"id": "req_0000beef", "action": "safe_reproduction",
                                               "risk_level": "L2", "title": "t", "description": "d",
                                               "status": "pending", "decided_by": None,
                                               "decided_at": None, "approval_ref": None}
            svc.decide_approval("req_0000beef", "approve", "alice")
            self.assertEqual(svc.a.approvals["req_0000beef"]["status"], "approved")
        finally:
            svc.workers.kill_all()

    def test_a_real_site_requires_it_whatever_the_setting(self):
        self.svc.separate_l2_approver = False
        with patch.object(self.svc, "_is_external_service_asset", return_value=True):
            self.assertTrue(self.svc._separation_required())
        with patch.object(self.svc, "_in_ownership_flow", return_value=True):
            self.assertTrue(self.svc._separation_required())
        self.assertFalse(self.svc._separation_required())


if __name__ == "__main__":
    unittest.main()
