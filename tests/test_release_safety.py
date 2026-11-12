"""Release checks: revoked authority never comes back unapproved, scope expiry
stops running workers, and - on Linux with the real kernel confinement - stop,
revocation and expiry kill a confined L2 worker and confirm it.

All traffic goes to loopback stand-ins (tests.test_real_service.FakeService)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import TEST_CONFINEMENT
from aegis import assessment as assessment_mod
from aegis.assessment import AssessmentService
from aegis.confinement import KernelConfinement
from aegis.runtime import WorkerPool
from tests.test_fail_closed import PersistenceBase
from tests.test_real_service import HOST, LAB_PORT, PROFILE_DIRS, TOKEN_A, TOKEN_B

REPO = Path(__file__).resolve().parent.parent
SLEEPER = [sys.executable, "-I", "-c", "import time; time.sleep(60)"]

CHILD = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService
from tests.test_real_service import PROFILE_DIRS
svc = AssessmentService(Path(sys.argv[2]), 19421, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                        l2_confinement=TEST_CONFINEMENT, revocation_marker_dirs=[Path(sys.argv[3])])
if sys.argv[4] == "close":
    print("CLEAN" if svc.close() else "UNCLEAN", flush=True)
os._exit(0)                     # "kill" leaves without any shutdown
"""


class ReleaseBase(PersistenceBase):
    def other_process(self, how):
        script = Path(tempfile.mkdtemp()) / "child.py"
        self.addCleanup(shutil.rmtree, script.parent, True)
        script.write_text(CHILD)
        self.assertTrue(self.svc.close())                     # this process lets go of the directory cleanly
        _ = assessment_mod._DATA_DIR_LOCKS.pop(str(self.dir.resolve()), None)
        if _ is not None:
            _.close()
        p = subprocess.run([sys.executable, str(script), str(REPO), str(self.dir), str(self.markers), how],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        return p.stdout.strip()

    def reopen_in_this_process(self):
        assessment_mod._LAST_INSTANCE.pop(str(self.dir.resolve()), None)   # nothing to ask in-process
        return self.open()


class TestRevokedAuthorityNeverComesBackUnapproved(ReleaseBase):
    def lock_everything(self):
        for f in self.dir.iterdir():
            if f.is_file() and f.name != "audit.jsonl":
                os.chmod(f, 0o400)
        os.chmod(self.dir, 0o500)
        os.chmod(self.markers, 0o500)
        self.addCleanup(os.chmod, self.markers, 0o700)

    def test_revocation_written_nowhere_then_disk_recovers_then_restart(self):
        """The case that previously brought the revoked scope back."""
        self.onboard()
        self.lock_everything()
        self.revoke()
        self.assertEqual(list(self.markers.glob("*.revoked")), [])     # the revocation is written nowhere
        self.unlock()
        os.chmod(self.markers, 0o700)
        self.svc.workers.kill_all()
        again = self.reopen_in_this_process()                          # as a new process would see it
        self.assertEqual(again.ledger.rejected_reason, "")             # the stale ledger itself verifies...
        self.assertIn(HOST, again._verified_external_hosts)
        self.assertIsNone(again._external_entry(HOST))                 # ...but grants nothing
        self.assertTrue(self.events("authority.held_after_unclean_shutdown", again))
        self.assertIn("保留", again.snapshot()["authority_notice"])
        card = next(x for x in again.assets() if x["name"] == HOST)
        self.assertFalse(card["scope_confirmed"])
        self.assertEqual(again._resolve_host(HOST), [])
        with self.assertRaises(ValueError):                            # the held proof is not a proof
            again.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                      allow_loopback_test=True)
        again.workers.kill_all()

    def test_a_killed_control_plane_needs_re_approval(self):
        self.onboard()
        self.assertEqual(self.other_process("kill"), "")
        again = self.reopen_in_this_process()
        self.assertIsNone(again._external_entry(HOST))
        self.assertTrue(self.events("authority.held_after_unclean_shutdown", again))
        # re-approval: a new ownership proof and a new scope confirmation
        self.svc = again
        again._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        ch = again.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.assertTrue(again.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                                     dns_lookup=self._token_lookup(ch))["verified"])
        again.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                  allow_loopback_test=True)
        self.assertIsNotNone(again._external_entry(HOST))
        self.assertEqual(self.run_l1()["state"], "completed")

    def test_a_clean_shutdown_keeps_the_scope(self):
        self.onboard()
        self.assertEqual(self.other_process("close"), "CLEAN")
        again = self.reopen_in_this_process()
        self.assertIsNotNone(again._external_entry(HOST))
        self.assertEqual(self.events("authority.held_after_unclean_shutdown", again), [])
        again.workers.kill_all()

    def test_close_is_not_clean_while_a_reduction_is_unsaved(self):
        self.onboard()
        self.lock_everything()
        self.revoke()
        self.assertFalse(self.svc.close())
        self.assertTrue((self.dir / "session.open").exists())

    def test_close_is_not_clean_while_a_worker_is_not_confirmed_dead(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            self.assertFalse(self.svc.close())
        self.assertTrue((self.dir / "session.open").exists())
        os.killpg(pid, 9)
        t.join(10)

    def test_an_unreadable_session_record_holds_everything(self):
        self.onboard()
        self.svc.workers.kill_all()
        (self.dir / "session.open").write_text("{ broken")
        again = self.reopen_in_this_process()
        self.assertIsNone(again._external_entry(HOST))
        again.workers.kill_all()

    def test_a_session_record_that_cannot_be_written_holds_everything(self):
        self.onboard()
        self.assertTrue(self.svc.close())
        real = os.open

        def no_session(path, flags, *a, **kw):
            if str(path).endswith("session.open.tmp"):
                raise PermissionError("read-only")
            return real(path, flags, *a, **kw)
        with patch("aegis.assessment.os.open", side_effect=no_session):
            again = self.reopen_in_this_process()
        self.assertIsNone(again._external_entry(HOST))
        self.assertIsNotNone(again._persist_error)
        again.workers.kill_all()

    def test_in_process_restart_after_clean_use_keeps_the_scope(self):
        self.onboard()
        self.assertIsNotNone(self.restart()._external_entry(HOST))


class TestScopeExpiryStopsRunningWorkers(ReleaseBase):
    def expire(self):
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1

    def test_expiry_kills_the_running_worker_and_confirms_it(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        epoch = self.svc.gateway._launch_epoch
        t0 = time.time()
        self.expire()
        t.join(10)
        self.assertFalse(t.is_alive())
        self.assertLess(time.time() - t0, 6)
        self.assertFalse(WorkerPool.group_alive(pid))
        self.assertGreater(self.svc.gateway._launch_epoch, epoch)       # waiting requests cancelled
        end = time.time() + 10
        while time.time() < end and not self.events("scope.expired"):   # recorded after the confirmation
            time.sleep(0.05)
        ev = self.events("scope.expired")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["fields"]["workers_stopped"], [pid])
        self.assertEqual(ev[0]["fields"]["unconfirmed"], [])
        self.assertIn("期限", self.svc.snapshot()["authority_notice"])
        time.sleep(1.2)
        self.assertEqual(len(self.events("scope.expired")), 1)        # handled once

    def test_a_worker_that_survives_expiry_is_recorded(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            self.expire()
            end = time.time() + 15
            while time.time() < end and not self.events("scope.expired"):
                time.sleep(0.1)
            self.assertEqual(self.events("scope.expired")[0]["fields"]["unconfirmed"], [pid])
            self.assertEqual(self.svc.system_status()["unstopped_workers"]["pids"], [pid])
        os.killpg(pid, 9)
        t.join(10)

    def test_a_run_in_progress_at_expiry_ends_failed_and_sends_nothing_more(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        self.fake.mode = "hang"
        out = {}
        th = threading.Thread(target=lambda: out.update(snap=self.svc.verify_finding(
            "f_ex_idor", actor="appr", roles={"approver"})))
        th.start()
        self.assertTrue(self.fake.hanging.wait(15))
        seen = len(self.fake.seen)
        self.expire()
        th.join(30)
        self.assertFalse(th.is_alive())
        time.sleep(1)
        self.assertEqual(len(self.fake.seen), seen)
        self.assertNotEqual(self.finding("f_ex_idor")["verdict"], "proven")
        self.assertEqual(self.events("scope.expired")[0]["fields"]["unconfirmed"], [])

    def test_an_inactive_assets_expiry_does_not_touch_lab_workers(self):
        self.onboard()
        self.svc.select_asset("lab")
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        self.expire()
        time.sleep(1.5)
        self.assertTrue(WorkerPool.group_alive(pid))
        self.svc.workers.terminate_active()
        t.join(10)


def _linux_confinement() -> bool:
    return sys.platform.startswith("linux") and KernelConfinement().status()["ok"]


@unittest.skipUnless(_linux_confinement(), "needs Linux with cgroup v2, nft and root or passwordless sudo")
class TestOnLinuxWithTheRealKernelConfinement(ReleaseBase):
    """End to end on the real kernel: a real-service L2 worker carrying test tokens
    runs inside per-run cgroup + nftables confinement, and is killed and confirmed
    dead by an emergency stop, a revocation, and scope expiry. Loopback only."""

    def setUp(self):
        super().setUp()
        self.svc.workers.kill_all()
        self.svc = self.open(l2_confinement=KernelConfinement())

    def start_hanging_l2(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        self.fake.mode = "hang"
        self.out = {}

        def run():
            try:
                self.out["snap"] = self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
            except Exception as e:
                self.out["err"] = e
        self.th = threading.Thread(target=run)
        self.th.start()
        self.assertTrue(self.fake.hanging.wait(30), self.out)
        applied = self.events("confinement.applied")
        self.assertTrue(applied, "the L2 worker was not started inside kernel confinement")
        self.cgroup = applied[-1]["fields"]["cgroup"]
        self.assertGreaterEqual(applied[-1]["fields"]["kernel_dropped_packets"], 1)
        self.assertTrue((Path("/sys/fs/cgroup") / self.cgroup).exists())
        procs = (Path("/sys/fs/cgroup") / self.cgroup / "cgroup.procs").read_text().split()
        self.assertTrue(procs, "the worker is not in its cgroup")
        self.seen_before = len(self.fake.seen)

    def assert_confined_worker_gone(self):
        self.th.join(30)
        self.assertFalse(self.th.is_alive())
        end = time.time() + 10
        while time.time() < end and (Path("/sys/fs/cgroup") / self.cgroup).exists():
            time.sleep(0.1)
        self.assertFalse((Path("/sys/fs/cgroup") / self.cgroup).exists(), "the cgroup was left behind")
        tables = subprocess.run(["sudo", "-n", "nft", "list", "tables"], capture_output=True, text=True).stdout
        self.assertNotIn(self.cgroup, tables, "the nftables table was left behind")
        self.assertIsNone(self.svc.system_status()["unstopped_workers"])
        time.sleep(0.5)
        self.assertEqual(len(self.fake.seen), self.seen_before)
        self.assertNotEqual(self.finding("f_ex_idor")["verdict"], "proven")

    def test_tokens_go_only_from_inside_the_confinement(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
        applied = self.events("confinement.applied")
        self.assertEqual(len(applied), 1)
        self.assertTrue(applied[0]["fields"]["probe_in_cgroup"])
        self.assertNotIn(applied[0]["fields"]["worker_uid"], (0, os.getuid()))
        for key in ("separate_uid", "no_capabilities", "protected_files_denied"):
            self.assertTrue(applied[0]["fields"][key], applied[0]["fields"])
        self.assertGreaterEqual(applied[0]["fields"]["protected_files"], 4)   # key, ledger, state, secrets...
        print(f"\n[linux-e2e] confined L2 worker ran as uid {applied[0]['fields']['worker_uid']} "
              f"(control plane uid {os.getuid()}); dropped={applied[0]['fields']['kernel_dropped_packets']}")
        self.assertTrue([a for _, a in self.fake.seen if a])
        self.assertEqual(self.finding("f_ex_idor")["verdict"], "proven")

    def test_emergency_stop_kills_the_confined_worker(self):
        self.start_hanging_l2()
        rep = self.svc.emergency_stop("appr")
        self.assertTrue(rep["confirmed"], rep)
        self.assertEqual(rep["survivors"], [])
        self.assert_confined_worker_gone()

    def test_revocation_kills_the_confined_worker(self):
        self.start_hanging_l2()
        self.revoke()                                   # returns only after the stop is confirmed
        self.assert_confined_worker_gone()

    def test_deletion_during_an_l2_run_is_refused_then_works_after_a_stop(self):
        self.start_hanging_l2()
        with self.assertRaises(ValueError):             # never "deleted" while its worker is running
            self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertIn(HOST, [x["name"] for x in self.svc.assets()])
        rep = self.svc.emergency_stop("appr")
        self.assertTrue(rep["confirmed"], rep)
        self.assert_confined_worker_gone()
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertNotIn(HOST, [x["name"] for x in self.svc.assets()])

    def test_expiry_kills_the_confined_worker(self):
        self.start_hanging_l2()
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        end = time.time() + 15
        while time.time() < end and not self.events("scope.expired"):
            time.sleep(0.1)
        self.assertEqual(self.events("scope.expired")[0]["fields"]["unconfirmed"], [])
        self.assert_confined_worker_gone()


if __name__ == "__main__":
    unittest.main()


# ---- findings of the pre-release review --------------------------------------
class TestPreReleaseReviewFindings(ReleaseBase):
    def test_a_ledger_restored_from_a_backup_is_refused(self):
        self.onboard()
        backup = {n: (self.dir / n).read_bytes() for n in ("authority.ledger", "authority.epoch")}
        self.revoke()                                       # saved normally
        self.assertTrue(self.svc.close())
        for n, raw in backup.items():                       # both files put back from the backup
            (self.dir / n).write_bytes(raw)
        again = self.reopen_in_this_process()
        self.assertIn("backup", again.ledger.rejected_reason)
        self.assertIsNone(again._external_entry(HOST))
        self.assertIn(HOST, again._real_service_hosts)
        again.workers.kill_all()

    def test_a_moved_data_directory_still_finds_its_records(self):
        self.onboard()
        key1 = self.svc.ledger.marker_key()
        self.assertTrue(self.svc.close())
        moved = Path(tempfile.mkdtemp()) / "moved"
        shutil.copytree(self.dir, moved)
        (moved / ".lock").unlink(missing_ok=True)
        svc = AssessmentService(moved, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                                l2_confinement=TEST_CONFINEMENT, revocation_marker_dirs=[self.markers])
        self.assertEqual(svc.ledger.marker_key(), key1)
        svc.workers.kill_all()

    def test_expired_real_service_is_never_shown_as_the_demo_lab(self):
        self.onboard()
        self.run_l1()
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        end = time.time() + 10
        while time.time() < end and not self.events("scope.expired"):
            time.sleep(0.05)
        snap = self.svc.snapshot()
        self.assertTrue(snap["is_external_service"])
        self.assertFalse(snap["scope_active"])
        self.assertFalse(snap["demo"])
        self.assertIsNone(snap["history"])
        self.assertEqual(snap["authorization"]["status"], "missing")
        self.assertNotIn("127.0.0.1", snap["lab_endpoint"])
        self.assertFalse(next(x for x in self.svc.assets() if x["name"] == HOST)["scope_confirmed"])

    def test_a_refused_restart_keeps_the_real_results(self):
        self.onboard()
        before = self.run_l1()
        evidence = [f["id"] for f in before["findings"] if f.get("evidence")]
        self.assertTrue(evidence)
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        with self.assertRaises(ValueError):
            self.svc.restart("appr")
        snap = self.svc.snapshot()
        self.assertEqual([f["id"] for f in snap["findings"] if f.get("evidence")], evidence)
        self.assertFalse({"f_banner", "f_idor", "f_sqli"} & {f["id"] for f in snap["findings"]})

    def test_a_workspace_reset_of_a_real_service_never_loads_lab_fixtures(self):
        self.onboard()
        self.svc._verified_external_hosts[HOST]["held_since"] = time.time()
        with self.svc._lock:
            self.svc._reset_workspace_locked()
        self.assertFalse({"f_banner", "f_idor", "f_sqli"} & set(self.svc.a.findings))

    def test_an_emergency_stop_holds_when_the_audit_log_cannot_be_written(self):
        self.svc.select_asset("lab")
        with patch.object(self.svc.audit, "record", side_effect=OSError("read-only")):
            rep = self.svc.gateway.emergency_stop("appr")
        self.assertEqual(self.svc.gateway.state.value, "stopped")
        self.assertFalse(rep.confirmed)

    def test_the_proof_file_must_contain_the_token_as_a_line(self):
        from aegis.ownership import proof_file_matches
        tok = "vulnix-verify=abc123"
        self.assertTrue(proof_file_matches(tok + "\n", tok))
        self.assertTrue(proof_file_matches("# comment\n  " + tok + "  \n", tok))
        self.assertFalse(proof_file_matches(f"<p>not found: {tok}</p>", tok))
        self.assertFalse(proof_file_matches(tok + "x", tok))
        self.assertFalse(proof_file_matches("", ""))


class TestCredentialReductionsAreNotSilentlyLost(unittest.TestCase):
    def setUp(self):
        from aegis.operators import OperatorStore, hash_password
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / "operators.json").write_text(json.dumps({"operators": [
            {"name": "root", "display": "r", "roles": ["operator", "admin"], "password_hash": hash_password("root-password-1")},
            {"name": "op", "display": "o", "roles": ["operator"], "password_hash": hash_password("op-password-12")}]}))
        self.Store = OperatorStore
        self.store = OperatorStore(self.tmp / "operators.json")

    def failing_writes(self):
        return patch.object(self.store, "_atomic_write", return_value=False)

    def test_logout_that_cannot_be_saved_is_reported(self):
        from aegis.operators import AuthError
        sess = self.store.login("op", "op-password-12")
        with self.failing_writes():
            with self.assertRaises(AuthError):
                self.store.logout(sess.token)
        self.assertIsNone(self.store.resolve(sess.token))        # gone in this process all the same

    def test_password_change_that_cannot_be_saved_is_reported(self):
        from aegis.operators import AuthError
        with self.failing_writes():
            with self.assertRaises(AuthError):
                self.store.change_password("op", "op-password-12", "new-password-123")

    def test_mfa_reset_that_cannot_be_saved_is_reported(self):
        from aegis.operators import AuthError
        with self.failing_writes():
            with self.assertRaises(AuthError):
                self.store.reset_totp("op", actor="root")


# ---- findings of the review of the release fixes ------------------------------
class TestSessionRecordIsAPrecondition(ReleaseBase):
    def test_no_grant_and_no_traffic_until_the_session_record_is_written(self):
        self.onboard()
        self.assertTrue(self.svc.close())
        real = os.open

        def no_session(path, flags, *a, **kw):
            if str(path).endswith("session.open.tmp"):
                raise PermissionError("no space")
            return real(path, flags, *a, **kw)
        with patch("aegis.assessment.os.open", side_effect=no_session):
            svc = self.reopen_in_this_process()
            self.svc = svc
            svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
            self.assertIsNone(svc._external_entry(HOST))
            # saving the state works, but the session record still cannot be written:
            # nothing may be re-approved in this session
            with self.assertRaises(ValueError):
                ch = svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
            self.assertIsNotNone(svc._persist_error)
        # once the record can be written, re-approval works - and the record exists
        ch = svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        self.assertTrue((self.dir / "session.open").exists())
        self.assertTrue(svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr",
                                                   dns_lookup=self._token_lookup(ch))["verified"])
        svc.confirm_asset_scope(url_or_host=self.url, approver="appr", activate_workspace=True,
                                allow_loopback_test=True)
        self.assertIsNotNone(svc._external_entry(HOST))


class TestEarlierVersionsMarkers(ReleaseBase):
    def test_a_marker_written_by_the_previous_version_is_still_honoured(self):
        import hashlib
        import hmac as hmac_mod
        self.onboard()
        led = self.svc.ledger
        gen = led.generation
        key = led.legacy_marker_key()
        mac = hmac_mod.new(led._key, f"revoked|{key}|{gen}".encode(), hashlib.sha256).hexdigest()
        (self.markers / f"{key}.revoked").write_text(json.dumps({"epochs": [gen], "mac": mac}))
        self.assertTrue(self.svc.close())
        again = self.reopen_in_this_process()
        self.assertIn("revocation", again.ledger.rejected_reason)
        self.assertIsNone(again._external_entry(HOST))
        again.workers.kill_all()

    def test_an_unverifiable_marker_of_the_previous_version_refuses(self):
        self.onboard()
        (self.markers / f"{self.svc.ledger.legacy_marker_key()}.revoked").write_text('{"epochs": ["1:x"], "mac": "no"}')
        self.assertTrue(self.svc.close())
        again = self.reopen_in_this_process()
        self.assertIsNone(again._external_entry(HOST))
        again.workers.kill_all()


class TestRestartKeepsTheStopWhileWorkersSurvive(ReleaseBase):
    def test_restart_with_a_survivor_does_not_lift_the_stop(self):
        self.svc.select_asset("lab")
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):
            self.svc.emergency_stop("appr")
            with self.assertRaises(ValueError):
                self.svc.restart("appr")
            self.assertEqual(self.svc.snapshot()["state"], "stopped")
            self.assertEqual(self.svc.gateway.state.value, "stopped")
        os.killpg(pid, 9)
        t.join(10)


class TestFailedStartDoesNotHold(unittest.TestCase):
    def test_a_busy_port_closes_the_service_cleanly(self):
        import socket
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen(1)
        self.addCleanup(busy.close)
        data = Path(tempfile.mkdtemp())
        markers = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, data, True)
        self.addCleanup(shutil.rmtree, markers, True)
        p = subprocess.run([sys.executable, "-m", "aegis.server", "--port", str(busy.getsockname()[1]),
                            "--lab-port", "19431", "--data-dir", str(data)],
                           cwd=str(REPO), capture_output=True, text=True, timeout=120,
                           env={**os.environ, "VULNIX_REVOCATION_MARKER_DIR": str(markers)})
        self.assertNotEqual(p.returncode, 0)
        self.assertFalse((data / "session.open").exists(), p.stderr[-1500:])


class TestUnsavedLogoutOverHttp(unittest.TestCase):
    def test_the_response_says_so_and_clears_the_cookie(self):
        import urllib.error
        import urllib.request
        from http.server import ThreadingHTTPServer
        from aegis.operators import OperatorStore
        from aegis.server import make_handler
        from tests.test_access_control import seed
        data = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, data, True)
        svc = AssessmentService(data, LAB_PORT, verify_seconds=0.1, l2_confinement=TEST_CONFINEMENT,
                                revocation_marker_dirs=[Path(tempfile.mkdtemp())])
        self.addCleanup(svc.workers.kill_all)
        ops = OperatorStore(seed(data))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(svc, ops))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        api = f"http://127.0.0.1:{srv.server_port}/api"
        hdr = {"Content-Type": "application/json", "X-Aegis-Request": "1"}
        with urllib.request.urlopen(urllib.request.Request(
                api + "/auth/login", json.dumps({"name": "op", "password": "op-password"}).encode(), hdr)) as r:
            cookie = r.headers["Set-Cookie"].split(";")[0]
        with patch.object(ops, "_atomic_write", return_value=False):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(api + "/auth/logout", b"{}", {**hdr, "Cookie": cookie}))
        self.assertEqual(cm.exception.code, 500)
        self.assertIn("Max-Age=0", cm.exception.headers.get("Set-Cookie", ""))
        self.assertFalse(json.loads(cm.exception.read())["logout_saved"])


class TestProofFileWithBom(unittest.TestCase):
    def test_a_bom_does_not_hide_the_token(self):
        from aegis.ownership import proof_file_matches
        self.assertTrue(proof_file_matches("﻿vulnix-verify=abc\n", "vulnix-verify=abc"))


# ---- auth state: save failures and restarts; expiry retries ---------------------
class AuthBase(unittest.TestCase):
    def setUp(self):
        from aegis.operators import OperatorStore, hash_password
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "operators.json").write_text(json.dumps({"operators": [
            {"name": "root", "display": "r", "roles": ["operator", "admin"], "password_hash": hash_password("root-password-1")},
            {"name": "op", "display": "o", "roles": ["operator"], "password_hash": hash_password("op-password-12")}]}))
        self.Store = OperatorStore
        self.store = OperatorStore(self.dir / "operators.json")

    def restart(self):
        self.store = self.Store(self.dir / "operators.json")
        return self.store

    def failing(self, *names):
        real = self.store._atomic_write

        def write(path, data):
            if Path(path).name in names:
                return False
            return real(path, data)
        return patch.object(self.store, "_atomic_write", side_effect=write)


class TestAuthStateAcrossSaveFailuresAndRestarts(AuthBase):
    def test_logout_saved_stays_logged_out_after_restart(self):
        tok = self.store.login("op", "op-password-12").token
        self.store.logout(tok)
        self.assertIsNone(self.restart().resolve(tok))

    def test_unsaved_logout_blocks_new_sign_ins_until_saved(self):
        from aegis.operators import AuthError
        tok = self.store.login("op", "op-password-12").token
        with self.failing("sessions.json"):
            with self.assertRaises(AuthError):
                self.store.logout(tok)
            self.assertIsNone(self.store.resolve(tok))          # gone in this process
            self.assertFalse(self.store.trusted())
            with self.assertRaises(AuthError) as cm:
                self.store.login("root", "root-password-1")      # nothing new while untrusted
            self.assertIn("保存できない", str(cm.exception))
        self.store._last_retry = -1e9                          # (retries happen at most once a second)
        self.assertTrue(self.store.trusted())                   # the next write goes through...
        self.assertIsNone(self.restart().resolve(tok))           # ...and the logout is durable
        self.assertIsNotNone(self.store.login("root", "root-password-1"))

    def test_unsaved_password_change_and_restart(self):
        from aegis.operators import AuthError
        keep = self.store.login("op", "op-password-12").token
        other = self.store.login("op", "op-password-12").token
        with self.failing("operators.json"):
            with self.assertRaises(AuthError):
                self.store.change_password("op", "op-password-12", "new-password-123", keep_token=keep)
            self.assertFalse(self.store.trusted())
            with self.assertRaises(AuthError):
                self.store.login("op", "new-password-123")
        self.store._last_retry = -1e9
        self.assertTrue(self.store.trusted())                   # retried: now on disk
        again = self.restart()
        self.assertIsNotNone(again.login("op", "new-password-123"))
        with self.assertRaises(AuthError):
            again.login("op", "op-password-12")
        self.assertIsNone(again.resolve(other))                 # the other session stays revoked

    def test_expired_sessions_do_not_come_back(self):
        t = [1000.0]
        store = self.Store(self.dir / "operators.json", clock=lambda: t[0])
        tok = store.login("op", "op-password-12").token
        t[0] += 10 * 24 * 3600
        self.assertIsNone(store.resolve(tok))
        again = self.Store(self.dir / "operators.json", clock=lambda: t[0])
        self.assertIsNone(again.resolve(tok))

    def test_revoke_all_sessions(self):
        toks = [self.store.login(n, p).token for n, p in (("op", "op-password-12"), ("root", "root-password-1"))]
        self.assertEqual(self.store.revoke_all_sessions("test"), 2)
        again = self.restart()
        self.assertTrue(all(again.resolve(t) is None for t in toks))


class TestUntrustedAuthStateOverHttp(unittest.TestCase):
    def setUp(self):
        import urllib.request
        from http.server import ThreadingHTTPServer
        from aegis.operators import OperatorStore
        from aegis.server import make_handler
        from tests.test_access_control import seed
        self.urllib = urllib.request
        self.data = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.data, True)
        self.svc = AssessmentService(self.data, LAB_PORT, verify_seconds=0.1, l2_confinement=TEST_CONFINEMENT,
                                     revocation_marker_dirs=[Path(tempfile.mkdtemp())])
        self.addCleanup(self.svc.workers.kill_all)
        self.ops = OperatorStore(seed(self.data))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.svc, self.ops))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        self.api = f"http://127.0.0.1:{srv.server_port}/api"

    def post(self, path, body, cookie=None):
        import urllib.error
        hdr = {"Content-Type": "application/json", "X-Aegis-Request": "1", **({"Cookie": cookie} if cookie else {})}
        try:
            with self.urllib.urlopen(self.urllib.Request(self.api + path, json.dumps(body).encode(), hdr)) as r:
                return r.status, json.loads(r.read() or b"{}"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}"), e.headers

    def test_new_operations_are_refused_but_stopping_is_not(self):
        code, _, h = self.post("/auth/login", {"name": "appr", "password": "appr-password"})
        cookie = h["Set-Cookie"].split(";")[0]
        with patch.object(self.ops, "_atomic_write", return_value=False):
            self.ops._persist_sessions()                         # some write failed
            self.assertEqual(self.post("/assessments/scan_001/start", {}, cookie)[0], 503)
            self.assertEqual(self.post("/assessments/scan_001/verify-finding", {"finding_id": "all"}, cookie)[0], 503)
            self.assertEqual(self.post("/assets", {"name": "x.example.test"}, cookie)[0], 503)
            self.assertNotEqual(self.post("/auth/login", {"name": "op", "password": "op-password"})[0], 200)
            code, body, _ = self.post("/assessments/scan_001/emergency-stop", {}, cookie)
            self.assertEqual(code, 200, body)                    # stopping is always possible
        self.ops._last_retry = -1e9                              # (retries happen at most once a second)
        self.assertEqual(self.post("/auth/login", {"name": "op", "password": "op-password"})[0], 200)


class TestUncleanShutdownSignsEveryoneOut(ReleaseBase):
    def test_build_server_revokes_sessions_after_an_unclean_shutdown(self):
        from types import SimpleNamespace
        from aegis.operators import OperatorStore
        from aegis.server import _build_server
        from tests.test_access_control import seed
        seed_path = seed(self.dir)
        tok = OperatorStore(seed_path).login("op", "op-password").token
        self.assertEqual(self.other_process("kill"), "")
        again = self.reopen_in_this_process()
        self.assertFalse(again.previous_session_clean)
        a = SimpleNamespace(port=0, no_read_auth=False, require_read_auth=False)
        srv = _build_server(again, a, self.dir, False, seed_path, False)
        self.addCleanup(srv.server_close)
        self.assertIsNone(OperatorStore(seed_path).resolve(tok))
        again.workers.kill_all()


class TestExpiryStopIsRetriedUntilConfirmed(ReleaseBase):
    def test_retries_until_the_worker_is_confirmed_dead(self):
        self.onboard()
        t = threading.Thread(target=lambda: self.svc.workers.run(SLEEPER, 120))
        t.start()
        while not self.svc.workers.active_pids():
            time.sleep(0.01)
        pid = self.svc.workers.active_pids()[0]
        with patch("aegis.runtime._killpg"):                    # the kill does not take
            self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
            end = time.time() + 15
            while time.time() < end and not self.events("scope.expired"):
                time.sleep(0.1)
            self.assertEqual(self.events("scope.expired")[0]["fields"]["unconfirmed"], [pid])
            self.assertIn("確認できていません", self.svc.snapshot()["authority_notice"])
            time.sleep(1.2)
            self.assertTrue(WorkerPool.group_alive(pid))
            self.assertEqual(len(self.events("scope.expired")), 1)      # no stream of duplicates
        end = time.time() + 10                                         # the kill works again: retried
        while time.time() < end and len(self.events("scope.expired")) < 2:
            time.sleep(0.1)
        t.join(10)
        self.assertFalse(WorkerPool.group_alive(pid))
        last = self.events("scope.expired")[-1]["fields"]
        self.assertTrue(last["retry"])
        self.assertEqual(last["unconfirmed"], [])
        self.assertIsNone(self.svc.system_status()["unstopped_workers"])

    def test_an_exception_during_the_stop_is_retried(self):
        self.onboard()
        calls = {"n": 0}
        real = self.svc._authority_reduced_locked

        def flaky(host):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient")
            return real(host)
        self.svc._authority_reduced_locked = flaky
        self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
        end = time.time() + 10
        while time.time() < end and not self.events("scope.expired"):
            time.sleep(0.1)
        self.assertGreaterEqual(calls["n"], 2)
        self.assertEqual(self.events("scope.expired")[0]["fields"]["unconfirmed"], [])


# ---- findings of the review of d49ac02 ------------------------------------------
class TestAuthStateReviewFindings(AuthBase):
    def test_registration_is_refused_while_untrusted(self):
        from aegis.operators import AuthError
        with self.failing("sessions.json"):
            self.store._persist_sessions()
            with self.assertRaises(AuthError):
                self.store.register("newbie", "a-long-password-1")
        self.assertNotIn("newbie", self.store._ops)

    def test_retries_are_rate_limited(self):
        calls = {"n": 0}
        real = self.store._atomic_write

        def count(path, data):
            calls["n"] += 1
            return False
        with patch.object(self.store, "_atomic_write", side_effect=count):
            self.store._persist_sessions()
            before = calls["n"]
            for _ in range(50):
                self.store.trusted()
            self.assertLessEqual(calls["n"] - before, 2)          # not 50 writes for 50 requests


class TestUnsavedAuthMakesTheShutdownUnclean(ReleaseBase):
    def test_close_with_unsaved_auth_leaves_the_session_record(self):
        self.assertFalse(self.svc.close(external_clean=False))
        self.assertTrue((self.dir / "session.open").exists())
        again = self.reopen_in_this_process()
        self.assertFalse(again.previous_session_clean)
        again.workers.kill_all()


class TestRolesWhileUntrustedOverHttp(TestUntrustedAuthStateOverHttp):
    def test_only_removals_pass_the_gate(self):
        code, _, h = self.post("/auth/login", {"name": "root", "password": "root-password"})
        cookie = h["Set-Cookie"].split(";")[0]
        with patch.object(self.ops, "_atomic_write", return_value=False):
            self.ops._persist_sessions()
            self.ops._last_retry = -1e9
            code, body, _ = self.post("/operators/roles", {"name": "op", "roles": ["operator", "approver"]}, cookie)
            self.assertEqual(code, 503, body)                         # a grant: refused
            self.assertNotIn("approver", self.ops.roles_of("op"))
            code, body, _ = self.post("/operators/roles", {"name": "appr", "roles": ["operator"]}, cookie)
            self.assertNotEqual(code, 503, body)                      # a removal: allowed (and reported if unsaved)
            self.assertNotIn("approver", self.ops.roles_of("appr"))


class TestExpiryNoticeSurvivesAnAuditFailure(ReleaseBase):
    def test_the_asset_is_marked_and_the_event_recorded_later(self):
        self.onboard()
        real = self.svc.audit.record
        fail = {"on": True}

        def record(event, **fields):
            if event == "scope.expired" and fail["on"]:
                raise OSError("no space")
            return real(event, **fields)
        with patch.object(self.svc.audit, "record", side_effect=record):
            self.svc._verified_external_hosts[HOST]["not_after"] = time.time() - 1
            end = time.time() + 10
            while time.time() < end and "期限" not in (self.svc.snapshot()["authority_notice"] or ""):
                time.sleep(0.1)
            self.assertIn("期限", self.svc.snapshot()["authority_notice"])
            self.assertFalse(next(x for x in self.svc.assets() if x["name"] == HOST)["scope_confirmed"])
            fail["on"] = False
            end = time.time() + 10
            while time.time() < end and not self.events("scope.expired"):
                time.sleep(0.1)
        self.assertTrue(self.events("scope.expired"))
