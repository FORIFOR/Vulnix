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

    def test_deletion_kills_the_confined_worker(self):
        self.start_hanging_l2()
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assert_confined_worker_gone()

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


class TestWorkerIdentity(unittest.TestCase):
    def conf(self, *, euid, separate):
        c = KernelConfinement(platform="linux", euid=euid, runner=lambda *a, **k: None,
                              which=lambda t: f"/bin/{t}")
        c._separate_uid = separate
        return c

    def test_the_worker_runs_as_nobody_when_its_code_is_readable_by_others(self):
        from aegis.confinement import ConfinementSession
        for euid in (0, 1000):
            argv = ConfinementSession(self.conf(euid=euid, separate=True), "203.0.113.7", 443).wrap(["w"])
            self.assertIn("--reuid=65534", argv)
            self.assertIn("--clear-groups", argv)

    def test_otherwise_never_root(self):
        from aegis.confinement import ConfinementSession
        argv = ConfinementSession(self.conf(euid=1000, separate=False), "203.0.113.7", 443).wrap(["w"])
        self.assertIn(f"--reuid={os.getuid()}", argv)
        with patch.dict(os.environ, {"SUDO_UID": "", "SUDO_GID": ""}):
            argv = ConfinementSession(self.conf(euid=0, separate=False), "203.0.113.7", 443).wrap(["w"])
        self.assertIn("--reuid=65534", argv)
        self.assertNotIn("--reuid=0", argv)
