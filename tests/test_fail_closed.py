"""Fail-closed behaviour around persistence, failure reporting and L2 isolation.

* A revocation that cannot be saved does not come back after a restart, whatever
  part of the data directory is unwritable; unknown or inconsistent persistent
  state grants nothing.
* A run whose results could not be saved is "failed" with the cause recorded,
  never "completed".
* Test-account tokens go to a real service only from a worker started inside
  kernel confinement that was applied and confirmed for that run (Linux only).
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests import TEST_CONFINEMENT
from aegis.assessment import AssessmentService
from aegis.confinement import (ConfinementError, ConfinementSession, KernelConfinement,
                               dropped_packets, ruleset)
from aegis.policy import PolicyError
from aegis.runtime import WorkerPool
from tests.test_real_service import HOST, LAB_PORT, PROFILE_DIRS, TOKEN_A, TOKEN_B, RealServiceBase

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class PersistenceBase(RealServiceBase):
    def setUp(self):
        super().setUp()
        self.markers = Path(tempfile.mkdtemp(prefix="vulnix-markers-"))
        self.addCleanup(shutil.rmtree, self.markers, True)
        self.addCleanup(self.unlock)
        self.svc.workers.kill_all()
        self.svc = self.open()

    def open(self, **kw):
        svc = AssessmentService(self.dir, LAB_PORT, verify_seconds=0.1, l2_profile_dirs=PROFILE_DIRS,
                                l2_confinement=kw.pop("l2_confinement", TEST_CONFINEMENT),
                                revocation_marker_dirs=kw.pop("markers", [self.markers]), **kw)
        svc._custom_resolver = lambda h: ["127.0.0.1"] if h == HOST else []
        return svc

    def restart(self, **kw):
        self.svc.workers.kill_all()
        self.svc = self.open(**kw)
        return self.svc

    def lock(self, *, files=("state.json", "authority.epoch")):
        """Make the data directory (and the named files in it) read-only."""
        for name in files:
            if (self.dir / name).exists():
                os.chmod(self.dir / name, 0o400)
        os.chmod(self.dir, 0o500)

    def unlock(self):
        if self.dir.exists():
            os.chmod(self.dir, 0o700)
            for p in self.dir.iterdir():
                if p.is_file():
                    os.chmod(p, 0o600)

    def revoke(self):
        """An approver's failed re-check: scope and proof are revoked in memory."""
        self.svc.verify_asset_ownership(url_or_host=self.url, dns_lookup=lambda n: [])
        self.assertFalse(self.svc._is_external_service_asset(HOST))

    def events(self, name, svc=None):
        return [e for e in (svc or self.svc).audit.entries() if e["event"] == name]

    def marker_files(self):
        return sorted(self.markers.glob("*.revoked"))


@unittest.skipIf(IS_ROOT, "root ignores directory permissions")
class TestRevocationSurvivesAnUnwritableDataDirectory(PersistenceBase):
    def test_read_only_directory_and_files_leave_a_marker_that_blocks_the_restart(self):
        self.onboard()
        self.lock()
        self.revoke()
        self.assertIsNotNone(self.svc._persist_error)
        self.assertTrue((self.dir / "authority.epoch").stat().st_size > 0)   # could not be touched
        self.assertEqual(len(self.marker_files()), 1)
        self.unlock()                                    # the disk is fine again before the restart
        again = self.restart()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertEqual(again._ownership_proofs, {})
        self.assertEqual(again._verified_external_hosts, {})
        self.assertTrue(self.events("state.authority_rejected"))
        self.assertIsNotNone(again.snapshot()["authority_notice"])
        # the rejection was saved, so the marker has done its job and is gone
        self.assertIsNone(again._persist_error)
        self.assertEqual(self.marker_files(), [])
        third = self.restart()
        self.assertFalse(third._is_external_service_asset(HOST))

    def test_read_only_directory_with_a_writable_epoch_record_is_emptied_in_place(self):
        self.onboard()
        self.lock(files=("state.json",))
        self.revoke()
        self.assertEqual((self.dir / "authority.epoch").stat().st_size, 0)
        self.assertEqual(self.marker_files(), [])        # not needed: the disk copy no longer verifies
        self.unlock()
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_nothing_writable_anywhere_and_still_unwritable_at_restart(self):
        self.onboard()
        self.lock()
        os.chmod(self.markers, 0o500)
        self.addCleanup(os.chmod, self.markers, 0o700)
        self.revoke()
        self.assertEqual(self.marker_files(), [])
        self.assertTrue(self.events("state.revocation_not_durable"))
        # same process: everything real is refused
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="appr")
        again = self.restart()                           # the directory is STILL read-only
        self.assertIsNotNone(again._persist_error)
        self.assertIn("not writable", again.snapshot()["persistence_error"])
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertEqual(again._ownership_proofs, {})
        self.assertEqual(self.fake.seen, [])

    def test_an_unwritable_directory_at_startup_honours_no_authority_even_without_a_revocation(self):
        self.onboard()
        self.svc.workers.kill_all()
        self.lock()
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertIsNotNone(again._persist_error)
        reasons = " ".join(e["fields"]["reason"] for e in self.events("state.authority_rejected", again))
        self.assertIn("not writable", reasons)
        again.workers.kill_all()


class TestRevocationMarkers(PersistenceBase):
    def fail_saves(self):
        """state.json cannot be replaced AND the epoch record cannot be removed or emptied."""
        real_open = open

        def no_truncate(path, mode="r", *a, **kw):
            if str(path).endswith("authority.epoch") and "+" in mode:
                raise PermissionError("read-only")
            return real_open(path, mode, *a, **kw)
        return (patch("aegis.assessment.os.replace", side_effect=self._replace_except_markers),
                patch("aegis.assessment.os.unlink", side_effect=self._unlink_except_epoch),
                patch("aegis.assessment.open", side_effect=no_truncate, create=True))

    def _replace_except_markers(self, src, dst):
        if str(dst).endswith(".revoked"):
            return os.rename(src, dst)
        raise OSError("read-only file system")

    def _unlink_except_epoch(self, path):
        if str(path).endswith("authority.epoch"):
            raise PermissionError("read-only")
        return os.remove(path)

    def revoke_without_being_able_to_save(self):
        a, b, c = self.fail_saves()
        with a, b, c:
            self.revoke()
        self.assertEqual(len(self.marker_files()), 1)

    def test_marker_is_signed_and_names_the_stale_epoch(self):
        self.onboard()
        epoch = json.loads((self.dir / "authority.epoch").read_text())["epoch"]
        self.revoke_without_being_able_to_save()
        body = json.loads(self.marker_files()[0].read_text())
        self.assertIn(epoch, body["epochs"])
        self.assertEqual(body["mac"], self.svc._marker_mac(body["epochs"]))
        self.assertEqual(self.marker_files()[0].stat().st_mode & 0o077, 0)
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_restoring_older_copies_of_both_files_does_not_get_past_the_marker(self):
        self.onboard()
        keep = {n: (self.dir / n).read_bytes() for n in ("state.json", "authority.epoch")}
        self.revoke_without_being_able_to_save()
        for n, raw in keep.items():                       # an attacker (or a backup) puts both back
            (self.dir / n).write_bytes(raw)
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_a_marker_of_ours_that_does_not_verify_still_refuses(self):
        self.onboard()
        self.svc.workers.kill_all()
        (self.markers / f"{self.svc._marker_key()}.revoked").write_text('{"epochs": ["1:00"], "mac": "nope"}')
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertIn("does not verify", " ".join(e["fields"]["reason"] for e in self.events("state.authority_rejected", again)))
        again.workers.kill_all()

    def test_an_unreadable_marker_refuses(self):
        self.onboard()
        self.svc.workers.kill_all()
        (self.markers / f"{self.svc._marker_key()}.revoked").write_text("{not json")
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        again.workers.kill_all()

    def test_a_marker_for_an_older_state_than_the_one_on_disk_is_ignored(self):
        self.onboard()
        old = "1:" + "0" * 32
        (self.markers / f"{self.svc._marker_key()}.revoked").write_text(
            json.dumps({"epochs": [old], "mac": self.svc._marker_mac([old])}))
        again = self.restart()                            # a later save had succeeded
        self.assertTrue(again._is_external_service_asset(HOST))

    def test_a_marker_for_another_data_directory_is_not_ours(self):
        self.onboard()
        (self.markers / ("0" * 32 + ".revoked")).write_text("{not json")
        self.assertTrue(self.restart()._is_external_service_asset(HOST))

    def test_a_second_failure_after_a_refused_restart_does_not_narrow_the_marker(self):
        """Refused at startup, and the save that would record the refusal fails too:
        the marker must still name the state that is on disk."""
        self.onboard()
        self.revoke_without_being_able_to_save()
        self.svc.workers.kill_all()
        a, b, c = self.fail_saves()
        with a, b, c:
            second = self.open()                          # refuses; cannot save the refusal
            self.assertFalse(second._is_external_service_asset(HOST))
            self.assertIsNotNone(second._persist_error)
            second.workers.kill_all()
        self.assertEqual(len(self.marker_files()), 1)
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_saving_again_in_the_same_process_persists_the_revocation_and_clears_the_marker(self):
        self.onboard()
        self.revoke_without_being_able_to_save()
        with self.svc._lock:
            self.svc._save_state_locked()                 # the disk works again
        self.assertIsNone(self.svc._persist_error)
        self.assertEqual(self.marker_files(), [])
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_default_marker_locations_are_outside_the_data_directory(self):
        from aegis.assessment import default_revocation_marker_dirs
        with patch.dict(os.environ, {"VULNIX_REVOCATION_MARKER_DIR": ""}):
            dirs = default_revocation_marker_dirs()
        self.assertEqual(len(dirs), 2)
        for d in dirs:
            self.assertNotIn(self.dir.resolve(), [d.resolve(), *d.resolve().parents])


class TestUnknownOrInconsistentStateGrantsNothing(PersistenceBase):
    def test_unreadable_state_file(self):
        self.onboard()
        self.svc.workers.kill_all()
        (self.dir / "state.json").write_text("{ truncated")
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertTrue(self.events("state.unreadable", again))
        self.assertIsNotNone(again.snapshot()["authority_notice"])
        again.workers.kill_all()

    def test_state_that_is_not_an_object(self):
        self.onboard()
        self.svc.workers.kill_all()
        (self.dir / "state.json").write_text("[]")
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertTrue(self.events("state.unreadable", again))
        again.workers.kill_all()

    def test_rolling_back_state_json_after_a_saved_revocation(self):
        self.onboard()
        before = (self.dir / "state.json").read_bytes()
        self.revoke()                                     # saved normally: the epoch moved on
        self.assertIsNone(self.svc._persist_error)
        self.svc.workers.kill_all()
        (self.dir / "state.json").write_bytes(before)
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        self.assertIn("not the latest", " ".join(e["fields"]["reason"] for e in self.events("state.authority_rejected", again)))
        again.workers.kill_all()

    def test_missing_epoch_record(self):
        self.onboard()
        self.svc.workers.kill_all()
        os.unlink(self.dir / "authority.epoch")
        again = self.open()
        self.assertFalse(again._is_external_service_asset(HOST))
        again.workers.kill_all()

    def test_a_clean_restart_still_keeps_a_valid_scope(self):
        self.onboard()
        self.assertTrue(self.restart()._is_external_service_asset(HOST))
        self.assertIsNone(self.svc.snapshot()["authority_notice"])


class TestRevocationUnderConcurrency(PersistenceBase):
    def hammer(self, stop):
        while not stop.is_set():
            self.svc.snapshot()
            with self.svc._lock:
                self.svc._save_state_locked()

    def run_with_savers(self, body):
        stop = threading.Event()
        threads = [threading.Thread(target=self.hammer, args=(stop,)) for _ in range(6)]
        for t in threads:
            t.start()
        try:
            body()
        finally:
            stop.set()
            for t in threads:
                t.join(10)

    def test_concurrent_saves_never_write_the_revoked_scope_back(self):
        self.onboard()
        self.run_with_savers(lambda: (time.sleep(0.05), self.revoke(), time.sleep(0.05)))
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_revocation_while_saves_fail_under_concurrency(self):
        self.onboard()
        def revoke_by_deleting():
            time.sleep(0.05)
            self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
            time.sleep(0.05)
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            self.run_with_savers(revoke_by_deleting)
        self.assertIsNotNone(self.svc._persist_error)
        self.assertFalse(self.restart()._is_external_service_asset(HOST))

    def test_l2_requests_racing_a_revocation_send_no_token_after_it(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        errors, started = [], threading.Event()

        def run():
            started.set()
            try:
                self.svc.verify_finding("f_ex_idor", actor="appr")
            except Exception as e:                        # refused: also fine
                errors.append(e)
        threads = [threading.Thread(target=run) for _ in range(4)]
        for t in threads:
            t.start()
        started.wait(5)
        self.revoke()
        mark = len(self.fake.seen)
        for t in threads:
            t.join(30)
        time.sleep(0.2)
        late = [auth for _, auth in self.fake.seen[mark:] if auth]
        self.assertEqual(late, [], "a token was sent after the revocation returned")
        with self.assertRaises(ValueError):
            self.svc.verify_finding("f_ex_idor", actor="appr")


class TestFailedSaveIsNeverReportedAsCompleted(PersistenceBase):
    def test_bulk_verification_of_a_real_service_with_saving_broken(self):
        self.onboard()
        self.run_l1()
        self.assertEqual(self.svc.snapshot()["state"], "completed")
        seen = len(self.fake.seen)
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            snap = self.svc.verify_finding("all", actor="appr")
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(snap["failure"]["kind"], "persistence")
        self.assertIn("保存", snap["failure"]["reason"])
        self.assertEqual(snap["failure"]["error"], "OSError")
        self.assertEqual(len(self.fake.seen), seen)       # nothing was sent
        self.assertTrue(self.events("assessment.failed"))

    def test_results_that_could_not_be_saved_are_not_a_completed_run(self):
        self.svc.select_asset("lab")
        real = os.replace
        calls = {"n": 0}

        def flaky(src, dst):                              # the run itself works; the last saves do not
            calls["n"] += 1
            return real(src, dst)
        with patch("aegis.assessment.os.replace", side_effect=flaky):
            self.svc.verify_finding("f_banner", actor="appr")
        with self.svc._lock:
            with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
                self.svc._set_state("completed")
        snap = self.svc.snapshot()
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(snap["failure"]["kind"], "persistence")

    def test_failure_cause_is_kept_across_a_restart(self):
        self.onboard()
        self.run_l1()
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            self.svc.verify_finding("all", actor="appr")
        with self.svc._lock:
            self.svc._save_state_locked()                 # the disk is back
        snap = self.restart().snapshot()
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(snap["failure"]["kind"], "persistence")
        self.assertEqual(snap["failure"]["error"], "OSError")

    def test_failure_cause_is_cleared_by_the_next_good_run(self):
        self.onboard()
        self.run_l1()
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            self.svc.verify_finding("all", actor="appr")
        self.assertEqual(self.svc.snapshot()["state"], "failed")
        snap = self.svc.verify_finding("all", actor="appr")
        self.assertEqual(snap["state"], "completed")
        self.assertIsNone(snap["failure"])

    def test_a_refused_run_records_why(self):
        self.onboard()
        self.run_l1()
        with patch("aegis.policy.Budget.spend", side_effect=PolicyError("budget exhausted")):
            snap = self.svc.verify_finding("all", actor="appr")
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(snap["failure"]["kind"], "run")
        self.assertIn("budget exhausted", snap["failure"]["reason"])

    def test_lab_bulk_verification_does_not_overwrite_a_failed_item(self):
        self.svc.select_asset("lab")
        with patch("aegis.policy.Budget.spend", side_effect=PolicyError("budget exhausted")):
            snap = self.svc.verify_finding("all", actor="appr")
        self.assertEqual(snap["state"], "failed")
        self.assertIsNotNone(snap["failure"])


# ---- L2 isolation ------------------------------------------------------------
class _Refusing:
    """Preflight says yes; applying the confinement for the run fails."""
    def __init__(self):
        self.asked = []

    def status(self):
        return {"ok": True, "reason": "", "mechanism": "refusing"}

    def session(self, ip, port):
        self.asked.append((ip, port))
        raise ConfinementError("nft apply failed")


class _Session:
    evidence = {"mechanism": "fake"}

    def __init__(self, enforced):
        self._enforced = list(enforced)
        self.wrapped = 0

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def wrap(self, argv, env_keys=(), cpu_seconds=60):
        self.wrapped += 1
        return list(argv)

    def still_enforced(self):
        return self._enforced.pop(0) if self._enforced else False

    def kill(self):
        return None


class _Scripted:
    def __init__(self, enforced):
        self.s = _Session(enforced)

    def status(self):
        return {"ok": True, "reason": "", "mechanism": "fake"}

    def session(self, ip, port):
        return self.s


class TestRealServiceL2NeedsKernelConfinement(PersistenceBase):
    def prepare(self, confinement):
        self.restart(l2_confinement=confinement)
        self.onboard()
        self.set_secrets()
        self.run_l1()

    def tokens_seen(self):
        return [auth for _, auth in self.fake.seen if auth]

    def test_not_linux_means_no_l2_and_no_token_leaves(self):
        self.prepare(KernelConfinement(platform="darwin"))
        snap = self.svc.snapshot()
        self.assertFalse(snap["l2_isolation"]["ok"])
        self.assertIn("Linux", snap["l2_isolation"]["reason"])
        with self.assertRaises(ValueError) as cm:
            self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
        self.assertIn("Linux", str(cm.exception))
        self.assertEqual(self.tokens_seen(), [])
        # and the worker environment is empty whatever asks for it
        self.assertFalse(any("TOKEN" in k.upper() for k in
                             self.svc._ephemeral_worker_env("reproduction_probe", {"check": "ex_idor_notes"})))

    def test_windows_and_bsd_are_not_linux_either(self):
        for plat in ("win32", "freebsd14", "cygwin"):
            self.assertFalse(KernelConfinement(platform=plat).status()["ok"])

    def test_default_service_uses_the_real_confinement(self):
        svc = AssessmentService(Path(tempfile.mkdtemp()), LAB_PORT)
        self.addCleanup(svc.workers.kill_all)
        self.assertIsInstance(svc._l2_confinement, KernelConfinement)
        if not sys.platform.startswith("linux"):
            self.assertFalse(svc.l2_isolation_status()["ok"])

    def test_confinement_that_cannot_be_applied_for_the_run_starts_no_worker(self):
        conf = _Refusing()
        self.prepare(conf)
        with patch.object(self.svc.secrets, "worker_env_for_check", wraps=self.svc.secrets.worker_env_for_check) as env:
            self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
            env.assert_not_called()                      # tokens were not even read
        self.assertEqual(len(conf.asked), 1)
        self.assertEqual(self.tokens_seen(), [])
        self.assertTrue(any("カーネル隔離" in e["fields"].get("reason", "") for e in self.events("deny")))
        self.assertNotEqual(self.finding("f_ex_idor")["verdict"], "proven")

    def test_confinement_gone_before_the_worker_starts(self):
        conf = _Scripted([False])
        self.prepare(conf)
        self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
        self.assertEqual(conf.s.wrapped, 0)               # never launched
        self.assertEqual(self.tokens_seen(), [])

    def test_confinement_lost_during_the_run_discards_the_result(self):
        conf = _Scripted([True, False])
        self.prepare(conf)
        self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
        self.assertEqual(conf.s.wrapped, 1)
        self.assertTrue(self.events("confinement.lost"))
        f = self.finding("f_ex_idor")
        self.assertNotEqual(f["verdict"], "proven")
        self.assertFalse([e for e in f.get("evidence", []) if e.get("tool") == "reproduction_probe"])

    def test_a_confirmed_confinement_runs_and_is_recorded(self):
        conf = _Scripted([True, True])
        self.prepare(conf)
        self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
        self.assertEqual(conf.s.wrapped, 1)
        self.assertTrue(self.events("confinement.applied"))
        self.assertEqual(sorted(set(self.tokens_seen())), sorted({f"Bearer {TOKEN_A}", f"Bearer {TOKEN_B}"}))

    def test_l1_and_lab_runs_do_not_ask_for_confinement(self):
        conf = _Refusing()
        self.prepare(conf)                                # includes a real-service L1 run
        self.assertEqual(conf.asked, [])
        self.assertEqual(self.svc.snapshot()["state"], "completed")

    def test_the_test_stand_in_confines_nothing_but_loopback(self):
        with self.assertRaises(ConfinementError):
            TEST_CONFINEMENT.session("93.184.216.34", 443)


class _FakeRun:
    """Stands in for subprocess.run: records commands, plays a scripted kernel."""
    def __init__(self, *, sudo_ok=True, probe=None, counters=(0, 3), nft_apply_rc=0, listing=True):
        self.calls, self.sudo_ok, self.probe = [], sudo_ok, probe
        self.counters, self.nft_apply_rc, self.listing = list(counters), nft_apply_rc, listing
        self.name = None

    def __call__(self, argv, **kw):
        self.calls.append((list(argv), kw))
        R = subprocess.CompletedProcess
        a = [x for x in argv if x not in ("/bin/sudo", "-n")]
        if a == ["true"]:
            return R(argv, 0 if self.sudo_ok else 1, "", "")
        if a[0] == "/bin/nft" and a[1:3] == ["-f", "-"]:
            self.name = kw["input"].split()[2]
            return R(argv, self.nft_apply_rc, "", "boom" if self.nft_apply_rc else "")
        if a[0] == "/bin/nft" and a[1] == "list":
            if not self.listing:
                return R(argv, 1, "", "no such table")
            n = self.counters.pop(0) if len(self.counters) > 1 else self.counters[0]
            return R(argv, 0, f'table inet {self.name} {{\n chain confined {{\n  counter packets {n} bytes 0 drop\n }}\n'
                              f' chain output {{\n  type filter hook output priority filter; policy accept;\n'
                              f'  socket cgroupv2 level 1 "{self.name}" jump confined\n }}\n}}\n', "")
        if sys.executable in argv:                        # the probe
            out = self.probe if self.probe is not None else json.dumps(
                {"connect": "BLOCKED:TimeoutError", "cgroup": f"0::/{self.name}"})
            return R(argv, 0, out + "\n", "")
        return R(argv, 0, "", "")

    def ran(self, *needle):
        return [c for c, _ in self.calls if all(n in " ".join(c) for n in needle)]


class TestKernelConfinementLogic(unittest.TestCase):
    def make(self, run, *, euid=1000, tools=("nft", "sh", "sudo", "setpriv"), controllers=True):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        if controllers:
            (root / "cgroup.controllers").write_text("cpu memory")
        return KernelConfinement(runner=run, platform="linux", cgroup_root=root, euid=euid,
                                 which=lambda t: f"/bin/{t}" if t in tools else None)

    def test_ruleset_drops_everything_but_the_pinned_destination(self):
        text = ruleset("aegis_l2_0123456789ab", "203.0.113.7", 443)
        self.assertIn('socket cgroupv2 level 1 "aegis_l2_0123456789ab" jump confined', text)
        self.assertIn("ip daddr 203.0.113.7 tcp dport 443 ct state new accept", text)
        self.assertIn("counter drop", text)
        self.assertNotIn('oif "lo"', text)                # loopback is not a free pass
        self.assertEqual(text.count("accept"), 3)         # established, pinned, and the hook's own policy
        self.assertIn("ip6 daddr 2001:db8::1", ruleset("aegis_l2_0123456789ab", "2001:db8::1", 443))

    def test_ruleset_refuses_metadata_addresses_and_odd_names(self):
        for ip in ("169.254.169.254", "0.0.0.1", "fe80::1"):
            with self.assertRaises(ConfinementError):
                ruleset("aegis_l2_0123456789ab", ip, 80)
        with self.assertRaises(ConfinementError):
            ruleset('x" accept; #', "203.0.113.7", 443)
        with self.assertRaises(ConfinementError):
            ruleset("aegis_l2_0123456789ab", "203.0.113.7", 0)

    def test_counter_parsing(self):
        self.assertEqual(dropped_packets("counter packets 4 bytes 240 drop\n counter packets 1 bytes 60 drop"), 5)
        self.assertEqual(dropped_packets("counter packets 9 bytes 1 accept"), 0)

    def test_preflight_reasons(self):
        self.assertFalse(self.make(_FakeRun(), controllers=False).status()["ok"])
        self.assertFalse(self.make(_FakeRun(), tools=("sh", "sudo", "setpriv")).status()["ok"])
        self.assertFalse(self.make(_FakeRun(), tools=("nft", "sh")).status()["ok"])
        self.assertFalse(self.make(_FakeRun(sudo_ok=False)).status()["ok"])
        self.assertTrue(self.make(_FakeRun()).status()["ok"])
        self.assertTrue(self.make(_FakeRun(sudo_ok=False), euid=0, tools=("nft", "sh", "setpriv")).status()["ok"])
        self.assertFalse(self.make(_FakeRun(), euid=0, tools=("nft", "sh")).status()["ok"])
        with self.assertRaises(ConfinementError):
            self.make(_FakeRun(sudo_ok=False)).session("203.0.113.7", 443)

    def test_verified_session_and_teardown(self):
        run = _FakeRun()
        with self.make(run).session("203.0.113.7", 443) as s:
            self.assertEqual(s.evidence["kernel_dropped_packets"], 3)
            self.assertTrue(s.evidence["probe_in_cgroup"])
            self.assertTrue(s.still_enforced())
            name = s.name
        self.assertTrue(run.ran("cgroup.kill"))
        self.assertTrue(run.ran("delete", "table", name))
        self.assertTrue(run.ran("rmdir"))

    def assert_refused(self, run):
        with self.assertRaises(ConfinementError):
            with self.make(run).session("203.0.113.7", 443):
                self.fail("the worker would have been started")
        self.assertTrue(run.ran("rmdir"), "the cgroup was left behind")

    def test_unconfirmed_confinement_is_refused(self):
        self.assert_refused(_FakeRun(counters=(0, 0)))                         # the kernel dropped nothing
        self.assert_refused(_FakeRun(probe=json.dumps({"connect": "CONNECTED", "cgroup": "0::/x"})))
        self.assert_refused(_FakeRun(probe=json.dumps(                         # blocked, but not from inside
            {"connect": "BLOCKED:TimeoutError", "cgroup": "0::/user.slice"})))
        self.assert_refused(_FakeRun(probe="not json"))
        self.assert_refused(_FakeRun(nft_apply_rc=1))
        self.assert_refused(_FakeRun(listing=False))

    def test_a_runner_that_raises_is_a_refusal(self):
        def boom(argv, **kw):
            if "true" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise OSError("exec failed")
        with self.assertRaises(ConfinementError):
            with self.make(boom).session("203.0.113.7", 443):
                self.fail("started")

    def test_launch_command_keeps_secrets_out_of_argv_and_drops_root(self):
        s = ConfinementSession(self.make(_FakeRun()), "203.0.113.7", 443)
        argv = s.wrap(["/usr/bin/python3", "w.py"], env_keys=("PATH", "VULNIX_L2_TOKEN_A", "X"), cpu_seconds=7)
        self.assertEqual(argv[:2], ["/bin/sudo", "-n"])
        self.assertIn("--preserve-env=VULNIX_L2_TOKEN_A,X", argv)
        self.assertIn(str(s.cgroup / "cgroup.procs"), argv)
        self.assertIn(f"--reuid={os.getuid()}", argv)
        self.assertIn("--no-new-privs", argv)
        self.assertEqual(argv[-2:], ["/usr/bin/python3", "w.py"])
        self.assertLess(argv.index("/bin/setpriv"), argv.index("/usr/bin/python3"))
        with self.assertRaises(ConfinementError):
            s.wrap(["x"], env_keys=("BAD=1,ALL",))
        as_root = ConfinementSession(self.make(_FakeRun(), euid=0), "203.0.113.7", 443)
        root_argv = as_root.wrap(["w"])
        self.assertEqual(root_argv[0], "/bin/sh")
        self.assertNotIn("/bin/sudo", root_argv)
        self.assertIn("/bin/setpriv", root_argv)                   # a root control plane still drops root
        self.assertNotIn("--reuid=0", root_argv)
        self.assertIn("--no-new-privs", root_argv)

    def test_tools_are_not_taken_from_path(self):
        from aegis import confinement
        fake_bin = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, fake_bin, True)
        (fake_bin / "nft").write_text("#!/bin/sh\nexit 0\n")
        os.chmod(fake_bin / "nft", 0o755)
        with patch.dict(os.environ, {"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}):
            self.assertNotEqual(confinement._system_which("nft"), str(fake_bin / "nft"))

    def test_only_flows_opened_from_inside_are_let_out(self):
        text = ruleset("aegis_l2_0123456789ab", "203.0.113.7", 443)
        self.assertIn("ct state established ct direction original accept", text)
        self.assertNotIn("related", text)

    def test_non_canonical_addresses_are_refused(self):
        for ip in ("fe80::1%eth0", "2001:db8::1%1", "203.0.113.7 ", "not-an-ip", "0x7f.1"):
            with self.assertRaises(ConfinementError):
                ruleset("aegis_l2_0123456789ab", ip, 443)

    def test_rules_stay_when_the_cgroup_cannot_be_emptied(self):
        run = _FakeRun()
        real = run.__call__

        def stuck(argv, **kw):
            if any(str(a).startswith(("rmdir", "echo 1")) for a in argv):
                run.calls.append((list(argv), kw))
                return subprocess.CompletedProcess(argv, 1, "", "busy")
            return real(argv, **kw)
        conf = self.make(stuck)
        with patch("aegis.confinement.time.sleep"):
            with conf.session("203.0.113.7", 443) as s:
                pass
        self.assertTrue(s.leftover)
        self.assertEqual(run.ran("delete", "table"), [])           # still confined

    def test_a_kernel_without_cgroup_kill_is_refused(self):
        run = _FakeRun()
        real = run.__call__

        def old_kernel(argv, **kw):
            if any(str(a).startswith("test -e") for a in argv):
                return subprocess.CompletedProcess(argv, 1, "", "")
            return real(argv, **kw)
        with self.assertRaises(ConfinementError):
            with self.make(old_kernel).session("203.0.113.7", 443):
                self.fail("started")


class TestRequestsThatOutliveTheirAuthority(PersistenceBase):
    """A request can wait a long time in name resolution. Whatever was stopped,
    reset, revoked or deleted meanwhile must be seen before a worker starts."""

    def setUp(self):
        super().setUp()
        self.gate, self.entered, self.slow = threading.Event(), threading.Event(), {"on": False}
        self.addCleanup(self.gate.set)

        def resolver(h):
            if self.slow["on"]:
                self.entered.set()
                self.gate.wait(20)
            return ["127.0.0.1"] if h == HOST else []
        self.svc._custom_resolver = resolver

    def wait_idle(self):
        end = time.time() + 20
        while time.time() < end and self.svc.snapshot()["state"] == "running":
            time.sleep(0.05)

    def test_l2_item_waiting_in_lookup_sends_nothing_after_stop_and_restart(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        self.slow["on"] = True
        out = []

        def run():
            try:
                self.svc.verify_finding("f_ex_idor", actor="appr", roles={"approver"})
            except Exception as e:
                out.append(e)
        t = threading.Thread(target=run)
        t.start()
        self.assertTrue(self.entered.wait(10))
        self.svc.emergency_stop("appr")
        self.slow["on"] = False
        self.svc.restart("appr")
        self.wait_idle()
        mark = len(self.fake.seen)
        self.gate.set()
        t.join(30)
        time.sleep(0.3)
        self.assertEqual([a for _, a in self.fake.seen[mark:] if a], [], "tokens were sent after the stop")
        self.assertEqual(len(self.fake.seen), mark)
        self.assertNotEqual(self.finding("f_ex_idor")["verdict"], "proven")
        self.assertTrue(out and isinstance(out[0], ValueError))

    def test_runner_waiting_in_lookup_does_not_launch_in_the_next_workspace(self):
        self.onboard()
        self.slow["on"] = True
        self.svc.start()
        self.assertTrue(self.entered.wait(10))
        self.svc.emergency_stop("appr")
        self.slow["on"] = False
        self.svc.restart("appr")
        self.wait_idle()
        mark = len(self.fake.seen)
        self.gate.set()
        time.sleep(1.0)
        self.assertEqual(len(self.fake.seen), mark)

    def test_request_waiting_in_lookup_is_not_sent_after_a_revocation(self):
        self.onboard()
        self.slow["on"] = True
        self.svc.start()
        self.assertTrue(self.entered.wait(10))
        self.slow["on"] = False
        self.revoke()
        mark = len(self.fake.seen)
        self.gate.set()
        self.wait_idle()
        time.sleep(0.5)
        self.assertEqual(len(self.fake.seen), mark)
        self.assertTrue(self.events("deny"))

    def test_request_waiting_in_lookup_is_not_sent_after_the_asset_is_deleted(self):
        self.onboard()
        self.slow["on"] = True
        self.svc.start()
        self.assertTrue(self.entered.wait(10))
        self.svc.emergency_stop("appr")
        self.slow["on"] = False
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        mark = len(self.fake.seen)
        self.gate.set()
        time.sleep(1.0)
        self.assertEqual(len(self.fake.seen), mark)

    def test_emergency_stop_ends_the_generation(self):
        from aegis.assessment import _Stopped
        self.svc.select_asset("lab")
        self.svc._tls.gen = self.svc._run_generation          # this thread plays a runner past its last checkpoint
        self.addCleanup(setattr, self.svc._tls, "gen", None)
        stopper = threading.Thread(target=self.svc.emergency_stop, args=("appr",))
        stopper.start()
        stopper.join(20)
        with self.svc._lock:
            for write in (lambda: self.svc._set_state("completed"),
                          lambda: self.svc._phase("report", "done", "x")):
                with self.assertRaises(_Stopped):
                    write()
        self.assertEqual(self.svc.snapshot()["state"], "stopped")

    def test_tokens_are_not_released_to_a_worker_without_a_confinement_session(self):
        self.onboard()
        self.set_secrets()
        self.run_l1()
        self.svc._tls.confined = False
        env = self.svc._ephemeral_worker_env("reproduction_probe", {"check": "ex_idor_notes"})
        self.assertFalse(any("L2" in k or "TOKEN" in k.upper() for k in env))


class TestMoreFailClosedDetails(PersistenceBase):
    def test_single_item_result_that_could_not_be_saved_is_not_completed(self):
        self.svc.select_asset("lab")
        self.svc.start()
        end = time.time() + 30
        while time.time() < end and self.svc.snapshot()["state"] in ("running", "idle"):
            for ap in self.svc.snapshot()["approvals"]:
                if ap["status"] == "pending":
                    self.svc.decide_approval(ap["id"], "approved", "appr")
            time.sleep(0.05)
        self.assertEqual(self.svc.snapshot()["state"], "completed")
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            snap = self.svc.verify_finding("f_banner", actor="appr")
        self.assertEqual(snap["state"], "failed")
        self.assertEqual(snap["failure"]["kind"], "persistence")
        self.assertEqual(snap["persistence_error"], "OSError")

    def test_no_ownership_lookup_or_scope_grant_while_saving_is_broken(self):
        ch = self.svc.issue_ownership_challenge(url=self.url, approver="appr")["challenge"]
        looked = []

        def lookup(name):
            looked.append(name)
            return [f'{name} text = "{ch["dns_txt_value"]}"']
        with patch("aegis.assessment.os.replace", side_effect=OSError("disk full")):
            with self.svc._lock:
                self.svc._save_state_locked()
            with self.assertRaises(ValueError):
                self.svc.verify_asset_ownership(url_or_host=self.url, method="dns_txt", actor="appr", dns_lookup=lookup)
            with self.assertRaises(ValueError):
                self.svc.confirm_asset_scope(url_or_host=self.url, approver="appr")
        self.assertEqual(looked, [])
        self.assertFalse(self.svc._is_external_service_asset(HOST))

    def test_deleting_the_active_real_asset_clears_its_conversation(self):
        self.onboard()
        self.run_l1()
        self.svc.a.chat_messages.append({"id": "m1", "role": "assistant", "content": f"{HOST} のリスクは高です"})
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")
        self.assertEqual(self.svc.snapshot()["chat_messages"], [])

    def test_a_real_service_name_stays_real_after_a_refused_restart(self):
        self.onboard()
        self.svc.delete_asset(self.svc.a.asset["id"], actor="appr")   # no asset record is left
        self.svc.workers.kill_all()
        os.unlink(self.dir / "authority.epoch")                      # the saved authority will be refused
        again = self.open()
        self.assertTrue(self.events("state.authority_rejected", again) or again._real_service_hosts)
        self.assertIn(HOST, again._real_service_hosts)
        with self.assertRaises(ValueError):
            again.register_asset(name=HOST, kind="API", environment="x")
        again.workers.kill_all()

    def test_saves_are_synced_to_disk(self):
        with patch("aegis.assessment.os.fsync", wraps=os.fsync) as sync:
            self.onboard()
        self.assertGreaterEqual(sync.call_count, 4)                  # state, epoch, and their directory


class TestSignInThrottleDoesNotRevealAccounts(unittest.TestCase):
    def setUp(self):
        from aegis import operators as ops_mod
        from aegis.operators import OperatorStore, hash_password
        self.ops_mod = ops_mod
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        (d / "operators.json").write_text(json.dumps({"operators": [
            {"name": "root", "display": "r", "roles": ["operator", "admin"], "password_hash": hash_password("root-password-1")},
            {"name": "late", "display": "l", "roles": ["operator"], "password_hash": hash_password("late-password-1")}]}))
        self.store = OperatorStore(d / "operators.json")

    def attempt(self, name):
        from aegis.operators import AuthError, LockedOut
        try:
            self.store.login(name, "wrong")
        except LockedOut:
            return "locked"
        except AuthError:
            return "denied"
        return "ok"

    def test_a_flood_of_made_up_names_gives_the_same_answers_for_accounts_and_non_accounts(self):
        m = self.ops_mod
        with patch("aegis.operators.verify_password", return_value=False), \
                patch("aegis.operators._MAX_TRACKED_NAMES", 20):
            before = {n: [self.attempt(n) for _ in range(m.MAX_AUTH_FAILURES - 1)] for n in ("root", "ghost")}
            self.assertEqual(before["root"], before["ghost"])
            for i in range(300):
                self.attempt(f"made-up-{i}")
            self.assertLessEqual(len(self.store._auth_failures), 20)
            self.assertLessEqual(len(self.store._overflow_failures), m._OVERFLOW_BUCKETS)
            after = {n: [self.attempt(n) for _ in range(3)] for n in ("root", "ghost")}
            self.assertEqual(after["root"], after["ghost"])          # no counter was evicted for either
            self.assertEqual(after["root"][-1], "locked")
            # names first seen while the table is full are treated alike as well
            self.assertEqual(self.attempt("late"), self.attempt("ghost-late"))

    def test_nothing_about_account_existence_enters_the_slot_choice(self):
        import inspect
        src = inspect.getsource(self.ops_mod.OperatorStore._slot_locked)
        self.assertNotIn("_ops", src)


def _real_confinement_available() -> bool:
    return sys.platform.startswith("linux") and KernelConfinement().status()["ok"]


@unittest.skipUnless(_real_confinement_available(),
                     "needs Linux with cgroup v2, nft and root or passwordless sudo")
class TestKernelConfinementOnLinux(unittest.TestCase):
    """Runs against the live kernel (CI). Loopback and a documentation address only."""

    def listener(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        self.addCleanup(srv.close)
        return srv, srv.getsockname()[1]

    WORKER = (
        "import json,os,socket,sys\n"
        "out={'env':os.environ.get('VULNIX_TEST_SECRET'),'uid':os.getuid(),'cg':open('/proc/self/cgroup').read().strip()}\n"
        "for label,addr in (('pinned',('127.0.0.1',int(sys.argv[1]))),('other',('127.0.0.1',int(sys.argv[2]))),"
        "('external',('198.51.100.1',443))):\n"
        "    s=socket.socket(); s.settimeout(1.0)\n"
        "    try:\n        s.connect(addr); out[label]='CONNECTED'\n"
        "    except OSError as e:\n        out[label]='BLOCKED:'+type(e).__name__\n"
        "    finally:\n        s.close()\n"
        "print(json.dumps(out))\n")

    def test_worker_reaches_only_the_pinned_destination(self):
        _, pinned = self.listener()
        _, other = self.listener()
        conf = KernelConfinement()
        with conf.session("127.0.0.1", pinned) as s:
            name = s.name
            self.assertGreaterEqual(s.evidence["kernel_dropped_packets"], 1)
            self.assertTrue(s.evidence["probe_in_cgroup"])
            res = WorkerPool().run([sys.executable, "-I", "-c", self.WORKER, str(pinned), str(other)], 30,
                                   extra_env={"VULNIX_TEST_SECRET": "s3cr3t-value"}, session=s)
            self.assertTrue(s.still_enforced())
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout.strip().splitlines()[-1])
        self.assertEqual(out["pinned"], "CONNECTED")
        self.assertTrue(out["other"].startswith("BLOCKED:"), out)
        self.assertTrue(out["external"].startswith("BLOCKED:"), out)
        self.assertEqual(out["env"], "s3cr3t-value")                  # passed in the environment
        self.assertEqual(out["uid"], os.getuid())                     # not left running as root
        self.assertTrue(out["cg"].endswith("/" + name), out)
        # nothing is left behind
        self.assertFalse((Path("/sys/fs/cgroup") / name).exists())
        self.assertFalse(s.still_enforced())

    def test_the_same_program_outside_the_confinement_is_not_blocked(self):
        _, pinned = self.listener()
        _, other = self.listener()
        res = WorkerPool().run([sys.executable, "-I", "-c", self.WORKER, str(pinned), str(other)], 30)
        out = json.loads(res.stdout.strip().splitlines()[-1])
        self.assertEqual(out["other"], "CONNECTED")                   # so the block above is the kernel rule

    def test_timeout_kills_everything_in_the_cgroup(self):
        _, pinned = self.listener()
        with KernelConfinement().session("127.0.0.1", pinned) as s:
            t0 = time.monotonic()
            res = WorkerPool().run([sys.executable, "-I", "-c", "import time; time.sleep(60)"], 1.5, session=s)
            self.assertLess(time.monotonic() - t0, 20)
            self.assertTrue(res.killed or res.returncode != 0)
            procs = subprocess.run(["cat", str(s.cgroup / "cgroup.procs")], capture_output=True, text=True).stdout
            deadline = time.time() + 5
            while procs.strip() and time.time() < deadline:
                time.sleep(0.1)
                procs = subprocess.run(["cat", str(s.cgroup / "cgroup.procs")], capture_output=True, text=True).stdout
            self.assertEqual(procs.strip(), "")


if __name__ == "__main__":
    unittest.main()
