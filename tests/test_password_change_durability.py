"""A failed or interrupted password change never brings the old password back
(docs/PASSWORD_CHANGE_DURABILITY.md)."""
import tests  # noqa: F401  (hermetic revocation-marker directory)
import contextlib
import fcntl
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.audit import AuditLog, AuditWriteFailed
from aegis.operators import AuthError, OperatorStore, hash_password


class Crash(BaseException):
    """The process dies here (nothing after this point runs)."""


OLD, NEW = "op-password-12", "op-new-password-34"


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.seed = self.dir / "operators.json"
        self.seed.write_text(json.dumps({"operators": [
            {"name": "root", "display": "r", "roles": ["operator", "admin"],
             "password_hash": hash_password("root-password-1")},
            {"name": "op", "display": "o", "roles": ["operator"], "password_hash": hash_password(OLD)}]}))
        self.audit = AuditLog(self.dir / "platform-audit.jsonl")
        self.store = self.open()

    def reader(self):
        try:
            from aegis.operators import credential_history_reader
        except ImportError:         # before the review fixes
            from aegis.operators import audit_credential_generations
            return audit_credential_generations([self.dir / "audit.jsonl", self.dir / "platform-audit.jsonl"])
        return credential_history_reader(self.dir)()

    def open(self):
        try:
            return OperatorStore(self.seed, credential_generations=self.reader)
        except TypeError:           # before the fix: no such parameter
            return OperatorStore(self.seed)

    def restart(self):
        self.store = self.open()
        return self.store

    def journal(self, event="auth.password_changed", **fields):
        from aegis.server import _Journal
        return _Journal(self.audit, event, **fields)

    def change(self, store=None, journal=None):
        """What the server does: audit-first intent, the change, the abort record."""
        from aegis.operators import ChangeNotSaved
        store = store or self.store
        j = journal if journal is not None else self.journal(actor="op")
        try:
            return store.change_password("op", OLD, NEW, journal=j)
        except ChangeNotSaved:
            j.not_committed("not_saved")
            raise

    def signs_in(self, store, name, pw):
        try:
            store.login(name, pw)
            return True
        except AuthError:
            return False

    def assert_blocked(self, store, name="op", pws=(OLD, NEW)):
        for pw in pws:
            self.assertFalse(self.signs_in(store, name, pw), pw)

    def assert_only_new(self, store):
        self.assertFalse(self.signs_in(store, "op", OLD))
        self.assertTrue(self.signs_in(store, "op", NEW))

    def failing(self, store, *names):
        real = store._atomic_write

        def write(path, data):
            if Path(path).name in names:
                return False
            return real(path, data)
        return patch.object(store, "_atomic_write", side_effect=write)

    def events(self, name):
        return [e["fields"] for e in self.audit.entries() if e["event"] == name]


class TestReproduction(Base):
    """Fails on the code before the fix: the old password signed in again after a restart."""

    def test_old_password_does_not_come_back_after_restart(self):
        store = OperatorStore(self.seed)
        real = store._atomic_write
        with patch.object(store, "_atomic_write",
                          side_effect=lambda p, d: False if Path(p).name == "operators.json" else real(p, d)):
            with self.assertRaises(AuthError):
                store.change_password("op", OLD, NEW)
        again = OperatorStore(self.seed)
        with self.assertRaises(AuthError):
            again.login("op", OLD)


class TestPhaseTwoUnsaved(Base):
    def test_restart_while_phase_two_unsaved_blocks_both(self):
        with self.failing(self.store, "operators.json"):
            with self.assertRaises(AuthError):
                self.change()
            self.assertFalse(self.store.trusted())
        again = self.restart()                       # the retry never happened
        self.assert_blocked(again)
        self.assertTrue(self.signs_in(again, "root", "root-password-1"))   # nobody else is affected

    def test_admin_reset_clears_the_block(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        again = self.restart()
        j = self.journal("operator.password_reset", actor="root", target="op")
        again.reset_password("op", "reset-password-77", actor="root", journal=j)
        self.assertTrue(self.signs_in(again, "op", "reset-password-77"))
        self.assert_blocked(again, pws=(OLD, NEW))
        third = self.restart()
        self.assertTrue(self.signs_in(third, "op", "reset-password-77"))
        self.assertFalse(self.signs_in(third, "op", OLD))
        reset = self.events("operator.password_reset")[-1]
        self.assertEqual(reset["account"], "op")
        self.assertNotIn("password_hash", json.dumps(reset))

    def test_admin_reset_without_its_audit_record_changes_nothing(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        again = self.restart()
        j = self.journal("operator.password_reset", actor="root", target="op")
        with patch.object(AuditLog, "record", side_effect=OSError("disk full")):
            with self.assertRaises(AuditWriteFailed):
                again.reset_password("op", "reset-password-77", actor="root", journal=j)
        self.assert_blocked(self.restart(), pws=(OLD, NEW, "reset-password-77"))

    def test_admin_reset_is_admin_only_and_not_for_oneself(self):
        with self.assertRaises(AuthError):
            self.store.reset_password("root", "reset-password-77", actor="op")
        with self.assertRaises(AuthError):
            self.store.reset_password("root", "reset-password-77", actor="root")
        self.assertTrue(self.signs_in(self.store, "root", "root-password-1"))

    def test_offline_recovery(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        del self.store
        pw = self.recover("op")
        again = self.restart()
        self.assertTrue(self.signs_in(again, "op", pw))
        self.assert_blocked(again, pws=(OLD, NEW))
        self.assertEqual(self.events("auth.account_recovered_offline")[-1]["account"], "op")
        self.assertTrue(self.events("auth.password_change_committed"))

    def test_offline_recovery_of_the_only_admin(self):
        j = self.journal(actor="root")
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.store.change_password("root", "root-password-1", "root-new-password-9", journal=j)
        self.assert_blocked(self.restart(), "root", ("root-password-1", "root-new-password-9"))
        pw = self.recover("root")
        self.assertTrue(self.signs_in(self.restart(), "root", pw))

    def test_offline_recovery_refuses_while_the_server_runs(self):
        from scripts import recover_account
        fh = open(self.dir / ".lock", "a+")
        self.addCleanup(fh.close)
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = self.seed.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertNotEqual(recover_account.main(["--data-dir", str(self.dir), "--account", "op"]), 0)
        self.assertEqual(self.seed.read_bytes(), before)

    def test_retry_completing_makes_only_the_new_password_valid(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        self.store._last_retry = -1e9
        self.assertTrue(self.store.trusted())
        self.assertIn({"event": "auth.password_change_committed", "account": "op",
                       "credential_generation": 1, "after_retry": True}, self.store.recovery_events)
        self.assert_only_new(self.store)
        self.assert_only_new(self.restart())

    def recover(self, account):
        from scripts import recover_account
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(recover_account.main(["--data-dir", str(self.dir), "--account", account]), 0)
        text = (self.dir / "operators.recovery-credentials.txt").read_text()
        self.assertEqual((self.dir / "operators.recovery-credentials.txt").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(text.split("パスワード: ")[1].strip(), out.getvalue())   # never printed
        return text.split("パスワード: ")[1].strip()


class TestPhaseOneAndAuditFailures(Base):
    def test_phase_one_write_failure_changes_nothing(self):
        from aegis.operators import ChangeNotSaved
        before = self.seed.read_bytes()
        with self.failing(self.store, "operators.credential-state.json"):
            with self.assertRaises(ChangeNotSaved):
                self.change()
        self.assertTrue(self.store.trusted())
        self.assertEqual(self.seed.read_bytes(), before)
        self.assertTrue(self.signs_in(self.store, "op", OLD))
        self.assertFalse(self.signs_in(self.store, "op", NEW))
        aborted = self.events("auth.credential_change_aborted")[-1]
        self.assertEqual((aborted["account"], aborted["credential_generation"]), ("op", 1))
        again = self.restart()
        self.assertTrue(self.signs_in(again, "op", OLD))        # the intent is explicitly aborted

    def test_abort_after_restart_does_not_cancel_a_later_change_with_the_same_generation(self):
        from aegis.operators import ChangeNotSaved
        with self.failing(self.store, "operators.credential-state.json"), self.assertRaises(ChangeNotSaved):
            self.change()                                    # intent 1, aborted
        old_copy = self.seed.read_bytes()
        again = self.restart()
        self.assertEqual(self.change(again), 1)              # generation 1 again, a different hash
        self.seed.write_bytes(old_copy)                      # older copy restored
        self.assert_blocked(self.restart())

    def test_audit_failure_changes_nothing(self):
        before = self.seed.read_bytes()
        with patch.object(AuditLog, "record", side_effect=OSError("disk full")):
            with self.assertRaises(AuditWriteFailed):
                self.change()
        self.assertEqual(self.seed.read_bytes(), before)
        self.assertFalse((self.dir / "operators.credential-state.json").exists()
                         and "op" in (self.dir / "operators.credential-state.json").read_text())
        self.assertTrue(self.signs_in(self.store, "op", OLD))
        self.assertTrue(self.signs_in(self.restart(), "op", OLD))


class TestKillPoints(Base):
    """The process dies between two steps; after a restart the old password never works."""

    def crash_then_restart(self, ctx_factory):
        with ctx_factory(), self.assertRaises(Crash):
            self.change()
        return self.restart()

    def test_after_audit_intent(self):
        j = self.journal(actor="op")

        def then_die(**more):
            j(**more)
            raise Crash()
        with self.assertRaises(Crash):
            self.store.change_password("op", OLD, NEW, journal=then_die)
        self.assertEqual(self.events("auth.password_changed")[-1]["credential_generation"], 1)
        self.assert_blocked(self.restart())

    def _replace(self, target, after):
        real = os.replace

        def replace(src, dst):
            if Path(dst).name == target:
                if after:
                    real(src, dst)
                raise Crash()
            return real(src, dst)
        return lambda: patch("aegis.operators.os.replace", side_effect=replace)

    def test_after_temp_write_before_rename(self):
        self.assert_blocked(self.crash_then_restart(self._replace("operators.credential-state.json", False)))

    def test_after_rename_before_dir_fsync(self):
        self.assert_blocked(self.crash_then_restart(self._replace("operators.credential-state.json", True)))

    def test_between_phase_one_and_two(self):
        self.assert_blocked(self.crash_then_restart(self._replace("operators.json", False)))

    def test_phase_two_renamed_before_dir_fsync_is_committed(self):
        self.assert_only_new(self.crash_then_restart(self._replace("operators.json", True)))

    def test_after_phase_two_before_marker_cleared(self):
        real = self.store._atomic_write
        seen = []

        def write(path, data):
            if Path(path).name == "operators.credential-state.json":
                seen.append(1)
                if len(seen) == 2:            # the first wrote the marker; this one clears it
                    raise Crash()
            return real(path, data)
        self.assert_only_new(self.crash_then_restart(lambda: patch.object(self.store, "_atomic_write",
                                                                          side_effect=write)))

    def test_after_phase_two_before_completion_record(self):
        self.change()                         # the server's completion record never written
        self.assertFalse(self.events("auth.password_change_committed"))
        self.assert_only_new(self.restart())


class TestRollbackMissingCorrupt(Base):
    def test_accounts_file_restored_to_an_older_copy(self):
        old_copy = self.seed.read_bytes()
        self.change()
        self.seed.write_bytes(old_copy)
        self.assert_blocked(self.restart())

    def test_marker_file_restored_too(self):
        old_seed = self.seed.read_bytes()
        state = self.dir / "operators.credential-state.json"
        old_state = state.read_bytes() if state.exists() else None
        self.change()
        self.seed.write_bytes(old_seed)
        if old_state is None:
            state.unlink(missing_ok=True)
        else:
            state.write_bytes(old_state)
        self.assert_blocked(self.restart())

    def test_in_progress_flag_removed_by_hand(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        (self.dir / "operators.credential-state.json").write_text(json.dumps({"pending": {}}))
        self.assert_blocked(self.restart())

    def test_flag_removed_and_generation_raised_by_hand_with_the_old_hash(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        (self.dir / "operators.credential-state.json").write_text(json.dumps({"pending": {}}))
        raw = json.loads(self.seed.read_text())
        for o in raw["operators"]:
            if o["name"] == "op":
                o["credential_generation"] = 1
        self.seed.write_text(json.dumps(raw))
        self.assert_blocked(self.restart())

    def test_accounts_file_deleted_regenerates_fresh_accounts(self):
        self.change()
        self.seed.unlink()
        again = self.restart()
        self.assertIsNotNone(again.credentials_path)          # the existing first-run path
        self.assertFalse(self.signs_in(again, "op", NEW))
        self.assertFalse(self.signs_in(again, "root", "root-password-1"))
        creds = again.credentials_path.read_text()
        admin_pw = creds.split("ユーザー名: admin\nパスワード: ")[1].split("\n")[0]
        self.assertTrue(self.signs_in(again, "admin", admin_pw))
        self.assertTrue(self.signs_in(self.restart(), "admin", admin_pw))   # not blocked later either

    def test_accounts_file_corrupt_fails_closed(self):
        self.seed.write_text("{not json")
        with self.assertRaises(ValueError):
            self.open()

    def test_marker_file_corrupt_blocks_everyone_until_recovered(self):
        (self.dir / "operators.credential-state.json").write_text("{not json")
        again = self.restart()
        self.assertFalse(self.signs_in(again, "root", "root-password-1"))
        self.assertFalse(self.signs_in(again, "op", OLD))
        del again, self.store
        pw = TestPhaseTwoUnsaved.recover(self, "root")
        again = self.restart()
        self.assertTrue(self.signs_in(again, "root", pw))
        again.reset_password("op", "reset-password-77", actor="root",
                             journal=self.journal("operator.password_reset", actor="root", target="op"))
        self.assertTrue(self.signs_in(again, "op", "reset-password-77"))

    def test_unreadable_audit_refuses_to_start(self):
        from aegis.operators import CredentialStateUnverifiable
        self.change()

        def unreadable():
            raise ValueError("audit log cannot be read")
        with self.assertRaises(CredentialStateUnverifiable):
            OperatorStore(self.seed, credential_generations=unreadable)

    def test_blocked_account_cannot_unblock_itself_with_the_old_password(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        again = self.restart()
        with self.assertRaises(AuthError):
            again.change_password("op", OLD, "yet-another-password-5", journal=self.journal(actor="op"))
        self.assert_blocked(self.restart(), pws=(OLD, NEW, "yet-another-password-5"))

    def test_sessions_of_a_blocked_account_do_not_survive_restart(self):
        tok = self.store.login("op", OLD).token
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError):
            self.change()
        self.assertIsNone(self.restart().resolve(tok))


class TestSuccess(Base):
    def test_only_the_new_password_and_generation_matches_audit(self):
        keep = self.store.login("op", OLD).token
        other = self.store.login("op", OLD).token
        gen = self.store.change_password("op", OLD, NEW, keep_token=keep, journal=self.journal(actor="op"))
        self.assertEqual(gen, 1)
        self.assert_only_new(self.store)
        self.assertIsNotNone(self.store.resolve(keep))
        self.assertIsNone(self.store.resolve(other))
        on_disk = {o["name"]: o for o in json.loads(self.seed.read_text())["operators"]}
        self.assertEqual(on_disk["op"]["credential_generation"], 1)
        intent = self.events("auth.password_changed")[-1]
        self.assertEqual((intent["account"], intent["credential_generation"]), ("op", 1))
        self.assertEqual(intent["hash_digest"],
                         hashlib.sha256(on_disk["op"]["password_hash"].encode()).hexdigest())
        self.assertNotIn(on_disk["op"]["password_hash"], self.audit.path.read_text())
        self.assertEqual(self.reader()["op"][0], 1)
        again = self.restart()
        self.assert_only_new(again)
        self.assertIsNone(again.resolve(other))

    def test_second_change_increments_generation(self):
        self.change()
        gen = self.store.change_password("op", NEW, "third-password-56", journal=self.journal(actor="op"))
        self.assertEqual(gen, 2)
        again = self.restart()
        self.assertTrue(self.signs_in(again, "op", "third-password-56"))
        self.assertFalse(self.signs_in(again, "op", NEW))


# ---- review of PR #126 ------------------------------------------------------------------
class TestReviewFixes(Base):
    def recover(self, *extra, account="root", code=0):
        from scripts import recover_account
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = recover_account.main(["--data-dir", str(self.dir), "--account", account, *extra])
        self.assertEqual(rc, code)
        if code:
            return None
        return (self.dir / "operators.recovery-credentials.txt").read_text().split("パスワード: ")[1].strip()

    def test_junk_in_an_unused_platform_log_does_not_disable_the_check(self):
        # single-tenant: account events go to audit.jsonl (reviewer's s3.py)
        from aegis.operators import CredentialStateUnverifiable
        with patch.dict(os.environ, {"VULNIX_MULTI_TENANT": "0"}):
            self.audit = AuditLog(self.dir / "audit.jsonl")
            old = self.seed.read_text()
            self.change(self.open())
            self.seed.write_text(old)
            (self.dir / "operators.credential-state.json").unlink(missing_ok=True)
            (self.dir / "platform-audit.jsonl").write_text("garbage\n")
            with self.assertRaises(CredentialStateUnverifiable):
                self.open()
            self.recover(code=4)                                   # not without the explicit flag
            pw = self.recover("--quarantine-unreadable-audit")
            again = self.open()
            self.assertTrue(self.signs_in(again, "root", pw))
            self.assert_blocked(again)                             # nothing else is vouched for
            self.assertTrue(list(self.dir.glob("platform-audit.jsonl.quarantined-*")))
            events = [json.loads(line)["event"] for line in (self.dir / "audit.jsonl").read_text().splitlines()]
            self.assertIn("auth.account_recovered_offline", events)   # the log this mode uses
            self.assertIn("audit.log_quarantined", events)

    def test_unreadable_mode_log_refuses_to_start(self):
        from aegis.operators import CredentialStateUnverifiable
        self.change()
        with open(self.dir / "platform-audit.jsonl", "a") as fh:
            fh.write("{torn\n")
        with self.assertRaises(CredentialStateUnverifiable):
            self.open()

    def test_missing_log_with_past_changes_is_a_rollback(self):
        self.change()
        (self.dir / "platform-audit.jsonl").unlink()
        again = self.restart()
        self.assert_blocked(again)
        self.assertTrue(self.signs_in(again, "root", "root-password-1"))

    def test_audit_derived_block_is_kept_in_the_marker_file(self):
        old = self.seed.read_bytes()
        self.change()
        self.seed.write_bytes(old)
        self.restart()                                             # detects the rollback ...
        self.assert_blocked(OperatorStore(self.seed))              # ... and a store without the check still refuses

    def test_reregistered_account_is_not_locked_out_after_restart(self):
        self.change()                                              # op at generation 1 in the audit
        self.seed.unlink()
        again = self.restart()                                     # regenerated default accounts
        again.register("op", "op-again-password-3")
        self.assertTrue(self.signs_in(self.restart(), "op", "op-again-password-3"))

    def test_reregistered_name_with_existing_file(self):
        self.change()
        raw = json.loads(self.seed.read_text())
        raw["operators"] = [o for o in raw["operators"] if o["name"] != "op"]
        self.seed.write_text(json.dumps(raw))
        again = self.restart()
        again.register("op", "op-again-password-3")
        self.assertGreater(again.credential_fields("op")["credential_generation"], 1)
        self.assertTrue(self.signs_in(self.restart(), "op", "op-again-password-3"))

    def test_reset_lifts_the_sign_in_lock(self):
        from aegis.operators import LockedOut
        for _ in range(6):
            try:
                self.store.login("op", "wrong-password-0")
            except (AuthError, LockedOut):
                pass
        with self.assertRaises(LockedOut):
            self.store.login("op", OLD)
        self.store.reset_password("op", "reset-password-77", actor="root",
                                  journal=self.journal("operator.password_reset", actor="root", target="op"))
        self.assertTrue(self.signs_in(self.store, "op", "reset-password-77"))

    def test_phase_two_failure_message_says_the_account_locks(self):
        with self.failing(self.store, "operators.json"), self.assertRaises(AuthError) as cm:
            self.change()
        self.assertIn("ロック", str(cm.exception))
        self.assertNotIn("元へ戻ります", str(cm.exception))

    def test_listener_failure_after_the_intent_is_written_voids_it(self):
        def boom(entry):
            if entry["event"] == "auth.password_changed":
                raise RuntimeError("listener failed")
        self.audit.listeners.append(boom)
        with self.assertRaises(AuditWriteFailed):
            self.change()
        self.assertTrue(self.events("auth.password_changed"))     # the intent did reach the disk
        self.assertTrue(self.signs_in(self.restart(), "op", OLD))  # but it is voided, not a silent lockout

    def test_recovery_file_is_never_written_through_a_link(self):
        target = self.dir / "elsewhere.txt"
        os.symlink(target, self.dir / "operators.recovery-credentials.txt")
        before = self.seed.read_bytes()
        self.recover(account="op", code=2)
        self.assertFalse(target.exists())
        self.assertEqual(self.seed.read_bytes(), before)


class TestAnchoredPlatformLog(unittest.TestCase):
    """With an anchor, deleting or truncating the log that holds the intent is detected."""

    def setUp(self):
        from tests.test_audit_anchor import Helper, _short_tmp
        tmp = tempfile.TemporaryDirectory(dir=_short_tmp())
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.dir = root / "data"
        self.dir.mkdir()
        self.helper = Helper(root / "anchor", root / "a.sock").start()
        self.addCleanup(self.helper.stop)
        self.seed = self.dir / "operators.json"
        self.seed.write_text(json.dumps({"operators": [
            {"name": "root", "display": "r", "roles": ["operator", "admin"],
             "password_hash": hash_password("root-password-1")},
            {"name": "op", "display": "o", "roles": ["operator"], "password_hash": hash_password(OLD)}]}))

    def client(self):
        from tests.test_audit_anchor import separate_client
        return separate_client(self.helper.socket)

    def open(self):
        from aegis.operators import credential_history_reader
        return OperatorStore(self.seed, credential_generations=credential_history_reader(self.dir, anchor=self.client()))

    def signs_in(self, store, name, pw):
        return Base.signs_in(self, store, name, pw)

    def changed(self):
        from aegis.server import _Journal
        audit = AuditLog(self.dir / "platform-audit.jsonl", anchor=self.client(), anchor_root=self.dir)
        old = self.seed.read_bytes()
        self.open().change_password("op", OLD, NEW, journal=_Journal(audit, "auth.password_changed", actor="op"))
        return audit, old

    def test_deleted_log_and_restored_accounts_file_are_detected(self):
        _audit, old = self.changed()
        (self.dir / "platform-audit.jsonl").unlink()
        self.seed.write_bytes(old)
        (self.dir / "operators.credential-state.json").unlink(missing_ok=True)
        again = self.open()
        self.assertFalse(self.signs_in(again, "op", OLD))
        self.assertFalse(self.signs_in(again, "root", "root-password-1"))     # nothing can be vouched for
        self.assertFalse(self.signs_in(OperatorStore(self.seed), "op", OLD))  # kept on disk

    def test_appended_abort_cannot_void_an_anchored_intent(self):
        audit, old = self.changed()
        intent = [e for e in audit.entries() if e["event"] == "auth.password_changed"][-1]["fields"]
        AuditLog(self.dir / "platform-audit.jsonl").record(     # appended without the anchor
            "auth.credential_change_aborted", account="op", credential_generation=intent["credential_generation"],
            hash_digest=intent["hash_digest"])
        self.seed.write_bytes(old)
        (self.dir / "operators.credential-state.json").unlink(missing_ok=True)
        self.assertFalse(self.signs_in(self.open(), "op", OLD))

    def test_unchanged_anchored_log_signs_in_normally(self):
        self.changed()
        again = self.open()
        self.assertTrue(self.signs_in(again, "op", NEW))
        self.assertTrue(self.signs_in(again, "root", "root-password-1"))


if __name__ == "__main__":
    unittest.main()
