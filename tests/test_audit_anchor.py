"""Local audit anchor (Gate G option A, docs/AUDIT_ANCHOR.md).

A real helper (AnchorStore + AnchorServer on a Unix socket) runs in a thread, as the
same OS user; the separate-user setup is proven in Linux CI (scripts/audit_anchor_ci.py).
"""
import tests  # noqa: F401  (hermetic revocation-marker directory, no .env.local)
import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.audit import AuditLog, is_anchored_event
from aegis.audit_anchor import (ANCHOR_FILE, SOCKET_ENV, SOURCE_ENV, UID_ENV, AnchorClient, AnchorError,
                                AnchorServer, AnchorStore, StoreRefused, source_id_for)
from aegis.lab import set_lab_mode, start_lab

LAB_PORT = 18197
PAID = dict(endpoint_kind="external", reserve_micro_usd=100, cap_micro_usd=10_000)
NAME = "test"
# Tests run the helper as the same OS user. To exercise "protected", most clients are told
# the helper is another user and given that answer by an injected peer lookup; the real
# lookup (same user -> never protected) is tested on its own below.
OTHER_UID = os.getuid() + 1


def separate_client(sock, **kw):
    return AnchorClient(sock, expected_uid=OTHER_UID, source_name=NAME, timeout=2,
                        peer_uid=lambda s: OTHER_UID, **kw)


def _short_tmp() -> str:
    # Unix socket paths are limited to ~104 bytes on macOS.
    base = tempfile.gettempdir()
    return base if len(base) < 60 else "/tmp"


class Helper:
    """The anchor helper, in a thread."""

    def __init__(self, directory: Path, socket_path: Path):
        self.dir, self.socket = directory, socket_path
        self.srv = None

    def start(self, allow=(NAME,)):
        self.store = AnchorStore(self.dir)
        self.srv = AnchorServer(self.store, self.socket, allow_sources=allow)
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.srv is not None:
            self.srv.shutdown()
            self.srv.server_close()
            self.thread.join(2)
            self.srv = None

    def records(self) -> list[dict]:
        return [json.loads(line) for line in (self.dir / ANCHOR_FILE).read_text().splitlines()]


class AnchorBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=_short_tmp())
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.log_path = self.data / "audit.jsonl"
        self.helper = Helper(self.root / "anchor", self.root / "a.sock").start()
        self.addCleanup(self.helper.stop)

    def client(self):
        return separate_client(self.helper.socket)

    def audit(self, path=None, client=None):
        return AuditLog(path or self.log_path, anchor=client or self.client(), anchor_root=self.root)

    def assertRefused(self, reason, fn, *a, **kw):
        with self.assertRaises(AnchorError) as cm:
            fn(*a, **kw)
        self.assertIsInstance(cm.exception, ValueError)       # what audit-first callers catch
        self.assertEqual(cm.exception.reason, reason)


class TestCriticalEvents(unittest.TestCase):
    def test_the_anchored_event_list(self):
        for e in ("allow", "planner_llm.forwarding", "advisor.safe_send_requested", "result",
                  "approval.approved", "artex.item_approved", "diagnosis.observed", "diagnosis.opened"):
            self.assertTrue(is_anchored_event(e), e)
        for e in ("deny", "approval.auto", "approval.rejected", "agent.thought", "auth.login"):
            self.assertFalse(is_anchored_event(e), e)


class TestTamperAndRollback(AnchorBase):
    def test_anchored_records_and_status(self):
        log = self.audit()
        log.record("test.first")
        log.record("allow", tool="one")
        st = log.anchor_status(max_age=None)
        self.assertEqual(st, {"enabled": True, "protected": True, "last_seq": 2, "error": None})
        self.assertEqual(self.helper.store.head(log.anchor_source)["hash"], log.entries()[-1]["hash"])

    def test_tampered_entry_refuses_critical_record(self):
        log = self.audit()
        log.record("test.first", note="original")
        log.record("allow", tool="one")
        self.log_path.write_text(self.log_path.read_text().replace("original", "altered!"))
        self.assertRefused("chain_invalid", log.record, "allow", tool="two")
        self.assertFalse(log.anchor_status(max_age=None)["protected"])

    def test_truncated_log_is_a_rollback(self):
        log = self.audit()
        log.record("allow", tool="one")
        prefix = self.log_path.read_text()
        log.record("test.middle")
        log.record("allow", tool="two")
        self.log_path.write_text(prefix)
        self.assertRefused("rollback", log.record, "allow", tool="three")
        # also after a restart of the service (nothing in memory)
        fresh = self.audit()
        self.assertEqual(fresh.anchor_check()["error"], "rollback")
        self.assertRefused("rollback", fresh.record, "result", tool="x")

    def test_rewritten_tail_at_an_anchored_position_is_a_fork(self):
        log = self.audit()
        log.record("allow", tool="one")
        prefix = self.log_path.read_text()
        log.record("allow", tool="two")
        self.log_path.write_text(prefix)
        other = AuditLog(self.log_path)              # an unanchored writer refills the gap
        other.record("allow", tool="forged")
        self.assertRefused("fork", self.audit().record, "allow", tool="three")

    def test_rollback_of_log_and_reservation_file_together(self):
        log = self.audit()
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        floor = self.log_path.with_name(self.log_path.name + ".advisor-budget")
        old_log, old_floor = self.log_path.read_text(), floor.read_text()
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        self.assertEqual(floor.read_text().strip(), "200")
        # both files back to the same, consistent older state
        self.log_path.write_text(old_log)
        floor.write_text(old_floor)

        # The single-file check alone (no anchor) accepts it after a restart ...
        copy = self.root / "copy"
        shutil.copytree(self.data, copy)
        AuditLog(copy / "audit.jsonl").record_with_budget("advisor.safe_send_requested", **PAID)
        # ... the anchor does not.
        restarted = self.audit()
        self.assertRefused("rollback", restarted.record_with_budget, "advisor.safe_send_requested", **PAID)
        self.assertEqual(floor.read_text(), old_floor)


class TestAnchorFailures(AnchorBase):
    def test_helper_down_refuses_critical_and_keeps_noncritical(self):
        log = self.audit()
        log.record("allow", tool="one")
        self.helper.stop()
        self.assertRefused("anchor_unavailable", log.record, "allow", tool="two")
        self.assertRefused("anchor_unavailable", log.record, "diagnosis.observed", diag_id="d")
        log.record("test.noncritical")
        self.assertEqual(log.entries()[-1]["event"], "test.noncritical")
        self.assertNotIn("two", json.dumps(log.entries()))
        st = log.anchor_status(max_age=0)
        self.assertEqual((st["enabled"], st["protected"], st["error"]), (True, False, "anchor_unavailable"))

    def test_helper_never_started(self):
        log = self.audit(client=separate_client(self.root / "missing.sock"))
        self.assertFalse(log.anchor_check()["protected"])
        self.assertRefused("anchor_unavailable", log.record, "allow", tool="one")
        log.record("test.noncritical")

    def test_post_append_anchor_failure_is_reported_as_failure(self):
        log = self.audit()
        log.record("allow", tool="one")
        real = log._anchor.anchor
        with patch.object(log._anchor, "anchor", side_effect=AnchorError("anchor_unavailable")):
            self.assertRefused("anchor_unavailable", log.record, "result", tool="one")
        self.assertFalse(log.anchor_status(max_age=None)["protected"])
        # a status check verifies only: the failed record is not anchored behind the caller's back
        log.anchor_check()
        self.assertEqual(self.helper.store.head(log.anchor_source)["seq"], 1)
        # the unanchored record is still in the chain; the next critical record covers it
        with patch.object(log._anchor, "anchor", wraps=real):
            log.record("allow", tool="two")
        self.assertTrue(log.verify())
        self.assertTrue(log.anchor_status(max_age=None)["protected"])

    def test_corrupt_store_refuses_to_serve(self):
        log = self.audit()
        log.record("allow", tool="one")
        log.record("allow", tool="two")
        path = self.helper.dir / ANCHOR_FILE
        lines = path.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["seq"] = 7
        lines[0] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        self.assertRefused("anchor_corrupt", log.record, "allow", tool="three")
        self.assertEqual(log.anchor_status(max_age=0)["error"], "anchor_corrupt")
        self.helper.stop()
        with self.assertRaises(StoreRefused) as cm:
            AnchorStore(self.helper.dir)
        self.assertEqual(cm.exception.reason, "corrupt")

    def test_store_refuses_lower_or_forked_heads(self):
        store = self.helper.store
        store.anchor("audit:x", 3, "a" * 64)
        store.anchor("audit:x", 3, "a" * 64)                 # idempotent
        for seq, h, reason in ((2, "b" * 64, "rollback"), (3, "b" * 64, "fork")):
            with self.assertRaises(StoreRefused) as cm:
                store.anchor("audit:x", seq, h)
            self.assertEqual(cm.exception.reason, reason)
        self.assertEqual(len(self.helper.records()), 1)


@unittest.skipIf(os.geteuid() == 0, "root ignores file permissions")
class TestPermissions(AnchorBase):
    def test_anchor_file_not_writable(self):
        log = self.audit()
        log.record("allow", tool="one")
        path = self.helper.dir / ANCHOR_FILE
        os.chmod(path, 0o400)
        self.addCleanup(os.chmod, path, 0o600)
        self.assertRefused("anchor_store_unwritable", log.record, "allow", tool="two")

    def test_anchor_dir_not_writable_at_start(self):
        self.helper.stop()
        os.chmod(self.helper.dir, 0o500)
        self.addCleanup(os.chmod, self.helper.dir, 0o700)
        with self.assertRaises(StoreRefused):
            Helper(self.helper.dir, self.helper.socket).start()
        self.assertRefused("anchor_unavailable", self.audit().record, "allow", tool="one")

    def test_anchor_dir_writable_by_others_is_refused(self):
        self.helper.stop()
        os.chmod(self.helper.dir, 0o770)
        self.addCleanup(os.chmod, self.helper.dir, 0o700)
        with self.assertRaises(StoreRefused) as cm:
            AnchorStore(self.helper.dir)
        self.assertEqual(cm.exception.reason, "store_permissions")

    def test_socket_not_connectable(self):
        log = self.audit()
        log.record("allow", tool="one")
        os.chmod(self.helper.socket, 0o000)
        try:
            self.assertRefused("anchor_unavailable", log.record, "allow", tool="two")
        finally:
            os.chmod(self.helper.socket, 0o660)

    def test_new_store_is_private(self):
        self.assertEqual(self.helper.dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.helper.dir / ANCHOR_FILE).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.helper.socket.stat().st_mode & 0o777, 0o660)


class TestRestartAndConcurrency(AnchorBase):
    def test_service_restart_with_existing_anchor(self):
        log = self.audit()
        log.record("allow", tool="one")
        log.record("test.other")
        again = self.audit()
        st = again.anchor_check()
        self.assertEqual((st["protected"], st["last_seq"]), (True, 1))      # verify only, no tail anchoring
        again.record("allow", tool="two")
        self.assertTrue(again.verify())

    def test_helper_restart_rereads_its_file(self):
        log = self.audit()
        log.record("allow", tool="one")
        prefix = self.log_path.read_text()
        log.record("allow", tool="two")
        self.helper.stop()
        self.helper.start()
        self.assertEqual(self.helper.store.head(log.anchor_source)["seq"], 2)
        log.record("allow", tool="three")
        self.log_path.write_text(prefix)
        self.assertRefused("rollback", self.audit().record, "allow", tool="four")

    def test_lost_head_is_detected_in_memory(self):
        log = self.audit()
        log.record("allow", tool="one")
        self.helper.stop()
        (self.helper.dir / ANCHOR_FILE).write_text("")        # the helper's file is replaced
        self.helper.start()
        self.assertRefused("anchor_regressed", log.record, "allow", tool="two")

    def test_concurrent_writers_on_one_data_dir(self):
        logs = [self.audit(), self.audit()]
        errors = []

        def work(log, n):
            try:
                for i in range(15):
                    log.record("allow", tool=f"{n}-{i}")
                    log.record("test.noncritical", n=n)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        threads = [threading.Thread(target=work, args=(logs[i % 2], i)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)
        self.assertEqual(errors, [])
        entries, valid = logs[0].verified_entries()
        self.assertTrue(valid)
        self.assertEqual(len(entries), 120)
        seqs = [r["seq"] for r in self.helper.records()]
        self.assertEqual(seqs, sorted(set(seqs)))
        head = self.helper.store.head(source_id_for(NAME, self.root, self.log_path))
        self.assertEqual(entries[head["seq"] - 1]["hash"], head["hash"])
        for log in logs:
            self.assertTrue(log.anchor_status(max_age=None)["protected"])


class TestServiceIntegration(AnchorBase):
    def service(self, **kw):
        svc = AssessmentService(self.data, LAB_PORT, verify_seconds=0.01, audit_anchor=self.client(),
                                audit_anchor_root=self.root, **kw)
        self.addCleanup(svc.close)
        return svc

    def test_env_configured_same_user_helper_works_but_is_never_protected(self):
        env = {SOCKET_ENV: str(self.helper.socket), UID_ENV: str(os.getuid()), SOURCE_ENV: NAME}
        with patch.dict(os.environ, env):
            svc = AssessmentService(self.data, LAB_PORT, verify_seconds=0.01, audit_anchor_root=self.root)
        self.addCleanup(svc.close)
        svc.audit.record("allow", tool="one")                  # the anchor operates ...
        st = svc.snapshot()["audit_anchor"]
        self.assertEqual((st["enabled"], st["protected"], st["error"]), (True, False, "same_user"))
        self.assertNotIn("保護あり", svc.report_markdown())     # ... but is not protection

    def test_env_without_uid_or_source_refuses_critical_records(self):
        for env in ({SOCKET_ENV: str(self.helper.socket), SOURCE_ENV: NAME},
                    {SOCKET_ENV: str(self.helper.socket), UID_ENV: str(OTHER_UID)},
                    {SOCKET_ENV: str(self.helper.socket), UID_ENV: "x", SOURCE_ENV: NAME}):
            with self.subTest(env=sorted(env)), patch.dict(os.environ, env), \
                    tempfile.TemporaryDirectory(dir=self.root) as d:
                for k in (UID_ENV, SOURCE_ENV):
                    if k not in env:
                        os.environ.pop(k, None)
                svc = AssessmentService(Path(d), LAB_PORT, verify_seconds=0.01)
                try:
                    self.assertEqual(svc.snapshot()["audit_anchor"]["error"], "anchor_misconfigured")
                    self.assertRefused("anchor_misconfigured", svc.audit.record, "allow", tool="x")
                finally:
                    svc.close()

    def test_startup_check_and_status(self):
        svc = self.service()
        st = svc.snapshot()["audit_anchor"]
        self.assertTrue(st["enabled"] and st["protected"])
        self.assertIn("保護あり", svc.report_markdown())

    def test_startup_after_rollback_starts_refused(self):
        svc = self.service()
        svc.audit.record("allow", tool="one")
        prefix = svc.audit.path.read_text()
        svc.audit.record("allow", tool="two")
        svc.close()
        svc.audit.path.write_text(prefix)
        again = self.service()
        st = again.snapshot()["audit_anchor"]
        self.assertEqual((st["protected"], st["error"]), (False, "rollback"))
        report = again.report_markdown()
        self.assertNotIn("保護あり", report)
        self.assertIn("保護なし", report)
        with self.assertRaises(ValueError):
            again.diagnosis_state()

    def test_diagnosis_change_is_not_applied_without_the_anchor(self):
        svc = self.service()
        st = svc.diagnosis_state()
        st.observe(kind="account_resource_link", target_ref="T1", attrs={"present": True}, source="l1")
        before = json.dumps(st.export(), sort_keys=True)
        self.helper.stop()
        with self.assertRaises(ValueError):
            st.observe(kind="account_resource_link", target_ref="T1", attrs={"present": False}, source="l1")
        self.assertEqual(json.dumps(st.export(), sort_keys=True), before)
        self.assertFalse(svc.snapshot()["audit_anchor"]["protected"])


class TestFindingVerdictEndToEnd(AnchorBase):
    @classmethod
    def setUpClass(cls):
        cls.lab = start_lab(LAB_PORT)
        set_lab_mode("vulnerable", cls.lab)

    @classmethod
    def tearDownClass(cls):
        cls.lab.shutdown()
        cls.lab.server_close()

    def run_lab(self, stop_helper_at):
        svc = AssessmentService(self.data, LAB_PORT, verify_seconds=0.01, audit_anchor=self.client(),
                                audit_anchor_root=self.root)
        svc._may_switch_lab = False
        self.addCleanup(svc.close)
        original = svc.audit.record

        def record(event, **fields):
            if stop_helper_at(event, fields):
                self.helper.stop()
            return original(event, **fields)
        patch.object(svc.audit, "record", side_effect=record).start()
        self.addCleanup(patch.stopall)
        svc.start("operator")          # the requester; "audit" approves its L2
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            snap = svc.snapshot()
            pending = next((a for a in snap["approvals"] if a["status"] == "pending"), None)
            if pending:
                return svc, pending
            self.assertNotEqual(snap["state"], "failed", snap["failure"])
            time.sleep(0.02)
        self.fail("lab run did not request its approval")

    def wait_end(self, svc):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            snap = svc.snapshot()
            if snap["state"] in ("completed", "failed", "stopped"):
                return snap
            time.sleep(0.02)
        self.fail("lab run did not end")

    def assert_nothing_proven(self, snap):
        for f in snap["findings"]:
            self.assertNotEqual(f["evidence_status"], "proven", f["id"])
            self.assertFalse(any(e.get("tool") == "reproduction_probe" for e in f.get("evidence") or []))

    def test_verdict_is_not_applied_when_the_result_cannot_be_anchored(self):
        svc, pending = self.run_lab(lambda e, f: e == "result" and f.get("tool") == "reproduction_probe")
        svc.decide_approval(pending["id"], "approve", "audit")
        snap = self.wait_end(svc)
        self.assertEqual(snap["state"], "failed")
        self.assert_nothing_proven(snap)
        self.assertFalse(snap["audit_anchor"]["protected"])

    def test_approval_is_not_applied_when_it_cannot_be_anchored(self):
        svc, pending = self.run_lab(lambda e, f: False)
        self.helper.stop()
        with self.assertRaises(ValueError):
            svc.decide_approval(pending["id"], "approve", "audit")
        snap = svc.snapshot()
        self.assertEqual(next(a for a in snap["approvals"] if a["id"] == pending["id"])["status"], "pending")
        self.assert_nothing_proven(snap)

    def test_with_the_anchor_up_the_run_completes(self):
        svc, pending = self.run_lab(lambda e, f: False)
        svc.decide_approval(pending["id"], "approve", "audit")
        snap = self.wait_end(svc)
        self.assertEqual(snap["state"], "completed", snap["failure"])
        self.assertTrue(snap["audit_anchor"]["protected"])
        self.assertTrue(any(f["evidence_status"] == "proven" for f in snap["findings"]))


class TestSourceIdentity(AnchorBase):
    """A rolled-back copy must not pose as a new source (symlink, rename, other name)."""

    def rolled_back(self):
        log = self.audit()
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        floor = self.log_path.with_name(self.log_path.name + ".advisor-budget")
        old = (self.log_path.read_text(), floor.read_text())
        log.record("allow", tool="b")
        log.record_with_budget("advisor.safe_send_requested", **PAID)
        return old, floor

    def test_symlink_swap_to_an_older_copy(self):
        (old_log, old_floor), floor = self.rolled_back()
        (self.data / "audit-old.jsonl").write_text(old_log)
        self.log_path.unlink()
        os.symlink("audit-old.jsonl", self.log_path)
        floor.write_text(old_floor)
        restarted = self.audit()
        st = restarted.anchor_check()
        self.assertEqual((st["protected"], st["error"]), (False, "symlink"))
        self.assertRefused("symlink", restarted.record, "allow", tool="after-rollback")
        self.assertRefused("symlink", restarted.record_with_budget, "advisor.safe_send_requested", **PAID)

    def test_reviewer_poc_scenario(self):
        # scratchpad/poc/poc.py, on the current API: before the fix "allow" was accepted
        log = self.audit()
        log.record("allow", tool="a")
        old = self.log_path.read_text()
        log.record("allow", tool="b")
        log.record("approval.approved", request="x")
        self.assertTrue(log.anchor_status(max_age=None)["protected"])
        (self.data / "audit-old.jsonl").write_text(old)
        self.log_path.unlink()
        os.symlink("audit-old.jsonl", self.log_path)
        r = self.audit()
        self.assertFalse(r.anchor_check()["protected"])
        self.assertRefused("symlink", r.record, "allow", tool="after-rollback")
        self.assertEqual(len((self.data / "audit-old.jsonl").read_text().splitlines()), 1)   # nothing appended

    def test_directory_rename_and_symlink(self):
        (old_log, old_floor), _ = self.rolled_back()
        old_dir = self.root / "data-old"
        old_dir.mkdir()
        (old_dir / "audit.jsonl").write_text(old_log)
        (old_dir / "audit.jsonl.advisor-budget").write_text(old_floor)
        self.data.rename(self.root / "data-new")
        os.symlink("data-old", self.data)
        self.assertRefused("symlink", self.audit().record, "allow", tool="x")

    def test_directory_rename_without_symlink_is_a_rollback(self):
        (old_log, old_floor), _ = self.rolled_back()
        self.data.rename(self.root / "data-new")
        self.data.mkdir()
        (self.data / "audit.jsonl").write_text(old_log)
        (self.data / "audit.jsonl.advisor-budget").write_text(old_floor)
        self.assertRefused("rollback", self.audit().record, "allow", tool="x")

    def test_source_id_is_relative_and_unresolved(self):
        self.assertEqual(source_id_for(NAME, self.root, self.log_path), "test:data/audit.jsonl")
        self.assertIsNone(source_id_for(NAME, self.data, self.root / "elsewhere" / "audit.jsonl"))
        (self.root / "x").mkdir()
        log = AuditLog(self.root / "x" / "audit.jsonl", anchor=self.client(), anchor_root=self.data)
        self.assertRefused("anchor_misconfigured", log.record, "allow", tool="x")

    def test_unregistered_source_is_refused_by_the_helper(self):
        other = AnchorClient(self.helper.socket, expected_uid=OTHER_UID, source_name="other",
                             peer_uid=lambda s: OTHER_UID)
        self.assertRefused("anchor_unregistered_source", self.audit(client=other).record, "allow", tool="x")
        with self.assertRaises(StoreRefused):
            AnchorServer(self.helper.store, self.root / "b.sock", allow_sources=())


class TestPeerIdentity(AnchorBase):
    def test_peer_uid_mismatch_is_refused(self):
        wrong = AnchorClient(self.helper.socket, expected_uid=OTHER_UID, source_name=NAME,
                             peer_uid=lambda s: OTHER_UID + 1)
        self.assertRefused("anchor_peer_mismatch", self.audit(client=wrong).record, "allow", tool="x")
        unknown = AnchorClient(self.helper.socket, expected_uid=OTHER_UID, source_name=NAME,
                               peer_uid=lambda s: None)
        self.assertRefused("anchor_peer_unverified", self.audit(client=unknown).record, "allow", tool="x")

    def test_real_peer_lookup_same_user(self):
        real = AnchorClient(self.helper.socket, expected_uid=os.getuid(), source_name=NAME)
        log = self.audit(client=real)
        log.record("allow", tool="x")                      # works ...
        self.assertEqual(real.verified_peer_uid, os.getuid())
        st = log.anchor_status(max_age=None)
        self.assertEqual((st["protected"], st["error"]), (False, "same_user"))   # ... never "protected"
        other = AnchorClient(self.helper.socket, expected_uid=OTHER_UID, source_name=NAME)
        self.assertRefused("anchor_peer_mismatch", self.audit(client=other).record, "allow", tool="y")

    def test_env_local_cannot_configure_the_anchor(self):
        from aegis import server
        env_file = self.root / ".env.local"
        env_file.write_text(f"{SOCKET_ENV}=/tmp/fake.sock\n{UID_ENV}={os.getuid()}\n{SOURCE_ENV}=x\n"
                            "VULNIX_TEST_HARMLESS_KEY=1\n")
        with patch.dict(os.environ, {}, clear=False):
            for k in (SOCKET_ENV, UID_ENV, SOURCE_ENV, "VULNIX_TEST_HARMLESS_KEY"):
                os.environ.pop(k, None)
            self.assertEqual(server._load_env_local(env_file), 1)
            for k in (SOCKET_ENV, UID_ENV, SOURCE_ENV):
                self.assertNotIn(k, os.environ)


class TestDisabled(unittest.TestCase):
    def test_disabled_mode_is_unchanged_and_not_protected(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {SOCKET_ENV: ""}):
            svc = AssessmentService(Path(tmp), LAB_PORT, verify_seconds=0.01)
            try:
                self.assertIsNone(svc.audit._anchor)
                st = svc.snapshot()["audit_anchor"]
                self.assertEqual(st, {"enabled": False, "protected": False, "last_seq": None, "error": None})
                svc.audit.record("allow", tool="one")
                svc.audit.record("diagnosis.observed", diag_id="d")
                report = svc.report_markdown()
                self.assertNotIn("保護あり", report)
                self.assertIn("両方とも古い状態へ巻き戻された場合", report)
            finally:
                svc.close()

    def test_disabled_audit_log_does_not_touch_a_socket_or_extra_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = AuditLog(Path(tmp) / "audit.jsonl")
            with patch("socket.socket", side_effect=AssertionError("no socket when disabled")):
                log.record("allow", tool="one")
                log.record("result", tool="one")
                log.record_with_budget("advisor.safe_send_requested", **PAID)
                self.assertFalse(log.anchor_status()["enabled"])
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()),
                             ["audit.jsonl", "audit.jsonl.advisor-budget"])


if __name__ == "__main__":
    unittest.main()
