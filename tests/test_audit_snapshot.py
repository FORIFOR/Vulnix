"""A log response and its integrity verdict must describe the same file read."""
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.audit import AuditLog


class TestConcurrentValidAuditAppend(unittest.TestCase):
    def test_simultaneous_worker_authorizations_keep_one_valid_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first, second = AuditLog(path), AuditLog(path)
            read_done, release = threading.Event(), threading.Event()
            original = first.verified_entries

            def pause_after_read():
                result = original()
                read_done.set()
                if not release.wait(5):
                    raise TimeoutError("audit test did not release the reader")
                return result

            results = []
            with patch.object(first, "verified_entries", side_effect=pause_after_read):
                a = threading.Thread(target=lambda: results.append(first.record("allow", tool="one")))
                b = threading.Thread(target=lambda: results.append(second.record("allow", tool="two")))
                a.start()
                self.assertTrue(read_done.wait(5))
                b.start()
                b.join(1)
                release.set()
                a.join(5)
                b.join(5)
            self.assertFalse(a.is_alive() or b.is_alive())
            self.assertEqual(len(results), 2)
            self.assertTrue(first.verify())

    def test_simultaneous_paid_reservations_cannot_exceed_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first, second = AuditLog(path), AuditLog(path)
            read_done, release = threading.Event(), threading.Event()
            original = first.verified_entries
            paused = False

            def pause_first_read():
                nonlocal paused
                result = original()
                if not paused:
                    paused = True
                    read_done.set()
                    if not release.wait(5):
                        raise TimeoutError("audit test did not release the reader")
                return result

            results = []

            def reserve(audit):
                try:
                    audit.record_with_budget("advisor.safe_send_requested", endpoint_kind="external",
                                             reserve_micro_usd=700, cap_micro_usd=1000)
                    results.append("accepted")
                except ValueError as exc:
                    results.append(str(exc))

            with patch.object(first, "verified_entries", side_effect=pause_first_read):
                a = threading.Thread(target=lambda: reserve(first))
                b = threading.Thread(target=lambda: reserve(second))
                a.start()
                self.assertTrue(read_done.wait(5))
                b.start()
                b.join(1)
                release.set()
                a.join(5)
                b.join(5)
            self.assertFalse(a.is_alive() or b.is_alive())
            self.assertEqual(sorted(results), ["accepted", "advisor budget exceeded"])
            self.assertTrue(first.verify())

    def test_valid_prefix_rollback_cannot_authorize_worker_or_paid_send(self):
        for send_kind in ("allow", "paid"):
            with self.subTest(send_kind=send_kind), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "audit.jsonl"
                audit = AuditLog(path)
                audit.record("test.first")
                prefix = path.read_text()
                audit.record("test.second")
                path.write_text(prefix)
                if send_kind == "allow":
                    with self.assertRaisesRegex(ValueError, "audit chain invalid"):
                        audit.record("allow", tool="http_probe")
                else:
                    with self.assertRaisesRegex(ValueError, "audit chain invalid"):
                        audit.record_with_budget("advisor.safe_send_requested", endpoint_kind="external",
                                                 reserve_micro_usd=100, cap_micro_usd=1000)

    def test_two_service_objects_interleave_noncritical_records_without_breaking_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first = AuditLog(path)
            first.record("test.first")
            second = AuditLog(path)
            first.record("test.first_more")
            second.record("test.second")
            first.record("allow", tool="http_probe")
            self.assertTrue(first.verify())

    def test_another_service_append_preserves_the_chain_before_a_send(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first = AuditLog(path)
            first.record("test.first")
            second = AuditLog(path)
            second.record("test.second")
            first.record("allow", tool="http_probe")
            self.assertTrue(first.verify())

    def test_paid_send_reservation_continues_another_valid_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first = AuditLog(path)
            first.record("test.first")
            second = AuditLog(path)
            second.record("test.second")
            first.record_with_budget("advisor.safe_send_requested", endpoint_kind="external",
                                     reserve_micro_usd=100, cap_micro_usd=1000)
            self.assertTrue(first.verify())


class TestAuditSnapshot(unittest.TestCase):
    def test_log_response_verifies_the_entries_it_returns_with_one_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            svc = AssessmentService(Path(tmp), 18081)
            try:
                svc.audit.record("audit_snapshot.test")
                with patch.object(svc.audit, "entries", wraps=svc.audit.entries) as reads:
                    response = svc.logs()
                self.assertTrue(response["chain_valid"])
                self.assertIn("audit_snapshot.test", [e["event"] for e in response["entries"]])
                self.assertEqual(reads.call_count, 1)

                # A modified entry is still returned, but never described as valid.
                path = svc.audit.path
                raw = path.read_text()
                path.write_text(raw.replace("audit_snapshot.test", "audit_snapshot.fake"))
                with patch.object(svc.audit, "entries", wraps=svc.audit.entries) as reads:
                    altered = svc.logs()
                self.assertFalse(altered["chain_valid"])
                self.assertIn("audit_snapshot.fake", [e["event"] for e in altered["entries"]])
                self.assertEqual(reads.call_count, 1)
            finally:
                svc.close()
