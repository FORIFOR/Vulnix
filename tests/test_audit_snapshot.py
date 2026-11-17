"""A log response and its integrity verdict must describe the same file read."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis.audit import AuditLog


class TestConcurrentValidAuditAppend(unittest.TestCase):
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
