"""Persistence and audit tests for the read-only intelligence data."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegis.assessment import AssessmentService


class TestIntelligenceArchive(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.service = AssessmentService(self.root, 18081, real_site_read_only=True)
        self.addCleanup(self.service.close)

    def complete(self):
        with self.service._lock:
            self.service._set_state("running")
            self.service._set_state("completed")

    def test_only_saved_runs_are_exposed_and_reads_do_not_switch_assets(self):
        self.complete()
        before = self.service.a.asset["id"]
        payload = self.service.intelligence_snapshot("default")
        self.assertEqual(payload["state"], "available")
        self.assertEqual(len(payload["runs"]), 1)
        self.assertEqual(payload["runs"][0]["asset_id"], before)
        self.assertEqual(self.service.intelligence_snapshot("org_aaaaaaaaaaaa")["runs"], [])
        self.assertEqual(self.service.a.asset["id"], before)

    def test_failed_state_save_cannot_create_an_intelligence_history(self):
        with patch.object(self.service, "_save_state_locked", side_effect=lambda: setattr(self.service, "_persist_error", "disk")):
            self.complete()
        self.assertEqual(self.service.intelligence_snapshot("default")["runs"], [])

    def test_archive_durability_failure_cannot_expose_a_history_row(self):
        with patch("aegis.intelligence.sync_dir", side_effect=OSError("disk")):
            self.complete()
        self.assertEqual(self.service.intelligence_snapshot("default")["runs"], [])
        self.assertEqual(self.service.a.state, "completed")

    def test_changed_summary_or_broken_audit_cannot_be_used(self):
        self.complete()
        archive = self.root / "intelligence-runs.json"
        rows = json.loads(archive.read_text())
        rows[0]["summary"]["asset_id"] = "tampered"
        archive.write_text(json.dumps(rows))
        self.assertEqual(self.service.intelligence_snapshot("default")["runs"], [])
        with patch.object(self.service.audit, "verified_entries", return_value=([], False)):
            self.assertEqual(self.service.intelligence_snapshot("default")["state"], "audit_unavailable")
