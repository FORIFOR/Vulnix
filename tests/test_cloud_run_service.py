"""Cloud Run proof enters the existing signed scope gate, never L2 automatically."""
import tempfile
import time
import unittest
from pathlib import Path

from aegis.assessment import AssessmentService


class TestCloudRunService(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.svc = AssessmentService(Path(self.temp.name), 18081)
        self.addCleanup(self.svc.close)
        self.host = "cloud.example.com"
        self.svc.issue_ownership_challenge(url=f"https://{self.host}/")
        self.svc.register_cloud_run_subject(tenant="tenant-a", host=self.host,
                                            subject="sub-a", actor="admin-a")

    def finish(self, issued, *, tenant="tenant-a", requester="alice", host=None):
        now = time.time()
        return self.svc.finish_cloud_run_challenge(
            tenant=tenant, host=host or self.host, requester=requester,
            challenge=issued["challenge"], id_token="offline-token",
            verify_id_token=lambda _token, aud: {"iss": "https://accounts.google.com",
                "aud": aud, "sub": "sub-a", "iat": now - 1, "exp": now + 120},
            fetch_html=lambda _url: f'<html><head><meta name="vulnix-verify" content="{issued["proof_token"]}"></head></html>',
        )

    def test_verified_proof_needs_scope_and_revoke_blocks_diagnosis(self):
        issued = self.svc.issue_cloud_run_challenge(tenant="tenant-a", host=self.host, requester="alice")
        res = self.finish(issued)
        self.assertTrue(res["verified"])
        self.assertFalse(res["l2_auto_approved"])
        self.assertIsNone(self.svc._external_entry(self.host))
        scoped = self.svc.confirm_asset_scope(url_or_host=f"https://{self.host}/", approver="bob")
        self.assertTrue(scoped["scope_confirmed"])
        self.assertFalse(scoped["l2_auto_approved"])
        self.assertIsNotNone(self.svc._external_entry(self.host))
        self.svc.revoke_cloud_run_subject(tenant="tenant-a", host=self.host, actor="admin-a")
        self.assertIsNone(self.svc._external_entry(self.host))
        with self.assertRaises(ValueError):
            self.svc.confirm_asset_scope(url_or_host=f"https://{self.host}/")

    def test_other_requester_and_tenant_do_not_spend_challenge(self):
        issued = self.svc.issue_cloud_run_challenge(tenant="tenant-a", host=self.host, requester="alice")
        self.assertFalse(self.finish(issued, requester="bob")["verified"])
        self.assertFalse(self.finish(issued, tenant="tenant-b")["verified"])
        self.assertTrue(self.finish(issued)["verified"])

    def test_registration_change_during_fetch_rejects_proof(self):
        issued = self.svc.issue_cloud_run_challenge(tenant="tenant-a", host=self.host, requester="alice")
        now = time.time()
        def change(_url):
            self.svc.register_cloud_run_subject(tenant="tenant-a", host=self.host,
                                                subject="sub-a", actor="admin-a")
            return f'<head><meta name="vulnix-verify" content="{issued["proof_token"]}"></head>'
        res = self.svc.finish_cloud_run_challenge(
            tenant="tenant-a", host=self.host, requester="alice", challenge=issued["challenge"],
            id_token="offline-token", fetch_html=change,
            verify_id_token=lambda _token, aud: {"iss": "https://accounts.google.com",
                "aud": aud, "sub": "sub-a", "iat": now - 1, "exp": now + 120})
        self.assertFalse(res["verified"])
        self.assertIsNone(self.svc._external_entry(self.host))

    def test_asset_registration_refresh_invalidates_pending_challenge(self):
        issued = self.svc.issue_cloud_run_challenge(tenant="tenant-a", host=self.host, requester="alice")
        self.svc.issue_ownership_challenge(url=f"https://{self.host}/", approver="admin-a")
        self.assertFalse(self.finish(issued)["verified"])

    def test_asset_deletion_revokes_binding(self):
        asset_id = self.svc._asset_record(self.host)["id"]
        self.svc.delete_asset(asset_id, actor="admin-a")
        self.assertIsNone(self.svc.cloud_run_store.binding("tenant-a", self.host))
        with self.assertRaises(ValueError):
            self.svc.issue_cloud_run_challenge(tenant="tenant-a", host=self.host, requester="alice")


if __name__ == "__main__":
    unittest.main()
