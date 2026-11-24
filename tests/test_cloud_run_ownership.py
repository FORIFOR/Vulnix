"""Offline Cloud Run OIDC ownership contract; no Google or real host traffic."""
import unittest
import tempfile
from pathlib import Path

from aegis.cloud_run_ownership import CloudRunProof
from aegis.cloud_run_store import SQLiteCloudRunStore


class TestCloudRunProof(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = SQLiteCloudRunStore(Path(self.temp.name) / "challenges.sqlite3")
        self.store.register("tenant-a", "app.example.com", "service-account-sub-a", self.now)
        self.html = ""
        self.claims = {}
        self.calls = []

        def verify(token, audience):
            self.calls.append((token, audience))
            return dict(self.claims)

        def fetch(host, address):
            self.calls.append(("fetch", host, address))
            return self.html

        self.proof = CloudRunProof(
            store=self.store,
            verify_id_token=verify, resolve_addresses=lambda _host: ["8.8.8.8"],
            fetch_pinned=fetch, now=lambda: self.now,
            new_challenge=lambda: "challenge-0123456789abcdef0123456789abcdef",
        )

    def issue(self):
        issued = self.proof.issue("tenant-a", "app.example.com", "operator-a")
        self.claims = {
            "iss": "https://accounts.google.com",
            "aud": issued["audience"],
            "sub": "service-account-sub-a",
            "iat": self.now - 1,
            "exp": self.now + 120,
        }
        self.html = f'<head><meta name="vulnix-verify" content="{issued["proof_token"]}"></head>'
        return issued

    def finish(self, issued, **overrides):
        args = {"challenge": issued["challenge"], "tenant": "tenant-a",
                "host": "app.example.com", "requester": "operator-a", "id_token": "mock-token"}
        args.update(overrides)
        return self.proof.finish(**args)

    def test_valid_proof_requires_oidc_and_host_challenge(self):
        issued = self.issue()
        self.assertTrue(self.finish(issued))
        self.assertIn(("fetch", "app.example.com", "8.8.8.8"), self.calls)

    def test_oidc_success_alone_never_proves_an_arbitrary_host(self):
        issued = self.issue()
        self.html = ""
        self.assertFalse(self.finish(issued))

    def test_every_resolved_address_must_serve_the_exact_meta_tag(self):
        issued = self.issue()
        self.proof._resolve_addresses = lambda _host: ["8.8.8.8", "8.8.4.4"]
        self.proof._fetch_pinned = lambda _host, ip: self.html if ip == "8.8.8.8" else "<head></head>"
        self.assertFalse(self.finish(issued))
        issued = self.issue()
        self.proof._fetch_pinned = lambda _host, _ip: self.html
        self.assertEqual(self.finish(issued), ["8.8.4.4", "8.8.8.8"])

    def test_private_resolution_blocks_all_http_fetches(self):
        issued = self.issue()
        self.proof._resolve_addresses = lambda _host: ["8.8.8.8", "127.0.0.1"]
        self.assertFalse(self.finish(issued))
        self.assertFalse(any(c[0] == "fetch" for c in self.calls))

    def test_wrong_subject_is_rejected(self):
        issued = self.issue()
        self.claims["sub"] = "service-account-sub-b"
        self.assertFalse(self.finish(issued))

    def test_empty_id_token_is_rejected_before_verifier_or_network(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, id_token=""))
        self.assertEqual(self.calls, [])

    def test_other_tenant_is_rejected_before_token_or_network(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, tenant="tenant-b"))
        self.assertEqual(self.calls, [])

    def test_other_host_is_rejected_before_token_or_network(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, host="other.example.com"))
        self.assertEqual(self.calls, [])

    def test_expired_challenge_is_rejected(self):
        issued = self.issue()
        self.now += 301
        self.assertFalse(self.finish(issued))
        self.assertEqual(self.calls, [])

    def test_expiry_or_binding_change_during_fetch_is_rejected(self):
        issued = self.issue()
        def expire(_host, _address):
            self.now += 301
            return self.html
        self.proof._fetch_pinned = expire
        self.assertFalse(self.finish(issued))

        self.now = 1_800_000_000
        issued = self.issue()
        def revoke(_host, _address):
            self.store.register("tenant-a", "app.example.com", "service-account-sub-b", self.now)
            return self.html
        self.proof._fetch_pinned = revoke
        self.assertFalse(self.finish(issued))

    def test_replay_is_rejected(self):
        issued = self.issue()
        self.assertTrue(self.finish(issued))
        self.assertFalse(self.finish(issued))

    def test_wrong_requester_and_changed_binding_are_rejected(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, requester="operator-b"))
        self.store.register("tenant-a", "app.example.com", "service-account-sub-b", self.now)
        self.assertFalse(self.finish(issued))

    def test_invalid_claims_and_unregistered_host_are_rejected(self):
        with self.assertRaises(ValueError):
            self.proof.issue("tenant-a", "other.example.com", "operator-a")
        for bad in ({"aud": "wrong"}, {"iss": "https://evil.example"},
                    {"exp": self.now - 1}, {"exp": float("nan")}):
            issued = self.issue()
            self.claims.update(bad)
            self.assertFalse(self.finish(issued))

    def test_signature_verifier_or_host_fetch_failure_is_closed(self):
        def fail_verifier(_token, _audience):
            raise ValueError("signature invalid")

        issued = self.issue()
        self.proof._verify_id_token = fail_verifier
        self.assertFalse(self.finish(issued))
        self.assertFalse(self.finish(issued))

        issued = self.issue()
        self.proof._verify_id_token = lambda _token, _audience: self.claims
        self.proof._fetch_pinned = lambda _host, _address: (_ for _ in ()).throw(OSError("unavailable"))
        self.assertFalse(self.finish(issued))

    def test_binding_lookup_failure_and_malformed_challenge_are_closed(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, challenge=[]))
        self.store.revoke("tenant-a", "app.example.com")
        self.assertFalse(self.finish(issued))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
