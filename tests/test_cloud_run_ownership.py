"""Offline Cloud Run OIDC ownership contract; no Google or real host traffic."""
import unittest

from aegis.cloud_run_ownership import CloudRunProof


class TestCloudRunProof(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.bindings = {("tenant-a", "app.example.com"): "service-account-sub-a"}
        self.html = ""
        self.claims = {}
        self.calls = []

        def verify(token, audience):
            self.calls.append((token, audience))
            return dict(self.claims)

        def fetch(url):
            self.calls.append(("fetch", url))
            return self.html

        self.proof = CloudRunProof(
            registered_subject=lambda tenant, host: self.bindings.get((tenant, host)),
            verify_id_token=verify, fetch_html=fetch, now=lambda: self.now,
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
        self.assertIn(("fetch", "https://app.example.com/"), self.calls)

    def test_oidc_success_alone_never_proves_an_arbitrary_host(self):
        issued = self.issue()
        self.html = ""
        self.assertFalse(self.finish(issued))

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
        def expire(_url):
            self.now += 301
            return self.html
        self.proof._fetch_html = expire
        self.assertFalse(self.finish(issued))

        self.now = 1_800_000_000
        issued = self.issue()
        def revoke(_url):
            self.bindings[("tenant-a", "app.example.com")] = "service-account-sub-b"
            return self.html
        self.proof._fetch_html = revoke
        self.assertFalse(self.finish(issued))

    def test_replay_is_rejected(self):
        issued = self.issue()
        self.assertTrue(self.finish(issued))
        self.assertFalse(self.finish(issued))

    def test_wrong_requester_and_changed_binding_are_rejected(self):
        issued = self.issue()
        self.assertFalse(self.finish(issued, requester="operator-b"))
        issued = self.issue()
        self.bindings[("tenant-a", "app.example.com")] = "service-account-sub-b"
        self.assertFalse(self.finish(issued))

    def test_invalid_claims_and_unregistered_host_are_rejected(self):
        with self.assertRaises(ValueError):
            self.proof.issue("tenant-a", "other.example.com", "operator-a")
        for bad in ({"aud": "wrong"}, {"iss": "https://evil.example"}, {"exp": self.now - 1}):
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
        self.proof._fetch_html = lambda _url: (_ for _ in ()).throw(OSError("unavailable"))
        self.assertFalse(self.finish(issued))


if __name__ == "__main__":
    unittest.main()
