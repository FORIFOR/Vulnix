import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aegis import cloud_inventory as ci


class TestCloudInventory(unittest.TestCase):
    def test_fetch_uses_only_readonly_scope_and_returns_minimal_metadata(self):
        config = dict(client_id="synthetic", client_secret="fixture", redirect_uri="https://ui.lab.test/verify/cloud")
        calls = []

        def http(url, **kwargs):
            calls.append((url, kwargs))
            if url == ci.TOKEN_URL:
                return {"access_token": "fixture-access", "scope": ci.SCOPE, "token_type": "Bearer"}
            return {"projects": [{"projectId": "synthetic-project", "name": "projects/123",
                                  "displayName": "Lab", "state": "ACTIVE", "extra": "ignored"},
                                 {"projectId": "other-project", "name": "projects/234",
                                  "state": "DELETE_REQUESTED"}]}

        result = ci.fetch_projects(config, "lab-code", "lab-verifier", http=http)
        self.assertEqual(result, {"projects": [{"id": "synthetic-project", "number": "123", "label": "Lab"}],
                                  "incomplete": False})
        self.assertEqual(parse_qs(calls[0][1]["data"].decode())["code_verifier"], ["lab-verifier"])
        self.assertEqual(urlsplit(calls[1][0]).hostname, "cloudresourcemanager.googleapis.com")

    def test_rejects_broader_token_before_any_google_cloud_request(self):
        def http(url, **_kwargs):
            self.assertEqual(url, ci.TOKEN_URL)
            return {"access_token": "fixture-access", "scope": ci.SCOPE + " https://www.googleapis.com/auth/cloud-platform",
                    "token_type": "Bearer"}
        with self.assertRaises(ci.CloudInventoryError):
            ci.fetch_projects({}, "code", "verifier", http=http)

    def test_expired_or_cleared_auth_cannot_publish(self):
        registry = ci.Inventory()
        owner = ("org", "op", b"session")
        cfg = dict(client_id="synthetic", redirect_uri="https://ui.lab.test/verify/cloud")
        with patch.object(ci.time, "monotonic", return_value=1):
            reply = registry.start(owner, cfg)
            state = parse_qs(urlsplit(reply["url"]).query)["state"][0]
            flow, _ = registry.claim(owner, state)
        with patch.object(ci.time, "monotonic", return_value=1 + ci.STATE_TTL_S):
            with self.assertRaises(ci.CloudInventoryError):
                registry.publish(owner, flow, {"projects": []})

    def test_clear_invalidates_inflight_listing_and_its_verifier(self):
        registry = ci.Inventory()
        owner = ("org", "op", b"session")
        cfg = dict(client_id="synthetic", redirect_uri="https://ui.lab.test/verify/cloud")
        query = parse_qs(urlsplit(registry.start(owner, cfg)["url"]).query)
        state = query["state"][0]
        flow, _ = registry.claim(owner, state)
        registry.clear(owner)
        with self.assertRaises(ci.CloudInventoryError):
            registry.publish(owner, flow, {"projects": [{"id": "must-not-appear"}]})
        with self.assertRaises(ci.CloudInventoryError):
            registry.claim(owner, state)
        self.assertEqual(registry.get(owner), {"configured": True})
