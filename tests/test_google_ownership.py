"""Ownership proof through Google Search Console (aegis/google_ownership.py and the
/api/assets/google/* routes). Google is never contacted: its answers are stubbed."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from aegis import google_ownership as g
from tests.test_tenancy import TestPublicReadOnlyRealSites

CFG = {"VULNIX_GOOGLE_CLIENT_ID": "cid.apps.googleusercontent.com", "VULNIX_GOOGLE_CLIENT_SECRET": "sec-test",
       "VULNIX_GOOGLE_REDIRECT_URI": "https://vulnix.example.test/verify/google"}


class TestCoverage(unittest.TestCase):
    def test_a_domain_property_covers_the_domain_and_its_subdomains(self):
        sites = ["sc-domain:next-standards.com"]
        self.assertEqual(g.covering_property(sites, "next-standards.com", "https", 443), sites[0])
        self.assertEqual(g.covering_property(sites, "wonder.next-standards.com", "https", 443), sites[0])
        self.assertIsNone(g.covering_property(sites, "evil-next-standards.com", "https", 443))
        self.assertIsNone(g.covering_property(sites, "next-standards.com.evil.test", "https", 443))

    def test_a_url_prefix_property_covers_exactly_its_scheme_host_and_port(self):
        sites = ["https://next-standards.com/"]
        self.assertEqual(g.covering_property(sites, "next-standards.com", "https", 443), sites[0])
        self.assertIsNone(g.covering_property(sites, "wonder.next-standards.com", "https", 443))
        self.assertIsNone(g.covering_property(sites, "next-standards.com", "http", 80))
        self.assertIsNone(g.covering_property(sites, "next-standards.com", "https", 8443))

    def test_only_verified_owners_count_and_the_scope_must_be_granted(self):
        with patch.dict(os.environ, CFG):
            cfg = g.config()
        answers = {g.TOKEN_URL: {"access_token": "ya29.test", "scope": g.SCOPE},
                   g.SITES_URL: {"siteEntry": [
                       {"siteUrl": "sc-domain:mine.test", "permissionLevel": "siteOwner"},
                       {"siteUrl": "sc-domain:added-me.test", "permissionLevel": "siteFullUser"},
                       {"siteUrl": "https://unverified.test/", "permissionLevel": "siteUnverifiedUser"}]}}
        seen = []

        def http(url, data=None, headers=None):
            seen.append((url, headers or {}))
            return answers.get(url, {})
        self.assertEqual(g.owned_sites(cfg, "code", "verifier", http=http), ["sc-domain:mine.test"])
        self.assertEqual(seen[1][1]["Authorization"], "Bearer ya29.test")   # token only to Google
        answers[g.TOKEN_URL] = {"access_token": "ya29.test", "scope": "openid"}
        with self.assertRaises(g.GoogleOwnershipError):
            g.owned_sites(cfg, "code", "verifier", http=http)

    def test_not_configured_without_an_https_redirect(self):
        with patch.dict(os.environ, {**CFG, "VULNIX_GOOGLE_REDIRECT_URI": "http://x.test/cb"}):
            self.assertIsNone(g.config())


class TestGoogleOwnershipOverHttp(TestPublicReadOnlyRealSites):
    def setUp(self):
        super().setUp()
        p = patch.dict(os.environ, CFG)
        p.start()
        self.addCleanup(p.stop)

    def start(self, who, url):
        code, body = self.req(who, "/assets/google/start", {"url": url})
        self.assertEqual(code, 200, body)
        q = parse_qs(urlsplit(body["url"]).query)
        self.assertEqual(q["scope"], [g.SCOPE])
        self.assertEqual(q["code_challenge_method"], ["S256"])
        return q["state"][0]

    def finish(self, who, state, sites):
        with patch("aegis.google_ownership.owned_sites", return_value=sites):
            return self.req(who, "/assets/google/finish", {"code": "c", "state": state})

    def test_google_proof_then_start_the_diagnosis(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://wonder.next-standards.com"})
        st = self.start(a, "https://wonder.next-standards.com")
        code, body = self.finish(a, st, ["sc-domain:next-standards.com"])
        self.assertEqual(code, 200, body)
        self.assertTrue(body["verified"], body)
        code, body = self.req(a, "/assets/confirm-scope", {"host": "wonder.next-standards.com",
                                                          "confirmed_prohibited": True, "activate_workspace": True})
        self.assertEqual(code, 200, body)
        with patch("aegis.assessment.AssessmentService.start", return_value={"ok": True}):
            self.assertEqual(self.req(a, f"/assessments/{body['snapshot']['id']}/start", {})[0], 200)

    def test_a_property_for_another_host_does_not_prove_this_one(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://wonder.next-standards.com"})
        st = self.start(a, "https://wonder.next-standards.com")
        code, body = self.finish(a, st, ["https://next-standards.com/"])
        self.assertEqual(code, 200)
        self.assertFalse(body["verified"])
        self.assertNotEqual(self.req(a, "/assets/confirm-scope", {"host": "wonder.next-standards.com",
                                                                 "confirmed_prohibited": True})[0], 200)

    def test_the_state_is_single_use_and_bound_to_the_account(self):
        a, b = self.signup("alice"), self.signup("bobby")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        st = self.start(a, "https://next-standards.com")
        self.assertEqual(self.finish(b, st, ["sc-domain:next-standards.com"])[0], 400)   # other account
        st = self.start(a, "https://next-standards.com")
        self.assertEqual(self.finish(a, st, ["sc-domain:next-standards.com"])[0], 200)
        self.assertEqual(self.finish(a, st, ["sc-domain:next-standards.com"])[0], 400)   # replay

    def test_an_unregistered_site_cannot_start(self):
        a = self.signup("alice")
        self.assertEqual(self.req(a, "/assets/google/start", {"url": "https://next-standards.com"})[0], 400)

    def test_google_not_confirming_keeps_an_existing_proof(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        self._verify(a, "next-standards.com")
        st = self.start(a, "https://next-standards.com")
        self.assertFalse(self.finish(a, st, [])[1]["verified"])
        self.assertEqual(self.req(a, "/assets/confirm-scope", {"host": "next-standards.com",
                                                              "confirmed_prohibited": True})[0], 200)

    def test_the_option_is_visible_only_when_configured(self):
        a = self.signup("alice")
        self.assertIs(self.req(a, "/auth/me")[1]["google_ownership"], True)
        with patch.dict(os.environ, {"VULNIX_GOOGLE_CLIENT_ID": ""}):
            self.assertIs(self.req(a, "/auth/me")[1]["google_ownership"], False)
            self.assertEqual(self.req(a, "/assets/google/start", {"url": "https://x.test"})[0], 404)


if __name__ == "__main__":
    unittest.main()


class TestGoogleOwnershipReview(TestGoogleOwnershipOverHttp):
    """Review of the first version: path-scoped properties, the first real use, the
    registration changing during the check, the other modes and leaks."""

    def test_a_folder_property_does_not_prove_the_host(self):
        for site in ("https://shared.example.edu/~alice/", "https://shared.example.edu/?x=1",
                     "https://u:p@shared.example.edu/", "https://shared.example.edu:bad/"):
            self.assertIsNone(g.covering_property([site], "shared.example.edu", "https", 443), site)
        self.assertIsNone(g.covering_property(["sc-domain:com"], "example.com", "https", 443))

    def _proven_by_google(self, who, host):
        self.req(who, "/assets/challenge", {"url": f"https://{host}"})
        st = self.start(who, f"https://{host}")
        self.assertTrue(self.finish(who, st, [f"sc-domain:{host}"])[1]["verified"])
        self.req(who, "/assets/confirm-scope", {"host": host, "confirmed_prohibited": True, "activate_workspace": True})
        return self.reg.service(who["orgs"][0]["id"])

    def test_the_first_use_is_allowed_and_a_later_new_address_needs_a_new_proof(self):
        a = self.signup("alice")
        osvc = self._proven_by_google(a, "next-standards.com")
        ext = osvc._verified_external_hosts["next-standards.com"]
        with patch.object(type(osvc), "_withdrawn_since_locked", return_value=False):
            osvc._require_addresses_covered_by_proof("next-standards.com", ext, ["93.184.216.34"])
            self.assertEqual(ext["verified_addresses"], ["93.184.216.34"])
            with self.assertRaises(Exception):
                osvc._require_addresses_covered_by_proof("next-standards.com", ext, ["198.51.100.7"])
        self.assertNotIn("next-standards.com", osvc._verified_external_hosts)      # revoked

    def test_a_registration_changed_during_the_check_is_not_recorded(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        st = self.start(a, "https://next-standards.com")
        self.req(a, "/assets/challenge", {"url": "http://next-standards.com:8080"})       # switched meanwhile
        code, body = self.finish(a, st, ["https://next-standards.com/"])
        self.assertNotEqual(code, 200)
        self.assertNotEqual(self.req(a, "/assets/confirm-scope", {"host": "next-standards.com",
                                                                 "confirmed_prohibited": True})[0], 200)

    def test_a_state_from_another_org_of_the_same_account_is_refused(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        st = self.start(a, "https://next-standards.com")
        org2 = self.req(a, "/orgs", {"name": "second"})[1]["org"]["id"]
        with patch("aegis.google_ownership.owned_sites", return_value=["sc-domain:next-standards.com"]):
            code, _ = self.req(a, "/assets/google/finish", {"code": "c", "state": st}, org2)
        self.assertEqual(code, 400)
        self.assertEqual(self.finish(a, st, ["sc-domain:next-standards.com"])[0], 200)   # still usable by its owner

    def test_an_expired_state_is_refused(self):
        a = self.signup("alice")
        self.req(a, "/assets/challenge", {"url": "https://next-standards.com"})
        st = self.start(a, "https://next-standards.com")
        with patch("aegis.server.time.time", return_value=__import__("time").time() + g.STATE_TTL_S + 5):
            self.assertEqual(self.finish(a, st, ["sc-domain:next-standards.com"])[0], 400)

    def test_errors_never_carry_the_token_or_googles_answer(self):
        import urllib.error
        with patch.dict(os.environ, CFG):
            cfg = g.config()

        def boom(*a, **k):
            raise urllib.error.HTTPError(g.TOKEN_URL, 400, "ya29.SECRET-in-message", {}, None)
        with patch("urllib.request.urlopen", side_effect=boom):
            with self.assertRaises(g.GoogleOwnershipError) as cm:
                g.owned_sites(cfg, "code", "verifier")
        self.assertNotIn("ya29", str(cm.exception))

    def test_the_token_is_revoked_after_use(self):
        with patch.dict(os.environ, CFG):
            cfg = g.config()
        seen = []

        def http(url, data=None, headers=None):
            seen.append(url)
            return {g.TOKEN_URL: {"access_token": "ya29.t", "scope": g.SCOPE},
                    g.SITES_URL: {"siteEntry": []}}.get(url, {})
        g.owned_sites(cfg, "c", "v", http=http)
        self.assertEqual(seen[-1], g.REVOKE_URL)


class TestGoogleOwnershipWithoutTenancy(unittest.TestCase):
    def test_the_routes_work_on_a_single_workspace(self):
        import json, tempfile, threading, urllib.request
        from http.server import ThreadingHTTPServer
        from pathlib import Path
        from aegis.assessment import AssessmentService
        from aegis.operators import OperatorStore, hash_password
        from aegis.server import make_handler
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "operators.json").write_text(json.dumps({"operators": [
            {"name": "owner", "roles": ["operator", "approver", "admin"], "password_hash": hash_password("owner-pw-123")}]}))
        with patch.dict(os.environ, {}, clear=True):
            svc = AssessmentService(d, 18094, verify_seconds=30)
        self.addCleanup(svc.close)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(svc, OperatorStore(d / "operators.json")))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        root = f"http://127.0.0.1:{srv.server_port}/api"

        def post(path, body, cookie=""):
            r = urllib.request.Request(root + path, data=json.dumps(body).encode(), method="POST",
                                       headers={"Content-Type": "application/json", "X-Aegis-Request": "1", "Cookie": cookie})
            try:
                with urllib.request.urlopen(r) as x:
                    return x.status, json.loads(x.read()), x.headers.get("Set-Cookie", "")
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read()), ""
        import urllib.error
        _, _, ck = post("/auth/login", {"name": "owner", "password": "owner-pw-123"})
        cookie = ck.split(";")[0]
        with patch.dict(os.environ, CFG):
            post("/assets/challenge", {"url": "https://next-standards.com"}, cookie)
            code, body, _ = post("/assets/google/start", {"url": "https://next-standards.com"}, cookie)
        self.assertEqual(code, 200, body)
