"""Measure CORS findings against independently labelled HTTP responses."""
from __future__ import annotations

import threading
import tempfile
import time
import unittest
from pathlib import Path
from urllib.request import Request, urlopen

from aegis.assessment import AssessmentService
from aegis.service_diag import analyze_l1_service_response
from tests import TEST_CONFINEMENT
from tests.fixtures.cors_policy_lab import CorsPolicyLab


class TestIndependentCorsPolicyLab(unittest.TestCase):
    def test_detected_policy_requires_a_credentialed_untrusted_origin(self):
        truth = {
            "reflected_credentials": True,
            "reflected_public": False,
            "public_wildcard": False,
            "patched": False,
            "generic_200": False,
        }
        decisions = {}
        for mode, unsafe in truth.items():
            with self.subTest(mode=mode):
                site = CorsPolicyLab(mode)
                thread = threading.Thread(target=site.serve_forever, daemon=True)
                thread.start()
                try:
                    request = Request(f"http://127.0.0.1:{site.server_port}/",
                                      headers={"Origin": "https://untrusted-origin.example"})
                    with urlopen(request, timeout=3) as response:
                        result = {
                            "status": response.status,
                            "headers": dict(response.headers),
                            "cors_probe_origin": "https://untrusted-origin.example",
                            "set_cookies": response.headers.get_all("Set-Cookie") or [],
                        }
                    findings = analyze_l1_service_response(
                        result, {"audit_hash": "lab-proof"}, "http://owned-cors.example.test/")
                    detected = any(f["id"] == "f_l1_cors" and f["verdict"] == "detected"
                                   for f in findings)
                    decisions[mode] = detected
                    self.assertEqual(detected, unsafe)
                    self.assertEqual(site.seen, ["/"])
                finally:
                    site.shutdown()
                    site.server_close()
                    thread.join(timeout=2)
        self.assertEqual(decisions, truth)

    def test_owned_site_path_keeps_the_same_distinction_and_evidence(self):
        host = "owned-cors.example.test"
        for mode, expected in (("reflected_credentials", True), ("public_wildcard", False)):
            with self.subTest(mode=mode):
                site = CorsPolicyLab(mode)
                thread = threading.Thread(target=site.serve_forever, daemon=True)
                thread.start()
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT,
                                                real_site_read_only=True)
                        svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
                        url = f"http://{host}:{site.server_port}/"
                        try:
                            challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                            svc.verify_asset_ownership(
                                url_or_host=url, method="dns_txt",
                                dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
                            )
                            svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                                    activate_workspace=True, allow_loopback_test=True)
                            self.assertEqual(site.seen, [])
                            svc.start()
                            deadline = time.monotonic() + 20
                            while time.monotonic() < deadline:
                                snap = svc.snapshot()
                                if snap["state"] in ("completed", "failed"):
                                    break
                                time.sleep(0.02)
                            self.assertEqual(snap["state"], "completed", snap.get("failure"))
                            self.assertEqual(site.seen, ["/"])
                            cors = [f for f in snap["findings"] if f["id"] == "f_l1_cors"]
                            self.assertEqual(bool(cors), expected)
                            if cors:
                                self.assertEqual(cors[0]["evidence_status"], "detected")
                                self.assertTrue(cors[0]["evidence"][0]["audit_hash"])
                        finally:
                            svc.close()
                finally:
                    site.shutdown()
                    site.server_close()
                    thread.join(timeout=2)
