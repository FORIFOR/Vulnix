"""Fixed truth labels for the independent mod_status fixture."""
import json
import os
import subprocess
import sys
import threading
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tests.fixtures.status_exposure_lab import StatusExposureLab
from unittest.mock import patch

from aegis.assessment import AssessmentService
from aegis import assessment as assessment_module
from tests import TEST_CONFINEMENT
from tests.test_artex_bridge import FAKE, LOOPBACK_LLM
from tests.artex_mock_llm import MockLLM


class TestStatusExposureLab(unittest.TestCase):
    def test_expired_or_revoked_scope_never_launches_a_worker(self):
        result = subprocess.run(
            [sys.executable, "-m", "scripts.bench_status_exposure_baseline"],
            cwd=Path(__file__).resolve().parents[1],
            env={**os.environ, "VULNIX_NO_ENV_LOCAL": "1"},
            check=True, capture_output=True, text=True, timeout=30,
        )
        checks = json.loads(result.stdout)["safety"]
        self.assertEqual(set(checks), {"expired_scope", "revoked_ownership"})
        self.assertTrue(all(row["refused"] for row in checks.values()))
        self.assertTrue(all(row["worker_launches"] == 0 for row in checks.values()))
        self.assertTrue(all(row["target_requests"] == [] for row in checks.values()))

    def test_only_vulnerable_mode_exposes_status_markers(self):
        for mode, expected_status in (("vulnerable", 200), ("patched", 403), ("generic_200", 200)):
            with self.subTest(mode=mode):
                server = StatusExposureLab(mode)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                try:
                    base = f"http://127.0.0.1:{server.server_port}"
                    with urllib.request.urlopen(base + "/", timeout=2) as root:
                        self.assertEqual(root.status, 200)
                        self.assertEqual(root.headers.get("Server"), "Apache/2.4.62")
                        self.assertEqual(root.read(), b"status lab root\n")
                    try:
                        response = urllib.request.urlopen(base + "/server-status?auto", timeout=2)
                    except urllib.error.HTTPError as error:
                        response = error
                    with response:
                        self.assertEqual(response.status, expected_status)
                        body = response.read()
                    self.assertEqual(b"Total Accesses" in body, mode == "vulnerable")
                    self.assertEqual(server.seen, ["/", "/server-status?auto"])
                finally:
                    server.shutdown()
                    server.server_close()


class TestStatusPlanToEvidence(unittest.TestCase):
    def test_owned_lab_plan_gateway_worker_and_verdict(self):
        for mode, expected, consent in (("vulnerable", "detected", True),
                                        ("patched", "not_reproduced", True),
                                        ("generic_200", "not_reproduced", True),
                                        ("vulnerable", None, False),
                                        ("non_apache", None, True)):
            with self.subTest(mode=mode, consent=consent):
                site = StatusExposureLab(mode)
                thread = threading.Thread(target=site.serve_forever, daemon=True)
                thread.start()
                try:
                    with tempfile.TemporaryDirectory() as tmp:
                        with patch.dict(os.environ, {"AEGIS_ENV": "development"}):
                            svc = AssessmentService(Path(tmp), 18081,
                                l2_confinement=TEST_CONFINEMENT, real_site_read_only=True)
                            try:
                                host = "owned-status.example.test"
                                svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
                                svc._real_site_local_artex = True
                                svc._artex_real_cmd = FAKE
                                svc._artex_llm_url = LOOPBACK_LLM
                                url = f"http://{host}:{site.server_port}"
                                challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                                svc.verify_asset_ownership(url_or_host=url, method="dns_txt",
                                    dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
                                svc.confirm_asset_scope(url_or_host=url, activate_workspace=True,
                                    allow_loopback_test=True, allow_status_probe=consent)
                                original = assessment_module.run_artex_planner

                                def propose_status(command, request, **kwargs):
                                    request = {**request, "fake_intents": [{
                                        "summary": "Check Apache mod_status exposure",
                                        "asset_ids": [1], "priority": 5}]}
                                    return original(command, request, **kwargs)

                                with MockLLM() as model, patch.dict(os.environ, {
                                        "VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                                        "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                                        "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}), \
                                        patch.object(assessment_module, "run_artex_planner",
                                                     side_effect=propose_status):
                                    svc.start()
                                    deadline = time.monotonic() + 20
                                    while svc.snapshot()["state"] == "running" and time.monotonic() < deadline:
                                        time.sleep(0.02)
                                snap = svc.snapshot()
                                self.assertEqual(snap["state"], "completed", snap.get("failure"))
                                selected = consent and mode != "non_apache"
                                if selected:
                                    plan = snap["artex_plan"]["plan"]
                                    item = next(i for i in plan["items"]
                                                if i["catalog_id"] == "l1_apache_mod_status")
                                    self.assertEqual(item["status"], "completed")
                                else:
                                    self.assertIsNone((snap.get("artex_plan") or {}).get("plan"))
                                    self.assertTrue(any(e["event"] == "artex.initial_skipped"
                                                        for e in svc.audit.entries()))
                                self.assertEqual(site.seen, ["/", "/server-status?auto"] if selected else ["/"])
                                found = [f for f in snap["findings"]
                                         if f["id"] == "f_l1_apache_mod_status"]
                                if selected:
                                    self.assertEqual(found[0]["evidence_status"], expected)
                                    self.assertTrue(found[0]["evidence"][0]["audit_hash"])
                                else:
                                    self.assertEqual(found, [])
                            finally:
                                svc.close()
                finally:
                    site.shutdown()
                    site.server_close()
                    thread.join(timeout=2)
