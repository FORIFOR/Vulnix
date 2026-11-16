"""Owner contract plus independent 200-JSON target: classify only observed access."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.request import urlopen

from aegis.assessment import AssessmentService
from aegis.service_diag import analyze_l1_service_response
from tests import TEST_CONFINEMENT
from tests.fixtures.auth_response_lab import AuthResponseLab, BODIES


TRUTH = json.loads((Path(__file__).parent / "fixtures/auth_response_truth.json").read_text())


class TestAuthResponseLab(unittest.TestCase):
    def test_independent_labels_cover_targets(self):
        self.assertEqual(set(TRUTH), set(BODIES))

    def test_auth_error_200_is_not_detected_as_data_access(self):
        for mode, exposes_data in TRUTH.items():
            with self.subTest(mode=mode):
                lab = AuthResponseLab(mode)
                thread = threading.Thread(target=lab.serve_forever, daemon=True)
                thread.start()
                try:
                    with urlopen(f"http://127.0.0.1:{lab.server_port}/", timeout=3) as response:
                        observed = {"status": response.status, "headers": dict(response.headers),
                                    "body_prefix": response.read(4096).decode()}
                    findings = analyze_l1_service_response(
                        observed, {"audit_hash": "lab-proof", "saved_at": 1},
                        "http://owned-access.example.test/",
                        root_access={"requirement": "authentication_required", "spec_status": "confirmed",
                                     "spec_evidence": ["owner API contract v1"]})
                    finding = next(f for f in findings if f["id"] == "f_l1_unauth_api")
                    self.assertEqual(finding["verdict"] == "detected", exposes_data)
                    if mode.startswith("auth_error"):
                        self.assertIn("認証拒否", finding["summary"])
                        self.assertIn("保護対象データの取得は確認できません", finding["why_detected"])
                        self.assertNotIn("認証必須のJSON応答が未認証で取得可能", finding["title"])
                        self.assertIsNone(finding["what_was_established"])
                        self.assertNotIn("情報が露出", finding["impact"])
                    self.assertEqual(lab.seen, ["/"])
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)

    def test_gateway_worker_root_probe_keeps_the_same_six_labels(self):
        for mode, exposes_data in TRUTH.items():
            with self.subTest(mode=mode):
                lab = AuthResponseLab(mode)
                thread = threading.Thread(target=lab.serve_forever, daemon=True)
                thread.start()
                try:
                    with tempfile.TemporaryDirectory() as tmp, patch.dict("os.environ", {"AEGIS_ENV": "development"}):
                        svc = AssessmentService(Path(tmp), lab.server_port,
                                                l2_confinement=TEST_CONFINEMENT, verify_seconds=0.1)
                        try:
                            with patch.object(svc.gateway, "execute", wraps=svc.gateway.execute) as gateway, \
                                 patch.object(svc.workers, "run", wraps=svc.workers.run) as workers:
                                observed, ev = svc._exec("http_probe", "read_only_probe",
                                                         {"url": svc.a.target_url, "method": "GET"},
                                                         approval_actor="policy:auto-L1")
                            self.assertIsNotNone(observed)
                            self.assertEqual(gateway.call_count, 1)
                            self.assertEqual(workers.call_count, 1)
                            findings = analyze_l1_service_response(
                                observed, ev, svc.a.target_url,
                                root_access={"requirement": "authentication_required",
                                             "spec_status": "confirmed",
                                             "spec_evidence": ["owner API contract v1"]})
                            finding = next(f for f in findings if f["id"] == "f_l1_unauth_api")
                            self.assertEqual(finding["verdict"] == "detected", exposes_data)
                            self.assertEqual(lab.seen, ["/"])
                        finally:
                            svc.close()
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)
