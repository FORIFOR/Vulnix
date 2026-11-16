"""Owner contract plus independent 200-JSON target: classify only observed access."""
from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from urllib.request import urlopen

from aegis.service_diag import analyze_l1_service_response
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
                    self.assertEqual(lab.seen, ["/"])
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)
