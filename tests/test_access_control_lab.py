"""Independent labels for read-only and isolated IDOR observations."""
from __future__ import annotations

import json
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aegis.evidence import reproduction_verdict
from aegis.service_diag import analyze_l1_service_response
from aegis.workers.reproduction_probe import run_lab_check
from tests.fixtures.access_control_lab import AccessControlLab, MODES


TRUTH = json.loads((Path(__file__).parent / "fixtures/access_control_truth.json").read_text())


class TestIndependentAccessControlLab(unittest.TestCase):
    def test_truth_table_covers_every_isolated_mode(self):
        self.assertEqual(set(TRUTH), MODES)

    def test_public_json_is_never_reported_as_protected_access(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                lab = AccessControlLab(mode)
                thread = threading.Thread(target=lab.serve_forever, daemon=True)
                thread.start()
                try:
                    req = Request(f"http://127.0.0.1:{lab.server_port}/")
                    try:
                        response = urlopen(req, timeout=3)
                    except HTTPError as e:
                        response = e
                    with response:
                        observed = {"status": response.status, "headers": dict(response.headers),
                                    "body_prefix": response.read(4096).decode()}
                    findings = analyze_l1_service_response(
                        observed, {"audit_hash": "lab-proof", "saved_at": 1},
                        "http://owned-access.example.test/")
                    access = [f for f in findings if f["id"] == "f_l1_unauth_api"]
                    self.assertFalse(any(f["verdict"] == "detected" for f in access))
                    self.assertEqual(lab.seen, [("/", None)])
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)

    def test_only_a_cross_account_object_can_be_proven(self):
        for mode, labels in TRUTH.items():
            with self.subTest(mode=mode):
                lab = AccessControlLab(mode)
                thread = threading.Thread(target=lab.serve_forever, daemon=True)
                thread.start()
                try:
                    args = SimpleNamespace(scheme="http", host="lab.test", ip="127.0.0.1",
                                           port=lab.server_port, check="idor")
                    result = run_lab_check(args)
                    verdict = reproduction_verdict(result, "idor")
                    self.assertEqual(verdict == "proven", labels["cross_account_access"])
                    if mode == "denied_403":
                        self.assertEqual(verdict, "not_reproduced")
                    if mode == "denied_404":
                        self.assertEqual(verdict, "unverified")
                    self.assertEqual(lab.seen, [("/api/accounts/B/secret", "acct_A")])
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)
