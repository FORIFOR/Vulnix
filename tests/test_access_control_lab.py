"""Independent labels for read-only and isolated IDOR observations."""
from __future__ import annotations

import json
import os
import shlex
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aegis.evidence import reproduction_verdict
from aegis import assessment as assessment_module
from aegis.assessment import AssessmentService
from aegis.service_diag import analyze_l1_service_response
from aegis.l2_rules import L2RuleSet, validate_profile, RuleError
from aegis.workers.reproduction_probe import run_lab_check
from tests.fixtures.access_control_lab import AccessControlLab, MODES
from tests.test_artex_bridge import FAKE
from tests import TEST_CONFINEMENT


TRUTH = json.loads((Path(__file__).parent / "fixtures/access_control_truth.json").read_text())


class TestIndependentAccessControlLab(unittest.TestCase):
    def test_truth_table_covers_every_isolated_mode(self):
        self.assertEqual(set(TRUTH), MODES)

    def test_changed_owner_contract_is_held_until_exact_acceptance(self):
        raw = json.loads((Path(__file__).parent / "fixtures/l2_profiles/example.json").read_text())
        raw["root_access"] = {"requirement": "authentication_required", "spec_status": "confirmed",
                              "spec_evidence": ["owner API specification section 3"]}
        rules = L2RuleSet([validate_profile(raw)])
        rules.sources = {"example": {"site": True, "sha256": "contract-v1"}}
        self.assertEqual(rules.hold_unaccepted({}), ["example"])
        self.assertEqual(rules.profiles["example"]["root_access"]["spec_status"], "unaccepted")
        accepted = L2RuleSet([validate_profile(raw)])
        accepted.sources = {"example": {"site": True, "sha256": "contract-v1"}}
        self.assertEqual(accepted.hold_unaccepted({"example": "contract-v1"}), [])
        self.assertEqual(accepted.profiles["example"]["root_access"]["spec_status"], "confirmed")

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
                    expected = [("/api/accounts/B/secret", "acct_B")]
                    if mode in {"unauth_exposure", "idor_vulnerable", "denied_403",
                                "confusing_200", "auth_required_account_api", "idor_decoy_marker"}:
                        expected.append(("/api/accounts/B/secret", "acct_A"))
                    self.assertEqual(lab.seen, expected)
                finally:
                    lab.shutdown()
                    lab.server_close()
                    thread.join(timeout=2)

    def test_owner_contract_distinguishes_public_and_protected_json(self):
        raw = json.loads((Path(__file__).parent / "fixtures/l2_profiles/example.json").read_text())
        observed = {"status": 200, "headers": {"Content-Type": "application/json"},
                    "body_prefix": '{"docs":"public-looking content"}'}
        ev = {"audit_hash": "lab-proof", "saved_at": 1}
        for requirement, expected in (("public", None), ("authentication_required", "detected")):
            with self.subTest(requirement=requirement):
                raw["root_access"] = {"requirement": requirement, "spec_status": "confirmed",
                                      "spec_evidence": ["owner API specification section 3"]}
                contract = validate_profile(raw)["root_access"]
                findings = analyze_l1_service_response(
                    observed, ev, "http://owned-access.example.test/", root_access=contract)
                access = [f for f in findings if f["id"] == "f_l1_unauth_api"]
                self.assertEqual(access[0]["verdict"] if access else None, expected)
                if access:
                    self.assertNotIn("機密情報を取得", access[0]["summary"])
        raw["root_access"] = {"requirement": "authentication_required", "spec_status": "confirmed",
                              "spec_evidence": []}
        with self.assertRaises(RuleError):
            validate_profile(raw)

    def test_unconfirmed_owner_contract_never_promotes_json(self):
        observed = {"status": 200, "headers": {"Content-Type": "application/json"}, "body_prefix": "{}"}
        findings = analyze_l1_service_response(
            observed, {"audit_hash": "lab-proof", "saved_at": 1},
            "http://owned-access.example.test/",
            root_access={"requirement": "authentication_required", "spec_status": "placeholder",
                         "spec_evidence": []})
        self.assertEqual(next(f for f in findings if f["id"] == "f_l1_unauth_api")["verdict"],
                         "candidate")
        unrelated = analyze_l1_service_response(
            observed, {"audit_hash": "lab-proof", "saved_at": 1},
            "http://owned-access.example.test/public",
            root_access={"requirement": "authentication_required", "spec_status": "confirmed",
                         "spec_evidence": ["owner API specification section 3"]})
        self.assertEqual(next(f for f in unrelated if f["id"] == "f_l1_unauth_api")["verdict"],
                         "candidate")

    def test_local_planner_receives_only_measured_surface_not_lab_truth(self):
        lab = AccessControlLab("unauth_exposure")
        thread = threading.Thread(target=lab.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {
                    "AEGIS_ENV": "development", "VULNIX_ARTEX_REAL_CMD": shlex.join(FAKE),
                    "VULNIX_ARTEX_LLM_URL": "http://127.0.0.1:9/v1"}):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=TEST_CONFINEMENT)
                try:
                    res, ev = svc._exec("http_probe", "read_only_probe",
                                        {"url": svc.a.target_url, "method": "GET"},
                                        approval_actor="policy:auto-L1")
                    svc._analyze(res, ev)
                    captured = []
                    real = assessment_module.run_artex_planner
                    def record(command, request, **kwargs):
                        captured.append(request)
                        return real(command, {**request, "fake_intents": []}, **kwargs)
                    with patch.object(assessment_module, "run_artex_planner", record):
                        svc.plan_with_artex("planner")
                    serialized = json.dumps(captured, ensure_ascii=False)
                    self.assertIn("Measured account resource link", serialized)
                    self.assertIn("present", serialized)
                    self.assertNotIn("unauth_exposure", serialized)
                    self.assertNotIn("VULNIX_LAB_IDOR_PROVEN", serialized)
                    self.assertNotIn("他アカウントの保護リソース", serialized)
                finally:
                    svc.close()
        finally:
            lab.shutdown()
            lab.server_close()
            thread.join(timeout=2)
