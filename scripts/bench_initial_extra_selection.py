"""Same local HTTPS CORS/Cookie cases under fixed, always-plan, and gated L1.

The only currently executable extra real-site L1 check is Apache mod_status.
These two classes need no extra GET. This benchmark measures avoided planner
work, not an actual model's ability to understand unseen websites.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import ssl
import subprocess
import tempfile
import threading
import time
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from aegis import assessment as assessment_module  # noqa: E402
from aegis.artex_bridge import safe_public_fingerprint  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.confinement import KernelConfinement  # noqa: E402
from aegis.l2_rules import validate_profile  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.fixtures.cors_policy_lab import CorsPolicyLab  # noqa: E402
from tests.fixtures.cookie_purpose_lab import CookiePurposeLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
CORS_TRUTH = {"reflected_credentials": True, "reflected_public": False,
              "public_wildcard": False, "patched": False, "generic_200": False}
COOKIE_TRUTH = json.loads((FIXTURES / "cookie_purpose_truth.json").read_text())
COOKIE_OWNER = json.loads((FIXTURES / "cookie_owner_specs.json").read_text())
STATUS_INTENT = {"summary": "Check Apache mod_status exposure", "asset_ids": [1], "priority": 5}


def _certificate(directory: Path) -> Path:
    certificate = directory / "certificate.pem"
    private = directory / "private.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(private), "-out", str(certificate),
        "-subj", "/CN=owned-cors.example.test", "-days", "1",
        "-addext", "subjectAltName=DNS:owned-cors.example.test,DNS:owned-cookie.example.test",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return certificate


def measure(kind: str, mode: str, strategy: str, certificate: Path) -> dict:
    if kind not in ("cors", "cookie") or strategy not in ("fixed", "always", "observed"):
        raise ValueError("unknown benchmark condition")
    host = f"owned-{kind}.example.test"
    site = CorsPolicyLab(mode) if kind == "cors" else CookiePurposeLab(mode)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(certificate.parent / "private.pem"))
    site.socket = context.wrap_socket(site.socket, server_side=True)
    thread = threading.Thread(target=site.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN")
    command = [real_bin] if real_bin else FAKE
    try:
        with tempfile.TemporaryDirectory() as tmp, MockLLM(intents=[STATUS_INTENT]) as model:
            url = f"https://{host}:{site.server_port}/"
            env = {
                "AEGIS_ENV": "production" if real_bin else "development",
                "VULNIX_TEST_CA_FILE": str(certificate),
                "VULNIX_REAL_SITE_INITIAL_ARTEX": "1" if strategy == "observed" else "0",
                "VULNIX_REAL_SITE_LOCAL_ARTEX": "1",
                "VULNIX_ARTEX_REAL_CMD": shlex.join(command),
                "VULNIX_ARTEX_EXPECTED_SHA256": os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", ""),
                "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions",
            }
            with patch.dict(os.environ, env):
                svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT,
                                        real_site_read_only=True)
                try:
                    if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                        svc._l2_confinement = KernelConfinement()
                    svc._custom_resolver = lambda name: ["127.0.0.1"] if name == host else []
                    svc._real_site_local_artex = True
                    svc._artex_real_cmd = command
                    profile = None
                    if kind == "cookie":
                        profile = validate_profile({
                            **json.loads((FIXTURES / "l2_profiles/example.json").read_text()),
                            "cookie_policy": COOKIE_OWNER[mode],
                        })
                        profile["checks"] = []
                    profile_patch = (patch.object(svc, "_l2_profile", return_value=profile)
                                     if profile else nullcontext())
                    with profile_patch:
                        challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                        svc.verify_asset_ownership(
                            url_or_host=url, method="dns_txt",
                            dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'],
                        )
                        svc.confirm_asset_scope(url_or_host=url, confirmed_prohibited=True,
                                                activate_workspace=True, allow_loopback_test=True)
                        assert site.seen == []
                        observed_response = []
                        original_analyze = svc._analyze

                        def capture_response(response, evidence):
                            observed_response.append(response)
                            result = original_analyze(response, evidence)
                            if strategy == "always":
                                # The historical always-plan path ran during the
                                # initial diagnosis, before result completion.
                                fingerprint = safe_public_fingerprint(response, scheme="https")
                                svc._plan_with_artex("policy:benchmark", llm_mode="gateway-forward",
                                                     fingerprint=fingerprint)
                            return result

                        original_runner = assessment_module.run_artex_planner
                        planner_calls = [0]

                        def local_intent(cmd, request, **kwargs):
                            planner_calls[0] += 1
                            payload = request if real_bin else {**request, "fake_intents": [STATUS_INTENT]}
                            return original_runner(cmd, payload, **kwargs)

                        with patch.object(svc, "_analyze", side_effect=capture_response), \
                             patch.object(svc.workers, "run", wraps=svc.workers.run) as workers, \
                             patch.object(assessment_module, "run_artex_planner",
                                          side_effect=local_intent):
                            started = time.monotonic()
                            svc.start()
                            deadline = started + 120
                            while svc.snapshot()["state"] == "running" and time.monotonic() < deadline:
                                time.sleep(0.02)
                            snap = svc.snapshot()
                            if snap["state"] != "completed":
                                raise RuntimeError(snap.get("failure"))
                            assert len(observed_response) == 1
                            elapsed = time.monotonic() - started
                            finding_id = "f_l1_cors" if kind == "cors" else "f_l1_cookies"
                            finding = next((f for f in snap["findings"] if f["id"] == finding_id), None)
                            verdict = finding["verdict"] if finding else "none"
                            expected = ("detected" if CORS_TRUTH[mode] else "none") if kind == "cors" else COOKIE_TRUTH[mode]
                            payload = json.dumps(model.requests, ensure_ascii=False)
                            assert host not in payload and url not in payload and mode not in payload
                            plan = (snap.get("artex_plan") or {}).get("plan") or {}
                            planned = [i for i in plan.get("items", []) if i.get("catalog_id") == "l1_apache_mod_status"]
                            assert site.seen == ["/"], site.seen
                            return {
                                "kind": kind, "mode": mode, "strategy": strategy,
                                "expected": expected, "verdict": verdict,
                                "target_get": len(site.seen), "worker_launches": workers.call_count,
                                "planner_calls": planner_calls[0],
                                "local_model_calls": len(model.requests),
                                "status_plan_proposed": bool(planned),
                                "status_plan_executable": any(i.get("status") == "planned" for i in planned),
                                "elapsed_s": round(elapsed, 3),
                                "budget_est_tokens": (plan.get("llm_gateway") or {}).get("est_tokens") or 0,
                                "hypothetical_model_cost_usd": (plan.get("llm_gateway") or {}).get("est_cost_usd") or 0,
                                "engine_kind": (plan.get("engine") or {}).get("kind"),
                            }
                finally:
                    svc.close()
    finally:
        site.shutdown()
        site.server_close()
        thread.join(timeout=2)


def summarize(rows: list[dict]) -> dict:
    strategies = {}
    for strategy in ("fixed", "always", "observed"):
        selected = [row for row in rows if row["strategy"] == strategy]
        detection = {
            "tp": sum(r["expected"] == "detected" and r["verdict"] == "detected" for r in selected),
            "fp": sum(r["expected"] != "detected" and r["verdict"] == "detected" for r in selected),
            "fn": sum(r["expected"] == "detected" and r["verdict"] != "detected" for r in selected),
            "tn": sum(r["expected"] != "detected" and r["verdict"] != "detected" for r in selected),
        }
        detection["precision"] = (detection["tp"] / (detection["tp"] + detection["fp"])
                                  if detection["tp"] + detection["fp"] else None)
        detection["recall"] = (detection["tp"] / (detection["tp"] + detection["fn"])
                               if detection["tp"] + detection["fn"] else None)
        strategies[strategy] = {
            "cases": len(selected),
            "detection": detection,
            "selection": {"tp": 0, "fp": sum(r["status_plan_proposed"] for r in selected),
                          "fn": 0, "tn": sum(not r["status_plan_proposed"] for r in selected),
                          "precision": 0.0 if any(r["status_plan_proposed"] for r in selected) else None,
                          "recall": None},
            "matched_independent_labels": sum(r["verdict"] == r["expected"] for r in selected),
            "target_get": sum(r["target_get"] for r in selected),
            "worker_launches": sum(r["worker_launches"] for r in selected),
            "planner_calls": sum(r["planner_calls"] for r in selected),
            "local_model_calls": sum(r["local_model_calls"] for r in selected),
            "unnecessary_extra_proposals": sum(r["status_plan_proposed"] for r in selected),
            "elapsed_s_sum": round(sum(r["elapsed_s"] for r in selected), 3),
            "budget_est_tokens_sum": sum(r["budget_est_tokens"] for r in selected),
            "hypothetical_model_cost_usd_sum": round(sum(r["hypothetical_model_cost_usd"] for r in selected), 6),
        }
    return {"scope": "local_https_cors_and_cookie_only", "model": "local_scripted_not_abliteration",
            "selection_truth": "no Apache status check is applicable to these 15 cases",
            "strategies": strategies, "rows": rows}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true", help="One CORS and one Cookie case for the real ARTEX CI job")
    args = parser.parse_args()
    cases = (("cors", ("public_wildcard",)), ("cookie", ("session_no_httponly",))) if args.smoke else (
        ("cors", CORS_TRUTH), ("cookie", COOKIE_TRUTH))
    with tempfile.TemporaryDirectory(prefix="vulnix-extra-selection-") as tmp:
        certificate = _certificate(Path(tmp))
        rows = [measure(kind, mode, strategy, certificate)
                for kind, modes in cases
                for mode in modes for strategy in ("fixed", "always", "observed")]
    for strategy in ("fixed", "always", "observed"):
        subset = [row for row in rows if row["strategy"] == strategy]
        assert all(row["verdict"] == row["expected"] for row in subset), subset
        assert all(row["target_get"] == 1 and row["worker_launches"] == 1 for row in subset), subset
    assert all(row["planner_calls"] == 0 and row["local_model_calls"] == 0
               for row in rows if row["strategy"] != "always")
    assert all(row["planner_calls"] == 1 for row in rows if row["strategy"] == "always")
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(row["local_model_calls"] > 0 for row in rows if row["strategy"] == "always")
    print(json.dumps(summarize(rows), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
