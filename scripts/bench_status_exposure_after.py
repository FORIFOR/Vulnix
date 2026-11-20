"""Compare the fixed baseline with the ARTEX-planned status check in one lab.

With VULNIX_ARTEX_REAL_BIN, this uses the real overlay and a loopback mock model.
Without it, the Python stand-in verifies the local Gateway/Worker path only.
No public target or paid model is contacted.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"
os.environ["VULNIX_EXTERNAL_PROPOSALS"] = "0"
os.environ["VULNIX_REAL_SITE_SAFE_AI"] = "0"

from aegis.assessment import AssessmentService  # noqa: E402
from aegis import assessment as assessment_module  # noqa: E402
from aegis.confinement import KernelConfinement  # noqa: E402
from scripts.bench_status_exposure_baseline import (measure as baseline_measure,
                                                    measure_safety)  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.fixtures.status_exposure_lab import StatusExposureLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

HOST = "owned-status.example.test"
STATUS_INTENT = {"summary": "Check Apache mod_status exposure", "asset_ids": [1], "priority": 5}


def measure_after(mode: str) -> dict:
    original_runner = assessment_module.run_artex_planner
    site = StatusExposureLab(mode)
    thread = threading.Thread(target=site.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN")
    command = [real_bin] if real_bin else FAKE
    try:
        with tempfile.TemporaryDirectory() as tmp, MockLLM(intents=[STATUS_INTENT]) as model:
            url = f"http://{HOST}:{site.server_port}"
            config = {"AEGIS_ENV": "production" if real_bin else "development",
                      "VULNIX_REAL_SITE_INITIAL_ARTEX": "1",
                      "VULNIX_REAL_SITE_LOCAL_ARTEX": "1",
                      "VULNIX_ARTEX_REAL_CMD": " ".join(command),
                      "VULNIX_ARTEX_EXPECTED_SHA256": os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", ""),
                      "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                      "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}
            with patch.dict(os.environ, config):
                svc = AssessmentService(Path(tmp), 18081, l2_confinement=TEST_CONFINEMENT,
                                        real_site_read_only=True)
                try:
                    if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                        svc._l2_confinement = KernelConfinement()
                    svc._custom_resolver = lambda name: ["127.0.0.1"] if name == HOST else []
                    svc._real_site_local_artex = True
                    svc._artex_real_cmd = command
                    challenge = svc.issue_ownership_challenge(url=url)["challenge"]
                    svc.verify_asset_ownership(url_or_host=url, method="dns_txt",
                        dns_lookup=lambda name: [f'{name} text = "{challenge["dns_txt_value"]}"'])
                    svc.confirm_asset_scope(url_or_host=url, activate_workspace=True,
                                            allow_loopback_test=True, allow_status_probe=True)
                    assert site.seen == []
                    counts = {"gateway_calls": 0, "worker_launches": 0, "state_saves": 0,
                              "ledger_commits": 0, "artex_calls": 0}
                    for obj, attr, key in ((svc.gateway, "execute", "gateway_calls"),
                                           (svc.workers, "run", "worker_launches"),
                                           (svc, "_save_state_locked", "state_saves"),
                                           (svc.ledger, "commit", "ledger_commits"),
                                           (assessment_module, "run_artex_planner", "artex_calls")):
                        original = getattr(obj, attr)
                        def count(*args, _original=original, _key=key, **kwargs):
                            counts[_key] += 1
                            return _original(*args, **kwargs)
                        setattr(obj, attr, count)
                    if not real_bin:
                        original = assessment_module.run_artex_planner
                        def inject(command, request, **kwargs):
                            return original(command, {**request, "fake_intents": [STATUS_INTENT]}, **kwargs)
                        assessment_module.run_artex_planner = inject
                    started = time.monotonic()
                    svc.start()
                    deadline = started + 120
                    while svc.snapshot()["state"] == "running" and time.monotonic() < deadline:
                        time.sleep(0.02)
                    snap = svc.snapshot()
                    if snap["state"] != "completed":
                        raise RuntimeError(snap.get("failure"))
                    expected_paths = ["/", "/server-status?auto"]
                    assert site.seen == expected_paths, site.seen
                    found = [f for f in snap["findings"] if f["id"] == "f_l1_apache_mod_status"]
                    assert len(found) == 1
                    detected = found[0]["evidence_status"] == "detected"
                    assert detected == (mode == "vulnerable")
                    assert found[0]["evidence"][0]["audit_hash"]
                    plan = snap["artex_plan"]["plan"]
                    gateway = plan.get("llm_gateway") or {}
                    return {"mode": mode, "truth_status_exposed": mode == "vulnerable",
                            "elapsed_s": round(time.monotonic() - started, 3),
                            **counts, "engine_kind": plan["engine"]["kind"],
                            "local_model_calls": len(model.requests),
                            "ai_est_tokens": gateway.get("est_tokens"),
                            "hypothetical_model_cost_usd": gateway.get("est_cost_usd"),
                            "paid_model_cost_usd": 0,
                            "target_requests": list(site.seen),
                            "status_exposure_detected": detected,
                            "status_verdict": found[0]["evidence_status"]}
                finally:
                    svc.close()
    finally:
        assessment_module.run_artex_planner = original_runner
        site.shutdown()
        site.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    modes = ("vulnerable", "patched", "generic_200")
    before = [baseline_measure(mode) for mode in modes]
    after = [measure_after(mode) for mode in modes]
    def quality(rows):
        tp = sum(r["truth_status_exposed"] and r["status_exposure_detected"] for r in rows)
        fp = sum(not r["truth_status_exposed"] and r["status_exposure_detected"] for r in rows)
        fn = sum(r["truth_status_exposed"] and not r["status_exposure_detected"] for r in rows)
        tn = sum(not r["truth_status_exposed"] and not r["status_exposure_detected"] for r in rows)
        return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "false_positive_rate": fp / (fp + tn) if fp + tn else None}
    safety_before = measure_safety()
    safety_after = measure_safety(allow_status_probe=True)
    print(json.dumps({"before": before, "after": after,
                      "quality_before": quality(before), "quality_after": quality(after),
                      "safety_before": safety_before, "safety_after": safety_after,
                      "safety_success_rate_before": sum(v["refused"] and v["worker_launches"] == 0
                                                        and not v["target_requests"] for v in safety_before.values())
                                                    / len(safety_before),
                      "safety_success_rate_after": sum(v["refused"] and v["worker_launches"] == 0
                                                       and not v["target_requests"] for v in safety_after.values())
                                                   / len(safety_after)},
                     ensure_ascii=False, indent=2))
