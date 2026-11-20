"""Same seven independent loopback targets: fixed L1 versus ARTEX-planned IDOR.

The model is local and scripted; a real ARTEX binary is used when CI supplies it.
No result here establishes model selection quality or real-site L2 authority.
"""
from __future__ import annotations

import json
import os
import shlex
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from aegis import assessment as assessment_module  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.confinement import KernelConfinement  # noqa: E402
from aegis.service_diag import analyze_l1_service_response  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.fixtures.access_control_lab import AccessControlLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

TRUTH = json.loads((Path(__file__).resolve().parents[1] / "tests/fixtures/access_control_truth.json").read_text())
OWNER_SPECS = json.loads((Path(__file__).resolve().parents[1] /
                          "tests/fixtures/access_control_owner_specs.json").read_text())
INTENT = {"summary": "IDOR cross-account access-control verification", "asset_ids": [1], "priority": 7}


def _adaptive_intents(messages: list[dict]) -> list[dict]:
    # This test-only model reads measured structure, not the truth table, mode
    # name or response body. One public account directory is deliberately a
    # false selection, so this is not a perfect oracle.
    prompt = json.dumps(messages, ensure_ascii=False)
    import re
    return [INTENT] if re.search(r"Measured account resource link: present", prompt) else []


def _measure(mode: str, strategy: str, *, omit_account_fact: bool = False) -> dict:
    lab = AccessControlLab(mode)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN")
    command = [real_bin] if real_bin else FAKE
    owner = OWNER_SPECS[mode]
    requirement = owner["root_requirement"]
    root_access = {"requirement": (requirement if requirement != "unspecified" else "public"),
                   "spec_status": "placeholder" if requirement == "unspecified" else "confirmed",
                   "spec_evidence": [] if requirement == "unspecified" else ["owner API contract v1"]}
    try:
        with tempfile.TemporaryDirectory() as tmp, MockLLM(
                intents=[INTENT],
                intent_selector=_adaptive_intents if strategy in ("adaptive", "adaptive_one_pass") else None,
                prefer_initial_facts=strategy == "adaptive_one_pass") as model:
            env = {"AEGIS_ENV": "production" if real_bin else "development",
                   "VULNIX_ARTEX_REAL_CMD": shlex.join(command),
                   "VULNIX_ARTEX_EXPECTED_SHA256": (os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
                                                     if real_bin else ""),
                   "VULNIX_ARTEX_LLM_URL": model.url,
                   "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}
            with patch.dict(os.environ, env):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                        verify_seconds=0.1)
                if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                    svc._l2_confinement = KernelConfinement()
                counts = {"gateway_calls": 0, "worker_launches": 0, "planner_calls": 0, "state_saves": 0,
                          "ledger_commits": 0}
                try:
                    with patch.object(svc.gateway, "execute", wraps=svc.gateway.execute) as gw, \
                         patch.object(svc.workers, "run", wraps=svc.workers.run) as workers, \
                         patch.object(svc, "_save_state_locked", wraps=svc._save_state_locked) as saves, \
                         patch.object(svc.ledger, "commit", wraps=svc.ledger.commit) as commits:
                        start = time.monotonic()
                        result, ev = svc._exec("http_probe", "read_only_probe",
                                               {"url": svc.a.target_url, "method": "GET"},
                                               approval_actor="policy:auto-L1")
                        if result is None:
                            raise RuntimeError("fixed root probe was refused")
                        svc._analyze(result, ev)
                        l1 = analyze_l1_service_response(result, ev, svc.a.target_url,
                                                         root_access=root_access)
                        root_detected = any(f["id"] == "f_l1_unauth_api" and f["verdict"] == "detected"
                                            for f in l1)
                        if omit_account_fact:
                            # Test an incomplete initial graph without changing
                            # the independent HTTP response or owner contract.
                            svc._lab_account_resource_observed = None
                        adopted = False
                        verdict = "candidate"
                        plan_engine = None
                        gateway_meta = {}
                        if strategy != "fixed_l1":
                            original = assessment_module.run_artex_planner
                            planner_calls = [0]
                            def counted_planner(cmd, request, **kwargs):
                                planner_calls[0] += 1
                                if real_bin:
                                    return original(cmd, request, **kwargs)
                                chosen = ([INTENT] if strategy == "always"
                                          or svc._lab_account_resource_observed else [])
                                return original(cmd, {**request, "fake_intents": chosen}, **kwargs)
                            with patch.object(assessment_module, "run_artex_planner",
                                              side_effect=counted_planner):
                                snap = svc.plan_with_artex("planner")
                            counts["planner_calls"] = planner_calls[0]
                            plan = snap["artex_plan"]["plan"]
                            plan_engine = plan["engine"]["kind"]
                            gateway_meta = plan.get("llm_gateway") or {}
                            selected = [i for i in plan["items"] if i["catalog_id"] == "l2_idor"]
                            adopted = len(selected) == 1
                            if adopted:
                                svc.execute_artex_item(selected[0]["id"], "reviewer",
                                                       roles=("operator", "approver"))
                                verdict = svc.a.findings["f_idor"]["verdict"]
                            if real_bin:
                                model_payload = json.dumps(model.requests, ensure_ascii=False)
                                assert mode not in model_payload
                                assert '"truth"' not in model_payload
                                assert "VULNIX_LAB_IDOR_PROVEN" not in model_payload
                        counts.update(gateway_calls=gw.call_count, worker_launches=workers.call_count,
                                      state_saves=saves.call_count, ledger_commits=commits.call_count)
                        model_signals = []
                        for call in model.requests:
                            messages = call["body"].get("messages") or []
                            prompt = json.dumps(messages, ensure_ascii=False)
                            model_signals.append({"roles": [m.get("role") for m in messages if isinstance(m, dict)],
                                                  "prior_tool_names": [
                                                      tc.get("function", {}).get("name")
                                                      for m in messages if isinstance(m, dict)
                                                      and m.get("role") == "assistant"
                                                      for tc in m.get("tool_calls") or [] if isinstance(tc, dict)],
                                                  "has_surface_title": "Measured account resource link" in prompt,
                                                  "has_present": "present" in prompt,
                                                  "has_absent": "absent" in prompt,
                                                  "selector_chose_idor": bool(_adaptive_intents(messages))})
                        return {"mode": mode, "truth": TRUTH[mode], "strategy": strategy,
                                "elapsed_s": round(time.monotonic()-start, 3),
                                "target_requests": list(lab.seen), "root_exposure_detected": root_detected,
                                "idor_verdict": verdict, "idor_proven": verdict == "proven",
                                "plan_adopted": adopted, "engine_kind": plan_engine,
                                "observed_account_link": svc._lab_account_resource_observed,
                                "model_signals": model_signals,
                                "local_model_calls": len(model.requests),
                                "ai_est_tokens": gateway_meta.get("est_tokens"),
                                "hypothetical_model_cost_usd": gateway_meta.get("est_cost_usd"),
                                "paid_model_cost_usd": 0, **counts}
                finally:
                    svc.close()
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=2)


def _quality(rows: list[dict], truth_key: str, observed_key: str) -> dict:
    tp = sum(r["truth"][truth_key] and r[observed_key] for r in rows)
    fp = sum(not r["truth"][truth_key] and r[observed_key] for r in rows)
    fn = sum(r["truth"][truth_key] and not r[observed_key] for r in rows)
    tn = sum(not r["truth"][truth_key] and not r[observed_key] for r in rows)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "false_positive_rate": fp / (fp + tn) if fp + tn else None}


def main() -> None:
    assert set(TRUTH) == set(OWNER_SPECS)
    before = [_measure(mode, "fixed_l1") for mode in TRUTH]
    after = [_measure(mode, "always") for mode in TRUTH]
    adaptive = [_measure(mode, "adaptive") for mode in TRUTH]
    out = {"fixed_l1": before, "artex_plan": after, "adaptive_plan": adaptive,
           "fixed_root_exposure_quality": _quality(before, "unauth_exposure", "root_exposure_detected"),
           "artex_root_exposure_quality": _quality(after, "unauth_exposure", "root_exposure_detected"),
           "fixed_idor_quality": _quality(before, "cross_account_access", "idor_proven"),
           "artex_idor_quality": _quality(after, "cross_account_access", "idor_proven"),
           "adaptive_idor_quality": _quality(adaptive, "cross_account_access", "idor_proven"),
           "always_selection_quality": _quality(after, "idor_check_appropriate", "plan_adopted"),
           "adaptive_selection_quality": _quality(adaptive, "idor_check_appropriate", "plan_adopted"),
           "plan_adoption": sum(r["plan_adopted"] for r in after) / len(after)}
    print(json.dumps(out, ensure_ascii=False, indent=2))
    assert out["fixed_root_exposure_quality"]["fp"] == 0
    assert out["artex_root_exposure_quality"]["fp"] == 0
    assert out["fixed_root_exposure_quality"]["fn"] == 0
    assert out["artex_idor_quality"]["tp"] == 2
    assert out["artex_idor_quality"]["fp"] == 0
    assert out["adaptive_idor_quality"]["tp"] == 2
    assert out["adaptive_idor_quality"]["fp"] == 0
    assert out["adaptive_selection_quality"]["fp"] < out["always_selection_quality"]["fp"]
    assert out["adaptive_selection_quality"]["fn"] == 0
    assert all(len(r["target_requests"]) == 1 for r in before)
    assert sum(len(r["target_requests"]) for r in adaptive) < sum(len(r["target_requests"]) for r in after)
    assert out["plan_adoption"] == 1.0
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(r["engine_kind"] == "artex-binary" for r in after + adaptive)


if __name__ == "__main__":
    main()
