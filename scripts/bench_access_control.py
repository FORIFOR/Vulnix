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
INTENT = {"summary": "IDOR cross-account access-control verification", "asset_ids": [1], "priority": 7}


def _measure(mode: str, planned: bool) -> dict:
    lab = AccessControlLab(mode)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN")
    command = [real_bin] if real_bin else FAKE
    try:
        with tempfile.TemporaryDirectory() as tmp, MockLLM(intents=[INTENT]) as model:
            env = {"AEGIS_ENV": "production" if real_bin else "development",
                   "VULNIX_ARTEX_REAL_CMD": shlex.join(command),
                   "VULNIX_ARTEX_EXPECTED_SHA256": os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", ""),
                   "VULNIX_ARTEX_LLM_URL": model.url,
                   "VULNIX_ARTEX_LLM_MODE": "gateway-forward",
                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions"}
            with patch.dict(os.environ, env):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                        verify_seconds=0.1)
                if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                    svc._l2_confinement = KernelConfinement()
                counts = {"gateway_calls": 0, "worker_launches": 0, "state_saves": 0,
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
                        l1 = analyze_l1_service_response(result, ev, svc.a.target_url)
                        root_detected = any(f["id"] == "f_l1_unauth_api" and f["verdict"] == "detected"
                                            for f in l1)
                        adopted = False
                        verdict = "candidate"
                        plan_engine = None
                        gateway_meta = {}
                        if planned:
                            original = assessment_module.run_artex_planner
                            def inject(cmd, request, **kwargs):
                                return original(cmd, {**request, "fake_intents": [INTENT]}, **kwargs)
                            with patch.object(assessment_module, "run_artex_planner",
                                              original if real_bin else inject):
                                snap = svc.plan_with_artex("planner")
                            plan = snap["artex_plan"]["plan"]
                            plan_engine = plan["engine"]["kind"]
                            gateway_meta = plan.get("llm_gateway") or {}
                            selected = [i for i in plan["items"] if i["catalog_id"] == "l2_idor"]
                            adopted = len(selected) == 1
                            if adopted:
                                svc.execute_artex_item(selected[0]["id"], "reviewer",
                                                       roles=("operator", "approver"))
                                verdict = svc.a.findings["f_idor"]["verdict"]
                        counts.update(gateway_calls=gw.call_count, worker_launches=workers.call_count,
                                      state_saves=saves.call_count, ledger_commits=commits.call_count)
                        return {"mode": mode, "truth": TRUTH[mode], "elapsed_s": round(time.monotonic()-start, 3),
                                "target_requests": list(lab.seen), "root_exposure_detected": root_detected,
                                "idor_verdict": verdict, "idor_proven": verdict == "proven",
                                "plan_adopted": adopted, "engine_kind": plan_engine,
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
    before = [_measure(mode, False) for mode in TRUTH]
    after = [_measure(mode, True) for mode in TRUTH]
    out = {"fixed_l1": before, "artex_plan": after,
           "fixed_root_exposure_quality": _quality(before, "unauth_exposure", "root_exposure_detected"),
           "artex_root_exposure_quality": _quality(after, "unauth_exposure", "root_exposure_detected"),
           "fixed_idor_quality": _quality(before, "cross_account_access", "idor_proven"),
           "artex_idor_quality": _quality(after, "cross_account_access", "idor_proven"),
           "plan_adoption": sum(r["plan_adopted"] for r in after) / len(after)}
    assert out["fixed_root_exposure_quality"]["fp"] == 0
    assert out["artex_root_exposure_quality"]["fp"] == 0
    assert out["artex_idor_quality"]["tp"] == 2
    assert out["artex_idor_quality"]["fp"] == 0
    assert all(len(r["target_requests"]) == 1 for r in before)
    assert all(len(r["target_requests"]) == 2 for r in after)
    assert out["plan_adoption"] == 1.0
    if os.environ.get("VULNIX_ARTEX_REAL_BIN"):
        assert all(r["engine_kind"] == "artex-binary" for r in after)
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
