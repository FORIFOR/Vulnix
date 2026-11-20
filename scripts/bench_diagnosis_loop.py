"""Diagnosis loop on the independent access-control lab: three methods, same conditions.

    fixed_l1      the fixed L1 root GET only (hypotheses are opened, nothing is tested)
    fixed_rule    fixed table: the first testable hypothesis -> its catalog check
    artex_planner ARTEX + model choose the next check by id (aegis.plan_contract)

All three get the same initial observation, the same owner specification, the same
check catalog (aegis.artex_bridge.CATALOG), the same PlanLimits and the same Gateway
budget. The fixed judge (aegis.diagnosis_judge) decides every hypothesis for every
method. When a method ends with a supported hypothesis, the lab is switched to its
fixed behaviour (denied_403) and the same method re-checks it (confirm_fix).

The model is a LOCAL scripted stand-in (tests/diagnosis_planner.py) that reads only the
facts Vulnix sent. Without VULNIX_ARTEX_REAL_BIN the ARTEX process is the Python
stand-in as well. Nothing here measures the quality of a real model, and nothing here
sends anything outside 127.0.0.1.

Usage: VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_diagnosis_loop [--out FILE] [--modes a,b]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

os.environ["VULNIX_NO_ENV_LOCAL"] = "1"

from aegis import assessment as assessment_module  # noqa: E402
from aegis.adaptive_plan_runner import AdaptivePlanRunner  # noqa: E402
from aegis.adaptive_plan_state import PlanLimits  # noqa: E402
from aegis.assessment import AssessmentService  # noqa: E402
from aegis.confinement import KernelConfinement  # noqa: E402
from aegis.diagnosis_judge import fixed_rule_steps  # noqa: E402
from aegis.diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec  # noqa: E402
from aegis.diagnosis_state import DiagnosisState  # noqa: E402
from tests import TEST_CONFINEMENT  # noqa: E402
from tests.artex_mock_llm import MockLLM  # noqa: E402
from tests.diagnosis_planner import intents_from_facts, view_from_text  # noqa: E402
from tests.fixtures.access_control_lab import LOOP_MODES, MODES, AccessControlLab  # noqa: E402
from tests.test_artex_bridge import FAKE  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TRUTH = json.loads((ROOT / "tests/fixtures/access_control_loop_truth.json").read_text())["modes"]
OWNER_SPECS = {**json.loads((ROOT / "tests/fixtures/access_control_owner_specs.json").read_text()),
               **json.loads((ROOT / "tests/fixtures/access_control_loop_owner_specs.json").read_text())}
METHODS = ("fixed_l1", "fixed_rule", "artex_planner")
LIMITS = PlanLimits(max_steps=3, max_planner_rounds=5, max_seconds=300, max_planner_cost_usd=0.10)
APPROVER = ("approver-human", ("operator", "approver"))
FIXED_MODE = "denied_403"
_FACT_TEXT = re.compile(r"Vulnix (?:observation|hypothesis|plan contract)[^\n]{0,200}")


def _fixed_rule_intents(request: dict) -> list[dict]:
    text = "\n".join(o.get("title", "") for o in request.get("observations") or [])
    return [{"summary": json.dumps(s, sort_keys=True), "asset_ids": [1], "priority": 5}
            for s in fixed_rule_steps(view_from_text(text))]


def _outcome(state: DiagnosisState, claim: str) -> str:
    hs = [h for h in state.hypotheses() if h["claim"] == claim and h["purpose"] == "diagnose"]
    if not hs:
        return "not_applicable"
    return "untested" if hs[-1]["state"] == "open" else hs[-1]["state"]


def run_case(mode: str, method: str) -> dict:
    lab = AccessControlLab(mode)
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN") if method == "artex_planner" else None
    command = [real_bin] if real_bin else FAKE
    spec = OWNER_SPECS[mode]["account_resource_requirement"]
    try:
        with tempfile.TemporaryDirectory() as tmp, \
                MockLLM(intent_selector=lambda msgs: intents_from_facts(json.dumps(msgs, ensure_ascii=False))) as model:
            env = {"AEGIS_ENV": "production" if real_bin else "development",
                   "VULNIX_ARTEX_REAL_CMD": shlex.join(command),
                   "VULNIX_ARTEX_EXPECTED_SHA256": (os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
                                                     if real_bin else ""),
                   "VULNIX_ARTEX_LLM_URL": model.url,
                   "VULNIX_ARTEX_LLM_MODE": "gateway-forward" if real_bin else "direct",
                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": model.url + "/chat/completions",
                   "VULNIX_ARTEX_PG_DSN": os.environ.get("VULNIX_ARTEX_PG_DSN", "") if real_bin else ""}
            with patch.dict(os.environ, env):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=TEST_CONFINEMENT,
                                        verify_seconds=0.1)
                if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                    svc._l2_confinement = KernelConfinement()
                original = assessment_module.run_artex_planner
                requests: list[dict] = []

                def planner(cmd, request, **kw):
                    requests.append(request)
                    if real_bin:
                        return original(cmd, request, **kw)
                    intents = (_fixed_rule_intents(request) if method == "fixed_rule" else
                               intents_from_facts("\n".join(o.get("title", "")
                                                            for o in request.get("observations") or [])))
                    return original(cmd, {**request, "fake_intents": intents}, **kw)

                state = DiagnosisState()
                start = time.monotonic()
                with patch.object(assessment_module, "run_artex_planner", side_effect=planner), \
                        patch.object(svc.workers, "run", wraps=svc.workers.run) as workers:
                    observe_lab_root(svc, state)
                    targets = {t["target_id"] for t in svc.diagnosis_targets()}
                    if "T2" in targets:
                        record_owner_spec(state, "T2", spec)
                    plans, fix = [], None
                    if method != "fixed_l1":
                        runner = AdaptivePlanRunner(svc, actor="requester", approve=lambda item: APPROVER,
                                                    limits=LIMITS, diagnosis=state)
                        plans.append(runner.run())
                    else:
                        from aegis.diagnosis_judge import propose_hypotheses
                        propose_hypotheses(state)
                    outcome = _outcome(state, "other_account_read")
                    diag_gets = len(lab.seen)
                    if method != "fixed_l1" and outcome == "supported":
                        lab.mode = FIXED_MODE
                        made = begin_fix_check(svc, state, {"T2": spec})
                        fixer = AdaptivePlanRunner(svc, actor="requester", approve=lambda item: APPROVER,
                                                   limits=LIMITS, diagnosis=state)
                        plans.append(fixer.run())
                        fix = {"hypotheses": made,
                               "result": [state.hypothesis(h)["state"] for h in made],
                               "confirmed_fixed": bool(made) and all(state.hypothesis(h)["state"] == "contradicted"
                                                                     for h in made),
                               "f_idor_verdict": (svc.a.findings.get("f_idor") or {}).get("verdict")}
                    elapsed = time.monotonic() - start
                    launches = workers.call_count
                audit_ok = svc.audit.verify()
                results = {e["hash"] for e in svc.audit.entries() if e["event"] == "result"}
                judged = [e["fields"] for e in svc.audit.entries() if e["event"] == "diagnosis.judged"]
                payload = json.dumps(requests, ensure_ascii=False) + json.dumps(model.requests, ensure_ascii=False)
                view = (svc.artex_plan_view() or {}).get("plan") or {}
                return {
                    "mode": mode, "method": method, "truth": TRUTH[mode],
                    "other_account_read": outcome,
                    "unauthenticated_exposure": _outcome(state, "unauthenticated_exposure"),
                    "steps": [{k: s.get(k) for k in ("step_id", "catalog_id", "target_ref", "reason",
                                                     "evidence_refs", "judgement")}
                              for p in plans for s in p.executed],
                    "plans": [{"state": p.state.value, "reason": p.reason, "planner_rounds": p.planner_rounds,
                               "rejected_steps": p.rejected_steps, "planner_cost_usd": p.planner_cost_usd}
                              for p in plans],
                    "contradicted": sum(1 for h in state.hypotheses() if h["state"] == "contradicted"
                                        and h["purpose"] == "diagnose"),
                    "target_gets": diag_gets, "target_gets_with_fix_check": len(lab.seen),
                    "worker_launches": launches, "planner_calls": len(requests),
                    "elapsed_s": round(elapsed, 3),
                    "planner_cost_usd": round(sum(p.planner_cost_usd for p in plans), 6),
                    "fix_check": fix,
                    "audit_chain_valid": audit_ok,
                    "every_judgement_cites_an_audited_result": all(j["result_audit_hash"] in results
                                                                   for j in judged),
                    "planner_saw_lab_label_or_secret": any(x in payload for x in (
                        f'"{mode}"', "VULNIX_LAB_IDOR_PROVEN", '"truth"', "lab-only note")),
                    "engine_kind": (view.get("engine") or {}).get("kind"),
                    # what the model was shown (Vulnix facts only: ids and short words),
                    # so a run with the real overlay can be checked from its evidence
                    "model_saw_facts": sorted({m.group(0)[:160] for m in _FACT_TEXT.finditer(
                        json.dumps(model.requests, ensure_ascii=False))})[:12],
                    "plan_failures": [p.reason for p in plans if p.state.value == "FAILED"],
                }
    finally:
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=2)


def score(rows: list[dict]) -> dict:
    s = {"cases": len(rows), "correct": 0, "false_positive": 0, "missed": 0, "undecided": 0,
         "wrong_contradiction": 0, "needs_spec_correct": 0, "contradictions": 0,
         "target_gets": 0, "worker_launches": 0, "planner_calls": 0, "elapsed_s": 0.0,
         "planner_cost_usd": 0.0, "fix_checks": 0, "fix_confirmed": 0}
    for r in rows:
        want, got = r["truth"]["other_account_read"], r["other_account_read"]
        if got == want:
            s["correct"] += 1
            s["needs_spec_correct"] += got == "needs_spec"
        elif got == "supported":
            s["false_positive"] += 1
        elif want == "supported":
            s["missed"] += 1
        elif got == "contradicted":
            s["wrong_contradiction"] += 1
        else:
            s["undecided"] += 1          # untested, inconclusive, needs_spec when the spec exists
        s["contradictions"] += r["contradicted"]
        for k in ("target_gets", "worker_launches", "planner_calls"):
            s[k] += r[k]
        s["elapsed_s"] = round(s["elapsed_s"] + r["elapsed_s"], 3)
        s["planner_cost_usd"] = round(s["planner_cost_usd"] + r["planner_cost_usd"], 6)
        if r["fix_check"]:
            s["fix_checks"] += 1
            s["fix_confirmed"] += r["fix_check"]["confirmed_fixed"]
    return s


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--modes", default="")
    args = ap.parse_args(argv)
    modes = [m for m in args.modes.split(",") if m] or sorted(MODES | LOOP_MODES)
    assert set(TRUTH) == MODES | LOOP_MODES
    rows = {m: [run_case(mode, m) for mode in modes] for m in METHODS}
    out = {"about": __doc__.strip().splitlines()[0],
           "model": "local scripted stand-in (tests/diagnosis_planner.py); not a real model",
           "artex": "real overlay binary" if os.environ.get("VULNIX_ARTEX_REAL_BIN") else "Python stand-in",
           "limits": LIMITS.__dict__, "modes": modes,
           "summary": {m: score(rows[m]) for m in METHODS}, "cases": rows}
    text = json.dumps(out, ensure_ascii=False, indent=2, default=str)
    if args.out:
        Path(args.out).write_text(text + "\n")
    print(text)
    bad = []
    for m in ("fixed_rule", "artex_planner"):
        s = out["summary"][m]
        if s["false_positive"]:
            bad.append(f"{m}: false positive")
        if s["fix_checks"] != s["fix_confirmed"]:
            bad.append(f"{m}: a fix was not confirmed")
    for m, rs in rows.items():
        for r in rs:
            if not (r["audit_chain_valid"] and r["every_judgement_cites_an_audited_result"]):
                bad.append(f"{m}/{r['mode']}: audit")
            if r["planner_saw_lab_label_or_secret"]:
                bad.append(f"{m}/{r['mode']}: planner input leaked a lab label or secret")
            if os.environ.get("VULNIX_ARTEX_REAL_BIN") and m == "artex_planner" and r["planner_calls"]:
                if r["engine_kind"] != "artex-binary":
                    bad.append(f"{m}/{r['mode']}: not the real ARTEX binary")
    if "idor_spec_missing" in modes:
        for m in ("fixed_rule", "artex_planner"):
            r = next(r for r in rows[m] if r["mode"] == "idor_spec_missing")
            if r["other_account_read"] != "needs_spec":
                bad.append(f"{m}: missing spec was not reported as needs_spec")
    for b in bad:
        print("CHECK FAILED:", b, file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
