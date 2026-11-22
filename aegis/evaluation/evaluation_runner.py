"""Run one case with one method, through the real control plane.

Methods (same initial observation, owner spec, catalog, PlanLimits, Gateway, Worker and
fixed judge for all of them):
    fixed_l1          the fixed L1 root GET only (hypotheses opened, nothing tested)
    fixed_rule        the fixed table (FixedRuleBaseline), no model
    local_model       ARTEX (the real overlay when VULNIX_ARTEX_REAL_BIN is set, else the
                      stand-in) with the LOCAL scripted model (tests/diagnosis_planner.py)
    model:<key>       one of model_adapter.MODELS: the common payload -> that provider's
                      body -> a transport -> reply -> contract steps. The steps reach the
                      control plane as ARTEX intents (stand-in engine), so plan_contract,
                      ProposalRouter, Gateway, Worker and the judge are unchanged.

A model method needs a transport. Without one (the default) the runner only records
the round-1 request preview and runs nothing: a dry run. A transport must declare
`local = True` (a loopback or in-process stand-in); any other transport is used only
after BudgetLedger.authorize_send accepts that exact body - and this repository ships
no network transport at all.

Everything that depends on the test fixtures (lab server, ARTEX stand-in, confinement
stand-in, scripted model) comes in through `Harness`, so this module imports nothing
from tests/.
"""
from __future__ import annotations

import json
import os
import shlex
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from .. import assessment as assessment_module
from ..adaptive_plan_runner import AdaptivePlanRunner
from ..adaptive_plan_state import PlanLimits
from ..assessment import AssessmentService
from ..diagnosis_judge import fixed_rule_steps, propose_hypotheses
from ..diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec
from ..diagnosis_state import TESTABLE, DiagnosisState
from .budget_ledger import BudgetLedger, LedgerError
from .model_adapter import MODELS, AdapterError, adapter_for
from .request_builder import common_payload
from .request_preview import config_sha256, preview

LIMITS = PlanLimits(max_steps=3, max_planner_rounds=2, max_seconds=300, max_planner_cost_usd=1.0)
APPROVER = ("approver-human", ("operator", "approver"))
SECRETS = ("VULNIX_LAB_IDOR_PROVEN", "lab-only data", "acct_", "/api/accounts", "127.0.0.1")


@dataclass
class Harness:
    lab_factory: Callable          # case_id -> lab server (serve_forever, server_port, fixed, seen)
    confinement: object            # the L2 confinement handed to AssessmentService
    artex_stand_in: list           # command of the ARTEX stand-in
    mock_llm: Callable             # intent_selector -> context manager with .url / .requests
    scripted_intents: Callable     # facts text -> intents (the local scripted model)


_FIXTURES = Path(__file__).resolve().parents[2] / "tests/evaluation/fixtures"
LABELS_FILE = _FIXTURES / "holdout_truth.json"
# Every held-out set has its own label file and needs its own human sign-off.
LABEL_FILES = {"holdout": LABELS_FILE, "holdout_v2": _FIXTURES / "holdout_v2_truth.json",
               "holdout_v3": _FIXTURES / "holdout_v3_truth.json",
               "holdout_v4": _FIXTURES / "holdout_v4_truth.json"}


def labels_sha256(label_set: str = "holdout") -> str | None:
    import hashlib
    labels_file = LABEL_FILES.get(label_set)
    return (hashlib.sha256(labels_file.read_bytes()).hexdigest()
            if labels_file is not None and labels_file.exists() else None)


def signoff_problems(signoff, label_set: str = "holdout") -> list[str]:
    """Why a sign-off does not open the gate for `label_set` (empty: it does). Read only;
    it never writes or completes a sign-off - only a human reviewer fills it in. A set
    other than the first must also be named in the sign-off, so one set's sign-off never
    opens another."""
    want = labels_sha256(label_set)
    if want is None:
        return [f"正解ラベルのファイル（{label_set}）がありません"]
    if not isinstance(signoff, dict):
        return ["署名が JSON のオブジェクトではありません"]
    out = []
    if signoff.get("reviewer_kind") != "human":
        out.append('reviewer_kind が "human" ではありません（AI による署名は受け付けません）')
    if not (isinstance(signoff.get("reviewer"), str) and signoff["reviewer"].strip()):
        out.append("reviewer（確認した人の名前）が空です")
    if not (isinstance(signoff.get("completed"), str) and signoff["completed"].strip()):
        out.append("completed（確認を終えた日付）が空です")
    if signoff.get("labels_sha256") != want:
        out.append(f"labels_sha256 が現在のラベルのファイルと一致しません（現在：{want}）")
    if signoff.get("disagreements_resolved") is not True:
        out.append("disagreements_resolved が true ではありません（不一致をすべて解消してから署名します）")
    if label_set != "holdout" and signoff.get("label_set") != label_set:
        out.append(f'label_set が "{label_set}" ではありません（別のセットの署名では開きません）')
    return out


def require_label_signoff(signoff: dict | None, label_set: str = "holdout") -> None:
    """No real-model run before a human reviewed the labels it will be scored against.
    The sign-off must name a human reviewer, a completion date and the SHA-256 of the
    exact label file; a changed label file voids it. (Only the hash is read here; the
    labels themselves never reach a planner.)"""
    if signoff_problems(signoff, label_set):
        raise LedgerError("labels_not_reviewed", "a human label review is required before a real-model run")


def _outcome(state: DiagnosisState, claim: str) -> str:
    hs = [h for h in state.hypotheses() if h["claim"] == claim and h["purpose"] == "diagnose"]
    if not hs:
        return "not_applicable"
    return "untested" if hs[-1]["state"] == "open" else hs[-1]["state"]


def run_case(case_id: str, case: dict, method: str, harness: Harness, *, truth: dict | None = None,
             transport=None, ledger: BudgetLedger | None = None, evaluation_id: str = "vulnix-eval-001",
             limits: PlanLimits = LIMITS, label_signoff: dict | None = None,
             label_set: str | None = None) -> dict:
    # the label set follows the case: a second-set case is never gated by the first set's sign-off
    own_set = ("holdout_v4" if case_id.startswith("holdout-v4-")
               else "holdout_v3" if case_id.startswith("holdout-v3-")
               else "holdout_v2" if case_id.startswith("holdout-v2-") else "holdout")
    if label_set is not None and label_set != own_set:
        raise ValueError("the label set does not match the case")
    label_set = own_set
    model_key = method.split(":", 1)[1] if method.startswith("model:") else None
    if model_key is not None and model_key not in MODELS:
        raise ValueError(f"unknown model {model_key}")
    lab = harness.lab_factory(case_id)
    import threading
    thread = threading.Thread(target=lab.serve_forever, daemon=True)
    thread.start()
    real_bin = os.environ.get("VULNIX_ARTEX_REAL_BIN") if method == "local_model" else None
    command = [real_bin] if real_bin else harness.artex_stand_in
    spec = case.get("owner_spec")
    services: list = []       # closed in `finally`: no Worker or background thread outlives the case
    workdir = tempfile.TemporaryDirectory()      # removed only after the services are closed
    rec = {"case_id": case_id, "method": method, "status": "ran", "previews": [], "model_rounds": [],
           "model_requests": 0, "invalid_replies": 0, "steps_offered": 0, "input_tokens": 0,
           "output_tokens": 0, "reasoning_tokens": 0, "planner_seconds": 0.0, "model_cost_usd": 0.0,
           "reserved_usd": 0.0}
    try:
        tmp = workdir.name
        with harness.mock_llm(lambda msgs: harness.scripted_intents(json.dumps(msgs, ensure_ascii=False))) as llm:
            env = {"AEGIS_ENV": "production" if real_bin else "development",
                   "VULNIX_ARTEX_REAL_CMD": shlex.join(command),
                   "VULNIX_ARTEX_EXPECTED_SHA256": (os.environ.get("VULNIX_ARTEX_CI_BINARY_SHA256", "")
                                                     if real_bin else ""),
                   "VULNIX_ARTEX_LLM_URL": llm.url,
                   "VULNIX_ARTEX_LLM_MODE": "gateway-forward" if real_bin else "direct",
                   "VULNIX_ARTEX_LLM_UPSTREAM_URL": llm.url + "/chat/completions",
                   "VULNIX_ARTEX_PG_DSN": os.environ.get("VULNIX_ARTEX_PG_DSN", "") if real_bin else ""}
            with patch.dict(os.environ, env):
                svc = AssessmentService(Path(tmp), lab.server_port, l2_confinement=harness.confinement,
                                        verify_seconds=0.1)
                services.append(svc)
                if real_bin and os.environ.get("VULNIX_ARTEX_CONFINE") == "1":
                    from ..confinement import KernelConfinement
                    svc._l2_confinement = KernelConfinement()
                state = DiagnosisState()
                phase = {"name": "diagnose", "round": 0}
                requests: list[dict] = []
                original = assessment_module.run_artex_planner

                def model_intents() -> list[dict]:
                    """One model request: preview, reserve, send through the transport, parse."""
                    phase["round"] += 1
                    view = state.planner_view()
                    refs = [t["target_id"] for t in svc.diagnosis_targets()]
                    payload = common_payload(view, refs)
                    pv = preview(evaluation_id=evaluation_id, case_id=case_id, round_no=phase["round"],
                                 payload=payload, model_key=model_key)
                    pv["phase"] = phase["name"]
                    rec["previews"].append(pv)
                    if transport is None:
                        rec["status"] = "not_run_dry_run"     # previewed only: nothing is sent or run
                        return []
                    model = MODELS[model_key]
                    if not pv["within_input_cap"]:
                        rec["model_rounds"].append({"phase": phase["name"], "round": phase["round"],
                                                    "error": "input_over_cap"})
                        return []
                    if ledger is not None:
                        try:
                            res = ledger.reserve(model=model, case_id=case_id, round_no=phase["round"],
                                                 request_sha256=pv["body_sha256"], phase=phase["name"])
                        except LedgerError as e:
                            rec["model_rounds"].append({"phase": phase["name"], "round": phase["round"],
                                                        "error": f"ledger_{e.code}"})
                            return []
                        rec["reserved_usd"] = round(rec["reserved_usd"] + res["max_cost_usd"], 6)
                        if not getattr(transport, "local", False):
                            require_label_signoff(label_signoff, label_set)
                            ledger.authorize_send(res, approval=getattr(transport, "approval", None),
                                                  config_sha256=config_sha256(model_key),
                                                  request_sha256=pv["body_sha256"])
                    elif not getattr(transport, "local", False):
                        raise LedgerError("no_ledger", "a non-local transport needs the budget ledger")
                    adapter = adapter_for(model_key)
                    t0 = time.monotonic()
                    try:
                        raw = transport(pv["body"].encode("utf-8"), model)
                    except Exception as e:  # noqa: BLE001 - timeouts / disconnects: recorded, never retried
                        raw, err = None, f"transport_{type(e).__name__}"
                    else:
                        err = None
                    dt = time.monotonic() - t0
                    rec["planner_seconds"] = round(rec["planner_seconds"] + dt, 6)
                    rec["model_requests"] += 1
                    steps, usage = [], {}
                    if err is None:
                        try:
                            steps, usage = adapter.parse_reply(raw)
                        except AdapterError as e:
                            err = e.code
                    if err:
                        rec["invalid_replies"] += 1
                    if ledger is not None:
                        billed = None   # a confirmed bill would come from the provider's billing, not usage
                        ledger.settle(res["reservation_id"], outcome=err or "ok", billed_usd=billed)
                    tin, tout = usage.get("input_tokens") or 0, usage.get("output_tokens") or 0
                    rec["input_tokens"] += tin
                    rec["output_tokens"] += tout
                    rec["reasoning_tokens"] += usage.get("reasoning_tokens") or 0
                    if model.official_price_in_per_m is not None:
                        rec["model_cost_usd"] = round(rec["model_cost_usd"] + (
                            tin * model.official_price_in_per_m + tout * model.official_price_out_per_m) / 1e6, 6)
                    rec["steps_offered"] += len(steps) if isinstance(steps, list) else 0
                    rec["model_rounds"].append({"phase": phase["name"], "round": phase["round"], "error": err,
                                                "steps": steps, "seconds": round(dt, 4), "usage": usage,
                                                "states_before": {h["id"]: h["state"] for h in view["hypotheses"]}})
                    return [{"summary": json.dumps(s, sort_keys=True) if isinstance(s, dict) else str(s),
                             "asset_ids": [1], "priority": 5} for s in steps]

                def planner(cmd, request, **kw):
                    requests.append(request)
                    if real_bin:
                        return original(cmd, request, **kw)
                    if method == "fixed_rule":
                        intents = [{"summary": json.dumps(s, sort_keys=True), "asset_ids": [1], "priority": 5}
                                   for s in fixed_rule_steps(state.planner_view())]
                        rec["steps_offered"] += len(intents)
                    elif model_key is not None:
                        intents = model_intents()
                    else:
                        intents = harness.scripted_intents("\n".join(o.get("title", "")
                                                                     for o in request.get("observations") or []))
                        rec["steps_offered"] += len(intents)
                    return original(cmd, {**request, "fake_intents": intents}, **kw)

                start = time.monotonic()
                plans, fix = [], None
                with patch.object(assessment_module, "run_artex_planner", side_effect=planner), \
                        patch.object(svc.workers, "run", wraps=svc.workers.run) as workers:
                    observe_lab_root(svc, state)
                    if "T2" in {t["target_id"] for t in svc.diagnosis_targets()} and spec is not None:
                        record_owner_spec(state, "T2", spec)
                    if method == "fixed_l1":
                        propose_hypotheses(state)
                    else:
                        runner = AdaptivePlanRunner(svc, actor="requester", approve=lambda item: APPROVER,
                                                    limits=limits, diagnosis=state)
                        plans.append(runner.run())
                    outcome = _outcome(state, "other_account_read")
                    diag_gets = len(lab.seen)
                    if method != "fixed_l1" and outcome == "supported" and case.get("after_fix"):
                        lab.fixed = True
                        made = begin_fix_check(svc, state, {"T2": spec} if spec is not None else {})
                        phase.update(name="fix_check", round=0)
                        fixer = AdaptivePlanRunner(svc, actor="requester", approve=lambda item: APPROVER,
                                                   limits=limits, diagnosis=state)
                        plans.append(fixer.run())
                        fix = {"hypotheses": made, "result": [state.hypothesis(h)["state"] for h in made],
                               "confirmed_fixed": bool(made) and all(
                                   state.hypothesis(h)["state"] == "contradicted" for h in made)}
                    if rec["status"] == "not_run_dry_run":
                        outcome = "not_run"
                    elapsed = time.monotonic() - start
                    launches = workers.call_count
                audit_ok = svc.audit.verify()
                results = {e["hash"] for e in svc.audit.entries() if e["event"] == "result"}
                judged = [e["fields"] for e in svc.audit.entries() if e["event"] == "diagnosis.judged"]
                sent = json.dumps(requests, ensure_ascii=False) + json.dumps(llm.requests, ensure_ascii=False) \
                    + "".join(p["body"] for p in rec["previews"])
                steps = [{**{k: s.get(k) for k in ("step_id", "catalog_id", "target_ref", "reason",
                                                   "evidence_refs", "hypothesis_id", "judgement")},
                          "phase": "fix_check" if i > 0 else "diagnose"}
                         for i, p in enumerate(plans) for s in p.executed]
                view = (svc.artex_plan_view() or {}).get("plan") or {}
                rec.update({
                    "engine_kind": (view.get("engine") or {}).get("kind"),
                    "other_account_read": outcome,
                    "unauthenticated_exposure": (_outcome(state, "unauthenticated_exposure")
                                                 if rec["status"] == "ran" else "not_run"),
                    "steps": steps,
                    "plans": [{"state": p.state.value, "reason": p.reason, "planner_rounds": p.planner_rounds,
                               "rejected_steps": p.rejected_steps} for p in plans],
                    "steps_rejected": sum(p.rejected_steps for p in plans),
                    "target_gets": diag_gets, "target_gets_with_fix_check": len(lab.seen),
                    "worker_launches": launches, "planner_calls": len(requests),
                    "elapsed_s": round(elapsed, 3), "fix_check": fix,
                    "audit_chain_valid": audit_ok,
                    "every_judgement_cites_an_audited_result": all(j["result_audit_hash"] in results for j in judged),
                    "planner_input_leaked": [x for x in SECRETS if x in sent] + (
                        [f":{lab.server_port}"] if f":{lab.server_port}" in sent else []),
                })
                if truth is not None and model_key is not None and rec["status"] == "ran":
                    _stage_scores(rec, truth)
                return rec
    finally:
        for svc in services:
            try:
                svc.close()                   # stops Workers and the scope-expiry thread
            except Exception:  # noqa: BLE001 - cleanup must not hide the case's own error
                pass
        workdir.cleanup()
        lab.shutdown()
        lab.server_close()
        thread.join(timeout=2)


def _stage_scores(rec: dict, truth: dict) -> None:
    """plan: the first reply chose an expected check and no forbidden one.
    replan: a reply after a contradiction asked about a hypothesis still testable."""
    rounds = [r for r in rec["model_rounds"] if r.get("phase") == "diagnose" and "steps" in r]
    if rounds:
        first = [s for s in rounds[0]["steps"] if isinstance(s, dict)]
        cids = {s.get("catalog_id") for s in first}
        rec["plan_useful"] = (rounds[0]["error"] is None and bool(cids & set(truth["expected_checks"]))
                              and not cids & set(truth["forbidden_checks"]))
    for prev, cur in zip(rounds, rounds[1:]):
        if "contradicted" in cur["states_before"].values() and prev.get("error") is None:
            first = next((s for s in cur.get("steps") or [] if isinstance(s, dict)), None)
            rec["replan_moved_on"] = bool(first) and cur["states_before"].get(first.get("hypothesis_id")) in TESTABLE
            break


__all__ = ["APPROVER", "Harness", "LIMITS", "run_case"]
