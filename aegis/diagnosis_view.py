"""The read-only view of the diagnosis loop (docs/DIAGNOSIS_READ_API.md).

Built only from audited facts:
- the state is accepted only when it equals its replay from the verified audit log
  (aegis.diagnosis_state.DiagnosisState.replay); otherwise nothing is shown;
- a step is shown only when its `diagnosis.applied` record names a `diagnosis.judged`
  record that names a verified Worker `result` record, and the observation it cites
  is that result;
- every text is a fixed id (claim, state, catalog id, contract reason, judge rule, plan
  end reason). Planner text (ARTEX intent summaries, advisories), model output, raw
  response bodies and token counts are never read here.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .diagnosis_state import _TOKEN, DiagnosisState, StateError, _safe_value

SCHEMA_VERSION = 1
TERMINAL = ("COMPLETED", "REJECTED", "CANCELLED", "EXPIRED", "FAILED")
TESTABLE = ("open", "inconclusive")
_EMPTY = {"generation": None, "plan": None, "hypotheses": [], "steps": [], "evidence": [], "fix_comparison": []}


class _Refuse(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _canon(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _iso(ts) -> str | None:
    if not isinstance(ts, (int, float)) or isinstance(ts, bool):
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _attrs(attrs: dict) -> dict:
    """Short words and small integers only (the planner view's rule)."""
    return {k: sv for k, v in (attrs or {}).items()
            if _TOKEN.fullmatch(str(k)) and (sv := _safe_value(v)) is not None}


def _reason_id(reason) -> str | None:
    """The fixed id of a plan end reason. Some carry an exception text after a colon
    ("planner_failed: ..."); only the id before it is shown."""
    head = str(reason or "").split(":", 1)[0].strip()
    return head if _TOKEN.fullmatch(head) else ("other" if head else None)


def refused(base: dict, reason: str) -> dict:
    return {**base, **_EMPTY, "status": "unverified", "reason": reason, "next": {"kind": "check_audit"}}


def build_view(*, assessment_id: str, export: dict | None, refusal: str | None, entries: list[dict],
               chain_valid: bool, restored: bool, persisted: bool, l2_items: list[dict],
               catalog_levels: dict[str, str]) -> dict:
    base = {"schema_version": SCHEMA_VERSION, "lab_only": True, "assessment_id": assessment_id,
            "restored": bool(restored), "persisted": bool(persisted)}
    if refusal:
        return refused(base, refusal)
    if not chain_valid:
        return refused(base, "audit_chain_invalid")
    if export is None:
        return {**base, **_EMPTY, "status": "not_started", "next": {"kind": "none"}}
    try:
        return {**base, **_build(export, entries, l2_items, catalog_levels)}
    except _Refuse as e:
        return refused(base, e.reason)


def _build(export: dict, entries: list[dict], l2_items: list[dict], levels: dict[str, str]) -> dict:
    diag_id = export["diag_id"]
    # The log is read after the state was copied: cut it at the state's own last journal
    # record, so a change journaled meanwhile is neither shown nor taken for a mismatch.
    tail = export.get("tail")
    if tail is None:
        cut = 0
    else:
        cut = next((i + 1 for i, e in enumerate(entries) if e["hash"] == tail), None)
        if cut is None:
            raise _Refuse("state_audit_mismatch")      # the state's last change is not in the log
    journal = entries[:cut]
    try:
        replayed = DiagnosisState.replay(diag_id, journal).export()
    except (StateError, KeyError, TypeError, ValueError):
        raise _Refuse("journal_unreadable") from None
    if _canon(replayed) != _canon(export):
        raise _Refuse("state_audit_mismatch")
    by_hash = {e["hash"]: e for e in entries}
    results = {h for h, e in by_hash.items() if e.get("event") == "result"}
    mine = [e for e in journal if (e.get("fields") or {}).get("diag_id") == diag_id]
    observed_at = {}
    for e in mine:
        if e["event"] == "diagnosis.observed":
            observed_at[e["fields"]["record"]["evidence_id"]] = e["hash"]
    obs = {o["evidence_id"]: o for o in export["observations"]}

    evidence = []
    for o in export["observations"]:
        if o["audit_hash"] is not None and o["audit_hash"] not in results:
            raise _Refuse("evidence_not_in_audit")      # an observation must point at a verified result
        evidence.append({"evidence_id": o["evidence_id"], "kind": o["kind"], "source": o["source"],
                         "target_ref": o["target_ref"], "generation": o["generation"], "attrs": _attrs(o["attrs"]),
                         "step_id": o["step_id"], "catalog_id": o["catalog_id"], "audit_hash": o["audit_hash"],
                         "recorded_by": o.get("recorded_by"), "journal_hash": observed_at.get(o["evidence_id"]),
                         "at": _iso(o["at"])})

    steps = []
    for e in mine:
        if e["event"] != "diagnosis.applied" or not e["fields"]["record"].get("judged_audit_hash"):
            continue
        applied = e["fields"]["record"]
        judged = by_hash.get(applied["judged_audit_hash"])
        jf = (judged or {}).get("fields") or {}
        if (judged is None or judged.get("event") != "diagnosis.judged" or jf.get("diag_id") != diag_id
                or (jf.get("hypothesis_id"), jf.get("to"), jf.get("rule"))
                != (applied["hypothesis_id"], applied["to"], applied["rule"])):
            raise _Refuse("judgement_not_in_audit")
        if jf.get("result_audit_hash") not in results:
            raise _Refuse("result_not_in_audit")
        o = obs.get(jf.get("observation"))
        if o is None or o["audit_hash"] != jf["result_audit_hash"] or o["catalog_id"] != jf.get("catalog_id"):
            raise _Refuse("observation_not_the_result")
        steps.append({"plan_id": jf.get("plan_id"), "step_id": jf.get("step_id"), "catalog_id": jf["catalog_id"],
                      "level": levels.get(jf["catalog_id"]), "hypothesis_id": jf["hypothesis_id"],
                      "target_ref": jf.get("target_ref"), "reason": jf.get("reason"),
                      "evidence_refs": list(jf.get("cited") or []), "approved_by": jf.get("approved_by"),
                      "generation": o["generation"],
                      "observation": {"evidence_id": o["evidence_id"], "attrs": _attrs(o["attrs"])},
                      "judgement": {"from": jf.get("frm"), "to": jf["to"], "rule": jf["rule"]},
                      "result_audit_hash": jf["result_audit_hash"], "judged_audit_hash": judged["hash"],
                      "at": _iso(judged.get("ts"))})

    plan = None
    transitions = [e for e in entries if e.get("event") == "adaptive_plan.transition"
                   and (e.get("fields") or {}).get("diag_id") == diag_id]
    if transitions:
        pid = transitions[-1]["fields"]["plan_id"]
        own = [e["fields"] for e in transitions if e["fields"]["plan_id"] == pid]
        state = own[-1]["to"]
        plan = {"plan_id": pid, "state": state, "reason": _reason_id(own[-1].get("reason")) if state in TERMINAL else None,
                "steps_used": sum(1 for f in own if f["to"] == "EVIDENCE_RECORDED"),
                "steps_max": own[-1].get("max_steps")}

    hyps = [{k: h[k] for k in ("id", "claim", "target_ref", "state", "purpose", "generation", "supersedes",
                               "basis", "supporting", "contradicting", "inconclusive")}
            for h in export["hypotheses"]]
    by_id = {h["id"]: h for h in hyps}

    def last_step(hid):
        return next((s for s in reversed(steps) if s["hypothesis_id"] == hid), None)

    fix = []
    for h in hyps:
        if h["purpose"] != "confirm_fix" or not h["supersedes"]:
            continue
        before, after = last_step(h["supersedes"]), last_step(h["id"])
        side = (lambda s: {"generation": s["generation"], "to": s["judgement"]["to"], "rule": s["judgement"]["rule"],
                           "judged_audit_hash": s["judged_audit_hash"]} if s else None)
        result = {"contradicted": "fixed", "supported": "not_fixed"}.get(h["state"], "pending")
        fix.append({"hypothesis_id": h["id"], "supersedes": h["supersedes"],
                    "catalog_id": (after or before or {}).get("catalog_id"),
                    "before": side(before), "after": side(after), "result": result})

    return {"status": "ok", "diag_id": diag_id, "generation": export["generation"], "plan": plan,
            "hypotheses": hyps, "steps": steps, "evidence": evidence, "fix_comparison": fix,
            "next": _next(hyps, steps, plan, l2_items, by_id)}


def _next(hyps, steps, plan, l2_items, by_id) -> dict:
    current = [h for h in hyps if h["generation"] == max((x["generation"] for x in hyps), default=0)]
    running = plan is not None and plan["state"] not in TERMINAL
    for it in (l2_items if running else ()):      # an ended plan waits for no approval
        h = by_id.get(it.get("hypothesis_id"))
        if h and h["state"] in TESTABLE:
            return {"kind": "approve_l2", "item_id": it["item_id"]}
    spec = next((h for h in current if h["state"] == "needs_spec"), None)
    if spec:
        return {"kind": "needs_spec", "hypothesis_id": spec["id"], "target_ref": spec["target_ref"]}
    if steps and steps[-1]["judgement"]["rule"] == "control_failed":
        return {"kind": "prepare_accounts"}
    if plan and plan["state"] in TERMINAL:
        confirmed = {h["supersedes"] for h in hyps if h["purpose"] == "confirm_fix"}
        if plan["reason"] == "all_settled" and any(
                h["state"] == "supported" and h["purpose"] == "diagnose" and h["id"] not in confirmed for h in hyps):
            return {"kind": "confirm_fix_available"}
        return {"kind": "plan_ended", "state": plan["state"], "reason": plan["reason"]}
    return {"kind": "none"}


__all__ = ["SCHEMA_VERSION", "build_view", "refused"]
