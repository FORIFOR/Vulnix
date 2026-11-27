"""Structured and hybrid planner engines for the diagnosis loop (no ARTEX process).

`structured`: the planner model answers with plan-contract steps whose every field is
constrained by a JSON Schema built only from Vulnix's own ids - testable hypotheses, the
allowed catalog, registered target refs, current evidence ids and the contract reasons. The
model is reached through the same Planner LLM Gateway as ARTEX (loopback, audit, budget,
secret and host checks). Its reply is data: each step still goes through aegis.plan_contract
and the Gateway exactly like an ARTEX intent, and the fixed judge decides every hypothesis.

`hybrid`: the fixed rule (aegis.diagnosis_judge.fixed_rule_steps) proposes first. The model is
asked only when the fixed rule has no step left that is not a repeat, and a model failure
(timeout, refused or malformed reply, no useful step) ends the plan with the fixed rule's
result intact.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from .artex_bridge import CATALOG, ArtexRun
from .diagnosis_judge import fixed_rule_steps
from .diagnosis_state import TESTABLE

MAX_STEPS = 3
TIMEOUT_S = 120.0
CHECK_PURPOSE = {
    "l1_http_probe": "one unauthenticated GET of the target (read only): shows whether it answers without login",
    "l1_apache_mod_status": "one GET of a fixed Apache server-status marker (read only)",
    "l2_idor": "test account A requests the target while its owner B is the positive control: "
               "shows whether another account's resource is readable",
    "l2_sqli": "non-destructive SQL injection boundary reproduction in the lab",
    "l2_cve_2021_41773": "non-destructive CVE-2021-41773 reproduction in the lab",
    "l2_open_redirect": "redirect target check on the return-to parameter (Location only, never followed)",
}
SYSTEM_PROMPT = (
    "You choose the next verification checks for an authorized assessment of a registered lab "
    "target. You only choose checks by id; you never run anything and you never decide whether a "
    "hypothesis is true: a fixed judge does that from the measured result. Choose a check only when "
    "its result can change the state of an open or inconclusive hypothesis; do not repeat a check "
    "listed under already_tried unless new evidence appeared after it. Return no steps when no "
    "check would help."
)


def _testable(view: dict) -> list[dict]:
    return [h for h in view["hypotheses"] if h["state"] in TESTABLE and h["generation"] == view["generation"]]


def plan_schema(view: dict, catalog_ids: list[str], reasons: list[str]) -> dict | None:
    """The answer's JSON Schema: every id is an enum of what Vulnix holds now."""
    hyps = _testable(view)
    evidence = sorted({o["evidence_id"] for o in view["observations"] if o["generation"] == view["generation"]})
    targets = sorted({h["target_ref"] for h in hyps})
    if not hyps or not evidence or not catalog_ids:
        return None
    step = {"type": "object", "additionalProperties": False,
            "required": ["hypothesis_id", "catalog_id", "target_ref", "evidence_refs", "reason"],
            "properties": {
                "hypothesis_id": {"enum": [h["id"] for h in hyps]},
                "catalog_id": {"enum": list(catalog_ids)},
                "target_ref": {"enum": targets},
                "evidence_refs": {"type": "array", "minItems": 1, "maxItems": 8, "items": {"enum": evidence}},
                "reason": {"enum": list(reasons)}}}
    return {"type": "object", "additionalProperties": False, "required": ["steps"],
            "properties": {"steps": {"type": "array", "minItems": 0, "maxItems": MAX_STEPS, "items": step}}}


def _is_repeat(step: dict, state, executed) -> bool:
    from .plan_contract import _repeats
    return _repeats(state, step["catalog_id"], step["target_ref"], step["evidence_refs"], executed)


def _intents(steps: list[dict], targets: list[dict]) -> list[dict]:
    asset = {t["target_id"]: t["asset_id"] for t in targets}
    return [{"id": i + 1, "summary": json.dumps(s, sort_keys=True, ensure_ascii=False),
             "asset_ids": [asset[s["target_ref"]]] if s["target_ref"] in asset else [], "priority": 5}
            for i, s in enumerate(steps)]


def _ask_model(view: dict, schema: dict, tried: list[dict], *, llm_url: str, llm_key: str,
               llm_model: str, no_think: bool, timeout_s: float) -> tuple[list[dict] | None, dict]:
    catalog = schema["properties"]["steps"]["items"]["properties"]["catalog_id"]["enum"]
    from .planner_llm_gateway import SECRET_KEY_NAMES
    # an attribute named like a credential ("auth": "other_account") would be refused by the
    # gateway's secret check; the values are Vulnix enums, so only the key is renamed
    observations = [{**o, "attrs": {(f"{k}_kind" if SECRET_KEY_NAMES.match(k) else k): v
                                    for k, v in o["attrs"].items()}}
                    for o in view["observations"] if o["generation"] == view["generation"]]
    user = {"hypotheses": _testable(view), "observations": observations,
            "checks": {c: CHECK_PURPOSE.get(c, c) for c in catalog}, "already_tried": tried}
    body = {"model": llm_model, "temperature": 0,
            "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                         {"role": "user", "content": json.dumps(user, ensure_ascii=False, sort_keys=True)}],
            "response_format": {"type": "json_schema", "json_schema": {"name": "plan", "strict": True, "schema": schema}}}
    if no_think:
        body["reasoning_effort"] = "none"
    req = urllib.request.Request(llm_url.rstrip("/") + "/chat/completions", method="POST",
                                 data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
                                 headers={"Content-Type": "application/json", "Authorization": f"Bearer {llm_key}"})
    meta: dict = {"model_calls": 1}
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as r:   # the loopback gateway only
            data = json.loads(r.read(1_000_001))
        choice = data["choices"][0]
        meta["usage"] = data.get("usage") if isinstance(data.get("usage"), dict) else None
        if choice.get("finish_reason") != "stop":
            meta["error"] = f"finish_{choice.get('finish_reason')}"
            return None, meta
        steps = json.loads(choice["message"]["content"])["steps"]     # strict JSON: no scraping
        if not isinstance(steps, list):
            raise ValueError("steps")
        meta["format_ok"] = True
        return steps, meta
    except urllib.error.HTTPError as e:
        meta["error"] = f"http_{e.code}"
    except Exception as e:  # noqa: BLE001 - any failure leaves the plan to the fixed rule / no step
        meta["error"] = type(e).__name__
        meta["format_ok"] = False if isinstance(e, (ValueError, KeyError, TypeError)) else None
    return None, meta


def run_structured_planner(view: dict, state, targets: list[dict], executed, *, llm_url: str, llm_key: str,
                           llm_model: str, hybrid: bool, allowed_levels=("L1", "L2"),
                           no_think: bool = False, timeout_s: float = TIMEOUT_S) -> ArtexRun:
    from .plan_contract import REASONS
    start = time.monotonic()
    catalog_ids = sorted(c.id for c in CATALOG if c.level in allowed_levels)
    reasons = sorted(r for r in REASONS
                     if r != "confirm_fix" or any(h["purpose"] == "confirm_fix" for h in _testable(view)))
    meta: dict = {"model_calls": 0}
    source = "none"
    steps: list[dict] = []
    if hybrid:
        steps = [s for s in fixed_rule_steps(view) if not _is_repeat(s, state, executed)]
        source = "fixed_rule" if steps else "none"
    if not steps:
        # a target that lists its checks takes no other (the contract's check_not_for_target)
        by_ref = {t["target_id"]: t for t in targets}
        refs = {h["target_ref"] for h in _testable(view)}
        if refs and all(by_ref.get(r, {}).get("checks") is not None for r in refs):
            allowed = set().union(*(set(by_ref[r]["checks"]) for r in refs))
            catalog_ids = [c for c in catalog_ids if c in allowed]
        schema = plan_schema(view, catalog_ids, reasons)
        if schema is not None:
            tried = [{"catalog_id": e[0], "target_ref": e[1]} for e in executed]
            answer, meta = _ask_model(view, schema, tried, llm_url=llm_url, llm_key=llm_key, llm_model=llm_model,
                                      no_think=no_think, timeout_s=timeout_s)
            if answer:
                # a repeated or shape-broken step is dropped here; the contract re-checks everything
                steps = [s for s in answer if isinstance(s, dict)
                         and {"catalog_id", "target_ref", "evidence_refs"} <= set(s)
                         and isinstance(s["evidence_refs"], list)
                         and not _is_repeat(s, state, executed)][:MAX_STEPS]
                source = "model" if steps else "none"
    kind = "vulnix-hybrid" if hybrid else "vulnix-structured"
    return ArtexRun(intents=_intents(steps, targets), goal_met=False, allowed_tools=[], tool_calls=[],
                    denied_tool_calls=[], elapsed_ms=round((time.monotonic() - start) * 1000, 1),
                    provenance={"kind": kind, "pinned": False, "step_source": source, "model": llm_model, **meta})
