"""The plan contract (docs/DIAGNOSIS_LOOP_PLAN.md, stage 3).

A planner (ARTEX or a model) answers with steps that name everything by id:

    {"hypothesis_id": "H1", "catalog_id": "l2_idor", "target_ref": "T1",
     "evidence_refs": ["E1"], "reason": "test_hypothesis"}

Nothing is inferred from free text. A step is accepted only when every field has
the exact type and every id is one Vulnix already holds:

- `hypothesis_id`: a hypothesis that is still testable (open / inconclusive) and
  belongs to the current generation;
- `catalog_id`: a catalog check allowed at this level;
- `target_ref`: a registered target, and the hypothesis's own target;
- `evidence_refs`: 1..8 distinct observed evidence ids, every one about the SAME
  target and from the SAME (current) generation;
- `reason`: one of REASONS, and `confirm_fix` exactly for a confirm-fix hypothesis.

Accepting a step grants nothing: it still goes through the ProposalRouter, the
Gateway (scope, approval, budget) and an isolated Worker, which build the actual
request from the catalog and the registered target.
"""
from __future__ import annotations

import json
import re

from .artex_bridge import CATALOG_BY_ID
from .diagnosis_state import TESTABLE, DiagnosisState

KEYS = frozenset({"hypothesis_id", "catalog_id", "target_ref", "evidence_refs", "reason"})
REASONS = frozenset({
    "test_hypothesis",          # the check can support or contradict the hypothesis
    "collect_missing_evidence", # the hypothesis lacks an observation this check provides
    "confirm_fix",              # re-measure after the owner changed something
})
MAX_EVIDENCE_REFS = 8
MAX_STEPS = 20
_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


def _reject(rejected: list, index: int, reason: str) -> None:
    rejected.append({"index": index, "reason": reason})


def _is_id(v) -> bool:
    return type(v) is str and _ID.fullmatch(v) is not None


def step_from_summary(summary) -> object:
    """An ARTEX intent carries one step as a JSON object in its summary. Anything
    that is not exactly one JSON object is returned as None (not a contract step)."""
    if not isinstance(summary, str) or len(summary) > 2000:
        return None
    text = summary.strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    def _no_constant(_c):
        raise ValueError("NaN / Infinity is not JSON")
    try:
        return json.loads(text, parse_constant=_no_constant)
    except ValueError:
        return None


def _repeats(state: DiagnosisState, cid: str, tref: str, refs, executed) -> bool:
    """The same check on the same target again needs evidence measured AFTER its last
    run (the watermark: observations recorded by then), and not produced by that check
    itself. Re-citing older evidence in another combination is still a repeat."""
    for entry in executed:
        c, t, prev = entry[:3]
        watermark = entry[3] if len(entry) > 3 else 0
        if (c, t) != (cid, tref):
            continue
        fresh = [r for r in set(refs) - set(prev)
                 if state.seq(r) >= watermark
                 and not (state.observation(r)["source"] == "check" and state.observation(r)["catalog_id"] == cid)]
        if not fresh:
            return True
    return False


def parse_steps(raw, state: DiagnosisState, *, targets, allowed_levels,
                executed=frozenset(), target_checks=None) -> tuple[list[dict], list[dict]]:
    """(accepted steps, rejected [{index, reason}]). Never raises on a bad reply.

    `target_checks`: {target_ref: checks that act on it}; a target listed there takes
    no other check (check_not_for_target).

    `executed`: {(catalog_id, target_ref, frozenset(evidence_refs)[, watermark])} already
    run. A step repeats one of them unless it cites evidence recorded after that run
    (seq >= watermark) that the same check did not produce itself."""
    accepted: list[dict] = []
    rejected: list[dict] = []
    if not isinstance(raw, list):
        _reject(rejected, -1, "not_a_list")
        return accepted, rejected
    if len(raw) > MAX_STEPS:
        _reject(rejected, -1, "too_many_steps")
        return accepted, rejected
    view = state.planner_view()
    gen = view["generation"]
    hypotheses = {h["id"]: h for h in view["hypotheses"]}
    observed = {o["evidence_id"]: o for o in view["observations"]}
    seen: set = set()
    for i, step in enumerate(raw):
        if not isinstance(step, dict):
            _reject(rejected, i, "not_an_object")
            continue
        if set(step) != KEYS:
            _reject(rejected, i, "unexpected_keys" if set(step) - KEYS else "missing_keys")
            continue
        hid, cid, tref, refs, why = (step["hypothesis_id"], step["catalog_id"], step["target_ref"],
                                     step["evidence_refs"], step["reason"])
        if not (_is_id(hid) and _is_id(cid) and _is_id(tref) and type(why) is str
                and type(refs) is list and all(_is_id(r) for r in refs)):
            _reject(rejected, i, "bad_type")
            continue
        hyp = hypotheses.get(hid)
        entry = CATALOG_BY_ID.get(cid)
        if hyp is None:
            _reject(rejected, i, "unknown_hypothesis")
        elif hyp["state"] not in TESTABLE:
            _reject(rejected, i, "hypothesis_settled" if hyp["state"] in ("supported", "contradicted")
                    else "hypothesis_waits_for_owner")
        elif hyp["generation"] != gen:
            _reject(rejected, i, "stale_hypothesis")
        elif entry is None:
            _reject(rejected, i, "unknown_check")
        elif entry.level not in allowed_levels:
            _reject(rejected, i, "level_not_allowed")
        elif tref not in targets:
            _reject(rejected, i, "unknown_target")
        elif tref != hyp["target_ref"]:
            _reject(rejected, i, "target_mismatch")
        elif target_checks and tref in target_checks and cid not in target_checks[tref]:
            _reject(rejected, i, "check_not_for_target")
        elif not refs or len(refs) > MAX_EVIDENCE_REFS:
            _reject(rejected, i, "no_evidence" if not refs else "too_much_evidence")
        elif len(set(refs)) != len(refs):
            _reject(rejected, i, "duplicate_evidence")
        elif not set(refs) <= set(observed):
            _reject(rejected, i, "unknown_evidence")
        elif any(observed[r]["target_ref"] != tref for r in refs):
            _reject(rejected, i, "evidence_other_target")
        elif any(observed[r]["generation"] != gen for r in refs):
            _reject(rejected, i, "stale_evidence")
        elif why not in REASONS:
            _reject(rejected, i, "unknown_reason")
        elif (why == "confirm_fix") != (hyp["purpose"] == "confirm_fix"):
            _reject(rejected, i, "reason_mismatch")
        elif _repeats(state, entry.id, tref, refs, executed):
            _reject(rejected, i, "repeat")
        elif (entry.id, tref, hid) in seen:
            _reject(rejected, i, "duplicate_step")
        else:
            seen.add((entry.id, tref, hid))
            accepted.append({"hypothesis_id": hid, "catalog_id": cid, "target_ref": tref,
                             "evidence_refs": list(refs), "reason": why})
    return accepted, rejected


__all__ = ["KEYS", "MAX_EVIDENCE_REFS", "REASONS", "parse_steps", "step_from_summary"]
