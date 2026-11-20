"""The plan contract (docs/DIAGNOSIS_LOOP_PLAN.md, stage 3).

A planner (ARTEX or a model) answers with steps that name everything by id:

    {"hypothesis_id": "H1", "catalog_id": "l2_idor", "target_ref": "T1",
     "evidence_refs": ["E1"], "reason": "test_hypothesis"}

Nothing is inferred from free text. A step is accepted only when every id is one
Vulnix already holds: an unresolved hypothesis, a catalog check allowed at this
level, a registered target that is the hypothesis's own, and observed evidence.
Accepting a step grants nothing: it still goes through the ProposalRouter, the
Gateway (scope, approval, budget) and an isolated Worker, which build the actual
request from the catalog and the registered target.
"""
from __future__ import annotations

from .artex_bridge import CATALOG_BY_ID
from .diagnosis_state import SETTLED, DiagnosisState

KEYS = frozenset({"hypothesis_id", "catalog_id", "target_ref", "evidence_refs", "reason"})
REASONS = frozenset({
    "test_hypothesis",          # the check can support or contradict the hypothesis
    "collect_missing_evidence", # the hypothesis lacks an observation this check provides
    "confirm_fix",              # re-measure after the owner changed something
})


def _reject(rejected: list, index: int, reason: str) -> None:
    rejected.append({"index": index, "reason": reason})


def parse_steps(raw, state: DiagnosisState, *, targets, allowed_levels,
                executed=frozenset()) -> tuple[list[dict], list[dict]]:
    """(accepted steps, rejected [{index, reason}]). Never raises on a bad reply."""
    accepted: list[dict] = []
    rejected: list[dict] = []
    if not isinstance(raw, list):
        _reject(rejected, -1, "not_a_list")
        return accepted, rejected
    hypotheses = {h["id"]: h for h in state.planner_view()["hypotheses"]}
    observed = {o["evidence_id"] for o in state.planner_view()["observations"]}
    for i, step in enumerate(raw):
        if not isinstance(step, dict):
            _reject(rejected, i, "not_an_object")
            continue
        if set(step) != KEYS:
            _reject(rejected, i, "unexpected_keys" if set(step) - KEYS else "missing_keys")
            continue
        hyp = hypotheses.get(step["hypothesis_id"]) if isinstance(step["hypothesis_id"], str) else None
        entry = CATALOG_BY_ID.get(step["catalog_id"]) if isinstance(step["catalog_id"], str) else None
        refs = step["evidence_refs"]
        if hyp is None:
            _reject(rejected, i, "unknown_hypothesis")
        elif hyp["state"] in SETTLED:
            _reject(rejected, i, "hypothesis_settled")
        elif entry is None:
            _reject(rejected, i, "unknown_check")
        elif entry.level not in allowed_levels:
            _reject(rejected, i, "level_not_allowed")
        elif step["target_ref"] not in targets:
            _reject(rejected, i, "unknown_target")
        elif step["target_ref"] != hyp["target_ref"]:
            _reject(rejected, i, "target_mismatch")
        elif not isinstance(refs, list) or not refs or not all(isinstance(r, str) for r in refs):
            _reject(rejected, i, "no_evidence")
        elif not set(refs) <= observed:
            _reject(rejected, i, "unknown_evidence")
        elif step["reason"] not in REASONS:
            _reject(rejected, i, "unknown_reason")
        elif (entry.id, step["target_ref"], frozenset(refs)) in executed:
            _reject(rejected, i, "repeat")
        else:
            accepted.append({k: (list(v) if isinstance(v, list) else v) for k, v in step.items()})
    return accepted, rejected


__all__ = ["KEYS", "REASONS", "parse_steps"]
