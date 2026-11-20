"""Vulnix's fixed judge and proposer for the diagnosis loop (docs/DIAGNOSIS_LOOP_PLAN.md).

Only this module decides what a check result means for a hypothesis. It reads
Vulnix's own parsed Worker output and the owner's written specification - never
a planner's or a model's words. A `Verdict` can only be made here; the diagnosis
state refuses anything else (DiagnosisState.apply).

Rules (fixed, ordered; the first that matches decides):

A check was run and the owner's spec says the resource is public -> contradicted (intended_public)

other_account_read  x  l2_idor
    the owner control did not establish the resource       -> inconclusive (control_failed)
    reproduction proven (aegis.evidence.reproduction_verdict)
        owner spec: authentication_required                -> supported   (cross_account_read)
        owner spec: public                                 -> contradicted (intended_public)
        owner spec missing / unspecified                   -> needs_spec  (spec_missing)
    acct_A gets 401/403/404 while the owner gets 200       -> contradicted (denied)
    acct_A gets 200 with its own resource (no marker)      -> contradicted (own_resource_only)
    anything else                                          -> inconclusive (unrecognised_answer)

unauthenticated_exposure  x  l1_http_probe (one GET without any account)
    401/403/404                                            -> contradicted (denied_without_auth)
    200                                                    -> inconclusive (answered_without_auth_unverified)
        (a status alone does not show that the protected resource itself was served)
    anything else                                          -> inconclusive (unrecognised_answer)

A check that does not test the claim                       -> inconclusive (check_not_relevant)
"""
from __future__ import annotations

import weakref
from dataclasses import dataclass

from .diagnosis_state import DiagnosisState
from .evidence import reproduction_verdict

_ISSUER = object()          # only this module holds it
# The verdict objects this module made. A copy (dataclasses.replace, copy.copy) carries the
# token but is a different object, so it is not in here and is refused.
_ISSUED: "weakref.WeakSet[Verdict]" = weakref.WeakSet()
DENIED = (401, 403, 404)
REQUIREMENTS = frozenset({"authentication_required", "public", "unspecified"})


@dataclass(frozen=True, eq=False)
class Verdict:
    hypothesis_id: str
    to: str
    evidence: tuple[str, ...]
    rule: str
    _issuer: object = None

    def issued_by_judge(self) -> bool:
        return self._issuer is _ISSUER and self in _ISSUED


def _verdict(hid: str, to: str, evidence, rule: str) -> Verdict:
    v = Verdict(hid, to, tuple(evidence), rule, _ISSUER)
    _ISSUED.add(v)
    return v


# ---- fixed parsers: Worker output -> short observation attributes -------------------
def check_attrs(catalog_id: str, result: dict) -> dict:
    """The facts a check result adds, in words and small integers only."""
    if not isinstance(result, dict):
        return {"answer": "unreadable"}
    status = result.get("status") if isinstance(result.get("status"), int) else None
    if catalog_id == "l1_http_probe":
        return {"status": status, "auth": "none"}
    if catalog_id == "l2_idor":
        response = result.get("response")
        own = (isinstance(response, dict) and response.get("caller_account") == "acct_A"
               and response.get("resource_owner") == "acct_A")
        return {"status": status, "auth": "other_account",
                "control": "established" if result.get("control_verified") is True else "missing",
                "reproduction": reproduction_verdict(result, "idor"),
                "own_resource": bool(own)}
    return {"status": status}


def _requirement(state: DiagnosisState, target_ref: str, generation: int) -> tuple[str, list[str]]:
    specs = [o for o in state.observations(target_ref=target_ref, generation=generation)
             if o["source"] == "owner_spec" and o["kind"] == "owner_spec"]
    if not specs:
        return "unspecified", []
    req = specs[-1]["attrs"].get("requirement")
    return (req if req in REQUIREMENTS else "unspecified"), [specs[-1]["evidence_id"]]


def judge(state: DiagnosisState, hypothesis_id: str, catalog_id: str, evidence_id: str) -> Verdict:
    """Decide what the check observation `evidence_id` means for the hypothesis."""
    h = state.hypothesis(hypothesis_id)
    obs = state.observation(evidence_id)
    if obs["source"] != "check" or obs["target_ref"] != h["target_ref"]:
        raise ValueError("the judge reads a check result on the hypothesis's own target")
    a = obs["attrs"]
    status = a.get("status")
    requirement, spec_ev = _requirement(state, h["target_ref"], h["generation"])
    ev = [evidence_id]

    def by_spec(rule_ok: str) -> Verdict:
        if requirement == "authentication_required":
            return _verdict(hypothesis_id, "supported", ev + spec_ev, rule_ok)
        if requirement == "public":
            return _verdict(hypothesis_id, "contradicted", ev + spec_ev, "intended_public")
        return _verdict(hypothesis_id, "needs_spec", ev + spec_ev, "spec_missing")

    relevant = (h["claim"], catalog_id) in (("other_account_read", "l2_idor"),
                                            ("unauthenticated_exposure", "l1_http_probe"))
    if relevant and requirement == "public":
        return _verdict(hypothesis_id, "contradicted", ev + spec_ev, "intended_public")
    if h["claim"] == "other_account_read" and catalog_id == "l2_idor":
        if a.get("control") != "established":
            return _verdict(hypothesis_id, "inconclusive", ev, "control_failed")
        if a.get("reproduction") == "proven":
            return by_spec("cross_account_read")
        if status in DENIED:
            return _verdict(hypothesis_id, "contradicted", ev, "denied")
        if status == 200 and a.get("own_resource") is True:
            return _verdict(hypothesis_id, "contradicted", ev, "own_resource_only")
        return _verdict(hypothesis_id, "inconclusive", ev, "unrecognised_answer")
    if h["claim"] == "unauthenticated_exposure" and catalog_id == "l1_http_probe":
        if status in DENIED:
            return _verdict(hypothesis_id, "contradicted", ev, "denied_without_auth")
        if status == 200:
            return _verdict(hypothesis_id, "inconclusive", ev, "answered_without_auth_unverified")
        return _verdict(hypothesis_id, "inconclusive", ev, "unrecognised_answer")
    return _verdict(hypothesis_id, "inconclusive", ev, "check_not_relevant")


# ---- fixed proposer: observations -> hypotheses -------------------------------------
def propose_hypotheses(state: DiagnosisState) -> list[str]:
    """Open the hypotheses the current observations call for (fixed rules, idempotent).

    An account resource the target itself links to (measured by the fixed L1) may be
    readable without authentication, or by another account."""
    made = []
    # A claim already diagnosed in an earlier generation is not reopened here: after
    # a fix only a supported one is re-checked, through begin_fix_check/confirm_fix.
    existing = {(h["claim"], h["target_ref"]) for h in state.hypotheses()}
    for o in state.observations(generation=state.generation):
        if o["source"] != "l1" or o["kind"] != "account_resource_link" or o["attrs"].get("present") is not True:
            continue
        for claim in ("unauthenticated_exposure", "other_account_read"):
            if (claim, o["target_ref"]) not in existing:
                made.append(state.propose(claim=claim, target_ref=o["target_ref"], basis=[o["evidence_id"]]))
                existing.add((claim, o["target_ref"]))
    return made


# The fixed-rule planner used for the comparison (same catalog, same budget as ARTEX).
FIXED_CHECK_FOR_CLAIM = {"unauthenticated_exposure": "l1_http_probe", "other_account_read": "l2_idor"}


def fixed_rule_steps(view: dict) -> list[dict]:
    """One step per testable hypothesis, in hypothesis order, from a fixed table.
    The runner executes the first one the contract accepts."""
    steps = []
    for h in view["hypotheses"]:
        if h["state"] not in ("open", "inconclusive") or h["generation"] != view["generation"]:
            continue
        refs = [o["evidence_id"] for o in view["observations"]
                if o["target_ref"] == h["target_ref"] and o["generation"] == view["generation"]]
        steps.append({"hypothesis_id": h["id"], "catalog_id": FIXED_CHECK_FOR_CLAIM[h["claim"]],
                      "target_ref": h["target_ref"], "evidence_refs": refs,
                      "reason": "confirm_fix" if h["purpose"] == "confirm_fix" else "test_hypothesis"})
    return steps


__all__ = ["DENIED", "FIXED_CHECK_FOR_CLAIM", "Verdict", "check_attrs", "fixed_rule_steps", "judge",
           "propose_hypotheses"]
