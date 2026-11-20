"""Observations and hypotheses, kept apart from findings (docs/DIAGNOSIS_LOOP_PLAN.md).

A hypothesis is "this may be a problem, and here is what we still need to know". It
is not a finding: only a hypothesis that Vulnix itself marked `supported`, citing
evidence it recorded, may be turned into one. The model never changes a state; it
can only be shown the planner view and suggest the next check.

The planner view carries ids, kinds and short enum-like values only. Raw values
(cookies, URLs, page text, anything that does not look like a short token) are
dropped, so nothing secret from a real service can be phrased into a model request.
"""
from __future__ import annotations

import re
import time

SOURCES = frozenset({"l1", "check", "owner_spec"})          # never "model"
STATES = frozenset({"open", "supported", "contradicted", "inconclusive", "needs_spec"})
SETTLED = frozenset({"supported", "contradicted"})
# What may be claimed. A fixed list, so a hypothesis is never the model's free text.
CLAIMS = frozenset({
    "other_account_read",        # another account's resource can be read
    "unauthenticated_exposure",  # a protected resource answers without authentication
    "intended_public",           # the resource is meant to be public
})
_TOKEN = re.compile(r"[a-z0-9_]{1,40}")
# A string *value* passed to a planner: words only. Anything with digits (a session id, an
# API key, a hash) looks like a harmless token but may be a secret, so it is dropped.
_WORD = re.compile(r"[a-z_]{1,24}")
_REF = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,31}")


class StateError(ValueError):
    pass


def _safe_value(v):
    if isinstance(v, bool) or (isinstance(v, int) and -10**9 < v < 10**9):
        return v
    if isinstance(v, str) and _WORD.fullmatch(v):
        return v
    return None


class DiagnosisState:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._obs: dict[str, dict] = {}
        self._hyp: dict[str, dict] = {}
        self.history: list[dict] = []

    # ---- observations -----------------------------------------------------------
    def observe(self, *, kind: str, target_ref: str, attrs: dict, source: str, evidence_id: str) -> str:
        if source not in SOURCES:
            raise StateError(f"unknown observation source: {source!r}")
        if not isinstance(evidence_id, str) or not _REF.fullmatch(evidence_id or ""):
            raise StateError("an observation needs an evidence id")
        if evidence_id in self._obs:
            raise StateError(f"evidence {evidence_id} already recorded")
        if not _TOKEN.fullmatch(kind or "") or not _REF.fullmatch(target_ref or ""):
            raise StateError("kind and target_ref must be short ids")
        self._obs[evidence_id] = {"evidence_id": evidence_id, "kind": kind, "target_ref": target_ref,
                                  "source": source, "attrs": dict(attrs), "at": self._clock()}
        return evidence_id

    # ---- hypotheses -------------------------------------------------------------
    def _check_evidence(self, ids) -> list[str]:
        ids = list(ids or [])
        missing = [i for i in ids if i not in self._obs]
        if missing:
            raise StateError(f"evidence not observed: {missing}")
        return ids

    def propose(self, *, claim: str, target_ref: str, basis) -> str:
        if claim not in CLAIMS:
            raise StateError(f"unknown claim: {claim!r}")
        if not _REF.fullmatch(target_ref or ""):
            raise StateError("target_ref must be a short id")
        basis = self._check_evidence(basis)
        if not basis:
            raise StateError("a hypothesis needs at least one observation behind it")
        hid = f"H{len(self._hyp) + 1}"
        self._hyp[hid] = {"id": hid, "claim": claim, "target_ref": target_ref, "state": "open",
                          "basis": basis, "supporting": [], "contradicting": []}
        self._log(hid, "open", basis)
        return hid

    def update(self, hid: str, to: str, *, evidence) -> None:
        h = self._hyp.get(hid)
        if h is None:
            raise StateError(f"unknown hypothesis {hid}")
        if to not in STATES or to == "open":
            raise StateError(f"cannot move a hypothesis to {to!r}")
        if h["state"] in SETTLED:
            raise StateError(f"{hid} is already {h['state']}")
        evidence = self._check_evidence(evidence)
        if to in SETTLED | {"inconclusive"} and not evidence:
            raise StateError(f"{to} needs evidence")
        if to == "supported":
            h["supporting"] += evidence
        elif to == "contradicted":
            h["contradicting"] += evidence
        h["state"] = to
        self._log(hid, to, evidence)

    def _log(self, hid: str, to: str, evidence: list[str]) -> None:
        self.history.append({"hypothesis": hid, "to": to, "evidence": list(evidence), "at": self._clock()})

    # ---- reading ------------------------------------------------------------------
    def hypothesis(self, hid: str) -> dict:
        return {**self._hyp[hid], "basis": list(self._hyp[hid]["basis"]),
                "supporting": list(self._hyp[hid]["supporting"]),
                "contradicting": list(self._hyp[hid]["contradicting"])}

    def unresolved(self) -> list[dict]:
        return [self.hypothesis(h) for h, v in self._hyp.items() if v["state"] not in SETTLED]

    def finding_candidates(self) -> list[dict]:
        return [self.hypothesis(h) for h, v in self._hyp.items() if v["state"] == "supported"]

    def planner_view(self) -> dict:
        """What a planner may see: ids, kinds and short enum-like values only."""
        obs = []
        for o in self._obs.values():
            attrs = {k: sv for k, v in o["attrs"].items()
                     if _TOKEN.fullmatch(str(k)) and (sv := _safe_value(v)) is not None}
            obs.append({"evidence_id": o["evidence_id"], "kind": o["kind"], "target_ref": o["target_ref"],
                        "source": o["source"], "attrs": attrs})
        hyps = [{"id": h["id"], "claim": h["claim"], "target_ref": h["target_ref"], "state": h["state"],
                 "basis": list(h["basis"]), "supporting": list(h["supporting"]),
                 "contradicting": list(h["contradicting"])} for h in self._hyp.values()]
        return {"observations": obs, "hypotheses": hyps}


__all__ = ["CLAIMS", "DiagnosisState", "STATES", "StateError"]
