"""Observations and hypotheses, kept apart from findings (docs/DIAGNOSIS_LOOP_PLAN.md).

A hypothesis is "this may be a problem, and here is what we still need to know". It
is not a finding: only a hypothesis that Vulnix's fixed judge marked `supported`,
citing evidence Vulnix itself recorded, may be turned into one. A planner (ARTEX, a
model) never changes a state: it is shown the planner view and may only name the
next check by id (aegis.plan_contract).

Who may change what:
- `observe`   - Vulnix code that measured something (fixed L1, a check's Worker
                result, the owner's written specification). Never a model.
- `propose`   - Vulnix's fixed proposer (aegis.diagnosis_judge.propose_hypotheses).
- `apply`     - takes only a `Verdict`, which only aegis.diagnosis_judge can make.

Generations: every observation belongs to the generation it was measured in. When
the owner changes the target (a fix), `begin_generation` starts a new one; evidence
from an older generation can no longer be cited for a new step, and a supported
hypothesis is re-checked through a new `confirm_fix` hypothesis built on fresh
observations (`reopen_for_fix`).

The planner view carries ids, kinds and short enum-like values only. Raw values
(cookies, URLs, page text, audit hashes, anything that does not look like a short
word) are dropped, so nothing secret can be phrased into a model request.
"""
from __future__ import annotations

import re
import time

SOURCES = frozenset({"l1", "check", "owner_spec"})          # never "model"
STATES = frozenset({"open", "supported", "contradicted", "inconclusive", "needs_spec"})
SETTLED = frozenset({"supported", "contradicted"})
# Still worth a check: open, or inconclusive (new evidence may decide it).
# `needs_spec` waits for the owner, not for another request to the target.
TESTABLE = frozenset({"open", "inconclusive"})
PURPOSES = frozenset({"diagnose", "confirm_fix"})
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
_HASH = re.compile(r"[0-9a-f]{64}")


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
        self.generation = 1
        self.history: list[dict] = []

    # ---- observations -----------------------------------------------------------
    def observe(self, *, kind: str, target_ref: str, attrs: dict, source: str,
                evidence_id: str | None = None, audit_hash: str | None = None,
                step_id: str | None = None, catalog_id: str | None = None) -> str:
        """Record one measured fact. A `check` observation must name the audited
        Worker result (`audit_hash`) and the plan step that produced it."""
        if source not in SOURCES:
            raise StateError(f"unknown observation source: {source!r}")
        if evidence_id is None:
            evidence_id = f"E{len(self._obs) + 1}"
        if not isinstance(evidence_id, str) or not _REF.fullmatch(evidence_id):
            raise StateError("an observation needs an evidence id")
        if evidence_id in self._obs:
            raise StateError(f"evidence {evidence_id} already recorded")
        if not isinstance(kind, str) or not _TOKEN.fullmatch(kind):
            raise StateError("kind must be a short id")
        if not isinstance(target_ref, str) or not _REF.fullmatch(target_ref):
            raise StateError("target_ref must be a short id")
        if not isinstance(attrs, dict):
            raise StateError("attrs must be an object")
        if audit_hash is not None and not (isinstance(audit_hash, str) and _HASH.fullmatch(audit_hash)):
            raise StateError("audit_hash must be a SHA-256 hex digest")
        if step_id is not None and not (isinstance(step_id, str) and _REF.fullmatch(step_id)):
            raise StateError("step_id must be a short id")
        if catalog_id is not None and not (isinstance(catalog_id, str) and _TOKEN.fullmatch(catalog_id)):
            raise StateError("catalog_id must be a short id")
        if source == "check" and (audit_hash is None or step_id is None or catalog_id is None):
            raise StateError("a check observation must name its audit hash, step and check")
        self._obs[evidence_id] = {"evidence_id": evidence_id, "kind": kind, "target_ref": target_ref,
                                  "source": source, "attrs": dict(attrs), "generation": self.generation,
                                  "audit_hash": audit_hash, "step_id": step_id, "catalog_id": catalog_id,
                                  "at": self._clock()}
        return evidence_id

    def seq(self, evidence_id: str) -> int:
        """The order in which this observation was recorded (0-based)."""
        return list(self._obs).index(evidence_id)

    def count(self) -> int:
        return len(self._obs)

    def discard_unjudged(self, evidence_id: str) -> None:
        """Drop a check observation whose judgement could not be audited or applied.
        Only an observation nothing cites yet may go."""
        o = self._obs.get(evidence_id)
        if o is None or o["source"] != "check":
            raise StateError("only an unjudged check observation can be discarded")
        for h in self._hyp.values():
            if any(evidence_id in h[k] for k in ("basis", "supporting", "contradicting", "inconclusive")):
                raise StateError("this observation is already cited")
        del self._obs[evidence_id]

    def observation(self, evidence_id: str) -> dict:
        o = self._obs[evidence_id]
        return {**o, "attrs": dict(o["attrs"])}

    def observations(self, *, target_ref: str | None = None, generation: int | None = None) -> list[dict]:
        return [self.observation(e) for e, o in self._obs.items()
                if (target_ref is None or o["target_ref"] == target_ref)
                and (generation is None or o["generation"] == generation)]

    def begin_generation(self) -> int:
        """The target changed (the owner applied a fix): older evidence goes stale."""
        self.generation += 1
        self.history.append({"generation": self.generation, "at": self._clock()})
        return self.generation

    # ---- hypotheses -------------------------------------------------------------
    def _check_evidence(self, ids, *, target_ref: str | None = None) -> list[str]:
        if not isinstance(ids, (list, tuple)) or not all(isinstance(i, str) for i in ids):
            raise StateError("evidence must be a list of ids")
        ids = list(ids)
        missing = [i for i in ids if i not in self._obs]
        if missing:
            raise StateError(f"evidence not observed: {missing}")
        if len(set(ids)) != len(ids):
            raise StateError("evidence listed twice")
        if target_ref is not None and any(self._obs[i]["target_ref"] != target_ref for i in ids):
            raise StateError("evidence belongs to another target")
        return ids

    def propose(self, *, claim: str, target_ref: str, basis, purpose: str = "diagnose",
                supersedes: str | None = None) -> str:
        if claim not in CLAIMS:
            raise StateError(f"unknown claim: {claim!r}")
        if purpose not in PURPOSES:
            raise StateError(f"unknown purpose: {purpose!r}")
        if not isinstance(target_ref, str) or not _REF.fullmatch(target_ref):
            raise StateError("target_ref must be a short id")
        basis = self._check_evidence(basis, target_ref=target_ref)
        if not basis:
            raise StateError("a hypothesis needs at least one observation behind it")
        if any(self._obs[i]["generation"] != self.generation for i in basis):
            raise StateError("a hypothesis is built on current observations only")
        for h in self._hyp.values():
            if (h["claim"], h["target_ref"], h["purpose"], h["generation"]) == (
                    claim, target_ref, purpose, self.generation) and h["supersedes"] == supersedes:
                raise StateError(f"{h['id']} already states this")
        hid = f"H{len(self._hyp) + 1}"
        self._hyp[hid] = {"id": hid, "claim": claim, "target_ref": target_ref, "state": "open",
                          "purpose": purpose, "supersedes": supersedes, "generation": self.generation,
                          "basis": basis, "supporting": [], "contradicting": [], "inconclusive": []}
        self._log(hid, "open", basis, None)
        return hid

    def reopen_for_fix(self, hid: str, *, basis) -> str:
        """After a fix: re-check a supported hypothesis on new-generation evidence."""
        h = self._hyp.get(hid)
        if h is None or h["state"] != "supported":
            raise StateError("only a supported hypothesis is re-checked after a fix")
        if h["generation"] == self.generation:
            raise StateError("begin a new generation (the fix) before re-checking")
        return self.propose(claim=h["claim"], target_ref=h["target_ref"], basis=basis,
                            purpose="confirm_fix", supersedes=hid)

    def apply(self, verdict) -> bool:
        """Apply the fixed judge's verdict. Returns True when the state changed."""
        from .diagnosis_judge import Verdict
        if type(verdict) is not Verdict or not verdict.issued_by_judge():
            raise StateError("only the fixed judge changes a hypothesis")
        h = self._hyp.get(verdict.hypothesis_id)
        if h is None:
            raise StateError(f"unknown hypothesis {verdict.hypothesis_id}")
        to = verdict.to
        if to not in STATES or to == "open":
            raise StateError(f"cannot move a hypothesis to {to!r}")
        if h["state"] in SETTLED:
            raise StateError(f"{h['id']} is already {h['state']}")
        evidence = self._check_evidence(verdict.evidence, target_ref=h["target_ref"])
        if not evidence:
            raise StateError(f"{to} needs evidence")
        if any(self._obs[i]["generation"] != h["generation"] for i in evidence):
            raise StateError("a verdict cites evidence from another generation")
        if to in SETTLED and not any(self._obs[i]["source"] in ("check", "l1") for i in evidence):
            raise StateError("a settled verdict needs a measured observation")
        if to == "supported" and not any(self._obs[i]["source"] == "check" for i in evidence):
            raise StateError("support needs a check result, not only an initial observation")
        before = h["state"]
        key = {"supported": "supporting", "contradicted": "contradicting"}.get(to, "inconclusive")
        h[key] += [e for e in evidence if e not in h[key]]
        h["state"] = to
        self._log(h["id"], to, evidence, verdict.rule)
        return before != to

    def _log(self, hid: str, to: str, evidence: list[str], rule: str | None) -> None:
        self.history.append({"hypothesis": hid, "to": to, "evidence": list(evidence), "rule": rule,
                             "at": self._clock()})

    # ---- reading ------------------------------------------------------------------
    def hypothesis(self, hid: str) -> dict:
        h = self._hyp[hid]
        return {**h, **{k: list(h[k]) for k in ("basis", "supporting", "contradicting", "inconclusive")}}

    def hypotheses(self) -> list[dict]:
        return [self.hypothesis(h) for h in self._hyp]

    def unresolved(self) -> list[dict]:
        return [self.hypothesis(h) for h, v in self._hyp.items() if v["state"] not in SETTLED]

    def testable(self) -> list[dict]:
        return [self.hypothesis(h) for h, v in self._hyp.items() if v["state"] in TESTABLE]

    def finding_candidates(self) -> list[dict]:
        return [self.hypothesis(h) for h, v in self._hyp.items()
                if v["state"] == "supported" and v["purpose"] == "diagnose"]

    def planner_view(self) -> dict:
        """What a planner may see: ids, kinds and short enum-like values only."""
        obs = []
        for o in self._obs.values():
            attrs = {k: sv for k, v in o["attrs"].items()
                     if _TOKEN.fullmatch(str(k)) and (sv := _safe_value(v)) is not None}
            obs.append({"evidence_id": o["evidence_id"], "kind": o["kind"], "target_ref": o["target_ref"],
                        "source": o["source"], "generation": o["generation"], "attrs": attrs})
        hyps = [{"id": h["id"], "claim": h["claim"], "target_ref": h["target_ref"], "state": h["state"],
                 "purpose": h["purpose"], "generation": h["generation"],
                 "basis": list(h["basis"]), "supporting": list(h["supporting"]),
                 "contradicting": list(h["contradicting"]), "inconclusive": list(h["inconclusive"])}
                for h in self._hyp.values()]
        return {"generation": self.generation, "observations": obs, "hypotheses": hyps}


__all__ = ["CLAIMS", "DiagnosisState", "PURPOSES", "SETTLED", "STATES", "StateError", "TESTABLE"]
