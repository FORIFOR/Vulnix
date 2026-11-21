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

Journal (docs/DIAGNOSIS_READ_API.md): a state the service owns is given a `journal`.
Every change is written to the audit log first (`diagnosis.*` records carrying the
state's `diag_id`) and applied only when that write succeeded, by the same code that
`replay` uses. So the audit log alone can rebuild the state, and a state that does
not equal its replay (a lost write, an edited snapshot or log) is not shown.
"""
from __future__ import annotations

import contextlib
import json
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
_ACTOR = re.compile(r"[A-Za-z0-9_.@:-]{1,64}")


class StateError(ValueError):
    pass


def _safe_value(v):
    if isinstance(v, bool) or (isinstance(v, int) and -10**9 < v < 10**9):
        return v
    if isinstance(v, str) and _WORD.fullmatch(v):
        return v
    return None


JOURNAL_EVENTS = ("diagnosis.bound", "diagnosis.observed", "diagnosis.discarded", "diagnosis.generation",
                  "diagnosis.proposed", "diagnosis.applied")


def _plain(value):
    """What survives the audit log's JSON: the live state holds exactly what a replay rebuilds."""
    return json.loads(json.dumps(value, ensure_ascii=False))


class DiagnosisState:
    def __init__(self, clock=time.time, *, diag_id: str | None = None, journal=None, lock=None,
                 on_change=None):
        """`journal(event, fields) -> audit hash` is called before every change; when it
        raises, nothing changes. `lock` is held across the write and the change (so a
        reader never sees one without the other); `on_change` runs after each change."""
        self._clock = clock
        self._obs: dict[str, dict] = {}
        self._hyp: dict[str, dict] = {}
        self.generation = 1
        self.history: list[dict] = []
        self._recorded = 0            # observations ever recorded: ids and order never reuse a number
        self.binding: tuple | None = None   # (workspace run generation, root URL) it was measured on
        self.diag_id = diag_id
        self._journal = journal
        self._lock = lock
        self._on_change = on_change
        self.tail: str | None = None  # audit hash of the last journaled change
        self.frozen = False           # a history restored after a restart: read only

    # ---- journal ------------------------------------------------------------------
    def _guard(self):
        return self._lock if self._lock is not None else contextlib.nullcontext()

    def _commit(self, event: str, record: dict) -> None:
        """Audit first, then change. Called with the guard held."""
        if self.frozen:
            raise StateError("a diagnosis history restored after a restart is read only")
        record = _plain(record)
        if self._journal is not None:
            # the audit entry gets its own copy: later changes to this state never alter it
            tail = self._journal(event, {"diag_id": self.diag_id, "record": _plain(record)})
            if not (isinstance(tail, str) and _HASH.fullmatch(tail)):
                raise StateError("the change was not audited")
            self.tail = tail
        self._apply_record(event, record)
        if self._on_change is not None:
            try:
                self._on_change()
            except Exception:  # noqa: BLE001 - the change was audited and applied; a failed
                pass           # notification (snapshot / SSE) must not report it as failed

    def _apply_record(self, event: str, r: dict) -> None:
        """The only place a change takes effect - live (after the audit write) or in a replay."""
        if event == "diagnosis.bound":
            self.binding = tuple(r["binding"])
        elif event == "diagnosis.observed":
            if r["seq"] != self._recorded or r["evidence_id"] in self._obs:
                raise StateError("observation out of order")
            self._obs[r["evidence_id"]] = r
            self._recorded += 1
        elif event == "diagnosis.discarded":
            del self._obs[r["evidence_id"]]
        elif event == "diagnosis.generation":
            self.generation = r["generation"]
            self.history.append({k: r[k] for k in ("generation", "at", "abandoned") if k in r})
        elif event == "diagnosis.proposed":
            h = r["hypothesis"]
            if h["id"] in self._hyp:
                raise StateError("hypothesis id reused")
            self._hyp[h["id"]] = h
            self.history.append(r["log"])
        elif event == "diagnosis.applied":
            h = self._hyp[r["hypothesis_id"]]
            key = {"supported": "supporting", "contradicted": "contradicting"}.get(r["to"], "inconclusive")
            h[key] += [e for e in r["evidence"] if e not in h[key]]
            h["state"] = r["to"]
            self.history.append(r["log"])
        else:
            raise StateError(f"unknown diagnosis record {event!r}")

    @classmethod
    def replay(cls, diag_id: str, entries) -> "DiagnosisState":
        """Rebuild a state from audit entries (already chain-verified by the caller)."""
        state = cls(diag_id=diag_id)
        for e in entries:
            f = e.get("fields") or {}
            if e.get("event") in JOURNAL_EVENTS and f.get("diag_id") == diag_id:
                state._apply_record(e["event"], f["record"])
                state.tail = e["hash"]
        return state

    def export(self) -> dict:
        """Everything a replay must reproduce, in recording order."""
        with self._guard():
            return _plain({"diag_id": self.diag_id, "binding": self.binding, "generation": self.generation,
                           "recorded": self._recorded, "observations": list(self._obs.values()),
                           "hypotheses": list(self._hyp.values()), "history": self.history,
                           "tail": self.tail})

    # ---- observations -----------------------------------------------------------
    def observe(self, *, kind: str, target_ref: str, attrs: dict, source: str,
                evidence_id: str | None = None, audit_hash: str | None = None,
                step_id: str | None = None, catalog_id: str | None = None,
                recorded_by: str | None = None) -> str:
        """Record one measured fact. A `check` observation must name the audited
        Worker result (`audit_hash`) and the plan step that produced it. `recorded_by`
        (the person who wrote an owner spec) is audited, never shown to a planner."""
        with self._guard():
            return self._observe(kind=kind, target_ref=target_ref, attrs=attrs, source=source,
                                 evidence_id=evidence_id, audit_hash=audit_hash, step_id=step_id,
                                 catalog_id=catalog_id, recorded_by=recorded_by)

    def _observe(self, *, kind, target_ref, attrs, source, evidence_id, audit_hash, step_id, catalog_id,
                 recorded_by) -> str:
        if source not in SOURCES:
            raise StateError(f"unknown observation source: {source!r}")
        if evidence_id is None:
            evidence_id = f"E{self._recorded + 1}"
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
        if recorded_by is not None and not (isinstance(recorded_by, str) and _ACTOR.fullmatch(recorded_by)):
            raise StateError("recorded_by must be an account name")
        if source == "check" and (audit_hash is None or step_id is None or catalog_id is None):
            raise StateError("a check observation must name its audit hash, step and check")
        self._commit("diagnosis.observed", {
            "evidence_id": evidence_id, "kind": kind, "target_ref": target_ref, "source": source,
            "attrs": dict(attrs), "generation": self.generation, "audit_hash": audit_hash, "step_id": step_id,
            "catalog_id": catalog_id, "recorded_by": recorded_by, "at": self._clock(), "seq": self._recorded})
        return evidence_id

    def seq(self, evidence_id: str) -> int:
        """The order in which this observation was recorded (0-based, never reused)."""
        return self._obs[evidence_id]["seq"]

    def count(self) -> int:
        """How many observations were ever recorded (a watermark; discards do not lower it)."""
        return self._recorded

    def bind(self, binding: tuple) -> None:
        """Tie the state to the workspace and target it was measured on. Once bound, a
        state is never used for another run generation or another root."""
        with self._guard():
            if self.binding is None:
                self._commit("diagnosis.bound", {"binding": list(binding)})
            elif self.binding != tuple(_plain(list(binding))):
                raise StateError("this diagnosis state belongs to another run or target")

    def discard_unjudged(self, evidence_id: str) -> None:
        """Drop a check observation whose judgement could not be audited or applied.
        Only an observation nothing cites yet may go."""
        with self._guard():
            o = self._obs.get(evidence_id)
            if o is None or o["source"] != "check":
                raise StateError("only an unjudged check observation can be discarded")
            for h in self._hyp.values():
                if any(evidence_id in h[k] for k in ("basis", "supporting", "contradicting", "inconclusive")):
                    raise StateError("this observation is already cited")
            self._commit("diagnosis.discarded", {"evidence_id": evidence_id})

    def observation(self, evidence_id: str) -> dict:
        o = self._obs[evidence_id]          # dict reads are atomic; lists are copied
        return {**o, "attrs": dict(o["attrs"])}

    def observations(self, *, target_ref: str | None = None, generation: int | None = None) -> list[dict]:
        return [self.observation(e) for e, o in self._obs.items()
                if (target_ref is None or o["target_ref"] == target_ref)
                and (generation is None or o["generation"] == generation)]

    def begin_generation(self) -> int:
        """The target changed (the owner applied a fix): older evidence goes stale."""
        with self._guard():
            self._commit("diagnosis.generation", {"generation": self.generation + 1, "at": self._clock()})
            return self.generation

    def abandon_generation(self) -> None:
        """Undo begin_generation when nothing was recorded in the new generation (the
        re-observation failed): earlier hypotheses do not become stale for nothing."""
        with self._guard():
            if self.generation == 1 or any(o["generation"] == self.generation for o in self._obs.values()) \
                    or any(h["generation"] == self.generation for h in self._hyp.values()):
                raise StateError("the generation already holds observations")
            self._commit("diagnosis.generation", {"generation": self.generation - 1, "at": self._clock(),
                                                  "abandoned": True})

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
        with self._guard():
            return self._propose(claim, target_ref, basis, purpose, supersedes)

    def _propose(self, claim, target_ref, basis, purpose, supersedes) -> str:
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
        self._commit("diagnosis.proposed", {
            "hypothesis": {"id": hid, "claim": claim, "target_ref": target_ref, "state": "open",
                           "purpose": purpose, "supersedes": supersedes, "generation": self.generation,
                           "basis": basis, "supporting": [], "contradicting": [], "inconclusive": []},
            "log": self._log_entry(hid, "open", basis, None)})
        return hid

    def reopen_for_fix(self, hid: str, *, basis) -> str:
        """After a fix: re-check a supported hypothesis on new-generation evidence."""
        with self._guard():
            return self._reopen_for_fix(hid, basis)

    def _reopen_for_fix(self, hid, basis) -> str:
        h = self._hyp.get(hid)
        if h is None or h["state"] != "supported":
            raise StateError("only a supported hypothesis is re-checked after a fix")
        if h["generation"] == self.generation:
            raise StateError("begin a new generation (the fix) before re-checking")
        return self.propose(claim=h["claim"], target_ref=h["target_ref"], basis=basis,
                            purpose="confirm_fix", supersedes=hid)

    def apply(self, verdict, *, judged_audit_hash: str | None = None) -> bool:
        """Apply the fixed judge's verdict. Returns True when the state changed.
        `judged_audit_hash`: the `diagnosis.judged` record this verdict was audited in."""
        with self._guard():
            return self._apply_verdict(verdict, judged_audit_hash)

    def _apply_verdict(self, verdict, judged_audit_hash) -> bool:
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
        if judged_audit_hash is not None and not (isinstance(judged_audit_hash, str)
                                                  and _HASH.fullmatch(judged_audit_hash)):
            raise StateError("judged_audit_hash must be a SHA-256 hex digest")
        before = h["state"]
        self._commit("diagnosis.applied", {
            "hypothesis_id": h["id"], "to": to, "evidence": evidence, "rule": verdict.rule,
            "judged_audit_hash": judged_audit_hash, "log": self._log_entry(h["id"], to, evidence, verdict.rule)})
        return before != to

    def _log_entry(self, hid: str, to: str, evidence: list[str], rule: str | None) -> dict:
        return {"hypothesis": hid, "to": to, "evidence": list(evidence), "rule": rule, "at": self._clock()}

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


__all__ = ["CLAIMS", "DiagnosisState", "JOURNAL_EVENTS", "PURPOSES", "SETTLED", "STATES", "StateError", "TESTABLE"]
