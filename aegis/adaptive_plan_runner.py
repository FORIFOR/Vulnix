"""Drive a multi-step ARTEX plan through the existing control plane.

The runner adds no authority. Each step calls the same entry points an operator
uses - AssessmentService.plan_with_artex (ARTEX -> reconstruct -> ProposalRouter)
and AssessmentService.execute_artex_item (Gateway -> Worker) - and only adds:

- a state machine (aegis.adaptive_plan_state) with an audited, write-ahead
  transition log: a transition that cannot be audited does not happen;
- per-plan limits (executed steps, planner rounds, wall time, planner cost) on top
  of the Gateway's action budget and the planner LLM gateway's budget;
- one item per step, and the next plan only after the step's evidence is recorded;
- no inherited approval: every executed item gets its own approval nonce and an
  L2 item needs a fresh human approval (the `approve` callback) every time;
- duplicate detection: a check already executed in this plan is never executed
  again (by catalog id; in the diagnosis loop by check, target and evidence);
- re-checks before planning and again before execution: stop/reset (generation),
  requester authority (logout, membership removal), deadline;
- evidence consistency: the step's evidence must be new, audited `result` records,
  and any evidence a finding gained during the step must be one of them.

Diagnosis loop (`diagnosis=DiagnosisState`, docs/DIAGNOSIS_LOOP_PLAN.md): every round
the planner sees the latest observations and hypotheses (with what supported,
contradicted or left them open) and must answer with id-only contract steps
(aegis.plan_contract). After a step, the Worker's result becomes a `check`
observation tied to its audit hash and step id, and ONLY the fixed judge
(aegis.diagnosis_judge) moves the hypothesis; the judgement is audited before it
is applied. The loop ends when no hypothesis is testable (all settled, or waiting
for the owner's specification), when the planner offers no acceptable new step,
when steps stop changing anything, at a limit, or on stop / revocation.
"""
from __future__ import annotations

import json
import secrets
import time

from .adaptive_plan_state import AdaptivePlan, IllegalTransition, PlanLimits, PlanState
from .gateway import State


class AdaptivePlanRunner:
    def __init__(self, svc, *, actor: str, roles=("operator",), request_authorized=None,
                 approve=None, limits: PlanLimits | None = None, clock=time.monotonic,
                 diagnosis=None):
        """`approve(item) -> (approver, roles) | None` is asked for each L2 item, every time.
        `diagnosis`: a DiagnosisState for the hypothesis-driven loop."""
        self.svc = svc
        self.actor = actor
        self.roles = tuple(roles) if roles is not None else None
        self.request_authorized = request_authorized
        self.approve = approve
        self.limits = limits or PlanLimits()
        self.clock = clock
        self.diagnosis = diagnosis
        # (catalog_id, target_ref, frozenset(evidence_refs)) already run in this loop
        self.executed_keys: set = set()

    # ---- helpers -----------------------------------------------------------------
    def _authority_generation(self) -> str:
        return str(getattr(self.svc.ledger, "generation", "") or "")

    def _budget(self, plan: AdaptivePlan) -> dict:
        return {"steps": self.limits.max_steps - len(plan.executed),
                "planner_rounds": self.limits.max_planner_rounds - plan.planner_rounds,
                "seconds": round(self.limits.max_seconds - (self.clock() - self._t0), 3),
                "planner_cost_usd": round(self.limits.max_planner_cost_usd - plan.planner_cost_usd, 6),
                "gateway_actions": getattr(self.svc.gateway.budget, "_left", None)}

    def _move(self, plan: AdaptivePlan, to: PlanState, **kw) -> bool:
        """Audit first, then transition. False (and FAILED) when the audit write fails."""
        try:
            entry = self.svc.audit.record(
                "adaptive_plan.transition", plan_id=plan.plan_id, frm=plan.state.value, to=to.value,
                catalog_id=kw.get("catalog_id"), item_id=kw.get("item_id"),
                approval_nonce=kw.get("approval_nonce"), evidence_ids=list(kw.get("evidence_ids", ())),
                step_id=kw.get("step_id"), hypothesis_id=kw.get("hypothesis_id"),
                assessment_generation=plan.assessment_generation,
                authority_generation=self._authority_generation(), reason=kw.get("reason", "")[:200])
            audit_hash = entry.get("hash") if isinstance(entry, dict) else None
            if not audit_hash:
                raise ValueError("audit record has no hash")
        except Exception as e:  # noqa: BLE001 - no audit, no transition
            if not plan.terminal:
                plan.transition(PlanState.FAILED, authority_generation=self._authority_generation(),
                                budget_remaining=self._budget(plan), audit_hash=None,
                                reason=f"audit_failed: {type(e).__name__}")
            return False
        plan.transition(to, authority_generation=self._authority_generation(),
                        budget_remaining=self._budget(plan), audit_hash=audit_hash, **kw)
        return True

    def _abort_reason(self, plan: AdaptivePlan) -> tuple[PlanState, str] | None:
        svc = self.svc
        if svc._run_generation != plan.assessment_generation or svc.gateway.state is State.STOPPED:
            return PlanState.CANCELLED, "stopped_or_reset"
        if svc.gateway.state is State.PAUSED:
            return PlanState.CANCELLED, "paused"
        if self.request_authorized is not None and not self.request_authorized():
            return PlanState.REJECTED, "requester_authority_revoked"
        if self.clock() - self._t0 > self.limits.max_seconds:
            return PlanState.EXPIRED, "deadline"
        return None

    def _finish(self, plan: AdaptivePlan, to: PlanState, reason: str) -> AdaptivePlan:
        if not plan.terminal:
            self._move(plan, to, reason=reason)
        return plan

    def _results(self) -> list[dict]:
        return [e for e in self.svc.audit.entries() if e["event"] == "result"]

    def _finding_evidence(self) -> dict[str, set[str]]:
        with self.svc._lock:
            return {fid: {e.get("audit_hash") for e in (f.get("evidence") or []) if isinstance(e, dict)}
                    for fid, f in self.svc.a.findings.items()}

    def _item(self, item_id: str) -> dict | None:
        plan = ((self.svc.artex_plan_view() or {}).get("plan") or {})
        return next((i for i in plan.get("items", []) if i["id"] == item_id), None)

    # ---- diagnosis loop --------------------------------------------------------------
    def _nothing_testable(self) -> str | None:
        """Why the diagnosis loop has nothing left to check, or None."""
        from .diagnosis_judge import propose_hypotheses
        state = self.diagnosis
        propose_hypotheses(state)                    # fixed rules, idempotent
        if state.testable():
            return None
        hyps = state.hypotheses()
        if not hyps:
            return "no_hypothesis"
        if any(h["state"] == "needs_spec" for h in hyps):
            return "needs_spec"
        return "all_settled"

    def _judge_step(self, plan: AdaptivePlan, item: dict, step_id: str, new_results: list[str],
                    ids: dict) -> str | None:
        """Turn the step's own Worker result into an observation and let the fixed
        judge decide. Returns a failure reason, or None."""
        from .diagnosis_judge import check_attrs, judge
        state, step = self.diagnosis, item.get("step") or {}
        if state.generation != self._round_generation:
            return "generation_changed"            # the target changed while the step ran
        evidence = self.svc.artex_item_evidence(item["id"])
        verified, valid = self.svc.audit.verified_entries()
        results = {e["hash"] for e in verified if e.get("event") == "result"}
        if (not valid or len(evidence) != 1
                or evidence[0].get("audit_hash") not in set(new_results) & results):
            return "evidence_mismatch"
        ev = evidence[0]
        try:
            parsed = json.loads(ev.get("content") or "")
        except ValueError:
            parsed = None
        hid, before = step["hypothesis_id"], state.hypothesis(step["hypothesis_id"])["state"]
        eid = state.observe(kind="check_result", target_ref=step["target_ref"],
                            attrs=check_attrs(item["catalog_id"], parsed), source="check",
                            audit_hash=ev["audit_hash"], step_id=step_id, catalog_id=item["catalog_id"])
        try:
            verdict = judge(state, hid, item["catalog_id"], eid)
        except Exception as e:  # noqa: BLE001
            state.discard_unjudged(eid)
            return f"judge_failed: {type(e).__name__}"
        try:                                          # audited before it takes effect
            entry = self.svc.audit.record(
                "diagnosis.judged", plan_id=plan.plan_id, step_id=step_id, item_id=item["id"],
                hypothesis_id=hid, frm=before, to=verdict.to, rule=verdict.rule,
                catalog_id=item["catalog_id"], target_ref=step["target_ref"],
                cited=list(step["evidence_refs"]), evidence=list(verdict.evidence),
                result_audit_hash=ev["audit_hash"], approval_nonce=ids["approval_nonce"])
            if not (isinstance(entry, dict) and entry.get("hash")):
                raise ValueError("audit record has no hash")
        except Exception as e:  # noqa: BLE001
            state.discard_unjudged(eid)               # an unaudited judgement leaves no trace
            return f"audit_failed: {type(e).__name__}"
        try:
            changed = state.apply(verdict)
        except Exception as e:  # noqa: BLE001
            state.discard_unjudged(eid)
            self.svc.audit.record("diagnosis.judgement_not_applied", plan_id=plan.plan_id, step_id=step_id,
                                  judged=entry["hash"], reason=type(e).__name__)
            return f"judgement_not_applied: {type(e).__name__}"
        self.executed_keys.add((item["catalog_id"], step["target_ref"], frozenset(step["evidence_refs"]),
                                state.count()))
        plan.stalled_steps = 0 if changed else plan.stalled_steps + 1
        self._last_judgement = {"hypothesis_id": hid, "from": before, "to": verdict.to,
                                "rule": verdict.rule, "observation": eid,
                                "result_audit_hash": ev["audit_hash"], "judged_audit_hash": entry["hash"]}
        return None

    # ---- the loop -------------------------------------------------------------------
    def run(self) -> AdaptivePlan:
        self._t0 = self.clock()
        diag = self.diagnosis is not None
        plan = AdaptivePlan(self.svc._run_generation, self._authority_generation(), self.limits)
        if not self._move(plan, PlanState.OBSERVED, reason="initial observation"):
            return plan
        executed_ids: set[str] = set()
        while True:
            abort = self._abort_reason(plan)
            if abort:
                return self._finish(plan, *abort)
            if diag:
                done = self._nothing_testable()
                if done:
                    return self._finish(plan, PlanState.COMPLETED, done)
                if plan.stalled_steps >= self.limits.max_stalled_steps:
                    return self._finish(plan, PlanState.EXPIRED, "stalled")
            if plan.planner_rounds >= self.limits.max_planner_rounds:
                return self._finish(plan, PlanState.EXPIRED, "max_planner_rounds")
            if plan.planner_cost_usd >= self.limits.max_planner_cost_usd > 0:
                return self._finish(plan, PlanState.EXPIRED, "planner_cost_limit")
            plan.planner_rounds += 1
            self._round_generation = self.diagnosis.generation if diag else None
            try:
                snap = self.svc.plan_with_artex(
                    self.actor, roles=self.roles, request_authorized=self.request_authorized,
                    **({"diagnosis": (self.diagnosis, frozenset(self.executed_keys))} if diag else {}))
            except Exception as e:  # noqa: BLE001 - nothing from a failed plan is used
                abort = self._abort_reason(plan)
                return self._finish(plan, *(abort or (PlanState.FAILED, f"planner_failed: {str(e)[:150]}")))
            view = (snap.get("artex_plan") or {}).get("plan") or {}
            gw = view.get("llm_gateway") or {}
            plan.planner_cost_usd += float(gw.get("est_cost_usd") or 0.0)
            plan.advisories += len(view.get("advisories") or [])
            plan.rejected_steps += len(((view.get("contract") or {}).get("rejected")) or [])
            if not self._move(plan, PlanState.PROPOSED, reason=f"items={len(view.get('items') or [])}"):
                return plan
            items = view.get("items") or []
            if diag:
                fresh = [i for i in items if i["status"] in ("planned", "awaiting_approval") and i.get("step")]
            else:
                fresh = [i for i in items if i["status"] in ("planned", "awaiting_approval")
                         and i["catalog_id"] not in executed_ids]
                plan.duplicates += sum(1 for i in items if i["catalog_id"] in executed_ids)
            if plan.planner_cost_usd > self.limits.max_planner_cost_usd:
                return self._finish(plan, PlanState.EXPIRED, "planner_cost_limit")
            if not fresh:
                return self._finish(plan, PlanState.COMPLETED, "no_progress" if diag else "no_new_check")
            if len(plan.executed) >= self.limits.max_steps:
                return self._finish(plan, PlanState.EXPIRED, "max_steps")
            item = fresh[0]
            exec_actor, exec_roles = self.actor, self.roles
            if item["level"] == "L2":
                granted = self.approve(dict(item)) if self.approve is not None else None
                if not granted:
                    return self._finish(plan, PlanState.REJECTED, "l2_approval_missing")
                exec_actor, exec_roles = granted
            nonce = "apv_" + secrets.token_hex(8)
            ids = {"catalog_id": item["catalog_id"], "item_id": item["id"], "approval_nonce": nonce}
            if diag:
                ids.update(step_id=f"S{len(plan.executed) + 1}", hypothesis_id=item["step"]["hypothesis_id"])
            if not self._move(plan, PlanState.AUTHORIZED, **ids):
                return plan
            abort = self._abort_reason(plan)
            if abort:
                return self._finish(plan, *abort)
            if not self._move(plan, PlanState.EXECUTING, **ids):   # write-ahead: no audit, no worker
                return plan
            results_before = {e["hash"] for e in self._results()}
            evidence_before = self._finding_evidence()
            try:
                self.svc.execute_artex_item(item["id"], exec_actor, roles=exec_roles,
                                            request_authorized=self.request_authorized)
            except Exception as e:  # noqa: BLE001
                abort = self._abort_reason(plan)
                if abort:
                    return self._finish(plan, *abort)
                kind = PlanState.REJECTED if type(e).__name__ == "ApproverRequired" else PlanState.FAILED
                return self._finish(plan, kind, f"execute_failed: {str(e)[:150]}")
            abort = self._abort_reason(plan)
            if abort:
                # a result that arrives after a stop or a revocation is not adopted
                return self._finish(plan, *abort)
            after = self._item(item["id"])
            if not after or after["status"] != "completed":
                return self._finish(plan, PlanState.FAILED,
                                    f"item_{(after or {}).get('status', 'missing')}")
            new_results = [e["hash"] for e in self._results() if e["hash"] not in results_before]
            if not new_results:
                return self._finish(plan, PlanState.FAILED, "evidence_missing")
            gained = {h for fid, hs in self._finding_evidence().items()
                      for h in hs - evidence_before.get(fid, set()) if h}
            if not gained <= set(new_results) or not self.svc.audit.verify():
                return self._finish(plan, PlanState.FAILED, "evidence_mismatch")
            evidence_ids = tuple("ev_" + h[:12] for h in new_results)
            judgement = None
            if diag:
                try:
                    failure = self._judge_step(plan, item, ids["step_id"], new_results, ids)
                except Exception as e:  # noqa: BLE001 - never leave the plan open
                    failure = f"judge_failed: {type(e).__name__}"
                if failure:
                    return self._finish(plan, PlanState.FAILED, failure)
                judgement = self._last_judgement
            if not self._move(plan, PlanState.EVIDENCE_RECORDED, evidence_ids=evidence_ids, **ids):
                return plan
            executed_ids.add(item["catalog_id"])
            record = {**ids, "level": item["level"], "evidence_ids": list(evidence_ids),
                      "approved_by": exec_actor}
            if diag:
                record.update(target_ref=item["step"]["target_ref"],
                              evidence_refs=list(item["step"]["evidence_refs"]),
                              reason=item["step"]["reason"], judgement=judgement)
            plan.executed.append(record)
            if not self._move(plan, PlanState.OBSERVED, reason="re-observe after evidence"):
                return plan


__all__ = ["AdaptivePlanRunner", "IllegalTransition", "PlanLimits", "PlanState"]
