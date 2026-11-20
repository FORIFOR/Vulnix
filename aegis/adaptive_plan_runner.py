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
- duplicate detection: a catalog check already executed in this plan is never
  executed again;
- re-checks before planning and again before execution: stop/reset (generation),
  requester authority (logout, membership removal), deadline;
- evidence consistency: the step's evidence must be new, audited `result` records,
  and any evidence a finding gained during the step must be one of them.
"""
from __future__ import annotations

import secrets
import time

from .adaptive_plan_state import AdaptivePlan, IllegalTransition, PlanLimits, PlanState
from .gateway import State


class AdaptivePlanRunner:
    def __init__(self, svc, *, actor: str, roles=("operator",), request_authorized=None,
                 approve=None, limits: PlanLimits | None = None, clock=time.monotonic):
        """`approve(item) -> (approver, roles) | None` is asked for each L2 item, every time."""
        self.svc = svc
        self.actor = actor
        self.roles = tuple(roles) if roles is not None else None
        self.request_authorized = request_authorized
        self.approve = approve
        self.limits = limits or PlanLimits()
        self.clock = clock

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

    # ---- the loop -------------------------------------------------------------------
    def run(self) -> AdaptivePlan:
        self._t0 = self.clock()
        plan = AdaptivePlan(self.svc._run_generation, self._authority_generation(), self.limits)
        if not self._move(plan, PlanState.OBSERVED, reason="initial observation"):
            return plan
        executed_ids: set[str] = set()
        while True:
            abort = self._abort_reason(plan)
            if abort:
                return self._finish(plan, *abort)
            if plan.planner_rounds >= self.limits.max_planner_rounds:
                return self._finish(plan, PlanState.EXPIRED, "max_planner_rounds")
            if plan.planner_cost_usd >= self.limits.max_planner_cost_usd > 0:
                return self._finish(plan, PlanState.EXPIRED, "planner_cost_limit")
            plan.planner_rounds += 1
            try:
                snap = self.svc.plan_with_artex(self.actor, roles=self.roles,
                                                request_authorized=self.request_authorized)
            except Exception as e:  # noqa: BLE001 - nothing from a failed plan is used
                abort = self._abort_reason(plan)
                return self._finish(plan, *(abort or (PlanState.FAILED, f"planner_failed: {str(e)[:150]}")))
            view = (snap.get("artex_plan") or {}).get("plan") or {}
            gw = view.get("llm_gateway") or {}
            plan.planner_cost_usd += float(gw.get("est_cost_usd") or 0.0)
            plan.advisories += len(view.get("advisories") or [])
            if not self._move(plan, PlanState.PROPOSED, reason=f"items={len(view.get('items') or [])}"):
                return plan
            items = view.get("items") or []
            fresh = [i for i in items if i["status"] in ("planned", "awaiting_approval")
                     and i["catalog_id"] not in executed_ids]
            plan.duplicates += sum(1 for i in items if i["catalog_id"] in executed_ids)
            if plan.planner_cost_usd > self.limits.max_planner_cost_usd:
                return self._finish(plan, PlanState.EXPIRED, "planner_cost_limit")
            if not fresh:
                return self._finish(plan, PlanState.COMPLETED, "no_new_check")
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
            if not self._move(plan, PlanState.EVIDENCE_RECORDED, evidence_ids=evidence_ids, **ids):
                return plan
            executed_ids.add(item["catalog_id"])
            plan.executed.append({**ids, "level": item["level"], "evidence_ids": list(evidence_ids),
                                  "approved_by": exec_actor})
            if not self._move(plan, PlanState.OBSERVED, reason="re-observe after evidence"):
                return plan


__all__ = ["AdaptivePlanRunner", "IllegalTransition", "PlanLimits", "PlanState"]
