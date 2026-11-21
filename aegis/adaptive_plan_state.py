"""State machine for a multi-step ARTEX plan.

A plan is a record, not an authority. It never holds tokens, approvals or the
means to start a worker; every step it describes still goes through
AssessmentService.plan_with_artex -> ProposalRouter -> Gateway -> Worker.

    CREATED -> OBSERVED -> PROPOSED -> AUTHORIZED -> EXECUTING -> EVIDENCE_RECORDED
                  ^                                                    |
                  +----------------------- (next step) ----------------+
    PROPOSED / EVIDENCE_RECORDED -> COMPLETED
    any non-terminal state -> REJECTED | CANCELLED | EXPIRED | FAILED

Every transition is appended to `history` with the plan id, the assessment
generation, the authority generation, the step's own approval nonce, the catalog
id, the remaining budget, the audit hash and the evidence ids. A transition that
cannot be written to the audit log does not happen (the caller fails the plan).
"""
from __future__ import annotations

import enum
import secrets
import time
from dataclasses import dataclass, field


class PlanState(str, enum.Enum):
    CREATED = "CREATED"
    OBSERVED = "OBSERVED"
    PROPOSED = "PROPOSED"
    AUTHORIZED = "AUTHORIZED"
    EXECUTING = "EXECUTING"
    EVIDENCE_RECORDED = "EVIDENCE_RECORDED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


TERMINAL = frozenset({PlanState.COMPLETED, PlanState.REJECTED, PlanState.CANCELLED,
                      PlanState.EXPIRED, PlanState.FAILED})
_ABORT = frozenset({PlanState.REJECTED, PlanState.CANCELLED, PlanState.EXPIRED, PlanState.FAILED})
TRANSITIONS: dict[PlanState, frozenset[PlanState]] = {
    PlanState.CREATED: frozenset({PlanState.OBSERVED}) | _ABORT,
    # OBSERVED -> COMPLETED: the diagnosis loop has no testable hypothesis left
    PlanState.OBSERVED: frozenset({PlanState.PROPOSED, PlanState.COMPLETED}) | _ABORT,
    PlanState.PROPOSED: frozenset({PlanState.AUTHORIZED, PlanState.COMPLETED}) | _ABORT,
    PlanState.AUTHORIZED: frozenset({PlanState.EXECUTING}) | _ABORT,
    PlanState.EXECUTING: frozenset({PlanState.EVIDENCE_RECORDED}) | _ABORT,
    PlanState.EVIDENCE_RECORDED: frozenset({PlanState.OBSERVED, PlanState.COMPLETED}) | _ABORT,
}


class IllegalTransition(RuntimeError):
    pass


@dataclass(frozen=True)
class PlanLimits:
    """Upper bounds for one plan. The Gateway's own action budget and the planner
    LLM gateway's call/token/cost budget still apply underneath these."""
    max_steps: int = 3               # executed catalog items per plan
    max_planner_rounds: int = 5      # plan_with_artex calls per plan (includes rounds with no new item)
    max_seconds: float = 300.0
    max_planner_cost_usd: float = 0.10
    max_stalled_steps: int = 2       # diagnosis loop: executed steps that changed no hypothesis

    def __post_init__(self):
        if not (1 <= self.max_steps <= 10 and 1 <= self.max_planner_rounds <= 20
                and 0 < self.max_seconds <= 3600 and 0 <= self.max_planner_cost_usd <= 5
                and 1 <= self.max_stalled_steps <= 10):
            raise ValueError("plan limits out of range")


@dataclass
class Transition:
    seq: int
    at: float
    from_state: str
    to_state: str
    plan_id: str
    assessment_generation: int
    authority_generation: str
    approval_nonce: str | None
    catalog_id: str | None
    item_id: str | None
    budget_remaining: dict
    audit_hash: str | None
    evidence_ids: tuple[str, ...]
    reason: str = ""
    step_id: str | None = None
    hypothesis_id: str | None = None


@dataclass
class AdaptivePlan:
    assessment_generation: int
    authority_generation: str
    limits: PlanLimits = field(default_factory=PlanLimits)
    plan_id: str = field(default_factory=lambda: "ap_" + secrets.token_hex(6))
    state: PlanState = PlanState.CREATED
    history: list[Transition] = field(default_factory=list)
    executed: list[dict] = field(default_factory=list)       # one record per executed item
    duplicates: int = 0
    advisories: int = 0
    rejected_steps: int = 0                                   # contract steps refused
    stalled_steps: int = 0
    planner_rounds: int = 0
    planner_cost_usd: float = 0.0
    reason: str = ""
    started: float = field(default_factory=time.monotonic)

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    def transition(self, to: PlanState, *, authority_generation: str, budget_remaining: dict,
                   audit_hash: str | None, approval_nonce: str | None = None,
                   catalog_id: str | None = None, item_id: str | None = None,
                   evidence_ids: tuple[str, ...] = (), reason: str = "",
                   step_id: str | None = None, hypothesis_id: str | None = None) -> Transition:
        if self.terminal:
            raise IllegalTransition(f"plan already {self.state.value}")
        if to not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"{self.state.value} -> {to.value} is not allowed")
        t = Transition(len(self.history) + 1, time.time(), self.state.value, to.value, self.plan_id,
                       self.assessment_generation, authority_generation, approval_nonce, catalog_id,
                       item_id, dict(budget_remaining), audit_hash, tuple(evidence_ids), reason[:200],
                       step_id, hypothesis_id)
        self.history.append(t)
        self.state = to
        if to in _ABORT or to is PlanState.COMPLETED:
            self.reason = reason[:200]
        return t

    def to_dict(self) -> dict:
        return {"plan_id": self.plan_id, "state": self.state.value, "reason": self.reason,
                "assessment_generation": self.assessment_generation,
                "authority_generation": self.authority_generation,
                "limits": self.limits.__dict__, "executed": list(self.executed),
                "duplicates": self.duplicates, "advisories": self.advisories,
                "rejected_steps": self.rejected_steps, "stalled_steps": self.stalled_steps,
                "planner_rounds": self.planner_rounds, "planner_cost_usd": round(self.planner_cost_usd, 6),
                "history": [t.__dict__ for t in self.history]}
