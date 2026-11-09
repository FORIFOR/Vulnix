"""Independent Execution Gateway + Emergency Stop (layers 1-6 wired together).

The only path from an agent proposal to a running process. The model supplies
(proposal, token); it cannot mint tokens, approvals, scope, or budget.
"""
from __future__ import annotations

import enum
import hashlib
import json
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .audit import AuditLog
from .authz import ApprovalStore, AuthzError, Engagement, TokenAuthority
from .network import EgressGuard, NetworkError, PinnedDestination
from .policy import ArgSpec, Budget, PolicyError, Tool, validate_proposal
from .runtime import RuntimeLimitError, WorkerPool, WorkerResult


class State(enum.Enum):
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"      # emergency stop: terminal


@dataclass
class Decision:
    allowed: bool
    reason: str
    result: WorkerResult | None = None
    destination: PinnedDestination | None = None


@dataclass
class StopReport:
    steps: list[tuple[str, float]] = field(default_factory=list)
    killed_pids: list[int] = field(default_factory=list)
    survivors: list[int] = field(default_factory=list)
    confirmed: bool = False


def http_probe_tool() -> Tool:
    workers = Path(__file__).parent / "workers"
    worker = str(workers / "http_probe.py")
    sentinel = str(workers / "egress_sentinel.py")

    def build(args: dict, d: PinnedDestination) -> list[str]:
        inner = [worker, "--scheme", d.scheme, "--host", d.host, "--ip", d.ip,
                 "--port", str(d.port), "--path", d.path,
                 "--method", args.get("method", "HEAD")]
        # Launch through the egress sentinel so the worker can reach ONLY the
        # pinned ip:port even if its own code tries elsewhere (defense in depth).
        return [sys.executable, "-I", sentinel, "--allow", f"{d.ip}/{d.port}", "--", *inner]

    return Tool(
        name="http_probe", action="read_only_probe",
        args={"url": ArgSpec(str, pattern=r"https?://[^\s]+"),
              "method": ArgSpec(str, required=False, choices=("HEAD", "GET"))},
        build_argv=build, timeout_s=20,
    )


def reproduction_probe_tool() -> Tool:
    workers = Path(__file__).parent / "workers"
    worker = str(workers / "reproduction_probe.py")
    sentinel = str(workers / "egress_sentinel.py")

    def build(args: dict, d: PinnedDestination) -> list[str]:
        inner = [worker, "--scheme", d.scheme, "--host", d.host, "--ip", d.ip,
                 "--port", str(d.port), "--check", args.get("check", "idor")]
        return [sys.executable, "-I", sentinel, "--allow", f"{d.ip}/{d.port}", "--", *inner]

    return Tool(
        name="reproduction_probe", action="safe_reproduction",
        args={"url": ArgSpec(str, pattern=r"https?://[^\s]+"),
              "check": ArgSpec(str, required=False, choices=("idor", "cve_2021_41773", "sqli"))},
        build_argv=build, timeout_s=20,
    )


class Gateway:
    def __init__(self, *, engagement: Engagement, tokens: TokenAuthority,
                 approvals: ApprovalStore, egress: EgressGuard, workers: WorkerPool,
                 audit: AuditLog, tools: dict[str, Tool], budget: Budget, clock=time.time):
        self.engagement = engagement
        self.tokens = tokens
        self.approvals = approvals
        self.egress = egress
        self.workers = workers
        self.audit = audit
        self.tools = tools
        self.budget = budget
        self.clock = clock
        self._state = State.RUNNING
        self._state_lock = threading.Lock()
        self._inflight: set[str] = set()
        self._inflight_lock = threading.Lock()

    @property
    def state(self) -> State:
        return self._state

    # ---- main entry -------------------------------------------------------
    def execute(self, proposal: object, token: str) -> Decision:
        try:
            return self._execute(proposal, token)
        except (AuthzError, PolicyError, NetworkError, RuntimeLimitError) as e:
            self.audit.record("deny", reason=str(e), kind=type(e).__name__,
                              proposal=_safe(proposal))
            return Decision(False, str(e))

    def _execute(self, proposal: object, token: str) -> Decision:
        if self._state is not State.RUNNING:
            raise AuthzError(f"gateway {self._state.value}")
        tool, args = validate_proposal(proposal, self.tools)
        claims = self.tokens.verify(token)
        if (claims["eng"], claims["tgt"], claims["act"], claims["tool"]) != (
                self.engagement.id, proposal["target_id"], proposal["action"], tool.name):
            raise AuthzError("token does not authorize this proposal")
        self.engagement.check_active(self.clock())
        self.approvals.check(claims["apr"], claims["eng"], claims["tgt"], claims["act"])
        target = self.engagement.targets[claims["tgt"]]
        dest = self.egress.check(args["url"], target)

        key = hashlib.sha256(json.dumps([tool.name, claims["tgt"], args],
                                        sort_keys=True).encode()).hexdigest()
        with self._inflight_lock:
            if key in self._inflight:
                raise PolicyError("identical operation already in flight")
            self._inflight.add(key)
        try:
            self.tokens.consume(claims["jti"])
            self.budget.spend()
            if self._state is not State.RUNNING:   # re-check right before launch
                raise AuthzError(f"gateway {self._state.value}")
            self.audit.record("allow", jti=claims["jti"], tool=tool.name, target=claims["tgt"],
                              approval=claims["apr"], dest=dest.__dict__)
            result = self.workers.run(tool.build_argv(args, dest), tool.timeout_s)
            self.audit.record("result", jti=claims["jti"], rc=result.returncode,
                              killed=result.killed, elapsed=result.elapsed_s)
            return Decision(True, "executed", result, dest)
        finally:
            with self._inflight_lock:
                self._inflight.discard(key)

    # ---- pause / resume ---------------------------------------------------
    def pause(self, actor: str) -> None:
        with self._state_lock:
            if self._state is State.RUNNING:
                self._state = State.PAUSED
                self.audit.record("pause", actor=actor)

    def resume(self, actor: str) -> None:
        with self._state_lock:
            if self._state is not State.PAUSED:
                raise AuthzError(f"cannot resume from {self._state.value}")
            self.engagement.check_active(self.clock())   # re-validate window & authz
            self._state = State.RUNNING
            self.audit.record("resume", actor=actor)

    # ---- emergency stop (layer 6) ----------------------------------------
    def emergency_stop(self, actor: str, confirm_timeout_s: float = 5.0) -> StopReport:
        rep = StopReport()
        t0 = time.monotonic()
        mark = lambda name: rep.steps.append((name, time.monotonic() - t0))
        with self._state_lock:
            self._state = State.STOPPED;          mark("1_block_new_actions")
        self.tokens.revoke_all();                 mark("2_revoke_tokens")
        self.egress.block_all();                  mark("3_block_egress")
        rep.killed_pids = self.workers.kill_all(); mark("4_kill_workers")
        deadline = time.monotonic() + confirm_timeout_s
        while True:
            rep.survivors = [p for p in rep.killed_pids if WorkerPool.group_alive(p)]
            if not rep.survivors or time.monotonic() > deadline:
                break
            time.sleep(0.02)
        self.audit.record("emergency_stop", actor=actor, killed=rep.killed_pids,
                          survivors=rep.survivors);  mark("5_persist_audit")
        rep.confirmed = not rep.survivors and self.audit.verify()
        mark("6_confirmed" if rep.confirmed else "6_NOT_CONFIRMED")
        return rep


def _safe(obj: object) -> object:
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = repr(obj)
    return s[:2000]
