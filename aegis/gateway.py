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
from .confinement import ConfinementError
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
        # above the worker's own overall deadline (45 s, workers/http_probe.py), so a
        # slow first byte is reported by the worker with its stage, not killed blind
        build_argv=build, timeout_s=50,
    )


LAB_REPRODUCTION_CHECKS = ("idor", "cve_2021_41773", "sqli")


def reproduction_probe_tool(l2_rules=None) -> Tool:
    """`l2_rules` (an `aegis.l2_rules.L2RuleSet`) adds profile-defined checks. Their
    rule is passed to the worker on argv (no secrets in it); the gateway itself
    carries no service-specific check names."""
    workers = Path(__file__).resolve().parent / "workers"
    worker = str(workers / "reproduction_probe.py")
    sentinel = str(workers / "egress_sentinel.py")
    # only rules confirmed against the target API are executable at all
    rule_checks = tuple(l2_rules.runnable_check_ids()) if l2_rules is not None else ()

    def build(args: dict, d: PinnedDestination) -> list[str]:
        check = args.get("check", "idor")
        inner = [worker, "--scheme", d.scheme, "--host", d.host, "--ip", d.ip,
                 "--port", str(d.port), "--check", check]
        if check in rule_checks:
            inner += ["--rule-json", l2_rules.worker_rule_json(check)]
        return [sys.executable, "-I", sentinel, "--allow", f"{d.ip}/{d.port}", "--", *inner]

    return Tool(
        name="reproduction_probe", action="safe_reproduction",
        args={"url": ArgSpec(str, pattern=r"https?://[^\s]+"),
              "check": ArgSpec(str, required=False, choices=LAB_REPRODUCTION_CHECKS + rule_checks)},
        build_argv=build, timeout_s=30,
    )


class Gateway:
    def __init__(self, *, engagement: Engagement, tokens: TokenAuthority,
                 approvals: ApprovalStore, egress: EgressGuard, workers: WorkerPool,
                 audit: AuditLog, tools: dict[str, Tool], budget: Budget, clock=time.time,
                 ephemeral_env_provider=None, secret_redactor=None,
                 confinement_provider=None, launch_guard=None):
        self.engagement = engagement
        self.tokens = tokens
        self.approvals = approvals
        self.egress = egress
        self.workers = workers
        self.audit = audit
        self.tools = tools
        self.budget = budget
        self.clock = clock
        # Optional callable(tool_name, validated_args) -> dict. Evaluated per call,
        # after every authorization check, so a secret reaches only the one worker
        # process it was approved for (never argv, never the audit log).
        self.ephemeral_env_provider = ephemeral_env_provider
        # Optional callable(tool_name, validated_args, dest) -> None | context manager
        # yielding a kernel confinement session. It raises PolicyError when a run that
        # requires kernel confinement cannot have it; the worker is then not started.
        self.confinement_provider = confinement_provider
        # Optional callable(tool_name, validated_args, dest), called as the LAST step
        # before a worker starts. It raises PolicyError when what was authorised at
        # the start of this request (scope, addresses, workspace) no longer holds -
        # name resolution and proof re-checks in between can take a long time.
        self.launch_guard = launch_guard
        # Bumped by every emergency stop and workspace reset. A request that was
        # already past the first checks when that happened must not launch.
        self._launch_epoch = 0
        self.secret_redactor = secret_redactor
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

    def invalidate_pending(self) -> None:
        """Requests that are still waiting (e.g. in name resolution) may no longer launch."""
        with self._state_lock:
            self._launch_epoch += 1

    def _still_current(self, epoch: int) -> None:
        if self._state is not State.RUNNING:
            raise AuthzError(f"gateway {self._state.value}")
        if self._launch_epoch != epoch:
            raise AuthzError("gateway was stopped or reset while this request was waiting")

    def _execute(self, proposal: object, token: str) -> Decision:
        if self._state is not State.RUNNING:
            raise AuthzError(f"gateway {self._state.value}")
        # Both are fixed NOW. A stop or reset closes this pool and moves the epoch
        # on, so a request that outlives it can only fail.
        epoch, workers = self._launch_epoch, self.workers
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
            self._still_current(epoch)             # re-check right before launch
            self.audit.record("allow", jti=claims["jti"], tool=tool.name, target=claims["tgt"],
                              approval=claims["apr"], dest=dest.__dict__)
            argv = tool.build_argv(args, dest)
            confine = (self.confinement_provider(tool.name, args, dest)
                       if self.confinement_provider else None)
            if confine is None:
                extra_env = (self.ephemeral_env_provider(tool.name, args)
                             if self.ephemeral_env_provider else None)
                self._still_current(epoch)
                if self.launch_guard:
                    self.launch_guard(tool.name, args, dest)
                result = workers.run(argv, tool.timeout_s, extra_env=extra_env or None,
                                     permit=lambda: self._still_current(epoch))
            else:
                # Applied and confirmed by the kernel BEFORE any secret is read for
                # the worker; a failure here means nothing is launched.
                workers.hold(confine)              # from the probe on, until the teardown has finished
                held = [confine]
                try:
                    with confine as session:
                        self.audit.record("confinement.applied", jti=claims["jti"], tool=tool.name,
                                          **dict(getattr(session, "evidence", {}) or {}))
                        if not session.still_enforced():
                            raise PolicyError("kernel confinement was removed before the worker started")
                        extra_env = (self.ephemeral_env_provider(tool.name, args)
                                     if self.ephemeral_env_provider else None)
                        self._still_current(epoch)
                        if self.launch_guard:
                            self.launch_guard(tool.name, args, dest)
                        result = workers.run(argv, tool.timeout_s, extra_env=extra_env,
                                             session=session, permit=lambda: self._still_current(epoch))
                        intact = session.still_enforced()
                except ConfinementError as e:
                    raise PolicyError(f"kernel confinement not confirmed: {e}") from None
                finally:
                    for session_ in held:                # tracked until its teardown has finished
                        workers.release(session_)
                if getattr(session, "leftover", False):
                    # something in the cgroup could not be killed: its rules were
                    # left in place, and this run is not accepted
                    self.audit.record("confinement.leftover", jti=claims["jti"], tool=tool.name,
                                      cgroup=getattr(session, "name", ""))
                    raise PolicyError("a confined process could not be terminated; its confinement was left in place")
                if not intact:
                    # the rules were gone by the time the worker ended: its output
                    # is not evidence of a confined run
                    self.audit.record("confinement.lost", jti=claims["jti"], tool=tool.name)
                    raise PolicyError("kernel confinement was not in place for the whole run")
            if self.secret_redactor:
                result = WorkerResult(
                    result.returncode,
                    self.secret_redactor(result.stdout or ""),
                    self.secret_redactor(result.stderr or ""),
                    result.killed,
                    result.elapsed_s,
                )
            self.audit.record("result", jti=claims["jti"], tool=tool.name, rc=result.returncode,
                              killed=result.killed, elapsed=result.elapsed_s,
                              stdout_preview=result.stdout.strip()[:280])
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
            self._state = State.STOPPED
            self._launch_epoch += 1;              mark("1_block_new_actions")
        self.tokens.revoke_all();                 mark("2_revoke_tokens")
        self.egress.block_all();                  mark("3_block_egress")
        rep.killed_pids = self.workers.kill_all(); mark("4_kill_workers")
        # keeps killing until every worker is confirmed dead or the time is up
        rep.survivors = self.workers.confirm_stopped(rep.killed_pids, confirm_timeout_s)
        busy = self.workers.busy_sessions()          # a confined run still tearing down
        while busy and time.monotonic() - t0 < confirm_timeout_s:
            for x in busy:
                x.kill()
            time.sleep(0.05)
            busy = self.workers.busy_sessions()
        try:
            self.audit.record("emergency_stop", actor=actor, killed=rep.killed_pids,
                              survivors=rep.survivors)
            audited = True
        except Exception:
            # the stop itself has happened; an audit log that cannot be written must
            # not undo it, but the stop is then not reported as confirmed
            audited = False
        mark("5_persist_audit")
        rep.confirmed = not rep.survivors and not busy and audited and self.audit.verify()
        mark("6_confirmed" if rep.confirmed else "6_NOT_CONFIRMED")
        return rep


def _safe(obj: object) -> object:
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        s = repr(obj)
    return s[:2000]
