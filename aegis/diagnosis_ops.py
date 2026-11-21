"""PR-C: the state-changing operations of the lab-only diagnosis loop.

Four operations, each behind one permission that the server checks against the
caller's live roles in the bound organization (docs/DIAGNOSIS_ACTIONS.md):

| operation | permission | service role |
| --- | --- | --- |
| start the loop | diagnosis:request | operator |
| the owner's specification | asset:specify | admin (organization owner / admin) |
| start the after-fix re-check | diagnosis:request | operator |
| approve one L2 step | diagnosis:approve_l2 | approver, never the requester |
| read the view | diagnosis:read | any member |

Every operation needs an Idempotency-Key. A request is recorded (audit first, then the
request file on disk) before anything else happens, so

- the same key with the same request returns the stored outcome and does nothing again;
- the same key with a different request (other operation, body or person) is 409;
- one operation per scope (assessment run, diagnosis, generation, target / step) is
  accepted: a second request with another key is 409;
- at most one loop runs per assessment. After a restart, a loop that was running is
  recorded as interrupted and is never resumed by a retry: the Worker of a step runs
  at most once (the plan items live in memory only, and a retry finds the stored
  outcome instead of starting anything).

Nothing here talks to a real service: every operation answers 404 unless Vulnix lists
the registered local lab as a diagnosis target.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import threading
import time

from .diagnosis_loop import begin_fix_check, observe_lab_root, record_owner_spec
from .policy import PolicyError

PERMISSIONS = {
    "diagnosis:read": frozenset({"viewer", "operator", "approver", "admin"}),
    "diagnosis:request": frozenset({"operator"}),
    "asset:specify": frozenset({"admin"}),
    "diagnosis:approve_l2": frozenset({"approver"}),
}
OP_PERMISSION = {"start": "diagnosis:request", "owner-spec": "asset:specify",
                 "fix-check": "diagnosis:request", "approve": "diagnosis:approve_l2"}
SPECS = ("authentication_required", "public")     # what the owner may state (the screen's two choices)
KEY = re.compile(r"[A-Za-z0-9_-]{16,128}")
ACTIVE = ("awaiting_spec", "running", "waiting_approval")
MAX_REQUESTS = 500                                # remembered requests per assessment (oldest dropped)


def permitted(permission: str, roles) -> bool:
    return bool(PERMISSIONS[permission] & set(roles or ()))


def permissions_of(roles) -> list[str]:
    return sorted(p for p in PERMISSIONS if permitted(p, roles))


def member_permissions(roles) -> list[str]:
    """For a caller whose membership the server has just verified: a member of the
    organization may always read (a viewer has no service role, yet reads)."""
    return sorted(set(permissions_of(roles)) | {"diagnosis:read"})


class OpError(Exception):
    """An operation that is refused: (HTTP status, message, reason id)."""

    def __init__(self, status: int, message: str, reason: str):
        super().__init__(message)
        self.status, self.message, self.reason = status, message, reason


def _fingerprint(op: str, actor: str, body: dict) -> str:
    raw = json.dumps({"op": op, "actor": actor, "body": body}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _key_id(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def approval_timeout() -> float:
    try:
        return max(1.0, float(os.environ.get("VULNIX_DIAGNOSIS_APPROVAL_TIMEOUT", "900")))
    except ValueError:
        return 900.0


def approval_valid() -> float:
    """How long an approval, once taken by the loop, stays good for its one Worker."""
    try:
        return max(1.0, float(os.environ.get("VULNIX_DIAGNOSIS_APPROVAL_VALID", "300")))
    except ValueError:
        return 300.0


def spec_timeout() -> float:
    try:
        return max(1.0, float(os.environ.get("VULNIX_DIAGNOSIS_SPEC_TIMEOUT", "86400")))
    except ValueError:
        return 86400.0


class DiagnosisOperations:
    """One per AssessmentService (so per organization). All state is guarded by the
    service's lock, which the diagnosis state shares."""

    def __init__(self, svc):
        self.svc = svc
        self._requests: dict[str, dict] = {}     # key id -> record
        self._scopes: dict[str, str] = {}        # scope -> key id
        self._job: dict | None = None            # the latest loop job (public fields only)
        self._live: dict = {}                    # job id -> in-memory parts (authority, approval)
        self._closed = False
        self._persist_error: str | None = None
        self._load()

    # ---- persistence ----------------------------------------------------------------
    def _path(self):
        return self.svc.data_dir / "diagnosis_requests.json"

    def _load(self) -> None:
        try:
            data = json.loads(self._path().read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            data = None
        if not isinstance(data, dict) or data.get("assessment_id") != self.svc.a.id:
            # unreadable: refuse every operation until a reset (never guess what was accepted)
            self._persist_error = "unreadable"
            return
        self._requests = {k: v for k, v in (data.get("requests") or {}).items() if isinstance(v, dict)}
        self._scopes = {k: v for k, v in (data.get("scopes") or {}).items() if isinstance(v, str)}
        job = data.get("job")
        if isinstance(job, dict):
            if job.get("state") in ACTIVE:
                # the process ended while the loop ran: it is never resumed
                job = {**job, "state": "interrupted", "waiting_item_id": None,
                       "result": {"reason": "server_restarted"}}
                for rec in self._requests.values():
                    if rec.get("job_id") == job["id"] and rec.get("status") == "accepted":
                        rec["status"] = "interrupted"
            self._job = job
        try:
            self._save_locked()
        except OSError:
            pass

    def _save_locked(self) -> None:
        if self._closed:
            return            # a closed service never writes again (the next process owns the file)
        payload = {"version": 1, "assessment_id": self.svc.a.id, "requests": self._requests,
                   "scopes": self._scopes, "job": self._job}
        tmp = self._path().with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path())

    def reset(self) -> None:
        """The workspace was reset (audited by the service): forget every request."""
        with self.svc._lock:
            self._wake_locked()
            if self._job is not None:
                self._release_locked(self._job["id"])
            self._requests, self._scopes, self._job, self._live = {}, {}, None, {}
            self._persist_error = None
            try:
                os.unlink(self._path())
            except OSError:
                pass

    def close(self) -> None:
        """Clean shutdown: a loop that has not ended is recorded as interrupted (a retry
        after the restart replays that, never runs it again), then nothing more is written."""
        with self.svc._lock:
            if self._closed:
                return
            j = self._job
            if j is not None and j.get("state") in ACTIVE:
                j.update(state="interrupted", waiting_item_id=None, result={"reason": "server_restarted"})
                for rec in self._requests.values():
                    if rec.get("job_id") == j["id"] and rec.get("status") == "accepted":
                        rec["status"] = "interrupted"
                try:
                    self._save_locked()
                except OSError:
                    pass
            self._closed = True
            if j is not None:
                self._release_locked(j["id"])
            self._wake_locked()

    def _wake_locked(self) -> None:
        for live in self._live.values():
            ev = live.get("event")
            if ev is not None:
                ev.set()

    # ---- the public view of the loop job ------------------------------------------------
    def job_view_locked(self) -> dict | None:
        self._expire_locked()
        j = self._job
        if j is None:
            return None
        return {k: j.get(k) for k in ("id", "kind", "state", "requested_by", "diag_id", "generation",
                                      "waiting_item_id", "needs_spec", "result", "started_at")}

    def _release_locked(self, job_id: str) -> None:
        if self.svc._exec_owner == job_id:
            self.svc._exec_owner = None

    def _expire_locked(self) -> None:
        """A job waiting for the owner's statement holds the assessment: it ends when the
        run is stopped or reset, or when nobody answers in time. (A running loop ends
        itself: the runner checks stop, reset and its own deadline.)"""
        j, svc = self._job, self.svc
        if j is None or j.get("state") != "awaiting_spec":
            return
        reason = None
        if svc.gateway.state.name in ("STOPPED", "PAUSED") or svc._run_generation != j.get("run_generation") \
                or svc._diagnosis is None or svc._diagnosis.diag_id != j.get("diag_id"):
            reason = "stopped_or_reset"
        elif time.time() - float(j.get("spec_since") or j.get("started_at") or 0) > spec_timeout():
            reason = "spec_timeout"
        if reason:
            j.update(state="failed", waiting_item_id=None, result={"reason": reason})
            self._live.pop(j["id"], None)
            self._release_locked(j["id"])
            for rec in self._requests.values():
                if rec.get("job_id") == j["id"] and rec.get("status") == "accepted":
                    rec["status"] = "done"
            try:
                self._save_locked()
            except OSError:
                pass

    def active_locked(self) -> bool:
        self._expire_locked()
        return self._job is not None and self._job.get("state") in ACTIVE

    def active(self) -> bool:
        with self.svc._lock:
            return self.active_locked()

    # ---- the request record (idempotency) ----------------------------------------------
    def _accept(self, op: str, key: str, actor: str, body: dict, scope: str | None):
        """Under the lock. Returns (record, replay). Raises OpError on a conflict."""
        if self._persist_error:
            raise OpError(503, "診断の要求記録を読めないため、操作を受け付けません。作業領域をリセットしてください",
                          "request_store_unreadable")
        if not isinstance(key, str) or not KEY.fullmatch(key):
            raise OpError(400, "Idempotency-Key（16〜128文字の英数字・-・_）が必要です", "idempotency_key_required")
        kid = _key_id(key)
        fp = _fingerprint(op, actor, body)
        rec = self._requests.get(kid)
        if rec is not None:
            if rec.get("fingerprint") != fp:
                raise OpError(409, "同じ Idempotency-Key で、別の内容の要求が送られました", "idempotency_key_reused")
            return rec, True
        if scope is not None and scope in self._scopes:
            raise OpError(409, "同じ対象・世代への同じ操作は、すでに受け付けています", "already_accepted")
        rec = {"op": op, "fingerprint": fp, "actor": actor, "scope": scope, "at": time.time(),
               "status": "accepted", "result": None, "job_id": None}
        # audit first: a request that cannot be audited is not accepted
        try:
            self.svc._diagnosis_journal("diagnosis.request_accepted", {
                "op": op, "request": kid, "actor": actor, "scope": scope})
        except Exception as e:  # noqa: BLE001
            raise OpError(503, "監査ログに記録できないため、操作を受け付けません", "audit_failed") from e
        self._requests[kid] = rec
        if scope is not None:
            self._scopes[scope] = kid
        if len(self._requests) > MAX_REQUESTS:
            for old in sorted(self._requests, key=lambda k: self._requests[k].get("at", 0))[:-MAX_REQUESTS]:
                if self._requests[old].get("status") != "accepted":
                    dropped = self._requests.pop(old, None) or {}
                    if dropped.get("scope") and self._scopes.get(dropped["scope"]) == old:
                        self._scopes.pop(dropped["scope"], None)
        try:
            self._save_locked()
        except OSError as e:
            # not on disk: a restart could not tell this request was accepted
            try:
                self.svc.audit.record("diagnosis.request_dropped", request=kid, reason="not_persisted")
            except Exception:  # noqa: BLE001
                pass
            self._requests.pop(kid, None)
            if scope is not None:
                self._scopes.pop(scope, None)
            raise OpError(503, "要求を保存できないため、操作を受け付けません", "request_not_persisted") from e
        return rec, False

    def _finish_request_locked(self, rec: dict, status: str, result: dict) -> None:
        rec["status"], rec["result"] = status, result
        try:
            self._save_locked()
        except OSError:
            pass                                   # the outcome stays in memory until the next save

    def _replay(self, rec: dict) -> tuple[int, dict]:
        result = dict(rec.get("result") or {})
        result["replayed"] = True
        if rec.get("status") == "refused":
            return int(result.get("http_status") or 409), result
        if rec.get("status") in ("accepted", "interrupted") and not rec.get("result"):
            result.update({"status": rec["status"], "job": self.job_view_locked()})
        return (202 if rec.get("status") == "accepted" else 200), result

    # ---- checks common to every operation --------------------------------------------------
    def _lab_locked(self) -> None:
        svc = self.svc
        if not any(t["target_id"] == "T1" for t in svc._diagnosis_targets_locked()):
            raise OpError(404, "診断ループは登録済みのローカル検証ラボでのみ使用できます", "not_a_lab")
        if self._closed:
            raise OpError(503, "サーバーを停止しています", "closing")

    def _stop_locked(self) -> None:
        try:
            self.svc._refuse_after_stop_locked()
        except ValueError as e:
            raise OpError(409, str(e), "emergency_stopped") from None
        if self.svc.gateway.state.name == "PAUSED":
            raise OpError(409, "一時停止中です。再開してから操作してください", "paused")

    def _no_manual_item_locked(self) -> None:
        if any(r["item"].status == "running" for r in self.svc._artex_items.values()) \
                or self.svc._exec_owner is not None:
            raise OpError(409, "ARTEX 計画の項目を実行中です。終わってから開始してください", "item_running")

    def _authority(self, request_authorized) -> None:
        if request_authorized is not None and not request_authorized():
            raise OpError(403, "権限が失効しています。もう一度ログインしてください", "authority_revoked")

    def _state_locked(self, *, required: bool):
        st = self.svc._diagnosis
        if st is None or st.frozen:
            if required:
                raise OpError(409, "診断ループを開始してから操作してください", "not_started")
            return None
        return st

    # ---- the operations ----------------------------------------------------------------
    def run(self, op: str, *, key: str, actor: str, roles, body: dict, request_authorized=None,
            approver_authorized=None) -> tuple[int, dict]:
        """The single entry point the server calls. Returns (HTTP status, body)."""
        handler = {"start": self._start, "owner-spec": self._owner_spec, "fix-check": self._fix_check,
                   "approve": self._approve}.get(op)
        if handler is None:
            return 404, {"error": "not found"}
        try:
            return handler(key=key, actor=actor, roles=tuple(roles or ()), body=body,
                           request_authorized=request_authorized, approver_authorized=approver_authorized)
        except OpError as e:
            return e.status, {"error": e.message, "reason": e.reason}

    def _refuse_request(self, rec: dict, e: OpError) -> tuple[int, dict]:
        with self.svc._lock:
            self._finish_request_locked(rec, "refused", {"error": e.message, "reason": e.reason,
                                                         "http_status": e.status})
            # a refused request does not hold its scope: the operation may be asked again
            if rec.get("scope") and self._scopes.get(rec["scope"]) in self._requests \
                    and self._requests[self._scopes[rec["scope"]]] is rec:
                self._scopes.pop(rec["scope"], None)
                try:
                    self._save_locked()
                except OSError:
                    pass
        return e.status, {"error": e.message, "reason": e.reason}

    def _new_job_locked(self, kind: str, actor: str, roles, request_authorized) -> dict:
        """Under the service lock: the job takes the ARTEX execution right here, in the
        same critical section as the check that no manual item is running."""
        st = self.svc._diagnosis
        job = {"id": "dj_" + secrets.token_hex(8), "kind": kind, "state": "running", "requested_by": actor,
               "diag_id": st.diag_id if st is not None and not st.frozen else None,
               "generation": st.generation if st is not None and not st.frozen else None,
               "run_generation": self.svc._run_generation, "waiting_item_id": None, "needs_spec": [],
               "result": None, "started_at": time.time()}
        self._job = job
        self.svc._exec_owner = job["id"]
        self._live[job["id"]] = {"roles": tuple(roles), "authorized": request_authorized,
                                 "event": None, "grant": None, "nonce": None, "approval": None}
        return job

    def _job_changed_locked(self) -> None:
        try:
            self._save_locked()
        except OSError:
            pass
        self.svc._publish_diagnosis_locked()

    def _end_job(self, job: dict, state: str, result: dict) -> None:
        with self.svc._lock:
            if self._closed:
                self._live.pop(job["id"], None)
                return        # recorded as interrupted by close()
            job.update(state=state, waiting_item_id=None, result=result)
            self._live.pop(job["id"], None)
            self._release_locked(job["id"])
            for rec in self._requests.values():
                if rec.get("job_id") == job["id"] and rec.get("status") == "accepted":
                    rec["status"] = "done"
                    rec["result"] = {"job": self.job_view_locked()}
                    if state == "failed" and rec.get("scope"):
                        # nothing was measured in this generation: the operation may be asked again
                        self._scopes.pop(rec["scope"], None)
            self._job_changed_locked()

    # start ------------------------------------------------------------------------------
    def _start(self, *, key, actor, roles, body, request_authorized, approver_authorized):
        if not permitted("diagnosis:request", roles):
            raise OpError(403, "診断の開始には実行担当者の権限（diagnosis:request）が必要です", "permission_denied")
        if body:
            raise OpError(400, "開始の要求に指定できる項目はありません", "unexpected_fields")
        svc = self.svc
        with svc._lock:
            self._lab_locked()
            rec, replay = self._accept("start", key, actor, {}, None)
            if replay:
                return self._replay(rec)
            try:
                self._stop_locked()
                self._authority(request_authorized)
                if self.active_locked():
                    raise OpError(409, "この評価の診断ループはすでに進行中です", "loop_active")
                self._no_manual_item_locked()
                if svc._diagnosis_refused:
                    raise OpError(409, "診断の記録が監査ログと一致しないため、新しい診断を始められません",
                                  "history_refused")
            except OpError as e:
                return self._refuse_request(rec, e)
            job = self._new_job_locked("start", actor, roles, request_authorized)
            rec["job_id"] = job["id"]
            self._job_changed_locked()
        try:
            state = svc.diagnosis_state()
            with svc._lock:
                job["diag_id"], job["generation"] = state.diag_id, state.generation
            if not state.observations(generation=state.generation):
                observe_lab_root(svc, state, request_authorized=request_authorized)
        except Exception as e:  # noqa: BLE001 - nothing started: say why
            self._end_job(job, "failed", {"reason": "initial_observation_failed", "detail": str(e)[:200]})
            return 409, {"error": str(e)[:200], "reason": "initial_observation_failed",
                         "job": self._job_public()}
        return self._continue(job, state)

    def _job_public(self) -> dict | None:
        with self.svc._lock:
            return self.job_view_locked()

    def _missing_specs(self, state) -> list[str]:
        """Targets whose hypotheses need the owner's statement and do not have one in
        the current generation (the fixed judge would answer needs_spec)."""
        from .diagnosis_judge import propose_hypotheses
        propose_hypotheses(state)
        gen = state.generation
        spec_targets = {o["target_ref"] for o in state.observations(generation=gen) if o["source"] == "owner_spec"}
        need = {h["target_ref"] for h in state.hypotheses()
                if h["generation"] == gen and h["claim"] in ("other_account_read", "unauthenticated_exposure")
                and h["state"] in ("open", "inconclusive", "needs_spec")}
        return sorted(need - spec_targets)

    def _continue(self, job: dict, state) -> tuple[int, dict]:
        """After the initial observation: wait for the owner's specification, or run."""
        try:
            missing = self._missing_specs(state)
        except Exception as e:  # noqa: BLE001
            self._end_job(job, "failed", {"reason": "hypotheses_failed", "detail": type(e).__name__})
            return 409, {"error": "仮説を作成できませんでした", "reason": "hypotheses_failed"}
        with self.svc._lock:
            live = self._live.get(job["id"])
            if live is None or live.get("spawned") or job.get("state") not in ("running", "awaiting_spec"):
                # another request already moved this job on (or it ended): never a second runner
                return 202, {"job": self.job_view_locked()}
            if missing:
                job.update(state="awaiting_spec", needs_spec=missing, spec_since=time.time())
                self._job_changed_locked()
                return 202, {"job": self.job_view_locked()}
            live["spawned"] = True                     # claimed under the lock: one runner per job
            job.update(state="running", needs_spec=[])
            self._job_changed_locked()
        self._spawn(job, state)
        return 202, {"job": self._job_public()}

    def _spawn(self, job: dict, state) -> None:
        t = threading.Thread(target=self._run_loop, args=(job, state), name=f"diagnosis-{job['id']}", daemon=True)
        with self.svc._lock:
            live = self._live.get(job["id"])
            if live is not None:
                live["thread"] = t
        t.start()

    def _run_loop(self, job: dict, state) -> None:
        from .adaptive_plan_runner import AdaptivePlanRunner
        with self.svc._lock:
            live = self._live.get(job["id"]) or {}
        try:
            runner = AdaptivePlanRunner(self.svc, actor=job["requested_by"], roles=live.get("roles") or ("operator",),
                                        request_authorized=live.get("authorized"),
                                        approve=lambda item: self._wait_for_approval(job, item),
                                        diagnosis=state, exec_owner=job["id"])
            plan = runner.run()
            self._end_job(job, "finished", {"plan_state": plan.state.value, "reason": plan.reason})
        except Exception as e:  # noqa: BLE001 - the job never stays "running"
            self._end_job(job, "failed", {"reason": "loop_failed", "detail": type(e).__name__})

    # L2 approval ---------------------------------------------------------------------------
    def _wait_for_approval(self, job: dict, item: dict):
        """The runner asks for one L2 step: wait for a person with diagnosis:approve_l2
        (never the requester) to approve THIS item. Nothing is inherited: every step
        gets a new nonce and a new decision. A stop, a reset, a timeout or a revoked
        approver means no approval."""
        svc = self.svc
        ev = threading.Event()
        with svc._lock:
            live = self._live.get(job["id"])
            if live is None or self._closed:
                return None
            nonce = "an_" + secrets.token_hex(8)
            live.update(event=ev, grant=None, nonce=nonce)
            job.update(state="waiting_approval", waiting_item_id=item["id"])
            self._job_changed_locked()
        deadline = time.monotonic() + approval_timeout()
        stopped = False
        while time.monotonic() < deadline:
            ev.wait(min(1.0, max(0.0, deadline - time.monotonic())))
            with svc._lock:
                if self._closed or svc.gateway.state.name in ("STOPPED", "PAUSED") \
                        or svc._run_generation != job["run_generation"]:
                    stopped = True
                    break
                g = live.get("grant")
                if g is not None and g[0] == nonce:   # only an approval of THIS step ends the wait
                    break
        with svc._lock:
            # taken and cleared under the lock, for THIS nonce only: an approval that arrived
            # (audited) just as the wait ended still counts, unless the run was stopped
            grant = live.get("grant")
            granted = grant[1:] if grant is not None and grant[0] == nonce and not stopped else None
            live.update(event=None, grant=None, nonce=None)
            if job.get("state") == "waiting_approval":
                job.update(state="running", waiting_item_id=None)
                self._job_changed_locked()
        if granted is None:
            return None
        approver, roles, authorized = granted
        if authorized is not None and not authorized():
            return None                              # the approver's authority lapsed meanwhile
        with svc._lock:
            st = svc._diagnosis
            approval = {"nonce": nonce, "item_id": item["id"], "approver": approver,
                        "diag_id": st.diag_id if st is not None else None,
                        "generation": st.generation if st is not None else None,
                        "run_generation": job["run_generation"], "expires": time.time() + approval_valid()}
            live["approval"] = approval
        return approver, roles, self._step_authority(job, live, approval, authorized)

    def _step_authority(self, job: dict, live: dict, approval: dict, approver_authorized):
        """The authority for ONE approved L2 Worker. Checked when execute_artex_item starts
        and again by the Gateway's last hook before the Worker process starts
        (AssessmentService._late_launch_guard), with both people's grants held (`lease`):
        the requester's session and membership, the approver's session, membership and
        approver role, requester != approver, and this approval itself - its nonce, its
        item, the diagnosis and generation, the run, and its expiry."""
        svc = self.svc
        requester = live.get("authorized")

        def allowed() -> bool:
            with svc._lock:
                st = svc._diagnosis
                if (self._closed or live.get("approval") is not approval
                        or approval["approver"] == job["requested_by"]
                        or st is None or st.diag_id != approval["diag_id"] or st.generation != approval["generation"]
                        or svc._run_generation != approval["run_generation"]
                        or svc.gateway.state.name in ("STOPPED", "PAUSED")
                        or svc._exec_owner != job["id"]
                        or approval["item_id"] not in svc._artex_items
                        or time.time() > approval["expires"]):
                    return False
            if requester is not None and not requester():
                return False
            return approver_authorized is None or bool(approver_authorized())

        @contextlib.contextmanager
        def lease():
            with contextlib.ExitStack() as stack:
                # both grants held while the Worker starts: a logout or a removal waits for it
                for who in (requester, approver_authorized):
                    hold = getattr(who, "lease", None)
                    if callable(hold):
                        stack.enter_context(hold())
                if not allowed():
                    raise PolicyError("承認者または依頼者の権限、あるいは承認そのものが失効したため、Worker を起動しません")
                yield

        allowed.lease = lease
        return allowed

    def _approve(self, *, key, actor, roles, body, request_authorized, approver_authorized):
        if not permitted("diagnosis:approve_l2", roles):
            raise OpError(403, "L2 の承認には承認者の権限（diagnosis:approve_l2）が必要です", "permission_denied")
        item_id = body.get("item_id") if isinstance(body, dict) else None
        if set(body) - {"item_id"} or not isinstance(item_id, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,80}", item_id):
            raise OpError(400, "item_id が必要です", "item_id_required")
        svc = self.svc
        with svc._lock:
            self._lab_locked()
            job = self._job
            live = self._live.get(job["id"]) if job else None
            nonce = (live or {}).get("nonce")
            scope = f"approve:{item_id}:{nonce}" if nonce else None
            rec, replay = self._accept("approve", key, actor, {"item_id": item_id}, scope)
            if replay:
                return self._replay(rec)
            try:
                self._stop_locked()
                self._authority(approver_authorized)
                if job is None or job.get("state") != "waiting_approval" or job.get("waiting_item_id") != item_id \
                        or live is None or not nonce:
                    raise OpError(409, "この項目は承認を待っていません", "not_waiting")
                if actor == job["requested_by"]:
                    svc.audit.record("diagnosis.approval_denied", item=item_id, actor=actor,
                                     reason="separation of duties")
                    raise OpError(403, "診断を依頼した本人は、その L2 検査を承認できません", "self_approval")
            except OpError as e:
                return self._refuse_request(rec, e)
            try:
                svc._diagnosis_journal("diagnosis.l2_approved", {
                    "item": item_id, "approver": actor, "approval": nonce, "job": job["id"]})
            except Exception:  # noqa: BLE001 - not audited: not approved
                return self._refuse_request(rec, OpError(503, "監査ログに記録できないため、承認しませんでした",
                                                          "audit_failed"))
            live["grant"] = (nonce, actor, tuple(roles), approver_authorized)
            rec["job_id"] = job["id"]
            self._finish_request_locked(rec, "done", {"approved": item_id, "job": self.job_view_locked()})
            if live.get("event") is not None:
                live["event"].set()
            return 200, {"approved": item_id, "job": self.job_view_locked()}

    # the owner's specification ------------------------------------------------------------
    def _owner_spec(self, *, key, actor, roles, body, request_authorized, approver_authorized):
        if not permitted("asset:specify", roles):
            raise OpError(403, "仕様の入力には対象資産の管理者の権限（asset:specify）が必要です", "permission_denied")
        target, req = body.get("target_ref"), body.get("requirement")
        if set(body) - {"target_ref", "requirement"} or req not in SPECS \
                or not isinstance(target, str) or not re.fullmatch(r"T[0-9]{1,3}", target):
            raise OpError(400, "target_ref と requirement（authentication_required または public）が必要です",
                          "invalid_spec")
        svc = self.svc
        with svc._lock:
            self._lab_locked()
            st = self._state_locked(required=False)
            scope = f"owner_spec:{st.diag_id}:{st.generation}:{target}:{req}" if st is not None else None
            rec, replay = self._accept("owner-spec", key, actor, {"target_ref": target, "requirement": req}, scope)
            if replay:
                return self._replay(rec)
            try:
                self._stop_locked()
                self._authority(request_authorized)
                st = self._state_locked(required=True)
                if target not in {t["target_id"] for t in svc._diagnosis_targets_locked()}:
                    raise OpError(409, "この対象は、現在の登録済み対象にありません", "unknown_target")
                job = self._job
                if job is not None and job.get("state") in ("running", "waiting_approval"):
                    raise OpError(409, "診断ループの実行中は仕様を変更できません", "loop_running")
                prev = [o for o in st.observations(target_ref=target, generation=st.generation)
                        if o["source"] == "owner_spec"]
                if prev and prev[-1]["attrs"].get("requirement") == req:
                    unchanged = prev[-1]["evidence_id"]
                else:
                    unchanged = None
                    if prev:
                        old = {o["evidence_id"] for o in prev}
                        judged = [h["id"] for h in st.hypotheses()
                                  if h["generation"] == st.generation and h["target_ref"] == target
                                  and old & set(h["supporting"] + h["contradicting"] + h["inconclusive"])]
                        if judged:
                            # a verdict already rests on the earlier statement: changing it now would
                            # rewrite what was decided. The new statement starts a new generation.
                            raise OpError(409, "この仕様に基づく判定がすでにあります。変更は、修正後の確認"
                                               "（新しい世代）で入力してください", "needs_new_generation")
            except OpError as e:
                return self._refuse_request(rec, e)
        if unchanged is None:
            try:
                eid = record_owner_spec(st, target, req, actor=actor)     # audited before it applies
            except Exception:  # noqa: BLE001 - the audit write failed: nothing changed
                return self._refuse_request(rec, OpError(503, "監査ログに記録できないため、仕様を変更しませんでした",
                                                          "audit_failed"))
        else:
            eid = unchanged
        with svc._lock:
            job = self._job
            resume = (job is not None and job.get("state") == "awaiting_spec"
                      and job.get("diag_id") == st.diag_id and job.get("generation") == st.generation)
            if resume:
                job["state"] = "running"        # claimed: a concurrent statement does not resume it too
            self._finish_request_locked(rec, "done", {"evidence_id": eid, "unchanged": unchanged is not None,
                                                      "job": self.job_view_locked()})
        if resume:
            self._resume_after_spec(job, st)
        return 200, {"evidence_id": eid, "unchanged": unchanged is not None, "job": self._job_public()}

    def _resume_after_spec(self, job: dict, state) -> None:
        svc = self.svc
        with svc._lock:
            live = self._live.get(job["id"])
            authorized = (live or {}).get("authorized")
            if live is None or job.get("state") != "running" or live.get("spawned"):
                return
            stale = (svc._run_generation != job["run_generation"] or svc._diagnosis is not state
                     or svc.gateway.state.name in ("STOPPED", "PAUSED"))
        if stale:
            self._end_job(job, "failed", {"reason": "stopped_or_reset"})
            return
        if authorized is not None and not authorized():
            self._end_job(job, "failed", {"reason": "requester_authority_revoked"})
            return
        self._continue(job, state)

    # the after-fix re-check -----------------------------------------------------------------
    def _fix_check(self, *, key, actor, roles, body, request_authorized, approver_authorized):
        if not permitted("diagnosis:request", roles):
            raise OpError(403, "修正後の確認の開始には実行担当者の権限（diagnosis:request）が必要です",
                          "permission_denied")
        specs = body.get("owner_specs", {})
        if set(body) - {"owner_specs"} or not isinstance(specs, dict) or not all(
                isinstance(k, str) and re.fullmatch(r"T[0-9]{1,3}", k) and v in SPECS for k, v in specs.items()):
            raise OpError(400, "owner_specs は {対象: authentication_required | public} で指定してください",
                          "invalid_spec")
        if specs and not permitted("asset:specify", roles):
            raise OpError(403, "仕様の入力には対象資産の管理者の権限（asset:specify）が必要です", "permission_denied")
        svc = self.svc
        from .evidence import evidence_status
        with svc._lock:
            self._lab_locked()
            st = self._state_locked(required=False)
            scope = f"fix_check:{st.diag_id}:{st.generation}" if st is not None else None
            rec, replay = self._accept("fix-check", key, actor, {"owner_specs": specs}, scope)
            if replay:
                return self._replay(rec)
            try:
                self._stop_locked()
                self._authority(request_authorized)
                st = self._state_locked(required=True)
                if self.active_locked():
                    raise OpError(409, "この評価の診断ループはすでに進行中です", "loop_active")
                self._no_manual_item_locked()
                confirmed = {h["supersedes"] for h in st.hypotheses() if h["purpose"] == "confirm_fix"}
                supported = [h for h in st.finding_candidates() if h["id"] not in confirmed]
                proven = [fid for fid, f in svc.a.findings.items() if evidence_status(f) == "proven"]
                if not supported or not proven:
                    raise OpError(409, "修正前に実証された所見がないため、修正後の確認は開始できません",
                                  "no_proven_finding")
            except OpError as e:
                return self._refuse_request(rec, e)
            job = self._new_job_locked("fix_check", actor, roles, request_authorized)
            rec["job_id"] = job["id"]
            self._job_changed_locked()
        try:
            begin_fix_check(svc, st, specs, request_authorized=request_authorized, actor=actor)
        except Exception as e:  # noqa: BLE001 - nothing measured: the earlier generation stays usable
            self._end_job(job, "failed", {"reason": "initial_observation_failed", "detail": str(e)[:200]})
            return 409, {"error": str(e)[:200], "reason": "initial_observation_failed", "job": self._job_public()}
        with svc._lock:
            job["generation"] = st.generation
        return self._continue(job, st)


__all__ = ["DiagnosisOperations", "OP_PERMISSION", "OpError", "PERMISSIONS", "SPECS", "member_permissions", "permissions_of",
           "permitted"]
