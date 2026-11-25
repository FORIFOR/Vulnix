"""Per-organization approval and delivery of locally provisioned defence checks."""

from contextlib import contextmanager
from copy import deepcopy
import secrets
import threading
import time
from pathlib import Path

from .authz import AuthzError
from .local_defense import PROFILE, _canonical, reviewed_plan, run
from .local_defense_node import node_plan, reviewed_manifest
from .policy import PolicyError
from .runtime import RuntimeLimitError
from .workers.local_defense import sha256


ACTION_PREFIX = "local_defense:"
APPROVAL_TTL = 600
ACTIVE_RUNS = threading.BoundedSemaphore(2)


class LocalDefenseControl:
    def __init__(self, service, *, python_root: Path | None, node_bundle: Path | None, portable=None):
        self.service = service
        self.profiles = {}
        self.job = None
        self.portable = portable or {}
        for profile in self.portable.values():
            self._register(profile.bundle, profile.plan(), profile.manifest()["files"])
        if python_root:
            self._register(python_root, reviewed_plan(), PROFILE["files"])
        if node_bundle:
            files = reviewed_manifest(node_bundle)
            # This auxiliary case and transformer are supplied by the reviewed bundle.
            folder_files = {k: v for k, v in files.items()
                            if k not in {"src/lib/auth-controls-acceptance.test.ts", "vitest.config.mts"}}
            self._register(node_bundle, node_plan(node_bundle), folder_files)

    def _register(self, root, plan, files):
        self.profiles[plan["id"]] = (root, plan, files)

    def _enabled(self):
        svc = self.service
        return (svc.gateway.state.value == "running" and svc.a.state not in ("paused", "stopped")
                and not svc._persist_error and not svc.system_status()["unstopped_workers"])

    def view(self):
        svc = self.service
        with svc._lock:
            job = self.job
            public = None
            if job is not None:
                public = {k: job[k] for k in ("id", "profile", "requester", "status", "receipt")}
                approval = svc.a.approvals.get(job["id"])
                public["approval"] = deepcopy(approval)
                if job["status"] == "waiting" and (not approval or approval["status"] == "rejected"
                        or time.monotonic() >= job["deadline"] or job["generation"] != svc._run_generation):
                    public["status"] = "expired"
            return {"profiles": [{"plan": plan, "files": files, "plan_sha256": sha256(_canonical(plan))}
                                 for _, plan, files in self.profiles.values()],
                    "job": public, "available": self._enabled(), "assessment": svc.a.id}

    def request(self, profile, plan_sha256, folder_sha256, actor, authority):
        if not isinstance(profile, str) or profile not in self.profiles:
            raise ValueError("対応するローカル検証はありません")
        _, plan, files = self.profiles[profile]
        if plan_sha256 != sha256(_canonical(plan)) or folder_sha256 != sha256(_canonical(files)):
            raise ValueError("対象フォルダがレビュー済みスナップショットと一致しません")
        svc = self.service
        with authority.lease(), svc._lock:
            if not self._enabled():
                raise ValueError("停止中か、前の検証の回収を確認できません")
            if self.job is not None:
                old = self.job
                approval = svc.a.approvals.get(old["id"], {})
                active = old["status"] in ("running", "cancelling") or (
                    old["status"] == "waiting" and old["generation"] == svc._run_generation
                    and approval.get("status") != "rejected" and time.monotonic() < old["deadline"])
                if active:
                    raise ValueError("既存の検証依頼を完了または中断してください")
                if approval.get("approval_ref"):
                    svc.approval_store.revoke(approval["approval_ref"])
                if old["id"] in svc.a.approvals:
                    del svc.a.approvals[old["id"]]
            aid = "req_" + secrets.token_hex(16)
            action = ACTION_PREFIX + plan_sha256
            svc._audit_first("local_defense.requested", request=aid, actor=actor, plan_sha256=plan_sha256,
                             folder_sha256=folder_sha256, profile=profile)
            svc.a.approvals[aid] = {"id": aid, "action": action, "risk_level": "L2",
                                    "title": "レビュー済みローカル防御検証",
                                    "description": f"{plan['test']} ／ 計画 SHA-256 {plan_sha256}",
                                    "status": "pending", "decided_by": None, "decided_at": None,
                                    "approval_ref": None, "local_requester": actor}
            self.job = {"id": aid, "profile": profile, "requester": actor, "authority": authority,
                        "approver_authority": None, "status": "waiting", "receipt": None,
                        "plan_sha256": plan_sha256, "folder_sha256": folder_sha256,
                        "deadline": time.monotonic() + APPROVAL_TTL, "generation": svc._run_generation,
                        "cancel": threading.Event(), "session": None}
            svc._publish_approval(aid)

    def _waiting(self, aid):
        job = self.job
        if (not job or aid != job["id"] or job["status"] != "waiting" or not self._enabled()
                or job["generation"] != self.service._run_generation or time.monotonic() >= job["deadline"]):
            raise ValueError("実行依頼が失効しました")
        return job

    def decide(self, aid, decision, actor, approver_class, authority):
        svc = self.service
        with authority.lease(), svc._lock:
            job = self._waiting(aid)
            svc.decide_approval(aid, decision, actor, approver_class=approver_class, local=True)
            if decision == "approve":
                job["approver_authority"] = authority

    def start(self, aid, folder_sha256, actor, authority):
        svc = self.service
        # Bind the start to a live session belonging to the original requester.
        with authority.lease(), svc._lock:
            job = self._waiting(aid)
            record = svc.a.approvals[aid]
            if folder_sha256 != job["folder_sha256"]:
                raise ValueError("実行対象が承認したフォルダと一致しません")
            if actor != job["requester"] or record["status"] != "approved" or not job["approver_authority"]:
                raise ValueError("依頼者と独立した承認責任者の承認が必要です")
            with job["authority"].lease(), job["approver_authority"].lease():
                self._launch(aid, job, record, actor, authority)

    def _launch(self, aid, job, record, actor, authority):
        svc = self.service
        approval = record["approval_ref"]
        svc.approval_store.check(approval, "eng_demo", "lab", record["action"])
        if not ACTIVE_RUNS.acquire(blocking=False):
            raise ValueError("隔離実行が上限に達しました。承認の期限内に再試行してください")
        try:
            svc._audit_first("local_defense.started", request=aid, actor=actor, approval=approval,
                             approver=record["decided_by"], action=record["action"])
            job["run_id"] = secrets.token_hex(16)
            job["status"] = "running"
            thread = threading.Thread(target=self._execute, args=(job, svc.workers, authority, approval),
                                      name="local-defense", daemon=True)
            thread.start()
        except BaseException:
            ACTIVE_RUNS.release()
            if job["status"] == "running":
                job["status"] = "failed"
                svc.approval_store.revoke(approval)
            raise

    def cancel(self, aid, actor, approver):
        svc = self.service
        with svc._lock:
            job = self.job
            if not job or aid != job["id"] or (actor != job["requester"] and not approver):
                raise ValueError("中断できる実行がありません")
            if job["status"] not in ("waiting", "running", "cancelling"):
                return
            approval = svc.a.approvals.get(aid, {})
            if approval.get("approval_ref"):
                svc.approval_store.revoke(approval["approval_ref"])
            was_waiting = job["status"] == "waiting"
            job["status"] = "cancelled" if was_waiting else "cancelling"
            job["cancel"].set()
            session = job["session"]
            audit_error = svc._audit_reduction("local_defense.cancelled", request=aid, actor=actor)
            if was_waiting and approval.get("status") == "pending":
                audit_error = svc._decide(aid, "reject", actor) or audit_error
        if session is not None:
            session.kill()
        if audit_error:
            raise audit_error

    def _execute(self, job, pool, starter, approval):
        svc = self.service
        done = threading.Event()
        requester, approver = job["authority"], job["approver_authority"]

        def permit():
            if (job["cancel"].is_set() or job["generation"] != svc._run_generation
                    or svc.gateway.state.value != "running" or svc.a.state in ("paused", "stopped")
                    or time.monotonic() >= job["deadline"]):
                raise RuntimeLimitError("local defence authority ended")

        @contextmanager
        def lease():
            with requester.lease(), starter.lease(), approver.lease():
                permit()
                yield

        @contextmanager
        def hold(session):
            with svc._lock:
                permit()
                job["session"] = session
                session.on_leftover = svc._note_leftover_session
                pool.hold(session)
            try:
                yield
            finally:
                pool.release(session)
                with svc._lock:
                    job["session"] = None

        def watch():
            while not done.wait(0.2):
                try:
                    with lease():
                        pass
                except (PolicyError, RuntimeLimitError, PermissionError, RuntimeError, ValueError):
                    job["cancel"].set()
                    session = job["session"]
                    if session is not None:
                        session.kill()
                    return

        root, plan, _ = self.profiles[job["profile"]]
        monitor = threading.Thread(target=watch, name="local-defense-authority", daemon=True)
        report = None
        try:
            monitor.start()
            with lease():
                pass
            report = run(root, plan, portable=self.portable.get(job["profile"]),
                         pool=pool, hold_session=hold, permit=permit, prelaunch=lease)
        except (PolicyError, RuntimeLimitError, PermissionError, RuntimeError, ValueError, OSError):
            pass
        finally:
            done.set()
            try:
                with lease(), svc._lock:
                    permit()
                    record = svc.a.approvals.get(job["id"], {})
                    svc.approval_store.check(approval, "eng_demo", "lab", record["action"])
                    if report is not None:
                        if (report.get("plan_sha256") != job["plan_sha256"]
                                or report.get("plan") != plan):
                            raise ValueError("observed plan differs from the approval")
                        receipt = {"run_id": job["run_id"], "request": job["id"], "approval": approval,
                                   "approved_by": record["decided_by"], "requester": job["requester"],
                                   "assessment": svc.a.id, "folder_sha256": job["folder_sha256"],
                                   "result": report}
                        digest = sha256(_canonical(receipt))
                        svc._audit_first("local_defense.finished", request=job["id"], run=job["run_id"],
                                         approval=approval, receipt_sha256=digest,
                                         verdict=report["verdict"], status=report["execution_status"])
                        job["receipt"] = {**receipt, "receipt_sha256": digest}
                        job["status"] = report["execution_status"]
                    else:
                        job["status"] = "failed"
            except (AuthzError, PolicyError, RuntimeLimitError, PermissionError, RuntimeError, ValueError, OSError, KeyError):
                with svc._lock:
                    job["status"] = "cancelled" if (job["cancel"].is_set()
                                                    or job["generation"] != svc._run_generation
                                                    or svc.a.state in ("paused", "stopped")) else "failed"
            finally:
                ACTIVE_RUNS.release()
                with svc._lock:
                    svc.approval_store.revoke(approval)
                    job["authority"] = None
                    job["approver_authority"] = None
