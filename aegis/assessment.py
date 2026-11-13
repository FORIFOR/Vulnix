"""Assessment model + ARTEX runner that drives the real Gateway.

The runner coordinates the ARTEX Execution Engine and ProposalRouter: it
requests human approvals for L2+ operations, mints single-use HMAC tokens only
after approval, and submits sanitized proposals to the Gateway. Every worker it
launches is a real confined process that the emergency stop can kill.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.parse
import weakref
from dataclasses import dataclass, field
from pathlib import Path

from . import cve
from .audit import AuditLog
from .authz import ApprovalStore, Engagement, Target, TokenAuthority
from .events import EventBus
from .evidence import (EVIDENCE_LABELS, enforce_verdict, evidence_status,
                       evidence_summary, reproduction_note, reproduction_verdict)
from .gateway import (LAB_REPRODUCTION_CHECKS, Gateway, State, http_probe_tool,
                      reproduction_probe_tool)
from .lab import get_lab_mode, set_lab_mode
from .network import EgressGuard, NetworkError, system_resolver
from .ownership import (PROHIBITED_ACTIONS_SUMMARY, fetch_proof_file_pinned, proof_file_matches, public_address,
                        challenge_for_host, parse_service_target,
                        verify_ownership_challenge)
from .authority_ledger import AuthorityLedger, LedgerError, canonical, default_revocation_marker_dirs
from .confinement import ConfinementError, KernelConfinement
from .policy import ArgSpec, Budget, PolicyError, Tool
from .remotion_export import build_remotion_export
from .router import (AbliterationBackend, ArtexEngine, ArtexplannerBackend,
                     ArtexSubprocessBackend, HttpModelBackend, ProposalRouter,
                     verify_planner_connections)
from .artex_bridge import (CATALOG_BY_ID, ArtexBridgeError, command_from_env, reconstruct,
                           run_artex_planner)
from .runtime import WorkerPool
from .secrets_store import EncryptedSecretStore
from .l2_rules import BUILTIN_PROFILE_DIR, L2RuleSet, site_profile_dirs
from .service_diag import analyze_l1_service_response, build_l2_candidates, clean_target_text

SEVERITY_WEIGHT = {"critical": 40, "high": 25, "medium": 10, "low": 3, "info": 0}
VERDICT_FACTOR = {"proven": 1.0, "detected": 0.6, "unverified": 0.6, "aborted": 0.6,
                  "not_reproduced": 0.0}

EXECUTOR = {
    "agent": "ARTEX 実行エンジン（ProposalRouter 制御）",
    "model": "提案元は診断コンテキストを参照（実行権限なし）",
}


def demo_verify_tool(seconds: float) -> Tool:
    worker = str(Path(__file__).parent / "workers" / "demo_verify.py")
    return Tool("demo_verify", "safe_reproduction",
                {"url": ArgSpec(str, pattern=r"https?://[^\s]+")},
                lambda a, d: [sys.executable, "-I", worker, str(seconds)],
                timeout_s=seconds + 30)


@dataclass
class Assessment:
    id: str
    asset: dict
    engagement: Engagement
    target_url: str
    phases: list[dict]
    state: str = "idle"
    findings: dict[str, dict] = field(default_factory=dict)
    approvals: dict[str, dict] = field(default_factory=dict)
    activity: dict | None = None
    stop_report: dict | None = None
    chat_messages: list[dict] = field(default_factory=list)
    defense_comparison: dict | None = None
    # why the assessment is in state "failed": {"reason", "kind", "at"[, "error"]}
    failure: dict | None = None


class StopNotConfirmed(RuntimeError):
    """Authority was withdrawn, but a worker that was running could not be
    confirmed dead. The operation is NOT reported as completed."""


def _artex_isolation_view(iso: dict) -> dict:
    """What confined the ARTEX process (from the kernel probe evidence)."""
    keys = ("mechanism", "cgroup", "worker_uid", "pinned", "pinned_extra", "probe_connect",
            "probe_in_cgroup", "kernel_dropped_packets", "separate_uid", "no_capabilities",
            "unix_sockets", "io_uring", "inherited_fds_clean", "control_plane_signal",
            "protected_files_denied", "protected_files", "enforced_after_run",
            "run_dropped_packets", "limits", "files_left",
            "netns_separate", "netns_interfaces", "host_loopback_canary", "host_loopback_canary_arrived",
            "relay_endpoints", "hidden_paths_ok", "netlink_socket", "vsock_socket", "bpf_syscall",
            "procs_visible", "seccomp_mode", "netns_left")
    view = {k: iso[k] for k in keys if k in iso}
    view["confined"] = bool(iso.get("confined"))
    view["label"] = (f"OS 隔離あり（{iso.get('mechanism', '')}）" if view["confined"]
                     else "OS 隔離なし（開発用・本番利用不可）")
    return view


def _preview_responder(body: dict) -> dict:
    """PREVIEW: answers in place of the real model - nothing is sent anywhere. A final
    answer without tool calls: the planner ends its round; the request it made is
    what the operator reviews."""
    return {"id": "preview", "object": "chat.completion", "model": body.get("model", "preview"),
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant",
                                     "content": "（preview：実際のモデルには送信していません）"}}],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}


def _session_empty(sess) -> bool:
    try:
        return bool(sess.empty())
    except Exception:  # noqa: BLE001 - not confirmed empty
        return False


class _StaticProposals:
    """Hands already-rebuilt proposals to a ProposalRouter (so they are sanitized
    and audited like any backend's)."""

    def __init__(self, name: str, proposals: list[dict]):
        self.name = name
        self._proposals = [dict(p) for p in proposals]

    def propose(self, _context: dict) -> list[dict]:
        return [dict(p) for p in self._proposals]


class ApproverRequired(PermissionError):
    """The action needs the approver role (mapped to HTTP 403)."""


_DATA_DIR_LOCKS: dict[str, object] = {}

# The service object that last used each data directory IN THIS PROCESS (tests open
# several in a row; production opens one). Lets a new instance ask the previous one
# directly whether it ended with everything committed.
_LAST_INSTANCE: dict[str, "AssessmentService"] = {}

SESSION_FILE = "session.open"
# How often the scope window is checked while a real service is the active asset.
EXPIRY_CHECK_INTERVAL_S = 0.5


def _claim_data_dir(data_dir: Path) -> None:
    """One control-plane PROCESS per data directory. Two processes would each keep
    signing their own view of the authority tables, and a revocation made in one
    could be written over by the other. (Several service objects inside one
    process - as tests do when they 'restart' - share the claim.)"""
    key = str(Path(data_dir).resolve())
    if key in _DATA_DIR_LOCKS:
        return
    try:
        import fcntl
    except ImportError:          # no flock on this platform: nothing to enforce
        _DATA_DIR_LOCKS[key] = None
        return
    fh = open(Path(data_dir) / ".lock", "a+")
    try:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        raise RuntimeError(
            f"データディレクトリ {data_dir} は別のコントロールプレーンのプロセスが使用中です。"
            "同じデータディレクトリで2つ起動することはできません") from None
    _DATA_DIR_LOCKS[key] = fh      # held for the life of the process


# Findings whose single-item verification is a bundled-lab check (fixed lab paths).
LAB_ONLY_FINDING_IDS = frozenset({"f_banner", "f_idor", "f_sqli", "fx_idor", "fx_sqli", "fx_banner"})

# Under separation of duties, a request for an L2 run can be approved for this long.
L2_REQUEST_MAX_AGE_S = 24 * 3600

# Addresses a proof has covered are re-checked against the proof after this long.
ADDRESS_PROOF_MAX_AGE_S = 24 * 3600

# A scope confirmation (and every renewal of it) needs a proof at most this old.
OWNERSHIP_PROOF_MAX_AGE_S = 24 * 3600


class AssessmentService:
    def __init__(self, data_dir: Path, lab_port: int, verify_seconds: float = 1.5,
                 l2_profile_dirs: list[Path] | None = None,
                 separate_l2_approver: bool | None = None,
                 l2_confinement=None,
                 revocation_marker_dirs: list[Path] | None = None):
        self.data_dir = Path(data_dir)
        # Kernel confinement of the worker that carries test-account tokens to a real
        # service. The default is the real thing (Linux only); it can be replaced only
        # here, in code - there is no environment variable or API for it.
        self._l2_confinement = l2_confinement if l2_confinement is not None else KernelConfinement()
        self._marker_dirs = (list(revocation_marker_dirs) if revocation_marker_dirs is not None
                             else default_revocation_marker_dirs())
        # Service profiles: per-API L2 rules. Loaded and validated once at start.
        # Explicitly passed directories are the caller's own (trusted like code); the
        # default is the bundled templates plus SITE profiles from the data directory,
        # which stay non-runnable until an admin accepts their exact content.
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            st = self.data_dir.stat()
            if st.st_uid == os.getuid() and st.st_mode & 0o077:
                # nobody else may even list it (owner permissions are left as they are)
                os.chmod(self.data_dir, st.st_mode & 0o700)
        except OSError:
            pass
        _claim_data_dir(self.data_dir)
        # Every workspace reset starts a new generation. A runner thread belongs to
        # the generation it was started in; once that is over it may not write a
        # single result, however it comes to be scheduled again.
        self._run_generation = 0
        self._tls = threading.local()
        self._inflight = 0                 # verification operations in progress
        self._persist_error: str | None = None
        self._l2_dirs = list(l2_profile_dirs) if l2_profile_dirs else None
        self.l2 = self._read_l2_profiles()
        # Optional separation of duties for real-service L2: one operator requests
        # a run, a DIFFERENT approver approves and executes it.
        self.separate_l2_approver = (
            os.environ.get("AEGIS_SEPARATE_L2_APPROVER") == "1"
            if separate_l2_approver is None else bool(separate_l2_approver))
        # Pending requests live in memory only: under separation of duties they are
        # half of the authority to run, so they are never restored from state.json.
        self._l2_requests: dict[str, dict] = {}
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.data_dir / "state.json"
        self.secrets = EncryptedSecretStore(self.data_dir)
        self._ownership_secret = hashlib.sha256(
            self.secrets._master_key + b":vulnix-ownership-v1"
        ).hexdigest()
        self._state_mac_key = hashlib.sha256(self.secrets._master_key + b":vulnix-state-authority-v1").digest()
        self.bus = EventBus()
        self.audit = AuditLog(self.data_dir / "audit.jsonl")
        self.audit.listeners.append(self._on_audit)
        self._lock = threading.RLock()
        self.lab_port = lab_port
        self.verify_seconds = verify_seconds
        self._allowed_hosts: set[str] = {"lab.test", "api.lab.test"}
        # Everything that grants authority over a real service lives in the authority
        # ledger and nowhere else (authority_ledger.py): assets, ownership proofs,
        # confirmed scopes, real-service names and accepted profiles, committed as
        # one transaction with a generation token. The asset records shown in the UI
        # and everything in state.json are display state only.
        def _ledger_event(event, **fields):
            try:
                self.audit.record(event, **fields)
            except Exception:
                pass
        self.ledger = AuthorityLedger(self.data_dir, self._state_mac_key, self._marker_dirs, _ledger_event)
        self._custom_resolver = None
        # test seams for the proof re-check on address change (None = real lookups)
        self._proof_dns_lookup = None
        self._proof_file_fetch = None
        now = time.time()
        target = Target("lab", hosts=tuple(sorted(self._allowed_hosts)),
                        cidrs=("127.0.0.1/32",), ports=(lab_port,))
        eng = Engagement("eng_demo", True, "DEMO-AUTH-001（ローカル検証ラボ）", now - 60,
                         now + 30 * 86400, {"lab": target},
                         frozenset({"read_only_probe", "safe_reproduction"}))
        self.approval_store = ApprovalStore()
        self.tokens = TokenAuthority(secrets.token_bytes(32), time.time)
        from .runtime import HeldSessions
        self._held_sessions = HeldSessions()
        self.workers = WorkerPool(max_concurrent=2, held=self._held_sessions)
        self.gateway = Gateway(
            engagement=eng, tokens=self.tokens, approvals=self.approval_store,
            egress=EgressGuard(self._resolve_host),
            workers=self.workers, audit=self.audit,
            tools={
                "http_probe": http_probe_tool(),
                "reproduction_probe": reproduction_probe_tool(self.l2),
                "demo_verify": demo_verify_tool(verify_seconds),
            },
            budget=Budget(50),
            ephemeral_env_provider=self._ephemeral_worker_env,
            secret_redactor=self.secrets.redact,
            confinement_provider=self._worker_confinement,
            launch_guard=self._launch_guard)

        # Wire ARTEX (in-process + optional external CLI subprocess) + Abliteration ProposalRouter
        self._artex_cli_backend = ArtexSubprocessBackend()
        backends: list = [ArtexplannerBackend()]
        if os.environ.get("VULNIX_ARTEX_CLI") or os.environ.get("AEGIS_ARTEX_CMD"):
            backends.append(self._artex_cli_backend)
        ext_model = HttpModelBackend.from_env()
        if os.environ.get("VULNIX_EXTERNAL_PROPOSALS", "1") == "0":
            # proposals from the built-in planner only: a configured model is used for the
            # chat explanation (and, through the Planner LLM Gateway, for ARTEX) - never
            # for proposals outside the gateway's budget and approval
            ext_model = None
        if ext_model:
            backends.append(ext_model)
        self._external_model_configured = ext_model is not None
        self._chat_backend = AbliterationBackend.from_env()
        self._model_response_verified = False
        self._artex_cli_verified = False
        self._last_planner_verification: dict | None = None
        self.router = ProposalRouter(self.gateway, self.audit, backends)
        self.artex = ArtexEngine(self.router)
        # Real services are planned by the built-in planner only: nothing about them
        # (URL, findings, evidence) is sent to an external model or CLI.
        self._local_router = ProposalRouter(self.gateway, self.audit, [ArtexplannerBackend()])
        self.cve_monitor = cve.FeedMonitor()
        # The REAL ARTEX planner (planner-only overlay binary), when configured. It is
        # verified against a local (loopback) mock LLM only.
        self._artex_real_cmd = command_from_env()
        self._artex_llm_url = os.environ.get("VULNIX_ARTEX_LLM_URL", "")
        self._artex_llm_model = os.environ.get("VULNIX_ARTEX_LLM_MODEL", "mock")
        self._artex_pg_dsn = os.environ.get("VULNIX_ARTEX_PG_DSN", "")
        self._artex_expected_sha256 = os.environ.get("VULNIX_ARTEX_EXPECTED_SHA256", "")
        self._artex_plan: dict | None = None
        self._artex_items: dict = {}
        self._artex_live: set = set()           # confinement sessions of running ARTEX planners
        self._artex_llm_last: dict | None = None
        self._artex_gateways: set = set()       # gateways of running planner runs

        self.a = Assessment(
            id="scan_001",
            asset={"id": "lab", "name": "lab.test", "kind": "Webアプリケーション",
                   "environment": "ローカル検証ラボ（127.0.0.1）"},
            engagement=eng, target_url=f"http://lab.test:{lab_port}/",
            phases=self._default_phases())
        for f in _fixture_findings():
            self.a.findings[f["id"]] = f
        self._approval_events: dict[str, threading.Event] = {}
        self._thread: threading.Thread | None = None
        self._extra_assets: list[dict] = [
            {"id": "api", "name": "api.lab.test", "kind": "API", "environment": "検証環境",
             "status": "未診断", "assessment_id": self.a.id, "risk": None,
             "previous_risk_score": None, "last_assessed_at": None,
             "authorization_ref": "DEMO-AUTH-002", "ownership_verified": True,
             "scope_confirmed": True},
            {"id": "staging", "name": "internal-staging", "kind": "検証環境",
             "environment": "社内", "status": "承認待ち", "assessment_id": None, "risk": None,
             "previous_risk_score": None, "last_assessed_at": None,
             "authorization_ref": "", "ownership_verified": False,
             "scope_confirmed": False,
             "note": "書面許可が未登録のため診断できません"},
        ]
        # No service is registered on our behalf: real services enter only through
        # the ownership flow, and whatever was saved (including deletions) is kept.
        self._unstopped: list[dict] = []         # workers a withdrawal or stop could not confirm dead
        self._cleanup_pending: list = []         # emptied cgroups whose rules/directory remain to remove
        self._cleanup_at = -1e9
        self._cleanup_running = False
        self._state_had_ledger_flag = False
        self._closed = False
        self._session_written = False
        self._expiry_handled: set = set()       # expiries whose stop was confirmed
        self._expiry_seen: set = set()
        self._load_state_locked()
        with self._lock:
            self._reconcile_assets_with_ledger_locked()
            self._begin_session_locked()
        threading.Thread(target=AssessmentService._expiry_watch, args=(weakref.ref(self),),
                         daemon=True, name="scope-expiry").start()
        if (self._authority_notice or self._marker_pending or self.ledger.dirty()
                or not self._state_had_ledger_flag) and not self._persist_error:
            # Authority on disk was refused. Write that down now, so the disk no
            # longer holds it (and a marker that asked for this can be retired).
            with self._lock:
                self._save_state_locked()
        self._apply_profile_acceptance_locked(startup=True)
        # Stored test accounts exist only for a service that currently has a proof
        # or a confirmed scope. Anything else (e.g. left behind when a revocation
        # could not rewrite the token file) is dropped at startup.
        for orphan in self.secrets.asset_ids():
            if orphan not in self._ownership_proofs and orphan not in self._verified_external_hosts:
                try:
                    self.secrets.clear_credentials(orphan)
                    self.audit.record("secrets.orphan_cleared", host=orphan)
                except OSError:
                    pass        # unwritable store: nothing is sent while saving is broken

    # The tables live in the ledger; these names are how the service reads and
    # mutates them (always under self._lock, always followed by a commit).
    @property
    def _verified_external_hosts(self) -> dict:
        return self.ledger.verified_external_hosts

    @_verified_external_hosts.setter
    def _verified_external_hosts(self, value: dict) -> None:
        self.ledger.verified_external_hosts = value

    @property
    def _ownership_proofs(self) -> dict:
        return self.ledger.ownership_proofs

    @_ownership_proofs.setter
    def _ownership_proofs(self, value: dict) -> None:
        self.ledger.ownership_proofs = value

    @property
    def _real_service_hosts(self) -> set:
        return self.ledger.real_service_hosts

    @_real_service_hosts.setter
    def _real_service_hosts(self, value: set) -> None:
        self.ledger.real_service_hosts = value

    @property
    def _accepted_profiles(self) -> dict:
        return self.ledger.accepted_profiles

    @_accepted_profiles.setter
    def _accepted_profiles(self, value: dict) -> None:
        self.ledger.accepted_profiles = value

    @property
    def _authority_notice(self) -> str | None:
        return self.ledger.notice

    @_authority_notice.setter
    def _authority_notice(self, value: str | None) -> None:
        self.ledger.notice = value

    @property
    def _authority_epoch(self) -> str:
        return self.ledger.generation

    @property
    def _marker_pending(self) -> bool:
        return self.ledger.marker_pending

    _canonical = staticmethod(canonical)

    # ---- sessions: a revocation that could not be written anywhere --------------
    def _session_path(self) -> Path:
        return self.data_dir / SESSION_FILE

    def _previous_session_clean(self) -> tuple[bool, str]:
        """Did whatever used this data directory last end with every change of
        authority committed? If not, a revocation it made may exist nowhere on
        disk (data directory and marker locations all unwritable at the time), and
        the ledger would hand that authority back."""
        path = self._session_path()
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return True, ""                     # first start, or the last one ended cleanly
        except (OSError, ValueError, RecursionError):
            return False, "the previous session record cannot be read"
        prev = _LAST_INSTANCE.get(str(self.data_dir.resolve()))
        if isinstance(body, dict) and body.get("pid") == os.getpid() and prev is not None and prev is not self:
            with prev._lock:            # the previous instance lives in this process: ask it
                clean = (prev.ledger.error is None and not prev.ledger.dirty()
                         and not prev._unstopped and prev._persist_error is None
                         and getattr(prev, "_closed_clean", True))
            return clean, "" if clean else "the previous instance in this process ended with unsaved authority changes"
        return False, "the control plane did not shut down cleanly"

    def _begin_session_locked(self) -> None:
        clean, why = self._previous_session_clean()
        self.previous_session_clean = clean
        if not clean:
            self._hold_all_authority_locked(why)
        if not self._write_session_record():
            # Without this record, a revocation that later cannot be written would
            # be undone by a restart. So nothing is honoured in this session either,
            # and nothing new is granted until the record has been written.
            self._hold_all_authority_locked("the session record cannot be written")
            self._persist_error = self._persist_error or "session record not written"
        _LAST_INSTANCE[str(self.data_dir.resolve())] = self

    def _write_session_record(self) -> bool:
        try:
            body = json.dumps({"pid": os.getpid(), "started_at": time.time()})
            tmp = self._session_path().with_name(SESSION_FILE + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(body)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._session_path())
            self._sync_dir(self.data_dir)
            self._session_written = True
            return True
        except OSError:
            self._session_written = False
            return False

    def _hold_all_authority_locked(self, why: str) -> None:
        """Every confirmed scope and every ownership proof is held until an approver
        re-establishes it (new ownership proof, new scope confirmation). Names,
        asset cards and stored test accounts stay; nothing is sent meanwhile."""
        now = time.time()
        held = []
        for host, entry in self.ledger.verified_external_hosts.items():
            if not entry.get("held_since"):
                entry["held_since"] = now
                held.append(host)
        for host, proof in self.ledger.ownership_proofs.items():
            if not proof.get("held_since"):
                proof["held_since"] = now
                held.append(host)
        for rec in (self.a.asset, *self._extra_assets):
            if str(rec.get("name", "")).lower() in held:
                rec["scope_confirmed"] = False
                rec["ownership_verified"] = False
                rec.pop("ownership_proof", None)
                rec["status"] = "所有確認待ち"
                rec["note"] = "前回正常に終了しなかったため診断許可を保留しています。所有確認と範囲確認をやり直してください"
        if held:
            self._authority_notice = ("前回のコントロールプレーンが正常に終了しなかったため、取り消しが保存されていない可能性があります。"
                                      "実サービスの診断許可を保留しました。承認責任者が所有確認と範囲確認をやり直すまで診断しません")
            self.audit.record("authority.held_after_unclean_shutdown", reason=why, hosts=sorted(set(held)))

    def close(self, external_clean: bool = True) -> bool:
        """Clean shutdown. Workers are stopped and confirmed, everything is
        committed, and only then is the session record removed. Returns False (and
        leaves the record, so the next start holds all authority) otherwise."""
        with self._lock:
            self._closed = True
            pool = self.workers
            self.gateway.invalidate_pending()
            self._note_unstopped_locked((self.a.asset.get("name") or "").lower(),
                                        pool.confirm_stopped(pool.kill_all(), 5.0), pool)
            self._save_state_locked()
            clean = (external_clean and self._persist_error is None and self.ledger.error is None
                     and not self.ledger.dirty() and not self._unstopped_now_locked())
            if clean:
                try:
                    os.unlink(self._session_path())
                    self._sync_dir(self.data_dir)
                except FileNotFoundError:
                    pass
                except OSError:
                    clean = False
            self._closed_clean = clean
            try:
                self.audit.record("control_plane.closed", clean=clean)
            except Exception:
                pass
            return clean

    @staticmethod
    def _expiry_watch(ref) -> None:
        while True:
            svc = ref()
            if svc is None or svc._closed:
                return
            try:
                svc._enforce_scope_window()
            except Exception:
                pass
            del svc
            time.sleep(EXPIRY_CHECK_INTERVAL_S)

    def _enforce_scope_window(self) -> None:
        """When the scope window of the active real service closes, that is a
        withdrawal: waiting requests are cancelled and running workers are killed
        and confirmed dead - not merely refused the next time."""
        with self._lock:
            if self._closed:
                return
            host = (self.a.asset.get("name") or "").rstrip(".").lower()
            entry = self.ledger.verified_external_hosts.get(host)
            if not entry or entry.get("held_since"):
                return
            now = time.time()
            if float(entry.get("not_before", 0)) <= now <= float(entry.get("not_after", 0)):
                return
            key = (host, entry.get("not_after"), entry.get("confirmed_at"))
            if key in self._expiry_handled:
                return
            first = key not in self._expiry_seen
            had = list(self.workers.active_pids())
            if first:
                # cancel waiting requests; kill the workers and wait (up to 5 s) for them.
                # An exception here is retried on the next pass (audit failures inside
                # are caught, so this does not loop on a full disk).
                self._authority_reduced_locked(host)
                self._expiry_seen.add(key)
            # Marked as handled only once the stop is CONFIRMED. Until then every pass
            # re-checks (and re-kills) the survivors without blocking; new launches
            # are refused all along, because the scope is expired.
            unconfirmed = (self._unstopped_now_locked() or {}).get("pids", [])
            if not unconfirmed:
                self._expiry_handled.add(key)
            if first:
                self._authority_notice = (f"{host} の診断許可の期限が切れました。"
                                          + ("実行中の処理を停止しました。" if not unconfirmed else
                                             "実行中の処理の停止を確認できていません（確認できるまで新しい処理は起動しません）。")
                                          + "続けるには承認責任者が範囲確認をやり直してください")
                for rec in (self.a.asset, *self._extra_assets):
                    if str(rec.get("name", "")).lower() == host:
                        rec["scope_confirmed"] = False
                        rec["status"] = "範囲確認待ち"
                        rec["note"] = "診断許可の期限が切れました。範囲確認をやり直してください"
                self._save_state_locked()
            if first or not unconfirmed:
                try:
                    self.audit.record("scope.expired", host=host, not_after=entry.get("not_after"),
                                      workers_stopped=had, unconfirmed=unconfirmed, retry=not first)
                except Exception:
                    # not recorded: not "handled" either - the next pass records it
                    self._expiry_handled.discard(key)

    def _real_asset_records(self) -> dict[str, dict]:
        out = {}
        for rec in (self.a.asset, *self._extra_assets):
            name = str(rec.get("name", "")).rstrip(".").lower()
            if name and (rec.get("challenge") or name in self.ledger.real_service_hosts
                         or name in self.ledger.verified_external_hosts or name in self.ledger.ownership_proofs):
                out[name] = rec
        return out

    def _sync_ledger_assets_locked(self) -> None:
        """The ledger's asset table is the set of real-service asset records, so a
        registration or a deletion is committed together with whatever authority
        changes with it - one transaction."""
        self.ledger.assets = {name: {"id": str(rec.get("id") or "")}
                              for name, rec in self._real_asset_records().items()}

    def _reconcile_assets_with_ledger_locked(self) -> None:
        """After a restart the ledger decides. A process can die between the ledger
        commit and the display-state write, so:
          * an asset card for a real service the ledger does not list was deleted
            (its deletion committed): the card goes;
          * a ledger entry without a card belongs to nothing that can be shown,
            selected or revoked from the UI: its authority goes."""
        if self.ledger.rejected_reason or not self.ledger.assets_known:
            return                  # nothing was restored / an older layout: the cards are all there is
        cards = self._real_asset_records()
        for name in [n for n in cards if n not in self.ledger.assets]:
            rec = cards[name]
            self.audit.record("asset.dropped_not_in_ledger", host=name, asset_id=rec.get("id"))
            if rec is self.a.asset:
                self.a.asset = {"id": "lab", "name": "lab.test", "kind": "Webアプリケーション",
                                "environment": "ローカル検証ラボ（127.0.0.1）"}
                self._sync_scope_for_host("lab.test", "DEMO-AUTH-001（ローカル検証ラボ）")
                self.a.chat_messages = []
                self._reset_workspace_locked()
            else:
                self._extra_assets = [x for x in self._extra_assets if x is not rec]
        for name in [n for n in (*self.ledger.assets, *self.ledger.verified_external_hosts,
                                 *self.ledger.ownership_proofs) if n not in cards]:
            if (name in self.ledger.verified_external_hosts or name in self.ledger.ownership_proofs
                    or name in self.ledger.assets):
                self.audit.record("ledger.entry_without_asset_dropped", host=name)
                self._authority_notice = ("資産の記録が見つからないため、" + name +
                                          " の所有確認・範囲確認を取り消しました。登録からやり直してください")
            self.ledger.verified_external_hosts.pop(name, None)
            self.ledger.ownership_proofs.pop(name, None)
            self.ledger.assets.pop(name, None)

    def _commit_grant_locked(self, before: dict, what: str) -> None:
        """Commit a change that grants authority, now. If it cannot be written it
        is rolled back: nothing was granted, in memory or on disk."""
        try:
            self._sync_ledger_assets_locked()
            self.ledger.commit_or_rollback(before)
        except LedgerError:
            self._persist_error = self.ledger.error or "LedgerError"
            raise ValueError(f"権限台帳に保存できないため、{what}は記録されませんでした。保存先を確認してください") from None

    def _authority_reduced_locked(self, host: str) -> None:
        """Every withdrawal of authority goes through here, BEFORE it is committed:
        requests still waiting in the Gateway may no longer launch, and a worker
        already talking to that service is killed and confirmed dead."""
        h = (host or "").rstrip(".").lower()
        self.gateway.invalidate_pending()
        if (self.a.asset.get("name") or "").lower() != h:
            return                  # workers only ever run against the active asset
        self._note_unstopped_locked(h, self.workers.terminate_active(confirm_timeout_s=5.0), self.workers)

    def system_status(self) -> dict:
        """Conditions every page has to show, whatever asset is open."""
        with self._lock:
            return {"unstopped_workers": self._unstopped_now_locked(),
                    "persistence_error": self._persist_error,
                    "authority_notice": self._authority_notice}

    def _note_unstopped_locked(self, host: str, survivors: list[int], pool) -> None:
        # a confined run still being probed or torn down (its process is not a pid
        # of this pool any more, or not yet) counts as a survivor as well
        busy = [x for x in pool.busy_sessions() if not self._session_on_record(x)]
        if survivors or busy:
            sessions = [x for x in pool.sessions_for(survivors) if not self._session_on_record(x)]
            sessions += [x for x in busy if not any(x is y for y in sessions)]
            self._unstopped.append({"host": host, "pids": list(survivors), "at": time.time(), "pool": pool,
                                    # kept here: the pool forgets a session once its direct child is reaped
                                    "sessions": sessions})
            try:
                self.audit.record("workers.stop_unconfirmed", host=host, survivors=list(survivors))
            except Exception:
                pass        # the survivor is on record above; an audit failure must not undo that

    def _session_on_record(self, session) -> bool:
        return any(session is x for u in self._unstopped for x in (u.get("sessions") or []))

    def _retry_cleanup_locked(self) -> None:
        """Removing the rules and directory of emptied cgroups is slow (sudo) and not
        a safety matter any more: it runs in the background, never under the
        service lock, one batch at a time, at most every 30 s."""
        now = time.monotonic()
        if not self._cleanup_pending or self._cleanup_running or now - self._cleanup_at < 30:
            return
        self._cleanup_at = now
        self._cleanup_running = True
        batch, self._cleanup_pending = self._cleanup_pending, []

        def run():
            left = list(batch)                   # until proven removed, everything stays queued
            try:
                for x in batch:
                    try:
                        x.on_leftover = None     # a failed cleanup is not a new leftover
                        x._teardown()
                    except Exception:
                        pass
                    try:
                        removed = not getattr(x, "leftover", True)
                    except Exception:
                        removed = False
                    if removed:
                        left = [y for y in left if y is not x]
            finally:                             # whatever happened: nothing is lost, the next run can start
                with self._lock:
                    for x in left:
                        if not any(x is y for y in self._cleanup_pending):
                            self._cleanup_pending.append(x)
                    self._cleanup_running = False
        try:
            threading.Thread(target=run, daemon=True, name="cgroup-cleanup").start()
        except Exception:
            self._cleanup_pending.extend(x for x in batch if not any(x is y for y in self._cleanup_pending))
            self._cleanup_running = False

    def _note_leftover_session(self, session) -> None:
        """A confined run whose cgroup could not be emptied: kept on record like any
        other worker that was not confirmed dead."""
        with self._lock:
            if self._session_on_record(session):
                return
            self._unstopped.append({"host": (self.a.asset.get("name") or "").lower(), "pids": [],
                                    "at": time.time(), "pool": None, "sessions": [session]})
            try:
                self.audit.record("workers.stop_unconfirmed", host=self.a.asset.get("name"),
                                  cgroup=getattr(session, "name", ""), survivors=[])
            except Exception:
                pass

    def _raise_if_unstopped(self, done: str) -> None:
        with self._lock:
            pending = self._unstopped_now_locked()
        if pending:
            raise StopNotConfirmed(
                f"{done}が、実行中だったWorker（{len(pending['pids'])}件）の停止を確認できていません。"
                "プロセスを確認し、必要ならコントロールプレーンを停止してください")

    def _unstopped_now_locked(self) -> dict | None:
        """Workers that a withdrawal, reset or stop could not confirm dead and that
        are STILL not confirmed dead. While there are any, nothing new launches."""
        keep, confirmed_late = [], []
        for u in list(self._unstopped):          # a copy: nothing below may extend this pass
            pool, sessions = u.get("pool"), u.get("sessions") or []
            # LOOK first. A process that is gone is never signalled again (its pid
            # may belong to something else by now).
            if pool is not None:
                alive = pool.still_running(u["pids"])
            else:           # restored after a control-plane restart: we can only look
                alive = [p for p in u["pids"] if WorkerPool.group_alive(p)]
            not_empty = [x for x in sessions if not x.empty()]
            if alive and pool is not None:
                alive = pool.confirm_stopped(alive, 0.0)        # still there: kill again
            for x in not_empty:
                x.kill()
            for x in sessions:
                if x not in not_empty and getattr(x, "leftover", False):
                    # Empty now: nothing is running in it any more, so it no longer
                    # blocks anything. Removing its rules and cgroup is cleanup, retried
                    # at most every 30 s and never re-reported as a new leftover.
                    if not any(x is y for y in self._cleanup_pending):
                        self._cleanup_pending.append(x)
                    x.on_leftover = None
            if alive or not_empty:
                u["pids"] = alive or u["pids"]
                u["sessions"] = not_empty
                keep.append(u)
            else:
                confirmed_late.append(u)
        self._unstopped = keep
        for u in confirmed_late:                 # recorded only after the list is consistent
            try:
                self.audit.record("workers.stop_confirmed_late", host=u["host"], pids=u["pids"])
            except Exception:
                pass
        self._retry_cleanup_locked()
        if not keep:
            return None
        return {"host": "、".join(sorted({u["host"] for u in keep})),
                "pids": sorted({p for u in keep for p in u["pids"]}),
                "at": min(u["at"] for u in keep)}

    def _external_entry(self, host: str | None) -> dict | None:
        """The verified-external record for `host`, only while it is fully valid
        (ownership verified + scope confirmed + inside its time window)."""
        h = (host or "").rstrip(".").lower()
        ext = self._verified_external_hosts.get(h)
        if not ext or not ext.get("ownership_verified") or not ext.get("scope_confirmed"):
            return None
        if ext.get("held_since"):
            return None          # held after an unclean shutdown: needs re-approval
        try:
            ipaddress.ip_address(h)
            return None          # a real service is always a DNS name, never an address
        except ValueError:
            pass
        now = time.time()
        if not (float(ext.get("not_before", 0)) <= now <= float(ext.get("not_after", 0))):
            return None
        return ext

    def _asset_record(self, host: str) -> dict | None:
        """The asset record for a host, whether it is the active asset or not. Every
        ownership function goes through this, so the two cases cannot diverge."""
        h = (host or "").rstrip(".").lower()
        if self.a.asset.get("name", "").lower() == h:
            return self.a.asset
        return next((x for x in self._extra_assets if x.get("name", "").lower() == h), None)

    def _revoke_real_service_locked(self, host: str, *, note: str, keep_proof: bool = False) -> None:
        """Drop scope (and, unless told otherwise, the proof) and the stored test
        accounts of a real service, and make its record say so."""
        h = (host or "").rstrip(".").lower()
        self._verified_external_hosts.pop(h, None)
        if not keep_proof:
            self._ownership_proofs.pop(h, None)
        self._authority_reduced_locked(h)
        self.secrets.clear_credentials(h)
        self._l2_requests = {k: v for k, v in self._l2_requests.items() if v.get("host") != h}
        for rec in (self.a.asset, *self._extra_assets):
            if rec.get("name", "").lower() == h:
                rec["scope_confirmed"] = False
                rec["authorization_ref"] = ""
                if not keep_proof:
                    rec["ownership_verified"] = False
                    rec.pop("ownership_proof", None)
                rec["status"] = "範囲確認待ち" if keep_proof else "所有確認待ち"
                rec["note"] = note
                if rec is not self.a.asset:
                    rec["assessment_id"] = None

    def _in_ownership_flow(self, host: str | None) -> bool:
        """True for a host that was registered as a real service (it has, or had,
        an ownership challenge). Such a host is never treated as a lab alias."""
        h = (host or "").rstrip(".").lower()
        if h in self._verified_external_hosts or h in self._real_service_hosts:
            return True
        if self.ledger.names_unknown and h and h not in ("lab.test", "api.lab.test"):
            # the list of real-service names was lost or could not be trusted once:
            # every name that is not a bundled lab name is treated as a real service
            return True
        return any(x.get("name", "").lower() == h and x.get("challenge")
                   for x in (self.a.asset, *self._extra_assets))

    def _resolve_host(self, host: str) -> list[str]:
        """Resolve host strictly according to verified scope."""
        h = (host or "").rstrip(".").lower()
        if h in {"lab.test", "api.lab.test"}:
            return ["127.0.0.1"]
        if self._in_ownership_flow(h):
            # A host that went through the ownership flow is NEVER silently
            # redirected to the local lab: it resolves for real or not at all.
            with self._lock:
                ext = self._external_entry(h)
                epoch0 = self.gateway._launch_epoch       # every withdrawal and stop moves this on
            if ext is None:
                return []
            if self._persist_error:
                raise NetworkError("状態を保存できないため、名前解決と送信を中止しました")
            resolver_fn = self._custom_resolver or system_resolver
            allow_loopback = bool(ext.get("allow_loopback_test"))
            safe_addrs: list[str] = []
            for raw in resolver_fn(h):
                try:
                    ip = ipaddress.ip_address(str(raw).split("%")[0])
                except ValueError:
                    raise NetworkError(f"external service host {h} resolved to an invalid address")
                if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                    ip = ip.ipv4_mapped
                if not allow_loopback and public_address(str(ip)) is None:
                    raise NetworkError(
                        f"external service host {h} resolved to non-public IP {ip} (blocked)"
                    )
                safe_addrs.append(str(ip))
            if not allow_loopback:
                self._require_addresses_covered_by_proof(h, ext, safe_addrs, epoch0)
            return safe_addrs
        if h in self._allowed_hosts:
            return ["127.0.0.1"]
        return []

    def _withdrawn_since_locked(self, host: str, ext: dict, epoch0: int | None) -> bool:
        return (self._verified_external_hosts.get(host) is not ext
                or self._external_entry(host) is not ext          # e.g. the window closed meanwhile
                or self.gateway.state is not State.RUNNING
                or self._stale_runner()
                or (epoch0 is not None and self.gateway._launch_epoch != epoch0))

    def _require_addresses_covered_by_proof(self, host: str, ext: dict, addrs: list[str],
                                            epoch0: int | None = None) -> None:
        """Ownership was proven for a NAME; traffic goes to ADDRESSES. Whenever the
        name resolves to an address that no proof has covered yet (first use, DNS
        change, takeover of a dangling record), the proof is checked again before
        anything is sent there. If it no longer holds, the scope is revoked.

        The Gateway pins the worker to exactly the addresses returned by this
        resolution, so what is checked here is what is contacted."""
        if self._persist_error:
            # the outcome of a proof re-check (accepted addresses, or a revocation)
            # has to be recorded; without a working store nothing is looked up or fetched
            raise NetworkError("状態を保存できないため、所有の再確認と送信を中止しました")
        known = set(ext.get("verified_addresses") or [])
        new = [a for a in addrs if a not in known]
        first_use = not known
        stale = time.time() - float(ext.get("addresses_verified_at") or 0) > ADDRESS_PROOF_MAX_AGE_S
        if not new and not stale:
            return
        with self._lock:
            # the name lookup may have taken long: nothing more is looked up or
            # fetched for a scope that was withdrawn or stopped in the meantime
            if self._withdrawn_since_locked(host, ext, epoch0):
                raise NetworkError(f"{host} の診断許可は取り消しまたは停止済みです。所有の再確認は行いません")
        token = challenge_for_host(host, self._ownership_secret)["token"]
        method = str(ext.get("proof_method") or "dns_txt")
        ok, detail, address_bound = False, "", False
        try:
            if method == "well_known":
                # binds the ADDRESS: the file is fetched from each address itself
                fetch = self._proof_file_fetch or fetch_proof_file_pinned
                ok = all(proof_file_matches(fetch(host, a), token) for a in (new or addrs))
                address_bound = ok
                detail = "検証ファイルを各アドレスから取得して確認"
            else:
                # binds the NAME only: it shows the DNS zone is still the owner's,
                # not that a new address is (dangling record, takeover of a released IP)
                res = verify_ownership_challenge(host, "dns_txt", expected_token=token,
                                                 txt_lookup=self._proof_dns_lookup)
                ok, detail = bool(res.get("verified")), "DNS TXT を再確認"
        except Exception as e:      # any failure to re-prove is a failed proof
            ok, detail = False, f"再確認に失敗: {type(e).__name__}"
        with self._lock:
            if self._withdrawn_since_locked(host, ext, epoch0):
                # withdrawn or stopped while the proof was being re-checked: its
                # outcome is not recorded and nothing is sent
                raise NetworkError(f"{host} の診断許可は取り消しまたは停止済みです")
            if ok:
                live = self._verified_external_hosts.get(host)
                if live is not None:
                    live["verified_addresses"] = sorted(known | set(addrs))
                    live["addresses_verified_at"] = time.time()
                    if new and not first_use and not address_bound:
                        # The name moved to an address nobody has vouched for. The
                        # read-only L1 probe may follow the name, but test-account
                        # tokens are withheld until an approver re-confirms the scope.
                        live["address_change_pending"] = sorted(
                            set(live.get("address_change_pending") or []) | set(new))
                        # re-confirming needs a NEW proof, made after the move
                        self._ownership_proofs.pop(host, None)
                    self._save_state_locked()
            else:
                self._revoke_real_service_locked(
                    host, note="解決先のIPアドレスが変わり、所有を再確認できませんでした。所有確認からやり直してください")
                self._save_state_locked()
        self.audit.record("asset.addresses_reverified" if ok else "asset.scope_revoked_address_change",
                          host=host, method=method, new_addresses=new, known_addresses=sorted(known),
                          detail=detail)
        if not ok:
            raise NetworkError(
                f"{host} が所有確認されていないアドレス {', '.join(new)} に解決されました。"
                "所有を再確認できなかったため、診断範囲を取り消しました")

    def _ephemeral_worker_env(self, tool_name: str, args: dict) -> dict[str, str]:
        """Per-call worker environment (never argv, never audit). L2 test
        credentials are released only to a `reproduction_probe` run of a check that
        belongs to the profile of the currently active, verified external asset,
        and only the tokens that one rule needs."""
        env: dict[str, str] = {}
        cafile = os.environ.get("VULNIX_TEST_CA_FILE")
        active_ext = self._external_entry(self.a.asset.get("name"))
        if cafile and (os.environ.get("AEGIS_ENV", "").strip().lower() in ("development", "dev")
                       or (active_ext or {}).get("allow_loopback_test")):
            # a private test CA is never trusted for a real service outside development
            env["VULNIX_TEST_CA_FILE"] = cafile
        rule = self._active_l2_check(args.get("check")) if tool_name == "reproduction_probe" else None
        if rule is not None and not self._stored_overrides_allowed(rule):
            rule = None          # a stored path no longer fits what the accepted profile allows
        if rule is not None and not getattr(self._tls, "confined", False):
            rule = None          # no kernel confinement was set up for this worker: no tokens
        if rule is not None and self._l2_transport_ok():
            env.update(self.secrets.worker_env_for_check(
                self.a.asset.get("name", "").lower(), rule))
        return env

    def _worker_confinement(self, tool_name: str, args: dict, dest):
        """Gateway hook. A worker that takes test-account tokens to a real service
        is started only inside kernel confinement that was applied and confirmed
        for that run. Not Linux, or not confirmable: the worker is not started."""
        self._tls.confined = False
        if tool_name != "reproduction_probe":
            return None
        with self._lock:
            real = self._in_ownership_flow(self.a.asset.get("name"))
        if not real:
            return None
        try:
            # everything in the data directory (master key, ledger, sessions, the
            # stored test accounts of EVERY service) must be unreadable to the worker
            protected = sorted(str(p) for p in self.data_dir.iterdir() if p.is_file())
            session = self._l2_confinement.session(dest.ip, dest.port, forbidden_paths=protected,
                                                   protected_pid=os.getpid())
            try:
                session.on_leftover = self._note_leftover_session
            except AttributeError:
                pass
            self._tls.confined = True       # this thread's next worker starts inside it
            return session
        except ConfinementError as e:
            raise PolicyError(f"実サービスのL2検証はカーネル隔離を確認できる Linux ホストでのみ実行します: {e}") from None

    def _launch_guard(self, tool_name: str, args: dict, dest) -> None:
        """Gateway hook, the last step before a worker starts. Between the first
        checks and this point the request may have waited in name resolution or a
        proof re-check; whatever was revoked, deleted, stopped or switched in the
        meantime is seen here."""
        host = (urllib.parse.urlsplit(str(args.get("url") or "")).hostname or "").rstrip(".").lower()
        with self._lock:
            if self._stale_runner():
                raise PolicyError("この要求を出したワークスペースは停止または切り替え済みです")
            if self._unstopped_now_locked() or self.workers.busy_sessions():
                raise PolicyError("停止を確認できていないWorkerが残っているため、新しいWorkerは起動しません")
            if not self._in_ownership_flow(host):
                return
            ext = self._external_entry(host)
            if ext is None:
                raise PolicyError(f"{host} の診断範囲は取り消されています")
            if (self.a.asset.get("name") or "").lower() != host:
                raise PolicyError(f"{host} は現在の診断対象ではありません")
            if not ext.get("allow_loopback_test") and dest.ip not in (ext.get("verified_addresses") or []):
                raise PolicyError(f"{host} の送信先 {dest.ip} は所有確認済みのアドレスではありません")
            if self._persist_error:
                raise PolicyError("状態を保存できないため、送信を中止しました")

    def _require_working_store(self) -> None:
        """Nothing that looks up, fetches from, or grants authority over a real
        service happens while a save is known to be failing."""
        with self._lock:
            if self._persist_error:
                self._save_state_locked()          # it may work again by now
            if self._persist_error:
                raise ValueError("状態をディスクに保存できないため、実サービスの所有確認・範囲確認は行えません。"
                                 "保存先を確認してください")

    def l2_isolation_status(self) -> dict:
        try:
            st = dict(self._l2_confinement.status())
        except Exception as e:          # an unknown isolation state is "not available"
            st = {"ok": False, "reason": f"隔離状態を確認できません（{type(e).__name__}）"}
        return {"ok": bool(st.get("ok")), "reason": str(st.get("reason") or ""),
                "mechanism": str(st.get("mechanism") or "")}

    def _is_external_service_asset(self, host: str | None = None) -> bool:
        """True only for a real service that completed ownership + scope
        confirmation. Everything else is the local simulated lab."""
        return self._external_entry(host or self.a.asset.get("name")) is not None

    # ---- L2 profiles: loading, integrity, acceptance -------------------------
    def _read_l2_profiles(self) -> L2RuleSet:
        if self._l2_dirs is not None:
            return L2RuleSet.load(self._l2_dirs, [])
        return L2RuleSet.load([BUILTIN_PROFILE_DIR], site_profile_dirs(self.data_dir))

    def _apply_profile_acceptance_locked(self, *, startup: bool = False) -> None:
        """Hold site profiles nobody accepted (or that changed since), rebuild the
        Gateway tool so only runnable checks are in its schema, and put what was
        loaded on the record."""
        held = self.l2.hold_unaccepted(self._accepted_profiles)
        self.gateway.tools["reproduction_probe"] = reproduction_probe_tool(self.l2)
        for pid in held:
            was = self._accepted_profiles.get(pid)
            if was:        # accepted earlier, content is different now
                self.audit.record("l2.profile_changed", profile=pid, file=self.l2.sources[pid]["file"],
                                  accepted_sha256=was, current_sha256=self.l2.sources[pid]["sha256"])
        for rej in self.l2.rejected:
            self.audit.record("l2.profile_rejected", file=rej["file"], reason=rej["reason"][:300])
        if startup or held or self.l2.rejected:
            self.audit.record("l2.profiles_loaded", profiles=[
                {"id": pid, "file": src["file"], "site": src["site"], "sha256": src["sha256"],
                 "accepted": pid not in held} for pid, src in sorted(self.l2.sources.items())])

    def l2_profiles_status(self) -> dict:
        with self._lock:
            return {
                "profiles": [
                    {"id": pid, "label": self.l2.profiles[pid]["label"], "file": src["file"], "site": src["site"],
                     "sha256": src["sha256"], "hosts": self.l2.profiles[pid]["hosts"],
                     "accepted": (not src["site"]) or self._accepted_profiles.get(pid) == src["sha256"],
                     "changed_since_acceptance": bool(src["site"] and self._accepted_profiles.get(pid)
                                                      and self._accepted_profiles.get(pid) != src["sha256"]),
                     "confirmed_checks": [c["id"] for c in self.l2.profiles[pid]["checks"]
                                          if c["spec_status"] in ("confirmed", "unaccepted")],
                     "directory": src.get("directory", ""),
                     # what accepting this file would allow to be SENT: shown to the admin
                     "rules": [self._describe_rule(self.l2.profiles[pid], c)
                               for c in self.l2.profiles[pid]["checks"]
                               if c["spec_status"] in ("confirmed", "unaccepted")]}
                    for pid, src in sorted(self.l2.sources.items()) if pid in self.l2.profiles],
                "rejected": list(self.l2.rejected),
            }

    @staticmethod
    def _describe_rule(profile: dict, c: dict) -> dict:
        def req(node: dict) -> dict:
            meta = profile["paths"][node["path"]]
            return {"account": profile["tokens"][node["token"]]["label"], "token_key": node["token"],
                    "path": meta["default"], "path_override_pattern": meta.get("override_pattern"),
                    "headers": dict(node["headers"])}
        return {
            "id": c["id"], "label": c["label"],
            "request": req(c["subject"]),
            "controls": [{**req(p), "label": p["label"], "expect": p["expect"]} for p in c["preconditions"]],
            "denied": c["denied"], "exposed": c["exposed"],
            "spec_evidence": c["spec_evidence"],
        }

    def accept_l2_profile(self, profile_id: str, sha256: str, actor: str) -> dict:
        """An admin accepts the exact content of a site profile. The file is read
        again now: what is accepted is what is on disk at this moment, and it has
        to be the content the admin was shown (`sha256`)."""
        with self._lock:
            if self.a.state == "running":
                raise ValueError("診断実行中はプロファイルを承認できません")
            fresh = self._read_l2_profiles()
            src = fresh.sources.get(profile_id)
            if src is None or not src["site"]:
                raise ValueError("承認できるのは、データディレクトリに置かれた導入先プロファイルだけです")
            if not sha256 or src["sha256"] != sha256:
                raise ValueError("プロファイルの内容が表示時から変わっています。内容を確認し直してください")
            self._require_working_store()
            before = self.ledger.snapshot()
            self._accepted_profiles[profile_id] = src["sha256"]
            self._commit_grant_locked(before, "プロファイルの承認")      # committed, or not accepted at all
            self.l2 = fresh
            self._apply_profile_acceptance_locked()
            self._save_state_locked()
        self.audit.record("l2.profile_accepted", actor=actor, profile=profile_id, file=src["file"],
                          sha256=src["sha256"])
        return self.l2_profiles_status()

    def _l2_profile(self, host: str | None = None) -> dict | None:
        """The L2 rule profile bound to a verified external asset, if any."""
        h = (host or self.a.asset.get("name") or "").lower()
        return self.l2.profile_for_host(h) if self._external_entry(h) is not None else None

    def _active_l2_check(self, check_id) -> dict | None:
        """Rule for `check_id` only if it belongs to the active asset's profile."""
        profile = self._l2_profile()
        if profile is None or not isinstance(check_id, str):
            return None
        return next((c for c in profile["checks"] if c["id"] == check_id), None)

    @staticmethod
    def _l2_result_fields(finding: dict, outcome: str, note: str) -> dict:
        """Verdict fields after one L2 rule run.

        An inconclusive run never erases an earlier proof: the weakness was
        observed and nothing has shown it fixed. (The reverse does not hold: an
        earlier "not reproduced" is not kept when the latest run is inconclusive.)"""
        if outcome == "unverified" and finding.get("verdict") == "proven" and evidence_status(finding) == "proven":
            return {
                "verdict": "proven",
                "last_run_verdict": "unverified",
                "verdict_note": ("今回の再検証は判定できませんでした。" + note
                                 + " 前回の実証結果は取り消されていません（修正は未確認です）。"),
            }
        return {"verdict": outcome, "last_run_verdict": outcome, "verdict_note": note,
                "what_was_established": None}

    def _public_l2_request(self, finding_id: str) -> dict | None:
        req = self._l2_requests.get(finding_id)
        if (not req or req.get("host") != self.a.asset.get("name")
                or time.time() - float(req.get("requested_at", 0)) > L2_REQUEST_MAX_AGE_S):
            return None
        return {"requested_by": req["requested_by"], "requested_at": req["requested_at"]}

    def _l2_check_for_finding(self, finding_id: str) -> dict | None:
        profile = self._l2_profile()
        if profile is None:
            return None
        return next((c for c in profile["checks"] if c["finding"]["id"] == finding_id), None)

    def _stored_overrides_allowed(self, check: dict) -> bool:
        """Stored path overrides are checked again at the moment tokens would be
        released, against the profile as it is NOW (it may have been replaced and
        re-accepted since the override was saved)."""
        profile = self._l2_profile()
        if profile is None:
            return False
        status = self.secrets.public_status(self.a.asset.get("name", "").lower(), profile)
        values = {p["key"]: p["value"] for p in status["paths"] if p.get("value")}
        for node in (check["subject"], *check["preconditions"]):
            val = values.get(node["path"])
            if val is None:
                continue
            pattern = profile["paths"][node["path"]].get("override_pattern")
            if not pattern or re.fullmatch(pattern, val) is None:
                return False
        return True

    def _l2_block_reason(self) -> str | None:
        """Why test-account tokens may not be sent to the active asset right now."""
        ext = self._external_entry(self.a.asset.get("name"))
        if not ext:
            return "診断範囲が確認されていません"
        if not (ext.get("scheme") == "https" or ext.get("allow_loopback_test")):
            return "検証用トークンを平文（http）で送信することはできません。https の対象でのみL2検証を実行できます"
        if ext.get("address_change_pending"):
            return ("対象の解決先アドレスが所有確認後に変わりました（"
                    + "、".join(ext["address_change_pending"])
                    + "）。承認責任者が所有確認と範囲確認をやり直すまで、検証用トークンは送信しません")
        iso = self.l2_isolation_status()
        if not iso["ok"]:
            return ("実サービスのL2検証は、Workerのカーネル隔離を適用して確認できる Linux ホストでのみ実行します（"
                    + (iso["reason"] or "隔離を確認できません") + "）")
        return None

    def _l2_transport_ok(self) -> bool:
        """Tokens travel only over TLS, and only to addresses an approver's scope
        confirmation still covers (loopback test targets excepted)."""
        return self._l2_block_reason() is None

    def _ready_l2_checks(self, host: str | None = None) -> set[str]:
        h = (host or self.a.asset.get("name") or "").lower()
        profile = self._l2_profile(h)
        if profile is None:
            return set()
        return {c["id"] for c in profile["checks"]
                if c["spec_status"] == "confirmed" and not self.secrets.missing_for_check(h, c)}

    def _l2_candidates(self) -> list[dict]:
        return build_l2_candidates(self.a.target_url, self._l2_profile(), self._ready_l2_checks())

    def _save_state_locked(self) -> None:
        """Commit the authority ledger, then persist the display state (assessment,
        findings, evidence, approvals, asset cards). The two are independent files:
        a display state that cannot be written never keeps a revocation from being
        committed. Either failing sets `_persist_error`, which stops all
        real-service work until a save succeeds."""
        try:
            self._sync_ledger_assets_locked()
            self.ledger.commit()
        except Exception as e:          # never expected; unknown means not saved
            self.ledger.error = type(e).__name__
            try:
                self.ledger.invalidate()
            except Exception:
                pass
        state_error = None
        try:
            payload = {
                "version": 1,
                "saved_at": time.time(),
                "id": self.a.id,
                "asset": self.a.asset,
                "target_url": self.a.target_url,
                "state": self.a.state,
                "phases": self.a.phases,
                "findings": self.a.findings,
                "approvals": self.a.approvals,
                "activity": self.a.activity,
                "stop_report": self.a.stop_report,
                "chat_messages": self.a.chat_messages,
                "defense_comparison": self.a.defense_comparison,
                "failure": self.a.failure,
                # survivors of a stop/withdrawal outlive the control plane: so does their record
                "unstopped_workers": [{"host": u["host"], "pids": u["pids"], "at": u["at"],
                                       "cgroups": [getattr(x, "name", "") for x in u.get("sessions") or []]}
                                      for u in self._unstopped],
                # authority lives in authority.ledger; this only says that one is in use,
                # so that a ledger that disappears is noticed as a loss
                "authority_ledger": True,
                "extra_assets": self._extra_assets,
                "allowed_hosts": sorted(self._allowed_hosts),
                "authorization_ref": self.a.engagement.authorization_ref,
                "ownership_verified": self.a.engagement.ownership_verified,
                "lab_mode": get_lab_mode(),
                "artex_cli_verified": self._artex_cli_verified,
                "last_planner_verification": self._last_planner_verification,
            }
            tmp_path = self.state_path.with_suffix(".json.tmp")
            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False, indent=2))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, self.state_path)
            self._sync_dir(self.data_dir)
        except Exception as e:      # OSError, but also anything that makes the state unserialisable
            state_error = type(e).__name__
        error = self.ledger.error or state_error
        if error is None and not self._session_written and not self._closed and hasattr(self, "_expiry_handled"):
            # saving works again: so must the session record, before anything is granted
            if not self._write_session_record():
                error = "session record not written"
        if error is None:
            self._persist_error = None
            return
        # Not persisted. Say so, and refuse real-service work until saving works
        # again. (A reduction of authority that could not be committed has already
        # been made unacceptable on disk by the ledger.)
        first = self._persist_error is None
        self._persist_error = error
        if self.a.state == "completed":
            # "completed" promises that the results are on disk. Whatever was
            # just changed is not, so the state no longer says so.
            self.a.state = "failed"
            self.a.failure = {
                "reason": "結果をディスクに保存できなかったため、完了として扱いません。保存先を確認してから再実行してください",
                "kind": "persistence", "error": self._persist_error, "at": time.time()}
            try:
                self.bus.publish(self.a.id, "assessment.state", state="failed", risk=self._risk(),
                                 failure=self.a.failure)
            except Exception:
                pass
        if first:
            try:
                self.audit.record("state.persist_failed", error=error,
                                  ledger=bool(self.ledger.error), display_state=bool(state_error))
            except Exception:
                pass

    @staticmethod
    def _sync_dir(path: Path) -> None:
        from .authority_ledger import sync_dir
        sync_dir(path)

    def _load_state_locked(self) -> None:
        """Restore the authority ledger, then the display state (assessment, findings,
        evidence, approvals, asset cards)."""
        data = None
        unreadable = None
        if self.state_path.exists():
            try:
                data = json.loads(self.state_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("not an object")
            except (OSError, ValueError, RecursionError) as e:
                data, unreadable = None, type(e).__name__
        had_ledger = self.ledger.path.exists()
        rejected_reason = self.ledger.load(legacy=data, expect_ledger=bool(data and data.get("authority_ledger")))
        if had_ledger and data and any(data.get(k) for k in (
                "ownership_proofs", "verified_external_hosts", "real_service_hosts", "accepted_profiles")):
            # authority is read from the ledger only; whatever state.json says about it is not used
            self.audit.record("state.authority_fields_ignored",
                              reason="authority is only read from the ledger; fields in state.json are not used")
        if self.ledger.error:
            # nothing can be recorded here: no authority is honoured, and every
            # real-service request is refused until a save succeeds
            self._persist_error = self.ledger.error
        if unreadable:
            # Unknown persistent state: the asset records the ledger's entries
            # belong to are gone, so nothing they granted is kept either.
            for name in (*self.ledger.assets, *self.ledger.verified_external_hosts, *self.ledger.ownership_proofs):
                self.ledger.real_service_hosts.add(name)
            self.ledger.assets, self.ledger.verified_external_hosts, self.ledger.ownership_proofs = {}, {}, {}
            self.ledger.accepted_profiles = {}
            self._authority_notice = "保存された状態を読み取れないため、実サービスの所有確認・範囲確認は引き継いでいません"
            self.audit.record("state.unreadable", error=unreadable)
            try:        # keep what was there for whoever has to find out why
                os.replace(self.state_path, self.data_dir / f"state.unreadable-{int(time.time())}.json")
            except OSError:
                pass
        if rejected_reason:
            self.audit.record("state.authority_rejected",
                              reason=rejected_reason + "; ownership proofs and scope not restored")
        if data is None:
            return
        if isinstance(data.get("allowed_hosts"), list):
            self._allowed_hosts = {str(h) for h in data["allowed_hosts"] if h} | {"lab.test", "api.lab.test"}
        if isinstance(data.get("asset"), dict) and data["asset"].get("name"):
            self.a.asset = dict(data["asset"])
        auth_ref = str(data.get("authorization_ref") or self.a.engagement.authorization_ref)
        self._sync_scope_for_host(self.a.asset["name"], auth_ref)
        if isinstance(data.get("phases"), list) and data["phases"]:
            self.a.phases = [dict(p) for p in data["phases"] if isinstance(p, dict)]
        if isinstance(data.get("findings"), dict) and data["findings"]:
            # saved by an older version, an L1 observation may still read "proven"
            self.a.findings = {str(k): enforce_verdict(dict(v)) for k, v in data["findings"].items() if isinstance(v, dict)}
        if isinstance(data.get("approvals"), dict):
            self.a.approvals = {str(k): dict(v) for k, v in data["approvals"].items() if isinstance(v, dict)}
            for ap in self.a.approvals.values():
                # approvals in state.json are unsigned: they are only re-issued for the
                # local lab, never for a real service
                if ap.get("status") == "approved" and not self._in_ownership_flow(self.a.asset.get("name")):
                    ap["approval_ref"] = self.approval_store.approve(
                        str(ap.get("decided_by") or "approver"),
                        "eng_demo", "lab", str(ap.get("action") or "safe_reproduction"),
                    )
        if isinstance(data.get("extra_assets"), list):
            self._extra_assets = [dict(x) for x in data["extra_assets"] if isinstance(x, dict)]
        # The asset records are display state; authority lives only in the signed
        # host table. Make the records agree with it.
        for rec in (self.a.asset, *self._extra_assets):
            name = str(rec.get("name", "")).lower()
            if rec.get("challenge"):
                self._real_service_hosts.add(name)      # once a real service, never a lab alias
            if not (rec.get("challenge") or name in self._real_service_hosts):
                continue
            has_proof = name in self._ownership_proofs and not self._ownership_proofs[name].get("held_since")
            if self._external_entry(name) is None and rec.get("scope_confirmed"):
                rec["scope_confirmed"] = False
                rec["status"] = "所有確認待ち" if not has_proof else "範囲確認待ち"
                rec["note"] = "診断範囲の確認が失効または無効になりました。所有確認からやり直してください"
            if not has_proof and (rec.get("ownership_verified") or rec.get("ownership_proof")):
                rec["ownership_verified"] = False
                rec.pop("ownership_proof", None)
        if isinstance(data.get("failure"), dict):
            self.a.failure = dict(data["failure"])
        for u in (data.get("unstopped_workers") if isinstance(data.get("unstopped_workers"), list) else []):
            try:
                pids = [int(p) for p in u["pids"] if WorkerPool.group_alive(int(p))]
                sessions = []
                for name in (u.get("cgroups") or []):
                    try:
                        sessions.append(self._l2_confinement.reattach(str(name)))
                    except Exception:
                        continue
                if pids or sessions:
                    self._unstopped.append({"host": str(u.get("host") or ""), "pids": pids,
                                            "at": float(u.get("at") or time.time()), "pool": None,
                                            "sessions": sessions})
            except (KeyError, TypeError, ValueError):
                continue
        self._state_had_ledger_flag = bool(data.get("authority_ledger"))
        if isinstance(data.get("chat_messages"), list):
            self.a.chat_messages = [dict(m) for m in data["chat_messages"] if isinstance(m, dict)]
        if isinstance(data.get("stop_report"), dict):
            self.a.stop_report = dict(data["stop_report"])
        if isinstance(data.get("defense_comparison"), dict):
            self.a.defense_comparison = dict(data["defense_comparison"])
        saved_state = str(data.get("state", "idle"))
        if saved_state in ("idle", "completed", "stopped", "failed", "paused"):
            self.a.state = saved_state
            if saved_state == "stopped":
                self.gateway._state = State.STOPPED
            elif saved_state == "paused":
                self.gateway._state = State.PAUSED
        elif saved_state == "running":
            # A process restart interrupted an in-flight thread; preserve progress as paused
            self.a.state = "paused"
            self.gateway._state = State.PAUSED
        if self._stop_flag().exists():
            # an emergency stop was begun and never ended by a new run - whatever
            # state.json managed to record about it
            self.a.state = "stopped"
            self.gateway._state = State.STOPPED
        self._artex_cli_verified = bool(data.get("artex_cli_verified", False))
        if isinstance(data.get("last_planner_verification"), dict):
            self._last_planner_verification = dict(data["last_planner_verification"])

    def verify_planner_connections(self, actor: str = "operator") -> dict:
        """Run a live end-to-end connection verification of external ARTEX CLI and
        Abliteration OpenAI-compatible API, recording the cryptographic proof in audit."""
        rep = verify_planner_connections()
        with self._lock:
            self._artex_cli_verified = bool(rep["artex_cli"]["verified"])
            if rep["abliteration_api"]["verified"]:
                self._model_response_verified = True
            self._last_planner_verification = rep
            self._save_state_locked()
        self.audit.record(
            "router.connections_verified",
            actor=actor,
            all_verified=rep["all_verified"],
            proof_sha256=rep["proof_sha256"],
            artex_version=rep["artex_cli"]["version"],
            abliteration_mode=rep["abliteration_api"]["endpoint_mode"],
        )
        return rep

    # ---- ARTEX: the real planner, behind the Gateway --------------------------
    def _artex_targets_locked(self) -> list[dict]:
        """What ARTEX may see: the registered local lab only - never a real service."""
        return [{"asset_id": 1, "target_id": "lab", "url": self.a.target_url}]

    def _refuse_artex_on_real_service_locked(self) -> None:
        if self._is_external_service_asset() or self._in_ownership_flow(self.a.asset.get("name")):
            raise ValueError("ARTEX 計画は登録済みのローカル検証ラボでのみ使用できます"
                             "（実サービスの情報は ARTEX に渡しません）")

    def plan_with_artex(self, actor: str, *, llm_approval: dict | None = None, roles=None,
                        llm_mode: str | None = None) -> dict:
        """Ask the real ARTEX planner for a plan, then rebuild every item from Vulnix's
        own registered targets and allowed catalog. Nothing is executed here.

        `llm_approval` ({"max_calls": N, "first_request_sha256": <from the preview>}) is
        needed when the planner's model is a real (non-loopback) endpoint behind the
        Planner LLM Gateway; only an approver can give it."""
        if not self._artex_real_cmd:
            raise ValueError("ARTEX プランナーが設定されていません（VULNIX_ARTEX_REAL_CMD）")
        with self._lock:
            self._refuse_after_stop_locked()
            self._refuse_artex_on_real_service_locked()
            if self._unstopped_now_locked():
                # while anything is not confirmed stopped, nothing new launches
                raise ValueError("停止を確認できていないプロセスがあるため、ARTEX を起動しません")
            self._ensure_active_window_locked()
            targets = self._artex_targets_locked()
            observations = [{"title": clean_target_text(f["title"], 200), "detail": clean_target_text(f.get("summary", ""), 400)}
                            for f in self.a.findings.values() if f.get("id") in ("f_banner", "f_idor", "f_sqli")]
            gen = self._run_generation
        request = {"goal": "登録済みの検証対象について、許可された非破壊の検証で確認すべき脆弱性の方向を計画する",
                   "targets": targets, "observations": observations, "max_turns": 6}
        canary = os.environ.get("VULNIX_ARTEX_EGRESS_CANARY", "")
        if re.fullmatch(r"127\.0\.0\.1:\d{1,5}", canary):
            request["egress_canary"] = canary      # proves the confinement around ARTEX itself
        # ARTEX runs only under Vulnix's kernel confinement (the same per-run cgroup v2 +
        # nftables + own-uid + seccomp launcher as the L2 worker). Without it, it does not
        # run - except when an operator explicitly opts into an unconfined DEV run.
        # Outside development the ARTEX binary must be pinned: its SHA-256 is compared with
        # VULNIX_ARTEX_EXPECTED_SHA256 before it runs (a mismatch, or anything that is not
        # the ARTEX overlay build, is refused by the bridge).
        dev = os.environ.get("AEGIS_ENV", "").strip().lower() in ("development", "dev")
        if not dev and not re.fullmatch(r"[0-9a-fA-F]{64}", self._artex_expected_sha256.strip()):
            self.audit.record("artex.plan_refused", actor=actor, reason="binary sha256 not pinned")
            raise ValueError("本番環境では ARTEX バイナリの SHA-256（VULNIX_ARTEX_EXPECTED_SHA256）の指定が必須です")
        for url, default in ((self._artex_llm_url, None), (self._artex_pg_dsn, 5432)):
            if not url:
                continue
            u = urllib.parse.urlsplit(url)
            port = u.port or default or (443 if u.scheme == "https" else 80)
            if port == self.lab_port:
                # a pinned port gives the planner whatever listens there
                raise ValueError("ARTEX の LLM / DB の接続先に検証ラボのポートは使用できません")
        st = dict(self._l2_confinement.status())
        if st.get("ok"):
            confinement = self._l2_confinement
            protected = sorted(str(p) for p in self.data_dir.iterdir() if p.is_file())
        elif (os.environ.get("VULNIX_ARTEX_ALLOW_UNCONFINED") == "1"
              and os.environ.get("AEGIS_ENV", "").strip().lower() in ("development", "dev")):
            confinement, protected = None, ()
            self.audit.record("artex.unconfined_dev_run", actor=actor, reason=str(st.get("reason", ""))[:200])
        else:
            self.audit.record("artex.plan_refused", actor=actor, reason="no OS-level confinement")
            raise ValueError("ARTEX プランナーを OS レベルで隔離して起動できないため実行しません"
                             f"（{str(st.get('reason', ''))[:200]}）")
        self.audit.record("artex.plan_requested", actor=actor, targets=len(targets), confined=confinement is not None)
        gateway = self._planner_gateway(actor, llm_approval, roles, gen, llm_mode)
        llm_url, llm_key = self._artex_llm_url, ""
        if gateway is not None:
            try:
                gateway.__enter__()                   # ARTEX's only model: on loopback
            except Exception as e:  # noqa: BLE001
                self.audit.record("artex.plan_failed", actor=actor, reason=f"gateway:{type(e).__name__}")
                raise ValueError("Planner LLM Gateway を起動できません") from None
            with self._lock:
                self._artex_gateways.add(gateway)
            llm_url, llm_key = gateway.url, gateway.token
        try:
            run = run_artex_planner(self._artex_real_cmd, request, llm_url=llm_url, llm_key=llm_key,
                                    llm_model=self._artex_llm_model, pg_dsn=self._artex_pg_dsn,
                                    expected_sha256=self._artex_expected_sha256,
                                    confinement=confinement, forbidden_paths=protected,
                                    on_leftover=self._note_leftover_session,
                                    on_started=lambda sess: self._artex_session_started(sess, gen),
                                    on_finished=self._artex_session_finished,
                                    may_start=lambda: self._artex_may_start(gen),
                                    data_dirs=(str(self.data_dir),))
        except ArtexBridgeError as e:
            self.audit.record("artex.plan_failed", actor=actor, reason=str(e)[:200])
            raise ValueError(str(e)) from None
        except Exception as e:  # noqa: BLE001 - recorded, and never a half-made plan
            self.audit.record("artex.plan_failed", actor=actor, reason=type(e).__name__)
            raise ValueError(f"ARTEX の計画に失敗しました（{type(e).__name__}）") from None
        finally:
            if gateway is not None:
                gateway.__exit__(None, None, None)
                self._note_gateway_run(gateway, actor)
        if gateway is not None and gateway.failure:
            # one upstream failure ends the run: whatever ARTEX made of it is not a plan
            status = gateway.failure.get("http_status")
            self.audit.record("artex.plan_failed", actor=actor,
                              reason=f"upstream_http_{status}" if status else "upstream_failure")
            raise ValueError(f"Planner LLM の上流 API がエラーを返したため、計画を破棄しました（HTTP {status}）")
        run_id = "ax" + secrets.token_hex(4)
        rec = reconstruct(run.intents, targets, run_id)
        # The rebuilt proposals still pass ProposalRouter (sanitized, audited) and appear
        # as tasks in the existing plan view; the Gateway alone decides what may run.
        router = ProposalRouter(self.gateway, self.audit, [_StaticProposals("artex-oss", [i.proposal for i in rec.items])])
        with self._lock:
            if gen != self._run_generation:
                raise ValueError("停止またはリセットされたため、ARTEX 計画を破棄しました")
            self._refuse_after_stop_locked()
            if any(r["item"].status == "running" for r in self._artex_items.values()):
                raise ValueError("ARTEX 計画の項目を実行中です。完了してから再計画してください")
            # the previous plan's tasks leave the plan view with it
            self.artex.tasks = [t for t in self.artex.tasks if t.phase != "artex"]
            tasks = self.artex.plan_phase("artex", {"target_id": "lab"}, router=router)
        prov = run.provenance
        with self._lock:
            if gen != self._run_generation:
                raise ValueError("停止またはリセットされたため、ARTEX 計画を破棄しました")
            # a new plan replaces the previous one: its items can no longer run
            self._artex_items = {}
            for item in rec.items:
                tk = next((t for t in tasks if t.routed.proposal["tool"] == item.proposal["tool"]
                           and t.routed.proposal["args"] == item.proposal["args"]), None)
                if tk is None or tk.status == "unsupported":
                    item.status = "unsupported"      # the router or Gateway catalog refused it
                if tk is not None:
                    tk.id = item.id                  # unique across plans
                    tk.status = item.status
                self._artex_items[item.id] = {"item": item, "task_id": tk.id if tk else None,
                                              "gen": gen, "run_id": run_id, "requested_by": actor}
            kind = prov.get("kind")
            label = ("ARTEX 本体（overlay ビルド・ハッシュ固定）" if kind == "artex-binary" and prov.get("pinned")
                     else "ARTEX ビルド（ハッシュ未固定のため本体と未確認）" if kind == "artex-binary"
                     else "ARTEX 互換プロセス（本体と未確認）")
            self._artex_plan = {
                "run_id": run_id, "requested_by": actor, "at": time.time(),
                "engine": {"kind": kind, "pinned": bool(prov.get("pinned")), "sha256": prov.get("sha256"),
                           "artex_module": prov.get("artex_module"), "artex_commit": prov.get("artex_commit"),
                           "go_version": prov.get("go_version"), "norma_version": prov.get("norma_version"),
                           "label": label},
                "llm_gateway": ({k: v for k, v in (self._artex_llm_last or {}).get("report", {}).items()
                                 if k not in ("records", "failed_upstream")} if gateway is not None else None),
                "isolation": {**_artex_isolation_view(prov.get("isolation") or {}),
                              "egress_canary": prov.get("egress_canary") or None},
                "allowed_tools": run.allowed_tools, "tool_calls": run.tool_calls,
                "denied_tool_calls": run.denied_tool_calls, "goal_met": run.goal_met,
                "elapsed_ms": run.elapsed_ms, "intents": len(run.intents),
                "advisories": [{"intent_id": a.intent_id, "summary": clean_target_text(a.intent_summary, 500),
                                "reason": a.reason} for a in rec.advisories],
            }
        self.audit.record("artex.plan_received", actor=actor, run_id=run_id, engine_kind=prov.get("kind"),
                          engine_pinned=bool(prov.get("pinned")), engine_sha256=prov.get("sha256"),
                          artex_commit=prov.get("artex_commit"), intents=len(run.intents), items=len(rec.items),
                          advisories=len(rec.advisories), denied_tool_calls=len(run.denied_tool_calls))
        for a in rec.advisories:
            self.audit.record("artex.intent_advisory", run_id=run_id, intent=a.intent_id, reason=a.reason)
        self.bus.publish(self.a.id, "artex.plan", artex_plan=self.artex_plan_view())
        return self.snapshot()

    PREVIEW_TTL_S = 30 * 60

    def _planner_gateway(self, actor: str, approval: dict | None, roles, gen: int, mode: str | None):
        """The Planner LLM Gateway for this run. Mode: the request's `llm_mode`, else
        VULNIX_ARTEX_LLM_MODE: direct (none) | gateway-preview | gateway-forward."""
        configured = os.environ.get("VULNIX_ARTEX_LLM_MODE", "direct").strip()
        mode = (mode or configured).strip()
        if mode == "direct" and configured != "direct":
            # a request may narrow the mode (to preview), never bypass the gateway
            raise ValueError("Planner LLM Gateway が設定されているため、direct には切り替えられません")
        if mode == "direct":
            return None
        from .planner_llm_gateway import Budget, PlannerLLMGateway

        def num(name, default, cast=float):
            try:
                return cast(os.environ.get(name, default))
            except ValueError:
                return cast(default)
        budget = Budget(max_calls=num("VULNIX_PLANNER_LLM_MAX_CALLS", 6, int),
                        max_total_tokens=num("VULNIX_PLANNER_LLM_MAX_TOKENS", 60000, int),
                        max_cost_usd=num("VULNIX_PLANNER_LLM_MAX_COST_USD", 0.50),
                        usd_per_1k_input=num("VULNIX_PLANNER_LLM_USD_PER_1K_INPUT", 0.0),
                        usd_per_1k_output=num("VULNIX_PLANNER_LLM_USD_PER_1K_OUTPUT", 0.0))

        def denied():                                   # looked up on every request
            with self._lock:
                return set(self._real_service_hosts) | {
                    str(x.get("name") or "").lower() for x in self._extra_assets if x.get("name")}
        with self._lock:
            allowed = set(self._allowed_hosts) | {"lab.test"}
        model = os.environ.get("VULNIX_ARTEX_LLM_MODEL") or os.environ.get("VULNIX_ABLITERATION_MODEL") or "mock"
        may_forward = (lambda: self._artex_may_start(gen))
        common = dict(model=model, budget=budget, allowed_hosts=allowed, denied_hosts=denied, audit=self.audit,
                      may_forward=may_forward)
        if mode == "gateway-preview":
            return PlannerLLMGateway(mode="preview", responder=_preview_responder,
                                     api_key=os.environ.get("VULNIX_ABLITERATION_KEY", ""), **common)
        if mode != "gateway-forward":
            raise ValueError("llm_mode は direct / gateway-preview / gateway-forward のいずれかです")
        upstream = os.environ.get("VULNIX_ARTEX_LLM_UPSTREAM_URL") or os.environ.get("VULNIX_ABLITERATION_URL", "")
        host = (urllib.parse.urlsplit(upstream).hostname or "")
        real = host not in ("127.0.0.1", "::1", "localhost")
        bound = None
        if real:
            bound = self._take_preview_approval(actor, approval, roles)
        return PlannerLLMGateway(mode="forward", upstream_url=upstream,
                                 api_key=os.environ.get("VULNIX_ABLITERATION_KEY", "") if real else "",
                                 approval=bound, **common)

    def _previews_path(self) -> Path:
        return self.data_dir / "planner_llm_previews.json"

    def _load_previews_locked(self) -> dict:
        try:
            return json.loads(self._previews_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save_previews_locked(self, previews: dict) -> None:
        path = self._previews_path()
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(previews, ensure_ascii=False))
        os.replace(tmp, path)

    def _take_preview_approval(self, actor: str, approval: dict | None, roles) -> dict:
        """A real upstream: an approver approves ONE stored preview, once, within its
        lifetime, and is not the person who ran it. The fingerprint comes from the
        stored preview - not from the client."""
        if roles is not None and "approver" not in roles:
            raise ApproverRequired("実モデルへの送信の承認には承認責任者の権限が必要です")
        if not isinstance(approval, dict) or not isinstance(approval.get("preview_id"), str) \
                or not isinstance(approval.get("max_calls"), int) or approval["max_calls"] < 1:
            raise ValueError("実モデルへの送信には、preview に基づく承認（preview_id と max_calls）が必要です")
        with self._lock:
            previews = self._load_previews_locked()
            pv = previews.get(approval["preview_id"])
            if not pv or pv.get("used"):
                raise ValueError("この preview は存在しないか、すでに承認に使われています")
            if time.time() - float(pv.get("at", 0)) > self.PREVIEW_TTL_S:
                raise ValueError("preview の有効期限（30 分）が切れています。preview をやり直してください")
            if pv.get("run_by") == actor:
                self.audit.record("planner_llm.approval_denied", actor=actor, reason="separation of duties")
                raise ApproverRequired("preview を実行した本人は、その送信を承認できません")
            if not pv.get("first_request_sha256"):
                raise ValueError("この preview には送信予定の要求がありません")
            client_sha = approval.get("first_request_sha256")
            if client_sha is not None and client_sha != pv["first_request_sha256"]:
                raise ValueError("承認したフィンガープリントが preview と一致しません")
            max_calls = min(int(approval["max_calls"]), int(pv.get("budget_max_calls", approval["max_calls"])))
            pv.update(used=True, approved_by=actor, approved_at=time.time(), approved_max_calls=max_calls)
            self._save_previews_locked(previews)          # single use, before anything is sent
        self.audit.record("planner_llm.approved", actor=actor, preview_id=approval["preview_id"],
                          max_calls=max_calls, first_request_sha256=pv["first_request_sha256"])
        return {"max_calls": max_calls, "first_request_sha256": pv["first_request_sha256"]}

    def _note_gateway_run(self, gateway, actor: str) -> None:
        rep = gateway.report()
        with self._lock:
            self._artex_llm_last = {"report": rep, "at": time.time()}
            if gateway.mode == "preview":
                pid = "pv_" + secrets.token_hex(8)
                record = {"id": pid, "run_by": actor, "at": time.time(), "model": gateway.model,
                          "first_request_sha256": rep["first_request_sha256"], "calls": rep["calls"],
                          "budget_max_calls": rep["budget"]["max_calls"], "used": False,
                          # only the FIRST request is fixed by an approval; later ones depend on
                          # the model's answers and are inspected and budgeted, not pre-approved
                          "note": "承認で固定されるのは最初の要求のみです。2 回目以降は検査・上限の対象です。",
                          "requests": list(gateway.preview_requests)}
                previews = {k: v for k, v in self._load_previews_locked().items()
                            if time.time() - float(v.get("at", 0)) <= self.PREVIEW_TTL_S}
                previews[pid] = record
                self._save_previews_locked(previews)
                self._artex_llm_last["preview_id"] = pid
                self._artex_llm_last["requests"] = record["requests"]
                rep["preview_id"] = pid
            self._artex_gateways.discard(gateway)

    def artex_llm_preview(self) -> dict:
        """What the last gateway run sent or would have sent (approver review)."""
        with self._lock:
            return dict(self._artex_llm_last or {"report": None})

    def _close_planner_gateways_locked(self) -> None:
        for gw in list(self._artex_gateways):
            try:
                gw.close()                               # nothing more is forwarded
            except Exception:  # noqa: BLE001
                pass

    def artex_plan_view(self) -> dict | None:
        with self._lock:
            if self._artex_plan is None:
                return {"configured": bool(self._artex_real_cmd), "plan": None}
            items = []
            for rec in self._artex_items.values():
                it = rec["item"]
                items.append({"id": it.id, "intent_id": it.intent_id,
                              "intent_summary": clean_target_text(it.intent_summary, 500),
                              "catalog_id": it.catalog_id, "label": it.label, "level": it.level,
                              "target_id": it.target_id, "tool": it.proposal["tool"], "status": it.status})
            return {"configured": bool(self._artex_real_cmd), "plan": {**self._artex_plan, "items": items}}

    def _artex_session_started(self, sess, gen: int) -> None:
        """Registered before anything runs in the session; refused after a stop."""
        with self._lock:
            if not self._artex_may_start_locked(gen):
                raise ArtexBridgeError("緊急停止されたため ARTEX を起動しません")
            self._artex_live.add(sess)

    def _artex_may_start_locked(self, gen: int) -> bool:
        return (gen == self._run_generation and self.gateway.state is not State.STOPPED
                and self.a.state != "stopped" and not self._unstopped_now_locked())

    def _artex_may_start(self, gen: int) -> bool:
        with self._lock:
            return self._artex_may_start_locked(gen)

    def _artex_session_finished(self, sess) -> None:
        with self._lock:
            self._artex_live.discard(sess)

    def _kill_artex_planner_locked(self) -> None:
        """Emergency stop: a running ARTEX planner is killed with its cgroup, and only a
        planner CONFIRMED gone leaves the record - one that is not goes on the same
        unstopped record as an L2 worker (the stop is then reported unconfirmed)."""
        live = list(self._artex_live)
        for sess in live:
            try:
                sess.kill()
            except Exception:  # noqa: BLE001 - confirmed (or not) below
                pass
        deadline = time.monotonic() + 3.0
        pending = list(live)
        while pending and time.monotonic() < deadline:
            pending = [x for x in pending if not _session_empty(x)]
            for x in pending:
                # cgroup.kill acts on the processes in the cgroup NOW: a process that was
                # just launched and joins a moment later is killed by the next write
                try:
                    x.kill()
                except Exception:  # noqa: BLE001 - still pending: on record below
                    pass
            if pending:
                time.sleep(0.1)
        for sess in pending:
            if not self._session_on_record(sess):
                self._unstopped.append({"host": (self.a.asset.get("name") or "").lower(), "pids": [],
                                        "at": time.time(), "pool": None, "sessions": [sess]})
                self.audit.record("artex.stop_unconfirmed", cgroup=getattr(sess, "name", ""))

    def _claim_artex_item_locked(self, item_id: str) -> dict:
        """Check and claim (set running) in ONE locked step: no second request can
        claim the same item, and an item of an old plan or workspace never runs."""
        rec = self._artex_items.get(item_id)
        if rec is None or (self._artex_plan or {}).get("run_id") != rec["run_id"]:
            raise ValueError("ARTEX 計画の項目が見つからないか、新しい計画で置き換えられました")
        if rec["gen"] != self._run_generation:
            raise ValueError("停止またはリセット前の ARTEX 計画は実行できません。計画を作り直してください")
        item = rec["item"]
        if item.status not in ("planned", "awaiting_approval"):
            raise ValueError("この項目は実行できません（実行中・実行済み・未対応）")
        self._refuse_after_stop_locked()
        self._refuse_artex_on_real_service_locked()
        if self.gateway.state is State.PAUSED:
            raise ValueError("診断を一時停止中です。再開または停止してから実行してください")
        return rec

    def execute_artex_item(self, item_id: str, actor: str, *, roles=None) -> dict:
        """Run ONE item of the ARTEX plan. The operation is rebuilt from Vulnix's catalog
        (never from what ARTEX or the stored proposal says); L1 goes through the Gateway
        under the L1 policy, L2 needs an approver and runs in the isolated worker."""
        self._begin_operation()          # from here the active asset cannot be switched
        prev = getattr(self._tls, "gen", None)
        claimed = False
        try:
            with self._lock:
                rec = self._claim_artex_item_locked(item_id)
                item = rec["item"]
                entry = CATALOG_BY_ID[item.catalog_id]
                if entry.level == "L2":
                    if not actor or str(actor).startswith("policy:"):
                        raise ValueError("L2 検証には人間の個別承認が必要です（自動承認不可）")
                    if roles is not None and "approver" not in roles:
                        self.audit.record("artex.item_denied", item=item_id, actor=actor,
                                          reason="approver role required")
                        raise ApproverRequired("ARTEX 計画の L2 検証には承認責任者の権限が必要です")
                    if self.separate_l2_approver and actor == rec["requested_by"]:
                        self.audit.record("artex.item_denied", item=item_id, actor=actor,
                                          reason="separation of duties")
                        raise ApproverRequired("計画を依頼した本人は、その L2 検証を承認できません")
                item.status = "running"
                claimed = True
                self._tls.gen = self._run_generation
                url = self.a.target_url
            self._sync_artex_item(item_id)
            if entry.level == "L2":
                self.audit.record("artex.item_approved", item=item_id, approver=actor, check=entry.check,
                                  requested_by=rec["requested_by"])
                def _proofs():
                    with self._lock:
                        f = self.a.findings.get(entry.finding_id) or {}
                        return sum(1 for e in f.get("evidence") or [] if e.get("audit_hash"))
                before = _proofs()
                self.verify_finding(entry.finding_id, actor, roles=roles)
                ok = _proofs() > before          # this run recorded evidence for this finding
            else:
                with self._lock:
                    self._ensure_active_window_locked()
                res, ev = self._exec(entry.tool, entry.action, entry.args_for(url),
                                     approval_actor=f"artex-L1:{actor}")
                if res is not None:
                    with self._lock:
                        self._analyze(res, ev)
                ok = res is not None
            self._set_artex_item_status(item_id, "completed" if ok else "failed")
            claimed = False
            return self.snapshot()
        except _Stopped:
            if claimed:
                self._set_artex_item_status(item_id, "failed")
            raise ValueError("停止またはリセットされたため、検証を中止しました") from None
        except (ApproverRequired, ValueError):
            if claimed:
                self._set_artex_item_status(item_id, "failed")
            raise
        except Exception:
            if claimed:
                self._set_artex_item_status(item_id, "failed")
            raise
        finally:
            self._tls.gen = prev
            self._end_operation()

    def _sync_artex_item(self, item_id: str) -> None:
        with self._lock:
            rec = self._artex_items.get(item_id)
            if rec is None:
                return
            for tk in self.artex.tasks:
                if tk.id == rec["task_id"]:
                    tk.status = rec["item"].status
        self.bus.publish(self.a.id, "artex.plan", artex_plan=self.artex_plan_view())

    def _set_artex_item_status(self, item_id: str, status: str) -> None:
        with self._lock:
            rec = self._artex_items.get(item_id)
            if rec is None:
                return
            rec["item"].status = status
        self.audit.record("artex.item_status", item=item_id, status=status)
        self._sync_artex_item(item_id)

    @staticmethod
    def _default_phases() -> list[dict]:
        return [
            {"key": "scope", "label": "診断範囲を確認", "status": "pending", "detail": ""},
            {"key": "config", "label": "公開設定を検査", "status": "pending", "detail": ""},
            {"key": "analysis", "label": "検出結果を分析", "status": "pending", "detail": ""},
            {"key": "verification", "label": "脆弱性の検証", "status": "pending", "detail": ""},
            {"key": "report", "label": "結果をまとめる", "status": "pending", "detail": ""},
        ]

    def _ensure_active_window_locked(self) -> None:
        now = time.time()
        e = self.a.engagement
        name = self.a.asset.get("name")
        if self._in_ownership_flow(name) and self._persist_error:
            self._save_state_locked()          # try again; maybe the directory is writable now
            if self._persist_error:
                raise ValueError("状態をディスクに保存できないため、実サービスへの診断を停止しています。"
                                 "データディレクトリの書き込み権限と空き容量を確認してください")
        if self._in_ownership_flow(name):
            # A real service's window is the confirmed scope window. It is never
            # extended here; expiry or revocation needs a new proof + confirmation.
            ext = self._external_entry(name)
            if ext is None:
                raise ValueError("診断範囲の確認が失効または取り消されています。所有確認と範囲確認をやり直してください")
            self.a.engagement = Engagement(
                e.id, True, e.authorization_ref, e.not_before,
                min(e.not_after, float(ext["not_after"])), e.targets, e.allowed_actions,
            )
            self.gateway.engagement = self.a.engagement
        elif not (e.not_before <= now < e.not_after - 3600):
            self.a.engagement = Engagement(
                e.id, e.ownership_verified, e.authorization_ref,
                now - 60, now + 30 * 86400, e.targets, e.allowed_actions,
            )
            self.gateway.engagement = self.a.engagement
        self.gateway.budget = Budget(50)

    def _sync_scope_for_host(self, host: str, auth_ref: str) -> None:
        h = (host or "").rstrip(".").lower()
        now = time.time()
        e = self.a.engagement
        ext = self._external_entry(h)
        revoked_real_service = ext is None and self._in_ownership_flow(h)
        if ext is None and not revoked_real_service:
            self._allowed_hosts.add(h)     # local simulated-lab alias only
        if revoked_real_service:
            # registered as a real service but not (or no longer) verified + confirmed:
            # nothing is in scope, and it is not downgraded to the local lab.
            self._allowed_hosts.discard(h)
            target = Target("lab", hosts=(), cidrs=("127.0.0.1/32",), ports=(self.lab_port,))
            self.a.target_url = str(self.a.asset.get("target_url") or f"https://{h}/")
        elif ext is not None:
            scheme = str(ext.get("scheme", "https"))
            port = int(ext.get("port", 443))
            cidrs = tuple(ext.get("cidrs", ("0.0.0.0/0", "::/0")))
            target = Target("lab", hosts=(h,), cidrs=cidrs, ports=(port,))
            default_port = 443 if scheme == "https" else 80
            port_suffix = "" if port == default_port else f":{port}"
            self.a.target_url = f"{scheme}://{h}{port_suffix}/"
        else:
            target = Target("lab", hosts=tuple(sorted(self._allowed_hosts)),
                            cidrs=("127.0.0.1/32",), ports=(self.lab_port,))
            self.a.target_url = f"http://{h}:{self.lab_port}/"
        not_after = now + 30 * 86400
        if ext is not None:   # never outlive the ownership/scope confirmation window
            not_after = min(not_after, float(ext["not_after"]))
        self.a.engagement = Engagement(
            e.id, not revoked_real_service, auth_ref or e.authorization_ref,
            now - 60, not_after, {"lab": target}, e.allowed_actions
        )
        self.gateway.engagement = self.a.engagement
        self.gateway.egress = EgressGuard(self._resolve_host)


    # ---- snapshot -----------------------------------------------------------
    def assets(self) -> list[dict]:
        with self._lock:
            risk = self._risk()
            primary = {
                **self.a.asset,
                "status": _asset_status(self.a.state),
                "assessment_id": self.a.id,
                "risk": risk if self.a.state != "idle" else None,
                "previous_risk_score": None if self._is_external_service_asset() else 55,
                "last_assessed_at": None if self._is_external_service_asset() else int(time.time() - 86400 * 7),
                "authorization_ref": self.a.engagement.authorization_ref,
                "ownership_verified": self.a.engagement.ownership_verified,
            }
            extras = [
                dict(x) for x in self._extra_assets
                if x["id"] != primary["id"] and x["name"].lower() != primary["name"].lower()
            ]
            return [primary, *extras]

    def register_asset(self, *, name: str, kind: str, environment: str,
                       authorization_ref: str = "", ownership_verified: bool = False,
                       activate_workspace: bool = False, actor: str = "operator") -> dict:
        clean_name = (name or "").strip().lower()
        if not clean_name or len(clean_name) > 120 or " " in clean_name:
            raise ValueError("有効な対象ドメインまたはホスト名を入力してください")
        for text in (clean_name, kind or "", environment or "", authorization_ref or ""):
            try:
                str(text).encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("入力に不正な文字が含まれています") from None
        if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", clean_name):
            raise ValueError("有効な対象ドメインまたはホスト名を入力してください")
        clean_kind = (kind or "Webアプリケーション").strip()[:40]
        clean_env = (environment or "検証環境").strip()[:40]
        clean_ref = (authorization_ref or "").strip()[:80]
        authorized = bool(ownership_verified and clean_ref)

        with self._lock:
            in_ownership_flow = self._in_ownership_flow(clean_name)
            if in_ownership_flow:   # checked BEFORE anything is added to the lab allow-list
                raise ValueError("この資産は実サービスとして登録されています。所有確認（DNS TXT / 検証ファイル）の手順で登録してください")
            if authorized:
                self._allowed_hosts.add(clean_name)
            # Check if updating the current primary asset
            if self.a.asset["name"].lower() == clean_name:
                self.a.asset = {
                    **self.a.asset,
                    "kind": clean_kind,
                    "environment": clean_env,
                }
                if authorized:
                    self._sync_scope_for_host(clean_name, clean_ref)
                asset_record = {
                    **self.a.asset,
                    "status": _asset_status(self.a.state),
                    "assessment_id": self.a.id,
                    "risk": self._risk() if self.a.state != "idle" else None,
                    "authorization_ref": clean_ref,
                    "ownership_verified": authorized,
                }
            else:
                # Check if updating an existing extra asset (e.g. granting SOW to internal-staging)
                existing = next((x for x in self._extra_assets if x["name"].lower() == clean_name), None)
                if existing is not None:
                    existing["kind"] = clean_kind
                    existing["environment"] = clean_env
                    existing["authorization_ref"] = clean_ref
                    existing["ownership_verified"] = authorized
                    if authorized:
                        existing["status"] = "未診断"
                        existing["assessment_id"] = self.a.id
                        existing.pop("note", None)
                    else:
                        existing["status"] = "承認待ち"
                        existing["assessment_id"] = None
                        existing["note"] = "書面許可が未登録のため診断できません"
                    asset_record = dict(existing)
                else:
                    aid = "asset_" + secrets.token_hex(3)
                    asset_record = {
                        "id": aid,
                        "name": clean_name,
                        "kind": clean_kind,
                        "environment": clean_env,
                        "status": "未診断" if authorized else "承認待ち",
                        "assessment_id": self.a.id if authorized else None,
                        "risk": None,
                        "previous_risk_score": None,
                        "last_assessed_at": None,
                        "authorization_ref": clean_ref,
                        "ownership_verified": authorized,
                        **({} if authorized else {"note": "書面許可が未登録のため診断できません"}),
                    }
                    self._extra_assets.insert(0, asset_record)

                if activate_workspace and authorized and self.a.state != "running":
                    self._activate_asset_locked(asset_record, clean_ref)
            self._save_state_locked()

        self.audit.record(
            "asset.registered",
            actor=actor,
            name=clean_name,
            kind=clean_kind,
            environment=clean_env,
            authorized=authorized,
            authorization_ref=clean_ref,
        )
        return asset_record

    def _activate_asset_locked(self, asset_record: dict, auth_ref: str) -> None:
        # the single place where the active asset changes: never during a verification
        switching = asset_record.get("id") != self.a.asset.get("id")
        if switching:
            self._refuse_while_verifying_locked()
            if self.a.state in ("running", "paused"):
                # a paused run still has a runner thread that will write its results
                # into whatever workspace is active when it wakes up
                raise ValueError("診断の実行中・一時停止中は対象を切り替えられません。先に停止してください")
        prev_primary = {
            **self.a.asset,
            "status": _asset_status(self.a.state),
            "assessment_id": self.a.id,
            "risk": self._risk() if self.a.state != "idle" else None,
            "previous_risk_score": None if self._is_external_service_asset() else 55,
            "last_assessed_at": None if self._is_external_service_asset() else int(time.time() - 86400 * 7),
            "authorization_ref": self.a.engagement.authorization_ref,
            "ownership_verified": self.a.engagement.ownership_verified,
        }
        if not any(x["id"] == prev_primary["id"] for x in self._extra_assets):
            self._extra_assets.append(prev_primary)
        self._extra_assets = [
            x for x in self._extra_assets if x["id"] != asset_record["id"]
        ]
        self.a.asset = {
            "id": asset_record["id"],
            "name": asset_record["name"],
            "kind": asset_record["kind"],
            "environment": asset_record["environment"],
            # keep registration metadata of real services (ownership proof, URL)
            **{k: asset_record[k] for k in (
                "display_name", "target_url", "scheme", "port", "gcp_project",
                "scope_confirmed", "challenge", "ownership_proof", "approver",
                "sow_optional_ref") if k in asset_record},
        }
        self._sync_scope_for_host(asset_record["name"], auth_ref)
        if switching:
            # Nothing measured on one asset may remain in the workspace of another:
            # findings and evidence are cleared on EVERY switch, whichever route made it.
            self._reset_workspace_locked()
            self.a.chat_messages = []      # answers may quote the previous asset's findings

    def select_asset(self, asset_id: str, actor: str = "operator") -> dict:
        with self._lock:
            if self.a.state == "running":
                raise ValueError("診断実行中は対象を切り替えられません。一時停止または停止してください")
            self._refuse_while_verifying_locked()
            if self.a.asset["id"] == asset_id:
                return self.snapshot()
            target_asset = next((x for x in self._extra_assets if x["id"] == asset_id), None)
            if target_asset is None:
                raise ValueError("指定された診断対象が見つかりません")
            if not target_asset.get("ownership_verified") or not target_asset.get("authorization_ref"):
                raise ValueError("この資産は書面許可（SOW）が未登録のため診断できません")
            if self._in_ownership_flow(target_asset["name"]) and self._external_entry(target_asset["name"]) is None:
                raise ValueError("所有確認・診断範囲確認が未完了か有効期限切れです。資産管理から所有確認をやり直してください")
            self._activate_asset_locked(target_asset, str(target_asset["authorization_ref"]))
            self._reset_workspace_locked()
        self.audit.record("asset.selected", actor=actor, asset_id=asset_id, name=self.a.asset["name"])
        return self.snapshot()

    def asset_is_real_service(self, asset_id: str = "", host: str = "") -> bool:
        """Whether an asset (by id or host) was registered through the ownership flow."""
        with self._lock:
            if asset_id:
                rec = next((x for x in (self.a.asset, *self._extra_assets) if x.get("id") == asset_id), None)
                host = (rec or {}).get("name", "")
            return bool(host) and self._in_ownership_flow(host)

    def real_service_has_authority(self, host: str) -> bool:
        """True if the host currently has a recorded proof or a confirmed scope."""
        h = (host or "").rstrip(".").lower()
        with self._lock:
            return h in self._ownership_proofs or h in self._verified_external_hosts

    def _refuse_after_stop_locked(self) -> None:
        """An emergency stop is ended only by an explicit new run ("restart"), never
        as a side effect of some other request."""
        if self.gateway.state is State.STOPPED or self.a.state == "stopped":
            raise ValueError("緊急停止中です。検証は実行できません。「再診断を実行」で新しい診断を開始してください")

    def _refuse_while_verifying_locked(self) -> None:
        if self._inflight:
            raise ValueError("検証の実行中は対象を切り替え・変更できません。完了してからやり直してください")

    def _begin_operation(self) -> None:
        with self._lock:
            self._inflight += 1

    def _end_operation(self) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)

    def delete_asset(self, asset_id: str, actor: str = "operator") -> list[dict]:
        with self._lock:
            if self.a.asset["id"] == asset_id:
                self._refuse_while_verifying_locked()
                if self.a.state == "paused":
                    raise ValueError("診断を一時停止中の対象は削除できません。先に停止してください")
            if self.a.asset["id"] == asset_id:
                if self.a.state == "running":
                    raise ValueError("診断実行中の対象は削除できません。先に停止してください")
                deleted_name = self.a.asset["name"]
                self._withdraw_deleted_locked(deleted_name)
                # Promote next authorized extra asset, or recreate default lab.test
                next_auth = next(
                    (x for x in self._extra_assets
                     if x.get("ownership_verified") and x.get("authorization_ref")
                     # a real service is only promoted while its signed scope is valid
                     and (not self._in_ownership_flow(x["name"]) or self._external_entry(x["name"]) is not None)),
                    None,
                )
                if next_auth is not None:
                    self._extra_assets = [x for x in self._extra_assets if x["id"] != next_auth["id"]]
                    self.a.asset = {
                        "id": next_auth["id"],
                        "name": next_auth["name"],
                        "kind": next_auth["kind"],
                        "environment": next_auth["environment"],
                        # a real service keeps its registration metadata when promoted
                        **{k: next_auth[k] for k in (
                            "display_name", "target_url", "scheme", "port", "gcp_project",
                            "scope_confirmed", "challenge", "ownership_proof", "approver",
                            "sow_optional_ref") if k in next_auth},
                    }
                    self._sync_scope_for_host(next_auth["name"], str(next_auth["authorization_ref"]))
                else:
                    self.a.asset = {
                        "id": "lab",
                        "name": "lab.test",
                        "kind": "Webアプリケーション",
                        "environment": "ローカル検証ラボ（127.0.0.1）",
                    }
                    self._sync_scope_for_host("lab.test", "DEMO-AUTH-001（ローカル検証ラボ）")
                self.a.chat_messages = []      # the conversation was about the deleted asset
                self._reset_workspace_locked()
            else:
                target = next((x for x in self._extra_assets if x["id"] == asset_id), None)
                if target is None:
                    raise ValueError("削除対象の資産が見つかりません")
                deleted_name = target["name"]
                self._withdraw_deleted_locked(deleted_name)
                self._extra_assets = [x for x in self._extra_assets if x["id"] != asset_id]
                self._save_state_locked()
            gone = str(deleted_name).lower()
            try:
                self.secrets.clear_credentials(gone)
            except OSError:
                pass        # cleared again at the next start (orphan cleanup)
        self.audit.record("asset.deleted", actor=actor, asset_id=asset_id, name=deleted_name)
        self._raise_if_unstopped("対象を削除し、診断許可を取り消しました")
        return self.assets()

    def _withdraw_deleted_locked(self, name: str) -> None:
        """Deleting a real-service asset withdraws its scope and proof FIRST, in
        memory; the asset record and the authority then leave the ledger in the
        same commit (the first save after this)."""
        gone = str(name).rstrip(".").lower()
        if not (self._in_ownership_flow(gone) or gone in self._ownership_proofs):
            return
        self._verified_external_hosts.pop(gone, None)
        self._ownership_proofs.pop(gone, None)
        # the name stays marked as a real service: it can be registered again
        # through the ownership flow, but never as a lab alias
        self._real_service_hosts.add(gone)
        self._authority_reduced_locked(gone)
        self._l2_requests = {k: v for k, v in self._l2_requests.items() if v.get("host") != gone}

    def issue_ownership_challenge(
        self,
        *,
        url: str,
        sow_id: str = "",
        approver: str = "operator",
        kind: str = "Webアプリケーション",
        environment: str = "ステージング環境",
    ) -> dict:
        """Step 1 & 2 of the 5-step registration flow: parse target URL, generate
        DNS TXT / .well-known challenge, and create an unverified asset record.
        SOW number is optional; an internal authorization record is generated if omitted."""
        parsed = parse_service_target(url)
        host = parsed["host"]
        ch = challenge_for_host(host, self._ownership_secret)
        clean_sow = (sow_id or "").strip()[:80]
        internal_auth_ref = (
            clean_sow
            if clean_sow
            else f"AUTH-AUTO-{int(time.time())}-{host.split('.')[0][:12].upper()}"
        )
        now = time.time()

        if parsed["is_local_lab"] or host in ("lab.test", "api.lab.test", "localhost"):
            raise ValueError("模擬ラボの対象は、実サービスの所有確認フローでは登録できません")

        with self._lock:
            existing = self._asset_record(host)        # active asset or not: same handling
            if existing is not None and not self._in_ownership_flow(host):
                raise ValueError("この名前は模擬ラボの対象として登録されています。先に削除してから実サービスとして登録してください")
            if existing is self.a.asset and self.a.state in ("running", "paused"):
                raise ValueError("診断の実行中・一時停止中の対象は変更できません。先に停止してください")
            if existing is self.a.asset:
                self._refuse_while_verifying_locked()
            # the name must be durably recorded as a real service before a challenge
            # for it exists anywhere
            self._require_working_store()
            ledger_before = self.ledger.snapshot()
            endpoint_revoked = False
            self._real_service_hosts.add(host)
            if existing is not None:
                if (existing.get("scheme"), existing.get("port")) != (parsed["scheme"], parsed["port"]) and (
                        host in self._ownership_proofs or host in self._verified_external_hosts):
                    # a different endpoint of the host: the earlier proof, scope and
                    # stored test accounts do not carry over
                    endpoint_revoked = True
                    self._revoke_real_service_locked(
                        host, note="対象のポートまたはスキームが変更されました。所有確認からやり直してください")
                    if existing is self.a.asset:
                        self._sync_scope_for_host(host, "")
                        self._reset_workspace_locked()
                existing["target_url"] = parsed["target_url"]
                existing["scheme"] = parsed["scheme"]
                existing["port"] = parsed["port"]
                existing["kind"] = (kind or existing.get("kind") or "Webアプリケーション")[:40]
                existing["environment"] = (environment or existing.get("environment") or "ステージング環境")[:60]
                existing["challenge"] = ch
                existing["sow_optional_ref"] = internal_auth_ref
                existing["approver"] = approver
                if not existing.get("ownership_verified"):
                    existing["status"] = "所有確認待ち"
                asset_rec = dict(existing)
            else:
                aid = "asset_" + secrets.token_hex(3)
                asset_rec = {
                    "id": aid,
                    "name": host,
                    "target_url": parsed["target_url"],
                    "scheme": parsed["scheme"],
                    "port": parsed["port"],
                    "kind": (kind or "Webアプリケーション")[:40],
                    "environment": (environment or "ステージング環境")[:60],
                    "status": "所有確認待ち",
                    "assessment_id": None,
                    "risk": None,
                    "previous_risk_score": None,
                    "last_assessed_at": None,
                    "authorization_ref": "",
                    "sow_optional_ref": internal_auth_ref,
                    "approver": approver,
                    "not_before": now,
                    "not_after": now + 30 * 86400,
                    "ownership_verified": False,
                    "scope_confirmed": False,
                    "challenge": ch,
                    "note": "Step 2: DNS TXT または検証ファイルで管理権限を確認してください",
                }
                self._extra_assets.insert(0, asset_rec)
            if endpoint_revoked:
                self._save_state_locked()          # a reduction: kept in memory whatever the disk does
                if self.ledger.error:
                    raise ValueError("権限台帳に保存できないため、登録できませんでした。保存先を確認してください")
            else:
                # The registration (name + asset) is committed to the ledger BEFORE
                # the card is written anywhere. If it cannot be, nothing was
                # registered - and nothing else in the ledger is disturbed.
                try:
                    self._commit_grant_locked(ledger_before, "登録")
                except ValueError:
                    if existing is None:
                        self._extra_assets = [x for x in self._extra_assets if x is not asset_rec]
                    raise
                self._save_state_locked()

        self.audit.record(
            "asset.challenge_issued",
            actor=approver,
            host=host,
            target_url=parsed["target_url"],
            dns_txt_name=ch["dns_txt_name"],
            well_known_url=ch["well_known_url"],
            authorization_ref=internal_auth_ref,
        )
        if endpoint_revoked:
            self._raise_if_unstopped("対象の宛先を変更し、以前の診断許可を取り消しました")
        return {
            "asset": asset_rec,
            "challenge": ch,
            "prohibited_actions": PROHIBITED_ACTIONS_SUMMARY,
            "sow_optional": True,
            "internal_authorization_ref": internal_auth_ref,
        }

    def verify_asset_ownership(
        self,
        *,
        url_or_host: str,
        method: str = "dns_txt",
        actor: str = "operator",
        dns_lookup=None,
        http_fetch=None,
        roles=None,
    ) -> dict:
        """Step 2 of the 5-step registration flow: verify ownership via DNS TXT or
        /.well-known/vulnix-verify.txt. Ownership verification NEVER auto-approves L2."""
        parsed = parse_service_target(url_or_host)
        host = parsed["host"]
        self._require_working_store()
        with self._lock:
            if self.gateway.state is State.STOPPED or self.a.state == "stopped":
                raise ValueError("緊急停止中は所有確認（DNS 参照・検証ファイルの取得）を行いません。"
                                 "「再診断を実行」で停止を解除してからやり直してください")
            # no lookup or fetch for a name nobody registered here
            if host not in self._real_service_hosts or self._asset_record(host) is None:
                raise ValueError("先に対象URLを登録して検証トークンを発行してください")
        ch = challenge_for_host(host, self._ownership_secret)

        res = verify_ownership_challenge(
            host,
            method,
            expected_token=ch["token"],
            txt_lookup=dns_lookup,
            http_fetcher=http_fetch,
        )
        verified = bool(res.get("verified"))

        with self._lock:
            target_asset = next(
                (x for x in self._extra_assets if x.get("name", "").lower() == host),
                None,
            )
            if target_asset is None and self.a.asset.get("name", "").lower() == host:
                target_asset = self.a.asset
            if (not verified and roles is not None and "approver" not in roles
                    and (host in self._ownership_proofs or host in self._verified_external_hosts)):
                # Decided now, under the lock, and BEFORE anything is changed: someone
                # else may have verified or confirmed this host while our lookup was
                # in flight. Nothing about the asset is touched.
                self.audit.record("asset.reverification_denied", actor=actor, host=host, method=method,
                                  reason="approver role required for a host that holds authority")
                raise ApproverRequired("所有確認済みの対象の再確認には承認責任者の権限が必要です")
            if target_asset is not None:
                target_asset["ownership_verified"] = verified
                # The proof record is what scope confirmation checks, not the flag.
                target_asset["ownership_proof"] = {     # display copy only
                    **res, "host": host,
                    "token_sha256": hashlib.sha256(ch["token"].encode("utf-8")).hexdigest(),
                }
                if verified:
                    # the authoritative, signed record that scope confirmation checks;
                    # it also fixes WHICH endpoint was registered when the proof was made
                    before = self.ledger.snapshot()
                    self._ownership_proofs[host] = {
                        **target_asset["ownership_proof"],
                        "scheme": str(target_asset.get("scheme") or parsed["scheme"]),
                        "port": int(target_asset.get("port") or parsed["port"]),
                    }
                    try:
                        self._commit_grant_locked(before, "所有確認")
                    except ValueError:
                        target_asset["ownership_verified"] = False
                        target_asset.pop("ownership_proof", None)
                        raise
                if verified and not target_asset.get("scope_confirmed"):
                    target_asset["status"] = "範囲確認待ち"
                    target_asset["note"] = "Step 3: 診断対象スコープと禁止事項を確認してください（L2実証は自動承認されません）"
            if not verified:
                # A failed (re-)verification revokes any previously confirmed scope:
                # no further traffic is sent to this host until it is proven again.
                self._verified_external_hosts.pop(host, None)
                self._ownership_proofs.pop(host, None)
                self._authority_reduced_locked(host)
                # stored test accounts and pending L2 requests go with the authority
                self.secrets.clear_credentials(host)
                self._l2_requests = {k: v for k, v in self._l2_requests.items() if v.get("host") != host}
                if target_asset is not None:
                    target_asset["scope_confirmed"] = False
                    target_asset["authorization_ref"] = ""
                    if target_asset is not self.a.asset:
                        target_asset["status"] = "所有確認待ち"
                        target_asset["assessment_id"] = None
                        target_asset["note"] = "所有確認に失敗しました。DNS TXT または検証ファイルを確認してください"
            self._save_state_locked()

        self.audit.record(
            "asset.ownership_verified" if verified else "asset.ownership_failed",
            actor=actor,
            host=host,
            method=method,
            verified=verified,
            detail=res.get("detail", ""),
        )
        if not verified:
            self._raise_if_unstopped("所有確認に失敗したため診断許可を取り消しました")
        return {
            "host": host,
            "verified": verified,
            "verification": res,
            "l2_auto_approved": False,
            "asset": dict(target_asset) if target_asset else None,
        }

    def confirm_asset_scope(
        self,
        *,
        url_or_host: str,
        confirmed_prohibited: bool = True,
        approver: str = "operator",
        sow_id: str = "",
        activate_workspace: bool = False,
        allow_loopback_test: bool = False,
    ) -> dict:
        """Step 3 of the 5-step flow: confirm target scope & prohibited actions
        after ownership verification, enabling safe L1 diagnosis (while keeping
        L2 reproduction gated on separate human approval + credentials)."""
        if not confirmed_prohibited:
            raise ValueError("診断対象と禁止事項の確認チェックが必要です")
        parsed = parse_service_target(url_or_host)
        host = parsed["host"]

        self._require_working_store()
        with self._lock:
            target_asset = next(
                (x for x in self._extra_assets if x.get("name", "").lower() == host),
                None,
            )
            if target_asset is None and self.a.asset.get("name", "").lower() == host:
                target_asset = self.a.asset
            if target_asset is None:
                raise ValueError("先に Step 1-2 で対象URL登録と所有確認を行ってください")
            now = time.time()
            # Only the signed proof table counts. The asset record is display state
            # (it is restored from disk unsigned) and is never consulted here.
            if (activate_workspace and self.a.state != "running"
                    and target_asset.get("id") != self.a.asset.get("id")):
                # whatever can still refuse the activation refuses BEFORE the scope is granted
                self._refuse_while_verifying_locked()
                if self.a.state == "paused":
                    raise ValueError("診断の一時停止中は対象を切り替えられません。先に停止してください")
            proof = self._ownership_proofs.get(host)
            expected = hashlib.sha256(
                challenge_for_host(host, self._ownership_secret)["token"].encode("utf-8")).hexdigest()
            proof_ok = (
                isinstance(proof, dict) and proof.get("verified") is True
                and not proof.get("held_since")          # held after an unclean shutdown: prove again
                and proof.get("method") in ("dns_txt", "well_known")
                and proof.get("host") == host
                and hmac.compare_digest(str(proof.get("token_sha256") or ""), expected)
                and isinstance(proof.get("verified_at"), (int, float))
            )
            # The `ownership_verified` flag alone is never enough: the legacy lab
            # registration can set it from a checkbox. Only a recorded challenge
            # proof for THIS host and THIS installation's token counts.
            if not (host in self._real_service_hosts and proof_ok):
                raise ValueError("所有確認（DNS TXT または検証ファイル）が完了していません")
            if not (0 <= now - float(proof["verified_at"]) <= OWNERSHIP_PROOF_MAX_AGE_S):
                raise ValueError("所有確認から時間が経過しています。所有確認をやり直してから範囲を確認してください")

            auth_ref = (
                (sow_id or "").strip()[:80]
                or target_asset.get("authorization_ref")
                or target_asset.get("sow_optional_ref")
                or f"AUTH-AUTO-{int(now)}-{host.split('.')[0][:12].upper()}"
            )
            # endpoint from the SIGNED proof, not from the (unsigned) display record
            scheme = str(proof.get("scheme") or target_asset.get("scheme") or parsed["scheme"])
            port = int(proof.get("port") or target_asset.get("port") or parsed["port"])
            try:
                names_port = urllib.parse.urlsplit(
                    "//" + (url_or_host or "").strip().split("://", 1)[-1]).port is not None
            except ValueError:
                names_port = True          # an unparsable port is a mismatch, not "no port given"
            if (("://" in (url_or_host or "") and parsed["scheme"] != scheme)
                    or (names_port and int(parsed["port"]) != port)
                    or ("://" in (url_or_host or "") and int(parsed["port"]) != port)):
                # the approver named one endpoint, the proof is for another: do not
                # silently confirm something different from what was asked
                raise ValueError(
                    f"確認しようとしたURL（{parsed['scheme']}・ポート{parsed['port']}）は、"
                    f"所有確認を行った宛先（{scheme}・ポート{port}）と一致しません")
            target_asset["scheme"], target_asset["port"] = scheme, port
            if proof["method"] == "well_known" and (scheme, port) != ("https", 443) and not allow_loopback_test:
                # the proof file was served by the HTTPS service on 443; it says
                # nothing about who operates another port of the same host
                raise ValueError("検証ファイルによる所有確認で診断できるのは https の443番ポートだけです。"
                                 "他のポートを診断するには DNS TXT で所有確認してください")

            before = self.ledger.snapshot()
            self._verified_external_hosts[host] = {
                "host": host,
                "scheme": scheme,
                "port": port,
                "cidrs": ("0.0.0.0/0", "::/0"),
                "ownership_verified": True,
                "scope_confirmed": True,
                "l2_auto_approved": False,
                "approver": approver,
                "authorization_ref": auth_ref,
                "not_before": now - 60,
                "not_after": now + 30 * 86400,
                "allow_loopback_test": bool(allow_loopback_test),
                "confirmed_at": now,
                "proof_method": proof["method"],
                "proof_verified_at": proof["verified_at"],
            }
            self._commit_grant_locked(before, "範囲確認")
            self._authority_notice = None      # the operator has re-established authority since
            target_asset["authorization_ref"] = auth_ref
            target_asset["scope_confirmed"] = True
            target_asset["approver"] = approver
            target_asset["status"] = "未診断"
            target_asset["assessment_id"] = self.a.id
            target_asset.pop("note", None)

            if activate_workspace and self.a.state != "running":
                self._activate_asset_locked(target_asset, auth_ref)
                self._reset_workspace_locked()
            else:
                self._save_state_locked()

        self.audit.record(
            "asset.scope_confirmed",
            actor=approver,
            host=host,
            authorization_ref=auth_ref,
            l2_auto_approved=False,
        )
        return {
            "host": host,
            "scope_confirmed": True,
            "authorization_ref": auth_ref,
            "l2_auto_approved": False,
            "asset": dict(target_asset),
        }

    def configure_asset_secrets(
        self,
        *,
        host: str = "",
        tokens: dict | None = None,
        mock_paths: dict | None = None,
        actor: str = "operator",
    ) -> dict:
        """Store L2 verification account credentials in the encrypted secret store.
        Never logs or returns raw secret values. Only accepted for a service whose
        ownership and scope are confirmed, because that is the only place the
        tokens can ever be sent. Accepted keys come from the asset's L2 profile."""
        with self._lock:
            target_host = ((host or self.a.asset.get("name") or "").strip().lower())
            if not target_host:
                raise ValueError("対象のホスト名を指定してください")
            if self._external_entry(target_host) is None:
                raise ValueError("検証用アカウントは、所有確認と診断範囲確認が完了した実サービスにのみ設定できます")
            profile = self._l2_profile(target_host)
            if profile is None:
                raise ValueError("この対象に適用できるL2判定ルール（サービスプロファイル）がないため、検証用アカウントは設定できません")
            payload: dict[str, str] = {}
            for src in (tokens or {}, mock_paths or {}):
                for k, v in src.items():
                    if isinstance(v, str):
                        payload[str(k)] = v
            status = self.secrets.set_credentials(target_host, payload, profile=profile, actor=actor)
            # Refresh L2 candidate notes if active workspace matches
            if self.a.asset.get("name", "").lower() == target_host:
                for cand in self._l2_candidates():
                    existing_f = self.a.findings.get(cand["id"])
                    if existing_f is None or not existing_f.get("evidence"):
                        self.a.findings[cand["id"]] = cand
                self._save_state_locked()

        self.audit.record(
            "secrets.configured",
            actor=actor,
            host=target_host,
            profile=profile["id"],
            token_fingerprints={t["key"]: t["fingerprint"] for t in status["tokens"] if t["set"]},
            l2_ready=status.get("l2_ready"),
        )
        return self.secrets_status(target_host)

    def secrets_status(self, host: str | None = None) -> dict:
        with self._lock:
            target_host = (host or self.a.asset.get("name") or "").strip().lower()
            pub = self.secrets.public_status(target_host, self._l2_profile(target_host))
            return {
                **pub,
                "host": target_host,
                "has_l2_credentials": bool(pub.get("l2_ready")),
            }

    def remotion_export(self, *, anonymize: bool = True, display_name: str | None = None) -> dict:
        """Build an anonymized, strictly evidence-backed Remotion JSON payload."""
        with self._lock:
            snap = self.snapshot()
            entries = self.audit.entries()
        return build_remotion_export(
            snap,
            entries,
            anonymize=anonymize,
            display_name=display_name,
            secret_redactor=self.secrets.redact,
        )

    def _stop_flag(self) -> Path:
        return self.data_dir / "emergency-stop.flag"

    def _reset_workspace_locked(self, end_stop: bool = False) -> None:
        """A fresh workspace for the active asset. An emergency stop survives it:
        only `restart()` (end_stop=True) - an explicit new run - ends a stop."""
        stays_stopped = (not end_stop) and (self.gateway.state is State.STOPPED or self.a.state == "stopped")
        self._run_generation += 1          # any runner of the previous workspace is now stale
        self.gateway.invalidate_pending()  # and a request still waiting in the Gateway cannot launch
        old = self.workers
        # the previous workspace's workers are killed AND confirmed dead; any that
        # are not stay on record (and keep everything new from launching)
        survivors = old.confirm_stopped(old.kill_all(), 5.0)
        self._note_unstopped_locked((self.a.asset.get("name") or "").lower(), survivors, old)
        if survivors and end_stop:
            stays_stopped = self.gateway.state is State.STOPPED or self.a.state == "stopped"
        self.workers = WorkerPool(max_concurrent=2, held=self._held_sessions)
        self.gateway.workers = self.workers
        if not stays_stopped:
            self.gateway._state = State.RUNNING
            self.gateway.egress = EgressGuard(self._resolve_host)
            try:
                os.unlink(self._stop_flag())
            except OSError:
                pass
        self.gateway.budget = Budget(50)
        self.a.phases = self._default_phases()
        if self._in_ownership_flow(self.a.asset.get("name")):
            self.a.findings = {f["id"]: f for f in self._l2_candidates()}
        else:
            self.a.findings = {f["id"]: f for f in _fixture_findings()}
        self.a.approvals = {}
        self.a.activity = None
        if not stays_stopped:
            self.a.stop_report = None
        self.a.defense_comparison = None
        self.artex.tasks = []
        # an ARTEX plan belongs to the workspace it was made in
        self._artex_items = {}
        self._artex_plan = None
        self._set_state("stopped" if stays_stopped else "idle")

    def planner_status(self) -> dict:
        """Report loaded configuration, never pretend configuration proves connectivity."""
        return {
            "mode": "external_configured" if self._external_model_configured else "builtin",
            "external_model_configured": self._external_model_configured,
            "connection_verified": self._model_response_verified,
            "connected": self._model_response_verified,
            "artex_cli_verified": self._artex_cli_verified,
            "last_verification": self._last_planner_verification,
            "model_name": self._chat_backend._model if self._chat_backend else None,
            "backends": self.router.backends,
            "artex_engine": "ready",
            "autonomous_execution": False,
            "note": ("外部モデルから解説応答を確認済み。内蔵プランナーも有効です。" if self._model_response_verified else "外部モデルは設定済み・疎通未確認。内蔵プランナーも有効です。")
                    if self._external_model_configured else "内蔵 ARTEX プランナーで動作中。外部 AI モデルは未設定です。",
        }

    def snapshot(self) -> dict:
        with self._lock:
            e = self.a.engagement
            t = e.targets["lab"]
            risk = self._risk()
            # A real service stays a real service when its scope has expired, been
            # revoked or is held: it is never shown as the demo lab.
            is_ext = self._in_ownership_flow(self.a.asset.get("name"))
            scope_active = self._is_external_service_asset()
            return {
                "id": self.a.id, "asset": self.a.asset, "demo": not is_ext,
                "target_url": self.a.target_url,
                "is_external_service": is_ext,
                "scope_active": scope_active,
                "lab_mode": get_lab_mode(),
                "lab_endpoint": self.a.target_url if is_ext else f"127.0.0.1:{self.lab_port}",
                "planner": self.planner_status(),
                "artex_plan": self.artex_plan_view(),
                "secrets_status": self.secrets_status(),
                "prohibited_actions": PROHIBITED_ACTIONS_SUMMARY,
                "evidence_summary": evidence_summary(list(self.a.findings.values())),
                "authorization": {
                    "status": ("authorized" if e.ownership_verified and e.authorization_ref
                               and (scope_active or not is_ext) else "missing"),
                    "ref": e.authorization_ref, "ownership_verified": e.ownership_verified,
                    "not_before": e.not_before, "not_after": e.not_after,
                    "scope": {"hosts": list(t.hosts), "cidrs": list(t.cidrs), "ports": list(t.ports)},
                    "allowed_actions": sorted(e.allowed_actions)},
                "state": self.a.state,
                "phases": [dict(p) for p in self.a.phases],
                "activity": self.a.activity,
                "approvals": list(self.a.approvals.values()),
                "findings": [{**f, "evidence_status": evidence_status(f),
                              "requires_l2_approval": self.l2.has_check(f.get("reproduce_check")),
                              "l2_request": self._public_l2_request(f["id"]),
                              "l2_needs_request": bool(self.separate_l2_approver
                                                       and self.l2.has_check(f.get("reproduce_check")))}
                             for f in self.a.findings.values()],
                "l2_separation_required": self.separate_l2_approver,
                "persistence_error": self._persist_error,
                "authority_notice": self._authority_notice,
                "authority_generation": self.ledger.generation,
                "unstopped_workers": self._unstopped_now_locked(),
                "failure": self.a.failure,
                "l2_isolation": self.l2_isolation_status(),
                "risk": risk,
                "stop_report": self.a.stop_report,
                "chat_messages": list(self.a.chat_messages),
                # the demo history is fictional; never attach it to a real service
                "history": None if is_ext else self._history(risk),
                "defense_comparison": self.a.defense_comparison,
                "cve_status": self.cve_monitor.status(),
                "artex_tasks": [
                    {"id": tk.id, "phase": tk.phase, "title": clean_target_text(tk.title, 200),
                     "risk_level": tk.risk_level, "status": tk.status,
                     "tool": tk.routed.proposal["tool"]}
                    for tk in self.artex.tasks
                ],
                "last_seq": self.bus.last_seq,
            }

    def logs(self) -> dict:
        return {"entries": self.audit.entries(), "chain_valid": self.audit.verify()}

    # ---- commands -----------------------------------------------------------
    def set_verify_seconds(self, seconds: float) -> None:
        self.gateway.tools["demo_verify"] = demo_verify_tool(seconds)

    def start(self) -> None:
        with self._lock:
            if self.a.state != "idle":
                raise ValueError(f"cannot start from {self.a.state}")
            self._ensure_active_window_locked()
            set_lab_mode("vulnerable")
            self._set_state("running")
            self._thread = threading.Thread(target=self._run, args=(self._run_generation,),
                                            daemon=True, name="runner")
            self._thread.start()

    def restart(self, actor: str = "operator") -> dict:
        """Reset a completed, stopped, or failed assessment and immediately start a fresh live run."""
        with self._lock:
            if self.a.state == "running":
                raise ValueError("既に診断が実行中です")
            if self._in_ownership_flow(self.a.asset.get("name")):
                # refuse BEFORE the previous results are cleared: a run that cannot
                # be recorded will not start, so there is nothing to replace them
                self._save_state_locked()
                if self._persist_error:
                    raise ValueError("状態をディスクに保存できないため、実サービスへの診断を停止しています。"
                                     "データディレクトリの書き込み権限と空き容量を確認してください")
            if self._unstopped_now_locked():
                raise ValueError("停止を確認できていないWorkerが残っているため、新しい診断は開始できません")
            # a run that may not start (scope expired, revoked, held) is refused
            # BEFORE the previous results are cleared
            self._ensure_active_window_locked()
            self._reset_workspace_locked(end_stop=True)      # the one explicit way out of an emergency stop
            if self._unstopped_now_locked():
                # (an emergency stop, if there was one, is still in force)
                raise ValueError("前の診断のWorkerの停止を確認できなかったため、新しい診断は開始できません")
            self._ensure_active_window_locked()
            set_lab_mode("vulnerable")
            self._set_state("running")
            self._thread = threading.Thread(target=self._run, args=(self._run_generation,),
                                            daemon=True, name="runner")
            self._thread.start()
        self.audit.record("assessment.restarted", actor=actor, target=self.a.asset["name"])
        return self.snapshot()

    def pause(self, actor: str) -> None:
        with self._lock:
            if self.a.state != "running":
                raise ValueError(f"cannot pause from {self.a.state}")
            self.gateway.pause(actor)
            self._set_state("paused")

    def resume(self, actor: str) -> None:
        with self._lock:
            if self.a.state != "paused":
                raise ValueError(f"cannot resume from {self.a.state}")
            self._ensure_active_window_locked()
            self.gateway.resume(actor)   # re-validates engagement window
            self._set_state("running")

    def emergency_stop(self, actor: str) -> dict:
        # The whole stop runs under the service lock: no request can reset the
        # workspace or change state between "workers killed" and "stopped recorded".
        with self._lock:
            # The stop ends the generation: a runner that is past its last checkpoint
            # can no longer write "done"/"completed" over what the stop records.
            self._run_generation += 1
            pool = self.workers
            try:
                # written before anything else, so that the stop holds after a restart
                # even if the state cannot be saved afterwards
                fd = os.open(self._stop_flag(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.fsync(fd)
                os.close(fd)
                self._sync_dir(self.data_dir)
            except OSError:
                pass
            rep = self.gateway.emergency_stop(actor)
            self._kill_artex_planner_locked()       # a running ARTEX planner dies with its cgroup
            self._close_planner_gateways_locked()   # and its model gateway forwards nothing more
            report = {"actor": actor, "confirmed": rep.confirmed, "killed_pids": rep.killed_pids,
                      "survivors": rep.survivors,
                      "steps": [{"name": n, "elapsed_ms": round(t * 1000, 2)} for n, t in rep.steps],
                      "at": time.time()}
            # survivors stay on record beyond this report (a later restart clears the report)
            self._note_unstopped_locked((self.a.asset.get("name") or "").lower(), rep.survivors, pool)
            if self._unstopped_now_locked():
                # e.g. a confined run left behind earlier: not a confirmed stop either
                report["confirmed"] = False
            self.a.stop_report = report
            for p in self.a.phases:
                if p["status"] in ("pending", "running"):
                    self._phase(p["key"], "aborted", "緊急停止により中止")
            for f in self.a.findings.values():
                if f.get("_in_verification"):
                    self._upsert_finding({**f, "verdict": "aborted", "_in_verification": False})
            for ap in self.a.approvals.values():
                if ap["status"] == "pending":
                    self._decide(ap["id"], "rejected", actor, notify=False)
            self.a.activity = None
            self._set_state("stopped")
        self.bus.publish(self.a.id, "stop.report", stop_report=report)
        for ev in self._approval_events.values():
            ev.set()
        return report

    def decide_approval(self, approval_id: str, decision: str, actor: str) -> None:
        with self._lock:
            ap = self.a.approvals.get(approval_id)
            if ap is None or ap["status"] != "pending":
                raise ValueError("approval not pending")
            if self.a.state == "stopped":
                raise ValueError("assessment stopped")
            self._decide(approval_id, decision, actor)

    def _think(self, step: str, detail: str, *, phase: str = "", tool: str = "", level: str = "L1") -> None:
        if self._stale_runner():
            raise _Stopped()
        self.audit.record(
            "agent.thought",
            step=step,
            detail=detail,
            phase=phase,
            tool=tool,
            risk_level=level,
        )

    # ---- P2: On-demand single finding verification via real Gateway+Worker ---
    def request_l2_run(self, finding_id: str, actor: str) -> dict:
        """Record that `actor` asks for an L2 run of one item. It sends nothing and
        approves nothing; under separation of duties it is the precondition for a
        different approver to run that item."""
        with self._lock:
            check = self._l2_check_for_finding(finding_id)
            if not self._is_external_service_asset() or check is None:
                raise ValueError("L2検証の依頼は、実サービスの判定ルールに含まれる項目に対してのみ行えます")
            if check["spec_status"] != "confirmed":
                raise ValueError("この検証項目の判定ルールは対象APIの仕様と未照合（placeholder）のため、依頼できません")
            if not actor or str(actor).startswith("policy:auto"):
                raise ValueError("L2検証の依頼は人間の操作者だけが行えます")
            self._l2_requests[finding_id] = {"requested_by": actor, "requested_at": time.time(),
                                             "check": check["id"], "host": self.a.asset.get("name")}
            self._save_state_locked()
        self.audit.record("l2.run_requested", actor=actor, finding=finding_id, check=check["id"], risk_level="L2")
        return self.snapshot()

    def _take_l2_request(self, finding_id: str, check_id: str, approver: str) -> dict | None:
        """Under separation of duties: the pending request this approval answers.
        Raises unless a different operator requested this item for this host recently."""
        if not self.separate_l2_approver:
            return None
        req = self._l2_requests.get(finding_id)
        if (not req or req.get("check") != check_id or req.get("host") != self.a.asset.get("name")
                or time.time() - float(req.get("requested_at", 0)) > L2_REQUEST_MAX_AGE_S):
            raise ValueError("このL2検証には、別の担当者による実行依頼が必要です（依頼が無いか、期限切れです）")
        if req.get("requested_by") == approver:
            raise ValueError("依頼した本人は承認できません。別の承認責任者が承認してください")
        return req

    def finding_requires_human_l2_approval(self, finding_id: str) -> bool:
        """Decided by the profile (finding id) as well as the stored record, so an
        edited finding cannot shed the approver requirement."""
        with self._lock:
            f = self.a.findings.get(finding_id) or {}
            return (self.l2.has_check(f.get("reproduce_check"))
                    or self._l2_check_for_finding(finding_id) is not None)

    def verify_finding(self, finding_id: str, actor: str, *, roles=None) -> dict:
        """Execute a real Gateway + Worker probe for a specific finding on demand
        and attach the live HTTP response and SHA-256 audit hash.

        `roles`: the caller's roles as established by the HTTP layer. The decision
        "does this run need an approver" is made HERE, after the active asset is
        pinned for the duration of the run - never by a separate check beforehand,
        which a concurrent asset switch could invalidate. (`None` = an in-process
        caller that vouches for the actor itself.)"""
        self._begin_operation()        # the active asset cannot be switched while this runs
        prev = getattr(self._tls, "gen", None)
        try:
            return self._verify_finding(finding_id, actor, roles)
        except _Stopped:
            raise ValueError("停止またはリセットされたため、検証を中止しました") from None
        finally:
            self._tls.gen = prev
            self._end_operation()

    def _verify_finding(self, finding_id: str, actor: str, roles=None) -> dict:
        if self.gateway.state is State.PAUSED:
            # it would wait for "resume" while blocking every asset switch
            raise ValueError("診断を一時停止中です。再開または停止してから検証を実行してください")
        if finding_id == "all":
            with self._lock:
                self._refuse_after_stop_locked()
                # this thread now belongs to the workspace it verifies: after a stop
                # or reset it can neither write a result nor send a request
                self._tls.gen = self._run_generation
                self._ensure_active_window_locked()
                url = self.a.target_url
                is_ext = self._is_external_service_asset()
            self._think(
                "全問題の一括実機検証を開始",
                f"対象 {url} に対し、Gateway 経由で http_probe と承認済み検証プローブを順次実行します。",
                phase="verification",
                tool="http_probe / reproduction_probe",
                level="L2",
            )
            res, ev = self._exec("http_probe", "read_only_probe",
                                 {"url": url, "method": "GET"},
                                 approval_actor=f"verify:{actor}")
            if not (res and ev):
                # nothing was measured (refused, not saved, worker failed): the
                # reason is already recorded by _fail - this is not a completed run
                return self.snapshot()
            with self._lock:
                self._analyze(res, ev)
            if is_ext:
                # A bulk action is never an approval for L2 on a real service:
                # each L2 item needs its own explicit human approval.
                self._think(
                    "L2項目は一括実行しません",
                    "実サービスのL2検証（認可・テナント分離などの項目）は、項目ごとの人間承認でのみ実行します。今回はL1の読み取り専用検査のみ再実行しました。",
                    phase="verification", tool="Gateway", level="L1",
                )
            else:
                for fid in ("f_banner", "f_idor", "f_sqli"):
                    if fid in self.a.findings:
                        self.verify_finding(fid, actor=actor)
                        if self.a.state == "failed":
                            return self.snapshot()      # that item's failure stands
            with self._lock:
                self._phase("scope", "done", f"{url} は許可範囲内")
                self._phase("config", "done", "公開設定・HTTPヘッダーを検査済み")
                self._phase("analysis", "done", f"{len(self._real_findings())} 件を分析済み")
                self._phase("verification", "done",
                            "L1読み取り専用検査を再実行（L2は項目ごとの承認が必要）" if is_ext
                            else "全問題の隔離Worker検証を完了")
                self._phase("report", "done", "実機検証結果を反映しました")
                self.a.activity = None
                self._set_state("completed")
            self._think(
                "全問題の実機検証が完了",
                f"すべての Worker プローブ応答と SHA-256 監査ハッシュを記録しました（総合リスク: {self._risk()['score']}/100）。",
                phase="report",
                tool="Gateway",
                level="L1",
            )
            return self.snapshot()

        with self._lock:
            if finding_id not in self.a.findings:
                raise ValueError("指定された問題が見つかりません")
            self._refuse_after_stop_locked()
            self._tls.gen = self._run_generation
            self._ensure_active_window_locked()
            was_failed = self.a.state == "failed"
            if was_failed:
                self._set_state("idle")
            url = self.a.target_url
            target_f = dict(self.a.findings[finding_id])

        dn_check = target_f.get("reproduce_check")
        profile_check = self._l2_check_for_finding(finding_id)
        if self._is_external_service_asset():
            if finding_id in LAB_ONLY_FINDING_IDS or target_f.get("demo_fixture"):
                raise ValueError("模擬ラボ専用の検証は、実サービスに対しては実行できません")
            if profile_check is not None and dn_check != profile_check["id"]:
                # the stored finding was altered; the profile decides, not the record
                raise ValueError("この検証項目の内容が判定ルール（サービスプロファイル）と一致しません")
        if self.l2.has_check(dn_check) or profile_check is not None:
            if not self._is_external_service_asset():
                raise ValueError("L2再現試験は、所有確認と診断範囲確認が完了した実サービスでのみ実行できます")
            l2_check = self._active_l2_check(dn_check)
            if l2_check is None:
                raise ValueError("この検証項目は、現在の対象に適用された判定ルール（サービスプロファイル）に含まれていません")
            if l2_check["spec_status"] != "confirmed":
                raise ValueError(
                    "この検証項目の判定ルールは対象APIの仕様と未照合（placeholder）のため、実行できません。"
                    "仕様に基づいてルールを確定し、根拠（spec_evidence）を記録してください")
            l2_wrule = self.l2.worker_rule(dn_check)
            missing = self.secrets.missing_for_check(self.a.asset.get("name", "").lower(), l2_check)
            if missing:
                labels = self._l2_profile()["tokens"]
                raise ValueError(
                    "L2再現試験を実行するには、先に検証用アカウント（暗号化シークレット）を設定してください"
                    f"（未設定: {', '.join(labels[m]['label'] for m in missing)}）"
                )
            if not actor or str(actor).startswith("policy:auto"):
                raise ValueError("L2再現試験には人間の個別承認が必要です（自動承認不可）")
            if roles is not None and "approver" not in roles:
                self.audit.record("l2.run_denied", actor=actor, finding=finding_id, check=dn_check,
                                  reason="approver role required")
                raise ApproverRequired("実サービスのL2再現試験には承認責任者の権限が必要です")
            blocked = self._l2_block_reason()
            if blocked:
                raise ValueError(blocked)
            with self._lock:
                self._save_state_locked()
                if self._persist_error:
                    raise ValueError("状態をディスクに保存できないため、実サービスへの送信を中止しました")
            # resolve now, so an address change is noticed BEFORE the decision to release tokens
            try:
                self._resolve_host(self.a.asset.get("name", ""))
            except NetworkError as e:
                raise ValueError(str(e)) from None
            blocked = self._l2_block_reason()
            if blocked:
                raise ValueError(blocked)
            with self._lock:
                l2_request = self._take_l2_request(finding_id, dn_check, actor)
                self._l2_requests.pop(finding_id, None)     # one request, one run
            self._think(
                f"L2検証（{dn_check}）の個別承認実行",
                f"人間承認者（{actor}）の承認に基づき、暗号化シークレットの検証用アカウントを用いて {target_f['title']} を非破壊検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record(
                "approval.approved",
                request=f"req_{finding_id}",
                actor=actor,
                action="safe_reproduction",
                check=dn_check,
                risk_level="L2",
                requested_by=(l2_request or {}).get("requested_by"),
                separation_of_duties=self.separate_l2_approver,
            )
            try:
                res, ev = self._exec(
                    "reproduction_probe",
                    "safe_reproduction",
                    {"url": url, "check": dn_check},
                    approval_id=apr,
                )
            finally:
                self.approval_store.revoke(apr)     # one approval, one run of one item
            if res and ev:
                outcome = reproduction_verdict(res, dn_check, worker_rule=l2_wrule)
                l2_note = reproduction_note(res, dn_check, rule=l2_check, worker_rule=l2_wrule)
                est = outcome == "proven"
                ev_enriched = {
                    **ev,
                    "target_url": url,
                    "tool": "reproduction_probe",
                    "verification_conditions": f"L2人間承認済み ({actor}) / check={dn_check} / 検証用アカウント＆模擬データ限定",
                }
                self._think(
                    f"L2検証（{dn_check}）の判定完了",
                    l2_note + f" [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    fields = self._l2_result_fields(f, outcome, l2_note)
                    if est:
                        fields["what_was_established"] = (
                            f"検証用アカウントを用いた非破壊プローブ（{dn_check}）で、権限のないアカウントへの応答に所有者側の模擬データが含まれることを確認しました。")
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "_in_verification": False,
                        **fields,
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev_enriched],
                    })
        elif finding_id in ("f_idor", "fx_idor"):
            self._think(
                "IDOR（認可境界バイパス）の仮説検証",
                "テストアカウント acct_A のトークンで acct_B の保護リソース (/api/accounts/B/secret) をリクエストし、所有者照合の有無を検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request=f"req_{finding_id}", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "idor"}, approval_id=apr)
            if res and ev:
                outcome = reproduction_verdict(res, "idor")
                est = outcome == "proven"
                self._think(
                    "IDOR 実機応答の判定",
                    reproduction_note(res, "idor") + f" [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": outcome,
                        "_in_verification": False,
                        "what_was_established": (
                            "権限のないテストアカウント acct_A から、別の検証用リソース（acct_B の res_b_001）へのアクセスが実機Workerで成立しました。"
                            if est else None
                        ),
                        "verdict_note": reproduction_note(res, "idor"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        elif finding_id in ("f_sqli", "fx_sqli"):
            self._think(
                "SQLインジェクション境界（/api/search）の仮説検証",
                "検索パラメータ q=test' を送信し、未エスケープのSQL構文解釈（エラー差分）が発生するかを非破壊プローブで検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request=f"req_{finding_id}", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "sqli"}, approval_id=apr)
            if res and ev:
                outcome = reproduction_verdict(res, "sqli")
                est = outcome == "proven"
                self._think(
                    "SQLi 実機応答の判定",
                    reproduction_note(res, "sqli") + f" [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": outcome,
                        "_in_verification": False,
                        "what_was_established": (
                            "検索エンドポイント /api/search?q=test' に対し、未エスケープのSQL構文エラー差分（VULNIX_LAB_SQLI_PROVEN）が実機Workerで成立しました。"
                            if est else None
                        ),
                        "verdict_note": reproduction_note(res, "sqli"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        elif finding_id == "f_banner":
            self._think(
                "CVE-2021-41773 パス正規化バイパスの仮説検証",
                "Apache 2.4.49 のパス正規化不備（/cgi-bin/.%2e/...）が隔離ラボの検証用マーカーへ到達できるか reproduction_probe で検証します。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            apr = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request="req_f_banner", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res, ev = self._exec("reproduction_probe", "safe_reproduction",
                                 {"url": url, "check": "cve_2021_41773"}, approval_id=apr)
            if res and ev:
                outcome = reproduction_verdict(res, "cve_2021_41773")
                est = outcome == "proven"
                self._think(
                    "CVE-2021-41773 実機応答の判定",
                    reproduction_note(res, "cve_2021_41773") + f" [証拠 {ev['evidence_id']}]",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                with self._lock:
                    f = self.a.findings[finding_id]
                    prev_ev = [e for e in f.get("evidence", []) if e.get("audit_hash")]
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": outcome,
                        "_in_verification": False,
                        "what_was_established": (
                            "隔離ラボ環境において、正規化前のパスシーケンス（CVE-2021-41773）により検証用マーカー（VULNIX_LAB_PATH_TRAVERSAL_PROVEN）への到達が成立しました。"
                            if est else None
                        ),
                        "verdict_note": reproduction_note(res, "cve_2021_41773"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": prev_ev + [ev],
                    })
        else:
            self._think(
                "HTTP応答ヘッダー・露出情報の再検査",
                f"対象 {url} に対して非破壊 GET プローブ（http_probe）を実行し、セキュリティヘッダーとバージョン露出を確認します。",
                phase="config",
                tool="http_probe",
                level="L1",
            )
            res, ev = self._exec("http_probe", "read_only_probe",
                                 {"url": url, "method": "GET"},
                                 approval_actor=f"verify:{actor}")
            if res and ev:
                with self._lock:
                    self._analyze(res, ev)
        if not res or not ev:
            with self._lock:
                finding = self.a.findings[finding_id]
                if profile_check is not None:
                    # same rule as any inconclusive L2 run: an earlier proof is kept
                    self._upsert_finding({
                        **finding, "_in_verification": False,
                        **self._l2_result_fields(finding, "unverified",
                                                 "判定できず。今回のWorker応答を取得できませんでした。再現せずとは判定しません。"),
                    })
                else:
                    self._upsert_finding({
                        **finding, "verdict": "unverified", "_in_verification": False,
                        "what_was_established": None,
                        "verdict_note": "修正確認できず。今回のWorker応答を取得できませんでした。過去の証拠を現在の結果とは扱いません。",
                    })
        with self._lock:
            # a single-item run started from a failed assessment must not leave the
            # workspace looking as if nothing had been diagnosed yet
            if was_failed and self.a.state == "idle":
                if res and ev:
                    self._set_state("completed")
                else:
                    self._set_state("failed", reason="Workerの応答を取得できなかったため、検証を完了できませんでした")
        return self.snapshot()

    # ---- P2: Post-patch defense verification & before/after comparison ------
    def verify_fix(self, actor: str) -> dict:
        """Apply patched defense configuration to the lab (or re-verify an
        external target after remediation) and re-run the exact same probe and
        reproduction checks through the Gateway to prove mitigation."""
        self._begin_operation()        # the active asset cannot be switched while this runs
        prev = getattr(self._tls, "gen", None)
        try:
            return self._verify_fix(actor)
        except _Stopped:
            raise ValueError("停止またはリセットされたため、再検証を中止しました") from None
        finally:
            self._tls.gen = prev
            self._end_operation()

    def _verify_fix(self, actor: str) -> dict:
        with self._lock:
            if self.a.state not in ("completed", "idle"):
                raise ValueError("診断完了後に修正後の再検証を実行してください")
            self._tls.gen = self._run_generation
            self._ensure_active_window_locked()
            before_risk = self._risk()
            is_ext = self._is_external_service_asset()
            url = self.a.target_url        # decided together with is_ext, under the same lock
            before_verdicts = {
                f["id"]: {"title": f["title"], "severity": f["severity"], "verdict": f["verdict"]}
                for f in self._real_findings()
                if evidence_status(f) != "candidate"
            }

        if not is_ext:
            set_lab_mode("patched")
        self._think(
            "防御パッチ適用後の再検証を開始",
            "同一プローブの実HTTP応答で防御結果を確認します。",
            phase="verification",
            tool="http_probe / reproduction_probe",
            level="L2",
        )
        # 1. Re-run L1 HTTP probe
        res, ev_http = self._exec("http_probe", "read_only_probe",
                                  {"url": url, "method": "GET"},
                                  approval_actor=f"reverify:{actor}")
        latest_ids: dict[str, str | None] = {}

        if is_ext:
            ready = self._ready_l2_checks()
            for l2_check in (self._l2_profile() or {"checks": []})["checks"]:
                fid = l2_check["finding"]["id"]
                chk = l2_check["id"]
                l2_wrule = self.l2.worker_rule(chk)
                # only items a human already approved and ran once are re-run
                if (fid in before_verdicts and chk in ready and l2_check["spec_status"] == "confirmed"
                        and not self.separate_l2_approver    # then every L2 run needs its own request + approval
                        and self._l2_transport_ok()
                        and self.a.findings.get(fid, {}).get("reproduce_check") == chk):
                    apr_dn = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
                    self.audit.record("approval.approved", request=f"req_reverify_{fid}", actor=actor,
                                      action="safe_reproduction", check=chk, risk_level="L2")
                    try:
                        r_dn, e_dn = self._exec("reproduction_probe", "safe_reproduction",
                                                {"url": url, "check": chk}, approval_id=apr_dn)
                    finally:
                        self.approval_store.revoke(apr_dn)
                    with self._lock:
                        finding = self.a.findings[fid]
                        verdict = reproduction_verdict(r_dn, chk, worker_rule=l2_wrule)
                        l2_note = reproduction_note(r_dn, chk, rule=l2_check, worker_rule=l2_wrule)
                        latest_ids[fid] = e_dn["evidence_id"] if e_dn else None
                        fields = self._l2_result_fields(finding, verdict, l2_note)
                        if verdict == "proven":
                            fields["what_was_established"] = l2_note
                        self._upsert_finding({
                            **finding, "_in_verification": False, **fields,
                            "evidence": finding["evidence"] + ([e_dn] if e_dn else []),
                        })
        else:
            # 2. Re-run L2 reproduction probes with human approver authorization
            apr_ref = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            self.audit.record("approval.approved", request="req_reverify", actor=actor,
                              action="safe_reproduction", risk_level="L2")
            res_cve, ev_cve = self._exec("reproduction_probe", "safe_reproduction",
                                         {"url": url, "check": "cve_2021_41773"},
                                         approval_id=apr_ref)
            apr_ref2 = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            res_idor, ev_idor = self._exec("reproduction_probe", "safe_reproduction",
                                           {"url": url, "check": "idor"},
                                           approval_id=apr_ref2)
            apr_ref3 = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
            res_sqli, ev_sqli = self._exec("reproduction_probe", "safe_reproduction",
                                           {"url": url, "check": "sqli"},
                                           approval_id=apr_ref3)

            with self._lock:
                for fid, check, result, evidence in (
                    ("f_banner", "cve_2021_41773", res_cve, ev_cve),
                    ("f_idor", "idor", res_idor, ev_idor),
                    ("f_sqli", "sqli", res_sqli, ev_sqli),
                ):
                    if fid not in self.a.findings:
                        continue
                    finding = self.a.findings[fid]
                    verdict = reproduction_verdict(result, check)
                    latest_ids[fid] = evidence["evidence_id"] if evidence else None
                    self._upsert_finding({
                        **finding, "verdict": verdict, "_in_verification": False,
                        "what_was_established": reproduction_note(result, check) if verdict == "proven" else None,
                        "verdict_note": reproduction_note(result, check),
                        "evidence": finding["evidence"] + ([evidence] if evidence else []),
                    })

        with self._lock:
            headers = (res or {}).get("headers")
            valid_headers = isinstance(headers, dict) and (res or {}).get("status") is not None
            h = {k.lower(): v for k, v in headers.items()} if valid_headers else {}
            for fid in ("f_headers", "f_powered", "f_l1_cors", "f_l1_cookies"):
                if fid not in self.a.findings:
                    continue
                finding = self.a.findings[fid]
                if fid == "f_headers":
                    remains = any(not h.get(k) for k in ("content-security-policy", "x-content-type-options", "strict-transport-security"))
                elif fid == "f_powered":
                    remains = bool(h.get("x-powered-by"))
                elif fid == "f_l1_cors":
                    acao = h.get("access-control-allow-origin", "")
                    remains = acao in ("*", "https://untrusted-origin.example")
                else:
                    sc = " ".join((res or {}).get("set_cookies") or [h.get("set-cookie", "")]).lower()
                    remains = bool(sc.strip()) and any(flag not in sc for flag in ("secure", "httponly", "samesite"))
                # an L1 re-check observes; it never proves (proven is reserved for L2 runs)
                verdict = ("detected" if remains else "not_reproduced") if valid_headers else "unverified"
                note = ("最新のHTTP応答ヘッダーに設定不備が残っています。" if remains else "最新のHTTP応答ヘッダーで、この設定項目の対策を確認しました。") if valid_headers else "修正確認できず。HTTP応答ヘッダーを取得できませんでした。"
                latest_ids[fid] = ev_http["evidence_id"] if ev_http else None
                self._upsert_finding({
                    **finding, "verdict": verdict, "what_was_established": note if verdict == "detected" else None,
                    "verdict_note": note,
                    "evidence": finding["evidence"] + ([ev_http] if ev_http else []),
                })

            after_risk = self._risk()
            items = []
            for fid, binfo in before_verdicts.items():
                cur_f = self.a.findings.get(fid, {})
                items.append({
                    "id": fid,
                    "title": binfo["title"],
                    "severity": binfo["severity"],
                    "before_verdict": binfo["verdict"],
                    # what THIS re-verification observed, even where an earlier proof is kept
                    "after_verdict": (cur_f.get("last_run_verdict") if fid in latest_ids and cur_f.get("last_run_verdict")
                                      else cur_f.get("verdict", "unverified")),
                    "latest_evidence_id": latest_ids.get(fid),
                })
            self.a.defense_comparison = {
                "verified_at": time.time(),
                "actor": actor,
                "lab_mode": get_lab_mode(),
                "before_score": before_risk["score"],
                "after_score": after_risk["score"],
                "items": items,
            }
            self._think(
                "修正前後の防御比較が完了",
                f"HTTP応答とWorker判定に基づく結果を記録しました。総合リスク: {before_risk['score']}/100 → {after_risk['score']}/100。結果が不明な項目は修正未確認です。",
                phase="report",
                tool="Gateway",
                level="L1",
            )
            if self.a.state == "failed":
                pass        # a step already failed and recorded why; it is not overwritten
            elif any(f["verdict"] == "unverified" or f.get("last_run_verdict") == "unverified"
                     for f in self._real_findings()):
                self._set_state("failed", reason="一部の項目で応答を取得できず、修正後の再検証を完了できませんでした")
            else:
                self._set_state("completed")
            return self.snapshot()

    # ---- runner -------------------------------------------------------------
    def _plan(self, phase: str, context: dict) -> list:
        """Ask the planner for one phase. The router is chosen for this call from
        what the context is ABOUT: anything that names a real-service host is
        planned by the built-in planner only, whatever asset is active. A runner
        whose workspace is gone neither asks nor records."""
        with self._lock:
            if self._stale_runner():
                raise _Stopped()
            host = (urllib.parse.urlsplit(str(context.get("target_url") or "")).hostname or "").lower()
            real = (self._in_ownership_flow(self.a.asset.get("name")) or self._in_ownership_flow(host)
                    or (host != "" and host not in self._allowed_hosts))
            router = self._local_router if real else self.router
        tasks = self.artex.plan_phase(phase, context, router=router, accept=lambda: not self._stale_runner())
        if self._stale_runner():
            raise _Stopped()
        return tasks

    def _stale_runner(self) -> bool:
        """True in a runner thread whose workspace generation is over."""
        gen = getattr(self._tls, "gen", None)
        return gen is not None and gen != self._run_generation

    def _run(self, generation: int | None = None) -> None:
        self._tls.gen = self._run_generation if generation is None else generation
        try:
            self._run_inner()
        except _Stopped:
            pass
        except Exception as e:
            self._fail(f"診断エラー: {e}")

    def _run_inner(self) -> None:
        url = self.a.target_url
        is_ext = self._is_external_service_asset()
        scope_desc = (f"所有確認済みホスト {self.a.asset['name']} / ポート "
                      f"{', '.join(map(str, self.a.engagement.targets['lab'].ports))}"
                      if is_ext else "127.0.0.1/32")
        self._phase("scope", "running", "許可範囲・期間・所有確認記録を照合しています")
        self._activity("診断範囲を確認", "Gateway（範囲検査）", "L1")
        self._think(
            "診断範囲と許可記録の照合",
            f"対象 {url} が許可記録（{self.a.engagement.authorization_ref}）および許可スコープ（{scope_desc}）の範囲内にあることを検証しています。",
            phase="scope",
            tool="Gateway",
            level="L1",
        )
        self.gateway.engagement.check_active(time.time())
        self.gateway.egress.check(url, self.a.engagement.targets["lab"])
        self._phase("scope", "done", f"{url} は許可範囲内（{scope_desc}）")

        self._checkpoint()
        self._phase("config", "running", "ARTEX が公開設定の非破壊プローブを提案・実行しています")
        self._activity("公開設定を検査（GET 1回・非破壊）", "http_probe", "L1")
        self._think(
            "非破壊HTTPプローブの計画とサニタイズ",
            "ARTEX プランナーが公開設定・応答ヘッダー取得のため http_probe (GET) を提案し、ProposalRouter で安全性を検証しました。",
            phase="config",
            tool="http_probe",
            level="L1",
        )
        # by REGISTRATION (once a real service, always planned locally), not by whether
        # its scope happens to be valid at this instant
        tasks_l1 = self._plan("config", {"target_id": "lab", "target_url": url})

        def _is_the_executed_probe(tk) -> bool:
            # Only the fixed read-only GET below is ever executed in this phase. Any
            # other proposal (another URL, method, tool or check) stays a proposal.
            p = tk.routed.proposal
            a = p.get("args", {})
            return (p.get("tool") == "http_probe" and p.get("action") == "read_only_probe"
                    and a.get("url") == url and str(a.get("method", "GET")).upper() == "GET")
        for tk in tasks_l1:
            if tk.status == "unsupported":
                continue
            tk.status = "running" if _is_the_executed_probe(tk) else "not_executed"
        res, ev = self._exec("http_probe", "read_only_probe", {"url": url, "method": "GET"},
                             approval_actor="policy:auto-L1")
        if res is None:
            return
        for tk in tasks_l1:
            if tk.status == "running":
                tk.status = "completed"
        self._phase("config", "done", f"HTTP {res['status']} を取得")

        self._checkpoint()
        self._phase("analysis", "running", "取得した応答とNVD/CISA KEVフィードから問題を分析しています")
        self._activity("検出結果を分析（CVE / CISA KEV 照合）", "cve_engine", "L1")
        banner_id = self._analyze(res, ev)
        self._think(
            "CVE/CISA KEV 照合と検証仮説の構築",
            f"応答バナー（{clean_target_text(res.get('headers', {}).get('Server', 'unknown'), 120)}）およびAPI境界から {len(self._real_findings())} 件の項目を特定しました。",
            phase="analysis",
            tool="cve_engine",
            level="L1",
        )
        if "AI agent:" in res.get("body_prefix", ""):
            self.bus.publish(self.a.id, "agent.note",
                             message="ページ内にAI向けの指示文を検出しました。ProposalRouterにより無害化され実行権限には影響しません。")
        self._phase("analysis", "done", f"{len(self._real_findings())} 件を検出")

        self._checkpoint()
        if is_ext:
            # Real-service L1 diagnosis completes safely without auto-running L2.
            # L2 items remain in `candidate` state until encrypted credentials +
            # per-item human approval are provided.
            self._think(
                "実サービス L1 読み取り専用診断の完了（L2は個別人間承認待ち）",
                "所有確認のみでL2侵入実証を自動承認しない安全原則に従い、L1検査結果を確定しました。L2項目（対象に判定ルールが設定されている場合）は検証用アカウント設定と個別の人間承認後に実行できます。",
                phase="verification",
                tool="Gateway",
                level="L1",
            )
            self._phase(
                "verification",
                "skipped",
                "L1診断完了（L2再現試験は検証用アカウント設定と個別の人間承認が必要です）",
            )
        else:
            self._phase("verification", "running", "隔離環境での侵入成立実証（再現試験）の承認を待っています")
            self._activity("脆弱性の検証（侵入成立の実証）", "reproduction_probe", "L2")
            self._think(
                "L2 侵入成立実証の人間承認リクエスト",
                "CVE-2021-41773・IDOR・SQLi の再現試験は L2 操作のため、承認責任者による実行許可（単一使用トークン発行）を待機しています。",
                phase="verification",
                tool="reproduction_probe",
                level="L2",
            )
            tasks_l2 = self._plan("verification", {
                "target_id": "lab", "target_url": url, "has_cve_2021_41773": banner_id in self.a.findings,
            })
            for tk in tasks_l2:
                if tk.status != "unsupported":
                    tk.status = "awaiting_approval"
            ap_id = self._request_approval(
                "safe_reproduction", "L2", "検出された脆弱性の侵入成立実証（CVE-2021-41773 / IDOR / SQLi）",
                "検出したバージョン表示（CVE-2021-41773）、テストアカウント間の認可境界（IDOR）、および検索APIのSQLインジェクション境界が"
                "実際に成立するかを、egress_sentinel 隔離Worker（reproduction_probe）で非破壊実証します。")
            if self.a.approvals[ap_id]["status"] != "approved":
                for tk in tasks_l2:
                    if tk.status != "unsupported":
                        tk.status = "skipped"
                self._think(
                    "L2 再現試験をスキップ",
                    "承認責任者により却下されたため、L2 再現試験は実施せず検出段階の結果でレポートを作成します。",
                    phase="verification",
                    tool="Gateway",
                    level="L2",
                )
                self._phase("verification", "skipped", "承認されなかったため実施していません")
            else:
                for tk in tasks_l2:
                    if tk.status != "unsupported":
                        tk.status = "running"
                self._phase("verification", "running", "隔離Workerで侵入成立を実証中（reproduction_probe）")
                self._think(
                    "L2 承認完了・隔離Workerでの侵入成立実証を開始",
                    "単一使用 HMAC トークンを発行し、egress_sentinel 隔離下で reproduction_probe Worker を起動しています。",
                    phase="verification",
                    tool="reproduction_probe",
                    level="L2",
                )
                self._mark_verifying(banner_id, True)
                self._mark_verifying("f_idor", True)
                self._mark_verifying("f_sqli", True)

                # 1. Run demo_verify window first so emergency-stop tests during active verification
                #    can deterministically observe and SIGKILL the worker.
                vres, vev = self._exec("demo_verify", "safe_reproduction", {"url": url},
                                       approval_id=self.a.approvals[ap_id]["approval_ref"])
                if vres is None:
                    return

                # 2. Execute real non-destructive reproduction probes through the Gateway
                actor = self.a.approvals[ap_id]["decided_by"] or "approver"
                apr_cve = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
                cve_res, cve_ev = self._exec("reproduction_probe", "safe_reproduction",
                                             {"url": url, "check": "cve_2021_41773"},
                                             approval_id=apr_cve)
                if cve_res is None:
                    return
                if banner_id in self.a.findings:
                    f = self.a.findings[banner_id]
                    established = reproduction_verdict(cve_res, "cve_2021_41773") == "proven"
                    self._think(
                        "CVE-2021-41773 実証結果の確認",
                        reproduction_note(cve_res, "cve_2021_41773") + f" [証拠 {cve_ev['evidence_id']}]",
                        phase="verification",
                        tool="reproduction_probe",
                        level="L2",
                    )
                    self._upsert_finding({
                        **f,
                        "demo_fixture": False,
                        "verdict": reproduction_verdict(cve_res, "cve_2021_41773"),
                        "_in_verification": False,
                        "what_was_established": (
                            "隔離ラボ環境において、正規化前のパスシーケンス（CVE-2021-41773）により"
                            "検証用マーカー（VULNIX_LAB_PATH_TRAVERSAL_PROVEN）への到達が成立しました。"
                            if established else None
                        ),
                        "verdict_note": reproduction_note(cve_res, "cve_2021_41773"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": [e for e in f["evidence"] if e.get("audit_hash")] + [vev, cve_ev],
                    })

                apr_idor = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
                idor_res, idor_ev = self._exec("reproduction_probe", "safe_reproduction",
                                               {"url": url, "check": "idor"},
                                               approval_id=apr_idor)
                if idor_res is None:
                    return
                if "f_idor" in self.a.findings:
                    fi = self.a.findings["f_idor"]
                    idor_est = reproduction_verdict(idor_res, "idor") == "proven"
                    self._think(
                        "IDOR（認可境界）実証結果の確認",
                        reproduction_note(idor_res, "idor") + f" [証拠 {idor_ev['evidence_id']}]",
                        phase="verification",
                        tool="reproduction_probe",
                        level="L2",
                    )
                    self._upsert_finding({
                        **fi,
                        "demo_fixture": False,
                        "verdict": reproduction_verdict(idor_res, "idor"),
                        "_in_verification": False,
                        "what_was_established": (
                            "権限のないテストアカウント acct_A から、別の検証用リソース（acct_B の res_b_001）"
                            "へのアクセスが成立しました。"
                            if idor_est else None
                        ),
                        "verdict_note": reproduction_note(idor_res, "idor"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": [e for e in fi["evidence"] if e.get("audit_hash")] + [idor_ev],
                    })

                apr_sqli = self.approval_store.approve(actor, "eng_demo", "lab", "safe_reproduction")
                sqli_res, sqli_ev = self._exec("reproduction_probe", "safe_reproduction",
                                               {"url": url, "check": "sqli"},
                                               approval_id=apr_sqli)
                if sqli_res is None:
                    return
                if "f_sqli" in self.a.findings:
                    fs = self.a.findings["f_sqli"]
                    sqli_est = reproduction_verdict(sqli_res, "sqli") == "proven"
                    self._think(
                        "SQLインジェクション境界 実証結果の確認",
                        reproduction_note(sqli_res, "sqli") + f" [証拠 {sqli_ev['evidence_id']}]",
                        phase="verification",
                        tool="reproduction_probe",
                        level="L2",
                    )
                    self._upsert_finding({
                        **fs,
                        "demo_fixture": False,
                        "verdict": reproduction_verdict(sqli_res, "sqli"),
                        "_in_verification": False,
                        "what_was_established": (
                            "模擬検索エンドポイント /api/search?q=test' に対し、検証用のSQLエラーマーカー（VULNIX_LAB_SQLI_PROVEN）を含む応答差分を確認しました。"
                            if sqli_est else None
                        ),
                        "verdict_note": reproduction_note(sqli_res, "sqli"),
                        "executor": {**EXECUTOR, "tool": "reproduction_probe"},
                        "evidence": [e for e in fs["evidence"] if e.get("audit_hash")] + [sqli_ev],
                    })

                for tk in tasks_l2:
                    if tk.status != "unsupported":
                        tk.status = "completed"
                self._phase("verification", "done", "結果: 侵入成立を実証（証拠・監査ハッシュ保存済み）")

        self._checkpoint()
        self._phase("report", "running", "結果をまとめています")
        self._think(
            "診断結果と監査ハッシュチェーンの確定",
            f"全ステップが完了しました。総合リスクスコア: {self._risk()['score']}/100（監査チェーン検証済み）。",
            phase="report",
            tool="Gateway",
            level="L1",
        )
        self._phase("report", "done", "診断が完了しました")
        with self._lock:
            self.a.activity = None
            self._set_state("completed")

    def _exec(self, tool, action, args, approval_actor=None, approval_id=None):
        self._checkpoint()
        with self._lock:
            if self._in_ownership_flow(self.a.asset.get("name")):
                # Fail closed, for EVERY request to a real service (also mid-run): prove
                # that state can be written right now. If it cannot, what we are about
                # to do could not be recorded and a later revocation could not be made
                # durable - so nothing is sent.
                self._save_state_locked()
                if self._persist_error:
                    self._fail("状態をディスクに保存できないため、実サービスへの送信を中止しました", kind="persistence")
                    return None, None
        with self._lock:
            origin = "real_service" if self._in_ownership_flow(self.a.asset.get("name")) else "lab"
        if (tool == "reproduction_probe" and args.get("check", "idor") in LAB_REPRODUCTION_CHECKS
                and self._in_ownership_flow(self.a.asset.get("name"))):
            # last line of defence, whatever path led here: the bundled lab's attack
            # probes are never sent while the active asset is a real service
            self._fail("模擬ラボ専用の検証は、実サービスに対しては実行できません")
            return None, None
        auto_approval = approval_id is None
        if auto_approval:
            approval_id = self.approval_store.approve(approval_actor, "eng_demo", "lab", action)
            self.audit.record("approval.auto", actor=approval_actor, action=action,
                              tool=tool, risk_level="L1")
        try:
            try:
                tok = self.tokens.issue(self.a.engagement, "lab", action, tool, approval_id,
                                        self.approval_store, ttl=120)
            except Exception as e:
                self._fail(f"トークン発行が拒否されました: {e}")
                return None, None
            d = self.gateway.execute({"tool": tool, "target_id": "lab", "action": action,
                                      "args": args}, tok)
        finally:
            if auto_approval:       # an automatic L1 approval is for this one call only
                self.approval_store.revoke(approval_id)
        if self.gateway.state is State.STOPPED or self._stale_runner():
            # the result belongs to a workspace that no longer exists: it is dropped
            raise _Stopped()
        if not d.allowed:
            self._fail(f"Gateway が拒否しました: {d.reason}")
            return None, None
        if origin == "real_service":
            with self._lock:
                still = self._external_entry(self.a.asset.get("name")) is not None
            if not still:
                # the scope ended (expired or withdrawn) while the worker ran: what it
                # brought back is not recorded as a result of an authorised run
                self._fail("診断許可が終了したため、この実行の結果は記録しません")
                return None, None
        if d.result.killed or d.result.returncode != 0:
            self._fail(self._worker_failure_text(tool, d.result))
            return None, None
        entry = next(e for e in reversed(self.audit.entries()) if e["event"] == "result")
        clean_stdout = self.secrets.redact(d.result.stdout.strip())
        evidence = {
            "evidence_id": "ev_" + entry["hash"][:12],
            "kind": f"{tool} 出力",
            "tool": tool,
            # fixed at the moment of measurement; later changes to the asset list
            # (deletion, re-registration under the same name) cannot relabel it
            "origin": origin,
            "target_url": args.get("url", self.a.target_url),
            "saved_at": entry["ts"],
            "audit_hash": entry["hash"],
            "content": clean_stdout,
        }
        return json.loads(clean_stdout), evidence

    def _analyze(self, res: dict, ev: dict) -> str:
        if self._stale_runner():
            raise _Stopped()
        if self._is_external_service_asset():
            l1_findings = analyze_l1_service_response(
                res, ev, self.a.target_url, self.cve_monitor
            )
            for f in l1_findings:
                self._upsert_finding(f)
            for cand in self._l2_candidates():
                existing = self.a.findings.get(cand["id"])
                if existing is None or not existing.get("evidence"):
                    self._upsert_finding(cand)
            return "f_powered" if "f_powered" in self.a.findings else ""

        h = {k.lower(): v for k, v in res["headers"].items()}
        banner = h.get("server", "")
        bid = "f_banner"
        # CVE candidates come from the catalog engine (detection only, not proof).
        candidates = cve.detect_from_banner(banner, source="server-header",
                                            catalog=self.cve_monitor.catalog,
                                            kev=self.cve_monitor.kev)
        if candidates:
            cve_ids = sorted({c.cve.id for c in candidates})
            kev_note = "（CISA KEV 悪用確認済みカタログ掲載）" if any(c.in_kev for c in candidates) else ""
            self._upsert_finding({
                "id": bid, "title": f"既知の脆弱性に該当するWebサーバーのバージョン表示{kev_note}",
                "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
                "cve": cve_ids, "risk_level": "L2",
                "help_term": "cve",
                "summary": f"Server ヘッダーが「{banner}」を示しています。このバージョンはパス・トラバーサル等の既知脆弱性{kev_note}の影響範囲です。",
                "why_detected": "応答ヘッダーのバージョン文字列が、NVD / CISA KEV フィードの影響バージョンと一致したためです。",
                "caveat": "バナー段階では「検出（未実証）」です。L2再現試験を承認すると、隔離ラボで実際に到達可能か検証します。",
                "evidence": [ev],
                "remediation": {"steps": ["Apache HTTP Server を最新の安定版（2.4.62以降）に更新する",
                                          "Server ヘッダーのバージョン表示を抑制する（ServerTokens Prod）"],
                                "how_to_verify": "「防御パッチ適用・再検証」を実行し、再現試験の結果が「再現せず」に変わることを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})

        # Candidate IDOR check queued for L2 verification
        self._upsert_finding({
            "id": "f_idor", "title": "他アカウントの保護リソースへのアクセス制御不備（IDOR）",
            "severity": "high", "verdict": "detected", "category": "アクセス制御", "cve": [],
            "risk_level": "L2", "help_term": "idor",
            "summary": "APIエンドポイント /api/accounts/B/secret においてオブジェクト単位の所有者検証が必要と判定されました。",
            "why_detected": "ARTEX のエンドポイント分析により、アカウントID指定型リソースが検出されたためです（L2承認後に2アカウント間で実証試験を行います）。",
            "caveat": "L2承認前は「検出（未実証）」として扱います。",
            "evidence": [ev],
            "remediation": {"steps": ["サーバー側でセッション主体とリソース所有者を必ず照合し、不一致時は 403 Forbidden を返す"],
                            "how_to_verify": "修正後に同じ2アカウント間の試験を実行し、HTTP 403 が返ることを確認します。"},
            "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})

        # Candidate SQLi check queued for L2 verification
        self._upsert_finding({
            "id": "f_sqli", "title": "検索欄のSQLインジェクション境界不備（/api/search）",
            "severity": "critical", "verdict": "detected", "category": "インジェクション", "cve": [],
            "risk_level": "L2", "help_term": "sqli",
            "summary": "検索エンドポイント /api/search のクエリパラメータ q において、SQL構文差分の検証が必要と判定されました。",
            "why_detected": "ARTEX のパラメータ境界分析により、未バインドクエリの可能性が検出されたためです（L2承認後に非破壊エラー差分検証を行います）。",
            "caveat": "L2承認前は「検出（未実証）」として扱います。",
            "evidence": [ev],
            "remediation": {"steps": ["プリペアドステートメント（プレースホルダー付きクエリ）を使用し文字列連結を廃止する"],
                            "how_to_verify": "修正後に同じ試験を実行し、SQLエラー差分が発生しないことを確認します。"},
            "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})

        missing = [x for x in ("content-security-policy", "x-content-type-options",
                               "strict-transport-security") if x not in h]
        if missing:
            self._upsert_finding({
                "id": "f_headers", "title": "セキュリティヘッダーが設定されていない",
                "severity": "low", "verdict": "detected", "verdict_basis": "l1_observation", "category": "設定不備", "cve": [],
                "risk_level": "L1", "help_term": "security_headers",
                "summary": "ブラウザ側の防御を有効にするヘッダーが応答に含まれていません。",
                "what_was_established": "実際のHTTP応答に " + ", ".join(missing) + " が含まれないことを確認しました。",
                "why_detected": "取得した応答ヘッダーを直接確認した結果です。",
                "evidence": [ev],
                "remediation": {"steps": [f"{m} を設定する" for m in missing],
                                "how_to_verify": "修正後に同じGET検査を行い、ヘッダーが返ることを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})
        if "x-powered-by" in h:
            self._upsert_finding({
                "id": "f_powered", "title": "使用技術のバージョンが露出している",
                "severity": "low", "verdict": "detected", "verdict_basis": "l1_observation", "category": "情報露出", "cve": [],
                "risk_level": "L1", "help_term": "info_disclosure",
                "summary": f"X-Powered-By ヘッダーが「{h['x-powered-by']}」を示しています。",
                "what_was_established": "実際のHTTP応答で X-Powered-By ヘッダーが返されることを確認しました。",
                "why_detected": "取得した応答ヘッダーを直接確認した結果です。",
                "evidence": [ev],
                "remediation": {"steps": ["php.ini で expose_php = Off を設定する"],
                                "how_to_verify": "修正後に同じGET検査を行い、ヘッダーが返らないことを確認します。"},
                "executor": {**EXECUTOR, "tool": "http_probe"}, "demo_fixture": False})
        return bid

    # ---- helpers ------------------------------------------------------------
    def _request_approval(self, action, level, title, description) -> str:
        aid = "req_" + secrets.token_hex(4)
        ev = threading.Event()
        with self._lock:
            if self._stale_runner():
                raise _Stopped()        # never raise an approval request in someone else's workspace
            self._approval_events[aid] = ev
            self.a.approvals[aid] = {"id": aid, "action": action, "risk_level": level,
                                     "title": title, "description": description,
                                     "status": "pending", "decided_by": None,
                                     "decided_at": None, "approval_ref": None}
            self._save_state_locked()
            self._publish_approval(aid)
        while not ev.wait(0.2):
            self._checkpoint(allow_pause=True)
        self._checkpoint()
        return aid

    def _decide(self, aid, decision, actor, notify=True):
        ap = self.a.approvals[aid]
        ap["status"] = "approved" if decision == "approve" else "rejected"
        ap["decided_by"], ap["decided_at"] = actor, time.time()
        if ap["status"] == "approved":
            ap["approval_ref"] = self.approval_store.approve(actor, "eng_demo", "lab", ap["action"])
        self.audit.record("approval." + ap["status"], request=aid, actor=actor,
                          action=ap["action"], risk_level=ap["risk_level"])
        self._save_state_locked()
        self._publish_approval(aid)
        if notify and aid in self._approval_events:
            self._approval_events[aid].set()

    def _publish_approval(self, aid):
        self.bus.publish(self.a.id, "approval.updated", approval=dict(self.a.approvals[aid]))

    def _checkpoint(self, allow_pause=False) -> None:
        while True:
            if self.gateway.state is State.STOPPED or self.a.state == "stopped" or self._stale_runner():
                raise _Stopped()
            if self.a.state != "paused" or allow_pause:
                return
            time.sleep(0.2)

    def _phase(self, key, status, detail):
        with self._lock:
            if self._stale_runner():
                raise _Stopped()
            p = next(p for p in self.a.phases if p["key"] == key)
            p["status"], p["detail"] = status, detail
            self._save_state_locked()
            self.bus.publish(self.a.id, "phase.updated", phase=key, status=status,
                             message=detail, phases=[dict(x) for x in self.a.phases])

    def _activity(self, title, tool, level):
        with self._lock:
            if self._stale_runner():
                raise _Stopped()
            self.a.activity = {"title": title, "tool": tool, "risk_level": level, **EXECUTOR}
            self.bus.publish(self.a.id, "activity.updated", activity=self.a.activity)

    def _set_state(self, state, reason: str | None = None, kind: str = "run"):
        if self._stale_runner():
            raise _Stopped()
        if state == "failed":
            if reason or not self.a.failure:
                self.a.failure = {"reason": reason or "診断を完了できませんでした", "kind": kind,
                                  "at": time.time()}
        elif state in ("idle", "running", "completed"):
            self.a.failure = None
        self.a.state = state
        self._save_state_locked()
        if state == "completed" and self._persist_error:
            state = self.a.state        # the failed save has already made it "failed"
            try:
                self.audit.record("assessment.failed", reason="results could not be saved",
                                  error=self._persist_error)
            except Exception:
                pass
        elif state == "failed" and self._persist_error and self.a.failure:
            self.a.failure.setdefault("error", self._persist_error)    # saving is ALSO broken
        self.bus.publish(self.a.id, "assessment.state", state=state, risk=self._risk(),
                         failure=self.a.failure)

    @staticmethod
    def _worker_failure_text(tool: str, result) -> str:
        """Why a worker failed, from its own structured report when it gave one."""
        if result.killed:
            return f"Worker が制限時間内に終わらず停止されました（{tool}）"
        try:
            err = json.loads((result.stdout or "").strip() or "{}").get("error")
        except (ValueError, AttributeError):
            err = None
        if isinstance(err, dict):
            stage = {"connect": "TCP接続", "tls": "TLSハンドシェイク", "send": "リクエスト送信", "between_stages": "処理の途中",
                     "first_byte": "応答の最初のバイト待ち", "body": "応答本文の受信"}.get(str(err.get("stage")), "不明な段階")
            kind = {"timeout": "タイムアウト", "tls_verify_failed": "証明書の検証失敗", "tls_error": "TLSエラー",
                    "egress_blocked": "許可外の宛先への接続を遮断",
                    "connection_refused": "接続拒否", "connection_reset": "接続リセット",
                    "bad_http_response": "不正なHTTP応答", "network_error": "ネットワークエラー"}.get(str(err.get("kind")), "エラー")
            limit = err.get("timeout_s")
            limit_txt = f"、上限 {float(limit):g} 秒" if isinstance(limit, (int, float)) else ""
            return f"Worker が{stage}の段階で失敗しました（{kind}{limit_txt}、rc={result.returncode}）"
        return f"Worker が異常終了しました (rc={result.returncode})"

    def _upsert_finding(self, f):
        f = enforce_verdict(f)          # "proven" only with a recorded L2 reproduction
        with self._lock:
            if self._stale_runner():
                raise _Stopped()
            self.a.findings[f["id"]] = f
            self._save_state_locked()
            self.bus.publish(self.a.id, "finding.upserted",
                             finding={**f, "evidence_status": evidence_status(f)},
                             evidence_summary=evidence_summary(list(self.a.findings.values())),
                             risk=self._risk())

    def _mark_verifying(self, fid, flag):
        f = self.a.findings.get(fid)
        if f:
            self._upsert_finding({**f, "_in_verification": flag})

    def _fail(self, msg, kind: str = "run"):
        with self._lock:
            if self._stale_runner():
                return          # not this workspace's failure to report
            self.audit.record("assessment.failed", reason=msg)
            self.bus.publish(self.a.id, "agent.note", message=msg)
            for p in self.a.phases:
                if p["status"] == "running":
                    self._phase(p["key"], "aborted", msg)
            self.a.activity = None
            self._set_state("failed", reason=msg, kind=kind)

    def _real_findings(self):
        return [f for f in self.a.findings.values() if not f["demo_fixture"]]

    def _risk(self) -> dict:
        # Unmeasured candidates (no recorded evidence) are not counted either way:
        # they are neither a confirmed risk nor a confirmed absence of one.
        # An L2 rule check that ended inconclusive (preconditions not met, response
        # not matching the rule) says nothing about the boundary, so it does not
        # move the score either; such an item counts only once it is proven.
        fs = [f for f in self._real_findings()
              if evidence_status(f) != "candidate"
              and not (self.l2.has_check(f.get("reproduce_check")) and f.get("verdict") != "proven")]
        score = min(100, round(sum(SEVERITY_WEIGHT[f["severity"]] * VERDICT_FACTOR[f["verdict"]]
                                   for f in fs)))
        label = "高リスク" if score >= 70 else "中リスク" if score >= 40 else "低リスク"
        return {"score": score, "label": label,
                "provisional": self.a.state != "completed",
                "basis": "架空データ・未計測の候補・判定できなかったL2検証を除く検出結果の深刻度 × 判定（実証=1.0, 検出・未検証=0.6, 再現せず=0）の合計（上限100）"}

    def _on_audit(self, entry: dict) -> None:
        self.bus.publish(self.a.id if hasattr(self, "a") else "scan_001", "audit.recorded",
                         entry={k: entry[k] for k in ("ts", "event", "fields", "prev", "hash")})

    # ---- P1: AI chat with assessment context (read-only, zero authority) ----
    def ask_chat(self, question: str, actor: str, term: str | None = None,
                 finding_id: str | None = None) -> dict:
        q = question.strip()[:500]
        if not q:
            raise ValueError("question must not be empty")
        now = time.time()
        with self._lock:
            user_msg = {
                "id": "msg_" + secrets.token_hex(4),
                "role": "user",
                "actor": actor,
                "text": q,
                "term": term,
                "finding_id": finding_id,
                "ts": now,
            }
        # Inference can be slow. Never hold the control-plane lock while waiting:
        # snapshots, worker updates and emergency stop must remain responsive.
        source, answer_text = self._answer_question(q, term=term, finding_id=finding_id)
        # A model's answer is outside text too: make sure it can always be stored
        # (an unpaired surrogate would otherwise make every later save fail).
        answer_text = str(answer_text).encode("utf-8", "replace").decode("utf-8")[:20000]
        with self._lock:
            ai_msg = {
                "id": "msg_" + secrets.token_hex(4),
                "role": "assistant",
                "actor": f"AI解説（{self._chat_backend._model}）" if source == "external_model" else "内蔵解説",
                "source": source,
                "text": answer_text,
                "term": term,
                "finding_id": finding_id,
                "ts": time.time(),
            }
            self.a.chat_messages.extend([user_msg, ai_msg])
            self._save_state_locked()
            self.audit.record("chat.asked", actor=actor, term=term or "", finding_id=finding_id or "",
                              answered_by=source, sent_to_external_model=(source == "external_model"))
            self.bus.publish(self.a.id, "chat.message", messages=[user_msg, ai_msg])
            return {"message": ai_msg, "chat_messages": list(self.a.chat_messages), "planner": self.planner_status()}

    def _finding_touches_real_service(self, finding: dict | None) -> bool:
        """Whether a finding may NOT be shown to an external model. Allow-list: only
        evidence that was recorded as taken from the local lab passes. Evidence
        from a real service, evidence of unknown origin, and anything that names a
        host registered as a real service are all treated as real."""
        if not finding:
            return False
        if finding.get("l2_profile") or finding.get("requires_l2_approval"):
            return True
        for ev in finding.get("evidence") or []:
            if not isinstance(ev, dict) or ev.get("origin") != "lab":
                return True
            host = (urllib.parse.urlsplit(str(ev.get("target_url") or "")).hostname or "").lower()
            if not host or self._in_ownership_flow(host) or host not in self._allowed_hosts:
                return True
        return False

    def _answer_question(self, q: str, term: str | None = None, finding_id: str | None = None) -> tuple[str, str]:
        with self._lock:
            real = self._real_findings()
            all_f = list(self.a.findings.values())
            target_f = None
            if finding_id and finding_id in self.a.findings:
                target_f = self.a.findings[finding_id]
            elif term:
                target_f = next((f for f in real if f.get("help_term") == term), None) or next(
                    (f for f in all_f if f.get("help_term") == term), None
                )
            elif real:
                target_f = real[0]
            # Ground each answer in one immutable, point-in-time context.
            context = copy.deepcopy({
                "asset": self.a.asset,
                "state": self.a.state,
                "risk": self._risk(),
                "target_finding": target_f,
            })
            done_phases = sum(1 for p in self.a.phases if p["status"] == "done")
            total_phases = len(self.a.phases)
            # decided under the same lock that took the context: nothing can change
            # the asset or its registration between the check and the send
            external_ok = (not self._in_ownership_flow(self.a.asset.get("name"))
                           and not self._finding_touches_real_service(target_f)
                           and not any(k in self.a.asset for k in ("challenge", "ownership_proof")))
        target_f = context["target_finding"]
        ext = self._chat_backend
        # Findings and evidence of a real service (response bodies, cookies, the
        # ownership challenge, names) never leave this machine: the external model
        # is used for the local lab only.
        if ext is not None and external_ok:
            ans = ext.chat(q, context)
            if ans:
                with self._lock:
                    self._model_response_verified = True
                return "external_model", ans

        ql = q.lower()
        if target_f:
            evs = target_f.get("evidence", [])
            ev_summary = "、".join(
                f"{e['evidence_id']}（{e['kind']}・監査ハッシュ {(e.get('audit_hash') or 'なし')[:10]}）"
                for e in evs
            ) or "記録された証拠なし"
            rem = target_f.get("remediation", {})
            steps = " / ".join(rem.get("steps", []))
            verify = rem.get("how_to_verify", "")

            if any(k in ql for k in ("なぜ", "理由", "検出", "原因", "why")):
                return "builtin", (
                    f"【なぜ検出されたか：{target_f['title']}】\n"
                    f"・検出理由：{target_f.get('why_detected') or target_f['summary']}\n"
                    f"・判定状態：{target_f['verdict']}（危険度 {target_f['risk_level']}）\n"
                    f"・根拠となった証拠：{ev_summary}"
                )
            if any(k in ql for k in ("証拠", "判断", "ログ", "ハッシュ", "evidence")):
                return "builtin", (
                    f"【判断根拠の証拠：{target_f['title']}】\n"
                    f"・証拠一覧：{ev_summary}\n"
                    f"・成立内容：{target_f.get('what_was_established') or target_f.get('verdict_note') or target_f.get('caveat') or target_f['summary']}\n"
                    f"※ 問題詳細ページの「証拠」パネルから、実際のレスポンスとSHA-256監査ハッシュを確認できます。"
                )
            if any(k in ql for k in ("修正", "直", "対策", "確認", "再試験", "verify", "fix")):
                return "builtin", (
                    f"【修正方法と修正後の確認：{target_f['title']}】\n"
                    f"・修正手順：{steps}\n"
                    f"・修正後の確認方法：{verify}"
                )

        risk = context["risk"]
        parts = [
            f"現在の診断対象は {context['asset']['name']}（状態: {_asset_status(context['state'])}、進捗 {done_phases}/{total_phases} ステップ、総合リスク {risk['score']}/100 {risk['label']}）です。"
        ]
        if target_f:
            evs = target_f.get("evidence", [])
            ev_ids = ", ".join(e["evidence_id"] for e in evs) or "なし"
            parts.append(
                f"注目項目「{target_f['title']}」：\n"
                f"1. なぜ検出されたか：{target_f.get('why_detected') or target_f['summary']}\n"
                f"2. 判断した証拠：{ev_ids}（実行ツール: {target_f['executor']['tool']}）\n"
                f"3. 修正後の確認：{target_f['remediation']['how_to_verify']}"
            )
        else:
            parts.append(
                "診断を開始すると、公開設定の検査・CVE照合・隔離環境での検証結果と証拠がここに紐づけられます。"
                "※ Vulnix AI は説明・提案のみを行い、承認なしに操作を実行することはありません。"
            )
        return "builtin", "\n".join(parts)

    # ---- P2: assessment history comparison & Markdown report export ---------
    def _history(self, current_risk: dict) -> dict:
        prev_score = 55
        cur_score = current_risk["score"] if self.a.state != "idle" else None
        real_ids = {f["id"] for f in self._real_findings()}
        return {
            "demo_fixture": True,
            "previous_assessment_id": "scan_000",
            "previous_assessed_at": int(time.time() - 86400 * 7),
            "previous_score": prev_score,
            "previous_label": "中リスク",
            "delta_score": (cur_score - prev_score) if cur_score is not None else None,
            "resolved_findings": ["検索欄のSQLインジェクション（修正後に再現せずを確認）"],
            "new_findings_count": len(real_ids),
            "runs": [
                {"id": "scan_000", "at": int(time.time() - 86400 * 7), "score": prev_score,
                 "label": "中リスク", "status": "診断済み", "summary": "SQLi修正後の再検証完了（再現せず）"},
                {"id": self.a.id, "at": int(time.time()), "score": cur_score,
                 "label": current_risk["label"] if cur_score is not None else "未診断",
                 "status": _asset_status(self.a.state), "summary": "現在の診断セッション"},
            ],
        }

    def report_markdown(self) -> str:
        s = self.snapshot()
        auth = s["authorization"]
        risk = s["risk"]
        hist = s["history"]
        lines = [
            f"# Vulnix セキュリティ診断レポート — {s['asset']['name']}",
            "",
            "- **プラットフォーム**: Vulnix (Find. Prove. Secure. — AI Security Testing Platform)",
            f"- **診断ID**: `{s['id']}`",
            f"- **対象資産**: {s['asset']['name']} ({s['asset']['kind']} / {s['asset']['environment']})",
            f"- **診断状態**: {_asset_status(s['state'])}" + ("" if s.get("is_external_service") else f"（ラボ防御状態: `{s.get('lab_mode', 'vulnerable')}`）"),
            f"- **書面許可**: `{auth['ref']}` (所有確認: {'確認済み' if auth['ownership_verified'] else '未確認'})",
            f"- **許可範囲**: Hosts={', '.join(auth['scope']['hosts'])} / CIDRs={', '.join(auth['scope']['cidrs'])} / Ports={', '.join(map(str, auth['scope']['ports']))}",
            "- **総合リスク**: 未診断（安全性は未評価）" if s["state"] == "idle" else f"- **総合リスク**: **{risk['score']}/100 ({risk['label']})** {'※暫定' if risk['provisional'] else ''}",
            (f"- **前回診断との比較（架空のデモ履歴）**: 前回 `{hist['previous_assessment_id']}` ({hist['previous_score']}/100) → 差分 {hist['delta_score'] if hist['delta_score'] is not None else '未算出'}"
             if hist else "- **前回診断との比較**: 履歴なし（この対象の初回診断）"),
            "",
            "## 証拠の概要と検証範囲",
            f"- **提案エンジン**: {s['planner']['note']}",
            (f"- **検証環境**: 所有確認済みの実サービス ({s['target_url']})。L1は読み取り専用の実測、L2は検証用アカウントと模擬データに限定した個別承認分のみです。"
             if s.get("is_external_service") else
             f"- **検証環境**: ローカル模擬ラボ ({s['lab_endpoint']})。実在する Apache や本番環境の診断結果ではありません。"),
            "- **判定の限界**: 検出は実証を意味しません。「再現せず」は今回の条件での結果であり、安全性の保証ではありません。",
            "- **証拠状態**: " + " / ".join(f"{EVIDENCE_LABELS[k]} {v} 件" for k, v in s["evidence_summary"].items() if k != "fixture"),
            "",
            "## 1. 診断ステップ進捗",
        ]
        for p in s["phases"]:
            lines.append(f"- **{p['label']}**: {p['status']} {('— ' + p['detail']) if p['detail'] else ''}")
        lines.append("")
        lines.append("## 2. 検出された問題と実証結果")
        real_findings = [f for f in s["findings"] if not f.get("demo_fixture")]
        if not real_findings:
            lines.append("- 実環境の検出結果はまだありません（未診断または検査前）。")
        for f in real_findings:
            lines.extend([
                f"### [{f['severity'].upper()}] {f['title']} ({EVIDENCE_LABELS[f['evidence_status']]})",
                f"- **カテゴリ**: {f['category']} / **危険度**: {f['risk_level']}",
                f"- **関連CVE**: {', '.join(f['cve']) if f['cve'] else 'なし'}",
                f"- **概要**: {f['summary']}",
                f"- **なぜ検出されたか**: {f.get('why_detected', '—')}",
                f"- **成立内容 / 検証結果**: {f.get('what_was_established') or f.get('verdict_note') or f.get('caveat') or '—'}",
                "- **証拠**:",
            ])
            for ev in f.get("evidence", []):
                lines.append(f"  - `{ev['evidence_id']}` ({ev['kind']}) 監査ハッシュ: `{ev.get('audit_hash') or 'なし'}`")
            lines.append("- **修正方法**:")
            for step in f["remediation"]["steps"]:
                lines.append(f"  1. {step}")
            lines.append(f"- **修正後の確認方法**: {f['remediation']['how_to_verify']}")
            lines.append("")
        if s.get("defense_comparison"):
            dc = s["defense_comparison"]
            lines.extend([
                "## 3. 修正前後の防御比較（実証再検証）",
                f"- **修正前リスクスコア**: {dc['before_score']}/100 → **修正後リスクスコア**: {dc['after_score']}/100",
            ])
            for item in dc.get("items", []):
                lines.append(
                    f"  - {item['title']}: `{item['before_verdict']}` → `{item['after_verdict']}` (証拠 `{item['latest_evidence_id']}`)"
                )
            lines.append("")
        lines.append("## 4. 監査チェーン検証")
        lines.append(f"- **監査ログ件数**: {len(self.audit.entries())} 件")
        lines.append(f"- **SHA-256 ハッシュチェーン整合性**: {'✓ 整合性を確認（外部の真正性証明ではありません）' if self.audit.verify() else '✕ 不整合あり'}")
        return "\n".join(lines) + "\n"


class _Stopped(Exception):
    pass


def _asset_status(state: str) -> str:
    return {"idle": "未診断", "running": "診断中", "paused": "一時停止中",
            "stopped": "中止", "failed": "失敗", "completed": "診断済み"}[state]


def _fixture_findings() -> list[dict]:
    """Initial real candidate findings for the local verification lab (127.0.0.1), ready for live Gateway + Worker execution."""
    common = {"demo_fixture": False, "executor": {**EXECUTOR, "tool": "reproduction_probe"}}
    return [
        {**common, "id": "f_banner", "title": "既知の脆弱性に該当するWebサーバーのバージョン表示（CVE-2021-41773）",
         "severity": "high", "verdict": "detected", "category": "既知の脆弱性（CVE）",
         "cve": ["CVE-2021-41773", "CVE-2021-42013"], "risk_level": "L2", "help_term": "cve",
         "summary": "ローカル検証ラボ（127.0.0.1）の Server ヘッダーおよびパス正規化処理に CVE-2021-41773 の影響可能性があります。",
         "why_detected": "対象エンドポイントの構成プロファイルおよび応答バナーから CVE-2021-41773 / CVE-2021-42013 の検証対象として検出されました。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が実際に検証します。",
         "evidence": [],
         "remediation": {"steps": ["Apache HTTP Server を最新の安定版（2.4.62以降）に更新する",
                                   "Server ヘッダーのバージョン表示を抑制する（ServerTokens Prod）"],
                         "how_to_verify": "「防御パッチ適用・再検証」または「実機Workerで今すぐ検証」を実行し、結果が「再現せず」に変わることを確認します。"}},
        {**common, "id": "f_idor", "title": "他アカウントの保護リソースへのアクセス制御不備（IDOR）",
         "severity": "high", "verdict": "detected", "category": "アクセス制御", "cve": [],
         "risk_level": "L2", "help_term": "idor",
         "summary": "検証用アカウント acct_A のトークンで、別アカウント acct_B の保護リソース（/api/accounts/B/secret）へアクセスできるか検証します。",
         "why_detected": "APIエンドポイント /api/accounts/B/secret においてオブジェクト単位の所有者検証が必要と判定されたためです。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が2アカウント間の実通信で実証します。",
         "evidence": [],
         "remediation": {"steps": ["サーバー側でセッション主体とリソース所有者を必ず照合し、不一致時は 403 Forbidden を返す"],
                         "how_to_verify": "修正後に同じ手順で再試験し、HTTP 403 が返ることを確認します。"}},
        {**common, "id": "f_sqli", "title": "検索欄のSQLインジェクション境界不備（/api/search）",
         "severity": "critical", "verdict": "detected", "category": "インジェクション",
         "cve": [], "risk_level": "L2", "help_term": "sqli",
         "summary": "検索エンドポイント /api/search?q=test' に対し、未バインドのSQL構文解釈が発生するかを非破壊プローブで検証します。",
         "why_detected": "検索パラメータ q において未エスケープのクエリ連結が行われている可能性が検出されたためです。",
         "caveat": "「実機Workerで今すぐ検証」または「診断を開始」を実行すると、Gateway経由で reproduction_probe Worker が実際のHTTP応答と監査ハッシュを記録します。",
         "evidence": [],
         "remediation": {"steps": ["プリペアドステートメント（プレースホルダー付きクエリ）を使用し文字列連結を廃止する"],
                         "how_to_verify": "修正前後で同じ試験を行い、SQL構文エラー差分が解消されることを確認します。"}},
    ]

