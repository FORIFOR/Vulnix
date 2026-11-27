"""Control-plane HTTP API + SSE for the Aegis UI (local use).

Binds to 127.0.0.1 only. Two independent guards protect state-changing requests:
  1. CSRF: POST must carry `X-Aegis-Request: 1` and, if an Origin header is
     present, an allowed one.
  2. Operator auth: POST (except /api/auth/login) requires a valid session
     cookie. The session's operator name is the audit actor; deciding an L2+
     approval additionally requires the `approver` role.

Run:  python3 -m aegis.server  [--port 8787] [--lab-port 18081]
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import http.cookies
import hashlib
import json
import os
import re
import secrets
import signal
import threading
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import cloud_inventory, google_ownership, ownership_policy
from .assessment import (ApproverRequired, AssessmentService, SeparationConfigError, StopNotConfirmed,
                         separate_l2_approver_from_env)
from .audit import AuditWriteFailed
from .control_verification import run_live_control_verification
from .diagnosis_ops import OP_PERMISSION, member_permissions, permitted
from .lab import set_lab_mode, start_lab
from .operators import (CREDENTIAL_ABORT_EVENT, AuthError, ChangeNotSaved, CredentialStateUnverifiable,
                        LockedOut, MFAChallenge, OperatorStore, credential_history_reader)
from .ownership import OWNERSHIP_METHODS, parse_service_target
from .gateway import State
from .policy import PolicyError
from .real_software_cve import run_real_software_cve_comparison
from .tenancy import (DEFAULT_ORG, OrgStore, TenancyError, TenantRegistry, default_members_from,
                      service_roles, valid_org_id)

ALLOWED_ORIGINS = {"http://localhost:3000", "http://127.0.0.1:3000"}
COOKIE = "aegis_session"


# GET endpoints that answer without a session. Everything else that is read
# (assets, snapshots, logs, reports, evidence, the event stream, secrets status)
# needs a login unless the operator opts out explicitly.
PUBLIC_GET_PATHS = frozenset({"/api/auth/me", "/api/health"})


def development_mode() -> bool:
    """Open reads are a local-development convenience only. Anything that is not
    explicitly marked as development is treated as production."""
    return os.environ.get("AEGIS_ENV", "").strip().lower() in ("development", "dev")


MAX_BODY_BYTES = 1_000_000
# Limits for a publicly reachable beta (per process).
SIGNUPS_PER_MINUTE = 10          # self-registrations, whole platform
SIGNUP_ATTEMPTS_PER_MINUTE = 30  # sign-up attempts that reach password hashing, whole platform
SSE_PER_ACCOUNT = 4              # simultaneous event streams per account
CHAT_PER_ORG_PER_HOUR = 30       # AI explanation questions per organization
CHAT_PLATFORM_PER_HOUR = 300     # AI explanation questions, whole platform (one API key)
CHAT_PLATFORM_PER_DAY = int(os.environ.get("VULNIX_CHAT_PER_DAY", "1000") or 1000)
# Traffic to real (non-lab) sites: ownership checks over the network and diagnoses.
#   1            legacy single-service mode (L1, approved L2, ARTEX on the lab only);
#                multi-tenant mode still enforces read-only real-site checks
#   l1           public beta: ownership checks and the read-only (L1) diagnosis of a
#                site whose ownership this organization proved; nothing beyond that
#   0            no traffic to real sites at all
_REAL_SITE_MODE = (os.environ.get("VULNIX_REAL_SERVICE_DIAGNOSIS", "l1") or "l1").strip().lower()
REAL_SERVICE_DIAGNOSIS = _REAL_SITE_MODE == "1"
REAL_SITE_L1_ONLY = _REAL_SITE_MODE == "l1"


def optional_status_check_configured() -> bool:
    """Expose the extra read-only choice only for the local planner path."""
    if (not REAL_SITE_L1_ONLY
            or os.environ.get("VULNIX_REAL_SITE_LOCAL_ARTEX") != "1"
            or os.environ.get("VULNIX_REAL_SITE_INITIAL_ARTEX") != "1"
            or os.environ.get("VULNIX_ARTEX_LLM_MODE", "").strip() != "gateway-forward"
            or not os.environ.get("VULNIX_ARTEX_REAL_CMD", "").strip()):
        return False
    try:
        return urlsplit(os.environ.get("VULNIX_ARTEX_LLM_UPSTREAM_URL", "")).hostname in ("127.0.0.1", "::1")
    except ValueError:
        return False
OWNERSHIP_CHECKS_PER_ORG_PER_HOUR = 20   # DNS / .well-known lookups a single organization may trigger
OWNERSHIP_CHECKS_PLATFORM_PER_HOUR = 300
_OWNERSHIP_LOOKUPS = frozenset({"/api/assets/verify-ownership", "/api/assets/cloud-run/finish"})
_OWNERSHIP_APPROVAL_TTL = 15 * 60
_OWNERSHIP_REQUEST_TTL = 24 * 3600


def _ownership_traffic_mode(org_id: str | None = None) -> str:
    configured = os.environ.get("VULNIX_OWNERSHIP_TRAFFIC", "")
    if configured == "hybrid":
        personal = [org.strip() for org in os.environ.get("VULNIX_PERSONAL_OWNERSHIP_ORGS", "").split(",")]
        valid = len(personal) <= 200 and all(re.fullmatch(r"org_[0-9a-f]{12}", org) for org in personal)
        # Default and all other organizations keep separate approval. The org
        # parameter is populated only from an authenticated membership.
        return "preapproved" if valid and org_id in personal else "approved"
    if configured in ("approved", "preapproved"):
        return configured
    if configured:
        return "off"
    return "existing" if (REAL_SERVICE_DIAGNOSIS or REAL_SITE_L1_ONLY) else "off"
REAL_SITE_RUNS_PER_ORG_PER_HOUR = 10     # read-only runs on proven real sites
REAL_SITE_RUNS_PLATFORM_PER_HOUR = 200
# In L1-only mode these stay open on a real site: the read-only run and its controls
_L1_ONLY_ROUTES = ("/start", "/restart", "/resume", "/pause", "/emergency-stop", "/chat")
SSE_PLATFORM = 200               # simultaneous event streams, whole platform
ARTEX_LLM_PLANS_PER_ORG_PER_HOUR = int(os.environ.get("VULNIX_ARTEX_LLM_PLANS_PER_ORG_PER_HOUR", "3") or 0)  # plans reaching the real model
ARTEX_LLM_PLANS_PER_DAY = int(os.environ.get("VULNIX_ARTEX_LLM_PLANS_PER_DAY", "100") or 0)
ARTEX_PLANS_PER_ORG_PER_HOUR = int(os.environ.get("VULNIX_ARTEX_PLANS_PER_ORG_PER_HOUR", "6") or 0)  # any ARTEX run (CPU, confinement)
ARTEX_PLANS_PLATFORM_PER_HOUR = int(os.environ.get("VULNIX_ARTEX_PLANS_PER_HOUR", "60") or 0)
ARTEX_LLM_PLANS_PLATFORM_PER_HOUR = int(os.environ.get("VULNIX_ARTEX_LLM_PLANS_PER_HOUR", "20") or 0)
# Platform-wide POST routes: they act on this machine or on configuration shared by
# every organization, so they are decided by the account's own (global) roles.
PLATFORM_POST_ROUTES = frozenset({"/api/l2-profiles/accept", "/api/router/verify", "/api/cve/sync",
                                  "/api/system/verify-controls", "/api/cve/real-software-verify",
                                  "/api/agent-defense/evaluate", "/api/a2b/profile-draft"})
# Routes that start a verification job (spawn workers / probes on this machine).
JOB_ROUTES = frozenset({"/api/system/verify-controls", "/api/cve/real-software-verify",
                        "/api/agent-defense/evaluate"})

# Audit before state (docs/AUDIT_BEFORE_STATE.md): a grant is recorded first and is not
# made without its record; a removal is made whatever the audit log does, then recorded.
AUDIT_REFUSED = "監査ログに記録できないため、この操作は行いませんでした（何も変更していません）"
AUDIT_MISSING = "操作は反映しました（権限の取り消しは有効です）が、監査ログに記録できませんでした"


def audit_first(audit, event: str, **fields) -> None:
    try:
        audit.record(event, **fields)
    except Exception as e:  # noqa: BLE001 - disk, chain or anchor: all mean "not recorded"
        raise AuditWriteFailed(AUDIT_REFUSED) from e


def audit_after(audit, event: str, gap_svc=None, gap_log: str = "org", **fields) -> bool:
    """The record of an applied removal; False if it could not be written. A missing
    record is kept as an audit gap of `gap_svc` (shown in its status, written later)."""
    try:
        audit.record(event, **fields)
    except Exception:  # noqa: BLE001
        if gap_svc is not None:
            gap_svc._note_audit_gap(event, fields, log=gap_log)
        return False
    if gap_svc is not None:
        gap_svc._flush_audit_gaps()
    return True


class _Journal:
    """Audit-first record of a store change (`journal=` of OrgStore / OperatorStore).
    If the store then fails to save, the record is marked as not committed."""

    # a credential change (aegis/operators.py) is identified by these; its abort record
    # carries them, which voids exactly that intent (docs/PASSWORD_CHANGE_DURABILITY.md)
    _CARRIED = ("account", "credential_generation", "hash_digest")

    def __init__(self, audit, event: str, **fields):
        self.audit, self.event, self.fields, self.written = audit, event, fields, False
        self.more: dict = {}

    def __call__(self, **more):
        self.more = more
        try:
            audit_first(self.audit, self.event, **self.fields, **more)
        except AuditWriteFailed:
            # The record may be on disk all the same (a listener or the anchor failed after
            # the write). For a credential change that would leave an intent behind that
            # blocks the account at the next start: void it explicitly (best effort).
            self._abort_credential("record_failed")
            raise
        self.written = True

    def _carried(self) -> dict:
        return {k: self.more[k] for k in self._CARRIED if k in self.more}

    def _abort_credential(self, reason: str) -> bool:
        carried = self._carried()
        if len(carried) != len(self._CARRIED):
            return False
        with contextlib.suppress(Exception):
            self.audit.record(CREDENTIAL_ABORT_EVENT, grant=self.event, reason=reason, **carried)
        return True

    def not_committed(self, reason: str) -> None:
        if self.written and not self._abort_credential(reason):
            with contextlib.suppress(Exception):
                self.audit.record("grant.not_committed", grant=self.event, reason=reason)


class ControlPlaneHTTPServer(ThreadingHTTPServer):
    """Bound the production loopback listener before spawning handler threads."""

    request_queue_size = 64
    connection_limit = SSE_PLATFORM + 56
    timeout_per_connection = 12
    _busy_body = '{"error":"接続が混み合っています。少し待ってから再試行してください"}'.encode()
    _busy_response = (
        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 2\r\n"
        b"Cache-Control: no-store\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: "
        + str(len(_busy_body)).encode() + b"\r\n\r\n" + _busy_body
    )

    def __init__(self, address, handler):
        self._slots = threading.BoundedSemaphore(self.connection_limit)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            try:
                request.setblocking(False)
                request.sendall(self._busy_response)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            request.settimeout(self.timeout_per_connection)
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_handler(svc: AssessmentService, ops: OperatorStore, *, require_read_auth: bool | None = None,
                 allow_self_registration: bool | None = None, tenancy: TenantRegistry | None = None,
                 public_signup: bool | None = None, local_defense_python_root: Path | None = None,
                 local_defense_node_bundle: Path | None = None, local_defense_registry: Path | None = None):
    default_svc = svc
    inventory = cloud_inventory.Inventory()
    local_controls = {}
    portable = {}
    local_controls_lock = threading.Lock()
    if local_defense_registry:
        from .local_defense_profile import load_registry
        portable = load_registry(local_defense_registry)
        if tenancy is None and any(org != DEFAULT_ORG for org in portable):
            raise ValueError("organization-specific defence profiles require tenancy")
    if local_defense_python_root or local_defense_node_bundle or DEFAULT_ORG in portable:
        from .local_defense_control import LocalDefenseControl
        local_controls[DEFAULT_ORG] = LocalDefenseControl(svc, python_root=local_defense_python_root,
                                                          node_bundle=local_defense_node_bundle,
                                                          portable=portable.get(DEFAULT_ORG))

    def local_control(org, service):
        with local_controls_lock:
            control = local_controls.get(org)
            if control is not None:
                return control if control.service is service else None
            if org not in portable:
                return None
            from .local_defense_control import LocalDefenseControl
            control = LocalDefenseControl(service, python_root=None, node_bundle=None, portable=portable[org])
            local_controls[org] = control
            return control
    # where account-level events go: a platform log when there are organizations
    paudit = tenancy.platform_audit if tenancy is not None else svc.audit
    # audit gaps of account-level removals are kept by the default service and written
    # to the platform log once it is writable again
    svc._platform_audit = paudit

    def flush_platform_gaps(_entry):
        # the platform log took a record: write deferred account-level records too. In a
        # thread: the caller may hold the operator store's lock (no lock-order inversion)
        if default_svc.has_platform_audit_gaps() and not default_svc._flushing_gaps:
            threading.Thread(target=default_svc._flush_audit_gaps, kwargs={"log": "platform"},
                             daemon=True, name="audit-gap-flush").start()
    paudit.listeners.append(flush_platform_gaps)
    limits_lock = threading.Lock()
    ownership_lock = threading.Lock()
    ownership_requests: dict[tuple, dict] = {}
    signup_times: list[float] = []
    signup_attempts: list[float] = []
    chat_times: dict[str, list[float]] = {}
    chat_all: list[float] = []
    chat_day: list[float] = []
    plan_times: dict[str, list[float]] = {}
    plan_all: list[float] = []
    plan_day: list[float] = []
    run_times: dict[str, list[float]] = {}
    run_all: list[float] = []
    verify_times: dict[str, list[float]] = {}
    self_service_slots = ownership_policy.SelfServiceSlots()
    google_states: dict[str, dict] = {}     # OAuth state -> {at, account, org, host, verifier}
    verify_all: list[float] = []
    real_run_times: dict[str, list[float]] = {}
    real_run_all: list[float] = []
    sse_open: dict[str, int] = {}
    signup_lock = threading.Lock()

    def _approver_class(name: str) -> str:
        """For L2 approvals under separation of duties: "registered" (an account an
        administrator created) or "self" (signed up by itself, with or without 2FA or an
        invitation). Only "registered" may approve (AssessmentService._approver_refused)."""
        return "self" if ops.is_self_registered(name) else "registered"

    def room(times: list[float], window: float, cap: int) -> bool:
        """Whether one more use fits, without recording it."""
        now = time.monotonic()
        times[:] = [t for t in times if now - t < window]
        return len(times) < cap

    def within(times: list[float], window: float, cap: int) -> bool:
        """Sliding-window limit: records this use and says whether it is allowed."""
        now = time.monotonic()
        times[:] = [t for t in times if now - t < window]
        if len(times) >= cap:
            return False
        times.append(now)
        return True

    def self_registration_allowed() -> bool:
        # Anyone who can reach the port could otherwise mint themselves a session
        # (and a second identity). Without tenancy, outside development mode, accounts
        # are created by an admin only. With tenancy a self-registered account gets an
        # organization of its own and sees nothing else, so public sign-up can be
        # switched on (VULNIX_PUBLIC_SIGNUP=1).
        if allow_self_registration is not None:
            return bool(allow_self_registration)
        if tenancy is not None and (public_signup if public_signup is not None
                                    else os.environ.get("VULNIX_PUBLIC_SIGNUP") == "1"):
            return True
        return development_mode()

    # Secure by default: reads need a session. The environment switch
    # `AEGIS_REQUIRE_READ_AUTH=0` is honoured ONLY in development mode
    # (`AEGIS_ENV=development`); in production it is ignored. Passing
    # `require_read_auth=False` in code is the caller's explicit choice (tests).
    if require_read_auth is None:
        enforce_read_auth = not (development_mode() and os.environ.get("AEGIS_REQUIRE_READ_AUTH") == "0")
    else:
        enforce_read_auth = bool(require_read_auth)
    if not enforce_read_auth:
        svc.audit.record("config.read_auth_disabled", development_mode=development_mode())
    if ops.legacy_sessions_revoked:
        paudit.record("auth.legacy_sessions_revoked", count=ops.legacy_sessions_revoked,
                         reason="session file held bearer tokens in plaintext; sessions must sign in again")
        ops.legacy_sessions_revoked = 0

    def approver_grant_recorded(name: str) -> bool:
        """Whether the audit log shows an admin granting (or attesting) this
        account's approver role. Accounts that became approvers before roles
        were admin-granted have no such record and should be reviewed."""
        latest = None
        logs = [svc.audit] + ([paudit] if paudit is not svc.audit else [])
        for e in (x for log in logs for x in log.entries()):
            if e["event"] == "operator.roles_changed" and e["fields"].get("target") == name:
                latest = e["fields"]
        return bool(latest and "approver" in (latest.get("after") or []))

    @contextlib.contextmanager
    def live_grant_roles(sess, org_id: str, *, approver: bool = False, reader: bool = False, include_platform: bool = False):
        """Serialize a signed ownership/scope grant with logout and role removal.

        External ownership lookups happen before this guard is acquired. The short
        ledger commit holds the live session and membership locks in that order.
        """
        with ops.locked_session(sess.token) as current:
            if current is None or current.operator != sess.operator:
                raise AuthError("ログインの有効期限が切れました。もう一度ログインしてください")
            membership = (tenancy.store.locked_roles_in(org_id, current.operator)
                          if tenancy is not None else contextlib.nullcontext(current.roles))
            with membership as org_roles:
                roles = service_roles(org_roles) if tenancy is not None else tuple(org_roles)
                if (reader and not org_roles) or (not reader and not (
                        {"operator", "approver", "admin"} & set(roles))):
                    raise ApproverRequired("この組織で所有確認を行う権限がありません")
                if approver and "approver" not in roles:
                    raise ApproverRequired("診断範囲の確定には承認責任者の権限が必要です")
                yield (roles, current.roles) if include_platform else roles

    def live_request_allowed(sess, org_id: str, *, approver: bool = False) -> bool:
        # Used between turns of a long planner or just before a foreground
        # Worker launch. Never retain the account/organization locks while
        # waiting for the model or Worker to finish.
        try:
            with live_grant_roles(sess, org_id, approver=approver):
                return True
        except Exception:  # noqa: BLE001 - cannot confirm live authority: refuse
            return False

    def live_request_authority(sess, org_id: str, *, approver: bool = False):
        """A short check plus a launch lease for foreground Worker requests."""
        def allowed() -> bool:
            return live_request_allowed(sess, org_id, approver=approver)

        @contextlib.contextmanager
        def lease():
            guard = live_grant_roles(sess, org_id, approver=approver)
            try:
                guard.__enter__()
            except Exception:  # noqa: BLE001 - no live grant means no process start
                raise PolicyError("要求者の権限が失効したため、新しいWorkerは起動しません") from None
            try:
                yield
            finally:
                guard.__exit__(None, None, None)

        allowed.lease = lease
        return allowed

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def handle(self) -> None:
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass

        # ---- helpers --------------------------------------------------------
        def _json(self, code: int, obj, extra_headers: list[tuple[str, str]] = ()) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            for k, v in extra_headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _session(self):
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            morsel = jar.get(COOKIE)
            token = morsel.value if morsel else None
            if not token:
                auth_hdr = self.headers.get("Authorization", "")
                if auth_hdr.startswith("Bearer "):
                    token = auth_hdr[7:].strip()
            return ops.resolve(token)

        def _loopback_client(self) -> bool:
            """The agent check runs only for a browser on this machine talking to this machine."""
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
            return (self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")
                    and host in ("127.0.0.1", "localhost", "::1")
                    and not self.headers.get("X-Forwarded-For"))

        def _public_session(self, sess):
            return {"operator": sess.operator, "roles": list(sess.roles),
                    "expires": sess.expires,
                    "mfa_enabled": ops.totp_enabled(sess.operator)} if sess else None

        def _ownership_target(self, service, value, method):
            parsed = parse_service_target(value)
            host = parsed["host"]
            if method not in (*OWNERSHIP_METHODS, google_ownership.METHOD, "cloud_run_oidc"):
                raise ValueError("所有確認方法を選択してください")
            with service._lock:
                asset = service._asset_record(host)
                if (not asset or not service._in_ownership_flow(host) or not asset.get("challenge")
                        or (asset.get("scheme"), asset.get("port")) != (parsed["scheme"], parsed["port"])):
                    raise ValueError("先に対象URLを登録してください")
                if (method not in ("dns_txt", google_ownership.METHOD)
                        and (parsed["scheme"], parsed["port"]) != ("https", 443)):
                    raise ValueError("この確認方法には HTTPS の標準ポートが必要です")
                key = (getattr(self, "_bound_org", DEFAULT_ORG), asset["id"], asset["target_url"], method,
                       asset.get("ownership_registration_version"))
                stopped = service.gateway.state is State.STOPPED or service.a.state == "stopped" or service._stop_flag().exists()
                return key, service.gateway._launch_epoch, stopped

        @staticmethod
        def _ownership_status(record, epoch, now):
            if record is None:
                return "not_requested"
            if record["epoch"] != epoch or now >= record["expires_at"]:
                return "expired"
            return record["status"]

        def _self_service_mode(self):
            return (_ownership_traffic_mode(getattr(self, "_bound_org", None)) == "preapproved"
                    and os.environ.get("VULNIX_OWNERSHIP_SELF_SERVICE") == "1")

        @staticmethod
        def _managed_ownership(mode, method):
            return (mode == "preapproved" and method in ownership_policy.METHODS
                    and os.environ.get("VULNIX_OWNERSHIP_TRAFFIC") == "hybrid"
                    and os.environ.get("VULNIX_PERSONAL_OWNERSHIP_REQUESTS") == "1")

        def _ownership_request(self, service, sess, body):
            mode = _ownership_traffic_mode(getattr(self, "_bound_org", None))
            if mode not in ("approved", "preapproved"):
                return self._json(409, {"error": "所有確認の通信申請は運営者設定が必要です"})
            action = body.get("action")
            deciding = ("approve", "reject", "revoke")
            fields = {"action", "url", "method", "id"} if action in deciding else {"action", "url", "method"}
            if set(body) != fields or action not in ("status", "request", *deciding):
                return self._json(400, {"error": "所有確認の操作が不正です"})
            org = getattr(self, "_bound_org", DEFAULT_ORG)
            managed = self._managed_ownership(mode, body["method"])
            with live_grant_roles(sess, org, include_platform=True) as (roles, platform_roles), service._lock, ownership_lock:
                key, epoch, stopped = self._ownership_target(service, str(body["url"]), body["method"])
                now = time.time()
                if mode == "preapproved":
                    policies = ownership_policy.for_target(key[0], key[2], now)
                    available = [policy.method for policy in policies.values()
                                 if policy.not_before <= now < policy.expires_at
                                 and not stopped and ownership_policy.has_budget(service.data_dir, policy)]
                    policy = policies.get(key[3])
                    if policy or not managed:
                        if action != "status":
                            return self._json(409, {"error": "この対象と方法の通信許可は運営者設定で管理します"})
                        can_verify = key[3] in available
                        if policy is None:
                            status = "not_requested"
                        elif now >= policy.expires_at:
                            status = "expired"
                        elif now < policy.not_before:
                            status = "scheduled"
                        else:
                            status = "approved" if can_verify else "unavailable"
                        result = {"status": status, "stopped": stopped, "can_decide": False,
                                  "can_verify": can_verify, "available_methods": available, "managed": managed,
                                  "expires_at": policy.expires_at if policy else None,
                                  "self_service": bool(policy and policy.id.startswith("self-"))}
                        previous_timeout = self.connection.gettimeout()
                        self.connection.settimeout(2.0)
                        try:
                            return self._json(200, result)
                        finally:
                            self.connection.settimeout(previous_timeout)
                    if not key[2].startswith("https://"):
                        raise ValueError("この通信申請はHTTPSの対象だけに利用できます")
                request_key = (mode, key)
                record = ownership_requests.get(request_key)
                status = self._ownership_status(record, epoch, now)
                eligible_operator = "admin" in roles and (not managed or "admin" in platform_roles)
                separate_operator = bool(record and record["requester"] != sess.operator and eligible_operator)
                if action in deciding:
                    if not separate_operator:
                        raise ApproverRequired("依頼者とは別の、必要な権限を持つ運営者が操作してください"
                                               if managed else "依頼者とは別の組織管理者が操作してください")
                    if action == "revoke":
                        if not managed or record["id"] != body["id"] or status != "approved":
                            raise ValueError("この通信許可は取り消し可能な状態ではありません")
                        status = "rejected"
                        record.update(status=status, expires_at=now + _OWNERSHIP_REQUEST_TTL)
                        error = service._audit_reduction("asset.ownership_traffic_revoked", actor=sess.operator,
                                                         asset_id=key[1], method=key[3], request_id=record["id"])
                        if error:
                            raise error
                    else:
                        if record["id"] != body["id"] or status != "pending" or stopped:
                            raise ValueError("この申請は承認可能な状態ではありません")
                        service._audit_first("asset.ownership_traffic_decided", actor=sess.operator,
                                             asset_id=key[1], method=key[3], request_id=record["id"], decision=action)
                        status = "approved" if action == "approve" else "rejected"
                        record.update(status=status, expires_at=now + (_OWNERSHIP_APPROVAL_TTL if action == "approve" else _OWNERSHIP_REQUEST_TTL))
                elif action == "request" and status not in ("pending", "approved"):
                    if stopped:
                        raise ValueError("緊急停止中は所有確認を申請できません")
                    for expired in [k for k, v in ownership_requests.items() if now - v["expires_at"] > _OWNERSHIP_REQUEST_TTL]:
                        del ownership_requests[expired]
                    if len(ownership_requests) >= 5000 and request_key not in ownership_requests:
                        raise ValueError("所有確認の申請件数が上限に達しました")
                    status = "pending"
                    record = {"id": secrets.token_urlsafe(18), "requester": sess.operator, "status": status,
                              "expires_at": now + _OWNERSHIP_REQUEST_TTL, "epoch": epoch, "remaining": 3}
                    service._audit_first("asset.ownership_traffic_requested", actor=sess.operator,
                                         asset_id=key[1], method=key[3], request_id=record["id"])
                    ownership_requests[request_key] = record
                can_verify = bool(record and status == "approved" and record["requester"] == sess.operator
                                  and not stopped and (not managed or record["remaining"] > 0))
                result = {"status": status, "stopped": stopped, "can_decide": bool(separate_operator and status == "pending" and not stopped),
                          "can_verify": can_verify, "managed": managed,
                          "can_revoke": bool(managed and separate_operator and status == "approved")}
                if managed:
                    result.update(available_methods=available + ([key[3]] if can_verify else []),
                                  can_request=not stopped and status in ("not_requested", "expired", "rejected"))
                    if record and status == "approved" and record["remaining"] == 0:
                        result["status"] = "unavailable"
                if record:
                    result.update(id=record["id"], expires_at=record["expires_at"])
            return self._authorized_org_read(sess, org, lambda _: self._json(200, result), reader=False)

        @staticmethod
        def _audit_self_service_refusal(service, actor, asset_id, method, reason):
            """Refused self-service attempts are recorded too (nothing was sent); best effort,
            because a refusal must not turn into an error when the audit disk is unavailable."""
            try:
                service.audit.record("asset.ownership_traffic_refused", actor=actor, asset_id=asset_id,
                                     method=method, reason=reason[:200])
            except Exception:  # noqa: BLE001
                pass

        def _require_ownership_traffic(self, service, sess, value, method, expected=None, *, consume=False):
            mode = _ownership_traffic_mode(getattr(self, "_bound_org", None))
            managed = self._managed_ownership(mode, method)
            saved_method = expected[0] if isinstance(expected, tuple) else None
            if ((expected is not None and mode not in ("approved", "preapproved"))
                    or (saved_method == "managed" and not managed)
                    or (saved_method == "preapproved" and mode != "preapproved")):
                raise ApproverRequired("所有確認の通信許可が変更されました。もう一度お試しください")
            if mode == "off":
                raise ApproverRequired("この環境では所有確認用の通信が停止中です")
            if mode == "existing":
                with service._lock:
                    if service.gateway.state is State.STOPPED or service.a.state == "stopped" or service._stop_flag().exists():
                        raise ApproverRequired("緊急停止中は所有確認を行いません")
                return None
            key, epoch, stopped = self._ownership_target(service, value, method)
            if mode == "preapproved":
                claim = "所有確認は運営者が事前に許可した対象・方法・期間に限られます"
                policy = ownership_policy.for_target(key[0], key[2], time.time()).get(method)
                if policy or saved_method == "preapproved" or not managed:
                    if stopped or not policy or not policy.not_before <= time.time() < policy.expires_at:
                        raise ApproverRequired(claim)
                    current = ("preapproved", key, epoch, policy)
                    if expected is not None and expected != current:
                        raise ApproverRequired(claim)
                    if consume and policy.id.startswith("self-"):
                        if not ownership_policy.has_budget(service.data_dir, policy):
                            self._audit_self_service_refusal(service, sess.operator, key[1], method, "target_budget")
                            raise ApproverRequired("所有確認の試行上限に達したか、許可の状態を確認できません")
                        # account, organization, origin and platform limits (raises LimitReached: 429)
                        try:
                            ownership_policy.consume_self_service(
                                Path(default_svc.data_dir), account=sess.operator, org=key[0], origin=key[2],
                                method=method, now=time.time())
                        except ownership_policy.LimitReached as e:
                            self._audit_self_service_refusal(service, sess.operator, key[1], method, str(e))
                            e.audited = True
                            raise
                    if (consume or expected is None) and not ownership_policy.has_budget(service.data_dir, policy, consume=consume):
                        raise ApproverRequired("所有確認の試行上限に達したか、許可の状態を確認できません")
                    if consume:
                        service._audit_first("asset.ownership_traffic_preapproved", actor=sess.operator,
                                             asset_id=key[1], method=method, policy_id=policy.id)
                        # Fail closed if the operator revoked the permission while the attempt was recorded.
                        self._require_ownership_traffic(service, sess, value, method, current)
                    return current
            with ownership_lock:
                record = ownership_requests.get((mode, key))
                if (stopped or self._ownership_status(record, epoch, time.time()) != "approved"
                        or record["requester"] != sess.operator):
                    raise ApproverRequired("この対象・方法には有効な所有確認の通信承認がありません")
                current = ("managed", key, epoch, record["id"]) if managed else record["id"]
                if expected is not None and expected != current:
                    raise ApproverRequired("所有確認の通信許可が変更されました。もう一度お試しください")
                if managed and (consume or expected is None):
                    if not record["remaining"]:
                        raise ApproverRequired("所有確認の試行上限に達しました")
                    if consume:
                        service._audit_first("asset.ownership_traffic_managed", actor=sess.operator,
                                             asset_id=key[1], method=method, request_id=record["id"])
                        record["remaining"] -= 1
                return current

        def _touches_real_site(self, p: str, osvc) -> bool:
            """Requests that would send traffic to a registered real site."""
            if p in ("/api/assets/verify-ownership", "/api/assets/cloud-run/finish"):
                return True
            if p == "/api/assets/select":
                # switching the workspace onto a real site is the step before diagnosing it
                body_id = getattr(self, "_select_target", "")
                try:
                    return bool(osvc.asset_is_real_service(asset_id=body_id))
                except Exception:   # noqa: BLE001 - when in doubt, treat it as real
                    return True
            base = f"/api/assessments/{osvc.a.id}"
            if not p.startswith(base) or p.endswith(("/emergency-stop", "/pause", "/chat")):
                return False
            try:
                return bool(osvc._is_external_service_asset())
            except Exception:   # noqa: BLE001 - when in doubt, treat it as real
                return True

        def _real_site_refusal(self, p: str, osvc) -> str:
            """L1-only mode: why this request may not reach the real site ("" = allowed).
            The ownership check itself is allowed (rate-limited); switching to a site and
            starting the run are allowed (the service requires proven ownership and a
            confirmed scope); every other assessment action on a real site is refused."""
            if p in ("/api/assets/verify-ownership", "/api/assets/cloud-run/finish", "/api/assets/select"):
                return ""
            if p.endswith(_L1_ONLY_ROUTES):
                return ""
            base = f"/api/assessments/{osvc.a.id}"
            if getattr(osvc, "_real_site_local_artex", False) and (
                    p == base + "/artex/plan"
                    or re.fullmatch(base + r"/artex/items/[A-Za-z0-9_]{1,80}/execute", p)):
                return ""
            return ("実在するサイトに対しては、読み取り専用の診断（ページを1回取得して設定を調べる）だけを行います。"
                    "この操作は実在するサイトでは使えません")

        def _org_requested(self, query_org: str | None = None) -> str:
            """The organization the client says it is working in: header, query, or the
            `vulnix_org` cookie the UI sets. Only a choice - membership is checked by _bind."""
            jar = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            cookie = jar.get("vulnix_org")
            return (self.headers.get("X-Vulnix-Org") or query_org or (cookie.value if cookie else "")).strip()[:40]

        def _bind(self, sess, query_org: str | None = None):
            """The organization this request acts in: (its service, the session with the
            account's roles IN that organization). Answers 401/403/404 itself and returns
            None when there is none. Without tenancy: the single service, unchanged."""
            if tenancy is None:
                default_svc.real_site_read_only = not REAL_SERVICE_DIAGNOSIS
                return default_svc, sess
            if not sess:
                self._json(401, {"error": "ログインが必要です"})
                return None
            wanted = self._org_requested(query_org)
            if not wanted:
                orgs = tenancy.store.orgs_of(sess.operator)
                if not orgs:
                    self._json(403, {"error": "所属している組織がありません。組織を作成するか、招待を受け入れてください",
                                     "no_org": True})
                    return None
                wanted = orgs[0]["id"]
            roles = tenancy.store.roles_in(wanted, sess.operator) if valid_org_id(wanted) else ()
            if not roles:
                paudit.record("tenancy.access_denied", actor=sess.operator, org=wanted)
                self._json(403, {"error": "この組織のメンバーではありません"})
                return None
            try:
                osvc = tenancy.service(wanted)
            except TenancyError as e:
                self._json(404, {"error": str(e)})
                return None
            self._bound_org = wanted
            # enforced again inside the service, under its lock (an asset switch cannot race it)
            # The legacy broad switch is only for the single-service mode. A tenant
            # must never inherit real-site L2 from a process-wide environment value.
            osvc.real_site_read_only = True
            return osvc, dataclasses.replace(sess, roles=service_roles(roles))

        def _authorized_org_read(self, sess, org, action, *, reader=True, approver=False):
            """Keep a protected response within the current account/member grant."""
            try:
                with live_grant_roles(sess, org, reader=reader, approver=approver) as current_roles:
                    current_sess = dataclasses.replace(sess, roles=tuple(current_roles))
                    previous_timeout = self.connection.gettimeout()
                    self.connection.settimeout(2.0)
                    try:
                        return action(current_sess)
                    finally:
                        self.connection.settimeout(previous_timeout)
            except AuthError:
                return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
            except ApproverRequired:
                return self._json(403, {"error": "この組織のメンバーではありません"})

        def _deliver_diagnosis_op(self, sess, org, op: str, code: int, result: dict):
            """PR-C: the operation's state is already stored (and replayed by its key); this
            only decides what THIS answer may carry. The grant is checked again for delivery:
            once it lapsed, the answer says only whether the request was taken - never the
            job, the item or the evidence - and a retry with the same key cannot run it
            again (the stored record answers, after the permission check)."""
            committed = code < 400
            withheld = {"error": "権限が失効したため、結果は返しません" + (
                "。操作は受け付け済みです（同じキーで送り直しても、もう一度は実行されません）" if committed else ""),
                "reason": "authority_revoked_after_request", "committed": committed}
            approving = op == "approve"
            try:
                with live_grant_roles(sess, org, approver=approving) as roles:
                    if not permitted(OP_PERMISSION[op], roles):
                        return self._json(403, withheld)
                    previous_timeout = self.connection.gettimeout()
                    self.connection.settimeout(2.0)
                    try:
                        return self._json(code, result)
                    finally:
                        self.connection.settimeout(previous_timeout)
            except AuthError:
                return self._json(401, {**withheld, "error": "ログインの有効期限が切れました。もう一度ログインしてください"})
            except ApproverRequired:
                return self._json(403, withheld)

        def _authorized_platform_read(self, sess, action, *, admin=False):
            """Do not deliver a shared-platform job result after its grant expires."""
            with ops.locked_session(sess.token) as current:
                if current is None or current.operator != sess.operator:
                    return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                required = {"admin"} if admin else {"approver", "admin"}
                if not required.intersection(current.roles):
                    return self._json(403, {"error": "この操作を行う権限がありません"})
                previous_timeout = self.connection.gettimeout()
                self.connection.settimeout(2.0)
                try:
                    return action()
                finally:
                    self.connection.settimeout(previous_timeout)

        def _host_ok(self) -> bool:
            """The control plane answers only when addressed as loopback. A request
            whose Host is some other name (a DNS-rebinding page, a LAN client going
            through a forwarder) is refused before anything else is looked at."""
            host = (self.headers.get("Host") or "").strip().lower()
            port = self.server.server_port
            return host in {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

        def _refuse(self, code: int, error: str, extra: list[tuple[str, str]] = ()):
            # Nothing of the request body has been read: never reuse this socket, or
            # the unread body would be parsed as the next request.
            self.close_connection = True
            return self._json(code, {"error": error}, extra)

        # ---- GET ------------------------------------------------------------
        def do_GET(self):
            if not self._host_ok():
                return self._refuse(421, "misdirected request")
            if (self.headers.get("Content-Length") or "0").strip() not in ("", "0") \
                    or self.headers.get("Transfer-Encoding"):
                self.close_connection = True      # a GET with a body: answer, then drop the socket
            u = urlsplit(self.path)
            p = u.path.rstrip("/")
            sess = self._session()
            if p == "/api/auth/me":
                me = {"session": self._public_session(sess), "self_registration": self_registration_allowed()}
                # This reports the process configuration so the public launcher can
                # still reject a broad setting, even though tenants stay read-only.
                me["real_service_diagnosis"] = REAL_SERVICE_DIAGNOSIS
                me["external_site_traffic_enabled"] = REAL_SITE_L1_ONLY or REAL_SERVICE_DIAGNOSIS
                me["real_site_read_only"] = REAL_SITE_L1_ONLY or tenancy is not None
                me["google_ownership"] = google_ownership.config() is not None
                me["cloud_inventory_configured"] = cloud_inventory.config() is not None
                me["ownership_traffic_mode"] = _ownership_traffic_mode()
                me["optional_status_check"] = optional_status_check_configured()
                me["development"] = development_mode()
                if tenancy is not None:
                    me["multi_tenant"] = True
                    me["orgs"] = []
                if sess is None:
                    return self._json(200, me)
                with ops.locked_session(sess.token) as current:
                    if current is None or current.operator != sess.operator:
                        me["session"] = None
                    else:
                        me["session"]["roles"] = list(current.roles)
                        me["session"]["expires"] = current.expires
                        if tenancy is not None:
                            me["orgs"] = tenancy.store.orgs_of(current.operator)
                            wanted = self._org_requested() or next((org["id"] for org in me["orgs"]), None)
                            if any(org["id"] == wanted for org in me["orgs"]):
                                me["ownership_traffic_mode"] = _ownership_traffic_mode(wanted)
                    previous_timeout = self.connection.gettimeout()
                    self.connection.settimeout(2.0)
                    try:
                        return self._json(200, me)
                    finally:
                        self.connection.settimeout(previous_timeout)
            if p == "/api/health":
                return self._json(200, {"ok": True})
            if enforce_read_auth and not sess:
                return self._json(401, {"error": "ログインが必要です"})
            if p == "/api/operators":
                # account list is for admins only, whatever the read-auth setting
                if not sess or "admin" not in sess.roles:
                    return self._json(403, {"error": "アカウント一覧の参照には管理者の権限が必要です"})
                locked = ops.locked_accounts()
                accounts = {"operators": [
                    {"name": o.name, "display": o.display, "roles": list(o.roles),
                     "mfa_enabled": bool(o.totp_secret),
                     "locked_for": int(locked.get(o.name, 0)),
                     # approver without an admin's grant on record -> needs review
                     "needs_role_review": "approver" in o.roles and not approver_grant_recorded(o.name)}
                    for o in ops.operators()]}
                with ops.locked_session(sess.token) as current:
                    if current is None or current.operator != sess.operator:
                        return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                    if "admin" not in current.roles:
                        return self._json(403, {"error": "管理者の権限が失効しました"})
                    previous_timeout = self.connection.gettimeout()
                    self.connection.settimeout(2.0)
                    try:
                        return self._json(200, accounts)
                    finally:
                        self.connection.settimeout(previous_timeout)
            if p == "/api/system/status":
                if tenancy is not None:
                    # each tenant sees its own conditions (stuck workers, notices name hosts)
                    bound = self._bind(sess)
                    if bound is None:
                        return None
                    org, status_svc = self._bound_org, bound[0]
                elif enforce_read_auth:
                    org, status_svc = DEFAULT_ORG, svc
                else:
                    return self._json(200, svc.system_status())
                try:
                    with live_grant_roles(sess, org, reader=True):
                        pass
                except AuthError:
                    return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                except ApproverRequired:
                    return self._json(403, {"error": "この組織のメンバーではありません"})
                status_payload = status_svc.system_status()
                if "admin" in ops.roles_of(sess.operator):
                    # account-level audit gaps: platform admins only, never in an org's status
                    status_payload["platform_audit_gaps"] = default_svc.platform_audit_gaps()
                return self._authorized_org_read(sess, org, lambda _: self._json(200, status_payload))
            if tenancy is not None and p.startswith("/api/orgs"):
                previous_timeout = self.connection.gettimeout()
                self.connection.settimeout(2.0)
                try:
                    return self._tenancy_get(p, u, sess)
                finally:
                    self.connection.settimeout(previous_timeout)
            if p.startswith(("/api/assets", "/api/assessments/")):
                bound = self._bind(sess, (parse_qs(u.query).get("org") or [None])[0])
                if bound is None:
                    return None
                if tenancy is None and not enforce_read_auth:
                    return self._get_org(p, u, *bound)
                org = self._bound_org if tenancy is not None else DEFAULT_ORG
                if p.endswith("/events"):
                    return self._get_org(p, u, *bound)  # long stream: per-batch lease below
                if p in {"/api/assets/intelligence", f"/api/assessments/{bound[0].a.id}",
                         f"/api/assessments/{bound[0].a.id}/logs",
                         f"/api/assessments/{bound[0].a.id}/diagnosis",
                         f"/api/assessments/{bound[0].a.id}/report",
                         f"/api/assessments/{bound[0].a.id}/remotion"}:
                    # Large audit reads and report formatting must not hold the
                    # global account lock. Check before work and again for delivery.
                    try:
                        with live_grant_roles(sess, org, reader=True) as roles:
                            identified = p.endswith("/remotion") and \
                                (parse_qs(u.query).get("anonymize") or ["1"])[0] == "0"
                            allowed_identified = not identified or bool({"approver", "admin"} & set(roles))
                    except AuthError:
                        return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                    except ApproverRequired:
                        return self._json(403, {"error": "この組織のメンバーではありません"})
                    if not allowed_identified:
                        return self._json(403, {"error": "匿名化なしの出力には承認責任者または管理者の権限が必要です"})
                    if p == "/api/assets/intelligence":
                        payload = bound[0].intelligence_snapshot(org)
                    elif p == f"/api/assessments/{bound[0].a.id}":
                        payload = bound[0].snapshot()
                    elif p.endswith("/logs"):
                        payload = bound[0].logs()
                    elif p.endswith("/diagnosis"):
                        payload = bound[0].diagnosis_view()
                        if payload is None:          # a real service: there is no such view
                            return self._authorized_org_read(sess, org, lambda _: self._json(
                                404, {"error": "診断ループは登録済みのローカル検証ラボでのみ表示できます"}))
                        # what THIS caller may do, from the roles live at delivery (the server
                        # checks every operation again; the screen shows only these controls)
                        return self._authorized_org_read(sess, org, lambda current: self._json(200, {
                            **payload, "viewer": {"actor": current.operator,
                                                  "permissions": member_permissions(current.roles)}}))
                    elif p.endswith("/report"):
                        payload = {"markdown": bound[0].report_markdown(),
                                   "filename": f"vulnix-report-{bound[0].a.id}.md"}
                    else:
                        anon = (parse_qs(u.query).get("anonymize") or ["1"])[0] != "0"
                        payload = bound[0].remotion_export(anonymize=anon)

                        def deliver_remotion(current):
                            if not anon:
                                if not ({"approver", "admin"} & set(current.roles)):
                                    return self._json(403, {"error": "匿名化なしの出力には承認責任者または管理者の権限が必要です"})
                                bound[0].audit.record("export.remotion_identified", actor=current.operator)
                            return self._json(200, payload)

                        return self._authorized_org_read(sess, org, deliver_remotion)
                    return self._authorized_org_read(sess, org, lambda _: self._json(200, payload))
                return self._authorized_org_read(
                    sess, org, lambda current: self._get_org(p, u, bound[0], current))
            if p == "/api/router/status":
                if tenancy is not None:
                    bound = self._bind(sess, (parse_qs(u.query).get("org") or [None])[0])
                    if bound is None:
                        return None
                    return self._authorized_org_read(
                        sess, self._bound_org,
                        lambda _: self._json(200, bound[0].planner_status()))
                if enforce_read_auth:
                    return self._authorized_org_read(
                        sess, DEFAULT_ORG, lambda _: self._json(200, svc.planner_status()))
                return self._json(200, svc.planner_status())
            if p == "/api/l2-profiles":
                if not sess or not ({"admin", "approver"} & set(sess.roles)):
                    return self._json(403, {"error": "プロファイルの参照には管理者または承認責任者の権限が必要です"})
                profiles = svc.l2_profiles_status()
                with ops.locked_session(sess.token) as current:
                    if current is None or current.operator != sess.operator:
                        return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                    if not ({"admin", "approver"} & set(current.roles)):
                        return self._json(403, {"error": "参照権限が失効しました"})
                    previous_timeout = self.connection.gettimeout()
                    self.connection.settimeout(2.0)
                    try:
                        return self._json(200, profiles)
                    finally:
                        self.connection.settimeout(previous_timeout)
            if p in JOB_ROUTES:
                # these START a verification job: POST only (CSRF-checked, role-checked, audited)
                return self._json(405, {"error": "この操作は POST で実行してください"}, [("Allow", "POST")])
            if p == "/api/agent-defense/status":
                from . import agent_defense
                state = agent_defense.availability()
                if state["available"] and not self._loopback_client():
                    state = {"available": False, "reason": "この端末以外からの接続では実行しません"}
                return self._authorized_platform_read(sess, lambda: self._json(
                    200, {**state, "scope": agent_defense.SCOPE_NOTE}))
            if p == "/api/cve/status":
                status_payload = svc.cve_monitor.status()
                if enforce_read_auth:
                    with ops.locked_session(sess.token) as current:
                        if current is None or current.operator != sess.operator:
                            return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                        previous_timeout = self.connection.gettimeout()
                        self.connection.settimeout(2.0)
                        try:
                            return self._json(200, status_payload)
                        finally:
                            self.connection.settimeout(previous_timeout)
                return self._json(200, status_payload)
            return self._json(404, {"error": "not found"})

        def _get_org(self, p, u, svc, sess):
            """Reads of one organization's data, from that organization's service only."""
            if p == "/api/assets/local-defense":
                org = getattr(self, "_bound_org", DEFAULT_ORG)
                if not sess:
                    return self._json(401, {"error": "ログインが必要です"})
                local_defense = local_control(org, svc)
                if local_defense is None:
                    return self._json(404, {"error": "ローカル防御検証は構成されていません"})
                return self._json(200, {**local_defense.view(), "actor": sess.operator,
                                        "may_request": bool(set(sess.roles) & {"operator", "approver", "admin"}),
                                        "may_approve": "approver" in sess.roles
                                        and _approver_class(sess.operator) == "registered"})
            if p == "/api/assets":
                return self._json(200, svc.assets())
            if p == "/api/assets/intelligence":
                if not sess:
                    return self._json(401, {"error": "ログインが必要です"})
                return self._json(200, svc.intelligence_snapshot(getattr(self, "_bound_org", DEFAULT_ORG)))
            if p == "/api/assets/cloud-run/binding":
                if not sess or "admin" not in sess.roles:
                    return self._json(403, {"error": "組織管理者の権限が必要です"})
                host = (parse_qs(u.query).get("host") or [""])[0]
                return self._json(200, svc.cloud_run_binding(getattr(self, "_bound_org", DEFAULT_ORG), host))
            if p == "/api/assets/secrets-status":
                q = parse_qs(u.query)
                host = (q.get("host") or [None])[0]
                return self._json(200, svc.secrets_status(host))
            if p == f"/api/assessments/{svc.a.id}":
                return self._json(200, svc.snapshot())
            if p == f"/api/assessments/{svc.a.id}/logs":
                return self._json(200, svc.logs())
            if p == f"/api/assessments/{svc.a.id}/diagnosis":
                view = svc.diagnosis_view()
                if view is None:
                    return self._json(404, {"error": "診断ループは登録済みのローカル検証ラボでのみ表示できます"})
                # what THIS caller may do (the screen shows only those controls; the server
                # checks every operation again with the live roles)
                view = {**view, "viewer": {"actor": sess.operator if sess else None,
                                           "permissions": member_permissions(sess.roles) if sess else []}}
                return self._json(200, view)
            if p == f"/api/assessments/{svc.a.id}/artex/llm-preview":
                # what the planner model was (or would be) sent: approver review only
                if not sess or "approver" not in sess.roles:
                    return self._json(403, {"error": "preview の内容確認には承認責任者の権限が必要です"})
                return self._json(200, svc.artex_llm_preview())
            if p == f"/api/assessments/{svc.a.id}/report":
                return self._json(200, {
                    "markdown": svc.report_markdown(),
                    "filename": f"vulnix-report-{svc.a.id}.md",
                })
            if p == f"/api/assessments/{svc.a.id}/remotion":
                q = parse_qs(u.query)
                anon = (q.get("anonymize") or ["1"])[0] != "0"
                if not anon:
                    # the identifying export: a deliberate, recorded act by someone with authority
                    if not sess or not ({"approver", "admin"} & set(sess.roles)):
                        return self._json(403, {"error": "匿名化なしの出力には承認責任者または管理者の権限が必要です"})
                    svc.audit.record("export.remotion_identified", actor=sess.operator)
                return self._json(200, svc.remotion_export(anonymize=anon))
            if p == f"/api/assessments/{svc.a.id}/events":
                q = parse_qs(u.query)
                after = self.headers.get("Last-Event-ID") or (q.get("after") or ["0"])[0]
                after = int(re.sub(r"\D", "", after) or 0)
                return self._sse(after, svc, sess)
            return self._json(404, {"error": "not found"})

        def _sse(self, after: int, svc=None, sess=None) -> None:
            svc = svc or default_svc
            key = sess.operator if sess else ""
            with limits_lock:
                if key and sse_open.get(key, 0) >= SSE_PER_ACCOUNT:
                    return self._json(429, {"error": "同時に開ける更新の受信が上限に達しています。ほかのタブを閉じてください"})
                if sum(sse_open.values()) >= SSE_PLATFORM:
                    return self._json(429, {"error": "ただいま混み合っています。しばらくしてから再読み込みしてください"},
                                      [("Retry-After", "30")])
                if key:
                    sse_open[key] = sse_open.get(key, 0) + 1
            org = getattr(self, "_bound_org", None)
            token = sess.token if sess else None

            @contextlib.contextmanager
            def event_permission():
                """Serialize each event write with session and membership revocation."""
                if token is None:
                    yield 0
                    return
                grant = live_grant_roles(sess, org or DEFAULT_ORG, reader=True)
                try:
                    grant.__enter__()
                except AuthError:
                    yield 401
                    return
                except ApproverRequired:
                    yield 403
                    return
                try:
                    yield 0
                finally:
                    grant.__exit__(None, None, None)
            try:
                return self._sse_loop(after, svc, event_permission)
            finally:
                if key:
                    with limits_lock:
                        sse_open[key] -= 1

        def _sse_loop(self, after: int, svc, event_permission) -> None:
            self.close_connection = True   # never reuse a socket after a stream ends
            self.connection.settimeout(2.0)  # a stalled reader must not hold revocation indefinitely
            seq = after
            last_ping = time.monotonic()
            try:
                with event_permission() as denied:
                    if denied:
                        return self._json(denied, {"error": "更新の受信権限が失効しました"})
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache, no-transform")
                    self.send_header("X-Accel-Buffering", "no")
                    self.send_header("Connection", "keep-alive")
                    self.end_headers()
                    # send_header("Connection", "keep-alive") turns close_connection back off
                    self.close_connection = True
                    self.wfile.write(b"retry: 2000\n\n")
                    self.wfile.flush()
                while True:
                    events = svc.bus.wait(seq, timeout=5)
                    for ev in events:
                        # One event per lease lets logout and member removal enter
                        # between backlog entries, even if the client is slow.
                        with event_permission() as denied:
                            if denied:
                                return
                            data = json.dumps(ev, ensure_ascii=False)
                            self.wfile.write(f"id: {ev['event_id']}\ndata: {data}\n\n".encode())
                            seq = ev["seq"]
                            self.wfile.flush()
                    with event_permission() as denied:
                        if denied:
                            return
                        if time.monotonic() - last_ping > 4:
                            # Heartbeat seq lets the browser detect a missing event.
                            self.wfile.write(f"event: heartbeat\ndata: {{\"seq\":{seq}}}\n\n".encode())
                            last_ping = time.monotonic()
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                return

        # ---- POST -----------------------------------------------------------
        def do_POST(self):
            if not self._host_ok():
                return self._refuse(421, "misdirected request")
            origin = self.headers.get("Origin")
            if self.headers.get("X-Aegis-Request") != "1" or (origin and origin not in ALLOWED_ORIGINS):
                return self._refuse(403, "csrf check failed")
            if self.headers.get("Transfer-Encoding"):
                return self._refuse(400, "transfer-encoding is not supported")
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return self._refuse(400, "invalid content-length")
            if n < 0 or n > MAX_BODY_BYTES:
                return self._refuse(413, "request body too large")
            try:
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return self._json(400, {"error": "invalid json"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "request body must be a JSON object"})
            try:
                # e.g. lone surrogates: valid JSON escapes that cannot be stored as UTF-8
                json.dumps(body, ensure_ascii=False).encode("utf-8")
            except (UnicodeEncodeError, ValueError):
                return self._json(400, {"error": "request body contains characters that cannot be stored"})
            p = urlsplit(self.path).path.rstrip("/")

            if p == "/api/auth/login":
                return self._login(body)
            if p == "/api/auth/register":
                return self._register(body)
            if p == "/api/auth/logout":
                sess = self._session()
                if sess:
                    try:
                        paudit.record("auth.logout", actor=sess.operator)
                    except Exception:
                        pass        # an audit log that cannot be written must not keep a session alive
                try:
                    ops.logout(sess.token if sess else None)
                except AuthError as e:
                    # signed out in this process, but not on disk: say so (a restart
                    # would bring the session back); the cookie is cleared all the same
                    return self._json(500, {"session": None, "error": str(e), "logout_saved": False},
                                      self._clear_cookie())
                return self._json(200, {"session": None}, self._clear_cookie())

            sess = self._session()
            if not sess:
                return self._json(401, {"error": "ログインが必要です"})
            # (removing another account's second factor weakens its sign-in: not a reduction)
            reduces_power = p.endswith(("/emergency-stop", "/pause")) or (
                p == "/api/operators/roles" and isinstance(body.get("roles"), list)
                and set(map(str, body["roles"])) <= set(ops.roles_of(str(body.get("name", "")).strip())))
            if not ops.trusted() and not reduces_power:
                # The auth state on disk is not the one in force (a logout, password
                # change or role removal could not be saved). Nothing new is done until
                # it is; stopping things and removing power stay possible.
                return self._json(503, {"error": "認証情報を保存できないため、操作を停止しています。"
                                                 "データディレクトリの書き込み権限を確認してください",
                                        "auth_unsaved": ops.unsaved()})
            if p == "/api/auth/password":
                return self._change_password(body, sess)
            if p == "/api/auth/totp/enroll":
                return self._totp_enroll(sess)
            if p == "/api/auth/totp/confirm":
                return self._totp_confirm(body, sess)
            if p == "/api/auth/totp/disable":
                return self._totp_disable(body, sess)
            if p == "/api/operators/roles":
                return self._set_roles(body, sess)
            if p in ("/api/operators/unlock", "/api/operators/reset-mfa", "/api/operators/reset-password"):
                return self._admin_recovery(p, body, sess)
            if tenancy is not None:
                if p.startswith("/api/orgs") or p == "/api/invites/accept":
                    with ops.locked_session(sess.token) as current:
                        if current is None or current.operator != sess.operator:
                            return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                        previous_timeout = self.connection.gettimeout()
                        self.connection.settimeout(2.0)
                        try:
                            return self._tenancy_post(p, body, current)
                        finally:
                            self.connection.settimeout(previous_timeout)
                if p.endswith("/lab-mode"):
                    # the mock lab is shared even with the default organization;
                    # a platform admin could change another tenant's run mid-probe
                    paudit.record("tenancy.lab_mode_denied", actor=sess.operator)
                    return self._json(403, {"error": "模擬ラボは全組織で共有されているため、公開版では設定を変更できません"})
                if p not in PLATFORM_POST_ROUTES:
                    bound = self._bind(sess)
                    if bound is None:
                        return None
                    osvc, osess = bound
                    self._select_target = str(body.get("id", "")) if p == "/api/assets/select" else ""
                    if p.startswith(f"/api/assessments/{osvc.a.id}/diagnosis/"):
                        # the diagnosis loop exists for the registered lab only: on a real site
                        # (or a site still in the ownership flow) the route does not exist
                        try:
                            not_lab = not osvc.diagnosis_targets()
                        except Exception:   # noqa: BLE001 - when in doubt, it is not the lab
                            not_lab = True
                        if not_lab:
                            return self._json(404, {"error": "診断ループは登録済みのローカル検証ラボでのみ使用できます"})
                    # Mode 0 always disables real-site traffic. Only the legacy
                    # broad switch is narrowed to L1 when tenants are present.
                    read_only_real = REAL_SITE_L1_ONLY or (tenancy is not None and REAL_SERVICE_DIAGNOSIS)
                    if (p in _OWNERSHIP_LOOKUPS
                            and _ownership_traffic_mode(self._bound_org) in ("approved", "preapproved")):
                        real_site_traffic = True
                    elif (not REAL_SERVICE_DIAGNOSIS or tenancy is not None) and self._touches_real_site(p, osvc):
                        refusal = self._real_site_refusal(p, osvc) if read_only_real else \
                            "このβ版では、実サイトへの通信（所有確認の実行・診断）はまだ有効になっていません。模擬ラボで機能をお試しください"
                        if refusal:
                            paudit.record("tenancy.real_site_refused", actor=sess.operator, route=p[-60:])
                            return self._json(403, {"error": refusal})
                        real_site_traffic = True
                    else:
                        real_site_traffic = False
                    # viewers read; stopping things stays open to every member
                    if not ({"operator", "approver", "admin"} & set(osess.roles)) \
                            and not p.endswith(("/emergency-stop", "/pause")):
                        return self._json(403, {"error": "閲覧者の権限では操作できません"})
                    # L1-only mode: traffic to real sites is bounded per organization and platform-wide
                    limited = None
                    artex_item = bool(re.fullmatch(
                        f"/api/assessments/{osvc.a.id}" + r"/artex/items/[A-Za-z0-9_]{1,80}/execute", p))
                    if read_only_real and not real_site_traffic and (
                            (p.endswith(("/start", "/restart", "/resume")) and "/diagnosis/" not in p) or artex_item):
                        # the workspace can be switched onto a proven site between this check and
                        # the run: every run of an organization holding one is counted
                        try:
                            real_site_traffic = osvc.has_scoped_real_site()
                        except Exception:   # noqa: BLE001 - when in doubt, count it
                            real_site_traffic = True
                    if real_site_traffic and (read_only_real or p in _OWNERSHIP_LOOKUPS):
                        if p in ("/api/assets/verify-ownership", "/api/assets/cloud-run/finish"):
                            limited = (verify_times, verify_all, OWNERSHIP_CHECKS_PER_ORG_PER_HOUR,
                                       OWNERSHIP_CHECKS_PLATFORM_PER_HOUR,
                                       "所有確認は1時間あたりの上限に達しました。DNS の設定が反映されるまで少し待ってからお試しください")
                        elif (p.endswith(("/start", "/restart", "/resume")) and "/diagnosis/" not in p) or artex_item:
                            limited = (real_run_times, real_run_all, REAL_SITE_RUNS_PER_ORG_PER_HOUR,
                                       REAL_SITE_RUNS_PLATFORM_PER_HOUR,
                                       "このサイトの診断は1時間あたりの上限に達しました。時間をおいてお試しください")
                    if limited:
                        per_org, overall, cap_org, cap_all, msg = limited
                        with limits_lock:
                            mine_v = per_org.setdefault(self._bound_org, [])
                            ok = room(mine_v, 3600, cap_org) and room(overall, 3600, cap_all)
                            if ok:
                                within(mine_v, 3600, cap_org)
                                within(overall, 3600, cap_all)
                        if not ok:
                            return self._json(429, {"error": msg}, [("Retry-After", "600")])
                    if p.endswith("/chat"):
                        with limits_lock:
                            mine = chat_times.setdefault(self._bound_org, [])
                            # both limits are checked before either is used: a refusal costs no quota
                            ok = room(mine, 3600, CHAT_PER_ORG_PER_HOUR) and room(chat_all, 3600, CHAT_PLATFORM_PER_HOUR) \
                                and room(chat_day, 86400, CHAT_PLATFORM_PER_DAY)
                            if ok:
                                within(mine, 3600, CHAT_PER_ORG_PER_HOUR)
                                within(chat_all, 3600, CHAT_PLATFORM_PER_HOUR)
                                within(chat_day, 86400, CHAT_PLATFORM_PER_DAY)
                        if not ok:
                            return self._json(429, {"error": f"AI 解説は1つの組織につき1時間あたり {CHAT_PER_ORG_PER_HOUR} 回までです"},
                                              [("Retry-After", "600")])
                    if p.endswith("/artex/plan"):
                        # every ARTEX run costs CPU and a confined process, whatever the model mode
                        with limits_lock:
                            mine_r = run_times.setdefault(self._bound_org, [])
                            ok = room(mine_r, 3600, ARTEX_PLANS_PER_ORG_PER_HOUR) and room(run_all, 3600, ARTEX_PLANS_PLATFORM_PER_HOUR)
                            if ok:
                                within(mine_r, 3600, ARTEX_PLANS_PER_ORG_PER_HOUR)
                                within(run_all, 3600, ARTEX_PLANS_PLATFORM_PER_HOUR)
                        if not ok:
                            return self._json(429, {"error": "ARTEX の計画は、1時間あたりの上限に達しています。時間をおいてください"},
                                              [("Retry-After", "600")])
                    # the mode as the service decides it (request value, else the configured one)
                    mode = (str(body.get("llm_mode") or "") or os.environ.get("VULNIX_ARTEX_LLM_MODE", "direct")).strip().lower()
                    # counted only for a plan that can reach the real model: forward mode with an
                    # approval (the service refuses forward without one, so it costs nothing)
                    if p.endswith("/artex/plan") and mode != "direct" and mode != "gateway-preview" \
                            and isinstance(body.get("llm_approval"), dict):
                        with limits_lock:
                            mine = plan_times.setdefault(self._bound_org, [])
                            ok = room(mine, 3600, ARTEX_LLM_PLANS_PER_ORG_PER_HOUR) \
                                and room(plan_all, 3600, ARTEX_LLM_PLANS_PLATFORM_PER_HOUR) \
                                and room(plan_day, 86400, ARTEX_LLM_PLANS_PER_DAY)
                            if ok:
                                within(mine, 3600, ARTEX_LLM_PLANS_PER_ORG_PER_HOUR)
                                within(plan_all, 3600, ARTEX_LLM_PLANS_PLATFORM_PER_HOUR)
                                within(plan_day, 86400, ARTEX_LLM_PLANS_PER_DAY)
                        if not ok:
                            return self._json(429, {"error": "実モデルを使う ARTEX の計画は、利用上限に達しています。時間をおいてください"},
                                              [("Retry-After", "600")])
                    return self._dispatch(p, body, osess, osvc)
            return self._dispatch(p, body, sess)

        def _change_password(self, body, sess):
            journal = _Journal(paudit, "auth.password_changed", actor=sess.operator)
            try:
                # audit first: a password that cannot be recorded is not changed
                gen = ops.change_password(sess.operator, str(body.get("current", "")),
                                          str(body.get("new", "")), keep_token=sess.token, journal=journal)
            except AuditWriteFailed as e:
                return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
            except LockedOut as e:
                return self._locked(e, sess.operator)
            except AuthError as e:
                if isinstance(e, ChangeNotSaved):   # undone: the audit-first record did not happen
                    journal.not_committed("not_saved")
                return self._self_failure(sess, e)
            # the change is in force (its intent is recorded); a missing completion is a gap
            audit_after(paudit, "auth.password_change_committed", default_svc, "platform",
                        account=sess.operator, credential_generation=gen)
            return self._json(200, {"ok": True})

        def _totp_enroll(self, sess):
            try:
                secret, uri = ops.begin_totp_enroll(sess.operator, session_token=sess.token)
            except AuthError as e:
                return self._self_failure(sess, e)
            # The secret/URI are shown once to the operator to add to their
            # authenticator; they are not recorded in the audit log.
            paudit.record("auth.mfa_enroll_started", actor=sess.operator)
            return self._json(200, {"secret": secret, "uri": uri})

        def _totp_confirm(self, body, sess):
            try:
                ops.confirm_totp(sess.operator, str(body.get("code", "")), session_token=sess.token)
            except AuthError as e:
                return self._self_failure(sess, e)
            paudit.record("auth.mfa_enabled", actor=sess.operator)
            return self._json(200, {"ok": True, "mfa_enabled": True})

        def _totp_disable(self, body, sess):
            journal = _Journal(paudit, "auth.mfa_disabled", actor=sess.operator)
            try:
                # audit first: the second factor is not removed without its record
                ops.disable_totp(sess.operator, str(body.get("current", "")), str(body.get("code", "")) or None,
                                 session_token=sess.token, journal=journal)
            except AuditWriteFailed as e:
                return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
            except LockedOut as e:
                return self._locked(e, sess.operator)
            except AuthError as e:
                if isinstance(e, ChangeNotSaved):   # undone: the audit-first record did not happen
                    journal.not_committed("not_saved")
                return self._self_failure(sess, e)
            return self._json(200, {"ok": True, "mfa_enabled": False})

        def _locked(self, e: LockedOut, name: str):
            """429 for a paused sign-in. The same answer is given for names that do
            not exist, so it does not reveal which accounts are real."""
            if e.just_locked:
                paudit.record("auth.locked", name=name[:32], seconds=int(e.retry_after))
            return self._json(429, {"error": str(e), "locked": True, "retry_after": int(e.retry_after)},
                              [("Retry-After", str(int(e.retry_after)))])

        def _drain_recovery_events(self):
            while ops.recovery_events:
                ev = ops.recovery_events.pop(0)
                paudit.record(ev.pop("event"), **ev)

        def _login(self, body):
            try:
                sess = ops.login(str(body.get("name", "")), str(body.get("password", "")),
                                 str(body.get("code", "")) or None)
            except LockedOut as e:
                self._drain_recovery_events()
                return self._locked(e, str(body.get("name", "")))
            except MFAChallenge as e:
                time.sleep(0.2)
                return self._json(401, {"error": str(e), "mfa_required": True})
            except AuthError as e:
                time.sleep(0.2)   # uniform-ish delay on failure
                paudit.record("auth.login_failed", name=str(body.get("name", ""))[:32])
                return self._json(401, {"error": str(e)})
            self._drain_recovery_events()
            paudit.record("auth.login", actor=sess.operator, roles=list(sess.roles))
            cookie = (f"{COOKIE}={sess.token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={int(sess.expires - time.time())}")
            return self._json(200, {"session": self._public_session(sess)},
                              [("Set-Cookie", cookie)])

        def _register(self, body):
            # Roles are never taken from the request: every new account is an `operator`.
            raw_roles = body.get("roles")
            asked = [str(r) for r in raw_roles] if isinstance(raw_roles, list) else []
            name, password = str(body.get("name", "")), str(body.get("password", ""))
            display = str(body.get("display", ""))
            caller = self._session()
            if caller and "admin" in caller.roles:
                # an admin creates the account for someone else; the admin stays logged in
                try:
                    op = ops.create_account(name, password, display=display, actor=caller.operator,
                                            session_token=caller.token)
                except AuthError as e:
                    return self._admin_failure(caller, e, 400)
                paudit.record("operator.created", actor=caller.operator, target=op.name, roles=list(op.roles),
                                 requested_roles_ignored=[r for r in asked if r not in op.roles],
                                 **ops.credential_fields(op.name))   # a reused name: its new incarnation
                return self._json(200, {"created": {"name": op.name, "display": op.display, "roles": list(op.roles)}})
            if not self_registration_allowed():
                paudit.record("auth.registration_refused", name=name[:32])
                return self._json(403, {"error": "アカウントの作成は管理者が行います（設定 → アカウントとロール）。"
                                                 "自己登録は開発モードでのみ利用できます"})
            invite = str(body.get("invite", "") or "")
            tenancy_warning = None
            if tenancy is not None and invite and not tenancy.store.invite_valid(invite):
                # checked before the account exists: a bad link leaves no orphan account
                return self._json(400, {"error": "招待が無効です（使用済み・取り消し済み・期限切れ・誤り）"})
            if tenancy is not None and not invite and tenancy.store.at_capacity():
                return self._json(503, {"error": "現在、新しい登録を受け付けていません（β版の受け入れ上限に達しました）"})
            with limits_lock:
                allowed = room(signup_times, 60, SIGNUPS_PER_MINUTE)  # cheap early refusal
            if not allowed:
                paudit.record("auth.registration_throttled", name=name[:32])
                return self._json(429, {"error": "ただいま登録が混み合っています。少し時間をおいてお試しください"},
                                  [("Retry-After", "60")])
            # one sign-up at a time: the invite check, the account and the membership
            # happen together (two sign-ups racing on one invite cannot both pass)
            signup_lock.acquire()
            try:
                if tenancy is not None and invite and not tenancy.store.invite_valid(invite):
                    return self._json(400, {"error": "招待が無効です（使用済み・取り消し済み・期限切れ・誤り）"})
                with limits_lock:
                    # decided again here, one sign-up at a time: a parallel burst cannot pass
                    # the early check together; every attempt that will hash a password counts
                    if not room(signup_times, 60, SIGNUPS_PER_MINUTE) \
                            or not within(signup_attempts, 60, SIGNUP_ATTEMPTS_PER_MINUTE):
                        throttled = True
                    else:
                        throttled = False
                if throttled:
                    paudit.record("auth.registration_throttled", name=name[:32])
                    return self._json(429, {"error": "ただいま登録が混み合っています。少し時間をおいてお試しください"},
                                      [("Retry-After", "60")])
                try:
                    sess = ops.register(name, password, display=display)
                except AuthError as e:
                    return self._json(400, {"error": str(e)})
                with limits_lock:
                    signup_times.append(time.monotonic())
                if tenancy is not None:
                    # the new account sees only its own organization (or the one it was invited to)
                    try:
                        if invite:
                            org_id, roles = tenancy.store.accept_invite(
                                invite, sess.operator,
                                journal=lambda oid, r: audit_first(tenancy.service(oid).audit,
                                                                   "tenancy.invite_accepted",
                                                                   actor=sess.operator, roles=r))
                        else:
                            self._create_org(f"{display or sess.operator} の組織", sess.operator)
                    except (TenancyError, AuditWriteFailed) as e:
                        tenancy_warning = str(e)     # signed in all the same; no organization yet
            finally:
                signup_lock.release()
            # self-registration stays record-after (docs/AUDIT_BEFORE_STATE.md); a record that
            # cannot be written is kept as an audit gap and the response stays clean
            registered = audit_after(paudit, "auth.registered", gap_svc=default_svc, gap_log="platform",
                                     actor=sess.operator, roles=list(sess.roles), self_registered=True,
                                     requested_roles_ignored=[r for r in asked if r not in sess.roles],
                                     **ops.credential_fields(sess.operator))
            cookie = (f"{COOKIE}={sess.token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={int(sess.expires - time.time())}")
            out = {"session": self._public_session(sess)}
            if not registered:
                out["audit_failed"] = True
            if tenancy is not None:
                out["orgs"] = tenancy.store.orgs_of(sess.operator)
                if tenancy_warning:
                    out["warning"] = tenancy_warning
            return self._json(200, out, [("Set-Cookie", cookie)])

        def _admin_failure(self, sess, error, ordinary_status: int):
            current = ops.resolve(sess.token)
            if current is None or current.operator != sess.operator:
                return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
            if "admin" not in current.roles:
                return self._json(403, {"error": "管理者の権限が失効しました"})
            return self._json(ordinary_status, {"error": str(error)})

        def _self_failure(self, sess, error):
            if ops.resolve(sess.token) is None:
                return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
            return self._json(400, {"error": str(error)})

        def _set_roles(self, body, sess):
            if "admin" not in sess.roles:
                paudit.record("operator.roles_change_denied", actor=sess.operator,
                                 target=str(body.get("name", ""))[:64])
                return self._json(403, {"error": "ロールの変更には管理者の権限が必要です"})
            raw = body.get("roles")
            roles = [str(r) for r in raw] if isinstance(raw, list) else []
            target = str(body.get("name", "")).strip()
            unrecorded = []

            def journal(before, after):
                # audit first; only removing power goes ahead without its record
                try:
                    paudit.record("operator.roles_changed", actor=sess.operator, target=target,
                                  before=list(before), after=list(after),
                                  attested_unchanged=set(before) == set(after))
                except Exception as e:  # noqa: BLE001
                    if set(after) <= set(before) and set(after) != set(before):
                        unrecorded.append({"actor": sess.operator, "target": target,
                                           "before": list(before), "after": list(after)})
                        return
                    raise AuditWriteFailed(AUDIT_REFUSED) from e
            try:
                before, after = ops.set_roles(target, roles, actor=sess.operator,
                                              session_token=sess.token, journal=journal)
            except AuditWriteFailed as e:
                return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
            except AuthError as e:
                paudit.record("operator.roles_change_failed", actor=sess.operator, target=target[:64],
                                 requested=roles[:8], error=str(e)[:200])
                return self._admin_failure(sess, e, 409)
            if unrecorded:
                # noted after the store's lock is released
                default_svc._note_audit_gap("operator.roles_changed", unrecorded[0], log="platform")
                return self._json(503, {"error": AUDIT_MISSING, "applied": True, "audit_failed": True,
                                        "name": target, "roles": list(after)})
            return self._json(200, {"name": target, "roles": list(after)})

        def _admin_recovery(self, p, body, sess):
            """Recovery actions an admin performs for a legitimate user."""
            target = str(body.get("name", "")).strip()
            if "admin" not in sess.roles:
                paudit.record("operator.recovery_denied", actor=sess.operator, target=target[:64], action=p)
                return self._json(403, {"error": "この操作には管理者の権限が必要です"})
            # audit first: both weaken another account's protection (a lock, a second
            # factor), so neither happens without its record
            if p == "/api/operators/reset-password":
                # also the way out of an account blocked by an unfinished password change
                # (docs/PASSWORD_CHANGE_DURABILITY.md); audit first and two-phase
                journal = _Journal(paudit, "operator.password_reset", actor=sess.operator, target=target[:64])
                try:
                    gen = ops.reset_password(target, str(body.get("password", "")), actor=sess.operator,
                                             session_token=sess.token, journal=journal)
                except AuditWriteFailed as e:
                    return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
                except AuthError as e:
                    if isinstance(e, ChangeNotSaved):
                        journal.not_committed("not_saved")
                    return self._admin_failure(sess, e, 409)
                audit_after(paudit, "auth.password_change_committed", default_svc, "platform",
                            account=target, credential_generation=gen, reset_by=sess.operator)
                return self._json(200, {"name": target, "changed": True})
            if p == "/api/operators/unlock":
                journal = _Journal(paudit, "operator.unlocked", actor=sess.operator, target=target[:64])
            else:
                journal = _Journal(paudit, "operator.mfa_reset", actor=sess.operator, target=target[:64])
            try:
                if p == "/api/operators/unlock":
                    changed = ops.unlock(target, actor=sess.operator, session_token=sess.token,
                                         journal=lambda was: journal(was_locked=was))
                else:
                    changed = ops.reset_totp(target, actor=sess.operator, session_token=sess.token,
                                             journal=lambda had: journal(had_mfa=had))
            except AuditWriteFailed as e:
                return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
            except AuthError as e:
                if isinstance(e, ChangeNotSaved):   # undone: the audit-first record did not happen
                    journal.not_committed("not_saved")
                return self._admin_failure(sess, e, 409)
            return self._json(200, {"name": target, "changed": changed})

        # ---- organizations (tenancy) --------------------------------------------
        def _org_for_management(self, sess, body=None):
            org_id = self._org_requested(str((body or {}).get("org", "") or "") or None)
            if not org_id:
                orgs = tenancy.store.orgs_of(sess.operator)
                org_id = orgs[0]["id"] if orgs else ""
            if not org_id or not tenancy.store.roles_in(org_id, sess.operator):
                raise TenancyError("この組織のメンバーではありません")
            return org_id

        def _tenancy_get(self, p, u, sess):
            if not sess:
                return self._json(401, {"error": "ログインが必要です"})
            with ops.locked_session(sess.token) as current:
                if current is None or current.operator != sess.operator:
                    return self._json(401, {"error": "ログインの有効期限が切れました。もう一度ログインしてください"})
                if p == "/api/orgs":
                    return self._json(200, {"orgs": tenancy.store.orgs_of(current.operator)})
                try:
                    org_id = self._org_for_management(current, {"org": (parse_qs(u.query).get("org") or [""])[0]})
                except TenancyError as e:
                    return self._json(403, {"error": str(e)})
                with tenancy.store.locked_roles_in(org_id, current.operator) as roles:
                    mine = set(roles)
                    if not mine:
                        return self._json(403, {"error": "この組織のメンバーではありません"})
                    if p == "/api/orgs/members":
                        return self._json(200, {"org": {"id": org_id, "name": tenancy.store.org_name(org_id)},
                                                "my_roles": sorted(mine), "members": tenancy.store.members(org_id)})
                    if p == "/api/orgs/invites":
                        if not mine & {"owner", "admin"}:
                            return self._json(403, {"error": "招待の一覧はオーナーまたは管理者だけが見られます"})
                        return self._json(200, {"invites": tenancy.store.invites(org_id)})
                    return self._json(404, {"error": "not found"})

        def _create_org(self, name, owner):
            """Audit first, in the platform log (the organization's own log does not
            exist yet); then a copy in the new organization's log (best effort)."""
            journal = _Journal(paudit, "tenancy.org_created", actor=owner)
            try:
                org_id = tenancy.store.create_org(name, owner, journal=lambda oid: journal(org=oid))
            except (TenancyError, AuditWriteFailed):
                raise
            except Exception:
                journal.not_committed("not_saved")
                raise
            with contextlib.suppress(Exception):
                tenancy.service(org_id).audit.record("tenancy.org_created", actor=owner)
            return org_id

        def _tenancy_post(self, p, body, sess):
            st = tenancy.store
            journals: list[_Journal] = []      # audit-first records of this request
            try:
                if p == "/api/orgs":
                    org_id = self._create_org(str(body.get("name", "")), sess.operator)
                    return self._json(200, {"org": {"id": org_id, "name": st.org_name(org_id)},
                                            "orgs": st.orgs_of(sess.operator)})
                if p == "/api/invites/accept":
                    def accept_journal(oid, r):
                        journals.append(_Journal(tenancy.service(oid).audit, "tenancy.invite_accepted",
                                                 actor=sess.operator, roles=r))
                        journals[-1]()
                    org_id, roles = st.accept_invite(str(body.get("token", "")), sess.operator,
                                                     journal=accept_journal)
                    return self._json(200, {"org": {"id": org_id, "name": st.org_name(org_id)}, "roles": roles,
                                            "orgs": st.orgs_of(sess.operator)})
                org_id = self._org_for_management(sess, body)
                audit = tenancy.service(org_id).audit
                if p == "/api/orgs/members/roles":
                    target = str(body.get("name", "")).strip()
                    unrecorded = []

                    def journal(before, after):
                        # audit first; only removing power goes ahead without its record
                        try:
                            audit.record("tenancy.member_roles_changed", actor=sess.operator, target=target,
                                         before=before, after=after)
                            journals.append(_Journal(audit, "tenancy.member_roles_changed"))
                            journals[-1].written = True
                        except Exception as e:  # noqa: BLE001
                            # a removal: no new organization role (viewer carries no power)
                            # and no new service role
                            if (set(service_roles(after)) <= set(service_roles(before))
                                    and set(after) <= set(before) | {"viewer"} and set(after) != set(before)):
                                unrecorded.append({"actor": sess.operator, "target": target,
                                                   "before": before, "after": after})
                                return
                            raise AuditWriteFailed(AUDIT_REFUSED) from e
                    st.set_roles(org_id, sess.operator, target, body.get("roles"), journal=journal)
                    if unrecorded:
                        osvc_gap = tenancy.service(org_id)
                        osvc_gap._note_audit_gap("tenancy.member_roles_changed", unrecorded[0])
                        return self._json(503, {"error": AUDIT_MISSING, "applied": True, "audit_failed": True,
                                                "members": st.members(org_id)})
                    return self._json(200, {"members": st.members(org_id)})
                if p == "/api/orgs/members/remove":
                    target = str(body.get("name", "")).strip()
                    st.remove_member(org_id, sess.operator, target)
                    # a removal: applied whatever the audit log does, then recorded
                    if not audit_after(audit, "tenancy.member_removed", gap_svc=tenancy.service(org_id),
                                       actor=sess.operator, target=target):
                        return self._json(503, {"error": AUDIT_MISSING, "applied": True, "audit_failed": True,
                                                "members": st.members(org_id)})
                    return self._json(200, {"members": st.members(org_id)})
                if p == "/api/orgs/invites":
                    hours = body.get("ttl_hours", 168)
                    ttl = float(hours) * 3600 if isinstance(hours, (int, float)) else 168 * 3600
                    journals.append(_Journal(audit, "tenancy.invite_created", actor=sess.operator))
                    iid, token = st.create_invite(
                        org_id, sess.operator, body.get("roles"), ttl,
                        journal=lambda i, r: journals[-1](invite=i, roles=r))
                    # the token is shown once to the inviter; only its hash is stored
                    return self._json(200, {"id": iid, "token": token, "invites": st.invites(org_id)})
                if p == "/api/orgs/invites/revoke":
                    st.revoke_invite(org_id, sess.operator, str(body.get("id", "")))
                    if not audit_after(audit, "tenancy.invite_revoked", gap_svc=tenancy.service(org_id),
                                       actor=sess.operator, invite=str(body.get("id", ""))[:40]):
                        return self._json(503, {"error": AUDIT_MISSING, "applied": True, "audit_failed": True,
                                                "invites": st.invites(org_id)})
                    return self._json(200, {"invites": st.invites(org_id)})
            except AuditWriteFailed as e:
                return self._json(503, {"error": str(e), "applied": False, "audit_failed": True})
            except TenancyError as e:
                return self._json(403 if "権限" in str(e) or "メンバー" in str(e) else 400, {"error": str(e)})
            except OSError:
                # the store could not be saved: nothing changed (OrgStore._tx), so an
                # audit-first record of this request is marked as not committed
                for j in journals:
                    j.not_committed("not_saved")
                return self._json(500, {"error": "組織の情報を保存できなかったため、変更していません"})
            return self._json(404, {"error": "not found"})

        def _clear_cookie(self):
            return [("Set-Cookie", f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")]

        def _dispatch(self, p, body, sess, svc=None):
            # Binding can wait on target checks and rate limits. A logout or
            # membership change during that time must not use the old snapshot.
            live_error = None
            if not p.endswith(("/emergency-stop", "/pause")):
                # A failed auth-state save must never prevent reducing power.
                with ops.locked_session(sess.token) as current:
                    if current is None or current.operator != sess.operator:
                        live_error = (401, "ログインの有効期限が切れました。もう一度ログインしてください")
                    elif tenancy is not None and svc is not None:
                        with tenancy.store.locked_roles_in(self._bound_org, current.operator) as org_roles:
                            if not org_roles:
                                live_error = (403, "この組織のメンバーではありません")
                            else:
                                roles = service_roles(org_roles)
                                if not ({"operator", "approver", "admin"} & set(roles)):
                                    live_error = (403, "閲覧者の権限では操作できません")
                                sess = dataclasses.replace(current, roles=roles)
                    else:
                        sess = current
            if live_error:
                return self._json(live_error[0], {"error": live_error[1]})
            svc = svc or default_svc
            base = f"/api/assessments/{svc.a.id}"
            actor = sess.operator
            try:
                if p == "/api/assets/ownership-traffic":
                    return self._ownership_request(svc, sess, body)
                elif p == "/api/assets/cloud-inventory":
                    org = getattr(self, "_bound_org", DEFAULT_ORG)
                    owner = (org, actor, hashlib.sha256(sess.token.encode()).digest())
                    cfg = cloud_inventory.config()

                    def deliver(action):
                        return self._authorized_org_read(sess, org, action, reader=False)

                    def reply(action):
                        try:
                            return self._json(200, action())
                        except cloud_inventory.CloudInventoryError as e:
                            return self._json(e.status, {"error": str(e)})

                    action = body.get("action")
                    if action == "status" and set(body) == {"action"}:
                        return deliver(lambda _: self._json(200, {"configured": cfg is not None}))
                    if cfg is None:
                        return deliver(lambda _: self._json(404, {"error": "Google Cloud の閲覧連携は未設定です。"}))
                    if action in ("start", "projects", "clear") and set(body) == {"action"}:
                        if action == "start":
                            return deliver(lambda _: reply(lambda: inventory.start(owner, cfg)))
                        if action == "clear":
                            return deliver(lambda _: reply(lambda: inventory.clear(owner) or {"configured": True}))
                        return deliver(lambda _: reply(lambda: inventory.get(owner)))
                    if action != "finish" or set(body) != {"action", "code", "state"}:
                        return self._json(400, {"error": "不明な連携操作です。"})
                    code, state = body["code"], body["state"]
                    if (not isinstance(code, str) or not re.fullmatch(r"[!-~]{1,2048}", code)
                            or not isinstance(state, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", state)):
                        return self._json(400, {"error": "Google の応答が無効です。"})
                    try:
                        with live_grant_roles(sess, org, reader=False):
                            flow, verifier = inventory.claim(owner, state)
                        result = cloud_inventory.fetch_projects(cfg, code, verifier)
                    except cloud_inventory.CloudInventoryError as e:
                        status, message = e.status, str(e)
                        return deliver(lambda _: self._json(status, {"error": message}))

                    def publish():
                        inventory.publish(owner, flow, result)
                        return {"connected": True}

                    return deliver(lambda _: reply(publish))
                if p == "/api/assets/local-defense":
                    org = getattr(self, "_bound_org", DEFAULT_ORG)
                    local_defense = local_control(org, svc)
                    if local_defense is None:
                        return self._json(404, {"error": "ローカル防御検証は構成されていません"})
                    authority = live_request_authority(sess, org)
                    action = body.get("action")
                    if action == "request" and set(body) == {"action", "profile", "plan_sha256", "folder_sha256"}:
                        local_defense.request(body["profile"], body["plan_sha256"], body["folder_sha256"],
                                              actor, authority)
                    elif action == "start" and set(body) == {"action", "id", "folder_sha256"}:
                        local_defense.start(body["id"], body["folder_sha256"], actor, authority)
                    elif action == "cancel" and set(body) == {"action", "id"}:
                        with authority.lease():
                            local_defense.cancel(body["id"], actor, "approver" in sess.roles)
                    else:
                        return self._json(400, {"error": "対応していないローカル防御検証操作です"})
                    return self._authorized_org_read(
                        sess, org, lambda _: self._json(200, local_defense.view()), reader=False)
                if p == "/api/assets":
                    asset = svc.register_asset(
                        name=str(body.get("name", "")),
                        kind=str(body.get("kind", "Webアプリケーション")),
                        environment=str(body.get("environment", "検証環境")),
                        authorization_ref=str(body.get("authorization_ref", "")),
                        ownership_verified=bool(body.get("ownership_verified", False)),
                        activate_workspace=bool(body.get("activate_workspace", False)),
                        actor=actor,
                    )
                    payload = {"asset": asset, "assets": svc.assets()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False)
                elif p == "/api/assets/project":
                    if set(body) != {"id", "project_label"} or not isinstance(body["id"], str):
                        return self._json(400, {"error": "対象とプロジェクト名を指定してください"})
                    org = getattr(self, "_bound_org", DEFAULT_ORG)
                    return self._authorized_org_read(sess, org, lambda _: self._json(200, {
                        "assets": svc.set_asset_project(body["id"], body["project_label"], actor),
                    }), reader=False)
                elif p == "/api/assets/challenge":
                    target_host = ""
                    try:
                        target_host = parse_service_target(str(body.get("url", "")))["host"]
                    except ValueError:
                        pass                       # reported by the service call below
                    if (target_host and svc.real_service_has_authority(target_host)
                            and "approver" not in sess.roles):
                        # re-registering a verified service can drop its proof, scope and tokens
                        return self._json(403, {"error": "所有確認済みの対象の再登録には承認責任者の権限が必要です"})
                    res = svc.issue_ownership_challenge(
                        url=str(body.get("url", "")),
                        sow_id=str(body.get("sow_id", "")),
                        approver=actor,
                        kind=str(body.get("kind", "Webアプリケーション")),
                        environment=str(body.get("environment", "ステージング環境")),
                        project_label=body.get("project_label", ""),
                        grant_guard=lambda: live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)),
                    )
                    payload = {**res, "assets": svc.assets()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False)
                elif p == "/api/assets/cloud-run/register":
                    if "admin" not in sess.roles:
                        return self._json(403, {"error": "組織管理者の権限が必要です"})
                    res = svc.register_cloud_run_subject(
                        tenant=getattr(self, "_bound_org", DEFAULT_ORG),
                        host=str(body.get("host") or ""), subject=str(body.get("subject") or ""),
                        actor=actor,
                        grant_guard=lambda: live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)))
                    return self._authorized_org_read(sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                     lambda _: self._json(200, {**res, "assets": svc.assets()}),
                                                     reader=False)
                elif p == "/api/assets/cloud-run/revoke":
                    if "admin" not in sess.roles:
                        return self._json(403, {"error": "組織管理者の権限が必要です"})
                    res = svc.revoke_cloud_run_subject(
                        tenant=getattr(self, "_bound_org", DEFAULT_ORG),
                        host=str(body.get("host") or ""), actor=actor,
                        grant_guard=lambda: live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)))
                    return self._authorized_org_read(sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                     lambda _: self._json(200, {**res, "assets": svc.assets()}),
                                                     reader=False)
                elif p == "/api/assets/cloud-run/issue":
                    with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)):
                        res = svc.issue_cloud_run_challenge(
                            tenant=getattr(self, "_bound_org", DEFAULT_ORG),
                            host=str(body.get("host") or ""), requester=actor)
                    return self._authorized_org_read(sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                     lambda _: self._json(200, res), reader=False)
                elif p == "/api/assets/cloud-run/finish":
                    host = str(body.get("host") or "")
                    if svc.real_service_has_authority(host) and "approver" not in sess.roles:
                        return self._json(403, {"error": "所有確認済みの対象の再確認には承認責任者の権限が必要です"})
                    with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)) as current_roles:
                        self._require_ownership_traffic(svc, sess, "https://" + host, "cloud_run_oidc")
                        res = svc.finish_cloud_run_challenge(
                            tenant=getattr(self, "_bound_org", DEFAULT_ORG), host=host,
                            requester=actor, challenge=str(body.get("challenge") or ""),
                            id_token=str(body.get("id_token") or ""), roles=tuple(current_roles))
                    return self._authorized_org_read(sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                     lambda _: self._json(200, {**res, "assets": svc.assets()}),
                                                     reader=False)
                elif p == "/api/assets/google/start":
                    # Step 2 through Google: a one-time, short-lived state bound to this
                    # account, organization and host; the browser goes to Google with it
                    cfg = google_ownership.config()
                    if cfg is None:
                        return self._json(404, {"error": "Google での所有確認は設定されていません"})
                    ownership_value = str(body.get("url") or body.get("host") or "")
                    grant = self._require_ownership_traffic(svc, sess, ownership_value, google_ownership.METHOD)
                    g_host = parse_service_target(ownership_value)["host"]
                    g_asset = svc._asset_record(g_host)
                    if g_asset is None or not svc._in_ownership_flow(g_host):
                        return self._json(400, {"error": "先にサイトの URL を登録してください"})
                    bound_org = getattr(self, "_bound_org", None) or ""
                    with limits_lock:
                        now = time.time()
                        for k in [k for k, v in google_states.items() if now - v["at"] > google_ownership.STATE_TTL_S]:
                            google_states.pop(k, None)
                        mine_g = verify_times.setdefault(bound_org, [])
                        ok = (len(google_states) < 5000 and room(mine_g, 3600, OWNERSHIP_CHECKS_PER_ORG_PER_HOUR)
                              and room(verify_all, 3600, OWNERSHIP_CHECKS_PLATFORM_PER_HOUR))
                        if ok:
                            within(mine_g, 3600, OWNERSHIP_CHECKS_PER_ORG_PER_HOUR)
                            within(verify_all, 3600, OWNERSHIP_CHECKS_PLATFORM_PER_HOUR)
                    if not ok:
                        return self._json(429, {"error": "所有確認は1時間あたりの上限に達しました。時間をおいてお試しください"},
                                          [("Retry-After", "600")])
                    state = secrets.token_urlsafe(32)
                    verifier, challenge = google_ownership.new_pkce()
                    with limits_lock:
                        google_states[state] = {"at": time.time(), "account": actor, "org": bound_org,
                                                "host": g_host, "verifier": verifier, "grant": grant,
                                                "session": hashlib.sha256(sess.token.encode()).digest(),
                                                "target_url": g_asset.get("target_url") or ownership_value,
                                                "scheme": str(g_asset.get("scheme") or "https"),
                                                "port": int(g_asset.get("port") or 443)}
                    auth_url = google_ownership.authorization_url(cfg, state, challenge)
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, {"url": auth_url}), reader=False)
                elif p == "/api/assets/google/finish":
                    cfg = google_ownership.config()
                    if cfg is None:
                        return self._json(404, {"error": "Google での所有確認は設定されていません"})
                    bound_org = getattr(self, "_bound_org", None) or ""
                    with limits_lock:
                        key = str(body.get("state") or "")
                        st = google_states.get(key)
                        if (st is not None and st["account"] == actor and st["org"] == bound_org
                                and st["session"] == hashlib.sha256(sess.token.encode()).digest()):
                            google_states.pop(key, None)                     # single use
                        else:
                            st = None                                        # someone else's: left alone
                    if st is None or time.time() - st["at"] > google_ownership.STATE_TTL_S:
                        return self._json(400, {"error": "確認の有効期限が切れたか、別の操作で開始されています。もう一度お試しください"})
                    g_host = st["host"]
                    if svc.real_service_has_authority(g_host) and "approver" not in sess.roles:
                        return self._json(403, {"error": "所有確認済みの対象の再確認には承認責任者の権限が必要です"})
                    google_slot = contextlib.ExitStack()
                    if self._self_service_mode():
                        google_slot.enter_context(self_service_slots.hold(actor))
                    try:
                        with live_grant_roles(sess, bound_org or DEFAULT_ORG), svc._lock:
                            grant = self._require_ownership_traffic(
                                svc, sess, st["target_url"], google_ownership.METHOD, st["grant"], consume=True)
                    except BaseException:
                        google_slot.close()
                        raise

                    def guard_google_request():
                        with live_grant_roles(sess, bound_org or DEFAULT_ORG), svc._lock:
                            self._require_ownership_traffic(svc, sess, st["target_url"], google_ownership.METHOD, grant)

                    try:
                        with google_slot:    # the same slot, released after the Google call
                            sites = google_ownership.owned_sites(
                                cfg, str(body.get("code") or ""), st["verifier"],
                                **({"before_request": guard_google_request} if isinstance(grant, tuple) else {}),
                            )
                    except google_ownership.GoogleOwnershipError as e:
                        return self._json(502, {"error": str(e), "host": g_host})
                    # checked against the scheme / port registered when the check started;
                    # the service refuses (under its lock) if the registration changed since
                    prop = google_ownership.covering_property(sites, g_host, st["scheme"], st["port"])
                    # Google's HTTP lookup is over. Keep the short grant commit
                    # and its response in one live lease so logout cannot split them.
                    # The outer lease supplies current roles; do not nest its
                    # non-reentrant account lock through grant_guard.
                    def finish_google(current):
                        self._require_ownership_traffic(svc, sess, st["target_url"], google_ownership.METHOD, grant)
                        res = svc.verify_asset_ownership(url_or_host=g_host, method=google_ownership.METHOD,
                                                         actor=actor, roles=tuple(current.roles), google_property=prop,
                                                         google_endpoint=(st["scheme"], st["port"]))
                        return self._json(200, {**res, "assets": svc.assets()})

                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG), finish_google, reader=False)
                elif p == "/api/assets/verify-ownership":
                    ownership_value = str(body.get("url") or body.get("host") or "")
                    method = str(body.get("method", "dns_txt"))
                    if method not in OWNERSHIP_METHODS:
                        return self._json(400, {"error": "この経路では選択した方法を使用できません"})
                    v_host = ""
                    try:
                        v_host = parse_service_target(str(body.get("url") or body.get("host") or ""))["host"]
                    except ValueError:
                        pass
                    if v_host and svc.real_service_has_authority(v_host) and "approver" not in sess.roles:
                        # a failed re-check revokes scope and stored test accounts
                        return self._json(403, {"error": "所有確認済みの対象の再確認には承認責任者の権限が必要です"})
                    slot = contextlib.ExitStack()
                    if self._self_service_mode():
                        slot.enter_context(self_service_slots.hold(actor))
                    with slot:     # held until the lookup has finished
                        with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)), svc._lock:
                            grant = self._require_ownership_traffic(svc, sess, ownership_value, method, consume=True)

                        @contextlib.contextmanager
                        def proof_guard():
                            with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)) as roles, svc._lock:
                                self._require_ownership_traffic(svc, sess, ownership_value, method, grant)
                                yield roles

                        res = svc.verify_asset_ownership(
                            url_or_host=ownership_value,
                            method=method,
                            actor=actor,
                            roles=tuple(sess.roles),     # re-checked inside, when the result is applied
                            grant_guard=proof_guard,
                        )
                    payload = {**res, "assets": svc.assets()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False)
                elif p == "/api/assets/confirm-scope":
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "診断範囲の確定には承認責任者の権限が必要です"})
                    extra_check = body.get("allow_status_probe") is True
                    if extra_check and (not optional_status_check_configured()
                                        or not svc._real_site_local_artex or not svc._artex_real_cmd):
                        return self._json(409, {"error": "追加の読み取り確認は現在利用できません"})
                    res = svc.confirm_asset_scope(
                        url_or_host=str(body.get("url") or body.get("host") or ""),
                        confirmed_prohibited=body.get("confirmed_prohibited") is True,   # must be stated explicitly
                        approver=actor,
                        sow_id=str(body.get("sow_id", "")),
                        activate_workspace=bool(body.get("activate_workspace", False)),
                        allow_status_probe=extra_check,
                        grant_guard=lambda: live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                             approver=True),
                    )
                    payload = {**res, "assets": svc.assets(), "snapshot": svc.snapshot()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False, approver=True)
                elif p == "/api/assets/secrets":
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "検証用アカウントの設定には承認責任者の権限が必要です"})
                    raw_paths = body.get("mock_paths")
                    raw_tokens = body.get("tokens")
                    tokens = dict(raw_tokens) if isinstance(raw_tokens, dict) else {}
                    # also accept `<name>_token` at the top level of the body
                    tokens.update({k: v for k, v in body.items()
                                   if isinstance(k, str) and k.endswith("_token") and isinstance(v, str)})
                    res = svc.configure_asset_secrets(
                        host=str(body.get("host", "")),
                        tokens=tokens,
                        mock_paths=raw_paths if isinstance(raw_paths, dict) else None,
                        actor=actor,
                    )
                    payload = {"secrets_status": res, "snapshot": svc.snapshot()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False, approver=True)
                elif p == "/api/assets/delete":
                    real_asset = svc.asset_is_real_service(asset_id=str(body.get("id", "")))
                    if real_asset and "approver" not in sess.roles:
                        # deleting a real service revokes its scope and stored test accounts
                        return self._json(403, {"error": "実サービスの削除には承認責任者の権限が必要です"})
                    assets = svc.delete_asset(str(body.get("id", "")), actor=actor)
                    payload = {"assets": assets, "snapshot": svc.snapshot()}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False, approver=real_asset)
                elif p == "/api/assets/select":
                    snap = svc.select_asset(str(body.get("id", "")), actor=actor)
                    payload = {"assets": svc.assets(), "snapshot": snap}
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, payload), reader=False)
                elif p == "/api/l2-profiles/accept":
                    if "admin" not in sess.roles:
                        paudit.record("l2.profile_accept_denied", actor=actor, profile=str(body.get("id", ""))[:64])
                        return self._json(403, {"error": "プロファイルの承認には管理者の権限が必要です"})
                    result = svc.accept_l2_profile(str(body.get("id", "")), str(body.get("sha256", "")), actor)
                    return self._authorized_platform_read(sess, lambda: self._json(200, result), admin=True)
                elif p == "/api/a2b/profile-draft":
                    if not ({"approver", "admin"} & set(sess.roles)):
                        paudit.record("l2.profile_draft_denied", actor=actor)
                        return self._json(403, {"error": "検証プロファイルの保存には承認責任者または管理者の権限が必要です"})
                    draft = body.get("draft")
                    try:
                        result = svc.save_a2b_profile_draft(draft if isinstance(draft, dict) else {}, actor)
                    except ValueError as exc:
                        return self._json(400, {"error": str(exc)[:300]})
                    return self._authorized_platform_read(sess, lambda: self._json(200, result))
                elif p in ("/api/router/verify", "/api/cve/sync") and not ({"approver", "admin"} & set(sess.roles)):
                    # one spawns the planner CLI and an outbound model call, the other replaces feed data
                    paudit.record("system.job_denied", actor=actor, job=p)
                    return self._json(403, {"error": "この操作には承認責任者または管理者の権限が必要です"})
                elif p == "/api/router/verify":
                    rep = svc.verify_planner_connections(actor)
                    return self._authorized_platform_read(sess, lambda: self._json(200, rep))
                elif p in JOB_ROUTES:
                    if not ({"approver", "admin"} & set(sess.roles)):
                        paudit.record("system.job_denied", actor=actor, job=p)
                        return self._json(403, {"error": "検証ジョブの実行には承認責任者または管理者の権限が必要です"})
                    paudit.record("system.job_started", actor=actor, job=p)
                    if p == "/api/system/verify-controls":
                        rep = run_live_control_verification()
                        paudit.record("system.controls_verified", actor=actor, all_passed=rep["all_passed"])
                    elif p == "/api/agent-defense/evaluate":
                        # the AI coding agent's own rules, run offline (loopback stand-in model,
                        # network sandbox, scratch copy); only the selected settings text is sent
                        from . import agent_defense
                        text = body.get("settings_json")
                        if not self._loopback_client():
                            rep = {"status": "unsupported", "scope": agent_defense.SCOPE_NOTE,
                                   "reason": "この端末以外からの接続では実行しません"}
                        else:
                            def still_allowed():
                                # re-checked during the run: a logout, expiry or lost role stops it
                                cur = self._session()
                                if not cur or cur.operator != sess.operator:
                                    return "ログインが失効したため中断しました"
                                if not ({"approver", "admin"} & set(cur.roles)):
                                    return "権限が変更されたため中断しました"
                                return None
                            rep = agent_defense.evaluate_settings(text if isinstance(text, str) else None,
                                                                  still_allowed=still_allowed)
                        rep["settings_path"] = str(body.get("settings_path") or "")[:256] or None
                        paudit.record("agent_defense.evaluated", actor=actor, status=rep.get("status"),
                                      summary=rep.get("summary"))
                    else:
                        rep = run_real_software_cve_comparison()
                        paudit.record("cve.real_software_verified", actor=actor, all_passed=rep["all_passed"])
                    return self._authorized_platform_read(sess, lambda: self._json(200, rep))
                elif p == "/api/cve/sync":
                    st = svc.cve_monitor.ingest_payloads(
                        nvd_obj=body.get("nvd") if isinstance(body.get("nvd"), dict) else None,
                        kev_obj=body.get("kev") if isinstance(body.get("kev"), dict) else None,
                        source=str(body.get("source", "operator_sync")),
                    )
                    paudit.record("cve.synced", actor=actor, cve_count=st["cve_count"], kev_count=st["kev_count"],
                                     source=str(body.get("source", "operator_sync"))[:64],
                                     payload_sha256=hashlib.sha256(
                                         json.dumps({"nvd": body.get("nvd"), "kev": body.get("kev")},
                                                    sort_keys=True, default=str).encode()).hexdigest())
                    return self._authorized_platform_read(sess, lambda: self._json(200, st))
                elif p in (base + "/start", base + "/restart"):
                    refusal = None
                    with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)), svc._lock:
                        if (("reviewed_asset_id" in body or "reviewed_authority_generation" in body)
                                and (body.get("reviewed_asset_id") != svc.a.asset["id"]
                                     or body.get("reviewed_authority_generation") != svc.ledger.generation)):
                            refusal = (409, "対象または診断許可が変更されました。画面を更新し、範囲を確認してください。")
                        # The workspace can switch after the earlier route check.
                        elif (not (REAL_SERVICE_DIAGNOSIS or REAL_SITE_L1_ONLY)
                              and svc._in_ownership_flow(svc.a.asset.get("name"))):
                            refusal = (403, "この環境では実サイトへの診断通信は無効です")
                        elif p == base + "/start":
                            svc.start(actor=actor)
                        else:
                            result = svc.restart(actor)
                    if refusal:
                        status, message = refusal
                        return self._json(status, {"error": message})
                    if p == base + "/restart":
                        return self._authorized_org_read(
                            sess, getattr(self, "_bound_org", DEFAULT_ORG),
                            lambda _: self._json(200, result), reader=False)
                elif p == base + "/pause":
                    svc.pause(actor)
                    if not ops.trusted():
                        # A failed auth-state save must not disable a safety stop,
                        # but its snapshot cannot be sent without a live grant.
                        return self._json(200, {"stopped": True, "details_unavailable": True})
                    paused_snapshot = svc.snapshot()
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, paused_snapshot))
                elif p == base + "/resume":
                    with live_grant_roles(sess, getattr(self, "_bound_org", DEFAULT_ORG)):
                        svc.resume(actor)
                elif p == base + "/emergency-stop":
                    from . import agent_defense
                    agent_defense.stop_all()            # a running agent check dies with it
                    stop_report = svc.emergency_stop(actor)
                    if not ops.trusted():
                        return self._json(200, {"stopped": True, "details_unavailable": True})
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, {"stop_report": stop_report}))
                elif p == base + "/verify-finding":
                    fid = str(body.get("finding_id", "")).strip()
                    if not fid:
                        return self._json(400, {"error": "finding_id is required"})
                    # the service decides whether this needs an approver, under its own
                    # lock (a check here could be invalidated by a concurrent switch)
                    result = svc.verify_finding(
                        fid, actor, roles=tuple(sess.roles),
                        approver_class=_approver_class(actor),
                        request_authorized=live_request_authority(
                            sess, getattr(self, "_bound_org", DEFAULT_ORG),
                            approver="approver" in sess.roles))
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False,
                        approver="approver" in sess.roles)
                elif m := re.fullmatch(base + r"/diagnosis/(start|owner-spec|fix-check|approve)", p):
                    # PR-C (docs/DIAGNOSIS_ACTIONS.md): permission, Idempotency-Key, scope and
                    # the lab check are decided by the service, with the live roles
                    org = getattr(self, "_bound_org", DEFAULT_ORG)
                    approving = m.group(1) == "approve"
                    if approving and svc._separation_required() and svc._approver_refused(_approver_class(actor)):
                        return self._json(403, {"error": svc.approver_refusal_text(_approver_class(actor)),
                                                "reason": "self_registered"})
                    code, result = svc.diagnosis_ops.run(
                        m.group(1), key=self.headers.get("Idempotency-Key") or "", actor=actor,
                        roles=tuple(sess.roles), body=body,
                        request_authorized=live_request_authority(sess, org),
                        approver_authorized=live_request_authority(sess, org, approver=True) if approving else None)
                    return self._deliver_diagnosis_op(sess, org, m.group(1), code, result)
                elif p == base + "/artex/plan":
                    # the REAL ARTEX planner (planner-only overlay) proposes; Vulnix rebuilds
                    approval = body.get("llm_approval") if isinstance(body.get("llm_approval"), dict) else None
                    llm_mode = body.get("llm_mode") if isinstance(body.get("llm_mode"), str) else None
                    result = svc.plan_with_artex(actor, llm_approval=approval,
                                                 roles=tuple(sess.roles), llm_mode=llm_mode,
                                                 request_authorized=live_request_authority(
                                                     sess, getattr(self, "_bound_org", DEFAULT_ORG),
                                                     approver=approval is not None))
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False,
                        approver=approval is not None)
                elif m := re.fullmatch(base + r"/artex/items/([A-Za-z0-9_]{1,80})/execute", p):
                    # L2 needs an approver: decided by the service, with the caller's roles
                    result = svc.execute_artex_item(
                        m.group(1), actor, roles=tuple(sess.roles),
                        approver_class=_approver_class(actor),
                        request_authorized=live_request_authority(
                            sess, getattr(self, "_bound_org", DEFAULT_ORG),
                            approver="approver" in sess.roles))
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False,
                        approver="approver" in sess.roles)
                elif p == base + "/request-l2":
                    fid = str(body.get("finding_id", "")).strip()
                    if not fid:
                        return self._json(400, {"error": "finding_id is required"})
                    if svc._separation_required() and ops.is_self_registered(actor):
                        # a second identity anyone can mint is not a second person
                        return self._json(403, {"error": "自己登録のアカウントはL2検証を依頼できません。"
                                                         "管理者が作成したアカウントで依頼してください"})
                    result = svc.request_l2_run(fid, actor)
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False)
                elif p == base + "/lab-mode":
                    mode = str(body.get("mode", "vulnerable")).strip()
                    set_lab_mode(mode)
                    svc.audit.record("lab.mode_changed", actor=actor, mode=mode)
                    return self._json(200, svc.snapshot())
                elif p == base + "/verify-fix":
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "修正後の再検証には承認責任者の権限が必要です"})
                    result = svc.verify_fix(actor, approver_class=_approver_class(actor))
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False, approver=True)
                elif p == base + "/chat":
                    q = str(body.get("question", "")).strip()
                    if not q:
                        return self._json(400, {"error": "質問を入力してください"})
                    term = str(body.get("term") or "") or None
                    finding_id = str(body.get("finding_id") or "") or None
                    result = svc.ask_chat(q, actor, term=term, finding_id=finding_id,
                                          safe_advice=body.get("safe_advice") is True,
                                          request_authorized=live_request_authority(
                                              sess, getattr(self, "_bound_org", DEFAULT_ORG)))
                    return self._authorized_org_read(
                        sess, getattr(self, "_bound_org", DEFAULT_ORG),
                        lambda _: self._json(200, result), reader=False)
                elif m := re.fullmatch(base + r"/approvals/(req_[0-9a-f]+)", p):
                    decision = body.get("decision")
                    if decision not in ("approve", "reject"):
                        return self._json(400, {"error": "decision must be approve|reject"})
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "承認には承認責任者の権限が必要です"})
                    aid = m.group(1)
                    approval = svc.a.approvals.get(aid)
                    if approval and approval.get("local_requester"):
                        org = getattr(self, "_bound_org", DEFAULT_ORG)
                        local_defense = local_control(org, svc)
                        if local_defense is None:
                            return self._json(404, {"error": "ローカル防御検証は構成されていません"})
                        local_defense.decide(aid, decision, actor, _approver_class(actor),
                                             live_request_authority(sess, org, approver=True))
                    else:
                        svc.decide_approval(aid, decision, actor,
                                            approver_class=_approver_class(actor))
                else:
                    return self._json(404, {"error": "not found"})
            except AuthError as e:
                return self._json(401, {"error": str(e)})
            except ownership_policy.LimitReached as e:
                if not getattr(e, "audited", False):     # e.g. a concurrency slot refusal
                    self._audit_self_service_refusal(
                        default_svc, getattr(e, "account", "-"), "-", p, str(e))
                return self._json(429, {"error": str(e)}, [("Retry-After", "600")])
            except ApproverRequired as e:
                return self._json(403, {"error": str(e)})
            except StopNotConfirmed as e:
                # the withdrawal stands, but it is not reported as completed
                return self._json(500, {"error": str(e), "stop_confirmed": False})
            except Exception as e:
                # a missing audit record: 503, saying whether the change was applied (a
                # removal or stop) or not (a grant); the message is fixed text
                audit_failed = isinstance(e, AuditWriteFailed)
                status = 503 if audit_failed else 409
                extra = {"applied": e.applied, "audit_failed": True} if audit_failed else {}
                if tenancy is not None and p in PLATFORM_POST_ROUTES:
                    # Platform jobs have no tenant grant to bind. Their exception
                    # text can contain operational details, so return a fixed error.
                    return self._authorized_platform_read(
                        sess, lambda: self._json(status, {"error": "操作を完了できませんでした", **extra}),
                        admin=p == "/api/l2-profiles/accept")
                if tenancy is not None and not getattr(self, "_bound_org", None):
                    return self._json(status, {"error": "操作を完了できませんでした", **extra})
                error = str(e)
                return self._authorized_org_read(
                    sess, getattr(self, "_bound_org", DEFAULT_ORG),
                    lambda _: self._json(status, {"error": error, **extra}),
                    reader=p.endswith(("/pause", "/emergency-stop")))
            snapshot = svc.snapshot()
            return self._authorized_org_read(
                sess, getattr(self, "_bound_org", DEFAULT_ORG),
                lambda _: self._json(200, snapshot), reader=False,
                approver=bool(re.fullmatch(base + r"/approvals/req_[0-9a-f]+", p)))

    return H



def _build_server(svc, a, data, first, seed, env_opt_out):
    # Rollback check of password changes (docs/PASSWORD_CHANGE_DURABILITY.md): the log this
    # mode writes account events to (and the other one if it exists), checked against the
    # audit anchor when one is configured. Unreadable: the server does not start.
    try:
        ops = OperatorStore(seed, credential_generations=credential_history_reader(data, default_log=svc.audit))
    except CredentialStateUnverifiable as e:
        raise SystemExit(str(e)) from None
    blocked = ops.blocked_accounts()
    if blocked:
        print("パスワードの変更が完了していない、または監査ログと一致しないため、次のアカウントのログインを停止しています: "
              + ", ".join(sorted(blocked)) + "（管理者のリセット、または python3 -m scripts.recover_account で復旧）")
    tenancy = None
    if os.environ.get("VULNIX_MULTI_TENANT", "1") != "0":
        # organizations: the existing workspace is the default organization; each new
        # organization gets its own service and data directory under <data>/orgs/
        store = OrgStore(Path(data) / "orgs.json", bootstrap_members=lambda: default_members_from(ops))
        tenancy = TenantRegistry(
            store, svc,
            lambda d: AssessmentService(d, a.lab_port, a.verify_seconds,
                                        separate_l2_approver=a.separate_l2_approver or None,
                                        audit_anchor_root=Path(data)),
            Path(data))
    if not getattr(svc, "previous_session_clean", True):
        # a logout or sign-out-everywhere of the previous run may not be on disk
        n = ops.revoke_all_sessions("the control plane did not shut down cleanly")   # raises if not saved
        print(f"前回正常に終了しなかったため、すべてのログインセッション（{n}件）を無効にしました。")
    svc._auth_recovered = True
    read_auth = False if a.no_read_auth else (True if a.require_read_auth else None)
    srv = ControlPlaneHTTPServer(
        ("127.0.0.1", a.port),
        make_handler(svc, ops, require_read_auth=read_auth, tenancy=tenancy,
                     local_defense_python_root=getattr(a, "local_defense_python_root", None),
                     local_defense_node_bundle=getattr(a, "local_defense_node_bundle", None),
                     local_defense_registry=getattr(a, "local_defense_registry", None)),
    )
    srv.daemon_threads = True
    print(f"Vulnix control plane: http://127.0.0.1:{a.port}  (audit: {data / 'audit.jsonl'})")
    if first and ops.credentials_path:
        print(f"初回起動: 操作者アカウントを生成しました（ハッシュのみ {seed} に保存）。")
        print(f"初期ログイン情報（平文・600権限）: {ops.credentials_path}")
        print("内容は手元で確認してください。再生成するにはこの2ファイルを削除して再起動します。")
    if a.no_read_auth or env_opt_out:
        print("警告: 開発モードのため、読み取りAPIの認証を無効にしています（本番運用では使用不可）。")
    if ops.admin_credentials_path:
        print(f"管理者アカウントを作成しました（ロール付与用・平文・600権限）: {ops.admin_credentials_path}")
    srv.ops = ops
    srv.tenancy = tenancy
    return srv


_ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _load_env_local(path: Path | None = None) -> int:
    """Load `KEY=VALUE` lines from `<project root>/.env.local` into os.environ at startup,
    WITHOUT overriding variables already set in the real environment (explicit env wins).

    This file is git-ignored and holds local secrets such as VULNIX_ABLITERATION_KEY. It is
    read only here, only at startup, and its VALUES are never printed or logged. Blank values
    (a placeholder the operator has not filled yet) are skipped. Returns the count loaded."""
    if path is None:
        # Tests (and anyone who wants a clean environment) opt out, so a developer's
        # real key can never reach a test run or a server a test starts.
        if os.environ.get("VULNIX_NO_ENV_LOCAL") == "1":
            return 0
        path = Path(__file__).resolve().parents[1] / ".env.local"
    if not path.is_file():
        return 0
    loaded = 0
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, ValueError):            # unreadable or not UTF-8: start without it
        return 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if not _ENV_KEY.fullmatch(key):
            continue
        if key.startswith("VULNIX_AUDIT_ANCHOR_") or key == "AEGIS_SEPARATE_L2_APPROVER":
            # (separation of duties, too: only the operator's real environment may switch
            # it off - and only in an authorized-lab-only setup)
            # Who the audit anchor is (socket, helper user, source name) comes only from the
            # operator's real environment: the service user can write .env.local and could
            # otherwise point the service at a helper of its own (docs/AUDIT_ANCHOR.md).
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
            val = val[1:-1]                  # one matching pair of quotes, nothing more
        else:
            val = re.split(r"\s+#", val, maxsplit=1)[0].strip()   # trailing comment
        if not val or "\x00" in val or key in os.environ:   # keep already-set env; skip blanks
            continue
        os.environ[key] = val
        loaded += 1
    return loaded


def main() -> None:
    loaded = _load_env_local()
    if loaded:
        print(f".env.local から {loaded} 件の設定を読み込みました（値は表示しません）。")
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--lab-port", type=int, default=18081)
    ap.add_argument("--verify-seconds", type=float, default=2.0)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--local-defense-python-root", type=Path,
                    help="opt the default organization into a reviewed local Python snapshot")
    ap.add_argument("--local-defense-node-bundle", type=Path,
                    help="opt the default organization into a reviewed local Node.js bundle")
    ap.add_argument("--local-defense-registry", type=Path,
                    help="deployment-controlled registry for organization-scoped reviewed bundles")
    ap.add_argument("--require-read-auth", action="store_true",
                    help="(default) Require operator authentication on GET endpoints")
    ap.add_argument("--no-read-auth", action="store_true",
                    help="Allow unauthenticated GET reads. Development only: refused unless "
                         "AEGIS_ENV=development is set")
    ap.add_argument("--separate-l2-approver", action="store_true",
                    help="(default, kept for compatibility) the L2 requester never approves their own L2. "
                         "AEGIS_SEPARATE_L2_APPROVER=0 switches it off in an authorized-lab-only setup only")
    a = ap.parse_args()
    env_opt_out = os.environ.get("AEGIS_REQUIRE_READ_AUTH") == "0"
    if (a.no_read_auth or env_opt_out) and not development_mode():
        # refuse to start rather than silently serving open reads (or silently
        # ignoring what the operator asked for)
        raise SystemExit(
            "読み取りAPIの認証を無効にできるのは開発モードだけです。"
            "ローカル開発で必要な場合は AEGIS_ENV=development を明示してください。"
            "本番運用では --no-read-auth / AEGIS_REQUIRE_READ_AUTH=0 を使用しないでください。")
    try:
        # refuse to start rather than run with L2 self-approval outside an authorized lab
        # judged against the real-site mode this process actually runs with (read when
        # the module loaded), not a value .env.local may have added since
        separate_l2_approver_from_env({**os.environ, "VULNIX_REAL_SERVICE_DIAGNOSIS": _REAL_SITE_MODE})
    except SeparationConfigError as e:
        raise SystemExit(str(e)) from None
    data = Path(a.data_dir or tempfile.mkdtemp(prefix="aegis-"))
    data.mkdir(parents=True, exist_ok=True)
    seed = data / "operators.json"
    first = not seed.exists()
    start_lab(a.lab_port)
    svc = AssessmentService(data, a.lab_port, a.verify_seconds,
                            separate_l2_approver=a.separate_l2_approver or None,
                            audit_anchor_root=data)
    anchor = svc.audit.anchor_status(max_age=None)
    if anchor["enabled"]:
        print("監査アンカー: " + ("照合済み（保護あり）" if anchor["protected"] else
              f"照合できません（{anchor['error']}）。Worker の実行許可・有料送信・診断と所見の状態変更を拒否します"))
    try:
        srv = _build_server(svc, a, data, first, seed, env_opt_out)
    except BaseException:
        # e.g. the port is in use. Nothing ran in THIS start, so it is closed cleanly -
        # unless the previous run did not end cleanly and that was not dealt with
        # yet (its sessions are only revoked once the store could be opened and
        # saved): then the record stays, and the next start deals with it.
        svc.close(external_clean=bool(getattr(svc, "previous_session_clean", False))
                  and getattr(svc, "_auth_recovered", False))
        raise

    ops = srv.ops

    def _stop(signum, frame):
        # serve_forever() must be stopped from another thread
        threading.Thread(target=srv.shutdown, daemon=True).start()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        # Only a clean close removes the session record; otherwise the next start
        # holds every real-service authorisation until an approver re-confirms it.
        # an auth change that never reached the disk (a logout, a password change)
        # makes this an unclean shutdown too: the next start then signs everyone out
        auth_saved = ops.trusted()
        if getattr(srv, "tenancy", None) is not None:
            srv.tenancy.close_all()
        clean = svc.close(external_clean=auth_saved)
        print("コントロールプレーンを停止しました" + ("" if clean else
              "（保存または Worker の停止を確認できなかったため、次回起動時に実サービスの診断許可を保留します）"))


if __name__ == "__main__":
    main()

