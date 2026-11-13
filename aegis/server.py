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
import http.cookies
import hashlib
import json
import os
import re
import signal
import threading
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .assessment import ApproverRequired, AssessmentService, StopNotConfirmed
from .control_verification import run_live_control_verification
from .lab import set_lab_mode, start_lab
from .operators import AuthError, LockedOut, MFAChallenge, OperatorStore
from .ownership import parse_service_target
from .real_software_cve import run_real_software_cve_comparison

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
# Routes that start a verification job (spawn workers / probes on this machine).
JOB_ROUTES = frozenset({"/api/system/verify-controls", "/api/cve/real-software-verify"})


def make_handler(svc: AssessmentService, ops: OperatorStore, *, require_read_auth: bool | None = None,
                 allow_self_registration: bool | None = None):
    def self_registration_allowed() -> bool:
        # Anyone who can reach the port could otherwise mint themselves a session
        # (and a second identity). Outside development mode accounts are created
        # by an admin only.
        return development_mode() if allow_self_registration is None else bool(allow_self_registration)

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
        svc.audit.record("auth.legacy_sessions_revoked", count=ops.legacy_sessions_revoked,
                         reason="session file held bearer tokens in plaintext; sessions must sign in again")
        ops.legacy_sessions_revoked = 0

    def approver_grant_recorded(name: str) -> bool:
        """Whether the audit log shows an admin granting (or attesting) this
        account's approver role. Accounts that became approvers before roles
        were admin-granted have no such record and should be reviewed."""
        latest = None
        for e in svc.audit.entries():
            if e["event"] == "operator.roles_changed" and e["fields"].get("target") == name:
                latest = e["fields"]
        return bool(latest and "approver" in (latest.get("after") or []))

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

        def _public_session(self, sess):
            return {"operator": sess.operator, "roles": list(sess.roles),
                    "expires": sess.expires,
                    "mfa_enabled": ops.totp_enabled(sess.operator)} if sess else None

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
                return self._json(200, {"session": self._public_session(sess),
                                        "self_registration": self_registration_allowed()})
            if p == "/api/health":
                return self._json(200, {"ok": True})
            if enforce_read_auth and not sess:
                return self._json(401, {"error": "ログインが必要です"})
            if p == "/api/operators":
                # account list is for admins only, whatever the read-auth setting
                if not sess or "admin" not in sess.roles:
                    return self._json(403, {"error": "アカウント一覧の参照には管理者の権限が必要です"})
                locked = ops.locked_accounts()
                return self._json(200, {"operators": [
                    {"name": o.name, "display": o.display, "roles": list(o.roles),
                     "mfa_enabled": bool(o.totp_secret),
                     "locked_for": int(locked.get(o.name, 0)),
                     # approver without an admin's grant on record -> needs review
                     "needs_role_review": "approver" in o.roles and not approver_grant_recorded(o.name)}
                    for o in ops.operators()]})
            if p == "/api/system/status":
                return self._json(200, svc.system_status())
            if p == "/api/assets":
                return self._json(200, svc.assets())
            if p == "/api/assets/secrets-status":
                q = parse_qs(u.query)
                host = (q.get("host") or [None])[0]
                return self._json(200, svc.secrets_status(host))
            if p == "/api/router/status":
                return self._json(200, svc.planner_status())
            if p == "/api/l2-profiles":
                if not sess or not ({"admin", "approver"} & set(sess.roles)):
                    return self._json(403, {"error": "プロファイルの参照には管理者または承認責任者の権限が必要です"})
                return self._json(200, svc.l2_profiles_status())
            if p in JOB_ROUTES:
                # these START a verification job: POST only (CSRF-checked, role-checked, audited)
                return self._json(405, {"error": "この操作は POST で実行してください"}, [("Allow", "POST")])
            if p == "/api/cve/status":
                return self._json(200, svc.cve_monitor.status())
            if p == f"/api/assessments/{svc.a.id}":
                return self._json(200, svc.snapshot())
            if p == f"/api/assessments/{svc.a.id}/logs":
                return self._json(200, svc.logs())
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
                return self._sse(after)
            return self._json(404, {"error": "not found"})

        def _sse(self, after: int) -> None:
            self.close_connection = True   # never reuse a socket after a stream ends
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            seq = after
            last_ping = time.monotonic()
            try:
                self.wfile.write(b"retry: 2000\n\n")
                self.wfile.flush()
                while True:
                    for ev in svc.bus.wait(seq, timeout=10):
                        data = json.dumps(ev, ensure_ascii=False)
                        self.wfile.write(f"id: {ev['event_id']}\ndata: {data}\n\n".encode())
                        seq = ev["seq"]
                    if time.monotonic() - last_ping > 10:
                        self.wfile.write(b": ping\n\n")
                        last_ping = time.monotonic()
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
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
                        svc.audit.record("auth.logout", actor=sess.operator)
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
            reduces_power = p.endswith(("/emergency-stop", "/pause")) or p == "/api/operators/reset-mfa" or (
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
            if p in ("/api/operators/unlock", "/api/operators/reset-mfa"):
                return self._admin_recovery(p, body, sess)
            return self._dispatch(p, body, sess)

        def _change_password(self, body, sess):
            try:
                ops.change_password(sess.operator, str(body.get("current", "")),
                                    str(body.get("new", "")), keep_token=sess.token)
            except LockedOut as e:
                return self._locked(e, sess.operator)
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.password_changed", actor=sess.operator)
            return self._json(200, {"ok": True})

        def _totp_enroll(self, sess):
            try:
                secret, uri = ops.begin_totp_enroll(sess.operator)
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            # The secret/URI are shown once to the operator to add to their
            # authenticator; they are not recorded in the audit log.
            svc.audit.record("auth.mfa_enroll_started", actor=sess.operator)
            return self._json(200, {"secret": secret, "uri": uri})

        def _totp_confirm(self, body, sess):
            try:
                ops.confirm_totp(sess.operator, str(body.get("code", "")))
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.mfa_enabled", actor=sess.operator)
            return self._json(200, {"ok": True, "mfa_enabled": True})

        def _totp_disable(self, body, sess):
            try:
                ops.disable_totp(sess.operator, str(body.get("current", "")), str(body.get("code", "")) or None)
            except LockedOut as e:
                return self._locked(e, sess.operator)
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.mfa_disabled", actor=sess.operator)
            return self._json(200, {"ok": True, "mfa_enabled": False})

        def _locked(self, e: LockedOut, name: str):
            """429 for a paused sign-in. The same answer is given for names that do
            not exist, so it does not reveal which accounts are real."""
            if e.just_locked:
                svc.audit.record("auth.locked", name=name[:32], seconds=int(e.retry_after))
            return self._json(429, {"error": str(e), "locked": True, "retry_after": int(e.retry_after)},
                              [("Retry-After", str(int(e.retry_after)))])

        def _drain_recovery_events(self):
            while ops.recovery_events:
                ev = ops.recovery_events.pop(0)
                svc.audit.record(ev.pop("event"), **ev)

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
                svc.audit.record("auth.login_failed", name=str(body.get("name", ""))[:32])
                return self._json(401, {"error": str(e)})
            self._drain_recovery_events()
            svc.audit.record("auth.login", actor=sess.operator, roles=list(sess.roles))
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
                    op = ops.create_account(name, password, display=display, actor=caller.operator)
                except AuthError as e:
                    return self._json(400, {"error": str(e)})
                svc.audit.record("operator.created", actor=caller.operator, target=op.name, roles=list(op.roles),
                                 requested_roles_ignored=[r for r in asked if r not in op.roles])
                return self._json(200, {"created": {"name": op.name, "display": op.display, "roles": list(op.roles)}})
            if not self_registration_allowed():
                svc.audit.record("auth.registration_refused", name=name[:32])
                return self._json(403, {"error": "アカウントの作成は管理者が行います（設定 → アカウントとロール）。"
                                                 "自己登録は開発モードでのみ利用できます"})
            try:
                sess = ops.register(name, password, display=display)
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.registered", actor=sess.operator, roles=list(sess.roles),
                             self_registered=True,
                             requested_roles_ignored=[r for r in asked if r not in sess.roles])
            cookie = (f"{COOKIE}={sess.token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={int(sess.expires - time.time())}")
            return self._json(200, {"session": self._public_session(sess)},
                              [("Set-Cookie", cookie)])

        def _set_roles(self, body, sess):
            if "admin" not in sess.roles:
                svc.audit.record("operator.roles_change_denied", actor=sess.operator,
                                 target=str(body.get("name", ""))[:64])
                return self._json(403, {"error": "ロールの変更には管理者の権限が必要です"})
            raw = body.get("roles")
            roles = [str(r) for r in raw] if isinstance(raw, list) else []
            target = str(body.get("name", "")).strip()
            try:
                before, after = ops.set_roles(target, roles, actor=sess.operator)
            except AuthError as e:
                svc.audit.record("operator.roles_change_failed", actor=sess.operator, target=target[:64],
                                 requested=roles[:8], error=str(e)[:200])
                return self._json(409, {"error": str(e)})
            svc.audit.record("operator.roles_changed", actor=sess.operator, target=target,
                             before=list(before), after=list(after),
                             attested_unchanged=set(before) == set(after))
            return self._json(200, {"name": target, "roles": list(after)})

        def _admin_recovery(self, p, body, sess):
            """Recovery actions an admin performs for a legitimate user."""
            target = str(body.get("name", "")).strip()
            if "admin" not in sess.roles:
                svc.audit.record("operator.recovery_denied", actor=sess.operator, target=target[:64], action=p)
                return self._json(403, {"error": "この操作には管理者の権限が必要です"})
            try:
                if p == "/api/operators/unlock":
                    changed = ops.unlock(target, actor=sess.operator)
                    svc.audit.record("operator.unlocked", actor=sess.operator, target=target[:64], was_locked=changed)
                else:
                    changed = ops.reset_totp(target, actor=sess.operator)
                    svc.audit.record("operator.mfa_reset", actor=sess.operator, target=target[:64], had_mfa=changed)
            except AuthError as e:
                return self._json(409, {"error": str(e)})
            return self._json(200, {"name": target, "changed": changed})

        def _clear_cookie(self):
            return [("Set-Cookie", f"{COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")]

        def _dispatch(self, p, body, sess):
            base = f"/api/assessments/{svc.a.id}"
            actor = sess.operator
            try:
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
                    return self._json(200, {"asset": asset, "assets": svc.assets()})
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
                    )
                    return self._json(200, {**res, "assets": svc.assets()})
                elif p == "/api/assets/verify-ownership":
                    v_host = ""
                    try:
                        v_host = parse_service_target(str(body.get("url") or body.get("host") or ""))["host"]
                    except ValueError:
                        pass
                    if v_host and svc.real_service_has_authority(v_host) and "approver" not in sess.roles:
                        # a failed re-check revokes scope and stored test accounts
                        return self._json(403, {"error": "所有確認済みの対象の再確認には承認責任者の権限が必要です"})
                    res = svc.verify_asset_ownership(
                        url_or_host=str(body.get("url") or body.get("host") or ""),
                        method=str(body.get("method", "dns_txt")),
                        actor=actor,
                        roles=tuple(sess.roles),     # re-checked inside, when the result is applied
                    )
                    return self._json(200, {**res, "assets": svc.assets()})
                elif p == "/api/assets/confirm-scope":
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "診断範囲の確定には承認責任者の権限が必要です"})
                    res = svc.confirm_asset_scope(
                        url_or_host=str(body.get("url") or body.get("host") or ""),
                        confirmed_prohibited=body.get("confirmed_prohibited") is True,   # must be stated explicitly
                        approver=actor,
                        sow_id=str(body.get("sow_id", "")),
                        activate_workspace=bool(body.get("activate_workspace", False)),
                    )
                    return self._json(200, {**res, "assets": svc.assets(), "snapshot": svc.snapshot()})
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
                    return self._json(200, {"secrets_status": res, "snapshot": svc.snapshot()})
                elif p == "/api/assets/delete":
                    if svc.asset_is_real_service(asset_id=str(body.get("id", ""))) and "approver" not in sess.roles:
                        # deleting a real service revokes its scope and stored test accounts
                        return self._json(403, {"error": "実サービスの削除には承認責任者の権限が必要です"})
                    assets = svc.delete_asset(str(body.get("id", "")), actor=actor)
                    return self._json(200, {"assets": assets, "snapshot": svc.snapshot()})
                elif p == "/api/assets/select":
                    snap = svc.select_asset(str(body.get("id", "")), actor=actor)
                    return self._json(200, {"assets": svc.assets(), "snapshot": snap})
                elif p == "/api/l2-profiles/accept":
                    if "admin" not in sess.roles:
                        svc.audit.record("l2.profile_accept_denied", actor=actor, profile=str(body.get("id", ""))[:64])
                        return self._json(403, {"error": "プロファイルの承認には管理者の権限が必要です"})
                    return self._json(200, svc.accept_l2_profile(
                        str(body.get("id", "")), str(body.get("sha256", "")), actor))
                elif p in ("/api/router/verify", "/api/cve/sync") and not ({"approver", "admin"} & set(sess.roles)):
                    # one spawns the planner CLI and an outbound model call, the other replaces feed data
                    svc.audit.record("system.job_denied", actor=actor, job=p)
                    return self._json(403, {"error": "この操作には承認責任者または管理者の権限が必要です"})
                elif p == "/api/router/verify":
                    rep = svc.verify_planner_connections(actor)
                    return self._json(200, rep)
                elif p in JOB_ROUTES:
                    if not ({"approver", "admin"} & set(sess.roles)):
                        svc.audit.record("system.job_denied", actor=actor, job=p)
                        return self._json(403, {"error": "検証ジョブの実行には承認責任者または管理者の権限が必要です"})
                    svc.audit.record("system.job_started", actor=actor, job=p)
                    if p == "/api/system/verify-controls":
                        rep = run_live_control_verification()
                        svc.audit.record("system.controls_verified", actor=actor, all_passed=rep["all_passed"])
                    else:
                        rep = run_real_software_cve_comparison()
                        svc.audit.record("cve.real_software_verified", actor=actor, all_passed=rep["all_passed"])
                    return self._json(200, rep)
                elif p == "/api/cve/sync":
                    st = svc.cve_monitor.ingest_payloads(
                        nvd_obj=body.get("nvd") if isinstance(body.get("nvd"), dict) else None,
                        kev_obj=body.get("kev") if isinstance(body.get("kev"), dict) else None,
                        source=str(body.get("source", "operator_sync")),
                    )
                    svc.audit.record("cve.synced", actor=actor, cve_count=st["cve_count"], kev_count=st["kev_count"],
                                     source=str(body.get("source", "operator_sync"))[:64],
                                     payload_sha256=hashlib.sha256(
                                         json.dumps({"nvd": body.get("nvd"), "kev": body.get("kev")},
                                                    sort_keys=True, default=str).encode()).hexdigest())
                    return self._json(200, st)
                elif p == base + "/start":
                    svc.start()
                    svc.audit.record("assessment.start_requested", actor=actor)
                elif p == base + "/restart":
                    return self._json(200, svc.restart(actor))
                elif p == base + "/pause":
                    svc.pause(actor)
                elif p == base + "/resume":
                    svc.resume(actor)
                elif p == base + "/emergency-stop":
                    return self._json(200, {"stop_report": svc.emergency_stop(actor)})
                elif p == base + "/verify-finding":
                    fid = str(body.get("finding_id", "")).strip()
                    if not fid:
                        return self._json(400, {"error": "finding_id is required"})
                    # the service decides whether this needs an approver, under its own
                    # lock (a check here could be invalidated by a concurrent switch)
                    return self._json(200, svc.verify_finding(fid, actor, roles=tuple(sess.roles)))
                elif p == base + "/request-l2":
                    fid = str(body.get("finding_id", "")).strip()
                    if not fid:
                        return self._json(400, {"error": "finding_id is required"})
                    if svc.separate_l2_approver and ops.is_self_registered(actor):
                        # a second identity anyone can mint is not a second person
                        return self._json(403, {"error": "自己登録のアカウントはL2検証を依頼できません。"
                                                         "管理者が作成したアカウントで依頼してください"})
                    return self._json(200, svc.request_l2_run(fid, actor))
                elif p == base + "/lab-mode":
                    mode = str(body.get("mode", "vulnerable")).strip()
                    set_lab_mode(mode)
                    svc.audit.record("lab.mode_changed", actor=actor, mode=mode)
                    return self._json(200, svc.snapshot())
                elif p == base + "/verify-fix":
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "修正後の再検証には承認責任者の権限が必要です"})
                    return self._json(200, svc.verify_fix(actor))
                elif p == base + "/chat":
                    q = str(body.get("question", "")).strip()
                    if not q:
                        return self._json(400, {"error": "質問を入力してください"})
                    term = str(body.get("term") or "") or None
                    finding_id = str(body.get("finding_id") or "") or None
                    return self._json(200, svc.ask_chat(q, actor, term=term, finding_id=finding_id))
                elif m := re.fullmatch(base + r"/approvals/(req_[0-9a-f]+)", p):
                    decision = body.get("decision")
                    if decision not in ("approve", "reject"):
                        return self._json(400, {"error": "decision must be approve|reject"})
                    if "approver" not in sess.roles:
                        return self._json(403, {"error": "承認には承認責任者の権限が必要です"})
                    svc.decide_approval(m.group(1), decision, actor)
                else:
                    return self._json(404, {"error": "not found"})
            except ApproverRequired as e:
                return self._json(403, {"error": str(e)})
            except StopNotConfirmed as e:
                # the withdrawal stands, but it is not reported as completed
                return self._json(500, {"error": str(e), "stop_confirmed": False})
            except Exception as e:
                return self._json(409, {"error": str(e)})
            return self._json(200, svc.snapshot())

    return H



def _build_server(svc, a, data, first, seed, env_opt_out):
    ops = OperatorStore(seed)
    if not getattr(svc, "previous_session_clean", True):
        # a logout or sign-out-everywhere of the previous run may not be on disk
        n = ops.revoke_all_sessions("the control plane did not shut down cleanly")   # raises if not saved
        print(f"前回正常に終了しなかったため、すべてのログインセッション（{n}件）を無効にしました。")
    svc._auth_recovered = True
    read_auth = False if a.no_read_auth else (True if a.require_read_auth else None)
    srv = ThreadingHTTPServer(
        ("127.0.0.1", a.port),
        make_handler(svc, ops, require_read_auth=read_auth),
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
    return srv


def _load_env_local(path: Path | None = None) -> int:
    """Load `KEY=VALUE` lines from `<project root>/.env.local` into os.environ at startup,
    WITHOUT overriding variables already set in the real environment (explicit env wins).

    This file is git-ignored and holds local secrets such as VULNIX_ABLITERATION_KEY. It is
    read only here, only at startup, and its VALUES are never printed or logged. Blank values
    (a placeholder the operator has not filled yet) are skipped. Returns the count loaded."""
    if path is None:
        path = Path(__file__).resolve().parents[1] / ".env.local"
    if not path.is_file():
        return 0
    loaded = 0
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            if key.startswith("export "):
                key = key[len("export "):].strip()
            val = val.strip().strip('"').strip("'")
            if not key or not val or key in os.environ:   # keep already-set env; skip blanks
                continue
            os.environ[key] = val
            loaded += 1
    except OSError:
        return loaded
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
    ap.add_argument("--require-read-auth", action="store_true",
                    help="(default) Require operator authentication on GET endpoints")
    ap.add_argument("--no-read-auth", action="store_true",
                    help="Allow unauthenticated GET reads. Development only: refused unless "
                         "AEGIS_ENV=development is set")
    ap.add_argument("--separate-l2-approver", action="store_true",
                    help="Real-service L2 runs need a request by one operator and approval by another")
    a = ap.parse_args()
    env_opt_out = os.environ.get("AEGIS_REQUIRE_READ_AUTH") == "0"
    if (a.no_read_auth or env_opt_out) and not development_mode():
        # refuse to start rather than silently serving open reads (or silently
        # ignoring what the operator asked for)
        raise SystemExit(
            "読み取りAPIの認証を無効にできるのは開発モードだけです。"
            "ローカル開発で必要な場合は AEGIS_ENV=development を明示してください。"
            "本番運用では --no-read-auth / AEGIS_REQUIRE_READ_AUTH=0 を使用しないでください。")
    data = Path(a.data_dir or tempfile.mkdtemp(prefix="aegis-"))
    data.mkdir(parents=True, exist_ok=True)
    seed = data / "operators.json"
    first = not seed.exists()
    start_lab(a.lab_port)
    svc = AssessmentService(data, a.lab_port, a.verify_seconds,
                            separate_l2_approver=a.separate_l2_approver or None)
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
        clean = svc.close(external_clean=auth_saved)
        print("コントロールプレーンを停止しました" + ("" if clean else
              "（保存または Worker の停止を確認できなかったため、次回起動時に実サービスの診断許可を保留します）"))


if __name__ == "__main__":
    main()

