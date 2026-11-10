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
import json
import os
import re
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .assessment import AssessmentService
from .control_verification import run_live_control_verification
from .lab import set_lab_mode, start_lab
from .operators import AuthError, MFAChallenge, OperatorStore
from .real_software_cve import run_real_software_cve_comparison

ALLOWED_ORIGINS = {"http://localhost:3000", "http://127.0.0.1:3000"}
COOKIE = "aegis_session"


def make_handler(svc: AssessmentService, ops: OperatorStore, *, require_read_auth: bool | None = None):
    enforce_read_auth = (
        os.environ.get("AEGIS_REQUIRE_READ_AUTH") == "1"
        if require_read_auth is None
        else bool(require_read_auth)
    )

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

        # ---- GET ------------------------------------------------------------
        def do_GET(self):
            u = urlsplit(self.path)
            p = u.path.rstrip("/")
            sess = self._session()
            if p == "/api/auth/me":
                return self._json(200, {"session": self._public_session(sess)})
            if enforce_read_auth and not sess:
                return self._json(401, {"error": "ログインが必要です"})
            if p == "/api/assets":
                return self._json(200, svc.assets())
            if p == "/api/router/status":
                return self._json(200, svc.planner_status())
            if p == "/api/system/verify-controls":
                return self._json(200, run_live_control_verification())
            if p == "/api/cve/status":
                return self._json(200, svc.cve_monitor.status())
            if p == "/api/cve/real-software-verify":
                return self._json(200, run_real_software_cve_comparison())
            if p == f"/api/assessments/{svc.a.id}":
                return self._json(200, svc.snapshot())
            if p == f"/api/assessments/{svc.a.id}/logs":
                return self._json(200, svc.logs())
            if p == f"/api/assessments/{svc.a.id}/report":
                return self._json(200, {
                    "markdown": svc.report_markdown(),
                    "filename": f"vulnix-report-{svc.a.id}.md",
                })
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
            origin = self.headers.get("Origin")
            if self.headers.get("X-Aegis-Request") != "1" or (origin and origin not in ALLOWED_ORIGINS):
                return self._json(403, {"error": "csrf check failed"})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
            except json.JSONDecodeError:
                return self._json(400, {"error": "invalid json"})
            p = urlsplit(self.path).path.rstrip("/")

            if p == "/api/auth/login":
                return self._login(body)
            if p == "/api/auth/register":
                return self._register(body)
            if p == "/api/auth/logout":
                sess = self._session()
                if sess:
                    svc.audit.record("auth.logout", actor=sess.operator)
                ops.logout(sess.token if sess else None)
                return self._json(200, {"session": None}, self._clear_cookie())

            sess = self._session()
            if not sess:
                return self._json(401, {"error": "ログインが必要です"})
            if p == "/api/auth/password":
                return self._change_password(body, sess)
            if p == "/api/auth/totp/enroll":
                return self._totp_enroll(sess)
            if p == "/api/auth/totp/confirm":
                return self._totp_confirm(body, sess)
            if p == "/api/auth/totp/disable":
                return self._totp_disable(body, sess)
            return self._dispatch(p, body, sess)

        def _change_password(self, body, sess):
            try:
                ops.change_password(sess.operator, str(body.get("current", "")),
                                    str(body.get("new", "")), keep_token=sess.token)
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
                ops.disable_totp(sess.operator, str(body.get("current", "")))
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.mfa_disabled", actor=sess.operator)
            return self._json(200, {"ok": True, "mfa_enabled": False})

        def _login(self, body):
            try:
                sess = ops.login(str(body.get("name", "")), str(body.get("password", "")),
                                 str(body.get("code", "")) or None)
            except MFAChallenge as e:
                time.sleep(0.2)
                return self._json(401, {"error": str(e), "mfa_required": True})
            except AuthError as e:
                time.sleep(0.2)   # uniform-ish delay on failure
                return self._json(401, {"error": str(e)})
            svc.audit.record("auth.login", actor=sess.operator, roles=list(sess.roles))
            cookie = (f"{COOKIE}={sess.token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={int(sess.expires - time.time())}")
            return self._json(200, {"session": self._public_session(sess)},
                              [("Set-Cookie", cookie)])

        def _register(self, body):
            raw_roles = body.get("roles")
            roles = [str(r) for r in raw_roles] if isinstance(raw_roles, list) else ["operator"]
            try:
                sess = ops.register(
                    str(body.get("name", "")),
                    str(body.get("password", "")),
                    display=str(body.get("display", "")),
                    roles=roles,
                )
            except AuthError as e:
                return self._json(400, {"error": str(e)})
            svc.audit.record("auth.registered", actor=sess.operator, roles=list(sess.roles))
            cookie = (f"{COOKIE}={sess.token}; HttpOnly; SameSite=Strict; Path=/; "
                      f"Max-Age={int(sess.expires - time.time())}")
            return self._json(200, {"session": self._public_session(sess)},
                              [("Set-Cookie", cookie)])

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
                elif p == "/api/assets/delete":
                    assets = svc.delete_asset(str(body.get("id", "")), actor=actor)
                    return self._json(200, {"assets": assets, "snapshot": svc.snapshot()})
                elif p == "/api/assets/select":
                    snap = svc.select_asset(str(body.get("id", "")), actor=actor)
                    return self._json(200, {"assets": svc.assets(), "snapshot": snap})
                elif p == "/api/router/verify":
                    rep = svc.verify_planner_connections(actor)
                    return self._json(200, rep)
                elif p == "/api/system/verify-controls":
                    rep = run_live_control_verification()
                    svc.audit.record("system.controls_verified", actor=actor, all_passed=rep["all_passed"])
                    return self._json(200, rep)
                elif p == "/api/cve/real-software-verify":
                    rep = run_real_software_cve_comparison()
                    svc.audit.record("cve.real_software_verified", actor=actor, all_passed=rep["all_passed"])
                    return self._json(200, rep)
                elif p == "/api/cve/sync":
                    st = svc.cve_monitor.ingest_payloads(
                        nvd_obj=body.get("nvd") if isinstance(body.get("nvd"), dict) else None,
                        kev_obj=body.get("kev") if isinstance(body.get("kev"), dict) else None,
                        source=str(body.get("source", "operator_sync")),
                    )
                    svc.audit.record("cve.synced", actor=actor, cve_count=st["cve_count"], kev_count=st["kev_count"])
                    return self._json(200, st)
                elif p == base + "/start":
                    svc.start()
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
                    return self._json(200, svc.verify_finding(fid, actor))
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
            except Exception as e:
                return self._json(409, {"error": str(e)})
            return self._json(200, svc.snapshot())

    return H


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--lab-port", type=int, default=18081)
    ap.add_argument("--verify-seconds", type=float, default=2.0)
    ap.add_argument("--data-dir", default=None)
    ap.add_argument("--require-read-auth", action="store_true",
                    help="Require operator authentication on all GET endpoints")
    a = ap.parse_args()
    data = Path(a.data_dir or tempfile.mkdtemp(prefix="aegis-"))
    data.mkdir(parents=True, exist_ok=True)
    seed = data / "operators.json"
    first = not seed.exists()
    start_lab(a.lab_port)
    svc = AssessmentService(data, a.lab_port, a.verify_seconds)
    ops = OperatorStore(seed)
    srv = ThreadingHTTPServer(
        ("127.0.0.1", a.port),
        make_handler(svc, ops, require_read_auth=a.require_read_auth or None),
    )
    srv.daemon_threads = True
    print(f"Vulnix control plane: http://127.0.0.1:{a.port}  (audit: {data / 'audit.jsonl'})")
    if first and ops.credentials_path:
        print(f"初回起動: 操作者アカウントを生成しました（ハッシュのみ {seed} に保存）。")
        print(f"初期ログイン情報（平文・600権限）: {ops.credentials_path}")
        print("内容は手元で確認してください。再生成するにはこの2ファイルを削除して再起動します。")
    srv.serve_forever()


if __name__ == "__main__":
    main()

