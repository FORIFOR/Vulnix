"""Operator accounts + sessions for the control plane (local use).

Passwords are stored only as scrypt hashes in a seed file (operators.json);
plaintext is never logged or returned. Sessions are opaque random tokens kept
server-side and handed to the browser as an HttpOnly, SameSite=Strict cookie.

Roles:
  - operator: may start / pause / resume / emergency-stop an assessment.
  - approver: may additionally decide L2+ approvals (separation of duty:
    the person who runs a scan should not be the only one who can approve
    higher-risk actions).
  - admin: may grant and revoke roles. Roles are NEVER self-assigned:
    self-registration creates an `operator` account only, and the approver
    role exists only where an admin granted it (each change is audited by
    the control plane).
An account may hold several roles. This is authentication + coarse
authorization for the UI; it does NOT replace the Gateway's execution token.

Accounts may optionally enroll a TOTP second factor (RFC 6238). It is opt-in,
so a local operator is never locked out by a default; once enrolled, login
requires a current code in addition to the password.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

ROLES = ("operator", "approver", "admin")
SESSION_TTL = 12 * 3600
MIN_PASSWORD_LEN = 10
TOTP_STEP = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1               # accept the adjacent step on each side for clock skew
_N, _R, _P = 2 ** 15, 8, 1    # scrypt cost parameters
_MAXMEM = 128 * _N * _R * 2   # OpenSSL's default 32 MiB cap is just below our need


class AuthError(Exception):
    pass


class MFAChallenge(AuthError):
    """Password was correct but a valid TOTP code is still required."""


class LockedOut(AuthError):
    """Too many failed attempts for this name; sign-in is paused for a while."""

    def __init__(self, retry_after: float, just_locked: bool = False):
        super().__init__("認証の失敗が続いたため、このアカウントでのログインを一時的に停止しています。"
                         f"約{max(1, int(retry_after // 60) + (1 if retry_after % 60 else 0))}分後にもう一度お試しください")
        self.retry_after = max(1.0, float(retry_after))
        self.just_locked = just_locked


# Sign-in throttling (per account name, whether or not the account exists, so the
# response does not reveal which names are real).
MAX_AUTH_FAILURES = 5          # failures ...
AUTH_FAILURE_WINDOW = 15 * 60  # ... within this many seconds ...
AUTH_LOCK_SECONDS = 15 * 60    # ... pause sign-in for this long
_MAX_TRACKED_NAMES = 5000


def session_key(token: str) -> str:
    """Sessions are stored and looked up by the SHA-256 of the bearer token. The
    token itself is 256 random bits and exists only in the user's cookie, so
    neither sessions.json nor process memory lets someone resume a session."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---- TOTP (RFC 6238 / HOTP RFC 4226), standard library only -----------------
def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def totp_code(secret_b32: str, t: float | None = None) -> str:
    t = time.time() if t is None else t
    return _hotp(secret_b32, int(t // TOTP_STEP))


def verify_totp(secret_b32: str, code: str, t: float | None = None) -> bool:
    code = (code or "").strip()
    if not code.isdigit():
        return False
    t = time.time() if t is None else t
    c0 = int(t // TOTP_STEP)
    return any(hmac.compare_digest(_hotp(secret_b32, c), code.zfill(TOTP_DIGITS))
               for c in range(c0 - TOTP_WINDOW, c0 + TOTP_WINDOW + 1))


def matching_totp_counter(secret_b32: str, code: str, t: float | None = None) -> int | None:
    """The time-step counter the code is valid for (within the skew window), or None."""
    code = (code or "").strip()
    if not code.isdigit():
        return None
    t = time.time() if t is None else t
    c0 = int(t // TOTP_STEP)
    for c in range(c0 - TOTP_WINDOW, c0 + TOTP_WINDOW + 1):
        if hmac.compare_digest(_hotp(secret_b32, c), code.zfill(TOTP_DIGITS)):
            return c
    return None


def provisioning_uri(secret_b32: str, name: str, issuer: str = "Aegis") -> str:
    label = quote(f"{issuer}:{name}")
    return (f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP}")


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32, maxmem=_MAXMEM)
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${dk.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, dk_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        ni, ri, pi = int(n), int(r), int(p)
        dk = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                            n=ni, r=ri, p=pi, dklen=len(dk_hex) // 2, maxmem=128 * ni * ri * 2)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk.hex(), dk_hex)


@dataclass
class Operator:
    name: str
    display: str
    password_hash: str
    roles: tuple[str, ...]
    totp_secret: str | None = None     # set => a second factor is required at login
    created_by: str | None = None      # admin who created it; "self" = self-registered (development mode)


@dataclass
class Session:
    token: str
    operator: str
    roles: tuple[str, ...]
    created: float
    expires: float


class OperatorStore:
    """Thread-safe operator + session store backed by a JSON seed file."""

    def __init__(self, seed_path: Path, clock=time.time, sessions_path: Path | None = None):
        self.seed_path = Path(seed_path)
        # Sessions survive a control-plane restart so operators are not all
        # logged out when the process is bounced. Kept in a sibling 0600 file.
        self.sessions_path = Path(sessions_path) if sessions_path else self.seed_path.with_name("sessions.json")
        self._clock = clock
        self._lock = threading.Lock()
        self._ops: dict[str, Operator] = {}
        self._sessions: dict[str, Session] = {}     # keyed by session_key(token); never the token
        self._auth_failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._throttle_names: dict[str, str] = {}    # throttle key -> name as typed (for the admin view)
        self._totp_last_counter: dict[str, int] = {} # account -> last accepted TOTP step (no replay)
        self.recovery_events: list[dict] = []        # drained into the audit log by the server
        # one fixed dummy hash, so an unknown name costs the same single scrypt as a known one
        self._dummy_hash = hash_password(secrets.token_urlsafe(12))
        self.legacy_sessions_revoked = 0             # plaintext-token sessions dropped at load
        self._pending_totp: dict[str, str] = {}   # name -> secret awaiting confirmation
        self.credentials_path: Path | None = None
        self.admin_credentials_path: Path | None = None
        self._load_or_init()
        self._load_sessions()

    def _load_or_init(self) -> dict | None:
        """Returns a dict of generated plaintext passwords if seeded now, else None."""
        if self.seed_path.exists():
            raw = json.loads(self.seed_path.read_text())
            for o in raw["operators"]:
                self._ops[o["name"]] = Operator(o["name"], o.get("display", o["name"]),
                                                o["password_hash"],
                                                tuple(r for r in o["roles"] if r in ROLES),
                                                o.get("totp_secret"), o.get("created_by"))
            self._ensure_admin()
            return None
        # First run: generate the accounts with random passwords and write the seed.
        generated = {"operator": secrets.token_urlsafe(12),
                     "approver": secrets.token_urlsafe(12),
                     "admin": secrets.token_urlsafe(12)}
        defaults = [
            ("operator", "診断オペレーター", ("operator",), generated["operator"]),
            ("approver", "承認責任者", ("operator", "approver"), generated["approver"]),
            ("admin", "管理者", ("operator", "admin"), generated["admin"]),
        ]
        out = {"operators": []}
        for name, display, roles, pw in defaults:
            self._ops[name] = Operator(name, display, hash_password(pw), roles)
            out["operators"].append({"name": name, "display": display,
                                     "roles": list(roles),
                                     "password_hash": self._ops[name].password_hash})
        self._write_private(self.seed_path, json.dumps(out, ensure_ascii=False, indent=2))
        # Write plaintext to a 0600 side file the operator reads themselves;
        # it is never printed to logs or returned over the API.
        cred = self.seed_path.with_name("operators.initial-credentials.txt")
        self._write_private(
            cred,
            "Aegis 初期ログイン情報（ローカル用・このファイルは手元で確認してください）\n"
            "ログイン後は漏えいに注意し、本番運用では必ず変更してください。\n\n"
            + "".join(f"ユーザー名: {n}\nパスワード: {p}\n\n" for n, p in generated.items()))
        self.credentials_path = cred
        return generated

    def _ensure_admin(self) -> None:
        """An installation created before the admin role existed has nobody who can
        grant roles. Create one admin account with a random password, written only
        to a 0600 side file. No existing account is promoted: which of them should
        hold that power is not something this code can know."""
        if any("admin" in o.roles for o in self._ops.values()):
            return
        name = "admin" if "admin" not in self._ops else "admin-" + secrets.token_hex(3)
        password = secrets.token_urlsafe(12)
        self._ops[name] = Operator(name, "管理者", hash_password(password), ("operator", "admin"))
        self._persist_operators()
        cred = self.seed_path.with_name("operators.admin-credentials.txt")
        self._write_private(
            cred,
            "Aegis 管理者アカウント（ロール付与用・このファイルは手元で確認してください）\n"
            "ログイン後にパスワードを変更し、このファイルは削除してください。\n\n"
            f"ユーザー名: {name}\nパスワード: {password}\n")
        self.admin_credentials_path = cred

    def _load_sessions(self) -> None:
        """Restore unexpired sessions for still-known operators after a restart."""
        if not self.sessions_path.exists():
            return
        try:
            raw = json.loads(self.sessions_path.read_text())
        except (ValueError, OSError):
            return   # corrupt/unreadable session store: start with none, don't crash
        now = self._clock()
        with self._lock:
            for s in raw.get("sessions", []):
                if not isinstance(s, dict):
                    continue
                if "token_sha256" not in s:
                    # Written by an older version that stored the bearer token itself.
                    # Such a session is NOT carried over: the token sat on disk, so it
                    # is revoked and the operator simply signs in again.
                    self.legacy_sessions_revoked += 1
                    continue
                try:
                    key = str(s["token_sha256"])
                    sess = Session("", s["operator"], (), float(s["created"]), float(s["expires"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if len(key) == 64 and sess.expires > now and sess.operator in self._ops:
                    self._sessions[key] = sess
        # Rewrite so the file sheds expired/stale entries on load.
        self._persist_sessions()

    def _atomic_write(self, path: Path, data: str) -> bool:
        """Write 0600 via a temp file + rename so a reader never sees a half file."""
        tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
        try:
            self._write_private(tmp, data)
            os.replace(tmp, path)
            return True
        except OSError:
            tmp.unlink(missing_ok=True)   # best-effort: a write failure must not break the request
            return False

    @staticmethod
    def _write_private(path: Path, data: str) -> None:
        """Create the file 0600 from the start (no window in which it is readable)."""
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
        os.chmod(path, 0o600)

    def _persist_sessions(self) -> None:
        """Atomically write current sessions. The snapshot and the write are
        serialized under the lock so concurrent logins cannot clobber each
        other's entry (last writer would otherwise win with a stale set)."""
        with self._lock:
            payload = {"version": 2, "sessions": [
                # only the hash of the token, and no roles (roles come from the account)
                {"token_sha256": key, "operator": s.operator,
                 "created": s.created, "expires": s.expires}
                for key, s in self._sessions.items()
            ]}
            self._atomic_write(self.sessions_path, json.dumps(payload, ensure_ascii=False))

    def _persist_operators(self, *, strict: bool = False) -> None:
        """Atomically rewrite the operator seed (hashes only; never plaintext).
        `strict`: a change that REMOVES power (role revoked, second factor reset)
        must not look done when it was not written - after a restart it would be
        undone - so the caller is told."""
        with self._lock:
            payload = {"operators": [
                {"name": o.name, "display": o.display, "roles": list(o.roles),
                 "password_hash": o.password_hash,
                 **({"totp_secret": o.totp_secret} if o.totp_secret else {}),
                 **({"created_by": o.created_by} if o.created_by else {})}
                for o in self._ops.values()
            ]}
            written = self._atomic_write(self.seed_path, json.dumps(payload, ensure_ascii=False, indent=2))
        if strict and not written:
            raise AuthError("変更は現在のプロセスには反映されましたが、ファイルへの保存に失敗しました。"
                            "このままでは再起動後に元へ戻ります。データディレクトリの書き込み権限を確認してください")

    def change_password(self, name: str, current: str, new: str, *, keep_token: str | None = None) -> None:
        """Verify the current password, set a new one, and revoke this operator's
        other sessions (the one making the change, keep_token, is kept)."""
        with self._lock:
            op = self._ops.get(name)
        self._check_not_locked(name)
        if not op or not verify_password(current, op.password_hash):
            self._note_failure(name)
            raise AuthError("現在のパスワードが違います")
        if len(new) < MIN_PASSWORD_LEN:
            raise AuthError(f"新しいパスワードは{MIN_PASSWORD_LEN}文字以上にしてください")
        if new == current:
            raise AuthError("現在と異なるパスワードを設定してください")
        self._clear_failures(name)
        new_hash = hash_password(new)
        with self._lock:
            op.password_hash = new_hash
            keep = session_key(keep_token) if keep_token else None
            for key in [k for k, s in self._sessions.items() if s.operator == name and k != keep]:
                del self._sessions[key]
        self._persist_operators()
        self._persist_sessions()

    # ---- sign-in throttling ----------------------------------------------
    @staticmethod
    def _throttle_key(name: str) -> str:
        # The EXACT name as presented (account names are case-sensitive). Variants
        # such as "ROOT" or " root" are different keys, so they can neither lock
        # the real account nor reset its counter. Hashed to bound the key size.
        return hashlib.sha256((name or "").encode("utf-8", "replace")).hexdigest()

    def _apply_file_unlock_locked(self) -> None:
        """Recovery without a session: someone with access to the data directory
        (the machine's operator) creates `unlock.request` next to the seed file,
        one account name per line. It is honoured once and removed."""
        path = self.seed_path.with_name("unlock.request")
        try:
            st = os.lstat(path)
        except OSError:
            return
        import stat as _stat
        ok = (_stat.S_ISREG(st.st_mode) and not (st.st_mode & 0o022)
              and (not hasattr(os, "getuid") or st.st_uid == os.getuid()))
        names: list[str] = []
        if ok:
            try:
                names = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()][:50]
            except OSError:
                ok = False
        try:
            os.unlink(path)
        except OSError:
            pass
        if not ok:
            self.recovery_events.append({"event": "auth.unlock_file_rejected",
                                         "reason": "not a regular file owned by this user, or writable by others"})
            return
        for name in names:
            key = self._throttle_key(name)
            was = self._locked_until.pop(key, 0.0) > self._clock()
            self._auth_failures.pop(key, None)
            self.recovery_events.append({"event": "auth.unlocked_by_file", "name": name[:64], "was_locked": was})

    def _check_not_locked(self, name: str) -> None:
        self._begin_attempt(name)

    def _begin_attempt(self, name: str) -> None:
        """Reserve one attempt BEFORE the (slow) password check. Attempts in flight
        count, so firing many guesses in parallel gets no more evaluations than
        doing them one after another."""
        key, now = self._throttle_key(name), self._clock()
        with self._lock:
            self._apply_file_unlock_locked()
            until = self._locked_until.get(key, 0.0)
            if until > now:
                raise LockedOut(until - now)
            if until:
                self._locked_until.pop(key, None)
                self._auth_failures.pop(key, None)
            recent = [t for t in self._auth_failures.get(key, []) if now - t <= AUTH_FAILURE_WINDOW]
            if len(recent) >= MAX_AUTH_FAILURES:
                self._locked_until[key] = now + AUTH_LOCK_SECONDS
                self._auth_failures[key] = recent
                raise LockedOut(AUTH_LOCK_SECONDS, just_locked=True)
            if key not in self._auth_failures and len(self._auth_failures) >= _MAX_TRACKED_NAMES:
                self._make_room_locked(name, now)
            recent.append(now)
            self._auth_failures[key] = recent
            self._throttle_names[key] = (name or "")[:64]

    def _make_room_locked(self, name: str, now: float) -> None:
        """Bounded memory without letting a flood of made-up names push out the
        counter of a real account: only entries for names that are not accounts
        (and are not locked) are ever evicted."""
        account_keys = {self._throttle_key(n) for n in self._ops}
        evictable = [k for k in self._auth_failures
                     if k not in account_keys and self._locked_until.get(k, 0.0) <= now]
        if not evictable:
            raise LockedOut(60.0)
        evictable.sort(key=lambda k: self._auth_failures[k][-1] if self._auth_failures[k] else 0.0)
        for k in evictable[: max(1, len(evictable) // 10)]:
            self._auth_failures.pop(k, None)
            self._throttle_names.pop(k, None)

    def _note_failure(self, name: str) -> None:
        """The reserved attempt failed; raises LockedOut when it was the last one allowed."""
        key, now = self._throttle_key(name), self._clock()
        with self._lock:
            recent = [t for t in self._auth_failures.get(key, []) if now - t <= AUTH_FAILURE_WINDOW]
            if len(recent) >= MAX_AUTH_FAILURES:
                self._locked_until[key] = now + AUTH_LOCK_SECONDS
                raise LockedOut(AUTH_LOCK_SECONDS, just_locked=True)

    def _forget_attempt(self, name: str) -> None:
        """The reserved attempt was not a guess after all (e.g. step 1 of a two-step login)."""
        key = self._throttle_key(name)
        with self._lock:
            recent = self._auth_failures.get(key)
            if recent:
                recent.pop()

    def _clear_failures(self, name: str) -> None:
        key = self._throttle_key(name)
        with self._lock:
            self._auth_failures.pop(key, None)
            self._locked_until.pop(key, None)
            self._throttle_names.pop(key, None)

    def locked_accounts(self) -> dict[str, float]:
        """name (as typed) -> seconds remaining, for names currently locked."""
        now = self._clock()
        with self._lock:
            return {self._throttle_names.get(k, "?"): until - now
                    for k, until in self._locked_until.items() if until > now}

    def unlock(self, target: str, *, actor: str) -> bool:
        """An admin lifts a lock early (recovery for a legitimate user). The lock
        also ends by itself after AUTH_LOCK_SECONDS, is not kept across a restart,
        and can be lifted from the machine itself with an `unlock.request` file."""
        with self._lock:
            acting = self._ops.get(actor)
            if acting is None or "admin" not in acting.roles:
                raise AuthError("ロックを解除できるのは管理者だけです")
            key = self._throttle_key(target)
            was_locked = self._locked_until.pop(key, 0.0) > self._clock()
            self._auth_failures.pop(key, None)
            return was_locked

    def _accept_totp(self, op: "Operator", code: str | None) -> bool:
        """True if `code` is a current code that was not used before (no replay)."""
        counter = matching_totp_counter(op.totp_secret or "", code or "", self._clock())
        if counter is None:
            return False
        with self._lock:
            if counter <= self._totp_last_counter.get(op.name, -1):
                return False
            self._totp_last_counter[op.name] = counter
        return True

    def login(self, name: str, password: str, code: str | None = None) -> Session:
        self._begin_attempt(name)           # while locked, even the right password is refused
        with self._lock:
            op = self._ops.get(name)
        # Exactly one scrypt whether or not the name exists (no timing difference).
        ok = verify_password(password, op.password_hash if op else self._dummy_hash)
        if not op or not ok:
            self._note_failure(name)
            raise AuthError("ユーザー名またはパスワードが違います")
        # Second factor: only enforced for accounts that enrolled one (opt-in,
        # so a local operator can never be locked out by a default).
        if op.totp_secret and not self._accept_totp(op, code):
            if code:                        # a wrong (or replayed) code is a failed attempt
                self._note_failure(name)
            else:                           # a missing one is just step 1 of the login
                self._forget_attempt(name)
            raise MFAChallenge("認証コード（2要素）が必要です" if not code else "認証コードが違います")
        self._clear_failures(name)
        now = self._clock()
        sess = Session(secrets.token_urlsafe(32), op.name, op.roles, now, now + SESSION_TTL)
        with self._lock:
            self._sessions[session_key(sess.token)] = Session("", op.name, (), now, sess.expires)
        self._persist_sessions()
        return sess

    def resolve(self, token: str | None) -> Session | None:
        if not token:
            return None
        key = session_key(token)
        with self._lock:
            sess = self._sessions.get(key)
            if sess and self._clock() >= sess.expires:
                del self._sessions[key]
                return None
            if sess is None:
                return None
            # Roles come from the account as it is NOW, so a revoked role stops
            # working at once and a stored session cannot carry a stale one.
            op = self._ops.get(sess.operator)
            if op is None:
                del self._sessions[key]
                return None
            # the caller gets the token it presented; the store keeps only its hash
            return Session(token, sess.operator, op.roles, sess.created, sess.expires)

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            removed = self._sessions.pop(session_key(token), None) is not None
        if removed:
            self._persist_sessions()

    def create_account(self, name: str, password: str, *, display: str = "", actor: str) -> Operator:
        """An admin creates an `operator` account for someone else. No session is
        issued; the new operator logs in with the password they were given."""
        with self._lock:
            acting = self._ops.get(actor)
            if acting is None or "admin" not in acting.roles:
                raise AuthError("アカウントを作成できるのは管理者だけです")
        sess = self.register(name, password, display=display, _created_by=actor, _issue_session=False)
        with self._lock:
            return self._ops[sess.operator]

    def is_self_registered(self, name: str) -> bool:
        with self._lock:
            op = self._ops.get(name)
            return bool(op and op.created_by == "self")

    def register(self, name: str, password: str, *, display: str = "",
                 _created_by: str = "self", _issue_session: bool = True) -> Session:
        """Creates an `operator` account (storing only its scrypt password hash).
        Called directly it is SELF-registration, which the server allows only in
        development mode. It can never grant `approver` or `admin`; those are
        assigned by an admin via `set_roles`."""
        clean_name = (name or "").strip()
        if not clean_name or len(clean_name) < 2 or len(clean_name) > 32:
            raise AuthError("ユーザー名は2〜32文字で入力してください")
        if not all(c.isalnum() or c in ("_", "-", ".") for c in clean_name):
            raise AuthError("ユーザー名には英数字・ハイフン・アンダースコア・ドットのみ使用できます")
        if len(password or "") < MIN_PASSWORD_LEN:
            raise AuthError(f"パスワードは{MIN_PASSWORD_LEN}文字以上にしてください")
        clean_roles = ("operator",)
        clean_display = (display or "").strip()[:40] or clean_name
        pw_hash = hash_password(password)
        now = self._clock()
        with self._lock:
            if clean_name in self._ops:
                raise AuthError("このユーザー名は既に登録されています")
            self._ops[clean_name] = Operator(clean_name, clean_display, pw_hash, clean_roles,
                                             created_by=_created_by)
            sess = Session(secrets.token_urlsafe(32), clean_name, clean_roles, now, now + SESSION_TTL)
            if _issue_session:
                self._sessions[session_key(sess.token)] = Session("", clean_name, (), now, sess.expires)
        self._persist_operators()
        if _issue_session:
            self._persist_sessions()
        return sess

    def operators(self) -> list[Operator]:
        with self._lock:
            return list(self._ops.values())

    def set_roles(self, target: str, roles: list[str] | tuple[str, ...], *, actor: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        """Replace `target`'s roles. Returns (before, after). The caller (server)
        has already established that `actor` is an authenticated admin; this
        re-checks it, and refuses changes that would defeat the model."""
        unknown = [r for r in roles if r not in ROLES]
        if unknown:
            raise AuthError(f"不明なロールです: {', '.join(unknown)}")
        new_roles = tuple(r for r in ROLES if r == "operator" or r in roles)   # canonical order
        with self._lock:
            acting = self._ops.get(actor)
            if acting is None or "admin" not in acting.roles:
                raise AuthError("ロールを変更できるのは管理者だけです")
            op = self._ops.get(target)
            if op is None:
                raise AuthError("対象のアカウントが見つかりません")
            before = op.roles
            if target == actor and set(new_roles) != set(before):
                # no self-service in either direction: not granting oneself approver,
                # and not dropping the admin role by accident
                raise AuthError("自分自身のロールは変更できません。別の管理者が変更してください")
            if "admin" in before and "admin" not in new_roles and not any(
                    "admin" in o.roles for n, o in self._ops.items() if n != target):
                raise AuthError("最後の管理者から管理者ロールを外すことはできません")
            op.roles = new_roles
        self._persist_operators(strict=True)
        return before, new_roles

    # ---- two-factor (TOTP) enrollment ------------------------------------
    def totp_enabled(self, name: str) -> bool:
        with self._lock:
            op = self._ops.get(name)
        return bool(op and op.totp_secret)

    def begin_totp_enroll(self, name: str) -> tuple[str, str]:
        """Generate a pending secret and return (secret, otpauth URI). Not active
        until confirm_totp() proves the operator can produce a current code."""
        with self._lock:
            op = self._ops.get(name)
            if not op:
                raise AuthError("不明なアカウントです")
            if op.totp_secret:
                raise AuthError("2要素認証は既に有効です")
            secret = generate_totp_secret()
            self._pending_totp[name] = secret
        return secret, provisioning_uri(secret, name)

    def confirm_totp(self, name: str, code: str) -> None:
        with self._lock:
            secret = self._pending_totp.get(name)
            op = self._ops.get(name)
        if not secret or not op:
            raise AuthError("先に2要素認証の有効化を開始してください")
        if not verify_totp(secret, code, self._clock()):
            raise AuthError("認証コードが違います")
        with self._lock:
            op.totp_secret = secret
            self._pending_totp.pop(name, None)
        self._persist_operators()

    def disable_totp(self, name: str, current_password: str, code: str | None = None) -> None:
        """Turning the second factor off needs BOTH factors: the password and a
        current code. (Lost device: an admin resets it with `reset_totp`.)"""
        with self._lock:
            op = self._ops.get(name)
        self._check_not_locked(name)
        if not op or not verify_password(current_password, op.password_hash):
            self._note_failure(name)
            raise AuthError("現在のパスワードが違います")
        if op.totp_secret and not self._accept_totp(op, code):
            self._note_failure(name)
            raise AuthError("現在の認証コード（2要素）が必要です")
        self._clear_failures(name)
        with self._lock:
            op.totp_secret = None
            self._pending_totp.pop(name, None)
        self._persist_operators()

    def reset_totp(self, target: str, *, actor: str) -> bool:
        """Recovery for a lost authenticator: an admin (never the account itself)
        removes the second factor and signs the account out everywhere."""
        with self._lock:
            acting = self._ops.get(actor)
            if acting is None or "admin" not in acting.roles:
                raise AuthError("2要素認証をリセットできるのは管理者だけです")
            if target == actor:
                raise AuthError("自分自身の2要素認証はリセットできません。別の管理者に依頼してください")
            op = self._ops.get(target)
            if op is None:
                raise AuthError("対象のアカウントが見つかりません")
            had = bool(op.totp_secret)
            op.totp_secret = None
            self._pending_totp.pop(target, None)
            for key in [k for k, s in self._sessions.items() if s.operator == target]:
                del self._sessions[key]
        self._persist_operators(strict=True)
        self._persist_sessions()
        return had
