"""Operator accounts + sessions for the control plane (local use).

Passwords are stored only as scrypt hashes in a seed file (operators.json);
plaintext is never logged or returned. Sessions are opaque random tokens kept
server-side and handed to the browser as an HttpOnly, SameSite=Strict cookie.

Roles:
  - operator: may start / pause / resume / emergency-stop an assessment.
  - approver: may additionally decide L2+ approvals (separation of duty:
    the person who runs a scan should not be the only one who can approve
    higher-risk actions).
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

ROLES = ("operator", "approver")
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
        self._sessions: dict[str, Session] = {}
        self._pending_totp: dict[str, str] = {}   # name -> secret awaiting confirmation
        self.credentials_path: Path | None = None
        self._load_or_init()
        self._load_sessions()

    def _load_or_init(self) -> dict | None:
        """Returns a dict of generated plaintext passwords if seeded now, else None."""
        if self.seed_path.exists():
            raw = json.loads(self.seed_path.read_text())
            for o in raw["operators"]:
                self._ops[o["name"]] = Operator(o["name"], o.get("display", o["name"]),
                                                o["password_hash"], tuple(o["roles"]),
                                                o.get("totp_secret"))
            return None
        # First run: generate two accounts with random passwords and write the seed.
        generated = {"operator": secrets.token_urlsafe(12),
                     "approver": secrets.token_urlsafe(12)}
        defaults = [
            ("operator", "診断オペレーター", ("operator",), generated["operator"]),
            ("approver", "承認責任者", ("operator", "approver"), generated["approver"]),
        ]
        out = {"operators": []}
        for name, display, roles, pw in defaults:
            self._ops[name] = Operator(name, display, hash_password(pw), roles)
            out["operators"].append({"name": name, "display": display,
                                     "roles": list(roles),
                                     "password_hash": self._ops[name].password_hash})
        self.seed_path.write_text(json.dumps(out, ensure_ascii=False, indent=2))
        self.seed_path.chmod(0o600)
        # Write plaintext to a 0600 side file the operator reads themselves;
        # it is never printed to logs or returned over the API.
        cred = self.seed_path.with_name("operators.initial-credentials.txt")
        cred.write_text(
            "Aegis 初期ログイン情報（ローカル用・このファイルは手元で確認してください）\n"
            "ログイン後は漏えいに注意し、本番運用では必ず変更してください。\n\n"
            + "".join(f"ユーザー名: {n}\nパスワード: {p}\n\n" for n, p in generated.items()))
        cred.chmod(0o600)
        self.credentials_path = cred
        return generated

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
                try:
                    sess = Session(s["token"], s["operator"], tuple(s["roles"]),
                                   float(s["created"]), float(s["expires"]))
                except (KeyError, TypeError, ValueError):
                    continue
                if sess.expires > now and sess.operator in self._ops:
                    self._sessions[sess.token] = sess
        # Rewrite so the file sheds expired/stale entries on load.
        self._persist_sessions()

    def _atomic_write(self, path: Path, data: str) -> None:
        """Write 0600 via a temp file + rename so a reader never sees a half file."""
        tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
        try:
            tmp.write_text(data)
            tmp.chmod(0o600)
            os.replace(tmp, path)
        except OSError:
            tmp.unlink(missing_ok=True)   # best-effort: a write failure must not break the request

    def _persist_sessions(self) -> None:
        """Atomically write current sessions. The snapshot and the write are
        serialized under the lock so concurrent logins cannot clobber each
        other's entry (last writer would otherwise win with a stale set)."""
        with self._lock:
            payload = {"sessions": [
                {"token": s.token, "operator": s.operator, "roles": list(s.roles),
                 "created": s.created, "expires": s.expires}
                for s in self._sessions.values()
            ]}
            self._atomic_write(self.sessions_path, json.dumps(payload, ensure_ascii=False))

    def _persist_operators(self) -> None:
        """Atomically rewrite the operator seed (hashes only; never plaintext)."""
        with self._lock:
            payload = {"operators": [
                {"name": o.name, "display": o.display, "roles": list(o.roles),
                 "password_hash": o.password_hash,
                 **({"totp_secret": o.totp_secret} if o.totp_secret else {})}
                for o in self._ops.values()
            ]}
            self._atomic_write(self.seed_path, json.dumps(payload, ensure_ascii=False, indent=2))

    def change_password(self, name: str, current: str, new: str, *, keep_token: str | None = None) -> None:
        """Verify the current password, set a new one, and revoke this operator's
        other sessions (the one making the change, keep_token, is kept)."""
        with self._lock:
            op = self._ops.get(name)
        if not op or not verify_password(current, op.password_hash):
            raise AuthError("現在のパスワードが違います")
        if len(new) < MIN_PASSWORD_LEN:
            raise AuthError(f"新しいパスワードは{MIN_PASSWORD_LEN}文字以上にしてください")
        if new == current:
            raise AuthError("現在と異なるパスワードを設定してください")
        new_hash = hash_password(new)
        with self._lock:
            op.password_hash = new_hash
            for tok in [t for t, s in self._sessions.items()
                        if s.operator == name and t != keep_token]:
                del self._sessions[tok]
        self._persist_operators()
        self._persist_sessions()

    def login(self, name: str, password: str, code: str | None = None) -> Session:
        with self._lock:
            op = self._ops.get(name)
        # Always run a hash to blunt username enumeration via timing.
        reference = op.password_hash if op else hash_password("x")
        ok = verify_password(password, reference)
        if not op or not ok:
            raise AuthError("ユーザー名またはパスワードが違います")
        # Second factor: only enforced for accounts that enrolled one (opt-in,
        # so a local operator can never be locked out by a default).
        if op.totp_secret and not verify_totp(op.totp_secret, code or "", self._clock()):
            raise MFAChallenge("認証コード（2要素）が必要です" if not code else "認証コードが違います")
        now = self._clock()
        sess = Session(secrets.token_urlsafe(32), op.name, op.roles, now, now + SESSION_TTL)
        with self._lock:
            self._sessions[sess.token] = sess
        self._persist_sessions()
        return sess

    def resolve(self, token: str | None) -> Session | None:
        if not token:
            return None
        with self._lock:
            sess = self._sessions.get(token)
            if sess and self._clock() >= sess.expires:
                del self._sessions[token]
                return None
            return sess

    def logout(self, token: str | None) -> None:
        if not token:
            return
        with self._lock:
            removed = self._sessions.pop(token, None) is not None
        if removed:
            self._persist_sessions()

    def register(self, name: str, password: str, *, display: str = "",
                 roles: tuple[str, ...] | list[str] = ("operator",)) -> Session:
        """Register a new operator account (storing only its scrypt password hash)
        and return an authenticated session."""
        clean_name = (name or "").strip()
        if not clean_name or len(clean_name) < 2 or len(clean_name) > 32:
            raise AuthError("ユーザー名は2〜32文字で入力してください")
        if not all(c.isalnum() or c in ("_", "-", ".") for c in clean_name):
            raise AuthError("ユーザー名には英数字・ハイフン・アンダースコア・ドットのみ使用できます")
        if len(password or "") < MIN_PASSWORD_LEN:
            raise AuthError(f"パスワードは{MIN_PASSWORD_LEN}文字以上にしてください")
        role_set = [r for r in roles if r in ROLES]
        if "operator" not in role_set:
            role_set.insert(0, "operator")
        clean_roles = tuple(dict.fromkeys(role_set))
        clean_display = (display or "").strip()[:40] or clean_name
        pw_hash = hash_password(password)
        now = self._clock()
        with self._lock:
            if clean_name in self._ops:
                raise AuthError("このユーザー名は既に登録されています")
            self._ops[clean_name] = Operator(clean_name, clean_display, pw_hash, clean_roles)
            sess = Session(secrets.token_urlsafe(32), clean_name, clean_roles, now, now + SESSION_TTL)
            self._sessions[sess.token] = sess
        self._persist_operators()
        self._persist_sessions()
        return sess

    def operators(self) -> list[Operator]:
        with self._lock:
            return list(self._ops.values())

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

    def disable_totp(self, name: str, current_password: str) -> None:
        with self._lock:
            op = self._ops.get(name)
        if not op or not verify_password(current_password, op.password_hash):
            raise AuthError("現在のパスワードが違います")
        with self._lock:
            op.totp_secret = None
            self._pending_totp.pop(name, None)
        self._persist_operators()
