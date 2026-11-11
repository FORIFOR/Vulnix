"""Encrypted secret store for L2 verification test accounts (`aegis/secrets_store.py`).

Stores test account credentials (`user_a_token`, `user_b_token`, `free_plan_token`)
and mock resource identifiers (`mock_note_path`, `mock_audio_path`, `mock_share_path`,
`mock_gcs_path`, `mock_chat_path`, `mock_billing_path`; unset paths fall back to the
worker's built-in mock path for that check) encrypted at rest using
PBKDF2-HMAC-SHA256 + authenticated stream cipher + HMAC-SHA256 tag.

Security guarantees:
  * Master key (`0600` permissions) and ciphertext live in `data_dir` (never in git).
  * Raw secret values are NEVER returned by `public_status()`, NEVER written to
    `audit.jsonl`, `state.json`, Markdown reports, or Remotion exports.
  * `redact(text)` scrubs any registered secret value from arbitrary strings.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

SECRET_TOKEN_KEYS = ("user_a_token", "user_b_token", "free_plan_token")
MOCK_PATH_KEYS = (
    "mock_note_path",
    "mock_audio_path",
    "mock_share_path",
    "mock_gcs_path",
    "mock_chat_path",
    "mock_billing_path",
)

# check -> (mock path key, subject token key, owner-control token key or None)
CHECK_SECRET_MAP = {
    "deepnote_idor_notes": ("mock_note_path", "user_a_token", "user_b_token"),
    "deepnote_share_link": ("mock_share_path", "user_a_token", None),
    "deepnote_gcs_acl": ("mock_gcs_path", "user_a_token", "user_b_token"),
    "deepnote_ai_chat_isolation": ("mock_chat_path", "user_a_token", "user_b_token"),
    "deepnote_billing_plan": ("mock_billing_path", "free_plan_token", None),
}

_PATH_RE = re.compile(r"/[!-~]{0,299}")   # printable ASCII, no spaces / CR / LF


def _keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(enc_key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def encrypt_blob(master_key: bytes, plaintext: bytes) -> dict:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", master_key, salt, 60_000, dklen=64)
    enc_key, mac_key = derived[:32], derived[32:]
    stream = _keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    return {
        "v": 1,
        "alg": "PBKDF2-HMAC-SHA256-CTR-MAC",
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_blob(master_key: bytes, env: dict) -> bytes:
    salt = base64.b64decode(env["salt"])
    nonce = base64.b64decode(env["nonce"])
    ciphertext = base64.b64decode(env["ct"])
    tag = base64.b64decode(env["tag"])
    derived = hashlib.pbkdf2_hmac("sha256", master_key, salt, 60_000, dklen=64)
    enc_key, mac_key = derived[:32], derived[32:]
    expected_tag = hmac.new(mac_key, salt + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("secret store authentication tag mismatch")
    stream = _keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))


class EncryptedSecretStore:
    """Per-asset encrypted store for L2 test account credentials and mock paths."""

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._key_path = self.data_dir / ".secrets.key"
        self._enc_path = self.data_dir / "secrets.enc.json"
        self._master_key = self._load_or_create_key()
        self._cache: dict[str, dict] = self._load_all()

    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists():
            raw = self._key_path.read_bytes().strip()
            if len(raw) >= 32:
                return base64.b64decode(raw)
        key = secrets.token_bytes(32)
        encoded = base64.b64encode(key)
        fd = os.open(self._key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(encoded)
        return key

    def _load_all(self) -> dict[str, dict]:
        if not self._enc_path.exists():
            return {}
        try:
            env = json.loads(self._enc_path.read_text(encoding="utf-8"))
            raw = decrypt_blob(self._master_key, env)
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_all(self) -> None:
        plaintext = json.dumps(self._cache, ensure_ascii=False).encode("utf-8")
        env = encrypt_blob(self._master_key, plaintext)
        tmp = self._enc_path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(env, f, indent=2)
        os.replace(tmp, self._enc_path)

    def set_credentials(self, asset_id: str, payload: dict, *, actor: str = "operator") -> dict:
        rec = dict(self._cache.get(asset_id) or {})
        for k in SECRET_TOKEN_KEYS:
            if isinstance(payload.get(k), str) and payload[k].strip():
                val = payload[k].strip()
                if len(val) < 8 or len(val) > 4096 or any(c.isspace() for c in val):
                    raise ValueError("検証用トークンは空白を含まない8〜4096文字で指定してください")
                rec[k] = val
        if rec.get("user_a_token") and rec.get("user_a_token") == rec.get("user_b_token"):
            # Same account on both sides would make a cross-account check meaningless
            # (the "owner control" and the "attacker" would be the same identity).
            raise ValueError("アカウントAとアカウントBには異なる検証用アカウントのトークンを設定してください")
        for k in MOCK_PATH_KEYS:
            if isinstance(payload.get(k), str) and payload[k].strip():
                val = payload[k].strip()
                if not val.startswith("/"):
                    val = "/" + val
                if not _PATH_RE.fullmatch(val):
                    raise ValueError("模擬データのパスは空白を含まない ASCII 300 文字以内で指定してください")
                rec[k] = val
        rec["updated_at"] = time.time()
        rec["updated_by"] = actor
        self._cache[asset_id] = rec
        self._save_all()
        return self.public_status(asset_id)

    def clear_credentials(self, asset_id: str) -> dict:
        self._cache.pop(asset_id, None)
        self._save_all()
        return self.public_status(asset_id)

    def get_decrypted_for_worker(self, asset_id: str) -> dict | None:
        """Internal use ONLY when spawning an approved L2 worker. Never log the return value."""
        rec = self._cache.get(asset_id)
        if not rec or not rec.get("user_a_token") or not rec.get("user_b_token"):
            return None
        return dict(rec)

    def is_ready_for_l2(self, asset_id: str) -> bool:
        rec = self._cache.get(asset_id)
        return bool(rec and rec.get("user_a_token") and rec.get("user_b_token"))

    def missing_for_check(self, asset_id: str, check: str) -> list[str]:
        """Token keys still required before `check` can run (empty list = ready)."""
        if check not in CHECK_SECRET_MAP:
            return ["unsupported_check"]
        _, subject_key, control_key = CHECK_SECRET_MAP[check]
        rec = self._cache.get(asset_id) or {}
        return [k for k in (subject_key, control_key) if k and not rec.get(k)]

    def worker_env_for_check(self, asset_id: str, check: str) -> dict[str, str]:
        """Minimal environment for ONE approved worker run of `check`.
        Never log the return value."""
        if self.missing_for_check(asset_id, check):
            return {}
        path_key, subject_key, control_key = CHECK_SECRET_MAP[check]
        rec = self._cache[asset_id]
        env = {"VULNIX_L2_TOKEN": rec[subject_key]}
        if control_key:
            env["VULNIX_L2_CONTROL_TOKEN"] = rec[control_key]
        if rec.get(path_key):
            env["VULNIX_L2_PATH"] = rec[path_key]
        return env

    def public_status(self, asset_id: str) -> dict:
        """Safe status object for UI/API/logs — never includes raw token strings."""
        rec = self._cache.get(asset_id) or {}
        has_a = bool(rec.get("user_a_token"))
        has_b = bool(rec.get("user_b_token"))
        has_free = bool(rec.get("free_plan_token"))
        return {
            "asset_id": asset_id,
            "l2_ready": bool(has_a and has_b),
            "encryption": "PBKDF2-HMAC-SHA256-CTR-MAC (0600 file permissions)",
            "has_user_a_token": has_a,
            "has_user_b_token": has_b,
            "has_free_plan_token": has_free,
            "user_a_fingerprint": (
                hashlib.sha256(rec["user_a_token"].encode()).hexdigest()[:8] if has_a else None
            ),
            "user_b_fingerprint": (
                hashlib.sha256(rec["user_b_token"].encode()).hexdigest()[:8] if has_b else None
            ),
            "free_plan_fingerprint": (
                hashlib.sha256(rec["free_plan_token"].encode()).hexdigest()[:8] if has_free else None
            ),
            "mock_paths": {k: rec.get(k) for k in MOCK_PATH_KEYS if rec.get(k)},
            "checks": {
                c: {"ready": not self.missing_for_check(asset_id, c),
                    "missing": self.missing_for_check(asset_id, c)}
                for c in CHECK_SECRET_MAP
            },
            "updated_at": rec.get("updated_at"),
            "updated_by": rec.get("updated_by"),
        }

    def redact(self, text: str) -> str:
        """Replace any registered secret token in `text` with `[REDACTED_SECRET]`."""
        if not text:
            return text
        out = text
        for rec in self._cache.values():
            for k in SECRET_TOKEN_KEYS:
                secret_val = rec.get(k)
                if isinstance(secret_val, str) and len(secret_val) >= 4 and secret_val in out:
                    out = out.replace(secret_val, "[REDACTED_SECRET]")
        return out
