"""Encrypted secret store for L2 verification test accounts (`aegis/secrets_store.py`).

Stores test-account tokens (keys ending in `_token`) and operator overrides of
mock resource paths (keys ending in `_path`) per asset, encrypted at rest using
PBKDF2-HMAC-SHA256 + authenticated stream cipher + HMAC-SHA256 tag.

Which keys exist, which accounts must differ, and which check needs which key is
defined by the service profile (`aegis/l2_rules.py`), not by this module.

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

from .l2_rules import paths_used, tokens_needed

_PATH_RE = re.compile(r"/[!-~]{0,299}")   # printable ASCII, no spaces / CR / LF


def _is_token_key(key: str) -> bool:
    return key.endswith("_token")


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
            os.chmod(self._key_path, 0o600)
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

    def set_credentials(self, asset_id: str, payload: dict, *, profile: dict,
                        actor: str = "operator") -> dict:
        """Merge tokens/paths declared by `profile` into the asset's record.
        Empty values leave the stored value unchanged; undeclared keys are rejected."""
        unknown = [k for k, v in payload.items()
                   if isinstance(v, str) and v.strip()
                   and k not in profile["tokens"] and k not in profile["paths"]]
        if unknown:
            raise ValueError(f"この対象の判定ルールで定義されていない項目です: {', '.join(sorted(unknown))}")
        usable_tokens = {t for c in profile["checks"] if c["spec_status"] == "confirmed"
                         for t in tokens_needed(c)}
        unusable = [k for k in profile["tokens"]
                    if isinstance(payload.get(k), str) and payload[k].strip() and k not in usable_tokens]
        if unusable:
            # do not hold a credential that no executable rule can use
            raise ValueError(
                "仕様未照合（placeholder）の判定ルールでしか使われないトークンは保存できません: "
                + "、".join(profile["tokens"][k]["label"] for k in unusable))
        rec = dict(self._cache.get(asset_id) or {})
        for k in profile["tokens"]:
            if isinstance(payload.get(k), str) and payload[k].strip():
                val = payload[k].strip()
                if len(val) < 8 or len(val) > 4096 or any(c.isspace() for c in val):
                    raise ValueError("検証用トークンは空白を含まない8〜4096文字で指定してください")
                rec[k] = val
        for a, b in profile["distinct_tokens"]:
            # The same account in two roles would make the comparison meaningless
            # (the "owner control" and the "unauthorized side" would be one identity).
            if rec.get(a) and rec.get(a) == rec.get(b):
                raise ValueError(
                    f"「{profile['tokens'][a]['label']}」と「{profile['tokens'][b]['label']}」には"
                    "異なる検証用アカウントのトークンを設定してください")
        for k in profile["paths"]:
            if isinstance(payload.get(k), str) and payload[k].strip():
                val = payload[k].strip()
                if not val.startswith("/"):
                    val = "/" + val
                if not _PATH_RE.fullmatch(val):
                    raise ValueError("模擬データのパスは空白を含まない ASCII 300 文字以内で指定してください")
                pattern = profile["paths"][k].get("override_pattern")
                if not pattern or re.fullmatch(pattern, val) is None:
                    # the admin accepted this profile's requests; an override may only
                    # vary them the way the profile itself allows
                    raise ValueError(
                        f"「{profile['paths'][k]['label']}」は、判定ルールが許可する形式のパスにだけ変更できます"
                        + (f"（許可: {pattern}）" if pattern else "（このパスは変更できません）"))
                rec[k] = val
        rec["updated_at"] = time.time()
        rec["updated_by"] = actor
        self._cache[asset_id] = rec
        self._save_all()
        return self.public_status(asset_id, profile)

    def clear_credentials(self, asset_id: str) -> bool:
        """Forget an asset's tokens. Returns False if the file could not be rewritten:
        the tokens are gone from this process, but the old ciphertext is still on
        disk. A revocation must never be aborted because of that, so this does not
        raise; the caller's scope/proof revocation makes those tokens unusable."""
        self._cache.pop(asset_id, None)
        try:
            self._save_all()
            return True
        except OSError:
            return False

    def has_any_token(self, asset_id: str) -> bool:
        rec = self._cache.get(asset_id) or {}
        return any(_is_token_key(k) and v for k, v in rec.items())

    def missing_for_check(self, asset_id: str, check: dict) -> list[str]:
        """Token keys still required before `check` can run (empty list = ready)."""
        rec = self._cache.get(asset_id) or {}
        return [k for k in tokens_needed(check) if not rec.get(k)]

    def worker_env_for_check(self, asset_id: str, check: dict) -> dict[str, str]:
        """Minimal environment for ONE approved worker run of `check`: only the
        tokens and path overrides that rule uses. Never log the return value.
        Nothing is released for a rule that is not confirmed against the API."""
        if check.get("spec_status") != "confirmed" or self.missing_for_check(asset_id, check):
            return {}
        rec = self._cache[asset_id]
        env = {"VULNIX_L2_TOKENS": json.dumps({k: rec[k] for k in tokens_needed(check)})}
        overrides = {k: rec[k] for k in paths_used(check) if rec.get(k)}
        self._last_override_keys = sorted(overrides)
        if overrides:
            env["VULNIX_L2_PATHS"] = json.dumps(overrides)
        return env

    def public_status(self, asset_id: str, profile: dict | None) -> dict:
        """Safe status object for UI/API/logs - never includes raw token strings."""
        rec = self._cache.get(asset_id) or {}
        status = {
            "asset_id": asset_id,
            "encryption": "PBKDF2-HMAC-SHA256-CTR-MAC (0600 file permissions)",
            "profile": None,
            "tokens": [],
            "paths": [],
            "checks": {},
            "l2_ready": False,
            "updated_at": rec.get("updated_at"),
            "updated_by": rec.get("updated_by"),
        }
        if profile is None:
            return status
        status["profile"] = {"id": profile["id"], "label": profile["label"],
                             "spec_status": profile["spec_status"], "spec_note": profile["spec_note"]}
        status["tokens"] = [
            {"key": k, "label": meta["label"], "set": bool(rec.get(k)),
             "usable": any(c["spec_status"] == "confirmed" and k in tokens_needed(c)
                           for c in profile["checks"]),
             "fingerprint": hashlib.sha256(rec[k].encode()).hexdigest()[:8] if rec.get(k) else None}
            for k, meta in profile["tokens"].items()]
        status["paths"] = [
            {"key": k, "label": meta["label"], "default": meta["default"], "value": rec.get(k)}
            for k, meta in profile["paths"].items()]
        for c in profile["checks"]:
            missing = self.missing_for_check(asset_id, c)
            runnable = c["spec_status"] == "confirmed"
            status["checks"][c["id"]] = {
                "label": c["label"], "category": c["category"],
                "spec_status": c["spec_status"], "spec_note": c["spec_note"],
                "ready": runnable and not missing, "missing": missing if runnable else [],
                "preconditions": [p["label"] for p in c["preconditions"]],
            }
        status["l2_ready"] = any(c["ready"] for c in status["checks"].values())
        return status

    def redact(self, text: str) -> str:
        """Replace any registered secret token in `text` with `[REDACTED_SECRET]`."""
        if not text:
            return text
        out = text
        for rec in self._cache.values():
            for k, secret_val in rec.items():
                if (_is_token_key(k) and isinstance(secret_val, str)
                        and len(secret_val) >= 4 and secret_val in out):
                    out = out.replace(secret_val, "[REDACTED_SECRET]")
        return out
