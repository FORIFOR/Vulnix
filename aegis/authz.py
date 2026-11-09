"""Layer 1 Authorization: engagements, human approvals, short-lived execution tokens.

Tokens are HMAC-signed with a server-side secret that never reaches the model.
They bind engagement, target, action, tool, approval and expiry, are single-use,
and are invalidated wholesale when the emergency stop bumps the epoch.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass, field


class AuthzError(Exception):
    pass


@dataclass(frozen=True)
class Target:
    id: str
    hosts: tuple[str, ...]          # exact hostnames permitted
    cidrs: tuple[str, ...]          # every resolved IP must fall in one of these
    ports: tuple[int, ...]


@dataclass(frozen=True)
class Engagement:
    id: str
    ownership_verified: bool
    authorization_ref: str          # reference to the signed written authorization
    not_before: float
    not_after: float
    targets: dict[str, Target]
    allowed_actions: frozenset[str]

    def check_active(self, now: float) -> None:
        if not self.ownership_verified:
            raise AuthzError("ownership not verified")
        if not self.authorization_ref:
            raise AuthzError("no written authorization on file")
        if not (self.not_before <= now < self.not_after):
            raise AuthzError("engagement outside authorized window")


@dataclass
class ApprovalStore:
    """Approvals are recorded by humans via the control plane, never by the model."""
    _approvals: dict[str, tuple[str, str, str, str]] = field(default_factory=dict)

    def approve(self, approver: str, engagement_id: str, target_id: str, action: str) -> str:
        approval_id = "apr_" + secrets.token_hex(8)
        self._approvals[approval_id] = (approver, engagement_id, target_id, action)
        return approval_id

    def check(self, approval_id: str, engagement_id: str, target_id: str, action: str) -> None:
        rec = self._approvals.get(approval_id)
        if rec is None or rec[1:] != (engagement_id, target_id, action):
            raise AuthzError("no matching human approval")


class TokenAuthority:
    def __init__(self, secret: bytes, clock):
        if len(secret) < 32:
            raise ValueError("secret must be >= 32 bytes")
        self._secret = secret
        self._clock = clock
        self._lock = threading.Lock()
        self._epoch = 0
        self._revoked: set[str] = set()
        self._consumed: set[str] = set()

    def issue(self, engagement: Engagement, target_id: str, action: str, tool: str,
              approval_id: str, approvals: ApprovalStore, ttl: float = 300) -> str:
        now = self._clock()
        engagement.check_active(now)
        if target_id not in engagement.targets:
            raise AuthzError("target not in engagement")
        if action not in engagement.allowed_actions:
            raise AuthzError("action not allowed by engagement")
        approvals.check(approval_id, engagement.id, target_id, action)
        claims = {
            "jti": secrets.token_hex(16), "eng": engagement.id, "tgt": target_id,
            "act": action, "tool": tool, "apr": approval_id, "epoch": self._epoch,
            "iat": now, "exp": min(now + ttl, engagement.not_after),
        }
        payload = _b64(json.dumps(claims, sort_keys=True).encode())
        return payload + "." + _b64(self._sign(payload))

    def verify(self, token: str) -> dict:
        try:
            payload, sig = token.split(".")
            if not hmac.compare_digest(_unb64(sig), self._sign(payload)):
                raise AuthzError("bad signature")
            claims = json.loads(_unb64(payload))
        except AuthzError:
            raise
        except Exception as e:
            raise AuthzError("malformed token") from e
        with self._lock:
            if claims["epoch"] != self._epoch:
                raise AuthzError("token epoch revoked")
            if claims["jti"] in self._revoked:
                raise AuthzError("token revoked")
            if claims["jti"] in self._consumed:
                raise AuthzError("token already used")
        if self._clock() >= claims["exp"]:
            raise AuthzError("token expired")
        return claims

    def consume(self, jti: str) -> None:
        """Atomic single-use: the second caller with the same token loses."""
        with self._lock:
            if jti in self._consumed or jti in self._revoked:
                raise AuthzError("token already used")
            self._consumed.add(jti)

    def revoke(self, jti: str) -> None:
        with self._lock:
            self._revoked.add(jti)

    def revoke_all(self) -> None:
        with self._lock:
            self._epoch += 1

    def _sign(self, payload: str) -> bytes:
        return hmac.new(self._secret, payload.encode(), hashlib.sha256).digest()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
