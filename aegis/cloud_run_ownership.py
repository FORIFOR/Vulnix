"""Fail-closed Cloud Run OIDC ownership challenge validation.

The SQLite store binds the registered subject, host, tenant and requester. This
module grants no scope; AssessmentService commits a signed proof afterward.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
from typing import Callable, Mapping

from .ownership import default_well_known_fetcher, meta_tag_matches, parse_service_target
from .cloud_run_store import ChallengeStore

CHALLENGE_TTL_S = 300
GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})


class CloudRunProof:
    """Bind a one-use challenge to the current tenant, host, user and OIDC sub.

    verify_id_token(token, audience) verifies the JWT signature against trusted
    Google keys before returning claims. The host fetcher must use HTTPS
    443, certificate verification, a pinned public address and no redirects;
    the default ownership fetcher has those properties.
    """

    def __init__(
        self,
        *,
        store: ChallengeStore,
        verify_id_token: Callable[[str, str], Mapping],
        fetch_html: Callable[[str], str] | None = None,
        now: Callable[[], float] = time.time,
        new_challenge: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ):
        self._store = store
        self._verify_id_token = verify_id_token
        self._fetch_html = fetch_html or default_well_known_fetcher
        self._now = now
        self._new_challenge = new_challenge

    @staticmethod
    def _host(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError("host must be a string")
        target = parse_service_target(value)
        if target["is_local_lab"] or (target["scheme"], target["port"]) != ("https", 443):
            raise ValueError("Cloud Run proof requires a registered HTTPS 443 host")
        return target["host"]

    def issue(self, tenant: str, host: str, requester: str) -> dict:
        if not tenant or not requester:
            raise ValueError("tenant and requester are required")
        host = self._host(host)
        binding = self._store.binding(tenant, host)
        if not binding:
            raise ValueError("host and OIDC subject must be registered for this tenant")
        challenge = self._new_challenge()
        if not isinstance(challenge, str) or len(challenge) < 32:
            raise ValueError("challenge entropy is insufficient")
        audience_hash = hashlib.sha256(
            json.dumps([tenant, host, challenge], separators=(",", ":")).encode()).hexdigest()
        audience = f"urn:vulnix:cloud-run-proof:{audience_hash}"
        issued_at = self._now()
        self._store.issue(challenge, tenant, host, requester, audience,
                          binding[1], issued_at, issued_at + CHALLENGE_TTL_S)
        return {
            "challenge": challenge, "audience": audience,
            "proof_token": f"vulnix-cloud-run={challenge}",
            "host_url": f"https://{host}/", "expires_at": issued_at + CHALLENGE_TTL_S,
        }

    def finish(self, *, challenge: str, tenant: str, host: str,
               requester: str, id_token: str) -> bool:
        # The caller first authenticates the requester and checks organization
        # membership. Wrong requester/host/tenant must not spend someone else's proof.
        if not isinstance(challenge, str) or not isinstance(tenant, str) or not isinstance(requester, str):
            return False
        try:
            host = self._host(host)
        except (ValueError, TypeError):
            return False
        try:
            binding = self._store.binding(tenant, host)
        except Exception:
            return False
        if not binding:
            return False
        try:
            pending = self._store.consume(challenge, tenant, host, requester, binding[1], self._now())
        except Exception:
            return False
        if pending is None:
            return False
        if not isinstance(id_token, str) or not id_token:
            return False
        try:
            claims = self._verify_id_token(id_token, pending["audience"])
            now = self._now()
            if not isinstance(claims, Mapping):
                return False
            iat, exp = claims.get("iat"), claims.get("exp")
            if (claims.get("iss") not in GOOGLE_ISSUERS
                    or claims.get("aud") != pending["audience"]
                    or claims.get("sub") != binding[0]
                    or not isinstance(iat, (int, float)) or isinstance(iat, bool)
                    or not isinstance(exp, (int, float)) or isinstance(exp, bool)
                    or not math.isfinite(iat) or not math.isfinite(exp)
                    or iat > now + 60 or exp <= now or iat >= exp):
                return False
            html = self._fetch_html(f"https://{host}/")
            return (self._now() <= pending["expires_at"]
                    and self._store.binding(tenant, host) == binding
                    and meta_tag_matches(html, f"vulnix-cloud-run={challenge}"))
        except Exception:
            return False
