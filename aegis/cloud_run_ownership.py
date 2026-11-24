"""A fail-closed, offline-testable Cloud Run OIDC ownership proof primitive.

The caller must supply a signature-verifying Google ID-token verifier and an
authoritative tenant/host -> service-account-subject binding. This module does
not grant diagnostic scope; AssessmentService must make that decision after a
proof succeeds. No API route enables this unfinished integration.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from typing import Callable, Mapping

from .ownership import default_well_known_fetcher, meta_tag_matches, parse_service_target

CHALLENGE_TTL_S = 300
GOOGLE_ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})


class CloudRunProof:
    """Bind a one-use challenge to the current tenant, host, user and OIDC sub.

    verify_id_token(token, audience) must verify the JWT signature against
    trusted Google keys before returning claims. The host fetcher must use HTTPS
    443, certificate verification, a pinned public address and no redirects;
    the default ownership fetcher has those properties.
    """

    def __init__(
        self,
        *,
        registered_subject: Callable[[str, str], str | None],
        verify_id_token: Callable[[str, str], Mapping],
        fetch_html: Callable[[str], str] = default_well_known_fetcher,
        now: Callable[[], float] = time.time,
        new_challenge: Callable[[], str] = lambda: secrets.token_urlsafe(32),
    ):
        self._registered_subject = registered_subject
        self._verify_id_token = verify_id_token
        self._fetch_html = fetch_html
        self._now = now
        self._new_challenge = new_challenge
        self._pending: dict[str, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _host(value: str) -> str:
        target = parse_service_target(value)
        if target["is_local_lab"] or (target["scheme"], target["port"]) != ("https", 443):
            raise ValueError("Cloud Run proof requires a registered HTTPS 443 host")
        return target["host"]

    def issue(self, tenant: str, host: str, requester: str) -> dict:
        if not tenant or not requester:
            raise ValueError("tenant and requester are required")
        host = self._host(host)
        subject = self._registered_subject(tenant, host)
        if not isinstance(subject, str) or not subject:
            raise ValueError("host and OIDC subject must be registered for this tenant")
        challenge = self._new_challenge()
        if not isinstance(challenge, str) or len(challenge) < 32:
            raise ValueError("challenge entropy is insufficient")
        audience_hash = hashlib.sha256(
            json.dumps([tenant, host, challenge], separators=(",", ":")).encode()).hexdigest()
        audience = f"urn:vulnix:cloud-run-proof:{audience_hash}"
        issued_at = self._now()
        with self._lock:
            if challenge in self._pending:
                raise ValueError("challenge collision")
            self._pending[challenge] = {
                "tenant": tenant, "host": host, "requester": requester,
                "subject": subject, "audience": audience,
                "expires_at": issued_at + CHALLENGE_TTL_S,
            }
        return {
            "challenge": challenge, "audience": audience,
            "proof_token": f"vulnix-cloud-run={challenge}",
            "host_url": f"https://{host}/", "expires_at": issued_at + CHALLENGE_TTL_S,
        }

    def finish(self, *, challenge: str, tenant: str, host: str,
               requester: str, id_token: str) -> bool:
        # Consume before any callback or network access. All failures, including
        # a verifier exception, spend the challenge and cannot be retried.
        with self._lock:
            pending = self._pending.pop(challenge, None)
        if pending is None or self._now() > pending["expires_at"]:
            return False
        try:
            host = self._host(host)
        except ValueError:
            return False
        if ((tenant, host, requester) !=
                (pending["tenant"], pending["host"], pending["requester"])):
            return False
        if self._registered_subject(tenant, host) != pending["subject"]:
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
                    or claims.get("sub") != pending["subject"]
                    or not isinstance(iat, (int, float)) or isinstance(iat, bool)
                    or not isinstance(exp, (int, float)) or isinstance(exp, bool)
                    or iat > now + 60 or exp <= now or iat >= exp):
                return False
            html = self._fetch_html(f"https://{host}/")
            return (self._now() <= pending["expires_at"]
                    and self._registered_subject(tenant, host) == pending["subject"]
                    and meta_tag_matches(html, f"vulnix-cloud-run={challenge}"))
        except Exception:
            return False
