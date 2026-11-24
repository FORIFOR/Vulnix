"""Verify Google-signed ownership tokens; Cloud Run IAM audience is separate."""
from __future__ import annotations

from typing import Mapping

GOOGLE_CERTS_URL = "https://www.googleapis.com/oauth2/v1/certs"
ISSUERS = frozenset({"accounts.google.com", "https://accounts.google.com"})
PROOF_AUDIENCE_PREFIX = "urn:vulnix:cloud-run-proof:"


def verify_google_id_token(token: str, audience: str, *, request=None) -> Mapping:
    """Use google-auth's RSA signature and temporal checks, then enforce identity.

    `request` is injectable solely for offline certificate transport in tests.
    Cloud Run's service invocation audience (its URL) is never accepted here.
    """
    if not isinstance(token, str) or not token or not isinstance(audience, str) or \
            not audience.startswith(PROOF_AUDIENCE_PREFIX):
        raise ValueError("invalid ownership token or audience")
    from google.oauth2 import id_token
    if request is None:
        from google.auth.transport.requests import Request
        request = Request()
    claims = id_token.verify_token(token, request, audience=audience,
                                   certs_url=GOOGLE_CERTS_URL)
    if (not isinstance(claims, Mapping) or claims.get("iss") not in ISSUERS
            or claims.get("aud") != audience
            or not isinstance(claims.get("sub"), str) or not claims["sub"]):
        raise ValueError("invalid Google issuer, audience or subject")
    return claims
