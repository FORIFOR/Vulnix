"""Ownership proof through Google Search Console.

A site's owner has usually proven it to Google already. With the user's consent
(OAuth, read-only Search Console scope), Vulnix asks Google which properties this
Google account is a *verified owner* of, and accepts the registered host only when
one of them covers it:

  * a Domain property ``sc-domain:example.com`` covers example.com and every
    sub-domain of it (Google verified it through DNS);
  * a URL-prefix property ``https://shop.example.com/`` covers exactly that scheme
    and host (and port).

Only ``permissionLevel == "siteOwner"`` counts: full or restricted users were
added by an owner and do not prove ownership themselves.

The access token is used once, on the server, and discarded: it is never stored,
logged or sent to the browser. Only Google's endpoints are contacted, never the
site being registered.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import urllib.parse
import urllib.request
from typing import Callable
from urllib.parse import urlsplit

SCOPE = "https://www.googleapis.com/auth/webmasters.readonly"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SITES_URL = "https://www.googleapis.com/webmasters/v3/sites"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"
METHOD = "google_search_console"
STATE_TTL_S = 600
_DEFAULT_PORTS = {"http": 80, "https": 443}


class GoogleOwnershipError(RuntimeError):
    """Google could not be asked (configuration, consent refused, network)."""


def config() -> dict | None:
    """The OAuth client, from the environment; None when not configured."""
    cid = (os.environ.get("VULNIX_GOOGLE_CLIENT_ID") or "").strip()
    secret = (os.environ.get("VULNIX_GOOGLE_CLIENT_SECRET") or "").strip()
    redirect = (os.environ.get("VULNIX_GOOGLE_REDIRECT_URI") or "").strip()
    if not (cid and secret and redirect.startswith("https://")):
        return None
    return {"client_id": cid, "client_secret": secret, "redirect_uri": redirect}


def new_pkce() -> tuple[str, str]:
    """(verifier, S256 challenge)."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def authorization_url(cfg: dict, state: str, code_challenge: str) -> str:
    q = {
        "client_id": cfg["client_id"], "redirect_uri": cfg["redirect_uri"], "response_type": "code",
        "scope": SCOPE, "state": state, "code_challenge": code_challenge, "code_challenge_method": "S256",
        "access_type": "online", "include_granted_scopes": "false", "prompt": "select_account",
    }
    return f"{AUTH_URL}?{urllib.parse.urlencode(q)}"


def _http(url: str, *, data: bytes | None = None, headers: dict | None = None) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data else "GET")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:      # noqa: S310 - fixed Google URLs only
            return json.loads(r.read(1_000_000) or b"{}")
    except Exception as e:  # noqa: BLE001 - reported without any token or body
        raise GoogleOwnershipError(f"Google に接続できませんでした（{type(e).__name__}）") from None


def owned_sites(cfg: dict, code: str, verifier: str, *, http: Callable = _http) -> list[str]:
    """Exchanges the code and returns the site URLs this account is a verified owner of."""
    tok = http(TOKEN_URL, data=urllib.parse.urlencode({
        "code": code, "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
        "redirect_uri": cfg["redirect_uri"], "grant_type": "authorization_code", "code_verifier": verifier,
    }).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
    access = tok.get("access_token") if isinstance(tok, dict) else None
    if not isinstance(access, str) or not access:
        raise GoogleOwnershipError("Google での確認が許可されませんでした")
    granted = str(tok.get("scope") or "")
    if SCOPE not in granted.split():
        raise GoogleOwnershipError("Search Console の参照が許可されませんでした")
    try:
        sites = http(SITES_URL, headers={"Authorization": f"Bearer {access}"})
    finally:
        try:      # the token is not needed any more: ask Google to revoke it (best effort)
            http(REVOKE_URL, data=urllib.parse.urlencode({"token": access}).encode(),
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
        except GoogleOwnershipError:
            pass
        access = ""
    entries = sites.get("siteEntry") if isinstance(sites, dict) else None
    return [str(e.get("siteUrl") or "") for e in (entries or [])
            if isinstance(e, dict) and e.get("permissionLevel") == "siteOwner" and e.get("siteUrl")]


def covering_property(site_urls: list[str], host: str, scheme: str, port: int) -> str | None:
    """The first verified property that covers this host (see the module docstring)."""
    host = host.lower().rstrip(".")
    for site in site_urls:
        if site.startswith("sc-domain:"):
            domain = site[len("sc-domain:"):].lower().rstrip(".")
            # a whole top-level domain is never accepted as one owner's property
            if "." in domain and (host == domain or host.endswith("." + domain)):
                return site
            continue
        try:
            u = urlsplit(site)
            site_port = u.port or _DEFAULT_PORTS.get(u.scheme, 0)
        except ValueError:
            continue
        if u.scheme not in _DEFAULT_PORTS or not u.hostname or u.username or u.password:
            continue
        # only a property for the whole origin: a folder (https://host/~alice/) can be
        # verified by whoever controls that folder, which does not prove the host
        if u.path not in ("", "/") or u.query or u.fragment:
            continue
        if u.scheme == scheme and u.hostname.lower().rstrip(".") == host and site_port == port:
            return site
    return None
