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
import stat
import urllib.error
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def client_from_file(redirect: str) -> tuple[str, str] | None:
    """(client id, secret) from the web-client JSON downloaded from Google Auth Platform.

    VULNIX_GOOGLE_CLIENT_FILE names it (absolute path, a regular file of this user,
    not a link, readable by nobody else). The secret then never has to be typed,
    pasted or put in an environment variable. The redirect must be one the client lists.
    """
    name = (os.environ.get("VULNIX_GOOGLE_CLIENT_FILE") or "").strip()
    if not name or not os.path.isabs(name):
        return None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077
                    or not 0 < info.st_size <= 16384):
                return None
            web = json.loads(stream.read(16385)).get("web")
        cid, secret, uris = web.get("client_id"), web.get("client_secret"), web.get("redirect_uris")
        if (isinstance(cid, str) and cid and isinstance(secret, str) and secret
                and isinstance(uris, list) and redirect in uris):
            return cid, secret
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    return None


def config() -> dict | None:
    """The OAuth client, from the environment; None when not configured."""
    cid = (os.environ.get("VULNIX_GOOGLE_CLIENT_ID") or "").strip()
    secret = (os.environ.get("VULNIX_GOOGLE_CLIENT_SECRET") or "").strip()
    redirect = (os.environ.get("VULNIX_GOOGLE_REDIRECT_URI") or "").strip()
    if not (cid and secret) and (from_file := client_from_file(redirect)):
        cid, secret = from_file
    try:
        url = urlsplit(redirect)
        if (not cid or not secret or url.scheme != "https" or not url.hostname
                or url.username or url.password or url.path != "/verify/google" or url.query or url.fragment
                or url.port == 0):
            return None
    except ValueError:
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
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as r:
            raw = r.read(1_000_001)
            value = json.loads(raw or b"{}") if len(raw) <= 1_000_000 else None
            if isinstance(value, dict):
                return value
        raise GoogleOwnershipError("Google の応答を確認できませんでした")
    except Exception as e:  # noqa: BLE001 - reported without any token or body
        if isinstance(e, urllib.error.HTTPError):
            e.close()
            if url == TOKEN_URL and e.code == 400:
                raise GoogleOwnershipError("Google の確認が期限切れか無効です。対象画面から確認し直してください") from None
            if url == SITES_URL and e.code == 403:
                raise GoogleOwnershipError("Search Console を参照できません。選んだGoogleアカウントと同意を確認してください") from None
        raise GoogleOwnershipError(f"Google に接続できませんでした（{type(e).__name__}）") from None


def owned_sites(cfg: dict, code: str, verifier: str, *, http: Callable = _http,
                before_request: Callable[[], None] | None = None) -> list[str]:
    """Exchanges the code and returns the site URLs this account is a verified owner of."""
    def request(url, **kwargs):
        if before_request is not None:
            before_request()
        return http(url, **kwargs)

    tok = request(TOKEN_URL, data=urllib.parse.urlencode({
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
        sites = request(SITES_URL, headers={"Authorization": f"Bearer {access}"})
    finally:
        try:      # the token is not needed any more: ask Google to revoke it (best effort)
            request(REVOKE_URL, data=urllib.parse.urlencode({"token": access}).encode(),
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
