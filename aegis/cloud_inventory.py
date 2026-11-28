"""Read-only Google Cloud project discovery. This module grants no Vulnix authority."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .google_ownership import AUTH_URL, TOKEN_URL, STATE_TTL_S, NoRedirect, new_pkce

SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"
PROJECTS_URL = "https://cloudresourcemanager.googleapis.com/v3/projects:search"
CALLBACK = "/verify/cloud"
MAX_PAGES = 3


class CloudInventoryError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def config() -> dict | None:
    client = os.environ.get("VULNIX_CLOUD_CLIENT_ID", "").strip()
    secret = os.environ.get("VULNIX_CLOUD_CLIENT_SECRET", "").strip()
    redirect = os.environ.get("VULNIX_CLOUD_REDIRECT_URI", "").strip()
    if not (client and secret):
        from .google_ownership import client_from_file
        if from_file := client_from_file(redirect):
            client, secret = from_file
    try:
        url = urllib.parse.urlsplit(redirect)
        if (not client or not secret or url.scheme != "https" or not url.hostname
                or url.username or url.password or url.path != CALLBACK or url.query or url.fragment):
            return None
        if url.port == 0:
            return None
    except ValueError:
        return None
    return {"client_id": client, "client_secret": secret, "redirect_uri": redirect}


def _http(url, *, data=None, bearer=None):
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer:
        headers["Authorization"] = "Bearer " + bearer
    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=5) as response:
            payload = response.read(512 * 1024 + 1)
            if len(payload) <= 512 * 1024:
                value = json.loads(payload)
                if isinstance(value, dict):
                    return value
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code == 403 and url.startswith(PROJECTS_URL + "?"):
            raise CloudInventoryError(403, "プロジェクトの一覧を読み取れません。Cloud Resource Manager API の設定と、対象プロジェクトの閲覧権限を管理者に確認してください。") from None
        if code == 400 and url == TOKEN_URL:
            raise CloudInventoryError(400, "Google の確認が期限切れ、または無効です。もう一度接続してください。") from None
    except (OSError, ValueError, TypeError):
        pass
    raise CloudInventoryError(502, "Google Cloud の応答を読み取れませんでした。しばらくしてから再接続してください。")


def fetch_projects(cfg, code, verifier, *, http=None):
    http = http or _http
    data = urllib.parse.urlencode({
        **cfg, "grant_type": "authorization_code", "code": code, "code_verifier": verifier,
    }).encode("ascii")
    token = http(TOKEN_URL, data=data)
    access = token.get("access_token")
    if (not isinstance(access, str) or not re.fullmatch(r"[!-~]{1,4096}", access)
            or str(token.get("token_type", "")).lower() != "bearer"
            or str(token.get("scope", "")).split() != [SCOPE]):
        raise CloudInventoryError(403, "Google Cloud の読み取り専用の同意を確認できませんでした。")

    projects = {}
    cursor = ""
    for _ in range(MAX_PAGES):
        query = urllib.parse.urlencode({
            "pageSize": 100, "query": "state:ACTIVE", "pageToken": cursor,
            "fields": "nextPageToken,projects(name,projectId,displayName,state)",
        })
        result = http(PROJECTS_URL + "?" + query, bearer=access)
        entries = result.get("projects", [])
        if not isinstance(entries, list) or len(entries) > 100:
            raise CloudInventoryError(502, "Google Cloud のプロジェクト一覧を読み取れませんでした。")
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("state") != "ACTIVE":
                continue
            pid, name = entry.get("projectId"), entry.get("name")
            if (not isinstance(pid, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", pid)
                    or not isinstance(name, str) or not re.fullmatch(r"projects/[0-9]{1,24}", name)):
                continue
            label = entry.get("displayName")
            projects[pid] = {"id": pid, "number": name.split("/")[1],
                             "label": label[:120] if isinstance(label, str) else pid}
        cursor = result.get("nextPageToken")
        if not cursor:
            break
        if not isinstance(cursor, str) or len(cursor) > 2048:
            raise CloudInventoryError(502, "Google Cloud の一覧の続きが無効です。")
    return {"projects": list(projects.values()), "incomplete": bool(cursor)}


@dataclass
class Flow:
    at: float
    state: str
    verifier: str | None
    result: dict | None = None


class Inventory:
    def __init__(self):
        self._entries = {}
        self._lock = threading.Lock()

    def _prune(self, now):
        for key in [k for k, v in self._entries.items() if now - v.at >= STATE_TTL_S]:
            del self._entries[key]

    def start(self, owner, cfg):
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            previous = self._entries.get(owner)
            if (previous and now - previous.at < 3) or (not previous and len(self._entries) >= 256):
                raise CloudInventoryError(429, "接続試行が多すぎます。時間をおいて再試行してください。")
            state = secrets.token_urlsafe(32)
            verifier, challenge = new_pkce()
            self._entries[owner] = Flow(now, state, verifier)
        query = urllib.parse.urlencode({
            "client_id": cfg["client_id"], "redirect_uri": cfg["redirect_uri"], "response_type": "code",
            "scope": SCOPE, "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
            "access_type": "online", "include_granted_scopes": "false", "prompt": "select_account",
        })
        return {"url": AUTH_URL + "?" + query}

    def claim(self, owner, state):
        with self._lock:
            self._prune(time.monotonic())
            flow = self._entries.get(owner)
            if flow and flow.verifier and secrets.compare_digest(flow.state, state):
                verifier, flow.verifier = flow.verifier, None
                return flow, verifier
        raise CloudInventoryError(400, "接続の期限切れ、組織の変更、または使用済みの応答です。もう一度接続してください。")

    def publish(self, owner, flow, result):
        with self._lock:
            self._prune(time.monotonic())
            if self._entries.get(owner) is not flow:
                raise CloudInventoryError(409, "接続が取り消されました。")
            flow.result = result

    def get(self, owner):
        with self._lock:
            self._prune(time.monotonic())
            flow = self._entries.get(owner)
            return {"configured": True, **(flow.result if flow and flow.result else {})}

    def clear(self, owner):
        with self._lock:
            self._entries.pop(owner, None)
