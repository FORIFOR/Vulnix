"""Asset ownership verification (DNS TXT / .well-known file) & scope confirmation.

Implements the beginner-friendly 5-step registration model:
  Step 1: Enter service URL (`https://stg.example.com` or hostname).
  Step 2: Verify ownership via DNS TXT (`_vulnix-verify.<host>`) or verification
          file (`https://<host>/.well-known/vulnix-verify.txt`).
  Step 3: Confirm target scope and prohibited actions (no production data exfil,
          no destructive writes, no DoS, no automatic redirect scope expansion).
  Step 4: Start safe L1 read-only diagnosis (ownership NEVER auto-approves L2).
  Step 5: Review evidence-backed results.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import subprocess
import time
import urllib.request
from typing import Callable
from urllib.parse import urlsplit

PROHIBITED_ACTIONS_SUMMARY = (
    "本番データの取得禁止",
    "他ユーザーへの影響・データ変更・削除禁止",
    "高負荷・DoS送信禁止",
    "リダイレクト先・外部サービスの自動スコープ追加禁止",
    "所有確認のみでのL2侵入実証（再現試験）の自動承認禁止",
)

def parse_service_target(raw_input: str, *, default_lab_port: int = 18081) -> dict:
    """Accept either a full URL (`https://stg.example.com/path`) or a
    hostname (`stg.example.com`) and return normalized target metadata."""
    cleaned = (raw_input or "").strip()
    if not cleaned:
        raise ValueError("有効なサービスURLまたはホスト名を入力してください")
    if "://" not in cleaned:
        is_local = cleaned.lower() in ("lab.test", "api.lab.test", "localhost", "127.0.0.1") or cleaned.lower().endswith(".lab.test")
        cleaned = ("http://" if is_local else "https://") + cleaned
    parts = urlsplit(cleaned)
    if parts.scheme not in ("http", "https"):
        raise ValueError("スキームは https または http のみ指定可能です")
    host = (parts.hostname or "").strip().rstrip(".").lower()
    if not host or len(host) > 180 or " " in host or not re.match(r"^[a-z0-9.-]+$", host):
        raise ValueError("有効な対象ドメインまたはホスト名を入力してください")

    # A real service is identified by a DNS name. IP literals (and all-numeric
    # names that resolvers read as addresses) cannot carry a DNS/TLS ownership
    # proof and would bypass the resolver-side public-address check.
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip or not re.search(r"[a-z]", host.rsplit(".", 1)[-1]):
        raise ValueError("IPアドレスでは登録できません。対象のドメイン名（ホスト名）を入力してください")

    is_lab = host in ("lab.test", "api.lab.test") or host.endswith(".lab.test")
    scheme = "http" if is_lab else parts.scheme
    port = parts.port or (default_lab_port if is_lab else (443 if scheme == "https" else 80))
    service_url = f"{scheme}://{host}" + (f":{port}" if (scheme == "https" and port != 443) or (scheme == "http" and port != 80) else "")
    return {
        "host": host,
        "scheme": scheme,
        "port": int(port),
        "service_url": service_url,
        "target_url": f"{service_url}/",
        "is_local_lab": is_lab,
    }


def challenge_for_host(host: str, salt: str = "vulnix-ownership-v1") -> dict:
    digest = hashlib.sha256(f"{salt}:{host.lower()}".encode("utf-8")).hexdigest()[:24]
    token = f"vulnix-verify={digest}"
    return {
        "token": token,
        "dns_txt_name": f"_vulnix-verify.{host.lower()}",
        "dns_txt_value": token,
        "well_known_url": f"https://{host.lower()}/.well-known/vulnix-verify.txt",
        "well_known_content": token,
    }


def default_dns_txt_lookup(txt_domain: str) -> list[str]:
    try:
        proc = subprocess.run(
            ["nslookup", "-q=txt", txt_domain],
            capture_output=True, text=True, timeout=5,
        )
        return [proc.stdout] if proc.returncode == 0 else []
    except Exception:
        return []


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _require_public_host(host: str) -> None:
    """The control plane itself fetches the proof file, so refuse hosts that
    resolve to loopback / private / link-local / metadata addresses."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as e:
        raise ValueError(f"ホスト名を解決できません: {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise ValueError(f"{host} は公開アドレスに解決されないため、検証ファイルを取得しません")


def default_well_known_fetcher(url: str) -> str:
    _require_public_host(urlsplit(url).hostname or "")
    opener = urllib.request.build_opener(_NoRedirectHandler)
    req = urllib.request.Request(url, headers={"User-Agent": "vulnix-ownership-verifier/1.0"}, method="GET")
    with opener.open(req, timeout=5) as resp:  # pragma: no cover - live network
        if resp.status != 200:
            return ""
        return resp.read(2048).decode("utf-8", "replace")


def verify_ownership_challenge(
    host: str,
    method: str,
    *,
    expected_token: str | None = None,
    txt_lookup: Callable[[str], list[str]] | None = None,
    http_fetcher: Callable[[str], str] | None = None,
) -> dict:
    """Verify domain/service management authority via `dns_txt` or `well_known`."""
    chal = challenge_for_host(host)
    token = expected_token or chal["token"]
    now = time.time()

    if method == "dns_txt":
        lookup = txt_lookup or default_dns_txt_lookup
        records = lookup(chal["dns_txt_name"])
        matched = any(token in r for r in records)
        return {
            "verified": matched,
            "method": "dns_txt",
            "checked_target": chal["dns_txt_name"],
            "expected_token": token,
            "verified_at": now if matched else None,
            "detail": (
                f"DNS TXT ({chal['dns_txt_name']}) で検証トークンを確認しました。"
                if matched
                else f"DNS TXT ({chal['dns_txt_name']}) に検証トークン `{token}` が見つかりませんでした。"
            ),
        }

    if method == "well_known":
        fetcher = http_fetcher or default_well_known_fetcher
        try:
            body = fetcher(chal["well_known_url"])
        except Exception as e:
            return {
                "verified": False,
                "method": "well_known",
                "checked_target": chal["well_known_url"],
                "expected_token": token,
                "verified_at": None,
                "detail": f"検証ファイル ({chal['well_known_url']}) の取得に失敗しました: {e}",
            }
        matched = token in (body or "")
        return {
            "verified": matched,
            "method": "well_known",
            "checked_target": chal["well_known_url"],
            "expected_token": token,
            "verified_at": now if matched else None,
            "detail": (
                f"検証ファイル ({chal['well_known_url']}) で検証トークンを確認しました。"
                if matched
                else f"検証ファイル ({chal['well_known_url']}) の内容に `{token}` が含まれていません。"
            ),
        }

    raise ValueError("method must be dns_txt or well_known")
