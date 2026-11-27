"""Verdict and note for the lab open-redirect check (kept apart from the frozen evidence judge)."""
from __future__ import annotations

from urllib.parse import urljoin, urlsplit

from .workers.redirect_probe import PROOF_HOST, REDIRECT_PATH, REDIRECT_STATUSES, REDIRECT_VARIANTS

_BASE = "http://lab.invalid/"


def _host(location) -> str | None:
    return urlsplit(urljoin(_BASE, str(location).replace("\\", "/"))).hostname


def open_redirect_verdict(result: dict | None) -> str:
    """Proven only when a real 3xx sent the browser to the proof host while the same-site
    control worked; not reproduced only when both attack values stayed on the site."""
    if (not result or result.get("check") != "open_redirect" or result.get("request_path") != REDIRECT_PATH
            or result.get("control_verified") is not True):
        return "unverified"
    if (result.get("verdict") == "proven" and result.get("established") is True
            and result.get("status") in REDIRECT_STATUSES and _host(result.get("location", "")) == PROOF_HOST):
        return "proven"
    variants = result.get("variants") or []
    if (result.get("verdict") == "not_reproduced" and result.get("established") is False
            and sorted(str(v.get("target")) for v in variants) == sorted(REDIRECT_VARIANTS)
            and all(v.get("status") in REDIRECT_STATUSES and _host(v.get("location", "")) == "lab.invalid"
                    for v in variants)):
        return "not_reproduced"
    return "unverified"


def open_redirect_note(result: dict | None) -> str:
    verdict = open_redirect_verdict(result)
    status = (result or {}).get("status", "応答なし")
    if verdict == "proven":
        return (f"HTTP {status} の Location が外部の検証用ホスト（{(result or {}).get('location', '')}）を指しました。"
                "利用者を任意のサイトへ移動させられます（リダイレクトは追跡していません）。")
    if verdict == "not_reproduced":
        return f"絶対URLと // で始まるURLの両方で、HTTP {status} の移動先が同じサイト内に留まりました。"
    return f"修正確認できず（HTTP {status}）。対照の移動が成立しないか、移動先を判定できませんでした。"
