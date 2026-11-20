"""Deterministic A2B report. Contains no secret value, no request to any host."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .endpoint_inventory import build_inventory, compare_openapi
from .manifest import A2BInputError, UploadRecord
from .risk_mapper import map_risks
from .static_analyzer import scan_apk, scan_source_tree

REPORT_VERSION = "a2b-static/v1"


def analyze_app(*, record: UploadRecord, apk_bytes: bytes | None = None, source_dir: str | Path | None = None,
                openapi: dict | None = None, verified_hosts=(), fingerprint_key: bytes | None = None) -> dict:
    """Static analysis only. `verified_hosts` (hosts that already passed Vulnix's ownership
    verification) changes what a candidate MAY lead to later; it never triggers a request.
    `fingerprint_key` (e.g. a per-organization key) enables keyed secret fingerprints;
    without it only the kind and location of a secret are reported."""
    if (apk_bytes is None) == (source_dir is None):
        raise A2BInputError("APK とソースのどちらか一方を指定してください")
    if apk_bytes is not None:
        if hashlib.sha256(apk_bytes).hexdigest() != record.sha256:
            raise A2BInputError("提出記録とファイルのハッシュが一致しません")
        hints = scan_apk(apk_bytes, fingerprint_key=fingerprint_key)
    else:
        hints = scan_source_tree(source_dir, fingerprint_key=fingerprint_key)
    inv = build_inventory(hints)
    endpoints = inv["endpoints"]
    risks = map_risks(endpoints, auth_hints=hints.auth, verified_hosts=verified_hosts)
    verified = {h.lower() for h in verified_hosts}
    secrets = sorted({(s["kind"], s["location"], s["fingerprint"] or "") for s in hints.secrets})
    body = {
        "version": REPORT_VERSION,
        "app_sha256": record.sha256,
        "endpoints": [e.to_dict() for e in endpoints],
        "owner_hosts": [{"host": h, "ownership_verified": h in verified,
                         "next": ("診断範囲の承認後、既存の読み取り専用L1のみ" if h in verified
                                  else "所有確認（DNS TXT など）が必要。未確認のまま通信しない")}
                        for h in inv["owner_hosts"]],
        "third_party_hosts": inv["third_party_hosts"],
        "auth_hints": sorted(hints.auth),
        "secret_findings": [{"kind": k, "location": loc, "fingerprint_hmac_sha256_12": fp or None,
                             "status": "detected_in_app",
                             "advice_ja": "アプリに埋め込まれた秘密情報は取り出せる前提で扱い、失効・再発行してください。"}
                            for k, loc, fp in secrets],
        "risk_candidates": risks,
        "openapi": compare_openapi(endpoints, openapi) if openapi is not None else None,
        "skipped": sorted(hints.skipped),
        "files_scanned": hints.files_scanned,
        "network_requests": 0,
        "verdict_policy": "静的解析の結果はすべて候補。脆弱と断定しない。",
    }
    digest = hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return {**body, "report_sha256": digest, "upload": record.to_dict()}
