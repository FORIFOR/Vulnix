"""Remotion advertisement / demo video JSON exporter.

Produces an anonymized, strictly evidence-backed JSON payload from an
Assessment snapshot and audit log for Remotion video rendering:
- The default (anonymized) export is PUBLISHABLE: it is rebuilt from an allow-list
  (`to_public_export`), so it contains only enum values, numbers, booleans, hex
  digest prefixes and fixed texts from this module - never text copied from the
  assessment (titles, summaries, URLs, model output, target responses).
- `anonymize=False` returns the full, identifying export (role-gated by the API).
- Excludes ``demo_fixture`` / ``fixture`` and unmeasured ``candidate`` findings
  from confirmed findings, clearly distinguishing ``proven`` (L2 reproduction
  confirmed) vs ``detected`` (L1 observation confirmed) vs ``not_reproduced``.
- Includes before/after defense comparisons when executed.
- Emits deterministic UI animation timeline events.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Optional

from .evidence import l2_reproduction_recorded


_URL_HOST_RE = re.compile(r"https?://([^/\s\"':]+)")


_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f:]{1,4}(?![0-9A-Fa-f:])")


def anonymize_text(text: str, host_map: dict[str, str]) -> str:
    if not text:
        return ""
    out = str(text)
    for raw_host, anon_host in sorted(host_map.items(), key=lambda kv: -len(kv[0])):
        if raw_host:
            # case-insensitive, and with an optional :port
            out = re.sub(re.escape(raw_host) + r"(?::\d{1,5})?", anon_host, out, flags=re.IGNORECASE)
    # any IP address literal identifies infrastructure as well
    out = _IPV4.sub("[IPアドレス]", out)
    out = _IPV6.sub("[IPアドレス]", out)
    return out


def build_remotion_export(
    snapshot: dict,
    audit_entries: Optional[list[dict]] = None,
    *,
    anonymize: bool = True,
    display_name: Optional[str] = None,
    secret_redactor: Optional[Callable[[str], str]] = None,
) -> dict:
    """Build a Remotion-ready JSON structure from an assessment snapshot."""
    redact = secret_redactor or (lambda s: s)
    asset_obj = snapshot.get("asset") or {}
    raw_asset_name = str(
        asset_obj.get("name") or snapshot.get("asset_name") or "target.example"
    )
    raw_target_url = str(
        snapshot.get("target_url")
        or asset_obj.get("target_url")
        or f"https://{raw_asset_name}/"
    )

    host_map: dict[str, str] = {}
    if anonymize:
        host_map[raw_asset_name] = "verified-service.example"
        for m in _URL_HOST_RE.finditer(raw_target_url):
            host_map[m.group(1)] = "verified-service.example"
        for f in snapshot.get("findings", []):
            ev_raw = f.get("evidence")
            ev_list = ev_raw if isinstance(ev_raw, list) else ([ev_raw] if isinstance(ev_raw, dict) else [])
            for ev in ev_list:
                t_url = str(ev.get("target_url", ""))
                for m in _URL_HOST_RE.finditer(t_url):
                    host_map.setdefault(m.group(1), "verified-service.example")

    def _clean(val: object) -> str:
        s = redact(str(val or ""))
        return anonymize_text(s, host_map) if anonymize else s

    # Only claim ownership/scope verification when the service recorded it
    # (`is_external_service` is derived from the verified-scope record, not from UI input).
    ownership_confirmed = bool(snapshot.get("is_external_service"))

    safe_display_name = display_name or (
        ("所有確認済みクラウドWebサービス（匿名化済み）"
         if ownership_confirmed
         else "診断対象サービス（匿名化済み）")
        if anonymize
        else raw_asset_name
    )

    # Executed checks from artex_tasks / tasks (excluding unexecuted / unsupported)
    raw_tasks = snapshot.get("artex_tasks") or snapshot.get("tasks") or []
    executed_checks: list[dict] = []
    unsupported_proposals: list[dict] = []
    for idx, task in enumerate(raw_tasks):
        t_status = task.get("status", "pending")
        if t_status == "unsupported":
            unsupported_proposals.append(
                {
                    "id": task.get("id", f"t-{idx}"),
                    "title": _clean(task.get("title", "")),
                    "tool": task.get("tool", ""),
                    "status": "未対応",
                }
            )
        elif t_status in ("completed", "done"):
            executed_checks.append(
                {
                    "id": task.get("id", f"t-{idx}"),
                    "phase": task.get("phase", "L1"),
                    "title": _clean(task.get("title", "")),
                    "tool": task.get("tool", "http_probe"),
                    "status": "completed",
                }
            )

    # Findings: strictly exclude demo_fixture and unmeasured candidate items
    # from confirmed findings.
    confirmed_findings: list[dict] = []
    unverified_candidates: list[dict] = []
    for f in snapshot.get("findings", []):
        if f.get("demo_fixture"):
            continue
        ev_status = f.get("evidence_status") or f.get("verification_status") or "candidate"
        if ev_status == "fixture":
            continue
        if ev_status == "proven" and not l2_reproduction_recorded(f):
            # whatever the snapshot says, an L1 observation is not published (or counted) as proven
            ev_status = "detected"

        ev_raw = f.get("evidence")
        ev_list = ev_raw if isinstance(ev_raw, list) else ([ev_raw] if isinstance(ev_raw, dict) else [])
        latest_ev = ev_list[-1] if ev_list else {}
        rem = f.get("remediation") or {}
        fix_text = f.get("fix") or " / ".join(rem.get("steps", []))

        item = {
            "id": f.get("id"),
            "title": _clean(f.get("title", "")),
            "severity": str(f.get("severity", "medium")).lower(),
            "risk_score": f.get("risk_score"),
            "risk_rationale": _clean(f.get("risk_rationale", "")),
            "verification_status": ev_status,
            "verification_badge": (
                # evidence_status() returns "proven" only with a recorded L2 reproduction
                "実証済み（L2再現確認）"
                if ev_status == "proven"
                else "検出済み（L1観測・実証未実施）"
                if ev_status == "detected"
                else "再現せず（防御有効）"
                if ev_status == "not_reproduced"
                else "未計測の候補（未検証）"
            ),
            "is_reproduction_proven": ev_status == "proven",
            "tool": (f.get("executor") or {}).get("tool") or latest_ev.get("tool", ""),
            "target_url": _clean(latest_ev.get("target_url", raw_target_url)),
            "observed_at": latest_ev.get("saved_at") or latest_ev.get("observed_at", ""),
            "audit_hash": latest_ev.get("audit_hash", ""),
            "impact": _clean(f.get("impact") or f.get("summary", "")),
            "fix": _clean(fix_text),
        }
        if ev_status in ("proven", "detected", "not_reproduced"):
            confirmed_findings.append(item)
        else:
            unverified_candidates.append(item)

    # Before / After defense comparisons
    raw_dc = snapshot.get("defense_comparison") or {}
    before_after_comparisons: list[dict] = []
    if isinstance(raw_dc.get("items"), list):
        for item in raw_dc["items"]:
            after_v = item.get("after_verdict", "unverified")
            before_after_comparisons.append(
                {
                    "check_key": item.get("id"),
                    "title": _clean(item.get("title", "")),
                    "severity": item.get("severity"),
                    "before_status": item.get("before_verdict"),
                    "after_status": after_v,
                    "defense_verified": after_v == "not_reproduced",
                    "latest_evidence_id": item.get("latest_evidence_id"),
                }
            )
    else:
        for key, comp in raw_dc.items():
            if not isinstance(comp, dict):
                continue
            before = comp.get("before") or {}
            after = comp.get("after") or {}
            before_after_comparisons.append(
                {
                    "check_key": key,
                    "defense_verified": bool(comp.get("defense_verified")),
                    "summary": _clean(comp.get("summary", "")),
                    "before_status": before.get("verification_status"),
                    "after_status": after.get("verification_status"),
                }
            )

    # Build UI animation timeline events (at 30fps frames for Remotion)
    timeline_events: list[dict] = []
    frame = 0
    if ownership_confirmed:
        timeline_events.append(
            {
                "frame": frame,
                "duration_frames": 60,
                "scene": "ownership_verified",
                "title": "Step 1-3: 所有確認・スコープ検証完了",
                "subtitle": safe_display_name,
            }
        )
        frame += 60
    for chk in executed_checks[:8]:
        timeline_events.append(
            {
                "frame": frame,
                "duration_frames": 45,
                "scene": "check_execution",
                "phase": chk["phase"],
                "title": chk["title"],
                "tool": chk["tool"],
            }
        )
        frame += 45
    for cf in confirmed_findings:
        timeline_events.append(
            {
                "frame": frame,
                "duration_frames": 60,
                "scene": "finding_card",
                "finding_id": cf["id"],
                "title": cf["title"],
                "severity": cf["severity"],
                "verification_status": cf["verification_status"],
                "verification_badge": cf["verification_badge"],
                "audit_hash": str(cf["audit_hash"])[:16] if cf["audit_hash"] else "",
            }
        )
        frame += 60
    for cmp_item in before_after_comparisons:
        timeline_events.append(
            {
                "frame": frame,
                "duration_frames": 75,
                "scene": "before_after_comparison",
                "check_key": cmp_item["check_key"],
                "before_status": cmp_item["before_status"],
                "after_status": cmp_item["after_status"],
                "defense_verified": cmp_item["defense_verified"],
            }
        )
        frame += 75

    payload = {
        "schema_version": "vulnix-remotion-v1",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "anonymized": anonymize,
        "service": {
            "display_name": safe_display_name,
            "target_url": _clean(raw_target_url),
            "ownership_and_scope_confirmed": ownership_confirmed,
            "local_lab_demo": bool(snapshot.get("demo")),
            "state": snapshot.get("state", "idle"),
            "risk": snapshot.get("risk"),
        },
        "summary": {
            "executed_checks_count": len(executed_checks),
            "confirmed_findings_count": len(confirmed_findings),
            "proven_count": sum(
                1 for f in confirmed_findings if f["verification_status"] == "proven"
            ),
            "detected_count": sum(
                1 for f in confirmed_findings if f["verification_status"] == "detected"
            ),
            "not_reproduced_count": sum(
                1
                for f in confirmed_findings
                if f["verification_status"] == "not_reproduced"
            ),
            "unverified_candidate_count": len(unverified_candidates),
            "unsupported_ai_proposals_count": len(unsupported_proposals),
            "fictional_or_unmeasured_excluded": True,
        },
        "executed_checks": executed_checks,
        "confirmed_findings": confirmed_findings,
        "unverified_candidates": unverified_candidates,
        "unsupported_proposals": unsupported_proposals,
        "before_after_comparisons": before_after_comparisons,
        "remotion_timeline": {
            "fps": 30,
            "total_frames": max(frame, 90),
            "events": timeline_events,
        },
    }
    # The anonymized export is meant to be published. It is not "the full export
    # with names scrubbed": it is rebuilt from an allow-list, so a field or a text
    # that nobody decided to publish cannot be in it.
    return to_public_export(payload) if anonymize else payload


# --------------------------------------------------------------------------
# Public (publishable) export: allow-list only
# --------------------------------------------------------------------------
PUBLIC_SERVICE_NAME = "所有確認済みクラウドWebサービス（匿名化済み）"
PUBLIC_LAB_NAME = "診断対象サービス（匿名化済み）"
PUBLIC_TARGET_URL = "https://verified-service.example/"
WITHHELD = "[非公開]"

_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STATUSES = ("proven", "detected", "not_reproduced", "candidate", "incomplete", "unverified")
_STATES = ("idle", "running", "paused", "completed", "stopped", "failed")
_PHASES = ("scope", "config", "analysis", "verification", "report", "L1", "L2")
_TOOLS = {"http_probe": "読み取り専用のHTTP検査", "reproduction_probe": "承認制の再現検証",
          "demo_verify": "模擬検証", "cve_engine": "既知脆弱性の照合"}
_RISK_LABELS = ("高リスク", "中リスク", "低リスク")

# Text is never copied from a finding. It comes from this table, keyed by the
# built-in finding id; anything else gets a generic label by level.
PUBLIC_FINDING_TEXT = {
    "f_headers": ("セキュリティヘッダーの未設定", "ブラウザ側の防御が働かず、攻撃の影響が大きくなるおそれがあります。",
                  "不足しているセキュリティヘッダーを設定します。"),
    "f_l1_cookies": ("Cookie の保護属性の不足", "Cookie が盗み見や不正な送信に使われるおそれがあります。",
                     "Secure・HttpOnly・SameSite を設定します。"),
    "f_l1_cors": ("CORS 設定の過剰な許可", "信頼していないサイトから応答を読み取られるおそれがあります。",
                  "許可するオリジンを信頼できるものだけに限定します。"),
    "f_powered": ("製品名・バージョン情報の露出", "既知の脆弱性を探す手がかりを与えます。",
                  "応答ヘッダーから製品名とバージョンを取り除きます。"),
    "f_l1_unauth_api": ("認証なしで応答するAPIの可能性", "認証が必要なデータが公開されているおそれがあります。",
                        "APIの認証・認可の設定を確認します。"),
    "f_l1_tls": ("旧世代のTLSプロトコル", "通信内容を解読されるおそれがあります。", "TLS 1.2 以上だけを許可します。"),
    "f_l1_no_tls": ("HTTPS 未使用", "通信内容を読み取られ、改ざんされるおそれがあります。", "すべての通信を HTTPS で提供します。"),
    "f_banner": ("既知の脆弱性に該当する可能性のあるバージョン", "公開済みの攻撃手法の対象になるおそれがあります。",
                 "修正済みのバージョンへ更新します。"),
    "f_idor": ("他ユーザーのデータへのアクセス制御（IDOR）", "他の利用者のデータを閲覧されるおそれがあります。",
               "サーバー側でデータの所有者を照合します。"),
    "f_sqli": ("入力値の検証不備（SQLインジェクション）", "データベースの内容を読み取られるおそれがあります。",
               "プレースホルダを使ってクエリを組み立てます。"),
}
_GENERIC_L2 = ("認可・アクセス制御の検証項目", "権限のない利用者にデータや機能が開放されるおそれがあります。",
               "サーバー側で権限を照合します。")
_GENERIC = ("検出事項", WITHHELD, WITHHELD)

_BADGES = {
    ("proven", True): "実証済み（L2再現確認）",
    # no ("proven", False): an L1 observation is never shown as proven (see finding())
    ("detected", False): "検出済み（L1観測・実証未実施）", ("detected", True): "検出済み（L1観測・実証未実施）",
    ("not_reproduced", False): "再現せず（防御有効）", ("not_reproduced", True): "再現せず（防御有効）",
}
_HEX = re.compile(r"[0-9a-f]{1,64}")


def _enum(value, allowed, default):
    return value if isinstance(value, str) and value in allowed else default


def _score(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value or value in (
            float("inf"), float("-inf")):
        return None
    return max(0, min(100, int(value)))


def _hash16(value) -> str:
    """The first 16 hex digits of a full SHA-256 digest - and nothing shorter or
    other-shaped (a port number or a timestamp is also 'hex')."""
    v = value.lower() if isinstance(value, str) else ""
    return v[:16] if re.fullmatch(r"[0-9a-f]{64}", v) else ""


MAX_PUBLIC_ITEMS = 200


def _dicts(value) -> list[dict]:
    return [x for x in value if isinstance(x, dict)][:MAX_PUBLIC_ITEMS] if isinstance(value, list) else []


def to_public_export(full: dict) -> dict:
    """Rebuild the export from an allow-list. Every string in the result is a
    constant from this module, an enum value, or a hex digest prefix; every other
    value is a number or a boolean. Identifiers are replaced by neutral ones."""
    ids: dict[str, str] = {}

    def neutral(raw) -> str:
        return ids.setdefault(str(raw), f"finding-{len(ids) + 1}")

    def finding(f: dict) -> dict:
        status = _enum(f.get("verification_status"), _STATUSES, "candidate")
        is_l2 = "L2" in str(f.get("verification_badge", "")) or str(f.get("tool")) == "reproduction_probe"
        if status == "proven" and not is_l2:
            status = "detected"          # only an L2 reproduction is published as proven
        title, impact, fix = PUBLIC_FINDING_TEXT.get(str(f.get("id")), _GENERIC_L2 if is_l2 else _GENERIC)
        return {
            "id": neutral(f.get("id")),
            "title": title,
            "severity": _enum(f.get("severity"), _SEVERITIES, "medium"),
            "risk_score": _score(f.get("risk_score")),
            "verification_status": status,
            "verification_badge": _BADGES.get((status, is_l2), "未計測の候補（未検証）"),
            "is_reproduction_proven": status == "proven",
            "tool": _enum(f.get("tool"), tuple(_TOOLS), "other"),
            "target_url": PUBLIC_TARGET_URL,
            "audit_hash": _hash16(f.get("audit_hash")),
            "impact": impact,
            "fix": fix,
        }

    confirmed = [finding(f) for f in _dicts(full.get("confirmed_findings"))]
    candidates = [finding(f) for f in _dicts(full.get("unverified_candidates"))]
    checks = [{
        "id": f"check-{i + 1}",
        "phase": _enum(c.get("phase"), _PHASES, "L1"),
        "title": _TOOLS.get(str(c.get("tool")), "検査"),
        "tool": _enum(c.get("tool"), tuple(_TOOLS), "other"),
        "status": "completed",
    } for i, c in enumerate(_dicts(full.get("executed_checks")))]
    comparisons = [{
        "check_key": neutral(c.get("check_key")),
        "before_status": _enum(c.get("before_status"), _STATUSES, "unverified"),
        "after_status": _enum(c.get("after_status"), _STATUSES, "unverified"),
        "defense_verified": c.get("defense_verified") is True,
    } for c in _dicts(full.get("before_after_comparisons"))]

    svc = full.get("service") if isinstance(full.get("service"), dict) else {}
    ownership = svc.get("ownership_and_scope_confirmed") is True
    name = PUBLIC_SERVICE_NAME if ownership else PUBLIC_LAB_NAME
    risk = svc.get("risk") if isinstance(svc.get("risk"), dict) else {}

    events, frame = [], 0
    if ownership:
        events.append({"frame": frame, "duration_frames": 60, "scene": "ownership_verified",
                       "title": "Step 1-3: 所有確認・スコープ検証完了", "subtitle": name})
        frame += 60
    for c in checks[:8]:
        events.append({"frame": frame, "duration_frames": 45, "scene": "check_execution",
                       "phase": c["phase"], "title": c["title"], "tool": c["tool"]})
        frame += 45
    for f in confirmed:
        events.append({"frame": frame, "duration_frames": 60, "scene": "finding_card", "finding_id": f["id"],
                       "title": f["title"], "severity": f["severity"],
                       "verification_status": f["verification_status"],
                       "verification_badge": f["verification_badge"], "audit_hash": f["audit_hash"]})
        frame += 60
    for c in comparisons:
        events.append({"frame": frame, "duration_frames": 75, "scene": "before_after_comparison", **c})
        frame += 75

    summary = full.get("summary") if isinstance(full.get("summary"), dict) else {}
    return {
        "schema_version": "vulnix-remotion-v1",
        "anonymized": True,
        "service": {
            "display_name": name,
            "target_url": PUBLIC_TARGET_URL,
            "ownership_and_scope_confirmed": ownership,
            "local_lab_demo": svc.get("local_lab_demo") is True,
            "state": _enum(svc.get("state"), _STATES, "idle"),
            "risk": {"score": _score(risk.get("score")),
                     "label": _enum(risk.get("label"), _RISK_LABELS, WITHHELD),
                     "provisional": risk.get("provisional") is True},
        },
        "summary": {
            "executed_checks_count": len(checks),
            "confirmed_findings_count": len(confirmed),
            "proven_count": sum(1 for f in confirmed if f["verification_status"] == "proven"),
            "detected_count": sum(1 for f in confirmed if f["verification_status"] == "detected"),
            "not_reproduced_count": sum(1 for f in confirmed if f["verification_status"] == "not_reproduced"),
            "unverified_candidate_count": len(candidates),
            "unsupported_ai_proposals_count": _score(summary.get("unsupported_ai_proposals_count")) or 0,
            "fictional_or_unmeasured_excluded": True,
        },
        "executed_checks": checks,
        "confirmed_findings": confirmed,
        "unverified_candidates": candidates,
        "before_after_comparisons": comparisons,
        "remotion_timeline": {"fps": 30, "total_frames": max(frame, 90), "events": events},
    }


def public_strings() -> set[str]:
    """Every string the public export may contain (besides neutral ids and hex digests)."""
    out = {"vulnix-remotion-v1", PUBLIC_SERVICE_NAME, PUBLIC_LAB_NAME, PUBLIC_TARGET_URL, WITHHELD, "completed",
           "other", "検査", "未計測の候補（未検証）", "Step 1-3: 所有確認・スコープ検証完了",
           "ownership_verified", "check_execution", "finding_card", "before_after_comparison"}
    out.update(_SEVERITIES, _STATUSES, _STATES, _PHASES, _RISK_LABELS, _TOOLS, _TOOLS.values(), _BADGES.values())
    for triple in (*PUBLIC_FINDING_TEXT.values(), _GENERIC_L2, _GENERIC):
        out.update(triple)
    return out
