"""Remotion advertisement / demo video JSON exporter.

Produces an anonymized, strictly evidence-backed JSON payload from an
Assessment snapshot and audit log for Remotion video rendering:
- Anonymizes target hostnames and URLs by default.
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


_URL_HOST_RE = re.compile(r"https?://([^/\s\"':]+)")


def anonymize_text(text: str, host_map: dict[str, str]) -> str:
    if not text:
        return ""
    out = str(text)
    for raw_host, anon_host in sorted(host_map.items(), key=lambda kv: -len(kv[0])):
        if raw_host:
            out = out.replace(raw_host, anon_host)
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

    return {
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
