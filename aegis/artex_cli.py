"""Standalone ARTEX CLI / Subprocess Planner Engine (`python3 -m aegis.artex_cli`).

Integrates the ARTEX phased red-team planning engine as an isolated external
process communicating over JSON stdin/stdout. Like any external planner or LLM,
this process holds zero execution tokens or approval authority; its output is
ingested by `ArtexSubprocessBackend` and sanitized by `ProposalRouter` before
reaching the Gateway.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

ENGINE_NAME = "artex-oss-cli"
ENGINE_VERSION = "1.2.0"


def build_plan(context: dict) -> dict:
    """Generate phased diagnostic and non-destructive reproduction proposals
    from target observations and CVE correlation state."""
    phase = str(context.get("phase", "config"))
    target_id = str(context.get("target_id", "lab"))
    target_url = str(context.get("target_url", "http://lab.test/"))
    proposals: list[dict] = []

    if phase in ("recon", "config"):
        proposals.append({
            "tool": "http_probe",
            "target_id": target_id,
            "action": "read_only_probe",
            "args": {"url": target_url, "method": "GET"},
            "rationale": "ARTEX CLI [Phase 1/Config]: 公開HTTPヘッダー・Serverバナー・セキュリティ設定を非破壊GETで収集",
        })
    elif phase == "verification":
        proposals.append({
            "tool": "reproduction_probe",
            "target_id": target_id,
            "action": "safe_reproduction",
            "args": {"url": target_url, "check": "idor"},
            "rationale": "ARTEX CLI [Phase 2/IDOR]: テストアカウント acct_A から acct_B 保護リソースへの水平権限昇格（IDOR）を実証検証",
        })
        proposals.append({
            "tool": "reproduction_probe",
            "target_id": target_id,
            "action": "safe_reproduction",
            "args": {"url": target_url, "check": "sqli"},
            "rationale": "ARTEX CLI [Phase 2/SQLi]: 検索エンドポイント /api/search のSQL構文解釈境界を非破壊プローブで実証検証",
        })
        if context.get("has_cve_2021_41773", True):
            proposals.append({
                "tool": "reproduction_probe",
                "target_id": target_id,
                "action": "safe_reproduction",
                "args": {"url": target_url, "check": "cve_2021_41773"},
                "rationale": "ARTEX CLI [Phase 2/CVE-2021-41773]: 検出されたパス正規化不備が隔離環境マーカーへ到達するか実証検証",
            })

    return {
        "engine": ENGINE_NAME,
        "engine_version": ENGINE_VERSION,
        "generated_at": time.time(),
        "phase": phase,
        "target_id": target_id,
        "proposals": proposals,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ARTEX External Planner CLI")
    ap.add_argument("--version", action="store_true", help="Print engine version JSON")
    ap.add_argument("--context", type=str, default=None, help="Inline JSON context")
    args = ap.parse_args(argv)

    if args.version:
        sys.stdout.write(json.dumps({"engine": ENGINE_NAME, "version": ENGINE_VERSION}) + "\n")
        return 0

    raw = args.context if args.context is not None else sys.stdin.read()
    try:
        ctx = json.loads(raw) if raw and raw.strip() else {}
        if not isinstance(ctx, dict):
            ctx = {}
    except Exception:
        ctx = {}

    plan = build_plan(ctx)
    sys.stdout.write(json.dumps(plan, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
