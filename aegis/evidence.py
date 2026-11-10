"""Presentation-only evidence classification. Never grants execution authority."""

EVIDENCE_LABELS = {
    "candidate": "未計測の候補",
    "detected": "検出・未実証",
    "proven": "実証済み",
    "not_reproduced": "再現せず",
    "incomplete": "未完了・要確認",
    "fixture": "架空データ",
}


def evidence_status(finding: dict) -> str:
    if finding.get("demo_fixture"):
        return "fixture"
    if finding.get("verdict") in {"aborted", "unverified"}:
        return "incomplete"
    # A pre-populated candidate or unattached example is not a measured finding.
    recorded = any(e.get("audit_hash") and e.get("saved_at") is not None
                   for e in finding.get("evidence", []))
    if not recorded:
        return "candidate"
    verdict = finding.get("verdict")
    return verdict if verdict in {"detected", "proven", "not_reproduced"} else "incomplete"


def evidence_summary(findings: list[dict]) -> dict:
    counts = dict.fromkeys(EVIDENCE_LABELS, 0)
    for finding in findings:
        counts[evidence_status(finding)] += 1
    return counts


REPRODUCTION_MARKERS = {
    "idor": "VULNIX_LAB_IDOR_PROVEN",
    "sqli": "VULNIX_LAB_SQLI_PROVEN",
    "cve_2021_41773": "VULNIX_LAB_PATH_TRAVERSAL_PROVEN",
}


def reproduction_verdict(result: dict | None, check: str) -> str:
    """Require the observed HTTP result and worker verdict to agree."""
    import json
    if not result or result.get("check") != check or check not in REPRODUCTION_MARKERS:
        return "unverified"
    if (result.get("status") == 200 and result.get("established") is True
            and result.get("verdict") == "proven"
            and REPRODUCTION_MARKERS[check] in json.dumps(result.get("response"))):
        return "proven"
    if (result.get("status") == 403 and result.get("established") is False
            and result.get("verdict") == "not_reproduced"):
        return "not_reproduced"
    return "unverified"


def reproduction_note(result: dict | None, check: str) -> str:
    verdict = reproduction_verdict(result, check)
    if verdict == "proven":
        return "ローカル模擬ラボの HTTP 200 応答に検証用マーカーを確認しました。防御を確認できていません。"
    if verdict == "not_reproduced":
        return "同じ検証に対して HTTP 403 が返り、今回の条件でアクセスが拒否されたことを確認しました。"
    status = (result or {}).get("status", "応答なし")
    return f"修正確認できず（HTTP {status}）。応答と判定が不明または一致しないため、再現せずとは判定しません。"
