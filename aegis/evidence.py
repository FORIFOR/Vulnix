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
