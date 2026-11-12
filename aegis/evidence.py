"""Presentation-only evidence classification. Never grants execution authority."""

EVIDENCE_LABELS = {
    "candidate": "未計測の候補",
    "detected": "検出・未実証",
    "proven": "実証済み",
    "not_reproduced": "再現せず",
    "incomplete": "未完了・要確認",
    "fixture": "架空データ",
}


def l2_reproduction_recorded(finding: dict) -> bool:
    """True only when a recorded L2 run (`reproduction_probe`) is part of the evidence."""
    return any(isinstance(e, dict) and e.get("tool") == "reproduction_probe"
               and e.get("audit_hash") and e.get("saved_at") is not None
               for e in finding.get("evidence") or [])


def enforce_verdict(finding: dict) -> dict:
    """`proven` is reserved for a recorded L2 reproduction.

    A read-only L1 observation (a header, TLS, cookie or CORS check) shows that
    something is configured in a way that may be a weakness; it does not
    reproduce one. Whatever produced it, such a finding is stored and shown as
    `detected`. Demo fixtures are labelled as fixtures and left as they are."""
    if (finding.get("verdict") == "proven" and not finding.get("demo_fixture")
            and not l2_reproduction_recorded(finding)):
        return {**finding, "verdict": "detected", "verdict_basis": "l1_observation"}
    return finding


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
    verdict = enforce_verdict(finding).get("verdict")
    return verdict if verdict in {"detected", "proven", "not_reproduced"} else "incomplete"


def evidence_summary(findings: list[dict]) -> dict:
    counts = dict.fromkeys(EVIDENCE_LABELS, 0)
    for finding in findings:
        counts[evidence_status(finding)] += 1
    return counts


# Built-in checks of the bundled local lab only. Authorization checks against a
# real service are defined by service profiles and judged by `aegis.l2_rules`.
REPRODUCTION_MARKERS = {
    "idor": "VULNIX_LAB_IDOR_PROVEN",
    "sqli": "VULNIX_LAB_SQLI_PROVEN",
    "cve_2021_41773": "VULNIX_LAB_PATH_TRAVERSAL_PROVEN",
}

# HTTP statuses that count as an observed denial in the lab.
REPRODUCTION_DENY_STATUSES = {
    "idor": (403,),
    "sqli": (403,),
    "cve_2021_41773": (403,),
}


def reproduction_verdict(result: dict | None, check: str, rule: dict | None = None,
                         worker_rule: dict | None = None) -> str:
    """Require the observed result and the worker verdict to agree.

    `rule`/`worker_rule` are given for profile-defined L2 checks; those are judged
    by the rule engine (positive controls + status + response content)."""
    import json
    if worker_rule is not None:
        from .l2_rules import evaluate
        return evaluate(worker_rule, result)["verdict"]
    if not result or result.get("check") != check or check not in REPRODUCTION_MARKERS:
        return "unverified"
    if (result.get("status") == 200 and result.get("established") is True
            and result.get("verdict") == "proven"
            and REPRODUCTION_MARKERS[check] in json.dumps(result.get("response"))):
        return "proven"
    if (result.get("status") in REPRODUCTION_DENY_STATUSES[check]
            and result.get("established") is False
            and result.get("verdict") == "not_reproduced"):
        return "not_reproduced"
    return "unverified"


def reproduction_note(result: dict | None, check: str, rule: dict | None = None,
                      worker_rule: dict | None = None) -> str:
    if worker_rule is not None and rule is not None:
        from .l2_rules import evaluate, explain
        return explain(rule, result, evaluate(worker_rule, result))
    verdict = reproduction_verdict(result, check)
    status = (result or {}).get("status", "応答なし")
    if verdict == "proven":
        return f"HTTP {status} 応答に検証用マーカーを確認しました。防御を確認できていません。"
    if verdict == "not_reproduced":
        return f"同じ検証に対して HTTP {status} が返り、今回の条件でアクセスが拒否されたことを確認しました。"
    return f"修正確認できず（HTTP {status}）。応答と判定が不明または一致しないため、再現せずとは判定しません。"
