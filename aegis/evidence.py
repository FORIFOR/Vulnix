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
    "deepnote_idor_notes": "DEEPNOTE_MOCK_NOTE_USER_B",
    "deepnote_share_link": "DEEPNOTE_EXPIRED_SHARE_ACCESSIBLE",
    "deepnote_gcs_acl": "DEEPNOTE_GCS_UNAUTHORIZED_READ",
    "deepnote_ai_chat_isolation": "DEEPNOTE_AI_CROSS_TENANT_CONTEXT",
    "deepnote_billing_plan": "DEEPNOTE_BILLING_BYPASS_PROVEN",
}

# HTTP statuses that count as an observed denial, per check. Deliberately narrow:
# 401 (our own test token was rejected) is never evidence that the boundary holds,
# and 404 only counts where a missing object is a legitimate denial.
REPRODUCTION_DENY_STATUSES = {
    "idor": (403,),
    "sqli": (403,),
    "cve_2021_41773": (403,),
    "deepnote_idor_notes": (403, 404),
    "deepnote_share_link": (403, 404, 410),
    "deepnote_gcs_acl": (403, 404),
    "deepnote_ai_chat_isolation": (403, 404),
    "deepnote_billing_plan": (402, 403),
}

# Checks where "denied" is only meaningful if the resource owner could read the
# same mock resource in the same run (otherwise a wrong path looks like a defense).
OWNER_CONTROL_CHECKS = {
    "deepnote_idor_notes",
    "deepnote_gcs_acl",
    "deepnote_ai_chat_isolation",
}

DEEPNOTE_L2_CHECKS = {c for c in REPRODUCTION_MARKERS if c.startswith("deepnote_")}


def _control_ok(result: dict) -> bool:
    control = result.get("control")
    return (isinstance(control, dict) and control.get("performed") is True
            and control.get("status") == 200 and control.get("ok") is True)


def reproduction_verdict(result: dict | None, check: str) -> str:
    """Require the observed HTTP result and worker verdict to agree."""
    import json
    if not result or result.get("check") != check or check not in REPRODUCTION_MARKERS:
        return "unverified"
    if (result.get("status") == 200 and result.get("established") is True
            and result.get("verdict") == "proven"
            and REPRODUCTION_MARKERS[check] in json.dumps(result.get("response"))):
        return "proven"
    if (result.get("status") in REPRODUCTION_DENY_STATUSES[check]
            and result.get("established") is False
            and result.get("verdict") == "not_reproduced"
            and (check not in OWNER_CONTROL_CHECKS or _control_ok(result))):
        return "not_reproduced"
    return "unverified"


def reproduction_note(result: dict | None, check: str) -> str:
    verdict = reproduction_verdict(result, check)
    status = (result or {}).get("status", "応答なし")
    if verdict == "proven":
        return f"HTTP {status} 応答に検証用マーカーを確認しました。防御を確認できていません。"
    if verdict == "not_reproduced":
        control = "（所有者アカウントでは同じ模擬データを取得できることも同時に確認済み）" if check in OWNER_CONTROL_CHECKS else ""
        return f"同じ検証に対して HTTP {status} が返り、今回の条件でアクセスが拒否されたことを確認しました。{control}"
    if check in OWNER_CONTROL_CHECKS and result and not _control_ok(result) and result.get("established") is not True:
        return (f"判定できず（HTTP {status}）。所有者アカウントで模擬データを取得できなかったため、"
                "拒否応答が防御によるものか、パスやトークンの誤りによるものかを区別できません。再現せずとは判定しません。")
    return f"修正確認できず（HTTP {status}）。応答と判定が不明または一致しないため、再現せずとは判定しません。"
