"""What the AI advisor may say, as data: claim levels, verification operations, remediation actions.

The advisor's reply is checked against this catalog first (aegis/ai_advisor.py). A next
check is one of a fixed set of *operation* ids and a remediation step is one of a fixed set
of *fix* ids, each allowed only for the finding rules listed here. Anything else is a
schema error, whatever words it uses, so a dangerous suggestion cannot be phrased into the
result: there is simply no id for "brute force the login" or "scan the subdomains".

None of these ids names a gateway tool or action (http_probe, reproduction_probe,
read_only_probe, safe_reproduction ...); tests/test_ai_advisor.py checks that they stay
disjoint, so an operation id can never be mistaken for something the gateway executes.
"""
from __future__ import annotations

from types import MappingProxyType

ALL_RULES = ("f_l1_tls", "f_l1_no_tls", "f_headers", "f_l1_cookies", "f_l1_cors", "f_powered",
             "f_l1_unauth_api", "f_banner", "f_idor", "f_sqli")

# What the explanation claims about the finding. The verdict decides which are honest.
CLAIM_LEVELS = MappingProxyType({
    "observed": "応答で観測した事実をそのまま述べる",
    "suspected": "可能性を述べる（確かめていない）",
    "inconclusive": "証拠が足りず判断できないと述べる",
    "reproduced": "L2 の再現記録がある",
    "fixed_verified": "修正後の再検証で再現しなかった",
})
CLAIMS_BY_VERDICT = MappingProxyType({
    "detected": frozenset({"observed", "suspected", "inconclusive"}),
    "unverified": frozenset({"suspected", "inconclusive"}),
    "proven": frozenset({"reproduced", "observed"}),
    "not_reproduced": frozenset({"fixed_verified", "inconclusive"}),
    "fixed": frozenset({"fixed_verified", "inconclusive"}),
})

# Input fields an explanation may cite. "cve" and "kev" only when the finding has them.
CITABLE_FIELDS = frozenset({"rule", "category", "severity", "verdict", "verdict_basis", "cve", "risk_score", "kev"})

# level: L1 = one read-only request through the gateway; L2 = human-approved reproduction;
# manual = work for a person, never run by Vulnix.
OPERATIONS = MappingProxyType({
    "l1_recheck_security_headers": ("L1", "セキュリティヘッダーの有無を再確認する", {"f_headers"}),
    "l1_recheck_version_disclosure": ("L1", "バージョン表示が残っているかを再確認する", {"f_powered", "f_banner"}),
    "l1_recheck_tls_config": ("L1", "TLS のプロトコルと暗号スイートを再確認する", {"f_l1_tls"}),
    "l1_recheck_https_redirect": ("L1", "HTTPS での提供と誘導を再確認する", {"f_l1_no_tls"}),
    "l1_recheck_cookie_attributes": ("L1", "Cookie の属性を再確認する", {"f_l1_cookies"}),
    "l1_recheck_cors_policy": ("L1", "信頼しないオリジンへの CORS 応答を再確認する", {"f_l1_cors"}),
    "l1_recheck_unauth_response": ("L1", "未認証の要求への応答を再確認する", {"f_l1_unauth_api"}),
    "l2_authz_boundary_check": ("L2", "テスト用アカウント間の認可境界を確認する", {"f_idor", "f_l1_unauth_api"}),
    "l2_input_boundary_check": ("L2", "模擬データ環境で入力の境界を確認する", {"f_sqli"}),
    "manual_config_review": ("manual", "設定を人が見直す", set(ALL_RULES)),
    "vendor_advisory_review": ("manual", "製品の公開情報（勧告・修正版）を人が確認する", {"f_powered", "f_banner"}),
})

REMEDIATION_ACTIONS = MappingProxyType({
    "set_csp": ("Content-Security-Policy を設定する", {"f_headers"}),
    "set_hsts": ("Strict-Transport-Security を設定する", {"f_headers", "f_l1_no_tls"}),
    "set_xcto_nosniff": ("X-Content-Type-Options: nosniff を設定する", {"f_headers"}),
    "set_frame_ancestors": ("frame-ancestors または X-Frame-Options を設定する", {"f_headers"}),
    "set_referrer_policy": ("Referrer-Policy を設定する", {"f_headers"}),
    "remove_version_headers": ("Server / X-Powered-By からバージョンを外す", {"f_powered", "f_banner"}),
    "upgrade_component": ("製品を保守対象の版に更新する", {"f_powered", "f_banner"}),
    "apply_vendor_patch": ("修正版または回避策を適用する", {"f_banner"}),
    "disable_legacy_tls": ("TLS 1.2 未満を無効にする", {"f_l1_tls"}),
    "restrict_cipher_suites": ("弱い暗号スイートを無効にする", {"f_l1_tls"}),
    "enable_https": ("HTTPS で提供する", {"f_l1_no_tls"}),
    "redirect_http_to_https": ("HTTP から HTTPS へ誘導する", {"f_l1_no_tls"}),
    "set_cookie_secure": ("Cookie に Secure を付ける", {"f_l1_cookies"}),
    "set_cookie_httponly": ("Cookie に HttpOnly を付ける", {"f_l1_cookies"}),
    "set_cookie_samesite": ("Cookie に SameSite を付ける", {"f_l1_cookies"}),
    "restrict_cors_allowlist": ("許可するオリジンを明示的な一覧に限る", {"f_l1_cors"}),
    "disallow_credentials_for_untrusted": ("信頼しないオリジンに資格情報つきの応答を許可しない", {"f_l1_cors"}),
    "require_authentication": ("公開を意図しない API に認証を必須にする", {"f_l1_unauth_api"}),
    "minimize_response_fields": ("返す項目を最小限にする", {"f_l1_unauth_api", "f_idor"}),
    "confirm_intended_exposure": ("公開が意図どおりかを確認する", {"f_l1_unauth_api", "f_powered", "f_l1_cors"}),
    "enforce_object_ownership": ("資源ごとに所有者をサーバー側で照合する", {"f_idor"}),
    "use_unguessable_ids": ("推測しにくい識別子を使う", {"f_idor"}),
    "parameterize_queries": ("パラメータ化クエリを徹底する", {"f_sqli"}),
    "validate_input_server_side": ("入力の型と長さをサーバー側で検証する", {"f_sqli"}),
    "keep_regression_check": ("再発を防ぐ確認を定期的に続ける", set(ALL_RULES)),
})


def operation_allowed(op: str, rule: str) -> bool:
    spec = OPERATIONS.get(op)
    return spec is not None and rule in spec[2]


def action_allowed(action: str, rule: str) -> bool:
    spec = REMEDIATION_ACTIONS.get(action)
    return spec is not None and rule in spec[1]


# Rules whose issue only an L2 reproduction can show: an L1 observation of them is a hint,
# so "observed" would overstate it.
L2_ONLY_RULES = frozenset({"f_idor", "f_sqli"})


def claim_problem(claim: str, rule: str, verdict: str, basis: str) -> str | None:
    if claim not in CLAIMS_BY_VERDICT.get(verdict, ()):
        return f"unfaithful_claim: {claim} is not allowed for verdict {verdict}"
    if claim == "observed" and rule in L2_ONLY_RULES and basis != "l2_reproduction":
        return f"unfaithful_claim: {rule} cannot be observed by L1 alone"
    return None


def fix_verdict_problem(fix: str, verdict: str) -> str | None:
    """Fixes that the verdict alone rules out. After a fix was verified (fixed /
    not_reproduced) only keeping a regression check makes sense; once an L2 reproduction is
    on record, "confirm the exposure is intended" would wave a proven issue away."""
    resolved = verdict in ("fixed", "not_reproduced")
    if fix == "keep_regression_check" and not resolved:
        return "not_allowed_for_verdict: keep_regression_check needs a fixed finding"
    if resolved and fix != "keep_regression_check":
        return f"not_allowed_for_verdict: {fix} after the fix was verified"
    if verdict == "proven" and fix == "confirm_intended_exposure":
        return "not_allowed_for_verdict: a reproduced issue is not an intended exposure"
    return None


def gates_for(level: str) -> tuple[str, ...]:
    """Set by code, never by the model. A manual item is not run by Vulnix at all."""
    if level == "manual":
        return ("manual_only",)
    base = ("ownership_verified", "scope_approved")
    return base + ("l2_human_approval",) if level == "L2" else base


def catalog_for_prompt() -> str:
    """The ids the model may use, for the system prompt (no case data, no labels)."""
    ops = "; ".join(f"{k}({v[0]}: {', '.join(sorted(v[2]))})" for k, v in OPERATIONS.items())
    acts = "; ".join(f"{k}({', '.join(sorted(v[1]))})" for k, v in REMEDIATION_ACTIONS.items())
    claims = ", ".join(f"{v}: {', '.join(sorted(c))}" for v, c in CLAIMS_BY_VERDICT.items())
    return f"operations: {ops}. remediation actions: {acts}. claim_level by verdict: {claims}."
