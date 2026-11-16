"""Real-service (external HTTPS) L1 & L2 diagnostic analyzers.

Implements:
- L1 read-only HTTP/TLS inspection (TLS certificate & HTTPS, HSTS/CSP/XCTO,
  Cookie flags, CORS configuration, exposed technology headers, unauthenticated
  API access control, and NVD/CISA KEV correlation).
- L2 candidate generation from the asset's service profile
  (`aegis/l2_profiles/*.json`, see `aegis/l2_rules.py`), gated on human
  approval + encrypted test credentials. Nothing service-specific lives here.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Optional
import urllib.parse

from . import cve


EXECUTOR_DEFAULT = {
    "agent": "Vulnix 診断エンジン",
    "model": "内蔵の検査ルール（実行権限なし）",
}


def _auth_error_only(res: dict, headers_lower: dict[str, str]) -> bool:
    """Recognize a complete 200 JSON denial, not a protected data response."""
    body = res.get("body_prefix")
    length = headers_lower.get("content-length", "")
    if not isinstance(body, str):
        return False
    body_size = len(body.encode("utf-8"))
    if length:
        complete = len(length) <= 10 and length.isdecimal() and int(length) == body_size
    else:
        # http_probe.read(4096) returns a short body only at HTTP EOF.
        complete = body_size < 4096
    if not complete:
        return False
    try:
        payload = json.loads(body)
    except (ValueError, TypeError):
        return False
    if not isinstance(payload, dict) or set(payload) not in ({"error"}, {"message"}, {"error", "code"}):
        return False
    if "code" in payload and payload["code"] != "AUTH_REQUIRED":
        return False
    value = payload.get("error", payload.get("message"))
    return isinstance(value, str) and value.strip().casefold() in {
        "authentication required", "unauthorized", "login required", "sign in required",
        "認証が必要です", "ログインが必要です",
    }


SEVERITY_BASE_SCORE = {"critical": 90, "high": 75, "medium": 50, "low": 25}


def analyze_status_marker_report(report: dict, evidence: dict) -> dict:
    """Turn one audited fixed Worker report into an L1 finding."""
    if (report.get("check_id") != "apache_mod_status"
            or type(report.get("detected")) is not bool
            or not isinstance(evidence.get("audit_hash"), str)
            or evidence.get("tool") != "status_marker"):
        raise ValueError("status marker result has no auditable fixed verdict")
    detected = report["detected"]
    verdict = "detected" if detected else "not_reproduced"
    score, rationale = compute_finding_risk_score("medium", verdict)
    return {
        "id": "f_l1_apache_mod_status",
        "title": ("Apache mod_status の公開露出" if detected
                  else "Apache mod_status の公開は確認できず"),
        "category": "情報公開設定",
        "severity": "medium",
        "risk_level": "L1",
        "verdict": verdict,
        "verdict_basis": "l1_observation",
        "risk_score": score,
        "risk_rationale": rationale,
        "cve": [],
        "help_term": "security_headers",
        "summary": ("固定パスでApache mod_status固有の応答マーカーを観測しました。" if detected
                    else "固定パスではApache mod_status固有の応答マーカーを確認できませんでした。"),
        "why_detected": ("HTTP 200とTotal Accesses、Uptimeの両マーカーを確認しました。" if detected
                         else "この検査では露出を確認できませんでした。"),
        "what_was_established": ("固定パスで状態情報の公開を観測しました。" if detected else None),
        "evidence": [evidence],
        "remediation": {
            "steps": ["Apache mod_status を公開範囲から外すか、管理者だけにアクセスを制限する"],
            "how_to_verify": "同じ固定パスを再診断し、状態情報が公開されないことを確認します。",
        },
        "executor": {**EXECUTOR_DEFAULT, "tool": "status_marker"},
        "demo_fixture": False,
    }


def compute_finding_risk_score(
    severity: str,
    verdict: str,
    *,
    kev: bool = False,
    internet_facing: bool = True,
) -> tuple[int, str]:
    sev = severity.lower()
    base = SEVERITY_BASE_SCORE.get(sev, 40)
    factor = (
        1.0
        if verdict == "proven"
        else 0.75
        if verdict == "detected"
        else 0.0
        if verdict in ("candidate", "not_reproduced", "unverified", "aborted")
        else 0.5
    )
    bonus = (10 if kev else 0) + (5 if internet_facing else 0)
    score = min(100, max(0, round(base * factor + (bonus if factor > 0 else 0))))
    rationale = (
        f"基本重大度({sev.upper()}={base}) × 検証状態係数({verdict}={factor})"
        + (f" + KEV加算(10)" if kev and factor > 0 else "")
        + (f" + 外部公開加算(5)" if internet_facing and factor > 0 else "")
        + f" = {score}/100"
    )
    return score, rationale


MAX_TARGET_HEADERS = 100
# control characters (C0, DEL, C1), line/paragraph separators, bidi overrides, markup
_UNSAFE_TEXT = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u00ad\u061c\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ud800-\udfff"
    r"\U000e0000-\U000e007f<>`\[\]]")


_BLANK_LOOKALIKES = frozenset("\u3164\u2800\u115f\u1160\uffa0")     # render as nothing but are "letters"


def clean_target_text(value, limit: int = 512) -> str:
    """Text taken from a target's response, made safe to embed in titles, summaries
    and the Markdown report: bounded length, no control characters, no HTML tags
    and no Markdown link/code syntax."""
    kept = []
    # compose first, so ordinary accented or voiced letters written with combining
    # marks survive as single letters; marks that remain stand-alone are dropped
    for ch in unicodedata.normalize("NFC", _UNSAFE_TEXT.sub("", str(value))):
        cat = unicodedata.category(ch)
        # control, format, surrogate, private-use, unassigned, line/paragraph
        # separators and combining marks (variation selectors, joiners, fillers)
        if cat[0] == "C" or cat in ("Zl", "Zp", "Mn", "Me") or ch in _BLANK_LOOKALIKES:
            continue
        kept.append(ch)
        if len(kept) >= limit:
            break
    return "".join(kept)


def _hsts_effective(value: str) -> bool:
    m = re.search(r"(?:^|[;\s])max-age\s*=\s*\"?(\d{1,12})", value.lower())
    return bool(m) and int(m.group(1)) > 0


def _enrich_ev(
    base_ev: dict,
    *,
    target_url: str,
    verification_conditions: str,
    tool: str = "http_probe",
) -> dict:
    return {
        **base_ev,
        "target_url": target_url,
        "verification_conditions": verification_conditions,
        "tool": tool,
    }


# `Server` values set by a managed front end / CDN in front of every customer
# (Cloud Run, App Engine, Cloudflare, Vercel, Netlify, CloudFront, S3 ...).
# Without a version they identify the hosting platform, which is public anyway,
# and the service owner cannot remove them: reporting them is a false positive.
MANAGED_EDGE_SERVERS = frozenset({
    "google frontend", "gfe", "esf", "cloudflare", "vercel", "netlify", "cloudfront",
    "amazons3", "awselb", "akamaighost", "github.com", "fastly",
})


def _managed_edge_server(value: str) -> bool:
    v = (value or "").strip().lower()
    # a version ("nginx/1.18", "2.4.49") is a real disclosure even on a managed platform
    return bool(v) and not re.search(r"/\s*\d|\d+\.\d+", v) and v.split("/")[0].strip() in MANAGED_EDGE_SERVERS


def analyze_l1_service_response(
    res: dict,
    ev: dict,
    target_url: str,
    cve_monitor: Optional[cve.FeedMonitor] = None,
    *, root_access: Optional[dict] = None, cookie_policy: Optional[dict] = None,
) -> list[dict]:
    """Analyze a read-only L1 ``http_probe`` response for an external HTTPS service."""
    findings: list[dict] = []
    # Everything below is text chosen by the target. It is bounded and stripped of
    # control / markup characters once, here, before it reaches a title, a summary,
    # the report or a regular expression.
    headers_raw = {clean_target_text(k, 64): clean_target_text(v)
                   for k, v in list((res.get("headers") or {}).items())[:MAX_TARGET_HEADERS]}
    headers_lower = {str(k).lower(): str(v) for k, v in headers_raw.items()}
    status_code = res.get("status")
    is_redirect = isinstance(status_code, int) and 300 <= status_code < 400
    parsed_url = urllib.parse.urlparse(target_url)
    if parsed_url.path not in ("", "/"):
        root_access = None
    is_https = parsed_url.scheme.lower() == "https"
    tls_info = res.get("tls") or {}
    set_cookies: list[str] = [clean_target_text(c, 1024) for c in (res.get("set_cookies") or [])[:50]]
    if not set_cookies and "set-cookie" in headers_lower:
        set_cookies = [headers_lower["set-cookie"]]

    base_conditions = (
        f"L1読み取り専用・低負荷・リダイレクト自動追従なし (GET {target_url}, "
        f"Origin: {res.get('cors_probe_origin', 'https://untrusted-origin.example')})"
    )

    # 1. TLS certificate & HTTPS configuration
    if is_https:
        tls_version = str(tls_info.get("version") or "")
        if tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            r_score, r_rat = compute_finding_risk_score(
                "high", "detected", internet_facing=True
            )
            findings.append(
                {
                    "id": "f_l1_tls",
                    "title": f"旧世代のTLSプロトコル（{tls_version}）が有効",
                    "severity": "high",
                    "verdict": "detected",
                    "verdict_basis": "l1_observation",
                    "category": "暗号・TLS設定",
                    "cve": [],
                    "risk_level": "L1",
                    "help_term": "security_headers",
                    "risk_score": r_score,
                    "risk_rationale": r_rat,
                    "summary": f"HTTPS接続時に旧世代の {tls_version} がネゴシエートされました。TLS 1.2以上（推奨TLS 1.3）のみを許可する必要があります。",
                    "why_detected": f"TLSハンドシェイク実測時に protocol={tls_version}, cipher={tls_info.get('cipher')} が観測されたためです。",
                    "what_was_established": f"実際のTLS接続で旧バージョン {tls_version} が使用されることを確認しました。",
                    "impact": "ダウングレード攻撃や既知の暗号解読手法により通信内容が解読されるリスクがあります。",
                    "evidence": [
                        _enrich_ev(
                            ev,
                            target_url=target_url,
                            verification_conditions=f"{base_conditions} / TLSハンドシェイク検査",
                        )
                    ],
                    "remediation": {
                        "steps": [
                            "Cloud Run / ロードバランサのSSLポリシーで最小TLSバージョンを TLS 1.2 以上に設定する"
                        ],
                        "how_to_verify": "再診断を実行し、TLSv1.2 または TLSv1.3 で接続されることを確認します。",
                    },
                    "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                    "demo_fixture": False,
                }
            )

    # 1b. No TLS at all (an http endpoint that only redirects to https is the recommended setup)
    raw_location = headers_lower.get("location", "").strip()
    try:
        location = urllib.parse.urlsplit(raw_location)
        location_host = (location.hostname or "").rstrip(".").lower()
    except ValueError:
        location, location_host = urllib.parse.urlsplit(""), ""
    redirects_to_https = (isinstance(status_code, int) and status_code in (301, 302, 303, 307, 308)
                          # browsers and URL parsers disagree about "\\" and "@": do not guess
                          and "\\" not in raw_location and "@" not in raw_location
                          and location.scheme.lower() == "https"
                          and location_host != ""
                          and location_host == (parsed_url.hostname or "").rstrip(".").lower())
    if not is_https and not redirects_to_https:
        r_score, r_rat = compute_finding_risk_score("high", "detected", internet_facing=False)
        findings.append(
            {
                "id": "f_l1_no_tls",
                "title": "HTTPS が使われていません（平文HTTPでの提供）",
                "severity": "high",
                "verdict": "detected",
                "verdict_basis": "l1_observation",
                "category": "暗号・TLS設定",
                "cve": [],
                "risk_level": "L1",
                "help_term": "security_headers",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": "診断対象は http:// で応答しました。通信内容・Cookie・トークンが暗号化されずに流れます。",
                "why_detected": "登録された対象URLのスキームが http で、TLS を使わない接続で応答を取得できたためです。",
                "what_was_established": "TLS を使わない接続で応答が返ることを確認しました。",
                "impact": "経路上の第三者に通信内容を読み取られ、改ざんされるリスクがあります。",
                "evidence": [_enrich_ev(ev, target_url=target_url, verification_conditions=base_conditions)],
                "remediation": {
                    "steps": ["すべての通信を HTTPS（TLS 1.2 以上）で提供し、http は https へリダイレクトする",
                              "HSTS を設定してブラウザに HTTPS を強制させる"],
                    "how_to_verify": "https の URL で登録し直して同じGET検査を実行し、この項目が検出されないことを確認します。",
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    # 2. HSTS, CSP, X-Content-Type-Options
    missing_sec_headers: list[str] = []
    if is_https and "strict-transport-security" not in headers_lower:
        missing_sec_headers.append("Strict-Transport-Security (HSTS)")
    elif is_https and not _hsts_effective(headers_lower["strict-transport-security"]):
        missing_sec_headers.append("Strict-Transport-Security (HSTS・max-age が 0 または不正で無効)")
    # A redirect has no document to protect: CSP / nosniff are judged on the page it leads to.
    if is_redirect:
        pass
    elif "content-security-policy" not in headers_lower:
        missing_sec_headers.append("Content-Security-Policy (CSP)")
    if not is_redirect and headers_lower.get("x-content-type-options", "").lower() != "nosniff":
        missing_sec_headers.append("X-Content-Type-Options: nosniff")

    if missing_sec_headers:
        r_score, r_rat = compute_finding_risk_score(
            "low", "detected", internet_facing=is_https
        )
        findings.append(
            {
                "id": "f_headers",
                "title": f"セキュリティヘッダーの未設定（{', '.join(missing_sec_headers)}）",
                "severity": "low",
                "verdict": "detected",
                "verdict_basis": "l1_observation",
                "category": "設定不備",
                "cve": [],
                "risk_level": "L1",
                "help_term": "security_headers",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": f"HTTP応答ヘッダーにおいて {', '.join(missing_sec_headers)} が確認できませんでした（実測HTTPステータス: {status_code}）。",
                "why_detected": "取得したHTTP応答ヘッダーを直接検査した結果です。",
                "what_was_established": f"実際のHTTP応答に {', '.join(missing_sec_headers)} が含まれないことを確認しました。",
                "impact": "ブラウザ側でのXSS被害緩和（CSP）、MIMEスニッフィング防止（nosniff）、HTTPS強制（HSTS）が効かず、他の脆弱性成立時の被害が拡大しやすくなります。",
                "evidence": [
                    _enrich_ev(
                        ev,
                        target_url=target_url,
                        verification_conditions=f"{base_conditions} / HSTS・CSP・X-Content-Type-Options 検査",
                    )
                ],
                "remediation": {
                    "steps": [
                        "Strict-Transport-Security: max-age=31536000; includeSubDomains を付与する",
                        "Content-Security-Policy および X-Content-Type-Options: nosniff を付与する",
                    ],
                    "how_to_verify": "修正後に同じGET検査を実行し、各ヘッダーが応答に含まれることを確認します。",
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    # 3. Cookie Secure, HttpOnly, SameSite
    insecure_cookies: list[str] = []
    candidate_cookies: list[str] = []
    policy_confirmed = bool(cookie_policy and cookie_policy.get("status") == "confirmed"
                            and cookie_policy.get("evidence"))
    for raw_cookie in set_cookies:
        cookie_name = raw_cookie.split("=", 1)[0].strip()[:64] or "cookie"
        if policy_confirmed and cookie_name in cookie_policy["non_session"]:
            continue
        # attributes are the ";"-separated parts AFTER name=value; a cookie name or
        # value that merely contains the word "secure" does not count
        attrs = {}
        ambiguous = False
        for part in raw_cookie.split(";")[1:]:
            key, _, value = part.strip().partition("=")
            key = key.lower()
            if key in attrs and attrs[key] != value.strip():
                ambiguous = True
            attrs[key] = value.strip()
        missing_flags: list[str] = []
        if is_https and "secure" not in attrs:
            missing_flags.append("Secure")
        if "httponly" not in attrs:
            missing_flags.append("HttpOnly")
        expected_same_site = cookie_policy["same_site"] if policy_confirmed else None
        if expected_same_site:
            acceptable = {"Lax", "Strict"} if expected_same_site == "Lax" else {expected_same_site}
            if attrs.get("samesite", "").capitalize() not in acceptable:
                missing_flags.append(f"SameSite={expected_same_site}")
        elif "samesite" not in attrs:
            missing_flags.append("SameSite")
        if missing_flags:
            detail = f"{cookie_name} (未設定・不一致: {'/'.join(missing_flags)})"
            if policy_confirmed and cookie_name in cookie_policy["session"] and not ambiguous:
                insecure_cookies.append(detail)
            else:
                candidate_cookies.append(detail)

    if insecure_cookies or candidate_cookies:
        detected = bool(insecure_cookies)
        verdict = "detected" if detected else "candidate"
        described = insecure_cookies + candidate_cookies
        r_score, r_rat = compute_finding_risk_score(
            "medium", verdict, internet_facing=is_https
        )
        findings.append(
            {
                "id": "f_l1_cookies",
                "title": ("認証セッションCookieの保護属性不足・仕様不一致" if detected else
                          "Cookie用途と保護属性の確認候補"),
                "severity": "medium",
                "verdict": verdict,
                "verdict_basis": "owner_spec_and_l1_observation" if detected else "unverified_scope",
                "category": "セッション・Cookie設定",
                "cve": [],
                "risk_level": "L1",
                "help_term": "security_headers",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": f"Set-Cookie の属性を観測しました: {'; '.join(described)}",
                "why_detected": ("承認済み所有者仕様で認証セッション用途を確認し、応答属性との不一致を観測しました。"
                                 if detected else "属性不足を観測しましたが、認証セッション用途は確認できていません。"),
                "what_was_established": (f"認証セッションCookieの保護属性不足・仕様不一致（{'; '.join(insecure_cookies)}）を観測しました。"
                                         if detected else None),
                "caveat": ("セッション悪用やCSRFの成立は実証していません。" if detected else
                           "Cookie名だけでは用途を判定しません。所有者仕様が揃うまで脆弱性とは扱いません。"),
                "impact": ("セッション保護が弱まる可能性があります。悪用は未実証です。" if detected else
                           "認証セッションへの影響は未確認です。"),
                "evidence": [
                    _enrich_ev(
                        ev,
                        target_url=target_url,
                        verification_conditions=f"{base_conditions} / Set-Cookie 属性検査",
                    )
                ],
                "remediation": {
                    "steps": [
                        (f"所有者仕様で認証用と確認されたCookieに Secure; HttpOnly; SameSite={cookie_policy['same_site']} を設定する"
                         if detected else "Cookieの用途を確認し、認証用であれば所有者仕様に沿って保護属性を設定する")
                    ],
                    "how_to_verify": ("修正後に同じGET検査を実行し、Set-Cookieの属性と承認済み所有者仕様の一致を確認します。"
                                      if detected else "Cookie用途を所有者仕様で確定し、同じGET検査で属性を再確認します。"),
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    # 4. CORS settings
    acao = headers_lower.get("access-control-allow-origin", "")
    acac = headers_lower.get("access-control-allow-credentials", "").lower()
    probe_origin = str(res.get("cors_probe_origin", "https://untrusted-origin.example"))
    # A public response with ACAO * or a reflected origin is not by itself a
    # credentialed cross-origin exposure. Browsers reject ACAO * together with
    # credentials; require an observed credentialed policy before detection.
    # "null" represents untrusted sandboxed/file origins.
    if acac == "true" and (acao == "null" or (acao and probe_origin and acao == probe_origin)):
        sev = "high"
        r_score, r_rat = compute_finding_risk_score(
            sev, "detected", internet_facing=is_https
        )
        findings.append(
            {
                "id": "f_l1_cors",
                "title": f"CORS設定の過剰な許可（Access-Control-Allow-Origin: {acao}）",
                "severity": sev,
                "verdict": "detected",
                "verdict_basis": "l1_observation",
                "category": "CORS・オリジン境界",
                "cve": [],
                "risk_level": "L1",
                "help_term": "cors",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": (
                    f"外部Origin（{probe_origin}）からのリクエストに対し、"
                    f"Access-Control-Allow-Origin: {acao} "
                    f"(Allow-Credentials: {acac or '未設定'}) が返却されました。"
                ),
                "why_detected": f"Origin: {probe_origin} を付与した非破壊GETリクエストの応答ヘッダーで確認されました。",
                "what_was_established": (
                    f"Origin: {probe_origin} を付けたGETへの応答で "
                    f"Access-Control-Allow-Origin: {acao} と "
                    "Access-Control-Allow-Credentials: true を確認しました。"
                ),
                "verdict_note": "確認したのはCORS応答設定です。認証付きの機密情報をブラウザから読み取れたことは実証していません。",
                "impact": "悪意ある外部サイトからブラウザ経由でAPI応答を読み取られる（クロスオリジン情報漏えい）恐れがあります。",
                "evidence": [
                    _enrich_ev(
                        ev,
                        target_url=target_url,
                        verification_conditions=f"{base_conditions} / CORS Originプローブ検査",
                    )
                ],
                "remediation": {
                    "steps": [
                        "信頼されたフロントエンドのオリジン（例: https://app.example.com）のみを厳密なホワイトリストで許可する",
                        "任意のOrigin反射や認証付きAPIでのワイルドカード（*）指定を廃止する",
                    ],
                    "how_to_verify": "修正後に同じOriginプローブを実行し、未許可オリジンに対して Access-Control-Allow-Origin が返らないことを確認します。",
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    # 5. Exposed technology info & 7. NVD / CISA KEV correlation
    server_hdr = headers_lower.get("server", "")
    if _managed_edge_server(server_hdr):
        server_hdr = ""
    powered_by = headers_lower.get("x-powered-by", "")
    exposed_tech = [
        f"{k}: {v}"
        for k, v in [("Server", server_hdr), ("X-Powered-By", powered_by)]
        if v
    ]
    if exposed_tech:
        candidates = (
            cve.detect_from_banner(
                " ".join([server_hdr, powered_by]),
                source="server-header",
                catalog=cve_monitor.catalog,
                kev=cve_monitor.kev,
            )
            if cve_monitor
            else []
        )
        cve_ids = sorted({c.cve.id for c in candidates})
        kev_flag = any(c.in_kev for c in candidates)
        sev = "high" if cve_ids else "low"
        verdict = "detected"
        r_score, r_rat = compute_finding_risk_score(
            sev, verdict, kev=kev_flag, internet_facing=is_https
        )
        cve_note = (
            f" 関連CVE候補: {', '.join(cve_ids)}（バナー照合による検出・未実証）。"
            if cve_ids
            else "（NVD/CISA KEV上の既知悪用バナー一致なし）"
        )
        findings.append(
            {
                "id": "f_powered",
                "title": f"公開技術情報の露出（{', '.join(exposed_tech)}）",
                "severity": sev,
                "verdict": verdict,
                "verdict_basis": "l1_observation",
                "category": "既知の脆弱性（CVE）" if cve_ids else "情報露出",
                "cve": cve_ids,
                "risk_level": "L1",
                "help_term": "cve" if cve_ids else "info_disclosure",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": f"レスポンスヘッダーからサーバー技術情報（{', '.join(exposed_tech)}）が公開されています。{cve_note}",
                "why_detected": "応答ヘッダーのバージョン文字列と NVD / CISA KEV カタログを照合した結果です。",
                "what_was_established": (
                    None
                    if cve_ids
                    else f"実際のHTTP応答で {', '.join(exposed_tech)} ヘッダーが返されることを確認しました。"
                ),
                "caveat": "バナー段階では「検出（未実証）」であり、脆弱性の成立を断定するものではありません。" if cve_ids else None,
                "impact": "攻撃者に使用フレームワークやバージョンを特定され、既知CVEを狙った攻撃の足がかりにされるリスクがあります。",
                "evidence": [
                    _enrich_ev(
                        ev,
                        target_url=target_url,
                        verification_conditions=f"{base_conditions} / 公開技術情報・NVD/CISA KEV照合",
                    )
                ],
                "remediation": {
                    "steps": [
                        "Server ヘッダーの詳細バージョンおよび X-Powered-By ヘッダーの送出を抑制する",
                        "該当ミドルウェアを最新安定版へ更新する",
                    ],
                    "how_to_verify": "修正後に同じGET検査を実行し、詳細バージョンが露出しないことを確認します。",
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    # 6. Unauthenticated API access control boundary check
    content_type = headers_lower.get("content-type", "")
    media_type = content_type.lower().split(";", 1)[0].strip()
    if status_code == 200 and (media_type == "application/json" or media_type.endswith("+json")) \
            and not (root_access and root_access.get("spec_status") == "confirmed"
                     and root_access.get("requirement") == "public"):
        protected = bool(root_access and root_access.get("spec_status") == "confirmed"
                         and root_access.get("requirement") == "authentication_required"
                         and root_access.get("spec_evidence"))
        denial_only = _auth_error_only(res, headers_lower)
        verdict = "detected" if protected and not denial_only else "candidate"
        r_score, r_rat = compute_finding_risk_score(
            "medium", verdict, internet_facing=is_https
        )
        if denial_only:
            title = "未認証要求への認証拒否を確認（HTTP 200）"
            summary = f"認証ヘッダーなしのGET（{target_url}）には HTTP 200 が返りましたが、JSON本文は認証拒否だけでした。"
            reason = "HTTP 200のJSON本文は認証エラーだけでした。保護対象データの取得は確認できません。"
            impact = "この応答から保護対象データの露出は確認できません。"
            fix = "必要に応じて、認証拒否時のHTTPステータスを401/403に揃える"
        else:
            title = ("所有者仕様で認証必須のJSON応答が未認証で取得可能"
                     if protected else "未認証JSON応答の公開範囲を確認する候補")
            summary = (f"認証ヘッダーなしのGETリクエスト（{target_url}）に対して HTTP 200 "
                       f"({content_type}) が返却されました。公開エンドポイントとして意図されたものか確認が必要です。")
            reason = ("管理者承認済みの所有者仕様でルートが認証必須と定められ、"
                      "未認証の読み取り専用GETでJSON応答を観測しました。" if protected else
                      "未認証の読み取り専用プローブでJSON応答を観測しました。"
                      "保護対象かどうかは、この応答だけでは判定できません。")
            impact = "認証が必須であるべきAPIが未認証で応答している場合、内部ステータスやメタデータが外部へ露出する恐れがあります。"
            fix = "公開が不要なAPIエンドポイントでは認証ミドルウェアを必須化し、未認証時は HTTP 401 Unauthorized を返却する"
        findings.append(
            {
                "id": "f_l1_unauth_api",
                "title": title,
                "severity": "medium",
                "verdict": verdict,
                "verdict_basis": "owner_spec_and_l1_observation" if verdict == "detected" else "unverified_scope",
                "category": "APIアクセス制御",
                "cve": [],
                "risk_level": "L1",
                "help_term": "idor",
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": summary,
                "why_detected": reason,
                "what_was_established": ("認証ヘッダーなしのGETでHTTP 200のJSON応答を取得しました。"
                                         if verdict == "detected" else None),
                "caveat": ("認証要件との不一致を観測しました。応答内容が機密情報か、他ユーザーの情報を読めたかは未実証です。"
                           if verdict == "detected" else "保護対象データの取得は確認できません。追加の根拠が揃うまで脆弱性とは判定しません。"),
                "impact": impact,
                "evidence": [
                    _enrich_ev(
                        ev,
                        target_url=target_url,
                        verification_conditions=f"{base_conditions} / 未認証APIアクセス制御境界の観測",
                    )
                ],
                "remediation": {
                    "steps": [fix],
                    "how_to_verify": "未認証GETリクエストに対して HTTP 401/403 が返却されることを確認します。",
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "http_probe"},
                "demo_fixture": False,
            }
        )

    return findings


def build_l2_candidates(
    target_url: str,
    profile: Optional[dict],
    ready_checks: set[str],
) -> list[dict]:
    """Generate one candidate finding per check of the asset's L2 profile.

    No profile bound to the asset -> no L2 candidates (L1 only).

    Crucial safety rule: uninspected L2 items have empty ``evidence=[]`` so
    ``evidence_status(finding)`` classifies them as ``candidate`` ("未計測の候補")
    and NEVER marks them safe.
    """
    if profile is None:
        return []
    parsed = urllib.parse.urlparse(target_url)
    is_https = parsed.scheme.lower() == "https"
    candidates: list[dict] = []

    for check in profile["checks"]:
        spec = check["finding"]
        runnable = check["spec_status"] == "confirmed"
        ready = runnable and check["id"] in ready_checks
        cred_note = (
            "未検査（判定ルールが対象APIの仕様と未照合のため実行できません）"
            if not runnable
            else "暗号化シークレット（検証用アカウント）設定済み・人間の個別承認待ち"
            if ready
            else "未検査（この項目に必要なL2検証用アカウントが未設定・人間の個別承認待ち）"
        )
        r_score, r_rat = compute_finding_risk_score(
            spec["severity"], "candidate", internet_facing=is_https
        )
        candidates.append(
            {
                "id": spec["id"],
                "title": spec["title"],
                "severity": spec["severity"],
                "verdict": "candidate",
                "category": spec["category"],
                "cve": [],
                "risk_level": "L2",
                "help_term": spec["help_term"],
                "reproduce_check": check["id"],
                "requires_l2_approval": True,
                "l2_profile": profile["id"],
                "target_path": profile["paths"][check["subject"]["path"]]["default"],
                "l2_preconditions": [p["label"] for p in check["preconditions"]],
                "l2_ready": ready,
                "l2_spec_status": check["spec_status"],
                "risk_score": r_score,
                "risk_rationale": r_rat,
                "summary": f"{spec['summary']} （現在の状態: {cred_note} ※未検査項目を安全とは判定しません）",
                "why_detected": f"{profile['label']} 向け判定ルールの診断項目として登録されました。所有確認のみで自動実行されることはなく、個別の人間承認と検証用アカウント設定が必要です。",
                "caveat": (f"未検証候補（{cred_note}）。承認されるまで実行されません。" if runnable
                           else f"未検証候補（{cred_note}）。仕様を確認してルールを確定するまで、承認しても実行されません。"),
                "impact": spec["impact"],
                "evidence": [],
                "remediation": {
                    "steps": spec["steps"],
                    "how_to_verify": spec["how_to_verify"],
                },
                "executor": {**EXECUTOR_DEFAULT, "tool": "reproduction_probe"},
                "demo_fixture": False,
            }
        )
    return candidates
