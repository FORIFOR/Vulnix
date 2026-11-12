"""AI advisor: explanations, remediation and next-check suggestions for findings (phase 1: mock only).

What the model is given, and what comes back, are both narrow on purpose:

* Input is built from an explicit allow-list, never by copying a finding. Each finding
  becomes an opaque reference ("F1", "F2", ...) plus code-defined enumerations: rule,
  category, severity, verdict, verdict basis, CVE ids and a rounded risk score. Titles,
  summaries, evidence, URLs, hosts, headers, cookies, tokens and response bodies are
  never read, because analyzer titles embed observed values (an ACAO origin, a TLS
  version). The serialized payload is scanned again before sending and refused if it
  still looks like it carries a URL, host, IP, e-mail, token or cookie.
* A finding about a real service is not given to the advisor at all; the caller
  (`AssessmentService.advise_findings`) filters with the existing allow-list.
* Output must be one JSON object of a fixed schema. Anything else is rejected item by
  item with a reason: unknown keys (authority-shaped ones like "approved", "token",
  "tool" included), references that were not sent, URLs or hosts in the text, claims
  that a detected finding was proven, and next checks that are destructive, out of
  scope or about skipping approval.
* The result is inert data. Every next check is marked as a proposal that needs the
  normal gates (ownership, scope, L2 approval for L2 items). This module imports no
  gateway, token authority, approval store or worker runner, and a next check has no
  tool/action/args, so it cannot become a gateway proposal.
* Phase 1 talks only to a loopback endpoint (the bundled mock server) and takes no
  API key. Connecting the real Abliteration AI API is a separate, later decision.
"""
from __future__ import annotations

import json
import math
import re
import unicodedata
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Iterable

from .router import (DEFAULT_MODEL_TIMEOUT_SECONDS, MAX_MODEL_RESPONSE_BYTES, Transport,
                     _extract_json_from_text, _model_timeout, _NoRedirect)

PROMPT_MARKER = "vulnix-advisor/v1"

SYSTEM_ADVISOR_PROMPT = (
    f"[{PROMPT_MARKER}] あなたは Vulnix のセキュリティ診断アドバイザーです。"
    "与えられた所見（参照ID、規則、分類、深刻度、判定）だけを根拠に、日本語で答えてください。"
    "判定が detected のものを『実証済み』『確定』と書かないでください。"
    "URL、ホスト名、コマンド、攻撃手順は書かないでください。"
    "次に調べる項目は提案であり、実行は Vulnix の承認ゲートを通ります。"
    'JSON だけを返してください: {"advice": [{"ref": "F1", "risk_explanation": "...", '
    '"remediation": ["..."], "next_checks": [{"title": "...", "level": "L1|L2", "reason": "..."}]}]}'
)

# ---- input allow-list -------------------------------------------------------------

KNOWN_RULES = frozenset({
    "f_l1_tls", "f_l1_no_tls", "f_headers", "f_l1_cookies", "f_l1_cors", "f_powered",
    "f_l1_unauth_api", "f_banner", "f_idor", "f_sqli",
})
KNOWN_CATEGORIES = frozenset({
    "暗号・TLS設定", "設定不備", "セッション・Cookie設定", "CORS・オリジン境界", "既知の脆弱性（CVE）",
    "情報露出", "APIアクセス制御", "アクセス制御", "入力検証",
})
SEVERITIES = ("critical", "high", "medium", "low", "info")
VERDICTS = ("detected", "proven", "not_reproduced", "unverified", "fixed")
VERDICT_BASES = ("l1_observation", "l2_reproduction", "demo_fixture")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_FINDINGS = 20


def _enum(value: object, allowed: Iterable[str], default: str) -> str:
    return value if isinstance(value, str) and value in allowed else default


def finding_to_payload_item(ref: str, finding: dict) -> dict:
    """One finding -> the only fields the model may see. Built field by field; nothing is copied."""
    score = finding.get("risk_score")
    risk = round(float(score)) if isinstance(score, (int, float)) and math.isfinite(score) else None
    cves = [c for c in (finding.get("cve") or []) if isinstance(c, str) and _CVE_RE.match(c)][:5]
    return {
        "ref": ref,
        "rule": _enum(finding.get("id"), KNOWN_RULES, "other"),
        "category": _enum(finding.get("category"), KNOWN_CATEGORIES, "その他"),
        "severity": _enum(finding.get("severity"), SEVERITIES, "medium"),
        "verdict": _enum(finding.get("verdict"), VERDICTS, "detected"),
        "verdict_basis": _enum(finding.get("verdict_basis"), VERDICT_BASES, "l1_observation"),
        "cve": cves,
        "risk_score": risk if risk is None or 0 <= risk <= 100 else None,
        "kev": finding.get("kev") is True,
    }


# ---- leak and misproposal detectors ----------------------------------------------

# Boundaries are ASCII-only: Python's \b treats kana and kanji as word characters, so
# "接続先は10.0.0.1です" would hide the address from a \b-anchored pattern.
_B0, _B1 = r"(?<![A-Za-z0-9_])", r"(?![A-Za-z0-9_])"
_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://|www\.", re.I)
# a label may start right after ".", "-", "_" or "*" (*.example.com, _dmarc.example.com) and be
# followed by "-": only an ASCII letter or digit next to it means it is part of a longer word
_HOST_RE = re.compile(r"(?<![A-Za-z0-9])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24})(?![A-Za-z0-9])", re.I)
_IPV4_RE = re.compile(_B0 + r"\d{1,3}(?:\.\d{1,3}){3}" + _B1)
# an IPv6 address has "::" or eight groups; times (12:00:00) and C++ scopes (std::string) do not match
_IPV6_RE = re.compile(r"(?<![A-Za-z0-9_:])(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}"
                      r"|(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?)(?![A-Za-z0-9_:])", re.I)
_HEX_IP_RE = re.compile(_B0 + r"0x[0-9a-f]{8}" + _B1, re.I)
_DEFANGED_RE = re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.I)
_EMAIL_RE = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
# credential *values*, not vocabulary: "Cookie" or "Authorization" as words are fine in advice
_SECRETISH_RE = re.compile(r"\bbearer\s+\S{8,}|\b(?:set-)?cookie\s*:\s*[^\s=;]+=|\bapi[_-]?key\s*[:=]\s*\S+|\bsk-[a-z0-9]{8,}", re.I)
_LONG_OPAQUE_RE = re.compile(r"\b(?=[A-Za-z0-9_\-]*\d)(?=[A-Za-z0-9_\-]*[A-Za-z])[A-Za-z0-9_\-]{32,}\b")
_PATH_RE = re.compile(r"(?:^|\s)/(?:[\w.-]+/)*[\w.-]+")

# names that look like hosts but are header / technology vocabulary the advice may use
_HOSTLIKE_OK = frozenset({"x-powered-by", "node.js", "asp.net", "vue.js", "next.js", "express.js", "react.js",
                          "nuxt.js", "nest.js", "php.ini", "web.config", "nginx.conf", "httpd.conf", ".htaccess"})
# 。 and ｡ written where a dot belongs ("evil。com", "１０。０。０。１"); NFKC keeps 。 as it is
_IDEOGRAPHIC_DOT = str.maketrans({"。": ".", "｡": "."})


def _norm(text: str) -> str:
    """NFKC folds full-width letters and digits (ｂｕｒｐ, ＤｏＳ, １０．０．０．１) into ASCII before matching."""
    return unicodedata.normalize("NFKC", text)


def leak_reasons(text: str) -> list[str]:
    """Why a string must not be sent to, or shown from, the model. Empty when it is clean."""
    out = []
    text = _norm(text)
    if _URL_RE.search(text):
        out.append("url")
    dotted = text.translate(_IDEOGRAPHIC_DOT)
    if [h for t in (text, dotted) for h in _HOST_RE.findall(t) if h.lower() not in _HOSTLIKE_OK]:
        out.append("hostname")
    if _DEFANGED_RE.search(text):
        out.append("hostname")
    if _IPV4_RE.search(dotted) or _IPV6_RE.search(text) or _HEX_IP_RE.search(text):
        out.append("ip_address")
    if _EMAIL_RE.search(text):
        out.append("email")
    if _JWT_RE.search(text) or _SECRETISH_RE.search(text) or _LONG_OPAQUE_RE.search(text):
        out.append("secret_like")
    return out


_HOSTISH_IN_PATH = re.compile(r"/api/|/admin|/\.well-known")
# Next checks that are not acceptable as a suggestion at all, whatever the gate says.
# A next check is something Vulnix itself might later be asked to do, so these describe
# *actions*: "削除して確認する" is refused, "削除されたかを確認する" is not.
_ACT = r"(?:し|す|さ|せ)"
_FORBIDDEN_CHECK = [
    ("destructive", re.compile(r"(?:を|も)(?:削除|消去|破棄|初期化|改ざん|書き換え|上書き)" + _ACT
                               + r"|drop\s+table|truncate\s+table|rm\s+-rf|delete\s+from|update\s+\w+\s+set", re.I)),
    ("load_or_dos", re.compile(r"大量(?:に|の)?(?:送|リクエスト|要求|アクセス)|連続(?:で|して)?送|高頻度|繰り返し(?:送|実行|リクエスト)"
                               r"|(?:リクエスト|要求)を繰り返|負荷(?:を(?:かけ|与え)|試験|テスト)|" + _B0 + r"D?DoS" + _B1 + r"|フラッド|flood|stress\s*test"
                               r"|総当たり|ブルートフォース|brute", re.I)),
    ("production_or_other_users", re.compile(r"本番データ|実データ|顧客(?:データ|の個人情報)|実在の(?:利用者|アカウント)"
                                             r"|他(?:の)?(?:ユーザー|利用者|人)の(?:アカウント|データ|資源|情報)"
                                             r"|(?:他|別)(?:の)?(?:ユーザー|利用者)に影響", re.I)),
    ("approval_bypass", re.compile(r"承認(?:なし|無し|を省略|不要|をスキップ|を回避|を待たず|を得ず|より先に|せずに)|承認(?:取得)?前に(?:実行|試|送|検証|開始)|ゲートを(?:回避|迂回|無効)"
                                   r"|自動承認|bypass|skip\s+approval|without\s+approval", re.I)),
    ("scope_expansion", re.compile(r"(?:リダイレクト先|外部サービス|別ドメイン|サブドメイン)(?:を|も)(?:調べ|確認|診断|検査|列挙|対象|スキャン)"
                                   r"|スコープ(?:を広げ|外|を追加|を拡)|対象(?:を広げ|に含め|を追加|を拡)", re.I)),
    ("tooling_or_commands", re.compile(_B0 + r"(?:sqlmap|nmap|hydra|metasploit|burp|curl|wget|nikto|ffuf|gobuster)" + _B1
                                       + r"|`[^`]+`|\$\(", re.I)),
]
_TOOLING_RE = dict(_FORBIDDEN_CHECK)["tooling_or_commands"]
_OVERCLAIM_RE = re.compile(r"実証済み|実証され|確定(?:済み|した(?:ため|脆弱性|問題|不備))|(?:脆弱性|問題|不備)(?:が|は)確定"
                           r"|確実に悪用|悪用(?:され|に成功|可能(?:です|と確認|である))|侵害(?:され|済み)|侵入され"
                           r"|\bproven\b|exploited|confirmed\s+vulnerab", re.I)
# Remediation is advice to the operator, so security vocabulary (本番環境, 総当たり対策, リダイレクト先,
# サブドメイン, 削除) is normal there. Only directives that undermine the gates or destroy real
# data, and commands, are refused.
_REMEDIATION_FORBIDDEN = [
    ("approval_bypass", dict(_FORBIDDEN_CHECK)["approval_bypass"]),
    ("destroy_real_data", re.compile(r"(?:本番|実|顧客|利用者)(?:の)?データを(?:削除|消去|破棄|作り直|初期化|書き換え|上書き)", re.I)),
]


# ---- output schema --------------------------------------------------------------

ADVICE_KEYS = frozenset({"ref", "risk_explanation", "remediation", "next_checks"})
CHECK_KEYS = frozenset({"title", "level", "reason"})
AUTHORITY_KEYS = frozenset({"approved", "approval", "token", "tool", "action", "args", "target_id",
                            "execute", "run", "scope", "url", "command"})
MAX_EXPLANATION = 800
MAX_REMEDIATION_ITEMS, MAX_REMEDIATION_LEN = 6, 300
MAX_CHECKS, MAX_CHECK_TITLE, MAX_CHECK_REASON = 5, 200, 300
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True)
class NextCheck:
    """A suggestion only. It carries no tool, action, target or arguments, so it cannot be
    handed to the gateway; running anything still needs ownership, scope and (for L2) a
    separate human L2 approval."""
    title: str
    level: str                     # "L1" | "L2"
    reason: str
    status: str = "proposal_only"  # never "approved" / "running": set by this module, not the model
    required_gates: tuple[str, ...] = ()


@dataclass(frozen=True)
class Advice:
    ref: str                       # the opaque reference the model saw
    finding_id: str                # the caller's id, mapped back from the opaque ref
    risk_explanation: str
    remediation: tuple[str, ...]
    next_checks: tuple[NextCheck, ...]


@dataclass(frozen=True)
class AdviceResult:
    advice: tuple[Advice, ...]
    rejected: tuple[dict, ...]     # {"ref", "where", "reason"}: what was dropped and why
    sent_refs: tuple[str, ...]
    missing_refs: tuple[str, ...]  # sent but not answered (after rejection)
    backend: str
    endpoint_kind: str             # "loopback_mock" (or "injected_transport" in tests)
    status: str = "proposal_only"

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "backend": self.backend,
            "endpoint_kind": self.endpoint_kind,
            "sent_refs": list(self.sent_refs),
            "missing_refs": list(self.missing_refs),
            "rejected": [dict(r) for r in self.rejected],
            "advice": [{
                "finding_id": a.finding_id,
                "risk_explanation": a.risk_explanation,
                "remediation": list(a.remediation),
                "next_checks": [{"title": c.title, "level": c.level, "reason": c.reason, "status": c.status,
                                 "required_gates": list(c.required_gates)} for c in a.next_checks],
            } for a in self.advice],
        }


class AdvisorError(Exception):
    """The request could not be made safely (payload refused, endpoint refused, bad reply)."""


def _clean_text(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s or len(s) > limit or _CTRL_RE.search(s):
        return None
    return s


def _gates_for(level: str) -> tuple[str, ...]:
    base = ("ownership_verified", "scope_approved")
    return base + ("l2_human_approval",) if level == "L2" else base


def validate_advice(raw: object, ref_map: dict[str, dict]) -> tuple[list[Advice], list[dict]]:
    """Check one model reply against the schema and the safety rules, item by item."""
    rejected: list[dict] = []
    if not isinstance(raw, dict) or set(raw) != {"advice"} or not isinstance(raw.get("advice"), list):
        return [], [{"ref": None, "where": "root", "reason": "schema: expected exactly {\"advice\": [...]}"}]
    out: list[Advice] = []
    seen: set[str] = set()
    for item in raw["advice"][: len(ref_map) + 5]:
        ref = item.get("ref") if isinstance(item, dict) else None

        def reject(where: str, reason: str) -> None:
            rejected.append({"ref": ref if isinstance(ref, str) else None, "where": where, "reason": reason})

        if not isinstance(item, dict):
            reject("item", "schema: item is not an object")
            continue
        extra = set(item) - ADVICE_KEYS
        if extra:
            kind = "authority_key" if extra & AUTHORITY_KEYS else "unknown_key"
            reject("item", f"{kind}: {sorted(extra)}")
            continue
        if not isinstance(ref, str) or ref not in ref_map:
            reject("item", "unknown_ref: not a finding that was sent")
            continue
        if ref in seen:
            reject("item", "duplicate_ref")
            continue
        finding = ref_map[ref]
        explanation = _clean_text(item.get("risk_explanation"), MAX_EXPLANATION)
        if explanation is None:
            reject("risk_explanation", "schema: missing, empty, too long or control characters")
            continue
        if leak_reasons(explanation):
            reject("risk_explanation", f"leak: {leak_reasons(explanation)}")
            continue
        overclaim_ok = finding.get("verdict") == "proven"
        if not overclaim_ok and _OVERCLAIM_RE.search(_norm(explanation)):
            reject("risk_explanation", "overclaim: a detected finding described as proven or exploited")
            continue
        rem_raw = item.get("remediation")
        if not isinstance(rem_raw, list) or not 1 <= len(rem_raw) <= MAX_REMEDIATION_ITEMS:
            reject("remediation", f"schema: 1..{MAX_REMEDIATION_ITEMS} strings expected")
            continue
        remediation = []
        for r in rem_raw:                      # a bad entry is dropped on its own, not the whole advice
            s = _clean_text(r, MAX_REMEDIATION_LEN)
            if s is None:
                bad = "schema: remediation entry missing, too long or control characters"
            elif leak_reasons(s):
                bad = f"leak: {leak_reasons(s)}"
            elif _TOOLING_RE.search(_norm(s)):
                bad = "commands are not given as remediation text"
            elif not overclaim_ok and _OVERCLAIM_RE.search(_norm(s)):
                bad = "overclaim: a detected finding described as proven or exploited"
            else:
                hit = next((n for n, rx in _REMEDIATION_FORBIDDEN if rx.search(_norm(s))), None)
                bad = f"misproposal: {hit}" if hit else None
            if bad:
                reject("remediation", bad)
            else:
                remediation.append(s)
        if not remediation:
            reject("item", "schema: no usable remediation left")
            continue
        checks_raw = item.get("next_checks", [])
        if not isinstance(checks_raw, list) or len(checks_raw) > MAX_CHECKS:
            reject("next_checks", f"schema: up to {MAX_CHECKS} objects expected")
            continue
        checks = []
        for c in checks_raw:
            if not isinstance(c, dict):
                reject("next_check", "schema: not an object")
                continue
            extra = set(c) - CHECK_KEYS
            if extra:
                kind = "authority_key" if extra & AUTHORITY_KEYS else "unknown_key"
                reject("next_check", f"{kind}: {sorted(extra)}")
                continue
            title = _clean_text(c.get("title"), MAX_CHECK_TITLE)
            reason = _clean_text(c.get("reason"), MAX_CHECK_REASON) if c.get("reason") is not None else ""
            level = c.get("level")
            if title is None or reason is None or level not in ("L1", "L2"):
                reject("next_check", "schema: title / reason / level (L1|L2) invalid")
                continue
            text = f"{title} {reason}"
            leaks = leak_reasons(text)
            if leaks or _HOSTISH_IN_PATH.search(_norm(text)) or _PATH_RE.search(_norm(text)):
                reject("next_check", f"leak: {leaks or ['path']}")
                continue
            hit = next((name for name, rx in _FORBIDDEN_CHECK if rx.search(_norm(text))), None)
            if hit:
                reject("next_check", f"misproposal: {hit}")
                continue
            if not overclaim_ok and _OVERCLAIM_RE.search(_norm(text)):
                reject("next_check", "overclaim: a detected finding described as proven or exploited")
                continue
            checks.append(NextCheck(title=title, level=level, reason=reason, required_gates=_gates_for(level)))
        seen.add(ref)
        out.append(Advice(ref=ref, finding_id=finding["id"], risk_explanation=explanation,
                          remediation=tuple(remediation), next_checks=tuple(checks)))
    return out, rejected


# ---- the adapter ------------------------------------------------------------------

LOOPBACK_HOSTS = ("127.0.0.1", "::1")      # literals: "localhost" would depend on name resolution


def _require_loopback(url: str) -> None:
    """Phase 1 is mock-only: an endpoint other than a loopback address literal is refused."""
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme not in ("http", "https") or parts.username is not None or parts.password is not None
            or (parts.hostname or "").lower() not in LOOPBACK_HOSTS):
        raise AdvisorError("phase 1 advisor accepts only a loopback mock endpoint (127.0.0.1 / ::1); "
                           "connecting the real Abliteration AI API is not enabled")


def _loopback_transport(url: str, headers: dict, body: bytes, *, timeout_s: float) -> bytes:
    """POST to the loopback endpoint directly. Unlike the planner transport, no proxy is ever
    used (an http_proxy in the environment would otherwise carry the request off the machine),
    and redirects are not followed."""
    _require_loopback(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with opener.open(req, timeout=timeout_s) as r:
        data = r.read(MAX_MODEL_RESPONSE_BYTES + 1)
    if len(data) > MAX_MODEL_RESPONSE_BYTES:
        raise AdvisorError("reply too large")
    return data


@dataclass
class AbliterationAdvisor:
    """OpenAI-compatible chat adapter for advice. Holds no API key and no authority."""
    url: str
    model: str = "abliteration-sec-1"
    name: str = "abliteration-advisor"
    timeout_s: float = DEFAULT_MODEL_TIMEOUT_SECONDS
    transport: Transport | None = None
    _send: Callable[[str, dict, bytes], bytes] = field(init=False, repr=False)
    endpoint_kind: str = field(init=False, default="loopback_mock")

    def __post_init__(self) -> None:
        _require_loopback(self.url)
        self.timeout_s = _model_timeout(self.timeout_s)
        self._send = self.transport or partial(_loopback_transport, timeout_s=self.timeout_s)
        # an injected transport (tests) is not the loopback transport; say so in results and audit
        self.endpoint_kind = "loopback_mock" if self.transport is None else "injected_transport"

    def build_request(self, findings: list[dict]) -> tuple[bytes, dict[str, dict]]:
        findings = [f for f in findings if isinstance(f, dict) and isinstance(f.get("id"), str)][:MAX_FINDINGS]
        ref_map = {f"F{i + 1}": f for i, f in enumerate(findings)}
        items = [finding_to_payload_item(ref, f) for ref, f in ref_map.items()]
        user = json.dumps({"findings": items}, ensure_ascii=False)
        leaks = leak_reasons(user)
        if leaks:                   # defence in depth: the allow-list should make this unreachable
            raise AdvisorError(f"payload refused: {leaks}")
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": SYSTEM_ADVISOR_PROMPT},
                         {"role": "user", "content": user}],
            "temperature": 0.2,
        }
        return json.dumps(payload, ensure_ascii=False).encode("utf-8"), ref_map

    def advise(self, findings: list[dict]) -> AdviceResult:
        body, ref_map = self.build_request(findings)
        if not ref_map:
            return AdviceResult((), (), (), (), self.name, self.endpoint_kind)
        _require_loopback(self.url)
        try:
            raw = self._send(self.url, {"Content-Type": "application/json"}, body)
            data = json.loads(raw)
            content = data["choices"][0]["message"]["content"]
        except Exception as e:  # noqa: BLE001 - any transport / format failure is one error
            raise AdvisorError(f"no usable reply: {type(e).__name__}") from None
        parsed = _extract_json_from_text(content) if isinstance(content, str) else None
        advice, rejected = validate_advice(parsed, ref_map)
        answered = {a.ref for a in advice}
        return AdviceResult(
            advice=tuple(advice), rejected=tuple(rejected), sent_refs=tuple(ref_map),
            missing_refs=tuple(r for r in ref_map if r not in answered),
            backend=self.name, endpoint_kind=self.endpoint_kind,
        )
