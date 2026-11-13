"""Output checks for the external model's chat answer (untrusted text).

Text rules cannot prove an answer right, and wide rules withhold good answers, so the
guarantee that L1 detection is never presented as proof does NOT rest on them:

1. verdict_note (code-written, aegis/assessment.py): every model answer about a finding not
   proven by an approved L2 check is shown under a fixed note saying so.
2. cautions(): assertive overclaims about an unproven finding, and claims that a breach or
   leak happened, add a warning note. The answer is still shown (a false positive costs a
   note, not the answer).
3. check_answer(): the answer is withheld - the built-in explanation is shown instead - only
   for *instructions* (〜してください / 〜しましょう / "you should ...", imperative sentences)
   to bypass approval, disable a defence or destroy data, for attack tools used with options
   or "run it with", and for attack strings to enter / send / run. Explanations, conditionals
   ("無効にすると攻撃が成立します"), negations and remediation ("使用済みトークンを無効化して
   ください", "スキップしているコードを修正") pass.
"""
from __future__ import annotations

import re

from .ai_advisor import _norm

# ---- text preparation --------------------------------------------------------------

_INVISIBLE = re.compile(r"[­​-‏⁠-⁤﻿]")
# whitespace next to a non-ASCII character carries no meaning in Japanese ("脆弱性が　あります")
_JA_SPACE = re.compile(r"[ \t　]+(?=[^\x00-\x7f])|(?<=[^\x00-\x7f])[ \t　]+")


def _prepare(text: str) -> tuple[str, str]:
    """(text for English rules, text for Japanese rules)."""
    n = _INVISIBLE.sub("", _norm(text))
    return n, _JA_SPACE.sub("", n)


_CLAUSE_END = re.compile(r"[。、！？!?\n]|\.\s")
_SENTENCE_END = re.compile(r"[。！？!?\n]|\.\s")


def _clause_after(text: str, end: int, width: int = 24, stop: re.Pattern = _CLAUSE_END) -> str:
    t = text[end:end + width]
    m = stop.search(t)
    return t[:m.start()] if m else t


def _sentence_before(text: str, start: int, width: int = 60) -> str:
    h = text[max(0, start - width):start]
    cut = max((m.end() for m in _SENTENCE_END.finditer(h)), default=0)
    return h[cut:]


def _quoted(text: str, start: int) -> bool:
    return start > 0 and text[start - 1] in "「『\"'“‘"


# ---- instructions (withheld) ----------------------------------------------------------

_IMPERATIVE_JA = re.compile(
    r"てください|て下さい|てくだ|ましょう|すべき|べきです|てから|て(?:確認|再|検証|接続|実行|試|進め)"
    r"|ば(?:大丈夫|問題な|OK|早|簡単|確認|十分)|てOK|て大丈夫|で(?:大丈夫|OK)"
    r"|(?:良|よ)いでしょう|と(?:良|よ)い|お?(?:勧|すす)め|推奨|(?:実行|確認|検証|進め|試|再現)(?:でき|られ)ます|痕跡", re.I)
# permission to do it ("しても問題ありません") ends in ません but is not a negation
_PERMISSIVE_JA = re.compile(r"ても(?:問題|構い|大丈夫|差し支え|OK)|て構いません|で構いません|(?:問題|差し支え)(?:は)?ありません")
# "無効化すると検証しやすくなります": a suggestion dressed as a consequence
_SUGGESTED_JA = re.compile(r"^(?:する|して|に|にする|すれ|したら|すると|すれば|しておく|ておく|しておけば|ておけば)?(?:と|ば|ら)?"
                           r"[^。]{0,10}?(?:(?:検証|確認|テスト|再現|調査)(?:し)?やすく|簡単に|楽に|早く|確認でき|検証でき|再現でき|痕跡)")
_NEGATED_JA = re.compile(r"ないで|しない|せず|避け|いけな|はいけ|禁止|厳禁|べきでは|できない|ないよう|させな|されな|ません|ことはな")
# a match describing existing code/config, or a time, is not an instruction to do it
_DESCRIPTIVE_JA = re.compile(r"^(?:している|していた|していない|しており|されて|された|する(?:と|ような|コード|設定|処理|箇所)"
                             r"|設定|コード|箇所|処理|部分|機能|状態|後|中|時|済)")


# the defence is named as something narrower being replaced or as a leak to stop, not weakened
_REPLACED_JA = re.compile(r"移行|切り替|置き換|(?:認証|方式|モード)に(?:して|する|変更)|ブロック")
_QUALIFIED_BEFORE_JA = re.compile(r"(?:Basic|ベーシック|パスワード|ダイジェスト|旧|古い|レガシー|平文|デバッグ|開発用|検知のみ|検出のみ)(?:の)?$", re.I)


def _instructed_ja(rx: re.Pattern, text: str, skip=None) -> bool:
    for m in rx.finditer(text):
        if skip is not None and skip(text, m):
            continue
        tail = _clause_after(text, m.end())
        if _QUALIFIED_BEFORE_JA.search(text[max(0, m.start() - 8):m.start()]) or _REPLACED_JA.search(tail):
            continue
        if _PERMISSIVE_JA.search(tail) or _SUGGESTED_JA.search(tail):
            return True
        if _DESCRIPTIVE_JA.search(tail) or _NEGATED_JA.search(tail):
            continue
        if _IMPERATIVE_JA.search(tail):
            return True
    return False


_EN_NEG = re.compile(r"\b(?:not|never|don't|do\s+not|cannot|can't|no|nobody|avoid|prevent\w*)\b", re.I)
# a sentence that describes what happens or what attackers do is not advice
_EN_EXPLANATORY_HEAD = re.compile(r"\b(?:if|when|whenever|once|whether|because|attackers?|an\s+attacker|malware|someone)\b", re.I)
_EN_REPLACED_AFTER = re.compile(r"^(?:'s)?\s*(?:[\w-]+\s+){0,2}?(?:mode|of\s+(?:passwords?|tokens?|secrets?|session|credentials?|personal)"
                                r"|for\s+(?:passwords?|tokens?|secrets?)|containing|that\s+(?:logs?|contains?)|you\s+no\s+longer"
                                r"|(?:that|which)\s+(?:is|are)\s+no\s+longer)", re.I)


_EN_SUGGESTION_HEAD = re.compile(r"\b(?:easier|simpler|faster|quicker|best|recommend\w*|should|better)\b", re.I)


def _instructed_en(rx: re.Pattern, text: str) -> bool:
    for m in rx.finditer(text):
        head = _sentence_before(text, m.start())
        if _EN_NEG.search(head) or (_EN_EXPLANATORY_HEAD.search(head) and not _EN_SUGGESTION_HEAD.search(head)):
            continue
        if _EN_REPLACED_AFTER.search(text[m.end():m.end() + 40]):
            continue
        return True
    return False


_APPROVAL_JA = re.compile(r"承認(?:待ち)?の間に|承認より先に|承認(?:なし|無し|を省略|を省いて|を省き|をスキップ|を回避|を迂回|を待たず|を得ず|せず|を取らず|は不要|はいりません)"
                          r"|ゲートを(?:回避|迂回|無効|スキップ)|承認は後(?:から|で)|自動承認(?:に|を有効)")
_APPROVAL_EN = re.compile(r"\b(?:skip(?:ping)?|bypass(?:ing)?|circumvent(?:ing)?|ignor(?:e|ing)|disabl(?:e|ing))\s+(?:the\s+)?(?:approval|gate)s?\b"
                          r"|\bapprovals?\s+(?:can|could|may)\s+be\s+(?:skipped|bypassed|ignored)\b", re.I)
_WITHOUT_APPROVAL_EN = re.compile(r"\bwithout\s+(?:waiting\s+for\s+|getting\s+|an?\s+)?approval\b", re.I)

_DEFENCE_JA = (r"(?:WAF|ファイ[アヤ]ウォール|多要素認証|二要素認証|MFA|認証|認可|CSRF(?:対策|保護|検証)?(?!トークン)|証明書(?:の)?検証"
               r"|TLS(?:の)?検証|SSL(?:の)?検証|セキュリティ(?:機能|設定|対策|ヘッダー?)|入力(?:値)?(?:の)?検証|サニタイズ|エスケープ"
               r"|証明書(?:の)?(?:エラー|警告)|アクセス制御|レート制限|監査ログ|監査|CSP|HSTS|緊急停止|所有確認)")
_DISABLE_JA = re.compile(
    _DEFENCE_JA + r"(?:の?(?:ルール|設定|機能|チェック|処理|検証))?(?:機能)?(?:を|は)?(?:[^。、をは]{1,8}?(?:ので|から|ため)、?)?"
    r"(?:一時的に|いったん|一旦|すべて|全て|完全に|あえて|テスト用に)?"
    r"(?:無効(?:化|に)|オフ|切っ|切る|一時停止|停止|解除|外し|外す|外せ|外して|止め|消し|消す|消せ|スキップ|バイパス|迂回|無視|クリア|消去|削除|コメントアウト"
    r"|disable|turnoff)", re.I)
_UNSAFE_CSP_JA = re.compile(r"unsafe-(?:inline|eval)", re.I)
_DISABLE_EN_OBJECTS = (r"(?:waf|firewall|authentication|auth|mfa|csrf\s*(?:protection|middleware|checks?)?|certificate\s+(?:verification|validation|checks?)"
                       r"|tls\s+verification|ssl\s+verification|security\s+(?:headers?|checks?)|input\s+validation|rate\s+limit\w*"
                       r"|audit\s+logs?|csp|hsts|emergency\s+stop)")
_DISABLE_EN = re.compile(
    r"\b(?:the\s+|your\s+)?" + _DISABLE_EN_OBJECTS + r"\s+(?:can|could|should|may|must)\s+be\s+(?:temporarily\s+)?"
    r"(?:disabled|turned\s+off|switched\s+off|bypassed|removed|skipped)\b"
    r"|\b(?:disabl(?:e|ing)|turn(?:ing)?\s+off|switch(?:ing)?\s+off|bypass(?:ing)?|skip(?:ping)?|remov(?:e|ing)|comment(?:ing)?\s+out"
    r"|clear(?:ing)?|delet(?:e|ing))\s+(?:the\s+|your\s+|all\s+|any\s+)?"
    r"(?:waf|firewall|authentication|auth|mfa|csrf\s*(?:protection|middleware|checks?)?|certificate\s+(?:verification|validation|checks?)"
    r"|tls\s+verification|ssl\s+verification|security\s+(?:headers?|checks?)|input\s+validation|rate\s+limit\w*"
    r"|audit\s+logs?|csp|hsts|emergency\s+stop)\b"
    r"|\b(?:set|add|use|allow|enable)\b[^.\n]{0,30}?\bunsafe-(?:inline|eval)\b", re.I)
_INSECURE_FLAGS = re.compile(r"rejectUnauthorized\s*:\s*false|_create_unverified_context|InsecureSkipVerify\s*:\s*true"
                             r"|CURLOPT_SSL_VERIFYPEER\s*,?\s*(?:false|0)|--no-check-certificate|ssl_verify\s*=\s*false|\bverify\s*=\s*false\b|\bcurl\b[^\n]{0,40}?\s(?:-k|--insecure)\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0", re.I)

_DESTROY_JA = re.compile(
    r"(?:本番|実|顧客|利用者|ユーザー)(?:環境)?(?:の)?(?:DB|データベース|データ|テーブル)を(?:削除|消去|破棄|作り直|初期化|書き換え|上書き|DROP|TRUNCATE)"
    r"|(?:DB|データベース|テーブル)を(?:DROP|TRUNCATE)", re.I)
_DESTROY_EN = re.compile(r"\b(?:drop|truncate|delete|wipe|deleting|wiping)\s+(?:the\s+)?(?:production|prod|customer|user)\s+(?:data(?:base)?|db|tables?)\b|\brm\s+-rf\b", re.I)

_TOOLS = re.compile(r"(?<![A-Za-z0-9_])(?:sqlmap|hydra|metasploit|msfconsole|msfvenom|hashcat|john\s+the\s+ripper|nikto|ffuf"
                    r"|gobuster|dirbuster|wfuzz|nmap)(?![A-Za-z0-9_])", re.I)
_TOOL_USE_AFTER = re.compile(r"^\s*-{1,2}[A-Za-z]|^(?:で|を)(?:確認|実行|使|試|スキャン|検証|攻撃|調べ)|^\s+(?:-|against\b|on\s+the\b)", re.I)
_TOOL_USE_BEFORE = re.compile(r"\b(?:run|use|launch|try|execute|with)\s+(?:\w+\s+)?$", re.I)
_TOOL_NOT_USED = re.compile(r"使いません|使わない|使用しない|使用しません|行いません|行わない|しません|禁止|\b(?:not|never)\b", re.I)
_PAYLOADS = re.compile(r"\bunion\s+(?:all\s+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|(?:\.\./){2,}|%2e%2e[/%]"
                       r"|\bxp_cmdshell\b|\bsleep\s*\(\s*\d+\s*\)\s*--|<\s*script\b|\bonerror\s*=|javascript\s*:\s*\w"
                       r"|\b(?:drop|truncate)\s+table\b|\bdelete\s+from\s+\w+", re.I)
_PAYLOAD_ACTION = re.compile(r"入力|送信|指定|実行|試す|試して|貼り付|注入|取得でき|確認でき|再現|\b(?:enter|send|submit|inject|paste|run|type)\b", re.I)
_PAYLOAD_ACTION_BEFORE = re.compile(r"\b(?:enter|send|submit|inject|paste|run|type|put|append)\b", re.I)
_PAYLOAD_DEFENDED = re.compile(r"を防|をブロック|を拒否|を検知|を無害化|をエスケープ|を検証|を除去|を弾|から守|のような入力|などの入力|を含む"
                               r"|ても|されない|されず|拒否され|エスケープされ|無害化され|ブロックされ|されてしまい|が実行され|ことを確認|になります"
                               r"|\b(?:block|reject|escape|sanitiz|prevent|detect)", re.I)


_PAYLOAD_EXPLAINED_BEFORE = re.compile(r"攻撃者|例えば|たとえば|\b(?:attackers?|for\s+example|e\.g\.|such\s+as)\b", re.I)


def _attack_tooling(n: str) -> bool:
    for m in _TOOLS.finditer(n):
        after = n[m.end():m.end() + 24]
        if _TOOL_NOT_USED.search(after) or _EN_NEG.search(_sentence_before(n, m.start())):
            continue
        if _TOOL_USE_AFTER.search(after.lstrip(" ")) or _TOOL_USE_AFTER.search(after) \
                or _TOOL_USE_BEFORE.search(_sentence_before(n, m.start())):
            return True
    for m in _PAYLOADS.finditer(n):
        tail = n[m.end():m.end() + 36]
        head = _sentence_before(n, m.start(), 30)
        if _PAYLOAD_DEFENDED.search(tail) or _PAYLOAD_DEFENDED.search(head) or _PAYLOAD_EXPLAINED_BEFORE.search(head):
            continue
        if _PAYLOAD_ACTION.search(tail) or _PAYLOAD_ACTION_BEFORE.search(_sentence_before(n, m.start(), 30)):
            return True
    return False


# "承認は不要です" is true of L1 (passive observation) and a bypass for anything else
_APPROVAL_NOT_NEEDED = re.compile(r"承認(?:は|が)?(?:不要|いりません|必要ありません|要りません)")
_L1_CONTEXT = re.compile(r"L1|受動|観察|閲覧|読み取り専用|公開情報")


_L2_CONTEXT = re.compile(r"L2|実証|侵入|再現試験", re.I)
_L1_CONTEXT_EN = re.compile(r"\bL1\b|\bpassive\b", re.I)


_PART_END = re.compile(r"[。！？!?;；\n]|\.\s")


def _sentence_of(text: str, start: int, end: int) -> str:
    h = text[max(0, start - 80):start]
    cut = max((m.end() for m in _PART_END.finditer(h)), default=0)
    return h[cut:] + text[start:end] + _clause_after(text, end, 80, _PART_END)


def _about_l1_only(text: str, m: re.Match) -> bool:
    """A sentence about L1 / passive observation (and not L2) explains, it does not bypass."""
    sent = _sentence_of(text, m.start(), m.end())
    return bool((_L1_CONTEXT.search(sent) or _L1_CONTEXT_EN.search(sent)) and not _L2_CONTEXT.search(sent.replace("L1", "")))


def _approval_not_needed(ja: str) -> bool:
    return any(not _L1_CONTEXT.search(_sentence_before(ja, m.start()))
               and not _NEGATED_JA.search(_clause_after(ja, m.end(), 8)) for m in _APPROVAL_NOT_NEEDED.finditer(ja))


def check_answer(text: object, *, proven: bool) -> str | None:  # noqa: ARG001 - kept for one signature
    """None when the answer may be shown; otherwise a short reason code (no answer text)."""
    if not isinstance(text, str) or not text.strip():
        return "empty"
    n, ja = _prepare(text)
    if (_instructed_ja(_APPROVAL_JA, ja, skip=_about_l1_only) or _instructed_en(_APPROVAL_EN, n) or _approval_not_needed(ja)
            or any(not _EN_NEG.search(_sentence_before(n, m.start())) and not _about_l1_only(n, m)
                   for m in _WITHOUT_APPROVAL_EN.finditer(n))):
        return "approval_bypass"
    if (_instructed_ja(_DISABLE_JA, ja) or _instructed_ja(_UNSAFE_CSP_JA, ja) or _instructed_en(_DISABLE_EN, n)
            or any(not _EN_NEG.search(_sentence_before(n, m.start())) and not _NEGATED_JA.search(_clause_after(n, m.end()))
                   for m in _INSECURE_FLAGS.finditer(n))):
        return "disable_defence"
    if _instructed_ja(_DESTROY_JA, ja) or _instructed_en(_DESTROY_EN, n):
        return "destroy_real_data"
    if _attack_tooling(n):
        return "attack_tooling"
    return None


# ---- cautions (shown with a warning) ------------------------------------------------------

_HEDGE_AFTER_JA = re.compile(
    r"^と(?![しす])|可能性|かもしれ|おそれ|恐れ|疑い|かどうか|か(?:は|も|を)|とは|と(?:は)?(?:断定|言え|いえ|限)|と考え|ように見"
    r"|て(?:い)?な|てませ|ません|ない|ず|なかっ|る前|場合|とき|る時|た時|なら|まで|ると|ても|うる|得る|かね|ことがあ|リスク")
_HEDGE_BEFORE_EN = re.compile(r"\b(?:may|might|could|whether|if|unless|potentially|possibly|not|never|cannot|can't|no|prevent\w*|unable)\b", re.I)
_NEG_AFTER_EN = re.compile(r"^[^.!?\n]{0,30}\b(?:not|n't|never)\b", re.I)


_CONDITION_BEFORE_JA = re.compile(r"(?:ると|ないと|いると|場合|れば|たら|なら|際に?)[、,]?")


def _asserted_ja(rx: re.Pattern, text: str) -> bool:
    return any(not _quoted(text, m.start()) and not _HEDGE_AFTER_JA.search(_clause_after(text, m.end(), 16))
               and not _CONDITION_BEFORE_JA.search(_sentence_before(text, m.start(), 40))
               for m in rx.finditer(text))


def _asserted_en(rx: re.Pattern, text: str) -> bool:
    return any(not _quoted(text, m.start()) and not _HEDGE_BEFORE_EN.search(_sentence_before(text, m.start(), 40))
               and not _NEG_AFTER_EN.search(text[m.end():m.end() + 40])
               for m in rx.finditer(text))


_BREACH_JA = re.compile(r"侵害(?:され|済み)|侵入され|乗っ取られ|(?:漏洩|漏えい|流出)(?:し(?:て|ま)|が発生|済み)")
_BREACH_EN = re.compile(r"\b(?:was|were|been|is|are)\s+(?:already\s+)?(?:compromised|breached|hacked)\b"
                        r"|\bdata\s+(?:was|were|has\s+been|have\s+been)\s+(?:leaked|stolen|exfiltrated)\b", re.I)
_OVERCLAIM_JA = re.compile(
    r"実証(?:済み|され)|確定(?:済み|した|して|です|しま)|(?:脆弱性|問題|不備)(?:が|は)確定"
    r"|悪用(?:され|に成功|でき|して)|攻撃(?:でき|が成立)|侵入でき|閲覧でき|(?:管理者|他人|別のユーザー)になれ"
    r"|(?:悪用|攻撃|侵入|インジェクション|XSS|IDOR|改ざん|窃取|なりすまし|任意コード実行|情報漏洩)(?:が|は)?可能(?!性)"
    r"|(?:盗|奪|乗っ取|読み取|改ざん|窃取|書き換|なりすま)[ぁ-ん]{0,4}?(?:ことが)?(?:でき|可能(?!性)|え(?:ます|る)|め(?:ます|る)|れ(?:ます|る))"
    r"|(?:脆弱性|欠陥|セキュリティホール|脆弱な箇所)(?:が|は)?(?:確実に)?"
    r"(?:存在(?:します|している|する|しており|しています)|あります|ある|見つかりました|見つかった|確認されました|発見されました|実在|含まれ)"
    r"|(?:脆弱性|欠陥|セキュリティホール)を(?:確認|発見|特定)(?:しました|した|できました)|脆弱(?:です|である|な状態)", re.I)
_OVERCLAIM_EN = re.compile(
    r"\bis\s+(?:\w+\s+){0,2}?(?:vulnerable|exploitable)\b|\bexploitable\b|\b(?:was|has\s+been|were)\s+exploited\b"
    r"|\bcan\s+(?:\w+\s+){0,2}?exploit\b|\bvulnerabilit(?:y|ies)\s+(?:exists?|is\s+present|are\s+present)\b"
    r"|\bconfirmed\s+(?:xss|sqli|sql\s+injection|idor|vulnerab\w*|exploit\w*)\b|\bproven\s+vulnerab\w*"
    r"|\b(?:has|have|contains?)\s+an?\s+(?:[\w-]+\s+){0,3}?vulnerabilit(?:y|ies)\b|\bthere\s+(?:is|are)\s+an?\s+(?:[\w-]+\s+){0,3}?vulnerabilit"
    r"|\breal\s+vulnerabilit|\bwill\s+be\s+able\s+to\b", re.I)


def cautions(text: object, *, proven: bool) -> list[str]:
    """Reasons to show the answer with a warning (empty when none)."""
    if not isinstance(text, str) or not text.strip():
        return []
    n, ja = _prepare(text)
    out = []
    if not proven and (_asserted_ja(_OVERCLAIM_JA, ja) or _asserted_en(_OVERCLAIM_EN, n)):
        out.append("overclaim")
    if _asserted_ja(_BREACH_JA, ja) or _asserted_en(_BREACH_EN, n):
        out.append("breach_claim")
    return out


# ---- notes shown in the UI (written by code, never by the model) -----------------------------

GUARD_NOTES = {
    "approval_bypass": "AIの回答に承認を省く指示が含まれていたため表示を見合わせました。以下は内蔵の解説です。",
    "disable_defence": "AIの回答に防御機能を無効にする指示が含まれていたため表示を見合わせました。以下は内蔵の解説です。",
    "destroy_real_data": "AIの回答にデータを消す指示が含まれていたため表示を見合わせました。以下は内蔵の解説です。",
    "attack_tooling": "AIの回答に攻撃ツールや攻撃文字列の使い方が含まれていたため表示を見合わせました。以下は内蔵の解説です。",
    "empty": "AIから有効な回答が得られませんでした。以下は内蔵の解説です。",
}

CAUTION_NOTES = {
    "overclaim": "AIの回答には断定的な表現が含まれていますが、この問題は承認済みのL2検証で実証されていません。",
    "breach_claim": "AIの回答は侵害や情報流出が起きたかのように読めますが、Vulnixの検証は模擬データで行っており、侵害を示すものではありません。",
}


MIXED_OVERCLAIM_NOTE = ("AIの回答には断定的な表現が含まれていますが、この用語に当てはまる検出の一部は"
                        "承認済みのL2検証で実証されていません。")


def caution_note(reasons: list[str], *, mixed: bool = False) -> str:
    notes = {**CAUTION_NOTES, **({"overclaim": MIXED_OVERCLAIM_NOTE} if mixed else {})}
    return " ".join(notes[r] for r in reasons if r in notes)


VERDICT_LABELS = {"detected": "L1で検出（未実証）", "unverified": "未検証", "not_reproduced": "L2で再現せず",
                  "aborted": "検証中断（未実証）", "fixed": "修正確認済み"}


def verdict_note(verdict: object) -> str:
    """Code-written status shown with every model answer about an unproven finding."""
    label = VERDICT_LABELS.get(verdict if isinstance(verdict, str) else "", "未実証")
    return (f"この問題の判定は「{label}」です。承認済みのL2検証で実証されていません。"
            "AIの説明は可能性の説明であり、脆弱性があるとは断定できません。")


MIXED_VERDICT_NOTE = ("この用語に当てはまる検出のうち一部は、承認済みのL2検証で実証されていません。"
                      "AIの説明をすべての検出に当てはめないでください。各問題の判定は問題一覧で確認できます。")


CHAT_SYSTEM_PROMPT = (
    "あなたは Vulnix AI セキュリティ診断アシスタントです。"
    "与えられた診断コンテキストと証拠のみを根拠に、専門知識のない人にも分かる日本語で簡潔に答えてください。"
    "守るべき規則: "
    "(1) L1 は受動的な観察による「検出」であり、問題の存在を証明しません。"
    "verdict が proven（承認済みの L2 検証で再現）でない問題について、「脆弱性が存在する」「悪用できる」「実証済み」などと断定してはいけません。"
    "「可能性がある」「L2 で確認するまで断定できない」のように書いてください。"
    "proven であっても、模擬データでの再現であり、実際に侵害や情報流出が起きたとは書かないでください。"
    "(2) 承認を省く・回避する提案、WAF や認証など防御機能を無効にする提案、データを削除する提案をしてはいけません。"
    "(3) 攻撃ツールのコマンド、攻撃文字列、攻撃手順は書かないでください。"
    "(4) 分かる範囲で「何が問題か」「根拠（証拠）」「危険性」「修正方法」「修正後の確認方法」の順に説明してください。"
    "コンテキストにない事実は推測で補わず、分からないと書いてください。"
)
