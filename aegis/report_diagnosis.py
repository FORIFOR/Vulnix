"""The diagnosis-loop and "undecided" parts of the Markdown report.

Built only from the diagnosis view (aegis.diagnosis_view: rebuilt from the verified audit
log) and the findings' recorded evidence status. Every word comes from the same fixed
tables the screen uses (web/src/lib/labels.ts, copied into aegis/report_labels.json and
kept equal by tests/test_report_labels.py). An id without an entry is written as
"未定義の値（id）", never guessed. No model output is ever written here.
"""
from __future__ import annotations

import json
from pathlib import Path

_LABELS = json.loads((Path(__file__).with_name("report_labels.json")).read_text(encoding="utf-8"))

LEGEND = [
    "## この報告書の読み方",
    "- **【監査済みの事実】** 検査結果・判定・承認・入力の記録です。監査ログのハッシュの鎖で記録を確かめたもので、"
    "監査ハッシュを併記します。",
    "- **【固定の規則による判定】** 決まった判定規則による判定です（AI モデルの判断ではありません）。適用した規則を併記します。",
    "- **【固定の修正手順】** 所見ごとに用意した修正方法です。AI モデルが生成した文ではありません。",
    "- **AI（モデル）が書いた説明や提案は、この報告書に含めていません。** 画面に表示される AI の解説は参考情報で、"
    "監査済みの事実ではありません。ただし、診断ループで次にどの検査を行うかは、計画者（AI モデルの場合があります）が"
    "決まった選択肢の中から選びます。選ばれた検査・その理由の文言・判定は、決まった表と規則によるものです。",
    "- **【監査ログで確認できない記録】** 監査ハッシュがないか、検証できた監査ログに見つからない記録です。事実としては扱いません。",
    "- 外部から受け取った値（サーバーのヘッダーなど）は、書式として解釈されないよう記号を無効にして載せています。",
    "",
]


def md_text(value) -> str:
    """Untrusted text (a server header in a title, a note) as plain text: no links, HTML,
    code spans or new lines."""
    text = " ".join(str(value).split())
    for ch in "\\`*_[]<>|#!":
        text = text.replace(ch, "\\" + ch)
    return text


def word(table: str, key) -> str:
    t = _LABELS.get(table, {})
    return t[key] if isinstance(key, str) and key in t else f"未定義の値（{key}）"


def state_text(state: str, purpose: str) -> str:
    """A confirm-fix hypothesis reads the other way round (contradicted = fixed)."""
    if purpose == "confirm_fix" and state in _LABELS["DIAG_FIX_STATE"]:
        return _LABELS["DIAG_FIX_STATE"][state]
    return word("DIAG_STATE", state)


def end_text(reason) -> str:
    if isinstance(reason, str) and reason.startswith("item_"):
        return _LABELS["DIAG_END"]["execute_failed"]
    return word("DIAG_END", reason)


def _h(hash_: str | None) -> str:
    return f"`{hash_[:16]}…`" if isinstance(hash_, str) and hash_ else "なし"


def diagnosis_lines(view: dict | None) -> list[str]:
    """§4: what was checked, why, by which rule, and the before/after comparison."""
    if view is None:
        return []                     # a real service or an ownership flow: there is no loop
    out = ["## 4. 診断ループ（仮説と検査の記録・ラボ専用）"]
    status = view.get("status")
    if status == "not_started":
        return out + ["- このラボでは、まだ診断ループを実行していません。", ""]
    if status != "ok":
        return out + [f"- 記録を確かめられないため、診断ループの結果は載せていません（理由：{word('DIAG_REFUSAL', view.get('reason'))}）。",
                      "- 推測で内容を補うことはしません。監査ログを確認してください。", ""]
    plan = view.get("plan") or {}
    if view.get("restored"):
        out.append("- **注意**: 再起動前の記録です（読み取り専用）。")
    if view.get("persisted") is False:
        out.append("- **注意**: 診断の状態をファイルに保存できていません。再起動すると、この記録は表示できなくなります。")
    out.append(f"- **世代**: {view.get('generation')}（修正後の確認ごとに増えます）")
    if plan:
        line = f"- **状態**: {word('DIAG_PLAN_STATE', plan.get('state'))}（{plan.get('steps_used')} 手順）"
        if plan.get("reason"):
            line += f" — {end_text(plan['reason'])}"
        out.append(line)
    hyps = view.get("hypotheses") or []
    by_id = {h["id"]: h for h in hyps}
    out += ["", "### 確かめようとしたこと（仮説）"]
    if not hyps:
        out.append("- 仮説はありません。")
    for h in hyps:
        line = (f"- {h['id']} {word('DIAG_CLAIM', h['claim'])}（対象 {h['target_ref']}・世代 {h['generation']}）: "
                f"**{state_text(h['state'], h['purpose'])}**")
        if h["purpose"] == "confirm_fix" and h.get("supersedes"):
            line += f"（{h['supersedes']} を修正後に確かめ直したもの）"
        out.append(line)
    out += ["", "### 何を調べたか・なぜ調べたか（手順、古い順）"]
    steps = view.get("steps") or []
    if not steps:
        out.append("- まだ検査した手順はありません。")
    for s in steps:
        purpose = (by_id.get(s["hypothesis_id"]) or {}).get("purpose", "diagnose")
        label = s["step_id"] if s.get("generation", 1) == 1 else f"世代 {s['generation']}・{s['step_id']}"
        reason = word("DIAG_REASON", s.get("reason")).replace("{h}", s["hypothesis_id"])
        approval = (f"L2・承認者 {s.get('approved_by') or '—'}" if s.get("level") == "L2"
                    else f"{s.get('level') or '—'}（人の承認は不要）")
        j = s["judgement"]
        out += [f"- **{label} {word('DIAG_CHECK', s['catalog_id'])}**（{s['hypothesis_id']} を確認）",
                f"  - なぜ: {reason}",
                f"  - 承認: {approval}",
                f"  - 判定【固定の規則による判定】: {state_text(j['to'], purpose)} — {word('DIAG_RULE', j['rule'])}",
                f"  - 証拠【監査済みの事実】: 検査結果 {_h(s.get('result_audit_hash'))}、判定 {_h(s.get('judged_audit_hash'))}"
                + (f"、{s['at']}" if s.get("at") else "")]
    fixes = view.get("fix_comparison") or []
    if fixes:
        out += ["", "### 修正の前後（同じ検査での確かめ直し）"]
    for f in fixes:
        def side(x, purpose):
            if not x:
                return "まだ検査していません"
            rep = x.get("reproduction")
            return (f"{state_text(x['to'], purpose)}（世代 {x['generation']}"
                    + (f"・{word('REPRODUCTION', rep)}" if rep else "") + f"、検査結果 {_h(x.get('result_audit_hash'))}）")
        out.append(f"- {word('DIAG_CHECK', f.get('catalog_id'))}（{f['supersedes']} → {f['hypothesis_id']}）: "
                   f"修正前 {side(f.get('before'), 'diagnose')} → 修正後 {side(f.get('after'), 'confirm_fix')} — "
                   f"**{word('DIAG_FIX_RESULT', f.get('result'))}**")
        if f.get("finding"):
            out.append(f"  - 所見 `{f['finding']['finding_id']}` の現在の判定: "
                       f"{word('DIAG_FINDING_STATUS', f['finding']['status'])}")
    return out + [""]


def undecided_lines(view: dict | None, findings: list[dict], evidence_labels: dict) -> list[str]:
    """§5: what could not be decided, and why (never presented as safe)."""
    out = ["## 5. 判断できなかった項目",
           "- ここに載る項目は「安全」という意味ではありません。判断に必要な条件がそろわなかったものです。"]
    items = []
    for f in findings:
        st = f.get("evidence_status")
        if st in ("incomplete", "candidate"):
            why = f.get("verdict_note") or f.get("caveat") or f.get("why_detected") or "—"
            items.append(f"- 所見「{md_text(f['title'])}」: {evidence_labels.get(st, st)} — {md_text(why)}")
    if view is not None and view.get("status") == "ok":
        current = view.get("generation")
        steps = view.get("steps") or []
        for h in view.get("hypotheses") or []:
            if h["generation"] != current or h["state"] not in ("open", "inconclusive", "needs_spec"):
                continue
            last = next((s for s in reversed(steps) if s["hypothesis_id"] == h["id"]), None)
            why = word("DIAG_RULE", last["judgement"]["rule"]) if last else "まだ検査していません"
            items.append(f"- 仮説 {h['id']} {word('DIAG_CLAIM', h['claim'])}: "
                         f"{state_text(h['state'], h['purpose'])} — {why}")
        plan = view.get("plan") or {}
        if plan.get("reason") and plan["reason"] != "all_settled":
            items.append(f"- 診断ループの終了理由: {end_text(plan['reason'])}")
    elif view is not None and view.get("status") == "unverified":
        items.append(f"- 診断ループの記録: 確かめられないため判断に使っていません（{word('DIAG_REFUSAL', view.get('reason'))}）")
    return out + (items or ["- ありません。"]) + [""]


__all__ = ["LEGEND", "diagnosis_lines", "md_text", "undecided_lines"]
