"""Build the human label review sheet for a held-out set (docs/evaluation/LABEL_REVIEW_SHEET_<SET>.md).

For each case it shows what the lab server returns (anonymous, account A, owner B, after
the fix - the start of each body, from the set's own lab fixture), the author's labels and
reason, the blind second labeller's labels and reason, whether they agree, and empty
columns for the human reviewer. It only reads the fixtures and notes; it never writes a
sign-off and never runs the judge.

    python3 -m scripts.make_label_review_sheet --set holdout_v5
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/evaluation/fixtures"
DOCS = ROOT / "docs/evaluation"
FIELDS = ("other_account_read", "unauthenticated_exposure", "fix", "withhold_ok")
WORD = {"supported": "成立", "contradicted": "不成立", "needs_spec": "仕様が必要", "not_applicable": "範囲外",
        "fixed": "修正済み", "not_fixed": "未修正", None: "–", True: "はい", False: "いいえ"}


def _load(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("cases", data) if isinstance(data, dict) else data


def _lab(set_name: str):
    spec = importlib.util.spec_from_file_location("lab", FIX / f"{set_name}_lab.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _body(lab, kind: str) -> str:
    for table in ("JSON_BODIES", "TEXT_BODIES", "BODIES"):
        bodies = getattr(lab, table, None)
        if isinstance(bodies, dict) and kind in bodies:
            v = bodies[kind]
            v = v(0) if callable(v) else v
            text = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
            text = " ".join(text.split())
            return (text[:160] + "…") if len(text) > 160 else text
    return "（定義は lab ファイルを参照）"


def _answer(lab, pair) -> str:
    if not pair:
        return "–"
    status, kind = pair
    return f"{status} `{kind}`：{_body(lab, kind)}".replace("|", "\\|")


def _notes(path: Path) -> dict[str, str]:
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^\| (holdout-[a-z0-9-]+) \|.*\| ([^|]*) \|$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
        m = re.match(r"^- (holdout-[a-z0-9-]+): (.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def build(set_name: str) -> str:
    short = set_name.replace("holdout_", "")
    cases = _load(FIX / f"{set_name}_cases.json")
    author = _load(FIX / f"{set_name}_truth.json")
    second_path = FIX / f"{set_name}_truth_independent.json"
    second = _load(second_path) if second_path.exists() else {}
    lab = _lab(set_name)
    a_notes = _notes(DOCS / f"{set_name}_author_notes.md")
    b_notes = _notes(DOCS / f"{set_name}_independent_notes.md")
    truth_sha = hashlib.sha256((FIX / f"{set_name}_truth.json").read_bytes()).hexdigest()
    lines = [
        f"# 未見ケース {short} の正解ラベル：人によるレビュー用シート",
        "",
        f"`python3 -m scripts.make_label_review_sheet --set {set_name}` で作りました。手で書き換えないでください。",
        "",
        "## 進め方",
        "",
        "1. 各ケースについて、サーバーの応答を読み、作成者のラベルと2人目のラベルが正しいかを判断します。",
        "2. 結果を「人の確認」欄に書きます。正しければ OK、直したいラベルがあればその内容を書きます。2人のラベルが食い違うケース（**不一致**の行）は、特に確認してください。",
        "3. ラベルを直す場合は、`tests/evaluation/fixtures/" + f"{set_name}_truth.json` を直す PR を別に作ります。直すとハッシュが変わり、評価もやり直しになります。",
        f"4. `docs/evaluation/label_signoff_{set_name}.template.json` を `label_signoff_{set_name}.json` に写して記入します。",
        f"5. `VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation signoff-check --set {set_name}` で、署名が有効かを確かめます。",
        "",
        "AI（開発エージェントを含む）は、この確認と署名を代行しません。",
        "",
        "## 署名に書く値",
        "",
        f"- 正解ラベルのファイル：`tests/evaluation/fixtures/{set_name}_truth.json`",
        f"- その SHA-256：`{truth_sha}`",
        "",
        "## ラベルの読み方",
        "",
        "| 列 | 意味 |",
        "| --- | --- |",
        "| 他アカウント | A が B の機密の記録を読めるか（所有者の規則を踏まえて） |",
        "| 認証なし | 認証なしの要求で、B の記録を読めるか |",
        "| 修正 | 修正後の状態（修正済み／未修正） |",
        "| 保留 | どの検査者が集められる証拠でも決められず、判断を保留するのが妥当か |",
        "",
        "## ケースごとの確認",
        "",
        "| ケース | 分類 | 所有者の規則 | 匿名への応答 | A への応答 | B への応答 | 修正後の A | 作成者（他アカウント／認証なし／修正／保留） | 2人目 | 一致 | 作成者の理由 | 2人目の理由 | 人の確認 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    disagree = 0
    for cid in sorted(cases):
        c, t, s = cases[cid], author.get(cid, {}), second.get(cid, {})
        res = c.get("resource") or {}
        after = (c.get("after_fix") or {}).get("acct_A") if isinstance(c.get("after_fix"), dict) else None
        a_lab = "／".join(WORD.get(t.get(f), str(t.get(f))) for f in FIELDS)
        b_lab = "／".join(WORD.get(s.get(f), str(s.get(f))) for f in FIELDS) if s else "–"
        same = all(t.get(f) == s.get(f) for f in FIELDS) if s else None
        disagree += same is False
        lines.append("| " + " | ".join([
            cid, str(t.get("category", "")), str(c.get("owner_spec", "")),
            _answer(lab, res.get("anon")), _answer(lab, res.get("acct_A")), _answer(lab, res.get("acct_B")),
            _answer(lab, after), a_lab, b_lab, "一致" if same else ("**不一致**" if same is False else "–"),
            a_notes.get(cid, "").replace("|", "\\|"), b_notes.get(cid, "").replace("|", "\\|"), " ",
        ]) + " |")
    lines += ["", f"不一致の行：{disagree} 件。", ""]
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", default="holdout_v5")
    a = ap.parse_args(argv)
    out = DOCS / f"LABEL_REVIEW_SHEET_{a.set.replace('holdout_', '').upper()}.md"
    out.write_text(build(a.set) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
