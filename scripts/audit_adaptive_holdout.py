"""Leakage audit, metric recomputation and blind re-labelling packet for adaptive_holdout_v2.

This is an AUTOMATED CONSISTENCY CHECK by the dataset's own author. It is not an
independent audit and it does not validate the labels. Independent validation needs
people who have not seen truth.json to answer the blind packet built here.

  python3 -m scripts.audit_adaptive_holdout audit   [--out docs/ADAPTIVE_HOLDOUT_V2_AUDIT.json]
  python3 -m scripts.audit_adaptive_holdout packet  --out-dir docs/adaptive_holdout_v2_relabel
  python3 -m scripts.audit_adaptive_holdout compare --answers answers.csv [--key key.json]

Nothing here contacts a target or a model.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

os.environ.setdefault("VULNIX_NO_ENV_LOCAL", "1")

from aegis.ai_advisor import leak_reasons  # noqa: E402
from scripts import eval_adaptive_holdout as ev  # noqa: E402
from scripts.adaptive_baselines import RULES  # noqa: E402

TRUTH_KEYS = ("expected_catalog_ids", "requires_additional_check", "critical", "deciding_signal", "rationale_ja")
CATALOG_IDS = ("l1_http_probe", "l1_apache_mod_status", "l2_idor")
PACKET_SEED = 20261120
RULE_NAMES = ("A_fixed_l1", "B_fixed_rule", "B2_strong_rule", "E_keyword_rule")


# ---------------------------------------------------------------------------
# 1. leakage
# ---------------------------------------------------------------------------
def _atoms(node, prefix=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _atoms(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(node, list):
        if all(not isinstance(x, (dict, list)) for x in node):
            yield prefix, json.dumps(node, sort_keys=True)
        else:
            for i, v in enumerate(node):
                yield from _atoms(v, f"{prefix}[{i}]")
    else:
        yield prefix, json.dumps(node, ensure_ascii=False)


def leakage(cases, owners, truth) -> dict:
    issues: list[str] = []
    views = {c["case_id"]: ev.model_view(c, owners[c["case_id"]]) for c in cases}
    allowed_keys = {"category", "observation", "owner_spec", "allowed_catalog_ids"}
    for cid, v in views.items():
        if set(v) != allowed_keys:
            issues.append(f"{cid}: unexpected model-visible keys {sorted(set(v) ^ allowed_keys)}")
        if set(v["owner_spec"]) != set(ev.MODEL_VISIBLE_OWNER_KEYS):
            issues.append(f"{cid}: owner_spec keys differ")
    texts = {"planner_requests": "\n".join(json.dumps(ev.planner_request(v, "http://lab.test:1/"), ensure_ascii=False)
                                           for v in views.values())}
    request, mapping = ev.real_model_request(cases, owners)
    texts["real_model_request"] = json.dumps(request, ensure_ascii=False)
    truth_strings = [t["rationale_ja"] for t in truth.values()]
    for where, text in texts.items():
        for key in TRUTH_KEYS:
            if key in text:
                issues.append(f"{where}: truth key '{key}' present")
        for s in truth_strings:
            if s in text:
                issues.append(f"{where}: a truth rationale is present")
        for c in cases:
            if c["case_id"] in text:
                issues.append(f"{where}: original case id {c['case_id']} present")
        lr = leak_reasons(text.replace("http://lab.test:1/", ""))
        if lr:
            issues.append(f"{where}: leak_reasons {lr}")
    notes_with_ids = [c["case_id"] for c in cases
                      if any(i in owners[c["case_id"]]["note_ja"] for i in CATALOG_IDS)]
    if notes_with_ids:
        issues.append(f"owner notes name a catalog id: {notes_with_ids}")
    # order leak in D: original order is category-blocked; the mapping must not keep it
    order = list(mapping.values())
    kept_order = sum(1 for a, b in zip(order, order[1:]) if a < b) / max(1, len(order) - 1)

    # single-feature predictability (meta-signals): how well a lookup table on ONE
    # model-visible feature predicts the label, vs. the majority baseline
    labels = {c["case_id"]: json.dumps(truth[c["case_id"]]["expected_catalog_ids"]) for c in cases}
    base = Counter(labels.values()).most_common(1)[0][1]
    feats: dict[str, dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for c in cases:
        cid = c["case_id"]
        v = views[cid]
        derived = {"meta.note_present": json.dumps(bool(v["owner_spec"]["note_ja"])),
                   "meta.note_len_bucket": json.dumps(len(v["owner_spec"]["note_ja"]) // 20),
                   "meta.cookie_count": json.dumps(len(v["observation"]["cookies"]))}
        for k, val in [*_atoms(v), *derived.items()]:
            if k == "owner_spec.note_ja":
                continue           # free text: unique per case, a lookup on it is meaningless
            feats[k][val][labels[cid]] += 1
    single = sorted(({"feature": k, "distinct_values": len(vals),
                      "lookup_correct": sum(max(cnt.values()) for cnt in vals.values())}
                     for k, vals in feats.items()), key=lambda r: -r["lookup_correct"])
    pos = lambda cid: bool(truth[cid]["expected_catalog_ids"])  # noqa: E731
    note_cases = [c["case_id"] for c in cases if owners[c["case_id"]]["note_ja"]]
    return {
        "issues": issues,
        "truth_free_inputs": not issues,
        "real_model_order_monotonic_pairs_ratio": round(kept_order, 3),
        "majority_baseline_correct": base,
        "single_feature_lookup": single[:12],
        "note_presence_vs_label": {
            "with_note": f"{sum(pos(c) for c in note_cases)}/{len(note_cases)} need a check",
            "without_note": f"{sum(pos(c['case_id']) for c in cases if c['case_id'] not in note_cases)}/"
                            f"{len(cases) - len(note_cases)} need a check"},
        "notes_requesting_a_check": sorted(c["case_id"] for c in cases
                                           if "確認したい" in owners[c["case_id"]]["note_ja"]),
    }


# ---------------------------------------------------------------------------
# 2. independent recomputation of A/B/B2/E (own counting; cross-checked with ev.score)
# ---------------------------------------------------------------------------
def recompute(cases, owners, truth, labels: dict[str, set[str]] | None = None,
              critical: dict[str, bool] | None = None) -> dict:
    labels = labels or {c["case_id"]: set(truth[c["case_id"]]["expected_catalog_ids"]) for c in cases}
    critical = critical or {c["case_id"]: bool(truth[c["case_id"]]["critical"]) for c in cases}
    out = {}
    for name in RULE_NAMES:
        tp = fp = fn = 0
        crit_missed, errors = [], []
        for c in cases:
            cid = c["case_id"]
            picked = RULES[name](c, owners[cid]) & set(c["allowed_catalog_ids"])
            exp = labels[cid]
            tp += len(picked & exp)
            fp += len(picked - exp)
            fn += len(exp - picked)
            if picked != exp:
                errors.append(cid)
            if critical.get(cid) and not exp <= picked:
                crit_missed.append(cid)
        out[name] = {"tp": tp, "fp": fp, "fn": fn,
                     "precision": round(tp / (tp + fp), 4) if tp + fp else None,
                     "recall": round(tp / (tp + fn), 4) if tp + fn else None,
                     "f1": round(2 * tp / (2 * tp + fp + fn), 4) if 2 * tp + fp + fn else None,
                     "critical_missed": crit_missed, "critical_missed_count": len(crit_missed),
                     "case_errors": errors}
    return out


def focus_sets(cases, owners, truth) -> dict:
    crit = sorted(c["case_id"] for c in cases if truth[c["case_id"]]["critical"])
    e_err = recompute(cases, owners, truth)["E_keyword_rule"]["case_errors"]
    ceiling = ev.structured_ceiling(cases, owners, truth)
    groups = ceiling["conflicting_groups"]
    return {"critical": crit, "E_errors": sorted(e_err),
            "note_ambiguous_groups": groups,
            "note_ambiguous_cases": sorted({i for g in groups for i in g}),
            "note_unreachable_minimum": ceiling["cases_unreachable_without_note"],
            "union": sorted(set(crit) | set(e_err) | {i for g in groups for i in g})}


def audit() -> dict:
    manifest, cases, owners, truth = ev.load_dataset()
    rec = recompute(cases, owners, truth)
    cross = {}
    for name in RULE_NAMES:
        sel = {c["case_id"]: RULES[name](c, owners[c["case_id"]]) for c in cases}
        s = ev.score(sel, cases, truth)
        cross[name] = (s["tp"], s["fp"], s["fn"], s["critical_cases_missed"]) == \
            (rec[name]["tp"], rec[name]["fp"], rec[name]["fn"], rec[name]["critical_missed_count"])
    return {"nature": "author's automated consistency check - NOT an independent audit",
            "dataset_sha256": manifest["files_sha256"], "leakage": leakage(cases, owners, truth),
            "recomputed": rec, "matches_eval_score": cross, "focus_sets": focus_sets(cases, owners, truth)}


# ---------------------------------------------------------------------------
# 3. blind packet for independent re-labelling
# ---------------------------------------------------------------------------
CHECK_DEFINITIONS_JA = {
    "l1_http_probe": "同じURLへ読み取り専用のGETをもう1回だけ送り、応答ヘッダーと応答の形を取り直す。",
    "l1_apache_mod_status": "Apacheの状態ページ（/server-status?auto）が外から見えるかを、GET 1回で確かめる。",
    "l2_idor": "隔離ラボで、テスト用アカウントAからテスト用アカウントBの資源を取得できるかを確かめる（承認者の承認が必要）。",
}
FIELD_GLOSSARY_JA = """| 項目 | 意味 |
| --- | --- |
| `category` | 条件の分類（`auth_session`、`idor_bola`、`cors`、`cookie`、`info_tls`）。分類は検査の要否を決めない |
| `observation.scheme` / `status` / `content_type` | 最初のGETのスキームとHTTP状態コード、応答の種類 |
| `observation.body_shape` | 応答本文の形：`account_fields`（アカウントの情報らしい項目）、`auth_error`（認証エラーだけ）、`login_form`、`public_content`、`empty` |
| `observation.account_resource_link_observed` | 応答の中に、アカウントごとの資源（例：利用者IDを含むURL）へのリンクが見つかったか |
| `observation.initial_gets_consistent` | 最初のGETを複数回取得した場合に結果が一致したか。`true`=一致、`false`=食い違い、`null`=1回しか取得していない |
| `observation.cors` | `acao`：Access-Control-Allow-Origin の形（`none`、`wildcard`、`reflected`=送信元をそのまま返す、`fixed_origin`）。`credentials`：資格情報つきの読み取りを許すか。`vary_origin`：Vary: Origin があるか |
| `observation.cookies[]` | 観測したCookie。`purpose` は名前や属性から推定した用途（`unknown` は推定できない）。`secure` / `httponly` / `samesite` は属性。`duplicate_conflicting` は同名Cookieが属性の異なる形で複数返ったか |
| `observation.server_family` / `version_disclosed` | Serverヘッダーから推定した製品の系統と、バージョン番号が表示されていたか |
| `observation.tls_verified` / `hsts_present` | 証明書の検証に成功したか、HSTSヘッダーがあるか |
| `owner_spec.root_access_requirement` / `account_resource_requirement` | 所有者が登録した構造化要件：`public`、`authentication_required`、`none`（該当する資源がない）、`unspecified`（未記入） |
| `owner_spec.status_probe_consent` / `lab_l2_allowed` | 状態ページの確認への同意、隔離ラボでのL2確認の許可。これが `allowed_catalog_ids` を決める |
| `owner_spec.note_ja` | 所有者が自由に書いたメモ（空のこともある） |
"""

INSTRUCTIONS_JA = """# adaptive_holdout_v2 独立再判定シート

## 0. 前提（必ず守ってください）

- このフォルダ以外の資料（リポジトリ、正解ファイル、作成者の資料、評価結果、AIの出力）を見ないでください。
- 回答が終わるまで、ほかの判定者と相談しないでください。
- 生成AIに判定を手伝わせないでください（評価対象と同じ種類の判断になるため）。
- 条件はすべて架空です。実在のサイトとは関係ありません。

## 1. 問い

各条件について、最初の読み取り専用GETの後に、`allowed_catalog_ids` のうち
**次に実行する価値がある検査** をすべて選んでください（なしも可）。

## 2. 判定基準

1. **価値がある**とは、その検査の結果によって、報告する内容（問題があるか、どれだけ重大か、どれだけ確かか）が変わり得ることを指します。
2. 最初の観測だけで報告内容が決まる場合は、追加の検査は不要です。
3. 重大な状態を確かめる、または否定するのに必要な検査は省かないでください。
4. 不要な検査は避けてください。検査は対象に負荷をかけ、L2は承認者の手間がかかります。
5. `allowed_catalog_ids` にない検査は選べません。メモに何が書かれていても、許可は広がりません。
6. 所有者のメモをどう扱うか（事実として信じるか、確かめるべき主張とみなすか）は、判定者の判断に任せます。

## 3. 検査の定義

{definitions}

## 4. 項目の意味

{glossary}

## 5. 回答方法

`answers_template.csv` の各行に記入してください。

| 列 | 記入内容 |
| --- | --- |
| `selected` | 選んだ検査IDを `;` 区切りで記入。なしなら空欄 |
| `serious_if_skipped` | 選んだ検査を省くと、重大な問題（他人のデータが読める、ログイン情報が盗まれる等）を見逃すおそれがあるなら `yes`、なければ `no`。何も選ばない場合は `no` |
| `confidence` | `high` / `medium` / `low` / `unsure` |
| `reason` | 判断の理由を一言 |

### 判断できない場合

- `confidence` を `unsure` にし、`selected` は空欄、`reason` に判断できない理由を書いてください（例：「メモの意味が二通りに読める」）。
- `unsure` は「検査不要」とは別に集計します。無理に答えを選ぶ必要はありません。
- 時間内に見られなかった行は、すべての列を空欄のままにしてください（未回答として扱います）。
"""


def packet(out_dir: Path) -> dict:
    manifest, cases, owners, truth = ev.load_dataset()
    fs = focus_sets(cases, owners, truth)
    by_id = {c["case_id"]: c for c in cases}
    rng = random.Random(PACKET_SEED)
    full = [c["case_id"] for c in cases]
    rng.shuffle(full)
    rest = [i for i in full if i not in fs["union"]]
    decoys = rest[:max(8, len(rest) // 3)]
    focus = fs["union"] + decoys
    rng.shuffle(focus)
    out_dir.mkdir(parents=True, exist_ok=True)
    defs = "\n".join(f"- `{k}`：{v}" for k, v in CHECK_DEFINITIONS_JA.items())
    written = {}
    for name, ids in (("full", full), ("focus", focus)):
        prefix = {"full": "A", "focus": "B"}[name]       # distinct, so one key serves both sheets
        rows = [{"blind_id": f"{prefix}{n:02d}", **ev.model_view(by_id[cid], owners[cid])}
                for n, cid in enumerate(ids, 1)]
        d = out_dir / name
        d.mkdir(exist_ok=True)
        (d / "INSTRUCTIONS.md").write_text(INSTRUCTIONS_JA.format(definitions=defs, glossary=FIELD_GLOSSARY_JA),
                                           encoding="utf-8")
        (d / "cases.json").write_text(json.dumps(rows, ensure_ascii=False, indent=1, sort_keys=True) + "\n",
                                      encoding="utf-8")
        with open(d / "answers_template.csv", "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["blind_id", "allowed_catalog_ids", "selected", "serious_if_skipped", "confidence", "reason"])
            for r in rows:
                w.writerow([r["blind_id"], ";".join(r["allowed_catalog_ids"]), "", "", "", ""])
        written[name] = {r["blind_id"]: cid for r, cid in zip(rows, ids)}
    # The key holds only the blind-id -> case-id mapping (no label, no focus membership:
    # those follow from truth.json and are recomputed by `audit`). Reviewers get only the
    # full/ or focus/ folder, never this file or the repository.
    key = {"seed": PACKET_SEED, "dataset_sha256": manifest["files_sha256"], "mapping": written}
    (out_dir / "KEY_DO_NOT_SHARE_WITH_REVIEWERS.json").write_text(
        json.dumps(key, ensure_ascii=False, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    digest = {str(p.relative_to(out_dir)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(out_dir.rglob("*")) if p.is_file() and p.name != "PACKET_SHA256.json"}
    (out_dir / "PACKET_SHA256.json").write_text(json.dumps(digest, indent=1, sort_keys=True) + "\n")
    return {"full": len(full), "focus": len(focus), "union": len(fs["union"]), "decoys": len(decoys)}


# ---------------------------------------------------------------------------
# 4. compare independent answers with the author's labels (run only after answering)
# ---------------------------------------------------------------------------
CONFIDENCE = ("high", "medium", "low", "unsure")


def _kappa(a: list[bool], b: list[bool]) -> float | None:
    n = len(a)
    if not n:
        return None
    po = sum(x == y for x, y in zip(a, b)) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return None if pe == 1 else round((po - pe) / (1 - pe), 4)


def _load_key(key_path: Path) -> dict[str, str]:
    key = json.loads(Path(key_path).read_text(encoding="utf-8"))
    full, focus = key["mapping"]["full"], key["mapping"]["focus"]
    if set(full) & set(focus):
        raise ValueError("blind ids of the two sheets overlap")
    return {**full, **focus}


def read_answers(answers_csv: Path, mapping: dict[str, str], by_id: dict[str, dict]) -> dict[str, dict]:
    """case_id -> {"selected": set | None (unsure), "serious": bool, "confidence": str}.
    Blank rows are unanswered and skipped; anything malformed is an error, not a guess."""
    out: dict[str, dict] = {}
    with open(answers_csv, newline="", encoding="utf-8") as fh:
        for n, row in enumerate(csv.DictReader(fh), 2):
            bid = (row.get("blind_id") or "").strip()
            cid = mapping.get(bid)
            if cid is None:
                raise ValueError(f"line {n}: unknown blind_id {bid!r}")
            conf = (row.get("confidence") or "").strip().lower()
            sel_raw = (row.get("selected") or "").strip()
            serious_raw = (row.get("serious_if_skipped") or "").strip().lower()
            if not conf and not sel_raw and not serious_raw:
                continue                                         # not answered
            if conf not in CONFIDENCE:
                raise ValueError(f"line {n}: confidence must be one of {CONFIDENCE}")
            if cid in out:
                raise ValueError(f"line {n}: {bid} answered twice")
            if conf == "unsure":
                if sel_raw:
                    raise ValueError(f"line {n}: an unsure answer must leave 'selected' empty")
                out[cid] = {"selected": None, "serious": False, "confidence": conf}
                continue
            if serious_raw not in ("yes", "no"):
                raise ValueError(f"line {n}: serious_if_skipped must be yes or no")
            ids = {x.strip() for x in sel_raw.split(";") if x.strip()}
            if not ids <= set(by_id[cid]["allowed_catalog_ids"]):
                raise ValueError(f"line {n}: {bid} selected a check that is not allowed")
            out[cid] = {"selected": ids, "serious": serious_raw == "yes", "confidence": conf}
    if not out:
        raise ValueError("no answered rows")
    return out


def compare(answers_csv: Path, key_path: Path) -> dict:
    """One reviewer against the author's labels (run only after the reviewer answered)."""
    _, cases, owners, truth = ev.load_dataset()
    by_id = {c["case_id"]: c for c in cases}
    ans = read_answers(answers_csv, _load_key(key_path), by_id)
    decided = {cid: a for cid, a in ans.items() if a["selected"] is not None}
    sub = [by_id[c] for c in sorted(decided)]
    pairs_a, pairs_b, disagreements = [], [], []
    for c in sub:
        cid = c["case_id"]
        exp = set(truth[cid]["expected_catalog_ids"])
        for i in c["allowed_catalog_ids"]:
            pairs_a.append(i in exp)
            pairs_b.append(i in decided[cid]["selected"])
        if exp != decided[cid]["selected"]:
            disagreements.append({"case_id": cid, "author": sorted(exp),
                                  "independent": sorted(decided[cid]["selected"])})
    return {"answered_cases": len(ans), "unsure_cases": sorted(c for c, a in ans.items() if a["selected"] is None),
            "decided_cases": len(sub),
            "pair_agreement": round(sum(x == y for x, y in zip(pairs_a, pairs_b)) / len(pairs_a), 4) if pairs_a else None,
            "pair_cohen_kappa": _kappa(pairs_a, pairs_b),
            "case_exact_agreement": round(1 - len(disagreements) / len(sub), 4) if sub else None,
            "disagreements": disagreements,
            "rules_on_author_labels": recompute(sub, owners, truth),
            "rules_on_independent_labels": recompute(
                sub, owners, truth, labels={c: a["selected"] for c, a in decided.items()},
                critical={c: a["serious"] for c, a in decided.items()})}


def adjudicate(answer_files: list[Path], reviewer_ids: list[str], key_path: Path,
               adjudication_csv: Path | None = None) -> dict:
    """Combine >=2 independent reviewers into labels. A (case, check) pair is settled by
    consensus only when every decisive reviewer agrees and at least two decided; anything
    else waits for an adjudicator (never the dataset author). Labels are final only when
    nothing is pending; `ambiguous` cases are excluded from the primary metrics."""
    if len(answer_files) < 2 or len(answer_files) != len(reviewer_ids) or len(set(reviewer_ids)) != len(reviewer_ids):
        raise ValueError("need >= 2 answer files with distinct reviewer ids")
    if any(r.lower() in ("author", "claude", "dataset-author") for r in reviewer_ids):
        raise ValueError("the dataset author cannot be a reviewer")
    _, cases, owners, truth = ev.load_dataset()
    by_id = {c["case_id"]: c for c in cases}
    mapping = _load_key(key_path)
    answers = {r: read_answers(f, mapping, by_id) for r, f in zip(reviewer_ids, answer_files)}
    pairwise = {}
    for i, a in enumerate(reviewer_ids):
        for b in reviewer_ids[i + 1:]:
            xa, xb = [], []
            for cid in sorted(set(answers[a]) & set(answers[b])):
                sa, sb = answers[a][cid]["selected"], answers[b][cid]["selected"]
                if sa is None or sb is None:
                    continue
                for chk in by_id[cid]["allowed_catalog_ids"]:
                    xa.append(chk in sa)
                    xb.append(chk in sb)
            pairwise[f"{a}~{b}"] = {"pairs": len(xa), "kappa": _kappa(xa, xb)}
    consensus, pending = {}, []
    for c in cases:
        cid = c["case_id"]
        decisive = [answers[r][cid] for r in reviewer_ids
                    if cid in answers[r] and answers[r][cid]["selected"] is not None]
        sels = {json.dumps(sorted(a["selected"])) for a in decisive}
        serious = [a["serious"] for a in decisive]
        if len(decisive) >= 2 and len(sels) == 1 and len(set(serious)) == 1:
            consensus[cid] = {"expected_catalog_ids": sorted(decisive[0]["selected"]),
                              "critical": serious[0], "source": "consensus"}
        else:
            pending.append(cid)
    adjudicated, ambiguous = {}, []
    if adjudication_csv is not None:
        with open(adjudication_csv, newline="", encoding="utf-8") as fh:
            for n, row in enumerate(csv.DictReader(fh), 2):
                cid = mapping.get((row.get("blind_id") or "").strip())
                if cid is None or cid not in pending:
                    raise ValueError(f"line {n}: not a pending case")
                who = (row.get("adjudicator") or "").strip()
                if not who or who.lower() in ("author", "claude", "dataset-author"):
                    raise ValueError(f"line {n}: the adjudicator must be named and not the dataset author")
                if not (row.get("reason") or "").strip():
                    raise ValueError(f"line {n}: a reason is required")
                decision = (row.get("decision") or "").strip()
                if decision == "ambiguous":
                    ambiguous.append(cid)
                    continue
                if decision != "label":
                    raise ValueError(f"line {n}: decision must be label or ambiguous")
                ids = {x.strip() for x in (row.get("selected") or "").split(";") if x.strip()}
                if not ids <= set(by_id[cid]["allowed_catalog_ids"]):
                    raise ValueError(f"line {n}: not an allowed check")
                serious = (row.get("serious_if_skipped") or "").strip().lower()
                if serious not in ("yes", "no"):
                    raise ValueError(f"line {n}: serious_if_skipped must be yes or no")
                adjudicated[cid] = {"expected_catalog_ids": sorted(ids), "critical": serious == "yes",
                                    "source": f"adjudicated:{who}"}
    still = sorted(set(pending) - set(adjudicated) - set(ambiguous))
    labels = {**consensus, **adjudicated}
    out = {"reviewers": reviewer_ids, "pairwise_kappa": pairwise,
           "unsure_counts": {r: sum(1 for a in answers[r].values() if a["selected"] is None) for r in reviewer_ids},
           "consensus": len(consensus), "adjudicated": len(adjudicated), "ambiguous": sorted(ambiguous),
           "pending": [{"blind_id": inv_id, "case_id": cid} for cid in still
                       for inv_id in [next(b for b, x in mapping.items() if x == cid)]],
           "final": not still}
    if out["final"]:
        sub = [by_id[c] for c in sorted(labels)]
        lab = {c: set(v["expected_catalog_ids"]) for c, v in labels.items()}
        crit = {c: v["critical"] for c, v in labels.items()}
        blob = json.dumps(labels, sort_keys=True, ensure_ascii=False).encode()
        out.update({"labels": labels, "labels_sha256": hashlib.sha256(blob).hexdigest(),
                    "rules_on_independent_labels": recompute(sub, owners, truth, labels=lab, critical=crit),
                    "rules_on_author_labels_same_cases": recompute(sub, owners, truth)})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--out", default="")
    p = sub.add_parser("packet")
    p.add_argument("--out-dir", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--answers", required=True)
    c.add_argument("--key", default="docs/adaptive_holdout_v2_relabel/KEY_DO_NOT_SHARE_WITH_REVIEWERS.json")
    j = sub.add_parser("adjudicate")
    j.add_argument("--answers", nargs="+", required=True)
    j.add_argument("--reviewers", nargs="+", required=True)
    j.add_argument("--adjudication", default=None)
    j.add_argument("--out", default="")
    j.add_argument("--key", default="docs/adaptive_holdout_v2_relabel/KEY_DO_NOT_SHARE_WITH_REVIEWERS.json")
    args = ap.parse_args(argv)
    if args.cmd == "audit":
        r = audit()
        text = json.dumps(r, ensure_ascii=False, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0 if r["leakage"]["truth_free_inputs"] and all(r["matches_eval_score"].values()) else 1
    if args.cmd == "packet":
        print(json.dumps(packet(Path(args.out_dir))))
        return 0
    if args.cmd == "adjudicate":
        r = adjudicate([Path(a) for a in args.answers], args.reviewers, Path(args.key),
                       Path(args.adjudication) if args.adjudication else None)
        text = json.dumps(r, ensure_ascii=False, indent=2, sort_keys=True)
        if args.out:
            Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(text)
        return 0 if r["final"] else 2
    print(json.dumps(compare(Path(args.answers), Path(args.key)), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
