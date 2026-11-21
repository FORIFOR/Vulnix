# 診断ループの画面設計

2026-11-21。PR #97 の診断ループ（観測 → 仮説 → 検査 → 再判断）を、利用者が追えるように表示するための設計です。**この PR は設計だけです。** 画面とバックエンドの実装は、次の PR で行います。

## 1. 原則

- **表示するのは、監査済みの事実と、決まった選択肢の理由だけです。** 次のものは表示しません。
  - モデルの推論文
  - ARTEX の intent 本文
  - advisory の自由文
  - モデルのトークン数

  画面の文はすべて、決まった ID（仮説の種類、検査 ID、契約の理由、判定規則、終了理由）を、下の表で日本語に置き換えたものです。
- **根拠には、必ず監査の記録を付けます。** 観測と判定には、監査ハッシュの先頭12文字と時刻を出します。そこから、既存の証拠表示（`EvidencePanel`）へ移れるようにします。
- **既存の白基調を保ちます。** `Card`、`Pill`、`VerdictBadge`（`src/components/ui.tsx`）と、zinc の配色、`dark:` の対を使います。状態は色だけで表さず、必ず文字を添えます（`src/lib/labels.ts` の方針と同じ）。
- **表示する場面**：診断ループは、登録済みのローカル検証ラボでだけ動きます。実サイトの診断では、この区画を表示しません。

## 2. 置き場所

- 評価の画面（`app/assessments/[id]/page.tsx` → `AssessmentTabs`）で、`ArtexPlanPanel` のすぐ下に、新しい `DiagnosisLoopPanel` を置きます。
- L2 の承認は、既存の `ApprovalCard`（`AgentActivity.tsx`）で行います。この区画からは、承認カードへのリンクだけを出し、承認ボタンを二重に置きません。

## 3. 画面の構成

```
┌ 診断ループ ─────────────────────────────── [ラボ専用] [世代 1] ┐
│ 状態: 確認中（2 / 3 手順）     次に必要なこと: ▶ L2 検査の承認    │
├──────────────────────────────────────────────────┤
│ ① 確認しようとしていること                                        │
│   H1 認証なしで、アカウント資源が読めるか          [反証（不成立）] │
│   H2 別のアカウントが、B の資源を読めるか          [確認待ち]       │
├──────────────────────────────────────────────────┤
│ ② 手順の記録（新しい順）                                          │
│   S2 別アカウントでの読み取り検査（L2・承認: approver-human）       │
│      なぜ: H2 を確かめるため（根拠 E2: ルートがこの資源へリンク）     │
│      観測: 応答 200 / 所有者 B の対照 成立 / 再現 成立               │
│      判定: 支持（成立） — 所有者が「認証必須」とした資源を、          │
│            別のアカウントが読めた                                  │
│      証拠: 監査 3f9c0a12be47… 2026-11-21 10:42   [証拠を見る]       │
│   S1 認証なしの GET（L1）                                         │
│      なぜ: H1 を確かめるため（根拠 E2）                              │
│      観測: 応答 403                                                │
│      判定: 反証（不成立） — 認証なしの要求は拒否された              │
├──────────────────────────────────────────────────┤
│ ③ 修正の前後（修正後の確認があるときだけ）                         │
│   検査: 別アカウントでの読み取り                                    │
│   修正前（世代 1）  支持  応答 200・再現 成立   監査 3f9c…        │
│   修正後（世代 2）  反証  応答 403              監査 a71e…        │
│   結果: 改善を確認（所見 f_idor: 実証成功 → 再現せず）              │
└──────────────────────────────────────────────────┘
```

利用者が求めた6つの情報と、表示する場所の対応は次のとおりです。

| 求められた情報 | 表示する場所 | データの出所（監査済み） |
| --- | --- | --- |
| AI が何を確認しようとしているか | ① の各仮説、② の「検査」 | 仮説の `claim` と `target_ref`、手順の `catalog_id` |
| なぜその検査が必要か | ② の「なぜ」 | 手順の `reason`（契約の3択）と `evidence_refs` が指す観測。モデルの文ではありません。 |
| 実際に何を観測したか | ② の「観測」 | 検査の観測の `attrs`（`check_attrs` の固定項目）と、`result` の監査ハッシュ |
| 支持・反証・判断不能の理由 | ② の「判定」、① のバッジ | `diagnosis.judged` の `rule`（固定判定器の規則） |
| 次に必要な検査・利用者の操作 | 見出しの「次に必要なこと」 | 検査できる仮説、承認待ちの項目、`needs_spec`、計画の終了理由（下の表） |
| 修正前後の証拠と改善結果 | ③ | 世代1と世代2の同じ検査の判定・観測・監査ハッシュ、所見の verdict の変化 |

## 4. 表示の文言（固定の対応表）

これらは `src/lib/labels.ts` に追加し、`labels.test.mjs` で、すべての ID に文言があることを確かめます。

### 仮説の種類（claim）

| ID | 文言 |
| --- | --- |
| `unauthenticated_exposure` | 認証なしで、アカウント資源が読めるか |
| `other_account_read` | 別のアカウントが、B の資源を読めるか |

### 仮説の状態（state）

| ID | 文言 | 色 |
| --- | --- | --- |
| `open` | 確認待ち | zinc |
| `supported` | 支持（成立） | red（問題あり） |
| `contradicted` | 反証（不成立） | emerald |
| `inconclusive` | 判断不能 | amber |
| `needs_spec` | 所有者の仕様が必要 | sky |

修正確認の仮説（`purpose=confirm_fix`）の場合、`contradicted` は「改善を確認」、`supported` は「改善されていない」と表示します。

### 検査（catalog_id）

既存のカタログの `label` を使います。

| ID | 文言 |
| --- | --- |
| `l1_http_probe` | 認証なしの GET（L1） |
| `l2_idor` | 別アカウントでの読み取り検査（L2） |

### 選んだ理由（契約の reason）

| ID | 文言 |
| --- | --- |
| `test_hypothesis` | {仮説} を確かめるため |
| `collect_missing_evidence` | {仮説} の判断に足りない観測を集めるため |
| `confirm_fix` | 修正の後に、同じ検査で確かめ直すため |

文言の後に、「根拠」として引用した観測を並べます。例：「E2：ルートがこの資源へリンクしている（L1）」。

### 判定の理由（judge の rule）

| rule | 文言 |
| --- | --- |
| `cross_account_read` | 所有者が「認証必須」とした資源を、別のアカウントが読めた |
| `spec_missing` | 読めたが、誰が読めるべきかの仕様がない |
| `intended_public` | 所有者の仕様で「公開」とされている |
| `denied` | 別のアカウントの要求は拒否された（401・403・404） |
| `own_resource_only` | 返ったのは、要求した本人の資源だった |
| `control_failed` | 所有者本人でも資源を確認できず、比べられなかった |
| `unrecognised_answer` | 応答の形が想定と違い、判断できなかった |
| `denied_without_auth` | 認証なしの要求は拒否された |
| `answered_without_auth_unverified` | 認証なしで 200 が返ったが、保護された資源そのものかは確かめられない |
| `check_not_relevant` | この検査では、この仮説を判断できない |

### 次に必要なこと

| 状況 | 文言 | 操作 |
| --- | --- | --- |
| L2 の項目が承認待ち | L2 検査の承認が必要です | 承認カードへ移動（承認できるのは依頼者以外） |
| `needs_spec` | 資源を誰が読めるべきか、所有者の仕様を入力してください | 仕様の入力（認証必須／公開） |
| `control_failed` | 所有者のアカウントで資源を確認できるよう、検証用アカウントを準備してください | なし（案内のみ） |
| 終了：`all_settled` | すべての仮説を判断しました | 所見を見る |
| 終了：`no_progress`・`stalled` | 新しい検査で状況が変わりませんでした。条件を見直してください | なし |
| 終了：`max_steps`・`max_planner_rounds`・`deadline`・`planner_cost_limit` | 上限に達したため止めました | 再開 |
| 終了：`paused` | 一時停止中のため止めました | 再開 |
| 終了：`stopped_or_reset` | 停止またはリセットにより、この周回の結果は採用していません | なし |
| 終了：`requester_authority_revoked` | 依頼者の権限が失効したため、結果は採用していません | なし |
| 終了：`l2_approval_missing` | L2 の承認がないため止めました | 承認カードへ移動 |
| 終了：`FAILED`（`audit_failed`・`evidence_mismatch`・`evidence_missing`・`check_mismatch`・`state_from_another_run` など） | 記録の整合を確かめられなかったため、結果は採用していません | 監査ログを見る |
| 支持された仮説がある | 修正したら、修正後の確認を開始してください | 修正後の確認 |

## 5. バックエンドとのデータの受け渡し（次の PR で実装）

- **取得の経路**：`GET /api/assessments/{id}/diagnosis`、および SSE の `diagnosis.updated` です。
  - 組織の API なので、`_get_org` → `_dispatch` を通します。`tests/test_tenancy.py` に、他の組織のメンバーが読めないことを確かめるテストを追加します。
- **返す内容**（`DiagnosisView`）：

```json
{
  "lab_only": true,
  "generation": 2,
  "plan": {"state": "COMPLETED", "reason": "all_settled", "steps_used": 2, "steps_max": 3},
  "hypotheses": [{"id": "H2", "claim": "other_account_read", "target_ref": "T2", "state": "supported",
                   "purpose": "diagnose", "generation": 1}],
  "steps": [{"step_id": "S2", "catalog_id": "l2_idor", "level": "L2", "hypothesis_id": "H2",
              "reason": "test_hypothesis", "evidence_refs": ["E2"], "approved_by": "approver-human",
              "observation": {"evidence_id": "E5", "attrs": {"status": 200, "control": "established",
                                                             "reproduction": "proven"}},
              "judgement": {"from": "open", "to": "supported", "rule": "cross_account_read"},
              "result_audit_hash": "3f9c…", "judged_audit_hash": "…", "at": "2026-11-21T10:42:00Z"}],
  "evidence": [{"evidence_id": "E2", "kind": "account_resource_link", "source": "l1", "target_ref": "T2",
                 "generation": 1, "audit_hash": "…"}],
  "fix_comparison": [{"catalog_id": "l2_idor", "before": {"generation": 1, "to": "supported", "audit": "…"},
                       "after": {"generation": 2, "to": "contradicted", "audit": "…"},
                       "finding": {"id": "f_idor", "from": "proven", "to": "not_reproduced"}}],
  "next": {"kind": "approve_l2", "item_id": "…"}
}
```

- **組み立て方**：`DiagnosisState`、`AdaptivePlan.executed`、監査の `diagnosis.judged` と `result` から組み立てます。
  - 監査の鎖が検証できない場合は、`steps` を空にし、「記録を確かめられません」と表示します。
  - 推測で表示を埋めることはしません。
- **含めないもの**：ARTEX の intent 本文、advisory の自由文、モデルの推論やトークン、検査結果の生の本文。生の本文は、既存の秘密情報のマスキングを経た `EvidencePanel` で、利用者が開いたときだけ表示します。

## 6. 操作のしやすさとアクセシビリティ

- **新しい判定の通知**：新しい判定が届いたら、`role="status"` の `aria-live="polite"` で一文だけ知らせます。例：「S2 の判定：支持（成立）」。
- **状態の伝え方**：状態のバッジは、文字と色の両方で伝えます。手順は `<ol>` に並べ、各手順の詳細は `<details>` で開閉できるようにします。キーボードで操作でき、`focus-visible` の枠線を出します。
- **狭い画面**：③ の修正前後の比較は、2列の表から縦に積む形に切り替えます。

## 7. 次の PR で行う作業と、そのテスト

1. バックエンド：`diagnosis_view()` と経路、組織の分離のテスト。
2. `labels.ts` の対応表と `labels.test.mjs`。上のすべての ID に文言があり、色だけで表していないことを確かめます。
3. `DiagnosisLoopPanel` と、`assessmentEvents.applyEvent` での `diagnosis.updated` の取り込み。
4. ラボでの通し確認：観測 → 反証 → 再計画 → 支持 → 修正後の確認を画面に表示し、スクリーンショットで確かめます。
