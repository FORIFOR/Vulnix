# 診断ループ（観測 → 仮説 → 検査 → 再判断）

2026-11-21。[DIAGNOSIS_LOOP_PLAN.md](DIAGNOSIS_LOOP_PLAN.md) の第2・3段階と、第4段階の模擬比較の実装記録です。

このループは、登録済みのローカル検証ラボだけで動きます。実サイトでは、診断対象の一覧が空になり、計画の要求も拒否します。

## 何が変わったか

| 部品 | 場所 | 役割 |
| --- | --- | --- |
| 観測と仮説 | `aegis/diagnosis_state.py` | 観測（出所・対象・世代・監査ハッシュ・step ID）と、仮説（`open`・`supported`・`contradicted`・`inconclusive`・`needs_spec`）を、所見と別に持ちます。 |
| 固定判定器 | `aegis/diagnosis_judge.py` | 検査結果が仮説にとって何を意味するかを、固定の規則で決めます。仮説の状態を変える `Verdict` は、このモジュールでしか作れません。 |
| 計画の契約 | `aegis/plan_contract.py` | 計画者の答えを `{hypothesis_id, catalog_id, target_ref, evidence_refs, reason}` だけで受け付けます。 |
| ARTEX との受け渡し | `aegis/artex_bridge.py` | `diagnosis_observations()`：計画者向けの表示を ARTEX の事実（facts）にします。`reconstruct_contract()`：意図（intent）の summary にある JSON を契約として読みます。 |
| 再計画ループ | `aegis/adaptive_plan_runner.py`・`adaptive_plan_state.py` | PR #93 の状態機械に、仮説を軸にした周回を足しました（`diagnosis=`）。 |
| ラボでの観測 | `aegis/diagnosis_loop.py` | 初期の L1 観測、所有者の仕様の記録、修正後の再確認の開始を行います。 |
| 実行 | `aegis/assessment.py` | 次の4点を変更しました。<br>・`plan_with_artex(diagnosis=…)`<br>・`diagnosis_targets()`<br>・項目ごとの証拠（`artex_item_evidence`）<br>・Worker の結果が戻る前に依頼者の権限が失効したときは、その結果を採用しません（PR #93 から移植） |

ARTEX の overlay（`integrations/artex/overlay/`）は変えていません。既存の `observations`（事実）と `intents[].summary` で受け渡します。

## 1周の流れ

1. **固定の提案器**（`propose_hypotheses`）が、観測から仮説を開きます。例：ラボのルートがアカウント資源（T2）へリンクしている場合、「T2 が認証なしで読める」と「T2 を別アカウントが読める」の2つを開きます。
2. **ARTEX への入力**：最新の観測と仮説を渡します。仮説には、支持・反証・判断不能にした証拠 ID と、世代が含まれます。
   - 渡すのは、ID と短い英単語だけです。
   - URL、本文、Cookie、監査ハッシュは渡しません。
3. **契約の検査**：ARTEX の答えを `plan_contract` で検査します。通った手順だけが計画項目になり、ProposalRouter → Gateway → 隔離 Worker で実行されます。
   - L2 は毎回、人の個別承認が必要です。依頼者本人は承認できません。
4. **Worker の結果を観測にする**：結果を `check` 観測として記録します。記録には次を結びつけます。
   - その手順の step ID
   - 監査済みの `result` ハッシュ
   - 検査 ID
5. **判定**：固定判定器が判定します。判定はまず `diagnosis.judged` として監査に書き、書けたときだけ状態に反映します。
6. 次の周回は、この結果を含んだ新しい入力で、もう一度計画します。

### 計画の契約で拒否するもの

- **型**
  - 各フィールドの型が違うもの。
  - 予期しないキーや、足りないキーがあるもの。
  - JSON の NaN を使ったもの。
- **ID**
  - 一覧にない仮説・検査・対象。
  - 仮説の対象と違う対象（`target_mismatch`）。
- **証拠**
  - 別の対象の証拠（`evidence_other_target`）。
  - 古い世代の証拠（`stale_evidence`）。
  - 重複した証拠や、9件以上の証拠。
- **仮説の状態**
  - 決着済みの仮説（`hypothesis_settled`）。
  - 所有者の仕様待ちの仮説（`hypothesis_waits_for_owner`）。
- **理由**
  - 決められた選択肢以外の理由。
  - 修正確認用でない仮説に `confirm_fix` を使ったもの（逆も拒否します）。
- **繰り返し**
  - 同じ検査・同じ対象を、もう一度求めるもの（`repeat`）。ただし、前回の実行より後に記録された証拠を引用していれば受け付けます。その証拠は、別の検査や所有者の仕様によるものに限ります。古い証拠の組み合わせを変えただけの場合や、その検査自身の結果だけの場合は、繰り返しとして拒否します。

### 固定判定器の規則

| 仮説 × 検査 | 結果 | 判定（規則） |
| --- | --- | --- |
| どちらの仮説でも | 所有者の仕様が「公開」 | 反証（`intended_public`） |
| 別アカウントの読み取り × `l2_idor` | 所有者本人の対照で、資源を確認できない | 判断不能（`control_failed`） |
| 〃 | 再現が成立し、仕様が「認証必須」 | 支持（`cross_account_read`） |
| 〃 | 再現が成立し、仕様がない | 仕様不足（`spec_missing`） |
| 〃 | 401・403・404 | 反証（`denied`） |
| 〃 | 200 だが、呼び出した本人の資源だった | 反証（`own_resource_only`） |
| 認証なしの公開 × `l1_http_probe` | 401・403・404 | 反証（`denied_without_auth`） |
| 〃 | 200 | 判断不能（`answered_without_auth_unverified`）。状態コードだけでは、保護された資源そのものが返ったとは言えないためです |

### 終わり方

| 理由 | 状態 |
| --- | --- |
| 検査できる仮説が残っていない | `COMPLETED / all_settled` |
| 仕様待ちの仮説だけが残った | `COMPLETED / needs_spec` |
| 仮説がない | `COMPLETED / no_hypothesis` |
| 受け付けられる新しい手順が出なかった | `COMPLETED / no_progress` |
| 状態を変えない手順が続いた | `EXPIRED / stalled` |
| 手順数・周回数・時間・費用の上限に達した | `EXPIRED` |
| 停止・リセット | `CANCELLED / stopped_or_reset`（この周回の結果は採用しません） |
| 依頼者の権限の失効 | `REJECTED / requester_authority_revoked`（Worker の結果も記録しません） |
| 監査の記録失敗・証拠の不一致 | `FAILED`（仮説は変わりません） |

### 修正後の確認

所有者が修正したら、`begin_fix_check` で次を行います。

1. 世代を進めます。これで、以前の証拠は新しい手順に使えなくなります。
2. L1 と所有者の仕様を、取り直します。
3. 支持された仮説ごとに、`confirm_fix` の仮説を新しく作ります。

計画者は `reason: confirm_fix` で同じ検査を選びます。元の仮説は「修正前に成り立っていた」記録として、`supported` のまま残します。

## 隔離認可ラボでの E2E（`tests/test_diagnosis_loop.py`）

`idor_vulnerable` のラボで、次の工程を通しています。すべて実際の Gateway と Worker を使います。

1. **観測**：ルートが T2 へリンクしていることを、固定の L1 で観測します。
2. **S1**：`l1_http_probe` で T2 を認証なしで GET すると、403 でした。「認証なしの公開」を**反証**します。
3. **再計画**：2周目の入力には、反証の結果（`contradicting: [E4]`）が入っています。
4. **S2**：`l2_idor` は人の承認を経て実行し、「別アカウントの読み取り」を**支持**します。所見 `f_idor` は `proven` になり、その証拠のハッシュは S2 の結果と一致します。
5. **修正**：ラボを `denied_403` に切り替え、世代 2 で `confirm_fix` を行います。承認は改めて取ります。結果は**反証**で、修正を確認できました。所見は `not_reproduced` になります。

異常系として、次も確かめています。
- 仕様不足、契約違反だけの応答、変化のない手順、手順数の上限
- L2 の承認がない場合と、依頼者本人による承認
- 緊急停止、Worker の実行中の権限失効、リセット
- 判定の監査の失敗と、証拠の偽装
- 実サイトでの拒否と、偽の判定の拒否

## 3方式の比較（同じラボ・同じ予算）

`scripts/bench_diagnosis_loop.py` を使います。条件は16件で、既存の14件に `own_resource_only` と `idor_spec_missing` を加えています。

- 正解表は `tests/fixtures/access_control_loop_truth.json` です。診断のコードは、この表を読みません。
- 予算は3方式で共通です。手順は3、計画の周回は5、時間は300秒です。

2026-11-21 のローカル実行の結果を `docs/diagnosis_loop_comparison_local.json` に保存しました。ARTEX は Python の代役で、モデルは台本どおりに答える代役です。

| 方式 | 正解 | 誤検知 | 見逃し | 未決 | 仕様不足を正しく報告 | 反証 | 対象への GET | 修正確認 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 固定 L1 のみ | 5/16 | 0 | 2 | 9 | 0 | 0 | 16 | ― |
| 固定ルール＋追加検査 | 14/16 | 0 | 0 | 2 | 1 | 15 | 48 | 2/2 |
| ARTEX 計画（代役のモデル） | 14/16 | 0 | 0 | 2 | 1 | 15 | 48 | 2/2 |

- **未決の2件**（`denied_404`・`idor_owner_missing`）：所有者本人の対照でも資源を確認できない条件です。安全側に「判断不能」として止めています。
- **固定ルールと ARTEX 計画の差**：検査の順序だけです。精度と GET 数は同じでした。この比較は配線と安全性を確かめるもので、**実モデルの価値は測っていません。**
- **実モデルでの比較**：有料のため、送信する要求の SHA と費用の上限を示し、所有者の承認を得てから行います。
- **CI**（`artex-real-planner`）：実 ARTEX overlay とローカルの模擬モデルで、同じ比較を実行します。あわせて、`TestRealArtexDiagnosisLoop` の実行を必須にしました（スキップすると失敗します）。

## まだ行っていないこと

- 実モデル（有料）による比較。所有者の承認が必要です。
- 実サイト（第5段階）。このループは実サイトでは動かず、L2 も実行しません。
- 画面での表示。今回は、バックエンドとテストだけです。
