# 3つ目の未見30ケース（holdout v3）：固定した判定器の最終推定

2026-11-22 作成。[JUDGE_OWNER_RECORD.md](JUDGE_OWNER_RECORD.md) の判定器（PR #107）は、holdout v1 と v2 を見ながら調整しました。そのため v1・v2 の数字は、この判定器の偏りのない推定になりません。このセットは、**判定器を固定した後に作り、作成時には判定器を一度も実行していない**、最終推定用のケースです。

## 1. 固定した判定器（the frozen judge）

次の SHA-256 は、v3 のケースを作る前に記録しました。この評価の間、これらのファイルは変えません。

| ファイル | SHA-256 |
| --- | --- |
| `aegis/diagnosis_judge.py` | `8aae15f94b5d71537867de505209b982432f02e5528af248faf9d7fdc254ebea` |
| `aegis/workers/reproduction_probe.py` | `2602c97f5ba5e682ffc0254d96cecb65554d30c4518b126fc60fc5e12a90075d` |
| `aegis/diagnosis_loop.py` | `d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5` |
| `aegis/adaptive_plan_runner.py` | `1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1` |

## 2. 作成時点の記録（holdout v3 のファイル）

次の SHA-256 は、**3つのファイルを作った直後、固定した判定器をこのケースに一度も実行していない時点**（`--set holdout_v3` の配線より前）で記録しました。後でファイルを変えると一致しなくなります（`tests/evaluation/test_holdout_set.py` で確かめます）。

| ファイル | SHA-256 |
| --- | --- |
| `tests/evaluation/fixtures/holdout_v3_cases.json` | `64993b16549348c173f04154d60b3989ea3e3bc99be7264f7a96c56e4448d3f6` |
| `tests/evaluation/fixtures/holdout_v3_truth.json` | `32b1f16b7671b2839ec53f70926acddf63a952242d9f293b38263dae842adddc` |
| `tests/evaluation/fixtures/holdout_v3_lab.py` | `e326eb1aee6606def8aea4c7269c392edf0162c47a5376c6c78e8d9486b8e324` |

作成前に確かめたのはラボ単体の応答（状態コード、本文の長さ、Retry-After、Link ヘッダー）だけで、ループバックの GET を urllib で送って確認しました。判定器・Worker・計画器は通していません。

## 3. 作り方

- v1・v2 と同じ形式です。振る舞い（`holdout_v3_cases.json`）と正解（`holdout_v3_truth.json`）を別のファイルにし、ラボ（`holdout_v3_lab.py`）は正解のファイルを読みません。B 本人の対照（`owner_record`）と資源の URL は v1・v2 と同じです。
- ケース ID は `holdout-v3-001`〜`030` です。固定の乱数（種 20261123）で並べ替えているので、ID から分類や正解は読み取れません。
- 正解は [LABEL_REVIEW_SHEET.md](LABEL_REVIEW_SHEET.md) の判定の基準だけで付けました。「判定器が証明できること」ではなく、「サーバーが実際に A・匿名に何を返し、所有者が何を求めているか」です。修正（fix）は、修正後に A がまだ B の機密の記録を受け取るかどうかです。
- v1・v2 になかった応答の形を入れています。

| 分類 | 件数 | 内容 |
| --- | --- | --- |
| 修正後の再確認（fix_recheck） | 5 | 新しい形の成立（data 封筒、results 一覧に B の記録、camelCase、HTML の表、通常の記録）と、修正後の 404・日本語 JSON 拒否（200）・ドイツ語の拒否ページ（200）＝fixed、HTML の表・data 封筒で B の記録が残る＝not_fixed |
| 認可・IDOR（authorization_idor） | 2 | JSON エスケープ（`\u005f`）した B の記録、base64 で包んだ B の記録 |
| 紛らわしい例（near_miss） | 5 | 封筒に入った A 自身の記録、B の ID と名前だけで機密の値は伏せ字、件数だけ、機密の欄の名前を挙げる拒否、要求の経路と B の名前を繰り返す拒否 |
| 偽装応答・200 の拒否（decoy_200） | 6 | 日本語のログイン画面（パスワード欄あり）、ドイツ語の拒否ページ、日本語の JSON 拒否、フランス語のマジックリンクのログイン（パスワード欄なし）、入れ子の JSON 拒否、/login へ移る空の SPA |
| 途中で切れた本文（truncated_body） | 3 | B の識別子の後で切れた JSON、識別子の前で切れた B の記録（メモと残高だけ）、途中で切れた JSON 拒否 |
| 回数制限（rate_limited） | 2 | A が常に 429（Retry-After）、匿名が常に 429・A が常に 503（Retry-After） |
| 所有者の対照なし（no_owner_control） | 2 | B 本人が 401（期限切れ）で A は B の記録を受け取る、B 本人がログイン画面で A は日本語の拒否 |
| 公開・認証必須の仕様（auth_public_spec） | 2 | 所有者の仕様が公開で匿名と A が B の記録を受け取る、認証必須で匿名が封筒入りの B の記録を受け取り A は 403 |
| 仕様不足・検査不要（spec_missing_or_no_check） | 3 | 仕様なしで A が B の記録、読み手の指定がない規則で A が B の記録、Link ヘッダーなし |

### 実行前に記録した、判断が分かれうるラベル

結果を見る前に、作成者が迷った点を書いておきます（ラベルはこのまま変えていません）。

- **伏せ字の B の記録**（`redacted_b`）：A は B の資源 ID と名前を受け取るが、機密の値は `[REDACTED]`。基準の「B の機密の記録を受け取る」に当たらないとして **不成立** にしました。資源の存在や所有者名の露出も問題とみる立場なら、成立になりえます。
- **base64 の B の記録**（`b64_b`）：本文を復号すれば B の記録だと分かるので、**成立・保留は不適切**（withhold_ok=false）にしました。
- **識別子の前で切れた B の記録**（`trunc_b_noid`）：ケースの定義ではサーバーは B の記録を送っていますが、届いた部分から B のものとは決められないので、**成立・保留が妥当**にしました。
- **途中で切れた拒否**（`trunc_refusal`）：`{"error": "forbid` は人が読めば拒否と分かるので、**不成立・保留は不適切**にしました。
- **回数制限・対照なし**：v1 の holdout-007・029 と同じ扱い（A は B の記録を受け取らない＝不成立、受け取る＝成立、どちらも保留が妥当）にしました。

### ケースごとのラベル（人の確認用）

| ケース | 分類 | 匿名 | A（検査用） | B（所有者） | 所有者の規則 | 他アカウント | 認証なし | 修正 | 保留が妥当 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| holdout-v3-001 | near_miss | 401 not_authenticated | 200 redacted_b | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-002 | decoy_200 | 401 not_authenticated | 200 html_denied_de | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-003 | decoy_200 | 200 json_refusal_ja | 200 json_refusal_ja | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-004 | near_miss | 401 not_authenticated | 200 count_only | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-005 | decoy_200 | 401 not_authenticated | 200 json_refusal_nested | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-006 | near_miss | 401 not_authenticated | 200 own_record_env | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-007 | auth_public_spec | 200 env_data_b | 403 forbidden | 200 owner_record | authentication_required | 不成立 | 成立 | – | いいえ |
| holdout-v3-008 | spec_missing_or_no_check | 401 not_authenticated | 200 camel_b | 200 owner_record | unspecified | 仕様が必要 | 不成立 | – | いいえ |
| holdout-v3-009 | truncated_body | 401 not_authenticated | 200 trunc_b_noid | 200 owner_record | authentication_required | 成立 | 不成立 | – | はい |
| holdout-v3-010 | rate_limited | 401 not_authenticated | 429 rate_limited | 200 owner_record | authentication_required | 不成立 | 不成立 | – | はい |
| holdout-v3-011 | fix_recheck | 401 not_authenticated | 200 env_list_b | 200 owner_record | authentication_required | 成立 | 不成立 | not_fixed | いいえ |
| holdout-v3-012 | near_miss | 200 echo_refusal | 200 echo_refusal | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-013 | fix_recheck | 401 not_authenticated | 200 cross_record | 200 owner_record | authentication_required | 成立 | 不成立 | fixed | いいえ |
| holdout-v3-014 | near_miss | 401 not_authenticated | 200 field_hint | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-015 | authorization_idor | 401 not_authenticated | 200 b64_b | 200 owner_record | authentication_required | 成立 | 不成立 | – | いいえ |
| holdout-v3-016 | fix_recheck | 200 b_html_table | 200 b_html_table | 200 owner_record | authentication_required | 成立 | 成立 | not_fixed | いいえ |
| holdout-v3-017 | rate_limited | 429 rate_limited | 503 html_unavailable | 200 owner_record | authentication_required | 不成立 | 不成立 | – | はい |
| holdout-v3-018 | fix_recheck | 401 not_authenticated | 200 env_data_b | 200 owner_record | authentication_required | 成立 | 不成立 | fixed | いいえ |
| holdout-v3-019 | spec_missing_or_no_check | 401 not_authenticated | 200 cross_record | 200 owner_record | authentication_required | 範囲外 | 範囲外 | – | いいえ |
| holdout-v3-020 | spec_missing_or_no_check | 401 not_authenticated | 200 env_data_b | 200 owner_record | なし | 仕様が必要 | 不成立 | – | いいえ |
| holdout-v3-021 | decoy_200 | 200 html_login_ja | 200 html_login_ja | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-022 | no_owner_control | 401 not_authenticated | 200 cross_record | 401 session_expired | authentication_required | 成立 | 不成立 | – | はい |
| holdout-v3-023 | fix_recheck | 401 not_authenticated | 200 camel_b | 200 owner_record | authentication_required | 成立 | 不成立 | fixed | いいえ |
| holdout-v3-024 | decoy_200 | 200 html_spa_redirect | 200 html_spa_redirect | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-025 | auth_public_spec | 200 cross_record | 200 cross_record | 200 owner_record | public | 不成立 | 不成立 | – | いいえ |
| holdout-v3-026 | authorization_idor | 401 not_authenticated | 200 escaped_b | 200 owner_record | authentication_required | 成立 | 不成立 | – | いいえ |
| holdout-v3-027 | decoy_200 | 200 html_login_fr | 200 html_login_fr | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-028 | truncated_body | 401 not_authenticated | 200 trunc_refusal | 200 owner_record | authentication_required | 不成立 | 不成立 | – | いいえ |
| holdout-v3-029 | truncated_body | 401 not_authenticated | 200 trunc_b_ids | 200 owner_record | authentication_required | 成立 | 不成立 | – | いいえ |
| holdout-v3-030 | no_owner_control | 401 not_authenticated | 200 json_refusal_ja | 200 html_login_ja | authentication_required | 不成立 | 不成立 | – | はい |

## 4. 署名の分離

- 人の署名のひな形は [label_signoff_holdout_v3.template.json](label_signoff_holdout_v3.template.json)（`label_set: "holdout_v3"`）です。署名の本体（`label_signoff_holdout_v3.json`）は人が作ります。AI は作りません。
- `require_label_signoff(..., label_set="holdout_v3")` は、`holdout_v3_truth.json` の SHA-256 と `label_set: "holdout_v3"` の両方がそろわないと開きません。v1・v2 の署名では開かず、v3 の署名でも v1・v2 は開きません（`tests/evaluation/test_holdout_set.py` の `TestHoldoutV3Set`）。
- `holdout-v3-` のケースは、実行器（`aegis/evaluation/evaluation_runner.py` の `run_case`）で必ず `holdout_v3` の署名に結び付きます。判定器・Worker・診断ループ・計画の実行器（§1 の4ファイル）は変えていません。

## 5. 結果（固定した判定器、1回だけ実行）

`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation compare --set holdout_v3` を1回だけ実行しました（終了コード 0）。出力は [comparison_holdout_v3.json](comparison_holdout_v3.json)（SHA-256 `69f9fe90a8f5bf42c6a117d470246139fc80d89e41c9e168c4c70d1133031088`）です。

- `external_connection_attempts`：**0**（ループバック以外への接続の試み）。`checks_failed`：`[]`。`artex`：`Python stand-in`。`model`：ローカルの台本（実モデルではありません）。外部 API・課金・実サイトへの通信はありません。
- 下の表の値は `summary` からそのまま写しました。

| 項目（`summary` のキー） | fixed_l1 | fixed_rule | local_model |
| --- | --- | --- | --- |
| 正解 `correct`（他アカウントの読み取り、30件中） | 1 | 6 | 6 |
| 正解率 `accuracy` / 95% CI `accuracy_ci95` | 0.0333 / [0.0059, 0.1667] | 0.2 / [0.0951, 0.3731] | 0.2 / [0.0951, 0.3731] |
| 誤検知 `outcomes.false_positive` | 0 | 0 | 0 |
| 誤った決定（不成立・仕様が必要の誤り）`outcomes.wrong_decision` | 0 | 0 | 0 |
| 保留が妥当 `outcomes.withheld_appropriately` | 5 | 5 | 5 |
| 脆弱性の保留（見逃し）`outcomes.withheld_missing_vuln` | 10 | 9 | 9 |
| その他の保留 `outcomes.withheld_otherwise` | 14 | 10 | 10 |
| 正解＋保留が妥当 `appropriate_or_correct` / 95% CI | 6 / [0.0951, 0.3731] | 11 / [0.2187, 0.5449] | 11 / [0.2187, 0.5449] |
| tp / fp / fn / tn | 0 / 0 / 10 / 20 | 1 / 0 / 9 / 20 | 1 / 0 / 9 / 20 |
| 適合率 `precision` / 95% CI | null / null | 1.0 / [0.2065, 1.0] | 1.0 / [0.2065, 1.0] |
| 再現率 `recall` / 95% CI | 0.0 / [0.0, 0.2775] | 0.1 / [0.0179, 0.4042] | 0.1 / [0.0179, 0.4042] |
| 誤検知率の 95% CI `false_positive_ci95` | [0.0, 0.1611] | [0.0, 0.1611] | [0.0, 0.1611] |
| 特異度 `specificity` / 95% CI | 1.0 / [0.8389, 1.0] | 1.0 / [0.8389, 1.0] | 1.0 / [0.8389, 1.0] |
| 仕様が必要の正解 `needs_spec_correct` | 0 | 0 | 0 |
| 認証なしの露出：正解 `unauth_correct` | 1 | 23 | 23 |
| 認証なしの露出：誤検知 `unauth_false_positive` | 0 | 0 | 0 |
| 認証なしの露出：`unauth_outcomes` | correct 1, false_positive 0, wrong_decision 0, withheld_appropriately 0, withheld_missing_vuln 2, withheld_otherwise 27 | correct 23, false_positive 0, wrong_decision 0, withheld_appropriately 0, withheld_missing_vuln 2, withheld_otherwise 5 | correct 23, false_positive 0, wrong_decision 0, withheld_appropriately 0, withheld_missing_vuln 2, withheld_otherwise 5 |
| 修正の再確認：実行 `fix_checks` / 正解 `fix_correct` | 0 / 0 | 1 / 1 | 1 / 1 |
| 実行した検査 `checks_run` / 不要 `unnecessary_checks` / 禁止 `forbidden_checks_run` | 0 / 0 / 0 | 59 / 0 / 0 | 59 / 0 / 0 |
| Worker の起動 `worker_launches` | 30 | 90 | 90 |
| 対象への GET `target_gets` | 30 | 115 | 115 |
| 計画器の呼び出し `planner_calls` | 0 | 59 | 59 |
| 費用 `model_cost_usd` / 予約 `reserved_usd` | $0.0 / $0.0 | $0.0 / $0.0 | $0.0 / $0.0 |
| 経過秒 `elapsed_s` | 1.828 | 8.861 | 8.931 |

注意：`summary.per_category` の `correct` は、このファイルでは件数の2倍になっています（`aegis/evaluation/metrics.py` の `score` が、正解のときに `cat["correct"]` を2回数えるため。v2 の `comparison_holdout_v2.json` も同じです）。上の表は `per_category` を使っていません。評価コードは直していません。

### ケースごとの結果

| ケース | 分類 | 正解（他アカウント） | fixed_rule | local_model | 規則（fixed_rule の l2_idor） | 正解（認証なし） | fixed_rule |
| --- | --- | --- | --- | --- | --- | --- | --- |
| holdout-v3-001 | near_miss | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-002 | decoy_200 | contradicted | contradicted | contradicted | owner_record_absent | contradicted | contradicted |
| holdout-v3-003 | decoy_200 | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | inconclusive |
| holdout-v3-004 | near_miss | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-005 | decoy_200 | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-006 | near_miss | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-007 | auth_public_spec | contradicted | contradicted | contradicted | denied | supported | inconclusive |
| holdout-v3-008 | spec_missing_or_no_check | needs_spec | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-009 | truncated_body | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-010 | rate_limited | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-011 | fix_recheck | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-012 | near_miss | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | inconclusive |
| holdout-v3-013 | fix_recheck | supported | supported | supported | cross_account_read | contradicted | contradicted |
| holdout-v3-014 | near_miss | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-015 | authorization_idor | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-016 | fix_recheck | supported | inconclusive | inconclusive | unrecognised_answer | supported | inconclusive |
| holdout-v3-017 | rate_limited | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | inconclusive |
| holdout-v3-018 | fix_recheck | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-019 | spec_missing_or_no_check | not_applicable | not_applicable | not_applicable | – | not_applicable | not_applicable |
| holdout-v3-020 | spec_missing_or_no_check | needs_spec | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-021 | decoy_200 | contradicted | contradicted | contradicted | owner_record_absent | contradicted | contradicted |
| holdout-v3-022 | no_owner_control | supported | inconclusive | inconclusive | control_failed | contradicted | contradicted |
| holdout-v3-023 | fix_recheck | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-024 | decoy_200 | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | inconclusive |
| holdout-v3-025 | auth_public_spec | contradicted | contradicted | contradicted | intended_public | contradicted | contradicted |
| holdout-v3-026 | authorization_idor | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-027 | decoy_200 | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | inconclusive |
| holdout-v3-028 | truncated_body | contradicted | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-029 | truncated_body | supported | inconclusive | inconclusive | unrecognised_answer | contradicted | contradicted |
| holdout-v3-030 | no_owner_control | contradicted | inconclusive | inconclusive | control_failed | contradicted | contradicted |

### 読み取れること（推定として）

- **誤検知は 0 件、誤った決定も 0 件**でした（fixed_rule・local_model とも）。ただし誤検知率の 95% CI は [0.0, 0.1611] で、20件の陰性からは「0 に近い」以上のことは言えません。
- **成立の見逃しが多い**：正解が成立の 10 件のうち、成立にできたのは holdout-v3-013（v1・v2 と同じ形の記録）の 1 件だけです。data 封筒・results 一覧・camelCase・JSON エスケープ・base64・HTML の表・途中で切れた本文（識別子あり）は、いずれも「判断不能（`unrecognised_answer`）」でした。成立の規則が、応答本文の決まった形（`established` と `caller_account`）を必要とするためです（[FAILURE_ANALYSIS.md](FAILURE_ANALYSIS.md) 案2 の範囲。この評価では判定器を変えていません）。
- **「不成立」の規則（`owner_record_absent`）が働いたのは**、ドイツ語の拒否ページ（002）、日本語のログイン画面（021）、修正後のドイツ語の拒否ページ（013 の修正確認）だけでした。日本語の JSON 拒否（003）、入れ子の JSON 拒否（005）、フランス語のログイン（027）、SPA（024）、切れた拒否（028）、紛らわしい例の 5 件は、判断不能のままでした。
- 修正の再確認は、最初に成立にできた 1 件（013）でしか走らず、その 1 件は正解（fixed）でした。残り 4 件の修正ケースは評価できていません。
- fixed_rule と local_model（ARTEX の代役＋台本モデル）は、どのケースでも同じ結果でした。検査の選び方の差はなく、差は判定器の側にあります。
- この判定器の偏りのない推定（v3）は、他アカウントの読み取りで **正解 6/30（20%、95% CI 9.5〜37.3%）、正解＋保留が妥当 11/30（36.7%、95% CI 21.9〜54.5%）、誤検知 0** です。v2 の 17/30 より大きく下がっており、v1・v2 の数字は v1・v2 に見られる応答の形に合わせた結果だったと考えられます。

### 結果を見た後の「ラベルに疑問あり（人のレビュー用）」

ラベルと判定器は変えていません。次の点は、人のレビューで判断してください。

| ケース | 現在のラベル | 疑問 |
| --- | --- | --- |
| holdout-v3-001（`redacted_b`） | 不成立・保留は不適切 | 機密の値は伏せ字だが、B の資源 ID と所有者名は A に返る。存在・所有者の露出を問題とみるなら成立。実行前から迷っていた点（§3）。 |
| holdout-v3-015（`b64_b`） | 成立・保留は不適切 | 復号すれば B の記録。ただし「どの検査者が集められる証拠でも決められない」かどうかは、復号を検査者の役割に含めるかで変わる。含めないなら保留が妥当。 |
| holdout-v3-028（`trunc_refusal`） | 不成立・保留は不適切 | 本文が途中で切れているので、「本文を最後まで読めていない」として保留を妥当とみる立場もある。 |
| holdout-v3-009（`trunc_b_noid`） | 成立・保留が妥当 | ケースの定義では B の記録だが、届いた本文（メモと残高だけ）からは判断できない。成立とすること自体に異論がありうる。 |

これらを変えても、誤検知 0 と、成立の見逃しが多いという結論は変わりません（001・028 を保留が妥当にしても正解は増えず、保留が妥当が増えるだけです）。

## 6. 制約

- **作成者（この AI のセッション）は、判定器の設計と v1・v2 の結果を知った上でこのケースを作りました。** 判定器の規則に有利にも不利にもしないよう、正解は判定の基準だけで付け、作成時には判定器を実行していません。それでも独立した作成者の代わりにはなりません。
- **第2の判定者による独立のラベルはありません。人のラベル確認（署名）も未了です。** 署名がない間、実行器はこのセットでのループバック以外への送信を拒否します。
- ARTEX は Python の代役、モデルはローカルの台本です。実モデル・実 ARTEX での結果ではありません。
- 30件なので、95% CI は広いままです。

## 採点コードの修正（結果の数値は変わりません）

`aegis/evaluation/metrics.py` が、カテゴリ別（`per_category`）の正解数を二重に数えていました。この不具合を直し、v3 と v2 の比較ファイルを作り直しました。

- カテゴリ別の正解数は、ケースの数と一致するようになりました。
- 全体の正解数、誤検知、確定の誤り、再現率などの数値は変わっていません。
- 回帰テスト：`tests/evaluation/test_metrics_per_category.py`
- 1つ目のセットの `comparison.json`（PR #98 のもの）には、古いカテゴリ別の値が残っています。
