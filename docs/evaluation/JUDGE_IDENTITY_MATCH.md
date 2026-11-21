# 判定器の変更：Vulnix が測った事実で「別アカウントが B の記録を読めた」とする（案2）

2026-11-22。[FAILURE_ANALYSIS.md](FAILURE_ANALYSIS.md) の案2を実装しました。応答本文の自己申告（`caller_account`・`Check`・`established`）ではなく、Vulnix 自身が測った事実だけで「成立」を決めます。

外部 API への送信、課金、実サイトへの通信は、いずれも0件です（`compare` の遮断機能が数えた、ループバック以外への接続の試みは0件）。費用は $0 です。

## 1. 新しい条件

場所は `aegis/evidence.py` の `owner_record_read_by_other_account(result)` です。ラボの固定の IDOR 検査の Worker の結果（`aegis/workers/reproduction_probe.py` の `run_lab_check`）から、次の**すべて**がそろうときだけ真になります。

| 条件 | 何で確かめるか |
| --- | --- |
| Worker が A として送った | `request_path` が `/api/accounts/B/secret`、`request_headers` が **ちょうど** `{"X-Test-Account": "acct_A"}`。この値は Worker のコードの固定値（`CHECKS["idor"]`）で、対象が選ぶことはできません。 |
| 同じ Worker の実行で、B 本人の対照が成立した | `control_status` 200、`control_verified` が `True`、`control_response` が B 本人の記録（既存の `reproduction_verdict` と同じ検査） |
| A の応答を最後まで読んだ | `status` 200、`response_truncated` が `False`（フラグのない古い結果は「読めていない」とみなします） |
| B の記録の識別子が**両方**ある | 対照の資源 ID **と** 機密マーカーの両方。片方だけでは足りません。不成立の規則と同じ正規化（大文字・小文字、HTML の実体参照、% エンコード、JSON のエスケープ、JavaScript の `\uXXXX`）の後に探し、**識別子として独立して**現れること（`res_b_0012`・`xres_b_001`・`..._PROVEN_EXAMPLE` は一致としません） |
| 別の資源・A 自身の資源ではない | JSON：両方の識別子を持つ最小のオブジェクトで、ID の欄（`id`・`resource_id`・`record_id`。大文字・小文字と `_` を区別しない）が B の資源 ID だけを指し、そのオブジェクト・その中・それを囲むオブジェクトの所有者の欄（キーに `owner` を含む）がすべて B を指す。HTML・テキスト（構造を読めない）：応答に `acct_A` がどこにもない。加えて、既存の `own_resource`（本人の資源）でもない。 |

base64 などで包み直した記録は一致しません（判断不能のまま）。復号を判定に含めると「どの形なら B の記録か」の判断が判定器に入り込むためです。

判定器（`aegis/diagnosis_judge.py`）の順番：

1. 所有者の仕様が「公開」→ `contradicted`（`intended_public`）
2. 対照の失敗 → `inconclusive`（`control_failed`）
3. 再現の成立（`reproduction_verdict` が `proven`）→ 仕様で決める（下）
4. **新規：** 200、本人の資源ではない、`owner_record_match` が真 → 仕様で決める（下）
5. 401・403・404 → `denied`、本人の資源 → `own_resource_only`、B の記録がない拒否 → `owner_record_absent`、それ以外 → `unrecognised_answer`（いずれも変更なし）

「仕様で決める」：認証必須 → `supported`（`cross_account_read`）、公開 → `contradicted`（`intended_public`）、仕様なし・未指定 → `needs_spec`（`spec_missing`）。4 は 200 で識別子が両方あるときだけ働くので、5 の否定の規則とは重なりません（優先順位は変わりません）。

観測の項目に `owner_record_match`（`true`／`false`）を加え、画面の文言を `web/src/lib/labels.ts` に加えました。規則の名前は既存の `cross_account_read` のままです。どちらの根拠で成立したかは、同じ観測の `reproduction`（`proven` か否か）と `owner_record_match` で区別できます。

## 2. 判定器だけに入れ、所見の「実証成功」には広げない理由

- **所見の「実証成功」（`reproduction_verdict` の `proven`）は、これまでどおり**「Worker 自身の判定が `proven`」「応答が決まった形」**に加えて、新しい条件（`owner_record_read_by_other_account`）も満たす**ときだけです。つまり、実証成功の条件は判定器の「成立」の条件より常に強く、**判定器より弱い検査で所見が実証成功になることはありません**（`tests/test_judge_identity_match.py` の `test_proven_always_implies_the_measured_match`）。フラグのない古い結果だけは、これまでどおり「抜粋から辞書として読めた」ことを全体を読めた根拠とします。
- 新しい条件だけで成立した場合、判定器は仮説を `supported`（所見の候補）にしますが、所見は「実証成功」になりません。実証成功は、診断ループの外（評価の L2 再検証、修正確認の `not_reproduced`）でも使われる、製品の外向きの主張です。広げるには、サンドボックスで動く Worker の判定も同じ条件に変える必要があり、影響範囲が大きくなります。
- この条件は holdout v3 の結果を見て作ったもので、偏りのない推定がまだありません（§4）。実証成功に広げるかどうかは、新しい未見のセットで確かめた後、別の変更として独立したレビューを受けて決めます。

## 3. 回帰テスト

`tests/test_judge_identity_match.py`（判定器・`reproduction_verdict`・ループバックの実際のラボ Worker）。

- 成立にならない紛らわしい例：マーカーだけ（文書の文・HTML の文）、資源 ID だけ、伏せ字のマーカー、A 自身の資源が B の ID を引用（ID の欄あり・なし・封筒・HTML）、別の資源 ID とマーカー、長い ID・接頭辞付きの ID・長いマーカー・接頭辞付きのマーカー、所有者の欄が別人、識別子を欄に分割、別々の項目に分かれた識別子、数値の ID の欄、base64 の記録、対照の不成立・対照の中身の不一致、Worker が切った本文・フラグのない結果、B 本人の要求・ヘッダーなし・空・余分なヘッダー・小文字の `acct_a`・別の経路。
- 成立になる例：`{"data": {...}}` の封筒、結果の一覧の中の B の記録、camelCase のキー、JSON エスケープ（文字列のまま・解析後）、HTML の表、HTML の実体参照と大文字、% エンコード、「呼び出し元=B」と書いた B の記録（holdout-030）、自己申告の形。仕様が公開・未指定・なしのときは、それぞれ `intended_public`・`spec_missing`。

既存のテストで期待値を変えたのは、案2 が意図して変える次の3か所だけです（どれも正解のラベルは「成立」）。

- `tests/test_diagnosis_judge_owner_record.py`：B の記録を「呼び出し元=B」で返す応答（`OWNER`）と、封筒に入った B の記録（`b_record_nested`）は、`unrecognised_answer` から `supported`（`cross_account_read`）に変わります。`b_record_nested` は他アカウントの紛らわしい例の一覧から外し、専用のテストにしました（切れた本文なら判断不能のまま、を追加）。認証なしの検査では、これまでどおり紛らわしい例として確かめます。
- `tests/evaluation/test_development_cases.py`：holdout-030 は `inconclusive` から `supported` に変わります。
- `tests/evaluation/test_holdout_set.py` の `test_the_judge_is_the_frozen_one`：v3 の記録（[HOLDOUT_V3.md](HOLDOUT_V3.md) §1 の SHA-256）はそのまま残っていることを確かめ、**現在の判定器のファイルは下の §5 の表と一致すること**を確かめるように変えました。判定器を記録なしに変えると、これまでどおり失敗します。

## 4. 結果（判定器を変えた後に、それぞれ1回だけ実行）

コマンド：`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation compare --set holdout_v3 --name comparison_holdout_v3_identity_match.json`（`--set holdout_v2` も同様）。既存の `comparison_holdout_v3.json`・`comparison_holdout_v2.json` は上書きしていません。ARTEX は Python の代役、モデルはローカルの台本です（実モデルではありません）。外部への接続の試み 0、`checks_failed` は空、終了コード 0。

他アカウントの読み取り（30件）。fixed_rule と local_model は同じ値です。

| セット | 時点 | 正解 | 誤検知 | 誤った決定 | 保留が妥当 | 保留（脆弱性あり） | TP / FP / FN / TN | Precision | Recall | 修正の確認（正解/実行） |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v3 | 前 | 6 | 0 | 0 | 5 | 9 | 1 / 0 / 9 / 20 | 1.0 | 0.1 | 1/1 |
| v3 | 後 | 14 | 0 | 0 | 5 | 1 | 7 / 0 / 3 / 20 | 1.0 | 0.7 | 4/5 |
| v2 | 前 | 17 | 0 | 0 | 4 | 3 | 5 / 0 / 6 / 19 | 1.0 | 0.4545 | 3/3 |
| v2 | 後 | 18 | 0 | 0 | 4 | 2 | 6 / 0 / 5 / 19 | 1.0 | 0.5455 | 3/3 |

- v3 で変わったケース：011（一覧）・016（HTML の表）・018（封筒）・023（camelCase）・026（JSON エスケープ）・029（サーバーが途中で切った JSON。Worker は最後まで読めている）が `supported`、008・020（仕様なし）が `needs_spec`。v2 では 013（入れ子の B の記録）が `supported`。
- v3 の修正の確認で1件（023）が正解にならないのは、修正後の日本語の JSON 拒否を不成立の規則（案1）が読めず、判断不能になるためです（「修正済み」と誤って確定したわけではありません）。
- 認証なしの露出の正解（v3 23、v2 23）は変わりません。

出力の SHA-256：`comparison_holdout_v3_identity_match.json` `3af7ee30af843fb9c2a2a89de1a353eac206a302e5b01d2b7ddda148ca4d9574`、`comparison_holdout_v2_identity_match.json` `b91bed5e4b37ed258adc444c711c96394cf5d9093e1ea1f3914d3787cc8797ad`。

**この数字は、新しい判定器の偏りのない推定ではありません。** 案2 の条件は holdout v3 の結果（どの形の成立を見逃したか）を見て設計しました。v2 も以前の判定器の調整に使っています。偏りのない推定には、**この判定器を固定した後に作る、新しい未見のセット**が必要です（まだ作っていません）。作るときは、HOLDOUT_V3.md と同じく、作成前に下の §5 の SHA-256 を固定し、作成時には判定器を実行しないでください。

## 5. 固定した判定器（次の未見セット用。独立したセキュリティレビューの修正を含む）

| ファイル | SHA-256 |
| --- | --- |
| `aegis/diagnosis_judge.py` | `7f477a97f9b65c86267fd2f66ff1d213f72c02548db5d094b3ce61371e7c8830` |
| `aegis/evidence.py` | `0ac25b893d16159bb923c7f272450be0e9486b034247b2f4d1346e36e74386f1` |
| `aegis/workers/reproduction_probe.py` | `2602c97f5ba5e682ffc0254d96cecb65554d30c4518b126fc60fc5e12a90075d` |
| `aegis/diagnosis_loop.py` | `d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5` |
| `aegis/adaptive_plan_runner.py` | `1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1` |

Worker（`reproduction_probe.py`）・診断ループ・計画の実行器は変えていません。

## 6. 制約・未解決

- 機密マーカーは、B の記録だけが持つ秘密の値として扱います。ラボではマーカーが固定の文字列なので、マーカーと資源 ID の両方をたまたま書いた文書（構造のない HTML・テキストで、`acct_A` を含まないもの）は成立になりえます。実サイトでは、対照で得る値が秘密であることが前提です。
- HTML・テキストでは構造を読めないため、「A 自身の資源ではない」は「`acct_A` を含まない」でしか確かめていません。
- 所有者の欄が B 以外を指す、ID の欄が数値、など判断に迷う形は、すべて判断不能（成立にしない）側に倒しています。
- 人のラベル確認（署名）は、v2・v3 とも未了です。

## 独立したセキュリティレビューで直した点

レビューで、誤検知（脆弱でないのに「成立」）につながる形が見つかりました。次のように締めました。

| 指摘 | 例 | 修正 |
| --- | --- | --- |
| （重要）所有者の欄がオブジェクトや一覧だと照合されない | `"owner": {"id": "acct_A"}`、`"owners": ["acct_A"]` | 所有者の欄は、中身のすべての文字列が B を指す場合だけ認めます（数値や別の名前が1つでもあれば不可） |
| （重要）JSON を文字列として埋め込むと、構造の照合を素通りする | `{"data": "<B の記録の JSON 文字列>"}` | 記録そのものが、資源 ID と目印の両方を**欄の値として丸ごと**持つ場合だけ認めます（文字列の中、文章の中、URL の中、別々の一覧の項目に分かれている場合は不可） |
| `\x` エスケープで acct_A を隠す | `acct\x5fA` | `\xHH` も元に戻して照合します |

これらの形は、すべて回帰テスト `TestReviewFalsePositives` で確かめています。締めたあとの結果は、v3 が正解14・誤検知0・誤った確定0・再現率 0.7、v2 が正解18・誤検知0で、どちらも変わっていません。「両方の識別子が URL の中にあるだけ」の形は、成立から外し、判断不能にしました。
