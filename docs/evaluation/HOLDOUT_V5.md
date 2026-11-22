# 5つ目の未見40ケース（holdout v5）：v5 の凍結した判定器の評価用

2026-11-22 作成。[FROZEN_JUDGE_V5.md](FROZEN_JUDGE_V5.md) の判定器は、v1〜v4 を見ながら調整しました。このセットは、**判定器を凍結した後に作り、作成時には判定器・Worker・計画器・診断ループを一度も実行していない**、1回だけ評価するためのケースです。

**v1〜v4 は開発・回帰用のセットです。** v1〜v4 の数字は、v5 の判定器の偏りのない推定には使いません。**v5 は未見のセットです。** 人のラベル確認（署名）は未了です。

## 1. 凍結した判定器（FROZEN_JUDGE_V5.md から写し）

| ファイル | SHA-256 |
| --- | --- |
| `aegis/diagnosis_judge.py` | `a69d845ba9694d99bae4f32a88bb28ed680a511d2a4c00969bbc4bbcdc87771e` |
| `aegis/evidence.py` | `7aa81d124611c068bf42a33a817af47c53d0b1df86e162ac417f11d05699d0bb` |
| `aegis/workers/reproduction_probe.py` | `f01f3d28a77f8a67ada8dbb9e1a3a1bf8ef8d0b58f678cbca1133fef32a3a19a` |
| `aegis/diagnosis_loop.py` | `d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5` |
| `aegis/adaptive_plan_runner.py` | `1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1` |
| `aegis/evaluation/metrics.py` | `aa6020892ef26babbc91fada12ced6bee516e0cc6b1ba863e58a53d3fbf6dd9b` |
| `docs/evaluation/EVALUATION_PROTOCOL.md` | `98fbe21e553da3be6228cbb0fc7764164a9ec5967ffb0c9254e4cf9b504bb549` |

## 2. 作成時点の記録（holdout v5 のファイル）

2026-11-22。次の SHA-256 は、**3つのファイルを作った直後、凍結した判定器をこのケースに一度も実行していない時点**（`--set holdout_v5` の配線より前）で記録しました。後でファイルを変えると一致しなくなります（`tests/evaluation/test_holdout_set.py` の `TestHoldoutV5Set` で確かめます）。

| ファイル | SHA-256 |
| --- | --- |
| `tests/evaluation/fixtures/holdout_v5_cases.json` | `8ee7986a78331f3e9a3f2f3c365ebd7c30c423839025d12d4afa66b4d228dee7` |
| `tests/evaluation/fixtures/holdout_v5_truth.json` | `f775bc6e922526c8013dc66f07af1743e22044d3a55d1d00044531d4edf5272f` |
| `tests/evaluation/fixtures/holdout_v5_lab.py` | `869369d541bda44e0d04ff85c5f6b2702a47366e6a323b5ec68874c94abbf8e9` |

作成前に確かめたのは、ラボ単体の応答（状態コード、Link ヘッダー、修正後の切り替え、長い本文の長さと B の記録の位置）だけで、ループバックの GET を urllib で送って確認しました。判定器・Worker・計画器・診断ループは通していません。

## 3. 作り方

- v1〜v4 と同じ形式です。振る舞い（`holdout_v5_cases.json`）と正解（`holdout_v5_truth.json`）を別のファイルにし、ラボ（`holdout_v5_lab.py`）は正解のファイルを読みません。B 本人の対照（`owner_record`）と資源の URL は v1〜v4 と同じです。
- ケース ID は `holdout-v5-001`〜`040` です。固定の乱数（種 20261126）で並べ替えているので、ID から分類や正解は読み取れません。
- 正解は [LABEL_REVIEW_SHEET.md](LABEL_REVIEW_SHEET.md) の判定の基準だけで付けました。「判定器が証明できること」ではなく、「サーバーが実際に A・匿名に何を返し、所有者が何を求めているか」です。ケースごとの根拠は [holdout_v5_author_notes.md](holdout_v5_author_notes.md) にあります。
- v1〜v4 のケース・応答の形は使っていません。製品が実際に出会う API・Web の応答（OData、JSON:API の included、GraphQL の Relay 接続と部分的なデータ付きのエラー、HAL の一覧、NDJSON、data: URI、SOAP の fault、API の封筒、nginx の 429 など）から作りました。

| 分類 | 件数 | 内容 |
| --- | --- | --- |
| 認可・IDOR（authorization_idor） | 6 | OData のエンティティ、JSON:API の included、GraphQL の Relay 接続、B のアカウントの木の中に入れ子の記録、base64 の data: URI、「acct_A でサインイン中」と表示するページの B のカード |
| 修正後の再確認（fix_recheck） | 6 | 修正後に 404 problem+json・403 の OData エラー・GraphQL の部分的なデータ（A の viewer、secret は null）・値を伏せたカード ＝fixed、NDJSON に形式だけ変わった・GraphQL の部分的なデータに B の記録が残る ＝not_fixed |
| 紛らわしい例（near_miss） | 9 | OpenAPI の例（値はテンプレートの穴）、A の記録と関連する B の項目・以前の版、A への通知、所有者 A が深い入れ子の A の JSON:API、要求をこだまする拒否、A のサポート依頼の文面、base64 の A 自身の記録、A の一覧（絞り込みとカーソルに B）、埋め込み状態に A の記録と拒否された B |
| 偽装応答・200 の拒否（decoy_200） | 5 | GraphQL の日本語の拒否（部分的なデータ）、イタリア語の拒否ページ、フランス語の SOAP fault、中国語の OData エラー、success=false の API の封筒 |
| 長い本文（truncated_body） | 4 | 64 KB 超で B の記録が先頭、64 KB 超で B の記録が 65536 文字より後、64 KB 超で A の記録だけ、約 20 KB の HTML の中ほどに B の記録 |
| 公開・認証必須の仕様（auth_public_spec） | 3 | 公開の仕様で匿名と A が B のプロフィール、認証必須で匿名と A が B の記録、認証必須で匿名だけが B の記録（A は 404） |
| 仕様不足・検査不要（spec_missing_or_no_check） | 3 | 仕様なしで A が B の記録、読み手の指定がない規則で A は 404、Link ヘッダーなし |
| 所有者の対照なし（no_owner_control） | 2 | B 本人が 503 で A は B の記録、B 本人が 401（トークン期限切れ）で A は自分の記録 |
| 回数制限（rate_limited） | 2 | A が常に nginx の 429（Retry-After）、A が常に 200 の GraphQL RATE_LIMITED |

正例（他アカウントの読み取りが成立）は 17 件、不成立 21 件、仕様が必要 1 件、範囲外 1 件です。認証なしの露出の成立は 2 件です。保留が妥当は 6 件です。修正の確認は 6 件（fixed 4、not_fixed 2）です。

### 評価の前に記録した、判断が分かれうるラベル

- **base64 の data: URI の中の B の記録**（026）：デコードすれば B の記録全体なので、**成立・保留は不適切**にしました（v3・v4 と同じ考え方）。
- **「acct_A でサインイン中」のページに B のカード**（037）：A を名乗るのは閲覧者の表示で、記録は B のものなので**成立**にしました。
- **修正後に値だけ伏せたカード**（015）：B の ID と所有者はまだ見えますが、機密の値がないので **fixed** にしました（v3・v4 の伏せ字・所有関係だけの考え方）。
- **修正後の GraphQL の部分的なデータに B の記録が残る**（030）：エラーは別の欄だけを隠しているので **not_fixed** にしました。
- **65536 文字より後の B の記録**（025）：サーバーは B の記録を返していますが、検査が保持する範囲に現れないので、**成立・保留が妥当**にしました。v4 の 031 と同じく、2人目の判定者は「保留は妥当でない」とする可能性があります。
- **64 KB 超の A の記録だけの一覧**（039）：**不成立・保留が妥当**にしました（v4 の 030 と同じ考え方。同じく意見が分かれうる）。
- **B 本人が 401 で A は自分の記録**（016）：v4 の 011 と同じく、対照がないので**保留が妥当**にしました。A が受け取ったのは A 自身の記録なので「不成立」と決めてよい、とする立場もありえます。
- **200 の GraphQL RATE_LIMITED**（012）：状態コードは 200 でも回数制限なので、**不成立・保留が妥当**にしました。
- **要求をこだまする拒否**（006）：B の ID・所有者と欄の名前 `confidential_marker` を含みますが、値はないので**不成立**にしました。

## 4. 署名の分離

- 人の署名のひな形は [label_signoff_holdout_v5.template.json](label_signoff_holdout_v5.template.json)（`label_set: "holdout_v5"`）です。署名の本体（`label_signoff_holdout_v5.json`）は人が作ります。AI は作りません。
- `require_label_signoff(..., label_set="holdout_v5")` は、`holdout_v5_truth.json` の SHA-256 と `label_set: "holdout_v5"` の両方がそろわないと開きません。v1〜v4 の署名では開かず、v5 の署名でも v1〜v4 は開きません（`tests/evaluation/test_holdout_set.py` の `TestHoldoutV5Set`）。
- `holdout-v5-` のケースは、実行器（`aegis/evaluation/evaluation_runner.py` の `run_case`）で必ず `holdout_v5` の署名に結び付きます。別のセットの署名を指定すると、ラボ・Worker・判定器を起動する前に拒否します。正解のファイルは、署名の確認のためにハッシュを取るだけで、計画器・判定器には渡しません。
- 実行：`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation compare --set holdout_v5`（出力は `comparison_holdout_v5.json`）。**まだ実行していません。** 実行したら、出力の SHA-256 をこの文書に記録します（記録がないまま出力があると、テストが失敗します）。

## 5. 制約

- **作成者（この AI のセッション）は、v5 の判定器の設計と v1〜v4 の結果を知った上でこのケースを作りました。** 判定器の規則に有利にも不利にもしないよう、ケースは製品が実際に出会う応答の形から作り、正解は判定の基準だけで付けました。作成時には判定器を実行していません。それでも独立した作成者の代わりにはなりません。
- 2人目の判定者のラベルは、まだありません。**人のラベル確認（署名）は未了です。** 署名がない間、実行器はこのセットでのループバック以外への送信を拒否します。
- 40件なので、95% CI は広いままです。


## 独立した2人目の判定者によるラベル（評価の前に記録）

2人目の判定者は、作成者とは別のセッションです。作成者のラベル、作成者のメモ、この文書、判定器のコードを見ずに、ラベルを付けました。

- ラベル：`tests/evaluation/fixtures/holdout_v5_truth_independent.json`（SHA-256 `41698fdfe825a4f5b9747849aa69bbeb736c12b07b42882f5e9d61ffb316f7e6`）
- 判定の理由：`docs/evaluation/holdout_v5_independent_notes.md`

| 項目 | 一致 |
| --- | --- |
| 他アカウントの読み取り | 40/40 |
| 認証なしの露出 | 40/40 |
| 修正の結果 | 40/40 |
| 保留が妥当か | 37/40 |

「保留が妥当か」で食い違ったのは、016・025・039 です。作成者は「妥当」、2人目は「妥当でない」としました。

**採点には作成者のラベルをそのまま使います。** 人による確認と署名は、まだ行っていません。


## 結果：凍結した判定器で1回だけ評価（2026-11-22）

- 実行したコマンド：`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.run_model_evaluation compare --set holdout_v5`
- 外部への接続の試みは0件、`checks_failed` は空でした。
- 比較のために、**v4 の時点で凍結した判定器**（`claude/holdout-v4`、[FROZEN_JUDGE_V4.md](FROZEN_JUDGE_V4.md)）でも、同じ v5 を1回だけ評価しました（`comparison_holdout_v5_v4judge.json`）。

### 他アカウントの読み取り（40件、陽性17件）

固定ルールと、ARTEX＋台本モデルの結果は同じでした。

| 判定器 | 正解 | TP | FP | FN | TN | 適合率 | 再現率（95%CI） | 特異度 | 判断不能 | 誤った「安全」判定 | 正解率の95%CI |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| v4 で凍結した判定器 | 13 | 8 | 0 | 9 | 23 | 1.00 | 0.47（0.26〜0.69） | 1.00 | 27 | 0 | 0.20〜0.48 |
| **v5 で凍結した判定器** | **16** | **11** | **0** | **6** | **23** | **1.00** | **0.65（0.41〜0.83）** | 1.00 | 24 | **0** | 0.26〜0.55 |

### そのほかの指標

| 指標 | 結果 |
| --- | --- |
| 誤検知の95%CI | 0.00〜0.14 |
| 認証なしの露出 | 正解36、誤検知0 |
| 修正後の確認 | v5 の判定器で 4/5、v4 の判定器で 3/4 |
| Worker の起動回数 | v5 の判定器で128回、v4 の判定器で126回 |
| 費用 | $0 |

**特異度の読み方：** 判断不能も TN（真陰性）に数えています。負例23件のうち、実際に正しく判定できたのは5件でした。

### ケースごとの差分

ケースごとの差分は `holdout_v5_case_diff.json` にあります。

**変わった3件**（003・011・020）は、すべて「判断不能 → 成立」で、正解の方向への変化でした。

**見逃した6件**は、すべて判断不能のままです。「安全」と確定したものはありません。

| ケース | 理由 |
| --- | --- |
| 008、025 | B の記録が、保持する 64 KB より後ろにある |
| 010 | 所有者本人の対照がない（保留は妥当） |
| 026 | B の記録が base64 で包まれている（誤検知を防ぐために、意図して判定しない形） |
| 037 | ページに「acct_A としてサインイン中」とある（A を名乗る応答は拒否する規則による） |
| 015 | 修正後の確認 |

**この結果を見て、判定器は変えていません。** 改善する場合は、v5 を開発用に移し、新しい未見セットで評価し直します。

### 出力の SHA-256

| ファイル | SHA-256 |
| --- | --- |
| `comparison_holdout_v5.json` | `00b4f4445d0134846bfa197f3e0948b2b7395731bbd00ef82bb554fcbc180d02` |
| `comparison_holdout_v5_v4judge.json` | `6edd5bfa5bea6893bbf4439fe4705be335de90c1981a38635a99b7404fa6528d` |
| `holdout_v5_case_diff.json` | `24646f1b603eaffdef351b7b8e8296d6fc29ba88b1d205e8b9e460b4dfa683ff` |

- 1回だけの実行の記録：`comparison_holdout_v5.json`：`00b4f4445d0134846bfa197f3e0948b2b7395731bbd00ef82bb554fcbc180d02`
