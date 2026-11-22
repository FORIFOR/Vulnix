# v5 の評価のために凍結した判定器

2026-11-22。[V4_MISS_ANALYSIS.md](V4_MISS_ANALYSIS.md) の3つの改善を加えた判定器です。新しい未見セット v5 は、この表のファイルを凍結した**後**に作り、**1回だけ**評価します（v5 はまだ作っていません）。v5 の結果を見て、これらのファイルを1つでも変えた場合は、v5 を開発用に移し、新しい未見セットで評価し直します。`tests/evaluation/test_frozen_judge_v5.py` が、表とファイルの一致を確かめます。

## 凍結したファイル（SHA-256）

| ファイル | SHA-256 |
| --- | --- |
| `aegis/diagnosis_judge.py` | `a69d845ba9694d99bae4f32a88bb28ed680a511d2a4c00969bbc4bbcdc87771e` |
| `aegis/evidence.py` | `7aa81d124611c068bf42a33a817af47c53d0b1df86e162ac417f11d05699d0bb` |
| `aegis/workers/reproduction_probe.py` | `f01f3d28a77f8a67ada8dbb9e1a3a1bf8ef8d0b58f678cbca1133fef32a3a19a` |
| `aegis/diagnosis_loop.py` | `d973a752f8c744de6e466f8b822994c2887153f96d8186e8db7da51547f72de5` |
| `aegis/adaptive_plan_runner.py` | `1dca57a756dfadc1f1be94de3e5efb05a53217c8ba49e578767c5fe482c31bb1` |
| `aegis/evaluation/metrics.py` | `aa6020892ef26babbc91fada12ced6bee516e0cc6b1ba863e58a53d3fbf6dd9b` |
| `docs/evaluation/EVALUATION_PROTOCOL.md` | `98fbe21e553da3be6228cbb0fc7764164a9ec5967ffb0c9254e4cf9b504bb549` |

## v4 の凍結から変えたファイル

`aegis/diagnosis_judge.py`、`aegis/evidence.py`、`aegis/workers/reproduction_probe.py` の3つだけです。残りの4つは [FROZEN_JUDGE_V4.md](FROZEN_JUDGE_V4.md) と同じです。

v4 の凍結の記録は残しています。git の履歴は手元の検査では読めないため、`tests/evaluation/test_frozen_judge_v4.py` は次を確かめます。

- FROZEN_JUDGE_V4.md が7つのファイルを記録したまま残っている。
- 上の3つは v4 の記録と異なり、この文書に記録されている。
- 残りの4つは、v4 を評価したときのファイルとバイト単位で同じである。

## v4 から変えた規則

1. **標準的な API の封筒**（`aegis/evidence._owner_record_match`）
   - これまで：1つのオブジェクトが、資源 ID と目印の両方を欄の値として丸ごと持つ場合だけ、B の記録とみなしました。
   - v5：次の場合も、1つの記録とみなします。
     - オブジェクト自身の欄が B の資源 ID である。
     - そのオブジェクトから**辞書のキーだけをたどって**（途中に配列を挟まずに）届く子孫のオブジェクトが、目印を欄として丸ごと持つ。
   - 例：JSON:API の `data.attributes`、GraphQL のフィールドのオブジェクト、HAL の配列でない埋め込みオブジェクト。
   - ID の欄（`id`・`resource_id`・`record_id`）の確認を広げました。次のどこにある ID の欄も、B の資源だけを指す必要があります。
     - 記録そのもの
     - 記録からキーだけで届くすべてのオブジェクト（所有者のキーの下は除く。そこは所有者の確認が見ます）
     - 記録をキーだけで囲むオブジェクト
   - このため、`{"id": "res_a_001", "data": {B の記録}}` のような形は、v4 では成立でしたが、v5 では判断不能になります（締める方向の変更です）。配列の項目は、配列を持つオブジェクトと同じ記録とはみなしません。
   - 所有者の確認（欄の中・下・周りのすべての所有者の欄が、B だけを指す）は変えていません。
   - 次の形は引き続き一致しません。
     - 配列の項目、兄弟のオブジェクト、文字列、文章、URL、base64 に分かれた識別子
     - 子のオブジェクトが目印を持ち、親が ID を持たない形
2. **GraphQL のエラー**（`aegis/diagnosis_judge._json_refusal`）
   - `errors` の要素に、`code`・`message`・`detail` に加えて、`path`・`extensions`（スカラー値か、スカラー値の一覧・辞書）と `locations`（その一覧）も認めます。
   - 拒否の言葉を探すのは、`message`・`code`・`detail` と `extensions.code` だけです。
   - 最上位の `data` は、`null`・欠落・**すべての値が `null` のオブジェクト**（GraphQL で、どのフィールドも解決されなかった形。例 `{"node": null}`）の場合だけ認めます。それ以外の `data` がある場合は拒否ではありません。
   - 依頼の文面は「`data` は null か欠落」でした。すべての値が null の形を加えたのは、v4 の GraphQL のエラーがこの形（`{"data": {"node": null}, ...}`）だからです。データを1つも含まないため、B のデータを見落とす余地はありません。
3. **長い本文**（`aegis/workers/reproduction_probe.run_lab_check`）
   - ラボの IDOR 検査で、A の要求の本文を保持する上限を、4096文字から **65536文字**（`LAB_IDOR_EXCERPT`）に上げました。判定器側の写し `L2_EXCERPT` も 65536 です。
   - 読む上限 `MAX_BODY`（262144 バイト）は、UTF-8 で必ず65536文字以上になります（1文字は最大4バイト）。このため、`response_truncated` は「読んだ本文が上限を超えたか」で正しく決まります。
   - B 本人の対照、ほかのラボの検査、規則による L2 の検査は、4096文字のままです。

## 証拠の大きさの上限

- **Worker の出力**：A の本文は最大65536文字です。JSON に書き出すと、1文字が最大6バイトになります（制御文字の `\u0001`）。対照（4096文字以内）と固定の欄を含めても、Worker の出力は**約42万バイト以下**です。
  - 実行環境が保持する標準出力の上限は1,000,000バイト（`aegis/runtime.MAX_CAPTURE`）で、これを下回ります。
  - 上限を超えて切れた出力は JSON として読めないため、記録されません。
  - `tests/test_judge_api_envelopes.py` の `TestLongBodies` が、最悪の場合を確かめます。
  - 通常の ASCII の JSON の場合、出力は本文とほぼ同じ大きさ（64 KB 程度）です。
- **監査ログ**：`result` の記録が持つのは、出力の先頭280文字と、ハッシュの連鎖だけです。監査ログは大きくなりません。
- **評価の記録**：出力の全体（秘密値をマスクした後）は、発見事項の証拠（`content`）として、評価の状態に保存されます。ラボの IDOR 1回あたり、最大で約42万バイト増えます（v4 までは約3万バイト）。
- **診断ループ**：保存するのは、短い属性（`check_attrs`）と監査のハッシュだけです。

## 開発・回帰用のセット

次のセットは、判定器の調整に使いました。v5 の判定器の偏りのない推定には使いません。v4 は、この変更で開発用に移しました（v2・v3 と同じ扱い。[HOLDOUT_V4.md](HOLDOUT_V4.md) の末尾）。

| ファイル | SHA-256 |
| --- | --- |
| `tests/evaluation/fixtures/holdout_cases.json` | `bc5a083c83543b1d3986d5a6aa8fc6bdaea8aa66514172254c21f870cb149b24` |
| `tests/evaluation/fixtures/holdout_lab.py` | `a716f2589f24b1a06841c3196f1769c8e65b92182b1f7ac189ffea187261f48d` |
| `tests/evaluation/fixtures/holdout_truth.json` | `c82b58104ddc0881603052b504aca617bb56002f29d8bd50e320f1a8dc33114f` |
| `tests/evaluation/fixtures/holdout_v2_cases.json` | `e93e055c158247bf3829ab0d719a5030da6439ea50f0debff055a2fc4b68acbd` |
| `tests/evaluation/fixtures/holdout_v2_lab.py` | `90e2f5cee2163f932a32d7352f3f66b367b70852dd18d0cee24a82f0e6f65717` |
| `tests/evaluation/fixtures/holdout_v2_truth.json` | `bbe0a92357674722c00d51e45f6d130f2b8c472a26746bfff0f85402c244a95f` |
| `tests/evaluation/fixtures/holdout_v3_cases.json` | `64993b16549348c173f04154d60b3989ea3e3bc99be7264f7a96c56e4448d3f6` |
| `tests/evaluation/fixtures/holdout_v3_lab.py` | `e326eb1aee6606def8aea4c7269c392edf0162c47a5376c6c78e8d9486b8e324` |
| `tests/evaluation/fixtures/holdout_v3_truth.json` | `32b1f16b7671b2839ec53f70926acddf63a952242d9f293b38263dae842adddc` |
| `tests/evaluation/fixtures/holdout_v4_cases.json` | `c60832ea0ed0eced405295f35c6a6340927fc2d12141db08204a523c95159513` |
| `tests/evaluation/fixtures/holdout_v4_lab.py` | `5fa9cd83ef6a5c542dd6d42772fd2fc2881a877c03637e4ce712cdd8c9e8f015` |
| `tests/evaluation/fixtures/holdout_v4_truth.json` | `1fb998d2a55a5a2f9f047f6a072e8a495aacc7b20dd92942c86b8b70d348603a` |

## 開発用のセットでの確認（各1回。偏りのない推定ではありません）

固定ルールの結果です。ARTEX と台本モデルの結果も同じでした。「前」は FROZEN_JUDGE_V4 の判定器、「後」はこの判定器です。

| セット | 正解（前→後） | 誤検知 | 誤った「安全」判定（`wrong_decision`） | 再現率（前→後） | 修正の確認 |
| --- | --- | --- | --- | --- | --- |
| v1 | 27 → 27 / 30 | 0 → 0 | 0 → 0 | 0.90 → 0.90 | 3/3 |
| v2 | 18 → 19 / 30 | 0 → 0 | 0 → 0 | 0.5455 → 0.6364 | 3/3 |
| v3 | 14 → 14 / 30 | 0 → 0 | 0 → 0 | 0.70 → 0.70 | 4/5 |
| v4 | 14 → 17 / 40 | 0 → 0 | 0 → 0 | 0.4706 → 0.5882 | 2/5 |

- 変わったケース：
  - v2-029（長い本文）：判断不能 → 成立
  - v4-026・031（長い本文）：判断不能 → 成立
  - v4-007（GraphQL のエラー）：判断不能 → 不成立。認証なしの露出も、判断不能 → 不成立
- 認証なしの露出の誤検知は、どのセットも0件です。外部への接続の試みも、すべて0件です。
- 出力の SHA-256：
  - `comparison_holdout_v5judge.json`：`900afab7b485c41b8c1e890a75606b93c6b7262f4ba67228baf0b5789f5400af`
  - `comparison_holdout_v2_v5judge.json`：`f3d1cf1aa0368c649ad4ce0a8099ef08385549a2ab7502c520cd2baa15261c01`
  - `comparison_holdout_v3_v5judge.json`：`9757cf35823b16c5ff05f1decf43e383caaf8b43829674bb22a6d369e2b29a01`
  - `comparison_holdout_v4_v5judge.json`：`6a39a1794db695c467498cb48efbab7fb624884c861fd8425bdc7d86735c4019`

### 分析と違った点（v4 の 021・038・039・006 は、まだ判断不能です）

V4_MISS_ANALYSIS.md は、この4件の原因を「ID は親に、目印は子にある」と分類しました。実際の応答で確かめると、主な原因は**所有者の確認**でした。この判定器では、どれも判断不能のままです（安全側）。

| ケース | 実際の原因 |
| --- | --- |
| 038（HAL） | 記録は1つのオブジェクトにあります。所有者のリンク `_links.owner: {"href": "/api/accounts/B"}` が `acct_B` を名乗っていないため、一致しません |
| 039・006（GraphQL） | 所有者のオブジェクトが `__typename` と `handle` を持つため、一致しません |
| 021（JSON:API） | 規則1で ID と目印は1つの記録になります。ただ、`relationships.owner.data` が `"type": "accounts"` を持つため、一致しません |

所有者の確認を緩めるかどうか（型の欄や、リンクの欄を所有者の名前として扱わないなど）は、安全制御に関わります。そのため、ここでは実装していません。変える場合は、独立したレビューを受けてから、次のサイクルで行います。

## 凍結に含まないもの

- ケースを読み込むための配線（`aegis/evaluation/evaluation_runner.py`、`scripts/run_model_evaluation.py`）
- テスト


## 独立レビューを受けて締めた点（凍結の前）

独立レビューで、目印を B の記録の「下の、どのオブジェクトからでも」取れることが、誤検知につながると指摘されました。例は、ドキュメントの例、別の関連オブジェクト、以前の版、ID をそのまま返す拒否の応答です。次のように締めてから凍結しました。

- 目印を取れる子オブジェクトは、標準的な入れ子のキー（`attributes`・`fields`・`node`・`secret`・`record`・`embedded`）の下だけにしました。
- B の ID と並んで拒否の欄（`error`・`errors`、拒否の語を含む `status`・`message`）があれば、B の記録とはみなしません。
- 記録とその子オブジェクトに、B 以外を指す `…id` の欄（`uuid`・`noteId` など）があれば、拒否します。
- 記録の周囲（記録そのもの、子オブジェクト、記録を囲むオブジェクトの直接の欄）で、呼び出し元の欄以外に A を名乗る欄があれば、拒否します。

確かめた内容は次のとおりです。

- 回帰テスト：`tests/test_judge_api_envelopes.py` の `TestV5ReviewFalsePositives`
- 開発用セット（v1〜v4）：誤検知0、誤った「安全」判定0。正解は v1 27・v2 19・v3 14・v4 17 で、締める前と同じでした。
