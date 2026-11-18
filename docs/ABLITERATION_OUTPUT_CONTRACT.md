# Abliteration AIの構造化出力・ローカル検証

2026-11-18。実モデルの固定14条件評価は[2回とも本文なし](ABLITERATION_SELECTION_REAL_RESULT.md)で、検査選択精度を採点できなかった。本資料は有料送信を行わない次の候補を記録する。

## 公式仕様と採用範囲

- [Chat Completions互換仕様](https://abliteration.ai/docs/openai-compatibility)は `response_format: {"type":"json_object"}` によるJSONオブジェクト出力を案内している。
- [ツール呼び出し仕様](https://abliteration.ai/docs/tool-calling)は関数スキーマ、強制呼び出し、`tool_calls`応答を案内している。今回は検査選択だけを返すため、ツール実行ループは追加しない。
- [公式OpenAPI仕様](https://api.abliteration.ai/openapi.json)の`ChatCompletionRequest`には`response_format`の`json_schema`、`reasoning_effort`の`none`〜`ultracode`、`reasoning.max_tokens`が定義されている。ただし`reasoning`は選択したモデルのプロファイルに応じて変換されると記載され、今回の`abliterated-model`で実際に推論量を抑制できるか、JSON Schemaを強制できるかは未検証。これらの項目を現候補へ暗黙に追加しない。

既存の評価器は既に `{"selected":["C01", ...]}` の単一JSONオブジェクトだけを要求し、各条件の説明文を求めていない。Gatewayは新たに**完全一致する `{"type":"json_object"}` のみ**転送し、余分なキーや別形式を拒否する。送信内容のハッシュと費用予約にはこの指定も含まれる。モデル応答は引き続き、既知ID・重複・余分な項目を評価器で検証する。`length`で終わった回答は、偶然JSONとして読めても採用しない。

## 未送信の固定候補

| 項目 | ローカルGatewayプレビュー |
| --- | --- |
| 入力 | 前回と同じ匿名14条件。ホスト名、URL、認証情報、応答本文、正解ラベルなし |
| モデル | `abliterated-model` |
| 出力契約 | `{"selected":[既知の条件ID]}`、`response_format: {"type":"json_object"}` |
| 出力上限 | 960トークン |
| SHA-256 | `ac4a5fbdb37594be88a4a1432636169105349f3fbab6be41b420f9e90b4f7b23` |
| Gateway予約 | 1回、1,941トークン、US$0.005824。設定上限は2,000トークン・US$0.01 |
| 有料API / 対象GET / Worker | 0 / 0 / 0 |

ローカル模擬応答では、正常JSON、本文なし、`length`、不正JSON、未知ID、重複ID、余分なキー、`content_filter`を確認し、正常以外は採用しなかった。監査チェーンも確認した。これは形式と安全境界のテストであり、**実モデルがJSONを返す証明ではない**。元の2承認は消費済みで、この新しいSHAの有料送信は未承認・未実行。推論制御を試す場合は、モデル依存の挙動とGatewayの固定値検証を先に調べ、別ハッシュとして扱う。

## 推論制御のローカル候補と失敗時動作

公式OpenAPIが定義する推論設定はモデル別の実効性が未確認のため、Gatewayは`abliterated-model`に対する`reasoning_effort`の`none`/`low`、または`reasoning.max_tokens`の1〜256を**ローカルプレビューとループバック模擬送信のみ**で許可する。両設定の併用、未知キー、型不一致、0・負数・過大値、別モデル、実外部送信は送信前に拒否する。外部向け固定要求へ暗黙に設定を足さない。これは対象モデルが値を受け入れたり推論量を制御できたりする証拠ではない。

同じ匿名14条件、`json_object`、出力960トークンのローカルプレビューでは以下となった。費用はGatewayの保守的な予約値であり、請求額ではない。

| 推論設定 | 要求SHA-256 | 予約トークン | 予約費用 |
| --- | --- | ---: | ---: |
| なし（前節の未送信候補） | `ac4a5fbdb37594be88a4a1432636169105349f3fbab6be41b420f9e90b4f7b23` | 1,941 | US$0.005824 |
| `reasoning_effort: none`（ローカルのみ） | `7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5` | 1,950 | US$0.005852 |
| `reasoning.max_tokens: 128`（ローカルのみ） | `bd449aa117851dae1979fbb90c61e7f3aab9b454ad3f86847177c30d704bbbf2` | 1,952 | US$0.005858 |

ローカル模擬モデルでは、形式不正・`length`・本文なし・`content_filter`・タイムアウト・過大usageを不採用にする。Gatewayは報告されたusageが予約を超えた場合、最初の回答でも409で拒否し、残りの送信を停止する。実サイト用の初期観測は固定L1として先に保存され、ローカルARTEXの計画失敗時もその結果と監査記録を維持する。AIによる追加検査は実施済みと表示しない。実モデルのJSON採用可能性、実課金、推論設定のモデル対応は未確認。次の有料評価ではモデル、設定、要求ハッシュ、出力上限、費用上限と実行回数について**新しい承認**が必要で、上のローカル候補はいずれも送信していない。

[公開料金表](https://abliteration.ai/pricing/)には`abliterated-model-large-flash`も掲載され、入力US$1/100万・出力US$2/100万トークンとされる。出力形式の採用率、推論トークン消費、検査選択精度は未測定。モデル変更は評価対象と送信ハッシュを変えるため、この候補の成果として扱わず、別の承認・評価計画が必要。
