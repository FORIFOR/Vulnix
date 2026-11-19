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

汎用ARTEX経路のGatewayも`6565a3a`で、`length`・`content_filter`・未知/欠落した終了理由、本文とツール呼出しの双方なし、終了理由とツール呼出しの矛盾をterminal failureにする。応答は分類のためARTEXへ返る場合があるが、Gatewayの失敗状態は保持され、`AssessmentService._plan_with_artex()`が計画再構成前に破棄する。次のモデル送信は拒否する。ローカル模擬応答のテストに限定し、実モデルの完成度を証明しない。

`f01d88e`では固定14条件の評価器もGatewayのterminal failure状態を採用前に確認する。終了理由が`stop`でもツール呼出しを同時に含む矛盾したJSON応答は、Gatewayが失敗とし、評価器は`gateway_terminal_response`として不採用にする。追加の有料送信は行っていない。

`8b59843`ではterminal failure時のGateway記録も`failed=1`に一致させ、拒否理由・費用予約・監査件数を同じ失敗として追跡可能にした。関連101件と[Linux CI #44267218504](https://github.com/FORIFOR/Vulnix/actions/runs/44267218504)の3/3成功を確認。後続`d199021`のLinux CI #44272121286も3/3成功、単独ローカル全1,742件・27件スキップ・ResourceWarning 0件。この安全境界を経ても実モデルのJSON採用0/2は変わらない。

[公開料金表](https://abliteration.ai/pricing/)には`abliterated-model-large-flash`も掲載され、入力US$1/100万・出力US$2/100万トークンとされる。出力形式の採用率、推論トークン消費、検査選択精度は未測定。モデル変更は評価対象と送信ハッシュを変えるため、この候補の成果として扱わず、別の承認・評価計画が必要。

## 次回実モデル評価の承認申請仕様（未送信・承認待ち）

実モデルへの送信はユーザーの新たな明示承認後に限る。次回評価候補の10項目仕様を以下に整理する。

| 項目 | 仕様・制約 |
| --- | --- |
| **1. モデル名** | 候補A: `abliterated-model`（`response_format: {"type":"json_object"}` 指定）<br>候補B（別承認オプション）: `abliterated-model-large-flash` |
| **2. モデル別対応パラメータ** | 外部送信で許可する構造化指定は `response_format: {"type":"json_object"}` のみ。`reasoning_effort`（`none`/`low`）および `reasoning.max_tokens`（`1〜256`）は実モデルの対応が確認されるまでローカル模擬限定とし、明示承認なしに外部送信へ付与しない（`json_schema` はモデル別プロファイル依存のため未採用）。 |
| **3. 匿名入力の構成** | 固定14条件（`C01`〜`C14`）の匿名化された観測特徴量のみ（解説経路では `finding_to_payload_item` の固定enum項目：`ref`, `rule`, `category`, `severity`, `verdict`, `verdict_basis`, `cve`, `risk_score`, `kev` のみ）。ホスト名、URL、IPアドレス、Set-Cookie、認証トークン、応答本文、正解ラベルは一切含めない。 |
| **4. 出力契約** | 選択評価: `{"selected": ["C01", ...]}`（既知条件IDの重複なし配列、余分なキー禁止、`finish_reason == "stop"` かつ `tool_calls` なし）。<br>日本語解説: `{"advice": [{"ref", "claim_level", "cites", "risk_explanation", "remediation": [{"fix", "detail"}], "next_checks": [{"operation", "purpose"}]}]}`（`advisor_catalog.py` の許可IDおよび `chat_guard.py` の安全検査を通過すること）。 |
| **5. 最大入力・出力トークン** | 単回上限: 出力 `max_tokens = 960`、Gateway予約合計 `1,941` トークン（設定ハード上限 `2,000` トークン）。 |
| **6. 最大費用** | Gateway予約費用 `US$0.005824`（1回あたり設定ハード上限 `US$0.01 = 10,000 µUSD`）。監査ログおよび `0600` 累積予約額ファイルで原子的に上限を強制する。 |
| **7. 要求SHA-256** | 候補A（推論設定なし・`json_object`）: `ac4a5fbdb37594be88a4a1432636169105349f3fbab6be41b420f9e90b4f7b23`<br>（※ローカル検証用の `reasoning_effort: none` は `7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`、`reasoning.max_tokens: 128` は `bd449aa117851dae1979fbb90c61e7f3aab9b454ad3f86847177c30d704bbbf2`） |
| **8. 想定する採用基準** | HTTP 200、`finish_reason == "stop"`、有効な単一JSONオブジェクト、未知・重複IDなし、報告 `usage` が非負整数かつ予約トークン上限以内であり、独立正解ラベルに対して選択 Precision / Recall が固定L1基準を下回らないこと。 |
| **9. 失敗時の停止条件** | `finish_reason` が `length` / `content_filter` / 未知値、本文欠落、`tool_calls` 混在、JSON解析失敗、報告 `usage` の欠落・片側欠落・予約超過時は即座に `terminal failure` として不採用にし、単回承認マーカーを消費済みとして再送を停止する（診断本体は固定L1結果と内蔵解説へフォールバック）。 |
| **10. 評価後の保存内容** | 監査チェーン（`audit.jsonl`）および評価結果JSONに、要求SHA-256、単回消費マーカー、終了理由、報告 `usage`（prompt / completion / reasoning tokens）、概算費用、採用可否、不採用理由または選択 TP/FP/FN/TN を保存する（APIキーや秘密値は一切保存しない）。 |
