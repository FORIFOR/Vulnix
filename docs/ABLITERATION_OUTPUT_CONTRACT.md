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

## 次回実モデル評価の承認申請仕様と3回目（候補B）の実測結果（2026-11-19 更新）

### 1. 公式仕様の調査結果（Phase 2）と候補A〜Dのローカル比較（Phase 3）

公式ドキュメント（`https://docs.abliteration.ai/capabilities/thinking.md`、`https://docs.abliteration.ai/compatibility-matrix.md`、`https://docs.abliteration.ai/models.md`、`https://api.abliteration.ai/openapi.json`、`https://abliteration.ai/pricing/`）の精査により以下を確認した：
- 全モデルが既定で回答前に推論（`choices[].message.reasoning_content` / `usage.completion_tokens_details.reasoning_tokens`）を実行し、推論トークンが `max_tokens` 枠を消費する（`abliterated-model` の既定は `Native depth`、`abliterated-model-large-flash` の既定は `high`）。
- `POST /v1/chat/completions` において、`abliterated-model` および `abliterated-model-large-flash` は `reasoning_effort: "none"` に公式対応しており、**「`none` request: Turns reasoning off — the model does not reason; only the final answer is generated (fewer tokens)」** と明記されている（`abliterated-model-large-v2` のみ `none` でも `low` 推論が走る例外）。
- `include_reasoning: false` は推論トレースを応答から隠すだけで推論トークンは消費される（"does not save reasoning tokens"）。また `reasoning.max_tokens` はOpenRouter互換エイリアス（effort段階への変換）であるのに対し、`reasoning_effort: "none"` はChat Completionsのネイティブ指定である。

| 比較項目 | 候補A（`json_object` のみ） | **候補B（`json_object` + `reasoning_effort: "none"`）［採用］** | 候補C（プロンプト短縮のみ） | 候補D（`abliterated-model-large-flash` + `json_object`） |
| --- | --- | --- | --- | --- |
| **モデルID** | `abliterated-model` | **`abliterated-model`** | `abliterated-model` | `abliterated-model-large-flash` |
| **要求SHA-256** | `ac4a5fbdb37594be88a4a1432636169105349f3fbab6be41b420f9e90b4f7b23` | **`7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`** | 入力変更に伴い別SHA | モデル変更に伴い別SHA |
| **入力トークン推定（UTF-8 bytes）** | `981`（2,944 bytes、実測608） | **`990`（2,972 bytes、実測610）** | 約`910`（約2,730 bytes） | `985`（2,956 bytes） |
| **最大出力トークン（`max_tokens`）** | `960` | **`960`** | `960` | `960` |
| **推論制御** | なし（既定 `Native depth`） | **`reasoning_effort: "none"`（公式推論停止）** | なし（既定 `Native depth`） | なし（既定 `high`） |
| **JSON出力形式** | `response_format: {"type":"json_object"}` | **`response_format: {"type":"json_object"}`** | `response_format: {"type":"json_object"}` | `response_format: {"type":"json_object"}` |
| **事前予約トークン / 上限** | `1,941 / 2,000` | **`1,950 / 2,000`** | 約`1,870 / 2,000` | `1,945 / 2,000` |
| **事前予約費用 / 上限** | `US$0.005824 / US$0.01` | **`US$0.005852 / US$0.01`** | 約`US$0.005610 / US$0.01` | `US$0.004876 / US$0.01` |
| **API互換性・モデル対応根拠** | 対応（ただし推論抑制なし） | **公式 `thinking.md` & `compatibility-matrix.md` で確認済み** | 対応（推論抑制なし） | 対応（別モデルへ変更） |
| **予想される失敗条件・リスク** | 過去2回（384/1,024トークン全量推論消費）と同様、`960` トークンを推論で使い切り `length` 終了するリスクが大 | **推論トークンを0に抑え最終JSONのみ出力。リスクは推論停止時の選択精度への影響** | 入力608トークンは元々小さく、プロンプト短縮では既定推論を止められない | 既定 `high` 推論で `length` リスクが残り、過去2回との同一モデル比較可能性も失う |

### 2. 候補Bの1回限定・承認済み実送信結果（Phase 7〜8）

所有者の1回限定承認のもと、21条件のローカル異常系・安全テスト（`tests/test_selection_model_eval.py`）と12項目の送信直前ゲートを通過した上で、候補B（SHA-256: `7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`）を `PlannerLLMGateway` から **1回だけ** 送信した（詳細は [ABLITERATION_SELECTION_REAL_RESULT.md](ABLITERATION_SELECTION_REAL_RESULT.md)）：
- **応答・トークン**: HTTP 200、`finish_reason="stop"`、`prompt_tokens=610`、`completion_tokens=44`、**`reasoning_tokens=0`**、`total_tokens=654`、応答時間 `1.022秒`。
- **JSON採用と選択精度**: **採用PASS（1/1、通算1/3）**。選択ID `["C01", "C03", "C04", "C05", "C06", "C07", "C08", "C13"]` は独立正解ラベルと14条件すべて一致し、**`TP=8, FP=0, FN=0, TN=6`（`Precision=1.000, Recall=1.000, F1=1.000`、不要検査率 `0.000`、見逃し率 `0.000`）**。
- **費用**: Gateway事前予約 `US$0.005852`、精算後保守値 `US$0.003104`、公開単価×報告usage概算 **`US$0.000742`**（確定請求額は未照合 `null`）。承認消費記録を永続保存済み（再送不可）。
- **製品への反映（Phase 10）**: 日本語解説アダプタ `ExternalAbliterationAdvisor`（`aegis/ai_advisor.py`）でも `abliterated-model` / `abliterated-model-large-flash` に対して `reasoning_effort: "none"` を付与し、`finish_reason in ("length", "content_filter")` を安全側で拒否するよう改善した（`tests/test_ai_advisor.py` で検証済み）。
