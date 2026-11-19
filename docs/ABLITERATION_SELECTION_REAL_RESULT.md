# 実Abliteration AI・固定14条件の3回の評価

2026-11-18（1回目・2回目）および 2026-11-19（3回目）。所有者がその都度1回限定で明示承認した固定要求だけを、既存の `PlannerLLMGateway` から公式エンドポイント `https://api.abliteration.ai/v1/chat/completions`（モデル：`abliterated-model`）へ送信した。実サイト通信、診断判定への採用、Worker起動はいずれも一切行っていない（0回）。鍵の値と生のモデル応答本文は保存していない。

---

## 1. 3回の実送信の比較総括

| 指標 | 1回目（2026-11-18） | 2回目（2026-11-18） | **3回目（2026-11-19・今回）** |
| --- | --- | --- | --- |
| **要求SHA-256** | `52c4598a8c7563a3dc9e9d4a61c89bd6157a0e2bb0faa98a5f015c03931e6c62` | `1ffef1b25e2d12dbe2d8e78e0ca747da377a045475ba1b9d46cf79a0867dbc7e` | **`7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`** |
| **送信日時（JST）** | 2026-11-18T11:39+09:00 | 2026-11-18T11:53+09:00 | **2026-11-19T14:34:26+09:00** |
| **モデル名** | `abliterated-model` | `abliterated-model` | **`abliterated-model`** |
| **`max_tokens`（出力上限）** | `384` | `1,024` | **`960`** |
| **`response_format`** | 未指定 | 未指定 | **`{"type": "json_object"}`** |
| **`reasoning_effort`** | 未指定（既定 `Native depth`） | 未指定（既定 `Native depth`） | **`"none"`（公式仕様の推論停止指定）** |
| **HTTP結果 / 呼び出し回数** | HTTP 200 / 1回（消費済み） | HTTP 200 / 1回（消費済み） | **HTTP 200 / 1回（消費済み）** |
| **終了理由（`finish_reason`）** | `length` | `length` | **`stop`** |
| **入力トークン（`prompt_tokens`）** | `608` | `608` | **`610`** |
| **出力トークン（`completion_tokens`）** | `384` | `1,024` | **`44`** |
| **推論トークン（`reasoning_tokens`）** | `384`（出力の100%） | `1,024`（出力の100%） | **`0`（0%）** |
| **総トークン（`total_tokens`）** | `992` | `1,632` | **`654`** |
| **応答時間（`elapsed_s`）** | `2.481秒` | `4.956秒` | **`1.022秒`** |
| **JSON採用可否 / 不採用理由** | FAIL（0/1、`missing_content`） | FAIL（0/1、`missing_content`） | **PASS（1/1、不採用理由 `null`）** |
| **選択された条件ID（8件）** | なし | なし | **`C01, C03, C04, C05, C06, C07, C08, C13`** |
| **検査選択 TP / FP / FN / TN** | 未算出 | 未算出 | **`8 / 0 / 0 / 6`（全14条件一致）** |
| **Precision / Recall / F1** | 未算出 | 未算出 | **`1.000 / 1.000 / 1.000`** |
| **不要検査率 / 見逃し率** | 未算出 | 未算出 | **`0.000`（0/8） / `0.000`（0/8）** |
| **Gateway事前費用予約** | `US$0.004052` | `US$0.005973` | **`US$0.005852`**（精算後保守値 `US$0.003104`） |
| **usage×公開単価からの費用概算** | `US$0.001760` | `US$0.003680` | **`US$0.000742`**（3回累計概算 `US$0.006182`） |
| **事業者の確定請求額** | 未照合（`null`） | 未照合（`null`） | **未照合（`null`、usage概算と区別）** |
| **対象サイトGET / Worker起動** | `0 / 0` | `0 / 0` | **`0 / 0`** |

---

## 2. 過去2回の失敗分析と仮説検証（Phase 1〜3）

1. **過去2回の原因（H1・H2の検証）**:
   - 公式仕様（`https://docs.abliteration.ai/capabilities/thinking.md`）には「All Abliteration models reason before answering」「Abliterated Model の既定推論モードは `Native depth`」と明記されている。
   - 推論トークン（`choices[].message.reasoning_content` / `usage.completion_tokens_details.reasoning_tokens`）は `max_tokens` の出力枠を共有する。1回目（384トークン）と2回目（1,024トークン）では推論制御を指定しなかったため、最終JSON回答（`message.content`）を書き始める前に出力上限の100%を内部推論に使い切って `finish_reason="length"` で打ち切られた（**H1成立**）。
   - `response_format: {"type": "json_object"}` は最終回答（`content`）の形式制約であり、回答前の内部推論自体を無効化しない（**H2成立**）。
2. **公式仕様での推論制御の裏付け（H3の検証と候補B選定理由）**:
   - 公式ドキュメント（`https://docs.abliteration.ai/capabilities/thinking.md` および `https://docs.abliteration.ai/compatibility-matrix.md`）を精査し、`POST /v1/chat/completions` において `abliterated-model` が `reasoning_effort: "none"` に公式対応しており、**「`none` request: Turns reasoning off — on `abliterated-model`, `abliterated-model-large-flash`, and `abliterated-model-large`, the model does not reason; only the final answer is generated (fewer tokens)」** と明記されていることを確認した（`abliterated-model-large-v2` のみ `none` でも `low` 推論が走る例外）。
   - 候補A（`json_object` のみ・推論制御なし）は再び `length` 終了するリスクが高く、候補C（プロンプト短縮のみ）や候補D（別モデル `abliterated-model-large-flash`、既定推論 `high`）は推論抑制の根拠または過去2回との同一モデル比較可能性を欠くため、**候補B（`abliterated-model` + `response_format: {"type": "json_object"}` + `reasoning_effort: "none"` + `max_tokens: 960`、SHA-256 `7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`）** を唯一の実送信候補として選定した。
   - 3回目の実送信では `reasoning_tokens: 0`、`completion_tokens: 44`、`finish_reason: "stop"`、応答時間 `1.022秒` となり、**H3（`reasoning_effort: "none"` による推論トークン抑制とJSON本文出力）が実API上で実証された**。

---

## 3. 3回目（候補B）の14条件別・検査選択精度の詳細（Phase 8）

独立正解ラベル（`tests/fixtures/access_control_truth.json`、モデルへは未送信）との照合結果：

| 匿名ID | 独立ラボ条件（モデル非送信） | ルート要件 | アカウント資源要件 | リンク観測 | 独立正解（要検査） | 実モデル選択 | 判定 |
| :---: | --- | --- | --- | :---: | :---: | :---: | :---: |
| `C01` | `auth_required_account_api` | `authentication_required` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C02` | `auth_required_json` | `authentication_required` | `none` | `false` | `false` | 非選択 | **TN** |
| `C03` | `confusing_200` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C04` | `denied_403` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C05` | `denied_404` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C06` | `idor_decoy_marker` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C07` | `idor_owner_missing` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C08` | `idor_vulnerable` | `public` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C09` | `protected_json_decoy` | `authentication_required` | `none` | `false` | `false` | 非選択 | **TN** |
| `C10` | `public_account_directory` | `public` | `public` | `true` | `false` | **非選択** | **TN（おとり除外）** |
| `C11` | `public_json` | `public` | `none` | `false` | `false` | 非選択 | **TN** |
| `C12` | `public_json_marker` | `public` | `none` | `false` | `false` | 非選択 | **TN** |
| `C13` | `unauth_exposure` | `authentication_required` | `authentication_required` | `true` | `true` | **選択** | **TP** |
| `C14` | `unknown_json` | `unspecified` | `none` | `false` | `false` | 非選択 | **TN** |

### 分析とローカル参照規則との比較

- **おとり条件（`C10: public_account_directory`、`C02: auth_required_json`、`C09: protected_json_decoy`）の識別**:
  - `C10` は `account_resource_link_observed: true` だが、所有者仕様で `account_resource_requirement: "public"`（意図的な公開ディレクトリ）と定義されているため、アカウント間アクセス検査は不要（正解 `false`）である。実 `abliterated-model` は単に `link_observed == true` だけで選ぶのではなく、所有者のアクセス要件と組み合わせて `C10` を正しく除外（FP 0）した。
  - `C02`・`C09` は `root_access_requirement: "authentication_required"` だがアカウント資源が存在しない（`none` / `link_observed: false`）。実モデルはこれらも正しく除外し、必要な8条件（`C01, C03..C08, C13`）のみを漏れなく選択（FN 0）し、ローカル固定参照規則（TP=8, FP=0, FN=0, TN=6）と完全一致した。

---

## 4. 評価範囲の厳密な区別と限界（Phase 8・9）

- **標本サイズと適用範囲**: 本評価はアクセス制御・IDOR検査選択の **14条件の小標本（`n=14`、単一要求1回）** における実測である。3回通算のJSON採用率は **1/3**（推論制御なし `0/2`、`response_format: {"type": "json_object"}` + `reasoning_effort: "none"` 指定後 **`1/1`**）。
- **今回の結果に基づくローカル製品改善（Phase 10）**: 実送信で実証された `reasoning_effort: "none"` + `response_format: {"type": "json_object"}` の組み合わせと `finish_reason in ("length", "content_filter")` の拒否を、日本語解説アダプタ `ExternalAbliterationAdvisor`（`aegis/ai_advisor.py`）にも反映し、単体テストで確認した。
- **本番品質PASSへ一般化しない項目**:
  - 実モデルへの送信：**実施済み（今回承認分1回、累計3回すべて消費済み）**
  - JSON採用：**PASS（今回候補Bで 1/1、累計 1/3）**
  - 検査選択精度：**測定済み（14条件小標本で TP=8, FP=0, FN=0, TN=6、Precision=1.0, Recall=1.0, F1=1.0）**
  - 多段階ARTEXツール呼び出しループや実モデル日本語解説（`ai_advisor.py`）の実API品質：**未測定**
  - 実サイト診断：**未実施（0回）**
  - 正式GitHubレビュー：**未完了（0件）**
  - 公開β：**未完了（Gate D / E / F / H および実モデル解説等の未検証範囲が残るため、1回の成功だけで公開β全体をPASSとしない）**
