# ARTEX・モデル評価の分離

2026-11-17。実ARTEXバイナリとAbliteration AIの実モデルを区別する。実ARTEXの成功は、外部モデルの判断性能を証明しない。

| 評価 | 実行器 | モデル | 実測 | 限界 |
| --- | --- | --- | --- | --- |
| 所有済み模擬サイトの一連の診断 | 実ARTEX、Gateway、隔離Worker | ローカル模擬モデル | 計画から証拠付き結果まで通過 | 公開βの実DNS・実サイト通信ではない |
| 5分類17条件の横断比較 | ARTEX互換プロセス | 固定応答のローカル模擬モデル | 検査選択9/1/0/7（TP/FP/FN/TN）、Precision 0.900、Recall 1.00 | AIの未知サイト理解ではない |
| 初回事実の再利用 #82 | 実ARTEX | ローカル模擬モデル | 代表3条件で要求8→5、推定トークン30,478→18,622 | 実請求額ではない |
| Apache初回事実の再利用 #84 | 実ARTEX | ローカル模擬モデル | 代表2条件で要求3→2、推定トークン13,072→8,158 | 小標本、他分類への一般化不可 |
| 固定14条件の選択評価 #68 | Gateway経由で別々に承認された2回 | 実 `abliterated-model` | JSON採用0/2。出力384/1,024トークンともすべて推論、本文なし、`length`終了 | 選択精度は未算出。参照規則TP8/FP0/FN0/TN6は実モデル成績ではない |

固定14条件の有料評価は所有者が最初の要求を1回、出力上限だけを変えた要求を別に1回承認した。元ツリーの保護された設定から鍵をアプリの既存ローダーで利用し、値は表示していない。各実行前にモデル名、匿名入力、別々のSHA-256、Gatewayの1回・2,000トークン・US$0.01上限、監査記録、未使用の承認消費記録を照合した。両承認とも消費済みで再送しない。

実モデルのJSON採用率は0/2、推論・総トークンと時間は[2回の実測](ABLITERATION_SELECTION_REAL_RESULT.md)に記録した。選択TP/FP/FN/TN、Precision/Recall、確定請求額、日本語解説品質は**未測定**。ローカル参照規則の成績を実モデルの性能として報告しない。固定入力は[送信前プレビュー](ABLITERATION_SELECTION_PREVIEW.md)を参照。

## 2026-11-19 更新：分類別の検査選択効果・安全境界・AI失敗時フォールバック

1. **分類別の検査選択と比較（固定L1 vs 一律提案 vs 観測選択）**:
   - **CORS（3条件）・Cookie（2条件）**: 初回GETのヘッダー観測だけで確定判定が可能。`initial_real_site_extra_checks()` により不要な追加計画・モデル呼び出しを省略し（TP0/FP0/FN0/TN5）、一律提案で発生していた不要な計画起動15回・提案15件を0に削減した（[INITIAL_EXTRA_SELECTION.md](INITIAL_EXTRA_SELECTION.md)）。
   - **Apache `mod_status`（4条件）**: 固定L1はルート `/` のみを見るため TP0/FP0/FN1/TN3（Recall 0%）。ARTEXの観測選択は `server_family=apache` かつ所有者の追加GET同意（`allow_status_probe=true`）がある場合のみ `/server-status?auto` の固定マーカーWorkerを1回選択し、TP1/FP0/FN0/TN3（Precision 100%, Recall 100%）を達成した（[STATUS_SELECTION_HOLDOUT.md](STATUS_SELECTION_HOLDOUT.md)）。
   - **認証必須JSON・IDOR（14条件＋保留8条件＋Link 7条件＋新規4条件）**: 観測選択はルート応答や `Link` ヘッダーで保護リソースが確認された場合のみ検査を提案し、HTTP 200認証拒否JSONでは誤提案しない（[FIVE_CLASS_HOLDOUT.md](FIVE_CLASS_HOLDOUT.md), [ACCESS_LINK_HOLDOUT.md](ACCESS_LINK_HOLDOUT.md), [ACCESS_FRESH_HOLDOUT.md](ACCESS_FRESH_HOLDOUT.md)）。
2. **ARTEXの権限隔離とAI失敗時の証拠保持**:
   - ARTEX overlay は `Bash` / `WebFetch` / `Read` / `Write` 等の実行・通信ツールを一切持たず、Linux `nftables` でループバックの `PlannerLLMGateway` 以外への通信をカーネルレベルで遮断する（Linux CI #44419117701 `artex-real-planner` ジョブで実証済み）。
   - カタログ外の意図（RCE、アップロード、総当たり、ポートスキャン等）は `Advisory`（実行不能な助言）に落とされ、Gatewayの固定カタログ（`CATALOG`）に一致する操作しか再構成されない。
   - モデルがタイムアウト、`length` 打切り、不正JSON、過大usage等で失敗した場合、`AssessmentService._run_inner` は `artex.initial_fallback` を監査記録し、**初回に測定済みの固定L1所見と監査ハッシュをそのまま保持**して診断を完了させる（`tests/test_real_service.py` で検証済み）。
