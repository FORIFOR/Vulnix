# 正式レビューの資料と実環境E2Eの実行条件（Phase 5）

2026-11-19 JST。これは**レビューの準備資料**です。正式なGitHub Approve（第三者による承認）の代わりにはなりません。自己レビューでApproveを代用することもしません。実サイトへの通信とDNSの操作はしていません。

## 1. PR #85の累積差分をレビュー対象ごとに分けたもの

対象は `origin/main...fb676e0` の208ファイルです。ファイルごとの台帳は [PR85_FILE_REVIEW.md](PR85_FILE_REVIEW.md) にあります。

| 区分 | ファイル数 | 主なファイル | 重点的に確認してほしいこと |
| --- | --- | --- | --- |
| 認証・セッション・組織分離 | 6 | `aegis/server.py`（`_get_org` / `_dispatch` / `_bind` / `live_request_authority`）、`aegis/operators.py`、`aegis/tenancy.py`、`web/.../SessionProvider.tsx`、`web/src/lib/sessionResponse.ts` | 処理中にログアウトや除名が起きたとき、応答・SSE・保護GETで情報が漏れないか。別の組織の情報が読めないか |
| 所有確認・範囲・権限台帳 | 2 | `aegis/authority_ledger.py`、`aegis/google_ownership.py` | 証明の期限切れや取り下げと、Worker起動との競合。世代トークンの切り戻し |
| Gateway・ポリシー | 2 | `aegis/gateway.py`、`aegis/router.py` | 承認、トークン、送信先の制御、予算、停止の世代番号を確認する順序。AIの提案がGatewayを経由せずに実行される経路がないか |
| Worker・隔離・ARTEX | 7 | `aegis/runtime.py`、`aegis/confinement.py`、`aegis/workers/*`、`aegis/artex_bridge.py`、`integrations/artex/overlay/*` | 時間切れ・停止・残存プロセスの確認。ARTEXが許可外のツールを使ったり、外へ通信したりしないか |
| AI送信・費用 | 4（＋今回2） | `aegis/planner_llm_gateway.py`、`aegis/ai_advisor.py`、`aegis/advisor_catalog.py`、`scripts/eval_selection_model.py` | 承認SHAとの結び付き、予算の事前予約と精算、失効中の送信開始、外部へ送る項目の許可リスト |
| 監査・証拠・状態保存 | 3 | `aegis/audit.py`、`aegis/evidence.py`、`aegis/assessment.py` | 監査チェーンの完全性、監査が失敗したときに止まるか、判定と証拠が一致するか、Set-Cookieの秘密値を保存しないか |
| UIの保護情報表示 | 34 | `web/src/app/*`、`web/src/components/*` | 失効後に古い所見を表示しないか、候補や未再現の件数を「問題」として表示しないか |
| 診断ルール・CVE | 4 | `aegis/service_diag.py`、`aegis/cve.py`、`aegis/l2_rules.py`、`aegis/lab.py` | 誤って断定しないか、CVEの4つの状態（該当／非該当／不明／未取得）を正しく分けているか |
| CI・スクリプト | 25 | `.github/workflows/ci.yml`、`scripts/*` | 失敗を隠していないか。本物のARTEXのテストがスキップされた場合に、CIが失敗として扱うか |
| テスト・資料・その他 | 121 | — | 要点だけを確認 |

### 今回のブランチで追加・変更したもの（PR #85の外。未コミット）

| 区分 | ファイル | 確認してほしいこと |
| --- | --- | --- |
| AI評価 | `scripts/adaptive_baselines.py`、`scripts/eval_adaptive_holdout.py`、`tests/fixtures/adaptive_holdout_v2/*` | 正解ラベルがモデルの入力から切り離されているか。方式Dの要求が送信されていないか |
| 多段階ARTEX | `aegis/adaptive_plan_state.py`、`aegis/adaptive_plan_runner.py` | 権限を新たに持たないか。承認を引き継がないか。失効後の結果を採用しないか |
| 実行結果の採用（安全強化） | `aegis/assessment.py` の `_exec`（6行） | 要求者の権限が失効していたら、Workerの結果を捨てているか |
| AI解説の検査 | `aegis/ai_advisor.py`（`_Guarded`、`weaken_security_control`、`_UNSUPPORTED_IMPACT_RE`）、`aegis/abliteration_server.py` | 誤って拒否する文と、取りこぼす文のバランス |
| A2B | `aegis/a2b/*` | 通信しないこと、秘密値を出さないこと、悪意あるAPKへの耐性 |

### 修正が発生したときの手順

1. 修正前の失敗をテストで再現する。
2. 修正する。
3. 対象のテストを実行する。
4. バックエンドの全件、Web、ruffを実行する。
5. 最新のHEADで、Linux CIの3ジョブ（Python、Web、実ARTEX）が成功することを確認する。

### 今回の別エージェントによる読み取りレビューの結果（第三者レビューではない）

サブエージェントによる読み取りレビューで、P1は0件、P2は7件、P3は6件でした。すべて修正またはドキュメントの訂正を済ませています。詳細は各Phaseの資料に記載しています。これは正式レビューではありません。

## 2. 実環境E2Eの実行条件（承認があるまで実行しない）

| 項目 | 条件 |
| --- | --- |
| 対象 | 所有者が管理する検証用HTTPSドメイン1件（所有者が指定する） |
| 環境変数 | `VULNIX_REAL_SERVICE_DIAGNOSIS=l1`、`VULNIX_REAL_SITE_SAFE_AI=0`、`VULNIX_REAL_SITE_INITIAL_ARTEX=0`（有料AIは使わない） |
| 所有確認 | `_vulnix-verify.<host>` のDNS TXT照会を1〜2回 |
| 診断 | 読み取り専用のL1。GETは最大2回（`/`、同意がある場合のみ `/server-status?auto`）。リダイレクトは追わない |
| L2 | 禁止（コードで強制的に拒否する） |
| 有料AI | 使わない（US$0） |
| 停止の条件 | 想定外の送信先が出た、GETが3回目に入った、Workerが残った、監査の検証に失敗した、のいずれかで直ちに緊急停止する |
| 記録 | 送信先、時刻、HTTPの結果、証拠ID、監査ハッシュ |
| 確認すること | 所有確認から所見の詳細、レポートの出力まで通ること／Cookieの秘密値を保存しないこと／組織間で分離されていること（別組織のアカウントから読めない）／緊急停止が効くこと／証拠と判定が一致すること |
| 合格の条件 | 上の確認項目がすべて真であること。L2の実行、範囲外への送信、秘密値の保存がいずれも0件であること |

現時点では、対象ドメインも実行の承認も決まっていないため、通信は一度も実施していません。
