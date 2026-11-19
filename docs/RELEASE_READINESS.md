# 公開β判定

最新の開発ブランチ追記（2026-11-19 JST）:
- **P2候補（対象サイトが新規発行した `Set-Cookie` 秘密値の漏えい）の解消**: `http_probe` Worker・Gateway・`AssessmentService`・`enforce_verdict` の4境界で `Set-Cookie` 生値を除去し、Cookie名と保護属性のみを保持するよう修正。ローカルHTTPS模擬サイト（CANARY秘密値および引用符付き値）で修正前の赤テスト（`evidence[].content` 等への残存）を再現し、修正後は snapshot・report・監査ログ・`state.json`・Remotionエクスポートのいずれにも残らないことを確認した（[COOKIE_PURPOSE_LAB.md](COOKIE_PURPOSE_LAB.md)）。
- **AI評価ラベル整合・CVE 4条件分離・初期構想トレーサビリティ**: `advisor_eval/dataset.py` の禁止操作ラベル漏れ（`OTHER_RULE_OPS` / `OTHER_RULE_FIXES`）を解消し、CVE照合の4条件（該当/非該当/バージョン不明/フィード未取得）と完全性ハッシュ・鮮度表示を実装・検証。初期構想12項目の3軸評価を [PRODUCT_VISION_TRACEABILITY.md](PRODUCT_VISION_TRACEABILITY.md)、6段階ユーザージャーニーE2Eを [USER_JOURNEY_E2E.md](USER_JOURNEY_E2E.md) に整備した。
- **直前HEADのLinux CI完了確認と新コード全件回帰**: `6180df3` の [CI #44416189175](https://github.com/FORIFOR/Vulnix/actions/runs/44416189175)（Python 1,896件成功・17件スキップ・2,006.321秒）および `fb25f9b` の [CI #44419117701](https://github.com/FORIFOR/Vulnix/actions/runs/44419117701)（Python 1,896件成功・17件スキップ・1,708.349秒）はともに Python / Web / 実ARTEX の3/3ジョブが成功した。さらに今回の追加修正を含むローカル全バックエンド回帰（`VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests`）は **1,901件成功・27件スキップ・1,331.422秒・ResourceWarning 0件**（`/tmp/vulnix-pr85-phase0-5-full.log`）、Web 123件・Lintエラー0/既存警告5・本番ビルド・Ruff・390px/1280pxブラウザE2Eも成功した。続けて新HEADのLinux CIを確認する。
- **公開判定**: 実Abliteration AIの採用（0/2）、実DNS所有確認（Gate E）、許可済み実サイトL1 E2E（Gate F）、独立レビュアーによる正式GitHubレビュー（Gate D）、main統合・本番公開承認（Gate H）が未完了のため、引き続き **公開不可** を維持する。

---

## 公開βの8ゲート（A〜H）評価一覧

| ゲート | 区分 | 現在の判定 | 根拠と限界 | 次のアクション |
| --- | --- | :---: | --- | --- |
| **A. 製品機能の完成** | 初期構想12項目の実装・UI・教育・CVE・証拠分離 | **PASS（ローカル実装・動作）** | [PRODUCT_VISION_TRACEABILITY.md](PRODUCT_VISION_TRACEABILITY.md) および [USER_JOURNEY_E2E.md](USER_JOURNEY_E2E.md)。URL登録→所有確認→診断開始→結果・証拠12項目→3段階学習・修正手順→再診断の全6段階が390px/1280pxの本番ビルドで動作（8操作、ページエラー0、横スクロール0）。 | 新HEADのCIで維持を確認 |
| **B. ローカル診断品質** | CORS・Cookie・認証・IDOR・Apache・TLS・CVEの精度と秘密値非保存 | **PASS（独立模擬ラボ）** | [DIAGNOSTIC_QUALITY_REPORT.md](DIAGNOSTIC_QUALITY_REPORT.md), [COOKIE_PURPOSE_LAB.md](COOKIE_PURPOSE_LAB.md), [CVE_READINESS.md](CVE_READINESS.md)。5分類17条件（Macro Recall 0.60→1.00）、Cookie用途10条件（Precision/Recall 100%）、HTTPS 6条件、Set-Cookie秘密値非保存、CVE 4条件分離を実証。未知の実サイト全般への一般化はしない。 | 許可済み実サイトL1（Gate F）で実環境を確認 |
| **C. AI診断品質** | ARTEX検査選択・Abliteration AI構造化出力・日本語解説 | **FAIL（実モデル採用0/2）** | [ARTEX_MODEL_EVALUATION.md](ARTEX_MODEL_EVALUATION.md), [ABLITERATION_OUTPUT_CONTRACT.md](ABLITERATION_OUTPUT_CONTRACT.md)。実ARTEX＋ローカル模擬モデル、および解説検証器（構造的危険提案拒否100%・禁止操作採用0件・AI失敗時の固定L1/内蔵解説フォールバック）はPASS。一方、実 `abliterated-model` の承認済み2回は推論トークン消費による `length` 終了でJSON本文なし（採用0/2）。 | 下記の外部承認仕様に基づき新規承認後に実モデル再評価、または所有者承認のもと「固定L1＋内蔵解説限定β」を別案として選択 |
| **D. 安全性と独立レビュー** | 権限失効・組織分離・Gateway/Worker隔離・累積差分監査・正式GitHub Approve | **BLOCKED（正式Approve 0件）** | [SECURITY_REVIEW.md](SECURITY_REVIEW.md), [PR85_FILE_REVIEW.md](PR85_FILE_REVIEW.md)。208変更ファイル中185件を確認（36件で問題を修正・再検証、46件でコードとテストを確認、103件で対象経路を照合）、23件は進行記録等の分類のみ。P1/P2（Set-Cookie秘密値、旧設定でのテナントL2、ログアウト競合、監査切り戻し等）はすべて解消。ただし独立レビュアーによるGitHub正式Approveは0件。 | 独立レビュアーによるPR #85の正式GitHub Approve取得 |
| **E. 実DNS所有確認** | 実DNSサーバーでの `_vulnix-verify.<host>` TXT照会 | **BLOCKED（承認待ち）** | ローカル模擬DNSとループバック固定IP取得はPASS。実DNS照会は未実施。 | 下記の承認要件に基づき1ホストで実DNS TXT確認を実施 |
| **F. 許可済み実サイトL1のE2E** | 所有者管理下の実HTTPSサイトに対する読み取り専用L1通し診断 | **BLOCKED（承認待ち）** | 実サイト通信禁止ルールに従い未実施（0回）。 | Gate E通過後、署名済み範囲で最大2 GETのL1診断を1回実施 |
| **G. 運用・費用・障害復旧** | 費用上限・監査チェーン・緊急停止・未停止Worker封じ込め・起動ガード | **限定PASS（ローカル・Linux CI）** | `AuditLog.record_with_budget` と `0600` 累積予約額ファイルによる単独JSONL切り戻し拒否、緊急停止（5秒以内）、未停止Worker生存時の新規起動拒否、`scripts/public-app.sh` の広い実サイトモード拒否を確認。両ファイル同時ロールバック検知や本番インフラ設定の実機確認は未了。 | 本番/公開βサーバー環境での `VULNIX_REAL_SERVICE_DIAGNOSIS=l1` 実設定照合 |
| **H. main統合・本番公開承認** | PR #85のmainマージと本番デプロイ | **BLOCKED（所有者承認必須）** | Draft PR #85は未マージ。 | Gate A〜Gの完了または明示的な限定β承認後に所有者が判断 |

---

## 外部承認が必要な作業の申請仕様（承認前に実行しない）

以下の作業はすべて所有者の明示的な事前承認を必要とし、承認前にエージェントが実行することはない。

| 承認項目 | 対象・エンドポイント | 範囲・設定 | 通信量・回数 | 期間 | 推定・最大費用 | リスクと安全策 | 合格条件 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **1. 実Abliteration AI 選択再評価（Gate C）** | `https://api.abliteration.ai/v1/chat/completions`（モデル: `abliterated-model` または承認された別モデル） | 匿名14条件、`response_format: {"type":"json_object"}`、要求SHA `ac4a5fbdb37594be88a4a1432636169105349f3fbab6be41b420f9e90b4f7b23`（推論抑制パラメータを試す場合は別SHAを明示承認） | HTTPS POST **1回**（単回消費マーカーで二重送信防止、対象サイトGET 0回） | 単発（タイムアウト30秒） | 予約 `US$0.005824` / ハード上限 **US$0.01**（最大2,000トークン） | URL・ホスト名・秘密値・生本文は一切含まない。`length` や過大usage時は即座に不採用・停止 | `finish_reason="stop"` で有効JSONが返り、選択Precision/Recallを採点できること |
| **2. 実DNS所有確認 + 許可済み実サイトL1 E2E（Gate E / F）** | 所有者が管理・指定する検証用1ドメイン（HTTPS） | `VULNIX_REAL_SERVICE_DIAGNOSIS=l1`（読み取り専用L1のみ、実サイトL2はハード拒否） | DNS TXT照会 **1〜2回** + 対象サイトへの非破壊GET **最大2回**（`/` および同意時 `/server-status?auto` のみ、リダイレクト非追従） | 承認された1セッション（有効期限内、単発確認） | **US$0**（有料AI非使用時） | Gatewayピン留めIP・`egress_sentinel`・Linux `nftables` 隔離・Set-Cookie値非保存・緊急停止待機 | 所有確認→L1開始→所見・証拠表示→レポート出力までエラー0で完走し、秘密値が一切残らないこと |
| **3. 別案：固定L1＋内蔵解説限定βの先行公開判断（任意）** | 公開β環境（`VULNIX_REAL_SITE_SAFE_AI=0`, `VULNIX_REAL_SITE_INITIAL_ARTEX=0`） | 外部AIが未合格の間、AI追加検査と外部AI解説を無効化し、固定L1検査と3段階内蔵解説のみで提供する場合 | 外部AI通信 **0回** | 所有者が承認する期間 | **US$0** | 画面上で「内蔵の検査ルール・内蔵解説で動作中（AI追加検査未実施）」と明示し、AI診断と偽らない（実装済み）。**※ユーザーの承認なく初期構想のGoal自体は縮小しない** | 所有者が限定βとしての公開範囲を明示承認し、Gate D/E/F/Gを通過すること |
| **4. main統合・本番公開（Gate H）** | `FORIFOR/Vulnix` `main` ブランチおよび本番環境 | PR #85 のマージとデプロイ | — | 所有者承認後 | — | 正式GitHub Approve（Gate D）および最終HEADのLinux CI 3/3成功を前提とする | 所有者の明示的なマージ・公開承認 |


2026-11-19 JSTの最新状況: PR #85のpush済み製品コードHEADは`dbb180a`。監査費用履歴の単独切り戻しを拒否する修正後、[Linux CI #44403021164](https://github.com/FORIFOR/Vulnix/actions/runs/44403021164)はPython1,894件成功・17件スキップを含む3/3成功。macOS Python 3.15のローカル全件はHTTPタイムアウト競合テスト1件が間欠的に失敗し、`dbb180a`の局所33件と10回連続再実行、ローカル全1,895件成功・27件スキップ・1,327.903秒。`dbb180a`のLinux CI #44411931431はPython1,895件成功・17件スキップを含め3/3成功。ログアウト後の古い認証応答と同一オリジンの別タブ結果を隠すWeb修正は121件・Lint・ビルドと両幅のループバック模擬ブラウザで確認したが、実HTTP Cookieの到着順と異なる端末での即時同期は未実証。実モデル採用0/2、実DNS・許可済み実サイトE2E、正式GitHubレビュー0件は変わらず、**公開不可**。

2026-11-19 JSTの先行基点: PR #85の製品コード`bfdb8c9`で資産登録・選択・設定・削除と診断POSTの成功応答に送信時権限確認を追加し、失効後の旧200や例外文付き409を模擬再現から401へ改善した。単独ローカルのバックエンド全1,866件成功・27件スキップ、Web119件・Lint・ビルド、390px/1280pxのループバック模擬ブラウザが成功。対象はローカル模擬環境で、操作自体の取り消しと全エラー応答の保証は未実証。[Linux CI #44385883751](https://github.com/FORIFOR/Vulnix/actions/runs/44385883751)は3/3成功、Pythonログartifactで1,866件成功・17件スキップ・1,841.080秒を確認。ただし後続コード`e806ecf`の最終CIではない。198ファイル中40件を対象経路照合、158件は分類のみ。実モデル採用0/2、実DNS・実サイトE2E、正式GitHubレビュー0件は変わらず、**公開不可**。要件の正式な判定は[Goal完了判定表](GOAL_COMPLETION_MATRIX.md)を参照。

2026-11-19 JSTの追加監査: 所有確認トークンの応答前ログアウトで旧コード200を再現し、`5217969`で登録・証明・範囲確定・Google開始/完了の成功応答に送信時権限確認を追加した。登録のログアウト401・役割降格403、証明・範囲のログアウト401を模擬確認。Google固有28件・組織分離520件、単独ローカル全1,801件成功・27件スキップ。新コードの[Linux CI #44368482725](https://github.com/FORIFOR/Vulnix/actions/runs/44368482725)もPython・Web・実ARTEXの3/3成功、Python1,801件成功・17件スキップ。実モデル、実DNS・実サイトE2E、正式レビューが未完了なので、**公開不可**。

2026-11-19 JSTの最新追記: Draft PR #85はコード`084fb44`までpush済み。停止後応答とCVE状態の処理中失効に対する赤/緑テストを追加した。[198ファイルのレビュー台帳](PR85_FILE_REVIEW.md)では24件を対象経路照合、174件を分類のみと記録。前コミット`ec74b55`の[Linux CI #44354783049](https://github.com/FORIFOR/Vulnix/actions/runs/44354783049)は緊急停止の保存失敗時契約2件で失敗したが、ログartifactを回収できた。`084fb44`で停止を許したまま保護詳細を隠すよう修正。修正後の単独ローカル全1,781件成功・27件スキップ・1,252.488秒。[Linux CI #44359394810](https://github.com/FORIFOR/Vulnix/actions/runs/44359394810)は3/3成功、Pythonログで1,781件成功・17件スキップ、模擬失敗artifactの保存・再読込も確認。実モデル採用0/2、実DNS・許可済み実サイトE2E、正式GitHubレビュー0件は変わらず、**公開不可**。

2026-11-19 JSTの追記: 資料コミット`5317e0f`の[Linux CI #44331685004](https://github.com/FORIFOR/Vulnix/actions/runs/44331685004)は3/3成功し、Pythonログartifactから1,742件成功・17件スキップを確認した。現在の開発ツリーでは[API到達性](PR85_API_REACHABILITY.md)、[195ファイルのレビュー台帳](PR85_FILE_REVIEW.md)、[両幅の失効ブラウザQA](PR85_REVOKE_BROWSER_QA.md)を追加し、停止後応答のP2を修正したが、後続CIと正式レビューはまだ未確認。公開不可は変わらない。

最新`7effe09`（製品コード`d199021`）の単独ローカル全バックエンド1,742件・27件スキップ・ResourceWarning 0件、Web119件・Lint・ビルド・390px模擬ブラウザが成功した。[Linux CI #44325797831](https://github.com/FORIFOR/Vulnix/actions/runs/44325797831)もPython・Web・実ARTEXの3/3成功し、Pythonログartifactを取得した。ただし前CIの初回はPythonジョブが約51分後にログなしで失敗し、原因未特定。正常時のログ保存成功はその不安定性の解消を証明しない。実モデルの採用0/2、実DNS・実サイトE2E、正式GitHubレビューは変わらず未完了で、公開不可の判定を維持する。以下の詳細表の古いコミット値は過去の測定範囲を表す。

2026-11-18時点の判定は **公開不可**。実Abliteration AIの判断・解説、実DNS所有確認から許可済み実サイト結果表示まで、独立した正式レビューが未実証である。最終Linux CI成功はこれらの代替にならない。

公開βを再判定する際は、実際のバックエンドで`VULNIX_REAL_SERVICE_DIAGNOSIS=l1`と既存ランチャーの広いモード拒否を確認する。コードの既定値や模擬テストだけでは公開環境の設定を証明しない。

| ゲート | 状態 | 必要な証拠 |
| --- | --- | --- |
| 累積コードの全テストとLinux実ARTEX | PASS（統合候補のテストのみ） | `4f1ac7b`のローカル全1,727件成功・27件スキップ・ResourceWarning 0件。Web118件・Lintエラー0/警告5・ビルド成功。[Linux CI #44178305443](https://github.com/FORIFOR/Vulnix/actions/runs/44178305443)は3/3成功 |
| Gateway・Worker・所有確認・組織分離・停止 | NOT_TESTED（残る統合境界） | 既存のWorker/モデル送信・所有確認失効の隔離テストに加え、`40059c4`で保護GET、SSE、管理者/自己変更の失効競合を修正し個別テスト成功。単一組織の承認者previewも確認。直前コードのローカル全1,700件・Linux CI 3/3成功。新コード`4f1ac7b`は診断結果/状態の重い生成とsudo時間切れを修正、ローカル全1,727件成功。Linux CI #44178305443は3/3成功。公開βは未確認 |
| 外部AI解説の送信開始 | PASS（模擬送出境界のみ） | `6e0a4ab`の最終確認とtransport開始の間に残った競合を、`276ca67`で正規HTTP経路の権限リースと実際の要求送出で直列化。模擬4件とAI関連66件、ローカル全1,431件、Linux CI #44149943968成功。独立読み取りレビューに新たな明確なP1/P2なし。実モデル通信は未確認。既に送出した要求は停止後も応答し得る |
| 有料Planner forwardの停止保証 | 限定PASS | `f60f7fe`で送出開始を生存権限リース内へ移し、未送信時の費用解放を模擬確認。詰まった模擬書込みでは停止側ロックを2.5秒未満で取得。最新全件・CI #44159555107成功。実APIの停止時間と費用は未測定。実サイトの送信先はループバックに限定 |
| 複数分類の独立精度 | 限定PASS | 5分類17条件と別のLink7条件に加え、未知アクセス4条件でHTTP 200拒否のFPを1→0に修正。認証・IDORの2分類だけの追加測定で、実モデル性能ではない |
| 実Abliteration AI | FAIL | 別々に承認された固定14条件2回を実行。JSON採用0/2、`length`終了、出力384/1,024トークンともすべて推論で本文なし。選択精度は未算出、確定請求額未照合。[2回の実測](ABLITERATION_SELECTION_REAL_RESULT.md)。追加評価は別承認 |
| 初心者の4段階操作 | 一部PASS | 最新`d1b7289`の390pxローカル模擬対象で結果まで8操作、レポート出力・失効後の旧結果非表示・組織切替分離・SSE再接続を確認。無通知の回収32.427秒。エンジン`unverified`・モデル呼出し0。実DNS、公開β、全画面は未確認 |
| 公開βの実DNS・許可済み実サイトL1 | BLOCKED | 所有確認と範囲・通信量の承認後に対象バックエンドから一連の結果を確認 |
| GitHub正式レビュー | BLOCKED | 別担当のApproveと重大指摘の解消 |
| main統合・本番反映 | BLOCKED | 所有者の事前承認 |

次の自主作業は累積ブランチのテスト・レビュー、未知条件の模擬評価、画面の模擬E2Eである。実サイト通信、DNS変更、追加有料API、mainへのマージ、公開βへの反映は承認なしに行わない。詳しい要件ごとの判定は [Goal完了判定表](GOAL_COMPLETION_MATRIX.md) に記録する。

## 今回の実ブラウザ確認

`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium` を統合候補で実行。390px、ローカル模擬対象、DNS照合をプロセス内だけで置換した条件で、サイト画面から結果まで8操作、12 API要求、対象GETは `/` と `/server-status?auto`、結果表示まで診断開始後0.900秒、ページエラー0件だった。この経路はARTEX互換プロセスで、実モデル呼び出し0・実行元は `unverified` と記録された。実ARTEX・公開サイトの実証と混同しない。

同じ条件の `--cors-note` では390pxで観測CORSヘッダーと未実証事項の表示がともに真、ページエラー0件。`--revoke-session` では失効後の古い結果非表示まで7.814秒、ページエラー0件。追加オプションの実行ではAPI要求17件を観測した。いずれもローカル単発測定であり、速度保証ではない。

`--viewport-width 1280` を追加した同じローカルブラウザ経路では、結果まで8操作、12 API要求、対象GET2回、診断開始から表示まで0.913秒、ページエラー0、横スクロールなしだった。測定スクリプトの既定幅390pxは維持した。
