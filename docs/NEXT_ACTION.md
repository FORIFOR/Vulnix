# Security Graph v2 作業の再開点

## MCP候補への合成検証紐付け（2026-11-19）

- 現行作業ツリー `/Users/shuhei/Projects/Vulnix-graph-mcp-verified`、ブランチ `codex/graph-mcp-verified`、コードコミット `91a4707`。基点は[Draft PR #90](https://github.com/FORIFOR/Vulnix/pull/90) の `d42bea3`。この変更は別の小さなDraft PRとして提出する。
- SQLiteスキーマをv4へ移行し、AI仮説用の検証テーブルとは別に、MCP候補とスナップショット内ツールノードを参照する不変の合成検証記録を追加。v3からの移行で既存スナップショットを保持するテストを追加。
- `McpValidationBroker` は登録済み合成ソースの固定 `tools.py` が対象コミットと完全一致する場合だけ、既存WorkerPool・権限リースを通して固定ハーネスを実行。変更後checkout、未登録候補、別組織スナップショット、失効したリースを拒否。顧客ツールの実証や脆弱性確定には昇格しない。
- 関連21件、Ruff、Web124件、lintエラー0（既存警告5）、build成功。最初の関連523件は新作業ツリーにTypeScript AST依存関係がなく1件失敗し、`npm ci --offline` 後の単独6件・関連21件は成功。バックエンド全件は `/tmp/vulnix-mcp-verified-backend-full.log` に実行中。
- PR #90の[Linux CI #44332783026](https://github.com/FORIFOR/Vulnix/actions/runs/44332783026) は試行1でPythonランナー終了・ログ未保存、試行2を実行中。再開時に両方の結果を確認する。次は組織別API・日本語UIへ記録を接続し、`tests/test_tenancy.py` に他組織からの読取・操作拒否を追加する。

## 固定MCPポリシーラボ（2026-11-19）

- 現行作業ツリー `/Users/shuhei/Projects/Vulnix-graph-mcp-policy-lab`、ブランチ `codex/graph-mcp-policy-lab`、コードコミット `ba1174b`。基点は[Draft PR #89](https://github.com/FORIFOR/Vulnix/pull/89) の `1da769a`。この変更は別の小さなDraft PRとして提出する。
- `aegis/validation/mcp_policy_lab.py` に固定の合成FastMCPコントロールを追加。通常登録、内側のロールガード、登録より外側のガードを同じ合成データで比較する。既存のMac sandbox-exec / Linux KernelConfinementとWorkerPool実行器を共有し、外部ネットワーク・顧客秘密情報・任意ソースを使わない。
- Security Graphは内側のロール宣言も適用実証とは扱わず、ラボ実行結果は顧客ツールの検証結果へ昇格させない。関連25件、Ruff、差分チェック成功。バックエンド全件、Web、Linux CIはこのコミットでは未確認。
- 再開時は `git status --short --branch`、`git diff --check`、`VULNIX_NO_ENV_LOCAL=1 python3 -m unittest tests.test_mcp_policy_lab tests.test_source_workflow` を確認し、全件とLinux CIを実行する。次は登録済み合成リポジトリの特定候補と固定コントロール結果を結びつけるValidationBrokerを設計し、候補・実測・実証範囲を分離して保存する。

## MCP経路の誤検知修正（2026-11-19）

- 現行作業ツリーは `/Users/shuhei/Projects/Vulnix-graph-mcp-validation`、ブランチ `codex/graph-mcp-validation`、コードコミット `05bb593`、[Draft PR #89](https://github.com/FORIFOR/Vulnix/pull/89)。PR #88 の最新ヘッド `1cc2d9e` の上に積んだ。
- 未実行の入れ子関数・lambda・クラス本体にある読み取りを、MCPツールの直接アクセス経路へ誤って帰属しないようPython AST走査を修正。その場で呼ぶlambdaの読み取りは維持。解析器版を `source-ast-v5` に上げ、旧スナップショットを混ぜない。
- 失敗を先に確認したテストを含む関連30件、Ruff、Web124件、lintエラー0（既存警告5）、build成功。ローカルPython全件およびPR #88最新ヘッドのLinux CI #44326880415は確認中。実行時のMCP権限、外部文書注入、顧客コードの隔離実行は未検証。
- 再開時は `git status --short --branch`、`git diff --check`、ローカル全件ログ `/tmp/vulnix-mcp-validation-backend.log`、Linux CI #44326880415 と #44326241981 を確認する。PR #89 の最新コミットについてLinux CIを実行し、成功後にPR本文へ証拠を追記する。次の実装は合成MCPツールの実行時権限・承認を固定ハーネスで検証し、構造上の候補と実証結果を分けて保存する。

## AI/MCP拡張の現在地

- 現行作業ツリーは `/Users/shuhei/Projects/Vulnix-graph-mcp-scope`、ブランチ `codex/graph-mcp-scope`、コードコミット `6aae9ff`。基点はMCPツール構造抽出の[Draft PR #87](https://github.com/FORIFOR/Vulnix/pull/87)（`267f7d2`）、本変更は[Draft PR #88](https://github.com/FORIFOR/Vulnix/pull/88)。元の[Graph PR #86](https://github.com/FORIFOR/Vulnix/pull/86)は `1fff083` でLinux CI #44311300150 の3ジョブ成功。
- PR #87はFastMCPの明示登録をASTで抽出し、`ai_tool → handler → resource` を未確定の構造経路として保存する。再代入・動的名は安全確認に使わず、既存のAPI認可不備仮説には混ぜない。パーサー版は `source-ast-v3`。ローカル全1,835件成功（29件スキップ、`/tmp/vulnix-mcp-graph-backend.log`）、Web123件・lintエラー0（既存警告5）・build・Ruff成功。[Linux CI #44318721657](https://github.com/FORIFOR/Vulnix/actions/runs/44318721657) は3ジョブ成功。
- PR #88はMCPツールのデータ参照とロール宣言をレビュー候補として組織別API・日本語UIへ接続。宣言の適用順を考慮し、ロール名原文は保存しない。候補は `scope_unknown` または `role_declaration_unverified`、検証は `not_run`。パーサー版は `source-ast-v4`。関連14件、ローカル全1,840件成功（29件スキップ、`/tmp/vulnix-mcp-scope-backend-full.log`）、Web124件・lintエラー0（既存警告5）・build・Ruff、実バックエンド＋Next.jsの1280px/390pxブラウザ確認が成功。[Linux CI #44320273080](https://github.com/FORIFOR/Vulnix/actions/runs/44320273080) は3ジョブ成功。Linux Python全1,840件（20件スキップ）、カーネル隔離・緊急停止12件も成功。
- 次はMCPの実行時権限、承認、外部文書注入、権限委譲を合成・隔離ハーネスで評価し、誤検知・見逃しを未知条件で測る。顧客コード、実サイト、有料モデルには接続しない。正式独立レビュー、GitHub App顧客接続、顧客コード隔離実行、実モデル品質、実修正PR、継続監視、公開判定は未完了。

```sh
cd /Users/shuhei/Projects/Vulnix-graph-mcp-scope
git status --short --branch
git diff --check
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests
ruff check aegis tests
cd web && npm test && npm run lint && npm run build
```

## Graph基盤の履歴

更新: 2026-11-18。基盤作業ツリーは `/Users/shuhei/Projects/Vulnix-security-graph-v2`、ブランチ `codex/security-graph-v2`、基点は Draft PR #85 の `e1011afb8266df36985514a80a724a7fe210e84c`。Graph実装は `d4c7785`、UI文言は `34ab3c9`、Linuxの高FD修正は `7a31412`、合成Worker起動直前の組織権限リースは `51be685`、Python認可ガードの誤認修正は `fcae4ec`、ARTEX Graph入力固定は `c0edd88`、隔離リレーのパイプ後片付けは `b0815a8`、追加のAST認可解析修正は `edb3ae5`。Draft PR は [#86](https://github.com/FORIFOR/Vulnix/pull/86)。元ツリーと旧 `Vulnix-security-graph-e2e` ツリーの未コミット差分は保持した。

## 現在の実装と証拠

- `aegis/security_graph/`: 組織別 SQLite、コミット固定の不変スナップショット、Python/TypeScript AST による FastAPI/Next.js の基本関係、根拠参照、8ホップ/5,000状態/100経路の有界探索、修正効果の予測、コミット間の構造比較。
- `aegis/research/`: 交換可能な研究モデル、オフライン基準モデル、ARTEXの検証済み構造化出力からのアダプタ、根拠照合と反証処理。ARTEXへ渡したGraph要求のSHA-256を実行結果に記録し、別スナップショットの結果の流用を拒否。固定バイナリ・Linux隔離・ループバックモデルを要求するGraph研究入口を追加。実ARTEXとローカル模擬モデルによるGraph仮説テストはCI #44295128892で2回実行・成功。実LLMの採用率は未検証。Abliteration AI の実回答0/2の未合格状態は変わらない。
- `aegis/validation/`, `aegis/remediation/`: 登録済み合成2組織の固定fixtureだけをMacのsandbox-exec、Linuxでは既存KernelConfinementのcgroup/nftables/名前空間で検証する経路を実装し、ローカルDraft差分を生成。Linux実機の合成経路はCIで成功。AssessmentServiceの共有WorkerPoolを使うため、緊急停止の対象に入る。Worker起動直前の組織権限リースと結果保存前の再確認を通す。GraphServiceが仮説・検証・修正を組織別DBに保存。顧客コードの任意実行・実PR作成は行わない。
- `aegis/server.py`: 組織境界、既存セッション/CSRF/監査/ロール再確認を通すGraph API。HTTPから任意パスやURLを入力できない。
- `web/src/app/security-graph/`, `attack-paths/`, `remediations/`: 日本語の経路・根拠・予測・合成修正表示。390pxと1280pxのChromium実ブラウザでグラフ選択、証拠、修正効果、横幅はみ出し無しを確認（合成APIモック、`/tmp/vulnix_graph_browser_test.py`）。さらに実バックエンド＋Next.jsの通しE2Eで、合成Next.js＋FastAPIのGitソース登録→解析→仮説→Mac隔離検証→Draft差分表示を両幅で確認（`/tmp/vulnix_graph_live_browser.py`）。
- `2750e48` では関連116件（19件スキップ）、バックエンド全1,818件成功（29件スキップ）、Web123件、lintエラー0（既存警告5）、build、Ruffが成功。`149f1ad` では隔離リレー後片付けの関連90件（4件スキップ）、バックエンド全1,819件成功（29件スキップ、`/tmp/vulnix-graph-v2-backend-149f1ad.log`）、Ruffが成功。[Linux CI #44300217997](https://github.com/FORIFOR/Vulnix/actions/runs/44300217997) は3ジョブ成功。最新コード `edb3ae5` ではPython/TypeScriptの認可ガードをAST上の直接比較・直接拒否に限定し、条件付き拒否、403応答へのデータ混入、先行returnをunknownに残す。Next.jsの静的なexported arrow handlerを抽出し、動的handlerはunknownのまま。関連31件、バックエンド全1,827件成功（29件スキップ、`/tmp/vulnix-graph-v2-backend-edb3ae5.log`）、Web123件、lintエラー0（既存警告5）、build、Ruff、実バックエンド＋Next.jsの390px/1280pxブラウザE2Eが成功。[Linux CI #44306364319](https://github.com/FORIFOR/Vulnix/actions/runs/44306364319) はWeb・実ARTEX・Pythonの3ジョブ成功。Linux Python全1,827件（20件スキップ）とカーネル隔離・緊急停止12件も成功。CIログに `ResourceWarning` は0件。

## 未完了のゲート

- [先行Linux CI #44280933793](https://github.com/FORIFOR/Vulnix/actions/runs/44280933793) の高FD失敗は `selectors.DefaultSelector` と高FD回帰テストで解消。[CI #44295128892](https://github.com/FORIFOR/Vulnix/actions/runs/44295128892) は `2750e48` で3ジョブ成功したが、実ARTEXログに隔離リレーの未クローズ `ResourceWarning` があった。`b0815a8` で終了時の読取パイプを閉じ、[CI #44300217997](https://github.com/FORIFOR/Vulnix/actions/runs/44300217997) と最新コードの[CI #44306364319](https://github.com/FORIFOR/Vulnix/actions/runs/44306364319) ではPython全件・Linuxカーネル隔離と緊急停止・Web・実ARTEXの3ジョブ成功。実ARTEXのGraph仮説テストは先行CIで2回とも成功し、最新CI全ログの `ResourceWarning` は0件。CI内のモデル応答は明示的なローカル模擬サーバーであり、有料の実モデルへは送っていない。独立した安全レビューは未確認。Mac合成サンドボックスを顧客コードの隔離実行に転用しない。
- Python/TypeScriptの動的認可、共通ミドルウェア、AI/MCP、依存関係全体の解析精度は未測定。既知の合成ケースのみ確認し、未知コードでの誤検知率・見逃し率は未測定。
- GitHub Appの顧客リポジトリ接続、実モデル、実サイト、実Draft PR、継続監視、公開判定は未実装/未承認。合成結果を実証済みの顧客問題として扱わない。

## 再開コマンド

```sh
cd /Users/shuhei/Projects/Vulnix-security-graph-v2
git status --short --branch
git diff --check
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests
ruff check aegis tests
cd web && npm test && npm run lint && npm run build
```

## 旧作業ツリーの履歴

更新: 2026-11-18。基点は Draft PR #85 の `6565a3aca9a21822ea57902dc5b88549b9bd13f4`。
作業ツリー: `/Users/shuhei/Projects/Vulnix-security-graph-e2e`。
ブランチ: `codex/security-graph-e2e`。新規コミットはまだない。元の作業ツリーは変更していない。

## 現在の差分

- `aegis/connectors/github_source.py`: ローカルの清潔な Git checkout と40桁コミットの確認。GitHub App 接続は未実装。
- `aegis/security_graph/`: Python AST による FastAPI 型ルート、処理、依存注入、import依存関係、データ参照の一部を抽出。Next.js の route.ts(x) は解析不能として unknown に記録。Git 管理外のファイルを索引せず、解析は指定コミットの Git blob を読む。証拠はパス、行、コミット、行ハッシュで保持する。
- `aegis/research/`: オフライン規則ベース仮説、厳格な出力スキーマ、根拠照合、独立した保守的な反証、レポート組み立て。実 ARTEX と外部推論モデルへの接続は未実装。
- `aegis/validation/`, `aegis/remediation/`: 固定の合成2組織ケースだけを Mac の sandbox-exec で実行し、修正前の越境参照、修正後403、同一組織の正常参照を確認。修正テンプレートは `api.py` の特定のAST形だけに対応。GitHubへのPR作成はしない。
- `aegis/assessment.py`, `aegis/server.py`: 組織ごとの読み取りレポート API `/api/research/report`。他組織からの読取拒否テストを追加。
- `web/src/app/research/page.tsx`: 保存済みレポートのグラフ、仮説、証拠、ローカル差分、検証履歴を日本語表示。レポートがないときは空状態を表示。

## 確認と限界

- 関連単体テストと組織分離テストは成功。Web の `npm test` は118件成功、lint はエラー0・既存警告5、build は成功。
- 解析品質の観測は合成FastAPI 1件の不備候補と明示ガード1件の棄却だけ。誤検知0/1、見逃し0/1はこの既知条件に限定し、未知コードへの精度は未測定。
- 修正前・修正後の合成証拠を含む一時レポートは `/tmp/vulnix-research-ui/research-report.json` に保存した。永続的な製品データや実サイトの証拠ではない。
- 最初の全バックエンドテストは1,714件実行、27件スキップ、18件エラー。18件すべて固定ラボポートの `Address already in use`。同時に別作業ツリーの全件テストが動いていた。競合解消後、最終差分で単独再実行し **1,767件実行・27件スキップ・残り1,740件成功**（`/tmp/vulnix-security-graph-full-final.log`、1235.126秒）。模擬HTTP切断ケースの `BrokenPipeError` はサーバーログに出たが、unittest 最終判定は `OK`。
- ブラウザ操作ホストが利用できず、390px・1280pxの実ブラウザE2Eは未確認。
- Linux CI は未確認。Mac の合成サンドボックス経路は Linux でスキップされる。Mac 側は固定ハーネスにネットワーク禁止、ホーム領域の読取・書込禁止、CPU・時間・出力サイズ制限を設定した。隔離の敵対的検証、メモリ上限、既存緊急停止への接続は未実装。生成コードや顧客コードの実行には使わない。Linux 隔離基盤への接続が必要。
- Graph の広範な解析精度、未知アプリでのモデル性能、ARTEX再利用、顧客コードの隔離実行、GitHub App接続、実 Draft PR、日本語UIの通しE2Eは未達。実Abliteration AI の採用率0/2は変わらない。
- 顧客コードへ広げる前に、diff の秘密情報除去、組織ごとの保存権限、Linux のネットワーク・ファイル・メモリ隔離、緊急停止連動を製品ゲートとして実装・検証する。
- 合成ラボ結果を実サイト・顧客コードの実証と扱わない。

## 再開コマンド

```sh
cd /Users/shuhei/Projects/Vulnix-security-graph-e2e
git status --short --branch
git diff --check
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests -p test_security_graph.py
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests -p test_source_workflow.py
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest tests.test_tenancy.TestTenantIsolationOverHttp.test_research_report_is_scoped_to_its_organization
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests
cd web && npm test && npm run lint && npm run build
```

次は全件失敗の原因を修正し、Linux隔離を用いた合成ケースの実行、Python/Next.jsのAST解析強化、ARTEXからの構造化仮説生成、保存済み結果のブラウザE2Eを順に実施する。実顧客リポジトリへの接続・PR作成は対象と権限の明示承認後の別ゲートとする。

## PR #85 の以前の再開記録

この節は基点側の記録を保持したもの。上の新アーキテクチャ作業と混同しない。

- 作業ツリー `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、最新検証済みコミット`e1011af`（最新製品コードは`d199021`、後続はテスト・資料・ブラウザQA）、Draft PR #85。別ツリーの変更には触れない。再開時は`git status --short --branch`、`git diff --check`、`git log -3 --oneline`を確認する。
- [Linux CI #44293223522](https://github.com/FORIFOR/Vulnix/actions/runs/44293223522)は試行1のPythonが約51分後にログなしで失敗し、試行2は約27分で3/3成功。初回の原因は未特定。次の差分では`.github/workflows/ci.yml`のPython全件を非バッファ出力・42分上限・`tee`で記録し、失敗時もログartifactを回収する。ランナー消失ならartifactも失われ得る。新CIでログとartifactの動作を確認し、再発なら試験名・停止点・ランナー状態を切り分ける。
- 重点読み取り再監査では所有確認、組織権限、ARTEX/Gateway/Worker、費用予約、緊急停止に新たな具体的P1/P2なし。ただし195ファイル全体と正式Approveの代替ではない。`scripts/public-app.sh`の広い実サイトモード拒否を確認したが、公開βの実際の設定とランチャー利用は未確認。390pxのSSE遮断・無通知所見変更の模擬実行は7.83秒で表示回復、対象GET2・API24・ページエラー0。次の自律作業は新CIの結果とartifactを確認し、動的API・失効・未検証画面の模擬検証を進める。
- `f68cbaf`では公式OpenAPIの推論設定をローカル候補に限定し、実外部送信へは通さない。Gatewayの過大・片側・不正usage、評価器の未知終了理由を安全側で拒否。独立した読み取りレビューの2指摘を修正済み。関連98件、修正後の評価器19件、Ruff、Web118件、Lintエラー0/警告5、ビルド成功。実モデル送信、実サイト通信は0。
- 最新`d199021`と所見保持テストの単独ローカル全1,742件成功・27件スキップ・ResourceWarning 0件（1219.162秒、`/tmp/vulnix-pr85-d199-full-isolated.log`）。[Linux CI #44272121286](https://github.com/FORIFOR/Vulnix/actions/runs/44272121286)もPython・Web・実ARTEXの3/3成功。Web119件、Lintエラー0/警告5、ビルド、Ruff、390px模擬ブラウザが成功（8操作、対象GET2、モデル0、追加検査を行った検証用プランナーの表示と固定検査のみ文言の非表示）。最初の全件実行は別作業ツリーとの固定ポート競合30件で無効だったが、単独再実行では再発しなかった。
- [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)と[AUTONOMOUS_PROGRESS.md](AUTONOMOUS_PROGRESS.md)へ証拠を反映し、PR #85本文・[正式レビュー資料](SECURITY_REVIEW.md)を更新した。開発ブランチの最終CIを確認する。実Abliteration AIは0/2採用のままで、未送信候補の要求SHAは[ABLITERATION_OUTPUT_CONTRACT.md](ABLITERATION_OUTPUT_CONTRACT.md)に記録。追加有料送信には新しい承認が必要。
- 今回の資料・テスト更新は`tests/test_real_service.py`の固定L1所見保持アサーションと`docs/ABLITERATION_OUTPUT_CONTRACT.md`、`docs/AUTONOMOUS_PROGRESS.md`、`docs/GOAL_COMPLETION_MATRIX.md`、`docs/NEXT_ACTION.md`、`docs/RELEASE_READINESS.md`、`docs/SECURITY_REVIEW.md`を含む。後続の処理系統更新は`docs/CURRENT_FLOW.md`、`docs/PROCESS_AUDIT.md`、`docs/PROCESS_INVENTORY.json`にP42〜P45と機械再抽出を追加した。再開時は作業ツリーに未コミット変更があれば保護し、最終CIを確認する。別ツリーの変更には触れない。
- 次の承認不要作業は、最終CIの確認、PR #85本文の証拠更新、`scripts/flow_inventory.py`が解決できない動的経路の照合、未確認ブラウザ経路の模擬検証。正式GitHubレビュー、実DNS・許可済み実サイトE2E、main統合・公開は別ゲート。いずれも未完了を維持する。
- `eaa162c`のLinux CI #44277414011はWeb・実ARTEX成功、PythonがSSEテスト終了時の一時ディレクトリ競合1件で失敗した。`tests/test_server.py`の後片付けで診断runnerの停止・joinを加えた`42f101d`では、該当1件、同ファイル全30件、ローカル全1,742件成功・27件スキップ・ResourceWarning 0件。[Linux CI #44282408784](https://github.com/FORIFOR/Vulnix/actions/runs/44282408784)は3/3成功。次は正式レビュー資料の最終照合と、実DNS・実モデルの外部ゲートに必要な承認を整理する。
- 資料のみの先頭`6572d9c`でも[Linux CI #44287588026](https://github.com/FORIFOR/Vulnix/actions/runs/44287588026)は3/3成功。390px複合ブラウザQAでは`--cors-note`を`--revoke-session`より先に検証するよう`bench_browser_owned_flow.py`の順序を修正し、CORS観測・未実証事項、レポート、SSE再接続、組織切替、失効後非表示を同時に確認した。次のコードコミットでこのスクリプト修正のCIを確認する。実モデルと実DNS・許可済み実サイトE2E、正式レビューは別ゲートとして未完了。
