# Vulnix 初期構想（12項目）と実装・検証のトレーサビリティ表

更新日: 2026-11-28 JST
対応判定表: [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md) / 公開β判定: [RELEASE_READINESS.md](RELEASE_READINESS.md)

本資料は、Vulnixの初期構想12項目を実コード・API経路・権限・テスト・実証範囲に対応付け、**安全基盤の完成率と製品価値の完成率を混同しない**ために次の3軸で個別評価する。
- **実装済みか（Implementation）**: 製品コード・UI・データ構造が存在するか
- **正しく動作する証拠があるか（Verification Evidence）**: 単体・統合・隔離ブラウザ等で再現可能な合格証拠があるか
- **実ユーザーに価値を提供できるか（Customer Value Readiness）**: 公開β環境や実サービス・実モデルで顧客がそのまま価値を得られる状態か

判定値は `PASS`（記載範囲で実証）、`FAIL`（確認した不合格）、`NOT_TESTED`（証拠未十分）、`BLOCKED`（外部承認・設定・インフラが必要）を使用する。


## 2026-11-28 時点の完成度とリリース判定（PR #134）

区分：**実装済み**＝コードと画面がある／**ラボ検証済み**＝合成ラボ・CI・実 CLI・配備候補 VM で合格／**実務検証済み**＝管理下の実プロジェクトまたは承認済みの実サービスで、発見・根拠・修正・再検証まで確認。

| 初期構想 | 対応 | 実装済み | ラボ検証済み | 実務検証済み |
| --- | --- | :---: | :---: | :---: |
| 簡単なフォルダ診断 | V01・V07・V11 | ○ | ○ | **一部**（管理下の実プロジェクト3件。下記） |
| Claude Code への防御評価（静的） | V04 | ○ | ○ | 一部（実プロジェクトの設定を確認） |
| Claude Code への防御評価（実行時） | V04・V12 | ○（公開候補では有効化不可） | ○（実 CLI・自己診断。完全な隔離は未証明） | 未 |
| ARTEX への防御評価 | V03・V04 | ○ | 限定的 | 未 |
| A2B（静的：API 定義・ルート） | V05 | ○ | ○ | **一部**（実 FastAPI 2件で認証の読み取りを改善） |
| A2B（実行時） | V05 | ○（組織別の下書き・管理者承認） | ○（合成ラボ 3項目） | 未（実サイト L2 は禁止） |
| 最新 CVE への対策 | V09 | ○ | ○（ラボで版一致→実証→修正後再現せず） | 未（最新の CVE データ取得は承認待ち） |
| 修正パッチ | V07・V10 | ○（5分類） | ○（サンプルアプリ） | 一部（実プロジェクトの CI・Dockerfile の修正を再診断で確認） |
| 修正後の再検証 | V06・V07 | 一部 | ○（ラボ） | 一部（静的な再診断のみ） |
| Security Intelligence | V09・V11 | ○ | ○ | 未 |
| AI による診断・修正支援 | V03・V08 | ○ | 評価済み：固定ルールを上回っていない（固定95・AI 64.8・併用87.2） | 未 |
| 実サービスでの診断 | V01〜V12 | — | — | 未（DeepNote の承認待ち） |

### 実務評価（管理下の実プロジェクト、2026-11-28）
`scripts/scan_project_cli.mjs`（画面と同じ `scanProject`。秘密ファイルは開かず、内容は出力しない）と API 定義の解析で評価した。

| 対象 | 発見 | 判定 | 修正と再検証 |
| --- | --- | --- | --- |
| Vulnix | CI の Actions がタグ指定（コミット SHA 固定でない） | 正しい指摘 | 6種14か所を SHA に固定 → 再診断で解消、CI で動作確認 |
| Vulnix | テスト用の脆弱なサンプル 11件 | 検出は正しいが、実務上はノイズ | 未対応（テスト用フォルダの扱いは今後の改善候補） |
| Vulnix | ソース内の秘密鍵形式 2件 | 合成の文字列。「未確認」表示で妥当 | — |
| Lisen | frontend の Dockerfile が root で動く | 正しい指摘 | 複製に USER を追加 → 再診断で「対策が必要」が消える（元のプロジェクトは変更していない） |
| Lisen | backend の Dockerfile も root だが「未確認」止まり | **見逃し（過小評価）** | 規則を修正：既定で root の公式イメージ（python・ruby・golang など）も検出 |
| MOKO_EIGO | `USER 10001` 指定済みなのに理由が不明確 | 誤解を招く表示 | 「非rootを指定済み、配備側の上書きは未確認」と表示 |
| Lisen・MOKO_EIGO（API） | 認証の有無が「未確認」が大半（68件中61件、23件中23件） | **誤った未確認（読み取り不足）** | FastAPI の依存関係の別名とアプリ全体の 401 ミドルウェアを読むよう修正 → 未確認は 1件・2件に |
| Lisen（API） | `GET /sessions/{sid}` などに所有者の照合がない候補 | 候補（端末単位の認証のみ。複数利用者で使うなら問題） | 所有者の判断が必要 |

未評価：依存関係の CVE（最新の NVD・OSV データを取得していないため、同梱の2件のサンプルでしか照合していない）、Launchloom（読み込みに失敗。原因は未調査）。

### 配備候補の評価（2026-11-28）
| 候補 | カーネル・OS | 実カーネル隔離（スキップ不可） | 通信制限・緊急停止・権限昇格防止など6項目 | 永続化・監査・監査アンカー |
| --- | --- | --- | --- | --- |
| Lima `vulnix-l2` | 7.0.0-28 / Ubuntu 26.04 / Python 3.14 / nftables 1.1.6 | 10/10 | 6/6 | 213件合格 |
| Lima `vulnix-rc-debian13` | 6.12.118 / Debian 13 / Python 3.13 / nftables 1.1.3 | 10/10 | 6/6 | 206件合格 |
| Cloud Run | — | 未検証（単一プロセスの保証にならないことを文書化済み） | 未検証 | 未検証 |

配布物：0b0484b の Web 配布物をオフラインで作成（Node 22.23.5）。SBOM は 117 部品で、前回の正式受入（41f86b5）と同じ構成（差は sharp のプラットフォーム別バイナリだけ。今回は macOS で作成、正式は Linux で作る必要がある）。最新 CVE との照合は、データ取得の承認待ちで未実施。

### 段階的な提供範囲（案）
- **限定βで提供可能：** フォルダ診断、CVE 照合（データ取得後）、静的な防御評価（Claude Code の設定・Dockerfile・CI・API 定義）、修正差分、分析画面。
- **実務受入後：** Web・API の L1 診断、所有確認、実診断結果の分析。
- **検証・研究段階：** ARTEX による高度な追加診断、実行時の A2B 診断、Claude Code の実行時診断、AI による修正生成（固定ルールを上回る証拠はない）。

### リリース判定：限定βも未承認、正式リリースは不可（2026-11-28）
技術的に解消した阻害要因：Claude Code 実行時診断を公開候補で有効化できない構成、A2B の独立レビュー指摘、配備候補 VM での実カーネル検証、オフラインでの配布物と SBOM の作成。

残る阻害要因（外部の承認・操作が必要）：
1. 最新の CVE データ（NVD・OSV）の取得の承認と、配布物 SBOM との照合。
2. 正式な GitHub レビュー（PR #127〜#134 はすべて Draft、レビュー0件）。
3. DeepNote での許可済み L1 診断（承認待ち）。
4. 配備先（Cloud Run か VM か）の決定と、そこでの実測。
5. Google 認証の実機確認（補助機能）。

PR の依存関係：#127（main 向け）← #128 ← #129 ← #130 ← #131・#132・#133 ← #134。#127〜#133 の内容はすべて #134 に含まれ、各 PR の CI は合格している。

---

## 実機受入の判定範囲

- V01、V02、V05、V06、V07、V09〜V11の画面と診断データは、ローカルの実装・試験結果を根拠とする。DeepNote STGの所有確認、実測結果、修正、再検証の使いやすさは未評価。
- V03の実モデルによる選択実測は承認時点の14条件と1回の成功応答に限る。実ARTEXと模擬モデルの検査選択は別の測定。実Abliteration AIの日本語解説品質（V08）とDeepNoteでの選択精度は未評価。
- V04、V12のCIは試験ランナーの隔離と認可を検証する。正式配備先のカーネルと公開経路での安全性は別途検証が必要。
- プロジェクト画面のグループは表示用。登録、所有確認、診断許可、実行結果は引き続き資産単位。ソースとSBOMの照合はブラウザ内で行い、配備時の挙動を確定するには実測または許可済み防御テストが必要。

---

## 3軸サマリー一覧

| 機能ID | 初期構想の項目 | 実装済みか | 動作証拠（ローカル/CI） | 実ユーザー価値（公開β） | Goal完了判定表との対応 |
| --- | --- | :---: | :---: | :---: | --- |
| **V01** | 自分のWebサイトやAPIの登録 | PASS | PASS | NOT_TESTED（実環境） | 資産・診断POSTの送信時権限 / URL登録→所有確認→結果表示 |
| **V02** | 所有権・診断範囲・許可内容の確認 | PASS | PASS（模擬DNS/HTTP/Google） | BLOCKED（実DNS・OAuth公開設定は承認待ち） | 所有確認照会中の権限失効 / OAuth / 公開βの実DNS |
| **V03** | ARTEXとAIが観測事実から必要な検査を選択 | PASS | PASS（実ARTEX＋ローカル模擬モデル、実Abliteration AI 14条件選択1/1） | 限定PASS（14条件小標本の選択TP8/FP0/FN0/TN6実証・多段階は未測定） | 実ARTEX→Gateway / 5分類の選択性能 / 実Abliteration AI 14条件 |
| **V04** | Gatewayの提案検証と隔離Workerによる実行 | PASS | PASS（Linux nftables・egress_sentinel） | BLOCKED（配備先の隔離未確認） | ARTEXの直接通信・任意操作禁止 / 実サイトL2禁止 |
| **V05** | CORS/Cookie/認証/アクセス制御/情報露出/TLS/CVEの証拠付き診断 | PASS | PASS（独立ラボ・HTTPS・Set-Cookie値秘匿） | BLOCKED（許可済み実サイトL1 E2Eは承認待ち） | CORS・Cookie・認証・IDOR・情報露出の独立ラボ |
| **V06** | candidate / detected / proven / not_reproduced の厳格な区別 | PASS | PASS（バックエンド強制・UI集計分離） | NOT_TESTED（実機利用） | candidate / detected / provenの証拠整合 |
| **V07** | 危険度・根拠・影響・修正方法・再診断結果の初心者向け表示 | PASS | PASS（390px/1280px・所見詳細12項目） | NOT_TESTED（実機利用） | 390px・1280pxのローカル模擬操作 |
| **V08** | Abliteration AIなどによる安全な日本語解説 | PASS | PASS（ローカル検証器・内蔵フォールバック） | NOT_TESTED（実モデル解説は未測定・内蔵解説はPASS） | 構造化出力の安全境界 / 実Abliteration AIの日本語解説品質 |
| **V09** | 最新CVE情報の取り込みと対象ソフトウェアとの関連性評価 | PASS | PASS（該当/非該当/バージョン不明/未取得の分離） | NOT_TESTED（実配備との照合） | CVE状態GETの失効競合 / [CVE_READINESS.md](CVE_READINESS.md) |
| **V10** | 学習モード（セキュリティを理解しながら改善） | PASS | PASS（3段階解説・学習履歴・修正確認手順） | NOT_TESTED（実機利用） | [USER_JOURNEY_E2E.md](USER_JOURNEY_E2E.md) |
| **V11** | 白基調・シンプルかつ洗練された実用的UI | PASS | PASS（390px/1280px・横スクロール0・エラー0） | NOT_TESTED（実機利用） | 390px・1280pxのローカル模擬操作 |
| **V12** | 実行制御・監査・費用上限・停止・組織分離の維持 | PASS | PASS（1,898+件のバックエンド・Linux CI） | BLOCKED（配備先での実測待ち） | 認証・組織分離・権限失効 / 安全停止 / 費用上限・監査 |

---

## 各項目の詳細棚卸し（V01〜V12）

### V01: Webサイト・APIの登録
- **機能ID**: V01
- **ユーザーに提供する価値**: 診断したい自分のWebサイトやAPIのURLを登録し、対象ごとの所有確認トークンとワークスペースを安全に準備できる。
- **現在の実装ファイル**: `web/src/components/OwnershipWizard.tsx`, `aegis/server.py`, `aegis/assessment.py`, `aegis/ownership.py`
- **実際の呼び出し経路**: `OwnershipWizard.issue` → `POST /api/assets/challenge` → `server.py::_dispatch` → `AssessmentService.issue_ownership_challenge` → `ownership.challenge_for_host`
- **必要な権限**: ログイン済みセッション、対象組織の `operator` / `approver` / `admin` ロール（CSRFヘッダー `X-Aegis-Request: 1` 必須）
- **入力・出力**: 入力 `{url, kind, environment}` → 出力 `{asset, challenge: {token, dns_txt_name, dns_txt_value, well_known_url, well_known_content}}`（登録時点では対象へのネットワーク通信は0回）
- **既存テスト**: `tests/test_real_service.py`, `tests/test_tenancy.py`, `scripts/bench_browser_owned_flow.py`
- **実証済み範囲**: URL解析、プライベートIP/不正スキーム拒否、組織別の資産分離、処理中ログアウト時の401秘匿、390px/1280pxブラウザからの登録操作。
- **未実装機能**: なし
- **未検証機能**: 公開β中継（Cloudflare等）越しの登録操作
- **合格条件**: 登録時に対象へ通信せず、他組織から資産や確認トークンが参照できないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: 公開β環境での通し確認（Gate F）に含める。

### V02: 所有権・診断範囲・許可内容の確認
- **機能ID**: V02
- **ユーザーに提供する価値**: 第三者サイトへの無断診断を防ぎ、所有者が明示したホスト・ポート・有効期限・追加GET同意だけを署名付き台帳に記録してから診断を開始できる。
- **現在の実装ファイル**: `aegis/ownership.py`, `aegis/google_ownership.py`, `aegis/authority_ledger.py`, `aegis/assessment.py`, `web/src/components/OwnershipWizard.tsx`
- **実際の呼び出し経路**:
  - DNS/ファイル: `POST /api/assets/verify-ownership` → `AssessmentService.verify_asset_ownership`
  - Google OAuth: `POST /api/assets/google/start`, `/finish` → `google_ownership.py`
  - 範囲確定: `POST /api/assets/confirm-scope` → `AssessmentService.confirm_asset_scope` → `AuthorityLedger`
- **必要な権限**: 所有確認は組織 `operator` 以上、範囲確定（`confirm-scope`）は組織 `approver` または `admin`
- **入力・出力**: 入力 `{url_or_host, method, confirmed_prohibited, allow_status_probe}` → 出力：署名付き所有証明・範囲エントリおよび更新後スナップショット
- **既存テスト**: `tests/test_real_service.py`, `tests/test_google_ownership.py`, `tests/test_authority_ledger.py`, `tests/test_tenancy.py`
- **実証済み範囲**: DNS TXT照合、`.well-known` 固定IP取得、Google Search Console OAuth状態検証、照会中のログアウト・権限剥奪時の保存拒否と401/403応答、期限切れ時の自動失効。
- **未実装機能**: なし
- **未検証機能**: 実DNSサーバーでのTXTレコード照会E2E、本番Google OAuthクライアント設定での実認証
- **合格条件**: 所有未確認・期限切れ・禁止事項未同意の対象にはWorkerが一切起動しないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `BLOCKED`（実DNS・公開β設定の承認待ち）
- **次のアクション**: 所有者承認後に実DNS TXT確認を1ホストで実施する（Gate E）。

### V03: ARTEXとAIによる観測事実からの検査選択
- **機能ID**: V03
- **ユーザーに提供する価値**: 初回GETの観測事実（サーバー種別、ヘッダー、Link関係など）から必要な追加検査（Apache `mod_status` やラボ内の認可境界確認など）だけを選び、不要な検査通信や見逃しを減らす。
- **現在の実装ファイル**: `aegis/artex_bridge.py`, `integrations/artex/overlay/agent/vulnix_bridge.go`, `aegis/planner_llm_gateway.py`, `aegis/assessment.py`, `scripts/eval_selection_model.py`
- **実際の呼び出し経路**: `AssessmentService._run_inner` / `plan_with_artex` → `safe_public_fingerprint` / `anonymous_real_site_request` → `run_artex_planner`（実ARTEXバイナリ）→ `PlannerLLMGateway` → `reconstruct`（固定カタログ照合）
- **必要な権限**: 署名済み初期観測（`result_audit_hash`）、追加L1検査の明示同意（`allow_status_probe`）、Gatewayのトークン・予算枠
- **入力・出力**: 入力：匿名化された固定enum特徴量（URL・ホスト名・生の応答本文・秘密値を含まない）→ 出力：`CATALOG` 内の計画項目（`PlanItem`）または実行不能な助言（`Advisory`）
- **既存テスト**: `tests/test_artex_bridge.py`, `tests/test_status_exposure_lab.py`, `tests/test_access_control_lab.py`, `tests/test_five_class_holdout.py`, `tests/test_selection_model_eval.py`, Linux CI `artex-real-planner` ジョブ
- **実証済み範囲**: 実ARTEXバイナリ＋ローカル模擬モデルでの5分類17条件（選択TP9/FP1/FN0/TN7、Precision 0.900、Recall 1.00）、Link 7条件、初回事実再利用による推論回数削減（8→5回、3→2回）。さらに実 `abliterated-model` に対して公式仕様の `reasoning_effort: "none"` + `response_format: {"type":"json_object"}`（SHA `7a527a487a309962867f7d02096e527259946f2b62fdbf802a450d386e3803e5`）を1回限定承認のもと実送信し、推論0・出力44トークン・`stop`終了・1.022秒でJSON採用（1/1、通算1/3）、**TP=8/FP=0/FN=0/TN=6（Precision/Recall/F1 = 1.000、不要検査率0.000、見逃し率0.000）** を実証（[ABLITERATION_SELECTION_REAL_RESULT.md](ABLITERATION_SELECTION_REAL_RESULT.md)）。
- **未実装機能**: なし
- **未検証機能**: 14条件小標本以外の分類や多段階ARTEXツール呼び出しループでの実Abliteration AI評価
- **合格条件**: 許可カタログ外の操作を実行できず、AI失敗時にも固定L1の証拠を保持し、実モデルまたは承認された代替モデルで選択JSONが安定採用されること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS`（実ARTEX＋模擬モデル、および実モデル14条件選択1/1） / 実ユーザー価値 `限定PASS`（14条件小標本で選択精度100%実証・失敗時は固定L1証拠保持）
- **次のアクション**: 他分類・多段階ARTEXループへの実モデル適用を拡張する場合は別途承認を得る（Gate C）。

### V04: Gatewayの提案検証と隔離Workerによる実行
- **機能ID**: V04
- **ユーザーに提供する価値**: AIやプランナーの提案をそのまま信用せず、Gatewayがスコープ・ピン留めIP・単回トークン・期限・停止状態を直前審査し、隔離されたWorkerだけが非破壊検査を実行する。
- **現在の実装ファイル**: `aegis/gateway.py`, `aegis/policy.py`, `aegis/network.py`, `aegis/runtime.py`, `aegis/confinement.py`, `aegis/workers/egress_sentinel.py`, `aegis/workers/http_probe.py`, `aegis/workers/reproduction_probe.py`
- **実際の呼び出し経路**: `AssessmentService._exec` → `Gateway.execute` → `validate_proposal` / `EgressGuard.check` / `TokenAuthority.verify` → `KernelConfinement`（Linux nftables + cgroup）+ `egress_sentinel.py` → Worker起動
- **必要な権限**: 単回使用HMACトークン（TTL 120秒）、有効なEngagement期間、署名済み範囲、L2は依頼者と異なる承認者の承認ID
- **入力・出力**: 入力：`{tool, target_id, action, args}` → 出力：スキーマ検証・秘密値マスク済みの `Decision` と監査レコード
- **既存テスト**: `tests/test_gateway.py`, `tests/test_egress_sentinel.py`, `tests/test_http_probe_timeouts.py`, `tests/test_worker_deadline.py`, `tests/test_fail_closed.py`, Linux CI カーネル隔離検証
- **実証済み範囲**: スコープ外ドメイン100%拒否、DNSリバインディング防止（解決した単一IPへのピン留め）、リダイレクト非追従、タイムアウト時のプロセスグループ強制終了と未停止Worker記録による新規起動停止、実サイトL2の全面拒否（複数組織の旧設定1を含む）。
- **未実装機能**: なし
- **未検証機能**: なし（Linux実機相当のCI `nftables` 検証を含む）
- **合格条件**: 許可外のIP・ポート・ツール・L2操作が100%拒否され、隔離喪失時は起動せず結果も採用しないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `BLOCKED`
- **次のアクション**: 継続的に全件回帰とLinux CIで維持する。

### V05: CORS・Cookie・認証・アクセス制御・情報露出・TLS・CVEの証拠付き診断
- **機能ID**: V05
- **ユーザーに提供する価値**: Webサービスで頻発する設定不備や認可境界の問題を、所有者仕様と実際の応答証拠に基づいて高精度に診断し、新たに発行された認証Cookie値などの機微情報を一切保存・漏えいしない。
- **現在の実装ファイル**: `aegis/service_diag.py`, `aegis/workers/http_probe.py`, `aegis/workers/reproduction_probe.py`, `aegis/l2_rules.py`, `aegis/cve.py`
- **実際の呼び出し経路**: `http_probe` → `sanitize_set_cookie_header` → `Gateway` / `AssessmentService._exec` → `sanitize_http_probe_payload` → `analyze_l1_service_response` / `analyze_status_marker_report`
- **必要な権限**: 所有確認・範囲確定済みの対象（L1自動承認、L2は隔離ラボまたは承認済みプロファイルのみ）
- **入力・出力**: 入力：HTTP/TLS応答と承認済みサイトプロファイル（`cookie_policy`, `root_access`）→ 出力：証拠IDと監査ハッシュが紐付いた `Finding` 一覧
- **既存テスト**: `tests/test_cookie_purpose_lab.py`, `tests/test_cors_policy_lab.py`, `tests/test_auth_response_lab.py`, `tests/test_access_control_lab.py`, `tests/test_status_exposure_lab.py`, `tests/test_real_service.py`
- **実証済み範囲**:
  - CORS: 資格情報なしの公開ワイルドカード誤検知を0化し、資格情報付き反射/nullオリジンを検出（10条件 Precision/Recall 100%）
  - Cookie: 所有者仕様と応答属性の照合（10条件 Precision/Recall 100%）、ローカルHTTPS 6条件、**新規発行Set-Cookie秘密値のWorker/Gateway/Service/永続化境界での完全除去（P2解消）**
  - 認証/IDOR: HTTP 200認証拒否JSONの誤検知0化、所有者対照GETを伴うIDOR実証
  - Apache `mod_status`: 固定マーカーWorkerによる情報露出検出
  - TLS/ヘッダー/CVE: 旧TLS、平文HTTP、HSTS/CSP/XCTO、バナーCVE照合
- **未実装機能**: なし
- **未検証機能**: 許可済み実サイトに対する公開β環境からのL1通し診断（Gate F）
- **合格条件**: 独立ラボで誤検知・見逃しを増やさず、診断対象の認証Cookie生値がsnapshot/report/監査ログに残らないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `BLOCKED`（実サイトL1 E2Eは承認待ち）
- **次のアクション**: 所有者承認後に許可済み実サイトでL1診断を1回実行し検証する（Gate F）。

### V06: candidate / detected / proven / not_reproduced の状態区別
- **機能ID**: V06
- **ユーザーに提供する価値**: 「まだ調べていない候補」「設定から観測した問題」「隔離ラボで実際に成立を実証した問題」「修正後に再現しなかった項目」を明確に区別し、未実証のものを侵害成立と誤認させない。
- **現在の実装ファイル**: `aegis/evidence.py`, `aegis/assessment.py`, `aegis/remotion_export.py`, `web/src/lib/labels.ts`, `web/src/lib/idorEvidence.ts`
- **実際の呼び出し経路**: `enforce_verdict` / `evidence_status` / `evidence_summary` → `AssessmentService.snapshot` → Web `completedHeadline` / `FindingCard` / `FindingPage`
- **必要な権限**: 診断結果の閲覧権限（組織メンバー）
- **入力・出力**: `Finding` の `verdict` と `evidence`（`reproduction_probe` の監査ハッシュ有無）から `evidence_status` を決定
- **既存テスト**: `tests/test_evidence.py`, `tests/test_http_probe_timeouts.py`, `web/tests/labels.test.mjs`, `web/tests/idorEvidence.test.mjs`
- **実証済み範囲**: L1観測結果が `proven` にならない強制変換、完了見出し（`completedHeadline`）で `detected` / `proven` のみを「証拠のある問題」と数え `candidate` や `not_reproduced` を問題数に混ぜない表示、修正後再確認での `proven` → `not_reproduced` 遷移。
- **未実装機能**: なし
- **未検証機能**: なし
- **合格条件**: L1所見が `proven` と表示されず、候補のみの完了時に「問題を確認」と誤表示しないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: 回帰テストで維持する。

### V07: 危険度・根拠・影響・修正方法・再診断結果の初心者向け表示
- **機能ID**: V07
- **ユーザーに提供する価値**: 専門知識がない開発者や運営者でも、各所見の「何が観測されたか」「何がまだ証明されていないか」「起こり得る影響」「具体的な修正手順と確認方法」「証拠IDと検査元」を一画面で迷わず把握できる。
- **現在の実装ファイル**: `web/src/app/findings/[id]/page.tsx`, `web/src/components/findings/FindingCard.tsx`, `web/src/components/findings/FindingLearningCard.tsx`, `web/src/components/findings/RemediationPanel.tsx`, `web/src/components/findings/EvidencePanel.tsx`, `web/src/lib/findingReason.ts`, `web/src/lib/diagnosisSource.ts`
- **実際の呼び出し経路**: `GET /api/assessments/{id}` → `FindingCard` / `FindingPage`（`/findings/[id]?a={aid}`）→ 再確認 `POST /api/assessments/{id}/verify-fix` または `/verify-finding`
- **必要な権限**: 閲覧は組織メンバー、再検証実行は組織 `operator` 以上（L2は承認者）
- **入力・出力**: `Snapshot` 内の `Finding` オブジェクト → 所見詳細12項目（問題名、危険度、検証状態、何が観測されたか、何がまだ証明されていないか、起こり得る影響、修正方法、修正後の確認方法、証拠ID、検査日時、検査元、関連CVE）の表示
- **既存テスト**: `web/tests/findingReason.test.mjs`, `web/tests/diagnosisSource.test.mjs`, `web/tests/cookieChecks.test.mjs`, `scripts/bench_browser_owned_flow.py`, `scripts/bench_browser_lab_recheck.py`
- **実証済み範囲**: 所見詳細画面での全12項目の明示表示、AI追加検査が未実行の場合に実行済みと偽らない出所表示（`diagnosisSource`）、390px/1280pxブラウザでの表示と修正後再検証（HTTP 200 → 403、`proven` → `not_reproduced`）。
- **未実装機能**: なし
- **未検証機能**: なし
- **合格条件**: 所見詳細12項目が欠落なく表示され、出所（内蔵ルール/検証用プランナー/ピン留め実ARTEX）が正確であること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: 回帰テストで維持する。

### V08: Abliteration AIなどによる安全な日本語解説
- **機能ID**: V08
- **ユーザーに提供する価値**: 検出された所見について「なぜ検出されたか」「どう直すか」の日本語解説を提供し、外部AI利用時もURL・ホスト名・秘密値・生レスポンスを一切送らず、危険な提案や根拠のない断定を遮断して安全に利用できる（外部AI未設定・失敗時は内蔵解説へ自動フォールバック）。
- **現在の実装ファイル**: `aegis/ai_advisor.py`, `aegis/advisor_catalog.py`, `aegis/chat_guard.py`, `aegis/assessment.py`, `aegis/advisor_eval/dataset.py`, `aegis/advisor_eval/run.py`, `web/src/components/learning/ExplanationPanel.tsx`
- **実際の呼び出し経路**: `POST /api/assessments/{id}/chat` → `AssessmentService.ask_chat` → `_safe_real_ai_explanation`（`AbliterationAdvisor.advise`、予算予約・権限リース付き）または `_answer_question`（内蔵解説＋`chat_guard.check_answer`）
- **必要な権限**: 組織 `operator` 以上、外部AI送信時は監査ログの費用上限内かつ生存セッション・組織権限リース内
- **入力・出力**: 入力：匿名化された固定enum所見項目（`finding_to_payload_item`）または質問 → 出力：カタログ検証・テキストガード済みの日本語解説と注意事項（`verdict_note`, `cautions`）
- **既存テスト**: `tests/test_ai_advisor.py`, `tests/test_advisor_eval.py`, `tests/test_chat_answer_guard.py`, `web/tests/safeMarkdown.test.mjs`
- **実証済み範囲**:
  - 匿名化ペイロード（URL・ホスト名・Set-Cookie・秘密トークン・IPアドレスの完全除外）
  - 150ケース・1,267候補応答・6,149要素の評価データセットで構造的危険提案の拒否率100%（534/534）、禁止操作・禁止修正案の採用0件（`OTHER_RULE_OPS` / `OTHER_RULE_FIXES` の独立正解ラベル修正を含む）
  - 送信開始時の生存権限リースと再起動後の監査費用切り戻し検知
  - 外部AI未設定・失敗時の内蔵解説フォールバック
- **未実装機能**: なし
- **未検証機能**: 実Abliteration AIエンドポイントからの日本語解説JSON応答の採用率と品質測定（追加有料API送信には新規承認が必要）
- **合格条件**: 秘密情報や識別子を外部へ送信せず、許可カタログ外の操作を採用せず、AI失敗時に内蔵解説が機能すること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS`（ローカル検証器・内蔵解説） / 実ユーザー価値 `NOT_TESTED`（実モデル解説は未測定）
- **次のアクション**: 新規承認後に実モデル解説の採用率を測定するか、公開βでは内蔵解説を既定として提供する。

### V09: 最新CVE情報の取り込みと対象ソフトウェアとの関連性評価
- **機能ID**: V09
- **ユーザーに提供する価値**: NVD CVE 2.0およびCISA KEV（悪用確認済みカタログ）を取り込み、対象ヘッダーから観測された製品・バージョンとの関連性を評価しつつ、バナー一致だけで脆弱性成立（`proven`）と断定せず、データの出所・更新日時・鮮度・同期失敗を明示する。
- **現在の実装ファイル**: `aegis/cve.py`, `aegis/service_diag.py`, `aegis/assessment.py`, `aegis/feeds/nvd-recent.json`, `aegis/feeds/cisa-kev.json`, `web/src/lib/labels.ts`, `web/src/app/settings/page.tsx`
- **実際の呼び出し経路**:
  - 状態参照: `GET /api/cve/status` → `FeedMonitor.status` → Web `threatFeedSummary`
  - 同期: `POST /api/cve/sync` → `FeedMonitor.ingest_payloads`（管理者が与えたNVD/KEV JSONの取り込み）
  - 診断照合: `analyze_l1_service_response` / `AssessmentService._analyze` → `cve.detect_from_banner`
- **必要な権限**: 状態参照はログイン済みセッション、同期（`/api/cve/sync`）は全体 `admin` または `approver`
- **入力・出力**: 入力：NVD/CISA KEV JSONおよび観測バナー → 出力：`CveStatus`（件数、最終同期時刻、出所、`freshness`, `stale`, `nvd_sha256`, `kev_sha256`, `last_sync_error`）および所見の関連CVE候補
- **既存テスト**: `tests/test_cve.py`, `tests/test_final_review.py`, `web/tests/labels.test.mjs`
- **実証済み範囲**:
  - 複数製品を含むCVEでの他製品バージョン誤照合防止
  - ローカル固定CVE資料での4条件テスト：①該当バージョン（`Apache/2.4.49` → `detected`・高リスク・CVE付与）、②非該当バージョン（`Apache/2.4.58` → 低リスク情報露出・一致なし）、③バージョン不明（`Apache` / `Express` → バージョン不明のためCVE照合未判定と明示）、④フィード未取得（CVE照合未実施と明示）
  - 同期失敗時の既存カタログ保持・エラーと鮮度（`fresh` / `stale` / `unfetched`）およびSHA-256完全性ハッシュの記録・UI表示
- **未実装機能**: なし
- **未検証機能**: 公開β運用での定期外部フィード取得ジョブの運用設定
- **合格条件**: バナーだけで `proven` にせず、バージョン不明やフィード未取得を「脆弱性なし」と誤表示せず、出所と鮮度が追跡できること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: 詳細を [CVE_READINESS.md](CVE_READINESS.md) に記録。

### V10: 学習モード（セキュリティを理解しながら改善）
- **機能ID**: V10
- **ユーザーに提供する価値**: 各所見や専門用語について「かんたん」「詳しく」「専門家」の3段階解説と「なぜ問題になるのか」「どう直すのか」「直ったかをどう確かめるのか」を確認でき、学習履歴を振り返りながらセキュリティを改善できる。
- **現在の実装ファイル**: `web/src/lib/glossary.ts`, `web/src/lib/learningHistory.ts`, `web/src/components/learning/HelpPopover.tsx`, `web/src/components/learning/ExplanationPanel.tsx`, `web/src/components/findings/FindingLearningCard.tsx`, `web/src/app/settings/page.tsx`
- **実際の呼び出し経路**: 各画面の「？」ボタン（`HelpPopover`）→ `ExplanationPanel`（3段階切替＋`recordLearning`＋任意のAIコンテキスト解説質問）および所見詳細の `FindingLearningCard`
- **必要な権限**: ログイン済みセッション
- **入力・出力**: 用語キー（`sqli`, `idor`, `cve`, `security_headers`, `cors`, `info_disclosure`, `verdict_*`, `risk_level` 等）と所見コンテキスト → 3段階解説と安全な設定・確認手順の表示
- **既存テスト**: `web/tests/helpPopover.test.mjs`, `web/tests/safeMarkdown.test.mjs`, `tests/test_chat_answer_guard.py`
- **実証済み範囲**: 320px〜720px画面端でのポップオーバー見切れ防止（16条件）、内蔵3段階解説、学習履歴の保存とクリア、危険なコマンドや攻撃手順を含まない安全な解説表示。
- **未実装機能**: なし
- **未検証機能**: なし
- **合格条件**: 内蔵解説だけで「なぜ問題か・どう直すか・どう確かめるか」が完結し、モバイル幅でもポップオーバーが画面外にはみ出さないこと。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: 回帰テストで維持する。

### V11: 白基調でシンプルかつ洗練された実用的UI
- **機能ID**: V11
- **ユーザーに提供する価値**: 過剰なAI風装飾や複雑な画面遷移を排し、白基調で情報階層が明確な画面により、スマートフォン（390px）でもデスクトップ（1280px）でも登録から結果確認・再診断まで直感的に操作できる。
- **現在の実装ファイル**: `web/src/app/dashboard/page.tsx`, `web/src/app/assessments/[id]/page.tsx`, `web/src/app/findings/[id]/page.tsx`, `web/src/app/assets/page.tsx`, `web/src/app/settings/page.tsx`, `web/src/components/ui.tsx`, `web/src/components/layout/WorkspaceHeader.tsx`
- **実際の呼び出し経路**: Next.js App Router 各画面 → `/api/[...path]` プロキシ → バックエンドAPI
- **必要な権限**: ログイン済みセッション（未ログイン時は `/login` または公開ランディング `/`）
- **入力・出力**: ユーザー操作 → 8操作での診断結果到達、横スクロールなし、危険度バッジと検証状態バッジの分離表示
- **既存テスト**: `web/tests/*.test.mjs`（123件）、`scripts/bench_browser_owned_flow.py`（390px / 1280px）、`scripts/check_cookie_ui_390.py`, `scripts/bench_browser_lab_recheck.py`
- **実証済み範囲**: 390pxおよび1280pxの本番ビルド（`next build` / `next start`）でのループバック模擬ブラウザE2E（ログイン後8操作、対象GET 2回、ページエラー0、横スクロールなし）。
- **未実装機能**: なし
- **未検証機能**: なし
- **合格条件**: 390pxと1280pxの両方で横スクロールやページエラーがなく、危険度と検証状態が別バッジで明瞭に表示されること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `NOT_TESTED`
- **次のアクション**: [USER_JOURNEY_E2E.md](USER_JOURNEY_E2E.md) に全工程の検証記録を保持する。

### V12: 実行制御・監査・費用上限・停止・組織分離の維持
- **機能ID**: V12
- **ユーザーに提供する価値**: 複数組織（マルチテナント）での完全なデータ分離、SHA-256ハッシュチェーン監査ログ、外部AI費用の原子的上限管理と切り戻し検知、いつでも即座にWorkerを強制終了できる緊急停止により、企業やチームが安心して利用できる。
- **現在の実装ファイル**: `aegis/tenancy.py`, `aegis/operators.py`, `aegis/server.py`, `aegis/audit.py`, `aegis/gateway.py`, `aegis/planner_llm_gateway.py`, `web/src/components/layout/SessionProvider.tsx`
- **実際の呼び出し経路**:
  - 組織分離: `server.py::_get_org` / `_bind` / `_authorized_org_read` → `TenantRegistry.service`
  - 緊急停止: `POST /api/assessments/{id}/emergency-stop` → `AssessmentService.emergency_stop` → `Gateway.emergency_stop`
  - 監査・費用: `AuditLog.record` / `record_with_budget`
- **必要な権限**: 組織メンバーシップ検証（毎リクエストおよびレスポンス送信直前の生存セッション・ロール再確認）
- **入力・出力**: すべての保護API・SSE・Worker起動・外部AI要求に対する認可リースと監査チェーン記録
- **既存テスト**: `tests/test_tenancy.py`（590+件）、`tests/test_release_safety.py`, `tests/test_audit_snapshot.py`, `tests/test_planner_llm_gateway.py`, `tests/test_server.py`, `web/tests/sessionResponse.test.mjs`
- **実証済み範囲**:
  - 他組織からの読み書き・モデル状態参照・レポート取得の100%拒否（403）
  - 処理中・生成中・所有確認中・Worker起動直前・AI要求送出時のログアウト/除名に対する401/403拒否
  - 同一オリジン複数タブでのログアウト即時非表示と古い `/api/auth/me` 200応答の破棄
  - 監査ログの単独切り戻し（ロールバック）によるAI予算再利用の検知・拒否
  - 緊急停止による5秒以内のWorkerプロセスグループ強制終了と再開拒否
- **未実装機能**: 監査JSONLと予約額ファイルの**両方**を同時に過去時点へ戻すホスト側改ざんの単一ディレクトリ内検知（外部の改ざん防止ストレージが必要）、停止後の自動復旧UI
- **未検証機能**: 公開βインフラ（リバースプロキシ経由）でのSSE切断・失効通知の遅延実測
- **合格条件**: 他組織のデータや失効後セッションの保護情報が表示・返却されず、緊急停止と費用上限が確実に動作すること。
- **3軸評価**: 実装 `PASS` / 動作証拠 `PASS` / 実ユーザー価値 `BLOCKED`
- **次のアクション**: 独立レビュアーによる正式GitHubレビュー（Gate D）へ提出する。
