# 処理系統監査と段階的な最適化

対象: `codex/flow-audit-gates`（基礎監査は`codex/process-chain-optimization`）。起点は [REQUEST_FLOW.md](REQUEST_FLOW.md)。実コードの機械抽出結果は [PROCESS_INVENTORY.json](PROCESS_INVENTORY.json)、再生成は `python3 scripts/flow_inventory.py > docs/PROCESS_INVENTORY.json`。この抽出は**ソースの条件式・定義・呼び出し箇所の一覧**であり、動的に構成するパスと環境変数の実行先をすべて解決した呼び出しグラフではない。以下の手動追跡と組み合わせて読む。

## 後続Draft PR #53〜#55の現在地

以下の監査表・「現状」図・「目標」図は監査を行った時点のスナップショット。後続の実装では、P08の初回GETの証拠をP09のARTEXへ渡し、P10の追加L1 GETを明示同意・署名枠・Apacheの実測・Gateway直前審査がすべて成立する場合だけ自動実行する。P11はWorkerの固定マーカーと監査ハッシュから判定し、結果採用前に所有・範囲の世代を再確認する。P06の任意同意は既存画面・既存APIに加えたもので、未設定時は画面に出さずAPIも拒否する。更新後の時系列図は[REQUEST_FLOW.md](REQUEST_FLOW.md)、独立ラボの前後測定は[STATUS_EXPOSURE_INTEGRATION.md](STATUS_EXPOSURE_INTEGRATION.md)にある。

この後続経路は公開βでは既定無効で、公開環境への反映・実サイトでの追加通信・実Abliteration AIの採用可能な日本語解説は未確認。P15のSSEポーリング削減、P14の通常経路から使われない関数の削除、P12のドル建て費用上限も未実施。安全制御を削ってこれらを解決していない。

## 調査の範囲と漏れ

機械抽出ではバックエンド関数789、Web関数197、ARTEX overlayのGo関数27・通信関連箇所7、API分岐条件75、通信・プロセス起動箇所32、バックグラウンド起動箇所26、WebのAPI参照62を列挙した。`REQUEST_FLOW.md` に文字列として現れない固定APIパスは29件、動的な評価式は6件あった。未記載は主にアカウント/MFA/組織招待、資産削除・選択、CVE同期、全体の制御検証、監査ログ・イベント・レポート出力である。これらを「未使用」とみなして削除してはいけない。URLを構成する経路（例: `/api/assessments/{id}/...`）は機械抽出だけでは網羅判定できない。

| ID | 利用者・内部操作 → API | 主なコード | 主要テスト・状態 |
|---|---|---|---|
| P01 | 登録・ログイン・ログアウト、MFA・パスワード → `/api/auth/*` | `server.py` `do_POST` / `_register` / `_login`、`operators.py`、`SessionProvider` | `test_server.py`, `test_tenancy.py`; ログイン画面の重複取得を本PRで削減 |
| P02 | 組織選択・招待・権限変更 → `/api/orgs/*`, `/api/invites/accept` | `server.py` `_tenancy_get` / `_tenancy_post` / `_bind`、`tenancy.py` `TenantRegistry.service` | `test_tenancy.py`; 他組織のサービスに触れない |
| P03 | URL登録 → `/api/assets/challenge` | `OwnershipWizard.issue`, `server.py` `_dispatch`, `AssessmentService.issue_ownership_challenge` | `test_real_service.py`, `test_tenancy.py`; 登録時は対象通信なし |
| P04 | Google所有確認 → `/api/assets/google/start`, `/finish` | `google_ownership.py`、`server.py`、`AssessmentService.verify_asset_ownership` | `test_tenancy.py`; 公開βでは未設定。OAuth状態は短命・一回限り |
| P05 | DNS TXT/ファイル確認 → `/api/assets/verify-ownership` | `ownership.py`、`AssessmentService.verify_asset_ownership` | `test_real_service.py`, `test_tenancy.py`; 不一致・再確認失敗で拒否/取消 |
| P06 | 範囲確定 → `/api/assets/confirm-scope` | `OwnershipWizard.confirmScope`、`AssessmentService.confirm_asset_scope`、権限台帳 | `test_real_service.py`, `test_authority_ledger.py`; ホスト・ポート・期限を保存 |
| P07 | 初回開始/中断/再開/再診断 → `/api/assessments/{id}/{start,pause,resume,restart}` | `server.py` `_dispatch`、`AssessmentService.start` / `_run_inner` | `test_real_service.py`, `test_server.py`; 状態と世代を検査 |
| P08 | 初回の安全な観測と固定L1計画 | `_run_inner` → `_plan` → `_exec` → `Gateway.execute` → `WorkerPool.run` | `test_real_service.py`, `test_gateway.py`; 公開GETを1回、L2なし |
| P09 | ARTEX追加計画 → `/artex/plan`, `/artex/llm-preview`, 承認API | `plan_with_artex`、`artex_bridge.py`、`planner_llm_gateway.py`、`router.py` | `test_artex_bridge.py`; 現行は初回L1完了後の任意操作 |
| P10 | ARTEX項目の確認 → `/artex/items/{item}/execute` | `execute_artex_item` → カタログ再構成 → `_exec` → Gateway → Worker | `test_artex_bridge.py`, `test_gateway.py`; 実サイトは読み取り専用L1だけ |
| P11 | 証拠・判定・保存 → `/api/assessments/{id}`, `/logs`, `/events`, `/report`, `/remotion` | `_analyze`, `service_diag.py`, `evidence.py`, `snapshot`, `audit.py`, `EventBus` | `test_real_service.py`, `test_server.py`; candidate/detected/provenを分離 |
| P12 | 日本語解説 → `/chat` | `ask_chat`, `_safe_real_ai_explanation`, `ai_advisor.py`, 内蔵説明 | `test_ai_advisor.py`; 実サイトの外部AI経路は公開βで無効、実モデル採用率未確認 |
| P13 | 緊急停止・取消・期限切れ | `/emergency-stop`, `/api/assets/delete`, `_expiry_watch`, `_authority_reduced_locked`, Gateway起動世代 | `test_gateway.py`, `test_authority_ledger.py`; 保留中・実行中の権限を失効 |
| P14 | CVE資料・制御自己検証 → `/api/cve/*`, `/api/system/verify-controls`, `/api/router/verify` | `cve.py`, `control_verification.py`, `server.py` `JOB_ROUTES` | `test_cve.py`, `test_server.py`; 診断の通常経路から独立 |
| P15 | UIのセッション・進捗通信 | `SessionProvider.refresh`, `useAssessment.refetch` / SSE / 4秒バックアップ | `web/tests/polling.test.mjs`; 受信が静かな間はsnapshotと全監査ログを定期取得 |
| P16 | 画面内通知・承認待ちの再開 | `EventBus.publish` / `wait`、`server.py` `_sse_loop`、`AssessmentService._decide` | `test_server.py`; 画面へのSSE。メール・Webhook送信経路は見つからない |

外部通信先は、P05のDNS照会または対象ホストの確認用ファイル、P04のGoogle OAuth/Search Console API、P08/P10の所有確認済み対象または`lab.test`、P09の許可済みLLM上流（隔離ARTEXはローカルGatewayだけに接続）、P12の明示設定されたAbliteration AI APIである。P14の`/api/cve/sync`はリクエストに含む資料を取り込む処理で、外部へ取得しに行かない。`cve.py`には別途`sync_from_urls`があるが、通常のAPI経路への接続は確認できなかった。LLM上流と任意の資料URLは設定・引数から決まるため、固定文字列の機械抽出だけでは確定しない。これらは別々の権限・費用・送信情報の境界として扱う。

## 現状と目標の構成

```mermaid
flowchart LR
  U[利用者] --> UI[P03-P07 Web]
  UI --> S[P01-P07 認証・組織別 AssessmentService]
  S --> F[P08 固定L1プランナー]
  F --> G[P08 Gateway]
  G --> W[P08 隔離Worker]
  W --> E[P11 証拠・所見・保存]
  E --> UI
  UI -.完了後の任意操作.-> A[P09 ARTEX + LLM Gateway]
  A --> C[P10 許可カタログ]
  C --> G
  UI -.質問.-> J[P12 内蔵/任意のAbliteration AI解説]
  E --> J
```

```mermaid
flowchart LR
  U[利用者] --> UI[P03-P07 URL入力・所有確認・開始・結果]
  UI --> S[P01-P07 組織別 AssessmentService]
  S --> O[P08 権限内の安全な初期観測]
  O --> D[P09 送信許可済み構造化特徴]
  D --> A[P09 隔離ARTEX + LLM Gateway]
  A --> V[P09-P10 構造検証・許可カタログ照合]
  V --> G[P10 Gateway: 実行直前の権限再検証]
  G --> W[P10 隔離Worker: 実サイトL1のみ]
  W --> E[P11 証拠と検証状態を保存]
  E --> J[P12 許可済み情報から日本語解説]
  E --> UI
  J --> UI
```

目標図は**設計案**であり現行実装ではない。初期観測の対象通信も所有確認・範囲確定後に限る。ARTEXの提案からWorkerを直接起動する経路は設けない。AIが失敗/不採用なら固定L1と内蔵解説へ戻し、診断をAIの可用性に依存させない。実サイトL2は全経路で禁止を維持する。

## 現状と目標の時系列

```mermaid
sequenceDiagram
  participant U as 利用者
  participant UI as Web
  participant S as AssessmentService
  participant G as Gateway
  participant W as 隔離Worker
  participant A as ARTEX/AI
  U->>UI: URLを登録、所有確認、範囲確定
  UI->>S: P03→P06
  U->>UI: 開始
  UI->>S: P07
  S->>G: P08 固定L1 GET
  G->>W: 直前審査後に1回GET
  W-->>S: 応答・証拠
  S-->>UI: P11 結果
  opt 利用者が追加計画を要求
    UI->>S: P09
    S->>A: 匿名化した実測特徴
    A-->>S: 未信頼の提案
    S-->>UI: 許可可能項目
    opt 利用者が項目を実行
      UI->>S: P10
      S->>G: カタログから再構成した操作
      G->>W: 直前再審査
      W-->>S: 証拠
    end
  end
```

```mermaid
sequenceDiagram
  participant U as 利用者
  participant UI as Web
  participant S as AssessmentService
  participant A as ARTEX/LLM Gateway
  participant G as Gateway
  participant W as 隔離Worker
  U->>UI: URL・確認・開始
  UI->>S: P03→P07
  S->>G: 権限確認済みの初期観測
  G->>W: 所有・範囲・IP・停止状態を直前再審査
  W-->>S: 公開情報と証拠
  S->>A: 送信許可済みの固定項目だけ
  A-->>S: 未信頼の計画案
  S->>S: 形式・カタログ・費用枠を照合
  S->>G: 許可可能なL1操作のみ
  G->>W: 権限・期限・DNS/IP・回数・停止状態を再審査
  W-->>S: 応答と監査証拠
  S-->>UI: 検証状態別の結果・日本語解説
```

## 信頼境界

```mermaid
flowchart LR
  subgraph B1[ブラウザ: 未信頼入力]
    U[URL・操作・質問]
  end
  subgraph B2[制御プレーン: 組織ごと]
    H[P01-P02 認証/CSRF/_bind]
    S[P03-P07 AssessmentService/権限台帳]
    G[P08-P10 Gateway/許可カタログ]
    E[P11 証拠/監査/状態保存]
  end
  subgraph B3[隔離プロセス]
    W[P08-P10 Worker]
    A[P09 ARTEX]
  end
  X[所有確認先・公開サイト]
  M[外部AI/Google/CVE資料]
  U --> H --> S --> G --> W --> X
  S --> A
  A -.提案だけ.-> S
  S --> E
  S -.許可済み固定項目だけ.-> M
  M -.未信頼応答.-> S
```

```mermaid
flowchart LR
  subgraph T1[利用者・外部: 未信頼]
    U[URL/ブラウザ]
    X[サイトの応答]
    M[AIの返答]
  end
  subgraph T2[制御プレーン: 権限保持]
    H[P01-P02 認証・組織分離]
    S[P03-P07 所有証明・範囲・有効期限]
    V[P09 提案の構造/カタログ検査]
    G[P08-P10 Gateway直前検査]
    E[P11 証拠・監査・結果]
  end
  subgraph T3[隔離]
    W[P08-P10 Worker]
    A[P09 ARTEX]
  end
  U --> H --> S --> V --> G --> W --> X
  S -.匿名化固定項目.-> A
  A -.提案.-> V
  X -.応答.-> W --> E
  M -.助言.-> V
```

両図とも外部AI/ARTEX/サイト応答は信頼しない。ホスト名、URL、認証情報、個人情報、応答本文、秘密情報を外部AIへ無断送信しない。Gatewayの二度目の検査はTOCTOU対策であり重複として削除しない。

## 異常・再試行・競合の確認点

| 場面 | 現在の処理 | 最適化時に守る不変条件 |
|---|---|---|
| 未ログイン/他組織/失効セッション | `do_GET`/`do_POST`→`_bind`、SSEも再照会して終了 | 他組織のsnapshot、監査、証拠に到達しない |
| 所有確認失敗/再確認失敗 | 証明を記録せず、既存権限は取消し得る | 表示フラグだけで開始しない |
| 範囲期限・DNS/IP変化 | `_expiry_watch`、実行直前Gateway、結果採用直前の権限再照会 | 保留中の操作を起動せず、失効後の結果を採用しない |
| 同時実行/停止 | 世代番号・Gateway launch epoch・Worker停止確認 | 停止未確認なら新規起動拒否、旧世代の結果破棄 |
| ARTEX/LLM失敗・未対応提案 | 計画失敗を監査、未対応案は助言扱い | AI生出力や引数をそのままWorkerへ渡さない |
| SSE断/遅延 | スナップショットと全ログの定期再取得 | 進捗と監査チェーンの収束を保つ |
| 保存失敗 | 実サイト送信前に状態保存可否を確認 | 監査不能な送信をしない |

## 重複・未使用・未検証

| 区分 | 実コードからの所見 | 判断 |
|---|---|---|
| 重複 P01/P15 | ログイン画面と`SessionProvider`が同じ`/api/auth/me`を取得 | 本PRで共通の取得結果を利用。権限判定はサーバー側のまま |
| 重複候補 P08/P09 | 固定L1 GETのあとに任意ARTEX計画。AIは初回診断に寄与しない | 初期観測は残し、その証拠でARTEXを一度だけ計画へ組み込む設計を独立レビューへ |
| 必須の再検証 P06/P08/P10 | 所有・範囲とGateway直前検査 | 時間差、DNS/IP変更、停止競合があるため維持 |
| 重複候補 P15 | 静かなSSEでは4秒ごとにsnapshotと全ログを再取得 | 監査チェーンの鮮度を下げずに回数を減らせるか別測定が必要 |
| 修正 P11/P15 | `AssessmentService.logs()`が一覧取得とハッシュ検証で同じ監査ファイルを二度読んでいた | 一度読み取った一覧を検証にも渡す。検証式とポーリング頻度は維持 |
| 未使用と断定不可 | 管理・CVE・制御自己検証ルートは通常UIフローに現れない | 運用/安全機能なので使用実態の計測なしに削除不可 |
| 通常経路で未使用 P14 | `FeedMonitor.sync_from_urls` | 参照は`tests/test_cve.py`のみ。`/api/cve/sync`は`ingest_payloads`を呼ぶ。削除前に運用上の用途を確認 |
| 未検証 P04 | Google OAuthの公開β E2E | 設定なし。ボタンは非表示 |
| 未検証 P09/P12 | 実サイトでのARTEX計画、実Abliteration AIの採用可能な解説 | 公開βで無効。課金枠と送信内容の審査が必要 |
| 未検証 P07–P12 | 所有確認済み実サイトの公開β完走 | DNS設定と所有者操作がまだない。未承認の実通信はしない |

実サイト向け外部AI解説には、API回数と出力トークンの制限がある一方、ドル建ての強制上限はコード上で確認できなかった。モデル料金を仮定して「費用削減」と報告しない。実モデルを有効化する前に、送信許可情報・一回あたりの上限・合計予算・不採用時の課金を独立レビューする。

## 同一模擬条件での変更前後の測定

P01の模擬ブラウザ測定: ローカルNext.js開発サーバー、幅390px、`/api/auth/me`を固定応答（未ログイン・登録可・Google無効）で置換、Chrome headlessで`/login`を1回表示。Reactの開発時の再実行を含む。同じスクリプト・同じサーバーで測定。

| 指標 | 変更前 | 変更後 | 解釈 |
|---|---:|---:|---|
| `/api/auth/me`呼び出し | 4 | 2 | 50%減。開発モードでの実測。製品版の値とは区別 |
| 登録タブ表示 | 成功 | 成功 | 390pxで操作可 |
| ページ表示時間 | 0.751秒 | 0.718秒 | 変動の範囲。速度改善とは主張しない |
| AIトークン/費用、Worker、DB、脆弱性検出 | 0/0、0、未計測、対象外 | 同左 | この変更はログイン画面に限定 |
| ユーザー操作数 | 0 | 0 | 変化なし |
| サーバーの認証/組織安全制御 | 同じAPI・同じバックエンド | 同じ | 本修正では変更なし。全回帰テストで確認する |

**診断全体の前後比較は未完了。** 現在の固定L1と目標の初回ARTEX計画は、まだ同じ模擬対象で走る二つの実装になっていない。従って診断完了時間、AIトークン・推定費用、Worker起動、DBアクセス、検出数、偽陽性/見逃し、操作数、安全制御成功率について改善率を提示できない。次段階では脆弱・修正済みの同一ラボを使い、各指標の収集点をP07–P12に置く。料金表が確定しない限り推定費用は「未算定」とする。精度の現状値は `REQUEST_FLOW.md` のL1: TP3/FP0/FN2/TN2/未計測3で、AI追加後に低下しないことを独立ラボで確認する。

現行診断の模擬ベースラインも `python3 -m scripts.bench_lab_l1` で採取した（スクリプト内で外部モデルとローカル設定読み込みを無効化）。直近の脆弱ラボは0.083秒、修正済みラボは0.084秒。どちらもGateway 1回、Worker起動1回、外部モデル呼び出し0回、AIトークン0。状態保存メソッド呼び出しは脆弱ラボ19回、修正済みラボ16回だった。これは各1回の参考値であり、速度比較や改善率ではない。診断状態はJSONファイル保存なので、ここでSQLの「DBアクセス回数」を捏造しない。脆弱ラボの`detected`は3件、`candidate`は2件。修正済みラボの`detected`は0件、`candidate`は3件だった。安全制御の成功率はこのベンチマークでは測っておらず、既存の独立テストで確認する。

P11/P15の追加改善は `VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_audit_logs` で比較した。300件の同じローカル監査ログを各100回取得した中央値は、変更前1.582ms・2回読み取り、変更後1.154ms・1回読み取り。差はこの小規模ベンチマークの値であり、診断完了時間の改善率ではない。返す一覧と検証する一覧が一致すること、改ざん時に`chain_valid=false`となることをテストする。

## 追加監査: 実サイトARTEXと再起動

| ID | 実コードで確認した経路 | 対応・残る条件 |
|---|---|---|
| P07 | 保存状態が`running`または`paused`でも、プロセス再起動後に診断スレッドは復元されない | PR #47で部分証拠を保持した`failed`にし、既存の「再診断」を表示。生きたスレッドがない`resume`も拒否する。新たな診断開始時には所有・範囲・期限を再検査 |
| P09 | `plan_with_artex`は実サイトの初回診断完了後に限る。PR #45は専用のループバック上流へ、予算付きPlanner LLM Gatewayを通す選択肢を追加した | 公開βでは無効。ローカル上流自体が外部へ転送しないことは運用時に別途確認する。初回診断への接続ではない |
| P09/P10 | 計画開始・モデル転送・計画採用時に所有と期限を再検査。従来の共通関数はWorkerの予算を再設定した | PR #45/#46でARTEX計画と項目開始を読み取り専用の権限検査に変更。期限失効と予算枯渇の模擬テストを追加。Gatewayでの実行直前の再審査は維持 |
| P08/P10 | `_ensure_active_window_locked`は再開・再診断などで`Budget(50)`に戻す。項目の再計画、再起動、同時実行をまたぐ対象通信の永続上限はない | 初回ARTEXで追加GETを有効化する前に、署名付き権限台帳へ実行IDと消費済み検査を保存。Worker起動直前に上限・重複を検査し、保存失敗時は拒否。既存のデータディレクトリ単一プロセスロックも維持 |

PR #47時点の**同じ独立ラボ**で`python3 -m scripts.bench_status_exposure_baseline`を各条件1回実行した。脆弱・修正済み・汎用200の順に0.068/0.076/0.076秒。各条件でGateway 1回、Worker起動1回、状態保存メソッド15回、対象ルートGET 1回、ARTEX・外部AI・AIトークン0。mod_status公開の正解ラベルではTP0/FP0/FN1/TN2、Recall 0%、誤検知率0%、検出0件のためPrecisionは未定義。変更前の0.071/0.071/0.074秒との差は各1回の変動で、速度・精度の改善を示さない。期限切れ・所有取消しは2/2で診断開始を拒否し、Workerと対象通信は0。費用はモデル未使用で0、API回数と利用者操作数はこのサービス直呼び測定の対象外。ARTEX初回計画の変更後測定は未実装のため、診断全体の前後比較は未完了。

初回ARTEXの実装前に残る独立レビュー条件は、(1)追加通信の同意表示と上限、(2)署名付きの実行単位枠、(3)Worker応答の固定スキーマ検証と監査前の機密値除去、(4)検査項目専用の証拠・判定、(5)結果採用直前の所有・範囲・停止の再検査である。詳しくは[初回ARTEX計画の設計と合格条件](ARTEX_INITIAL_PLAN_REVIEW.md)。

## 実装順序

1. 本PR: P01の重複通信を削減し、機械棚卸しと目標設計を固定。公開βへは未反映。
2. 次の小PR: P07–P12に模擬専用の計測を追加し、現行診断の時間・通信・モデル利用・Worker・保存・精度・安全性を採取。通常経路の制御は変えない。
3. 独立レビュー後: [初回ARTEX計画の設計と合格条件](ARTEX_INITIAL_PLAN_REVIEW.md) に沿って初期観測をARTEXの入力に接続。未対応提案は候補として表示し、許可カタログ一致のL1だけGatewayへ渡す。AI失敗時は固定プランナーを使用。
4. 同一ラボで前後比較し、偽陽性増加・見逃し増加・停止/失効/組織境界の回帰がない場合に限って次段階へ進む。実サイト通信・有料AI・公開βへの反映は別途承認を取る。

## 段階実装の現在地

上記の表と基準値は監査時点の記録。後続のDraft PR #49でP08の初回ルートGETを署名付き台帳で1回に制限し、監査ハッシュ付きの成功結果をARTEXの重複項目に`observed`として引き継いだ。Draft PR #50はP10向け固定マーカーWorker出力とGatewayの形式検証を追加したが、サービスには未登録で、追加GETを許可しない。次のDraftではP09に初回観測からARTEXを自動計画する**別設定のオプトイン**を用意する。送る情報は固定の状態クラス、Webサーバー種別、TLSと主要ヘッダーの有無、証拠のある固定所見だけ。ループバックの実ローカルモデル以外を指定せず、対象へのGETは増やさない。公開βの設定は無効のまま。

この段階では追加検査と専用証拠判定が未接続であり、mod_statusのTP0/FP0/FN1/TN2という診断全体の基準値は改善していない。初回ARTEXの計画後も完了状態の採用直前に所有権・範囲・中断・停止を再検査する。初回ARTEXの費用・待ち時間を含む同一条件の前後測定、追加GETへの同意・署名付き上限、独立した検出精度、画面の操作数は次段階で測る。CI成功だけで公開可とは判定しない。

追加GETの準備実装では、署名付き範囲の`allow_status_probe`を既定falseとし、診断開始時の署名付き通信枠にもコピーする。成功した初回GETの監査ハッシュがあり、同意が両方の署名付き記録で有効な場合に限り、固定パスを1回予約できる。範囲確認ごとに世代を変え、旧診断の通信枠を再承認後に再利用できない。API・画面・診断カタログからはまだ到達できないため、実サイトの通信回数と上記の検出精度は変わらない。

後続のDraftでは固定`mod_status`項目をARTEXカタログ、Gateway、Worker、証拠判定に接続する。所有・範囲・追加通信同意・署名枠・初回GET監査ハッシュが揃い、Apache系の観測とARTEX提案が一致した場合だけ、固定の追加GETを1回実行する。所見はWorkerの固定形式報告と監査ハッシュからのみ作る。詳しい前後比較と未完了条件は[初回ARTEX追加検査の測定](STATUS_EXPOSURE_INTEGRATION.md)を参照。公開βの画面同意と設定は未接続で、実サイトへの新規通信は行っていない。

さらに後続のDraftでは、P06の既存「診断を開始」画面に任意の追加GET同意を置く。バックエンドの機能設定がないときは選択肢を表示せず、APIも`allow_status_probe=true`を拒否する。設定がある場合だけ、組織に結び付いた署名付き範囲へ同意を保存する。公開βの現行設定は無効であり、画面確認と実サイト通信は行っていない。
