# Vulnix v1.0（認可ラボ版）セキュリティレビュー資料

外部の人によるセキュリティレビュー（`docs/V1_COMPLETION.md` の A2「Gate D」）のための入口です。初めてこのコードを読む方を想定しています。

- **書いてあることは、コードかテストで確かめた事実だけです。** 各項目に `ファイル:行` を付けています。行番号は下の対象コミットのものです。
- 「要確認」と書いた項目は、資料の作成者がコードを読んで気づいた点で、脆弱性だと断定したものではありません。
- 領域ごとの詳細は別のファイルにあります（下の表）。

| 領域 | 詳細 |
|---|---|
| (a) 認証とセッション | [01_auth_sessions.md](01_auth_sessions.md) |
| (b) 組織の分離 | [02_org_isolation.md](02_org_isolation.md) |
| (c) 要求時点の権限と失効 | [03_authority_revocation.md](03_authority_revocation.md) |
| (d) Worker の隔離・Gateway・緊急停止 | [04_worker_isolation.md](04_worker_isolation.md) |
| (e) 監査の完全性 | [05_audit_integrity.md](05_audit_integrity.md) |

---

## 1. 対象と版

| 項目 | 内容 |
|---|---|
| 対象コミット | `main` `e977695`（PR #117 のマージ） |
| コードを検証したコミット | `9ce0571`（PR #116 のマージ）。`git diff 9ce0571 e977695` の差分は `docs/V1_COMPLETION.md` だけで、コードは同一 |
| v1.0 の機能範囲 | 登録済みの認可ラボでの診断：開始 → 所有者の仕様 → L1 → L2 の個別承認 → 仮説の判定 → 所見 → 修正方法 → 修正後の確認 → レポート（`docs/V1_COMPLETION.md` 冒頭） |
| main の最終 CI | run 45020174027（`9ce0571`、3ジョブ成功。`docs/V1_COMPLETION.md` §6） |

### 範囲に含めるもの

1. 認証とセッション（ログイン、TOTP、セッションの失効、CSRF のヘッダーと Origin、ロックアウト）
2. 組織の分離（`TenantRegistry`、`_bind` / `_get_org` / `_dispatch`、`PLATFORM_POST_ROUTES`、組織ごとのデータディレクトリ、SSE）
3. 要求時点の権限と失効（`live_request_authority` / `live_grant_roles` / リース、実行中の失効、依頼者と承認者、Worker 起動前の手順ごとの権限）
4. Worker の隔離（Gateway の方針、トークン、送信先の固定、Linux の nftables / cgroup、緊急停止、止まらない Worker の封じ込め）
5. 監査の完全性（ハッシュチェーン、監査が先の書き込み、予約ファイル、別 UID のローカル監査アンカー）
6. ラボの診断ループの状態を変える API：`POST /api/assessments/{id}/diagnosis/{start,owner-spec,approve,fix-check}`（`aegis/server.py:1528-1541`、`aegis/diagnosis_ops.py`、仕様は `docs/DIAGNOSIS_ACTIONS.md`）

### 範囲外

| 対象 | 理由・状態 |
|---|---|
| 実サイトでの L2 | v1.0 では無効。テナントありでは常に読み取り専用（`aegis/server.py:351-354`）。実サイトの ARTEX 計画からの L2 も拒否（`aegis/assessment.py:2686-2690`） |
| 外部モデル（Abliteration AI など）への送信 | 有料・外部通信。今回は対象外 |
| Security Graph（PR #86〜#92） | 未統合 |
| root の侵害 | 脅威モデルの外 |
| （参考）実サイトの所有確認と読み取り専用の L1 | 今回の5領域には含めていません。**既定で有効**です（`VULNIX_REAL_SERVICE_DIAGNOSIS` の既定は `l1`、`aegis/server.py:73`）。レビューでは `0` にしてください（§4） |

### 脅威モデル（要約）

| 攻撃者 | 想定する力 | 守りたいもの |
|---|---|---|
| 別の組織（テナント） | 自分の組織では owner。公開登録が有効なら誰でもなれる | 他組織のサイト・所有確認・診断結果・証拠・監査ログ・招待・イベント |
| 権限の少ないメンバー | 同じ組織の viewer / runner / approver | 自分の役割を超える操作（L2 の承認、仕様の入力、管理）。失効後の結果の受け取り |
| 悪意のある対象サイト | 診断の要求に任意の応答を返す（ラボを改造して再現） | Worker・コントロールプレーン・UI の破壊、偽の判定、秘密値の混入 |
| モデル・プランナー（ARTEX） | 任意の出力を返す。プロセスとしても信頼しない | Worker の直接起動、範囲外への送信、承認の迂回、ホストの秘密の読み取り |
| サービスの OS ユーザー（データディレクトリに書ける） | `audit.jsonl` などを書き換え・切り戻しできる | 監査の完全性（アンカーを有効にした場合） |
| root | — | 範囲外 |

---

## 2. 構成と信頼の境界

```
ブラウザ
  │ ① 同一オリジン。Cookie aegis_session（HttpOnly, SameSite=Strict）と vulnix_org
  ▼
Next.js（127.0.0.1:3000）
  ├ web/src/proxy.ts            VULNIX_PUBLIC_MODE=1 なら /api/* はすべて 404
  └ web/src/app/api/[...path]/route.ts
        Host がループバック名、POST は X-Aegis-Request: 1 かつ Origin のホスト = Host
        転送するのは Cookie / Last-Event-ID / Idempotency-Key（形を確認）だけ
  │ ② ループバックの HTTP
  ▼
コントロールプレーン aegis/server.py（127.0.0.1:8787、ThreadingHTTPServer）
  ├ Host 確認（421）→ CSRF（403）→ セッション（401）
  ├ OperatorStore（aegis/operators.py）   アカウント・scrypt・TOTP・セッション（SHA-256 だけ保存）
  ├ OrgStore / TenantRegistry（aegis/tenancy.py）
  │     _bind：組織の指定 → 所属の確認（403 + platform-audit）→ その組織の AssessmentService
  │     PLATFORM_POST_ROUTES：組織に結び付けず、アカウント自身の役割で判定
  └ _dispatch：現在のセッションと役割を読み直してから処理、応答も生きた権限の下で送る
  │ ③ プロセス内の呼び出し（組織ごとに別オブジェクト・別ディレクトリ <data>/orgs/<id>/、0700）
  ▼
AssessmentService（aegis/assessment.py）
  ├ DiagnosisOps（aegis/diagnosis_ops.py）   Idempotency-Key、監査が先、承認 nonce、実行権
  ├ AdaptivePlanRunner                       手順ごとに停止・失効・期限を確認
  ├ ARTEX プランナー（aegis/artex_bridge.py） ④ 信頼しない出力。Linux の netns/mount/PID 名前空間 + cgroup + nftables
  │                                           提案は固定カタログから作り直す
  ├ Gateway（aegis/gateway.py）              トークン・承認・送信先の固定・起動直前の権限確認・allow を監査
  │  ▼ ⑤ 子プロセス（PATH だけの環境、新しいプロセスグループ、RLIMIT_CPU、egress_sentinel）
  │ Worker（aegis/workers/*.py）
  │  ▼ ⑥ 127.0.0.1:<lab_port> だけ（ラボの対象 CIDR は 127.0.0.1/32）
  │ 模擬ラボ aegis/lab.py（全組織で共有）
  └ AuditLog（aegis/audit.py）  ハッシュチェーン（組織ごと）＋ 予約ファイル
        │ ⑦ Unix ソケット（相手の UID を確認）
        ▼
     ローカル監査アンカー（aegis/audit_anchor.py、別の OS ユーザー、任意）
```

| 境界 | 何を信頼しないか | 主な制御 |
|---|---|---|
| ① ブラウザ → Next.js | 別オリジンのページ、DNS リバインディング | `route.ts:23-30`, `:102-115`、`proxy.ts` |
| ② Next.js → コントロールプレーン | ループバックの他プロセスからの直接要求 | `aegis/server.py:414-420`, `:754-760`、全 API で認証（`:468-469`） |
| ③ 組織の間 | 他組織のメンバー | `_bind`（`aegis/server.py:322-355`）、組織ごとの別オブジェクト（`aegis/tenancy.py:327-344`） |
| ④ ARTEX → Vulnix | プランナーの出力とプロセス | カタログでの作り直し（`aegis/assessment.py:2664-2690`）、隔離（`:2201-2212`） |
| ⑤ Gateway → Worker | 提案・引数 | 単発トークン、承認、送信先の固定（`aegis/gateway.py:253-284`） |
| ⑥ Worker ↔ 対象 | 対象の応答 | 出力の上限・サニタイズ・秘密値の除去（`aegis/gateway.py:351-393`） |
| ⑦ サービス → アンカー | サービスの OS ユーザー | 別 UID、相手の確認、追記専用（`aegis/audit_anchor.py`） |

参考資料：[ARCHITECTURE.md](../../ARCHITECTURE.md)、[AGENTS.md](../../AGENTS.md)、[SECURITY.md](../../SECURITY.md)、[docs/SECURITY_REVIEW.md](../SECURITY_REVIEW.md)、[docs/AUDIT_ANCHOR.md](../AUDIT_ANCHOR.md)、[docs/DIAGNOSIS_ACTIONS.md](../DIAGNOSIS_ACTIONS.md)、[docs/V1_COMPLETION.md](../V1_COMPLETION.md)。

---

## 3. 領域ごとの要点

各領域の「設計・コードの場所・証拠のテスト・既知の制限・試してほしいこと」は、それぞれのファイルにあります。ここでは要点だけを示します。

| 領域 | 設計の要点 | 主な証拠 | 既知の制限（抜粋） |
|---|---|---|---|
| (a) 認証 | scrypt、トークンは SHA-256 で保存、ロールは毎回読み直し、名前ごとのロックアウト（試行を先に予約）、TOTP は任意で再利用拒否、失効は送出中の応答を待つ | `tests/test_attack_regressions.py::TestPasswordGuessing`、`tests/test_server.py::TestServer::test_csrf_guard`、`tests/test_final_review.py::TestSignInEdgeCases` | MFA は任意。Cookie に `Secure` なし。プロキシの CSRF 判定の単体テストは見当たらない |
| (b) 組織の分離 | 組織ごとに別オブジェクト・別ディレクトリ。毎回の所属確認と、処理直前・応答直前の再確認。プラットフォーム API はアカウントの役割 | `tests/test_tenancy.py`（`TestTenantIsolationOverHttp` ほか）、E2E の `outsider` | ラボは全組織で共有。既定の組織はデータルートを使う |
| (c) 権限と失効 | 生きた権限の関数とリース、Worker 起動直前の確認、結果採用前の確認、手順ごとの承認 nonce、応答時の秘匿 | `tests/test_diagnosis_actions.py::TestRemainingRisks`、`TestDiagnosisActionsOverHttp::test_authority_lost_right_after_the_operation_withholds_the_result_and_never_reruns` | 最後の確認から送信までの短い窓。承認の取り消し操作なし |
| (d) Worker の隔離 | Gateway の順序だった確認、ラボは `127.0.0.1/32` に固定、プロセス内の送信制限、停止の確認と生き残りの封じ込め。カーネル隔離は実サイトの L2 と ARTEX だけ | `tests/test_gateway.py`、`tests/test_worker_deadline.py`、CI「Linux kernel confinement end to end …」「… Emergency Stop (P0)」 | **ラボの Worker はカーネル隔離なし** |
| (e) 監査 | 鍵なしのハッシュチェーン、`flock`、監査が先、予約ファイル、別 UID のアンカー（任意） | `tests/test_audit_anchor.py`、`tests/test_audit_snapshot.py`、CI「Local audit anchor as a separate OS user …」 | アンカーは既定で無効。プラットフォーム全体の記録は対象外 |

### 特に試してほしいこと（各ファイルから抜粋）

| # | 領域 | 内容 | 出発点 |
|---|---|---|---|
| 1 | (a) | Origin なし・`null`・別ポートで、プロキシの CSRF を越えられないか | `web/src/app/api/[...path]/route.ts:102-115` |
| 2 | (b) | HTTP/1.1 の同じ接続で、前の要求の組織（`self._bound_org`）が次の要求に使われないか | `aegis/server.py:350`, `:1237-1258` |
| 3 | (b)(c) | org admin が第二のアカウントを approver にして、自分の L2 を承認させる | `aegis/tenancy.py:194-210`, `aegis/server.py:1533`, `aegis/diagnosis_ops.py:631` |
| 4 | (c) | 承認の nonce・世代・項目を変えて、別の手順の承認で Worker を起動する | `aegis/diagnosis_ops.py:518-607` |
| 5 | (c) | 2つの Worker を並行させ、別の実行の `result` 記録を所見の証拠に結び付ける | `aegis/assessment.py:5097` |
| 6 | (d) | 悪意のある応答で `http_probe` のパーサーや出力処理を崩す | `aegis/workers/http_probe.py`, `aegis/gateway.py:351-393` |
| 7 | (d) | 自己申告の `ownership_verified` で許可リストに入れたホスト名から、ラボ以外のループバックのサービスに届く | `aegis/assessment.py:2918-2925`, `:399-400`, `aegis/network.py:73-130` |
| 8 | (e) | アンカーなしでチェーンを作り直したとき、画面・レポートが「保護あり」と誤表示しない | `aegis/audit.py:185-202` |
| 9 | (e) | 記録元 ID の付け替えでアンカーの `rollback` / `fork` 判定を避ける | `aegis/audit.py:125-152`, `aegis/audit_anchor.py:442-474` |

### 資料の作成中に気づいた点（要確認）

| # | 内容 | 場所 |
|---|---|---|
| O1 | **設計の判断が必要（所有者の決定待ち）。** 手動の ARTEX の L2 と旧来の実行の承認（`/approvals/{id}`）では、依頼者≠承認者を確かめるのは `AEGIS_SEPARATE_L2_APPROVER=1` のときだけです。既定では、組織の owner が自分で計画し、自分で L2 を実行できます。診断ループの承認 API は常に拒否します。`docs/DIAGNOSIS_ACTIONS.md` §1 の記述（`execute_artex_item` は本人の承認を拒否）は、コードでは条件付きです。対象は登録済みラボだけです | `aegis/assessment.py:353-355`, `:2700-2703`, `:3980-3988`、`aegis/server.py:1603-1609`、`aegis/diagnosis_ops.py:631-637` |
| O2 | 自己登録アカウントの L2 承認の拒否も、同じ設定のときだけです。依頼者≠承認者はアカウント名の比較なので、公開登録が有効なら第二のアカウントで満たせます | `aegis/server.py:1533-1535`, `aegis/diagnosis_ops.py:582`, `:631` |
| O3 | **確認済みの欠陥（修正 PR あり）。** `_exec` は、Worker の後に監査ログの**最後の** `result` 記録をその実行のものとして使っていました。同じ組織の別の Worker がその間に終わると、証拠が他の実行の監査記録を指します（`tests/test_exec_result_entry.py` で再現）。修正：トークンの `jti` が一致する記録だけを使い、見つからなければ結果を記録しない（PR #118） | `aegis/assessment.py:5097` |
| O4 | **確認済みの欠陥（修正 PR あり）。** TOTP の登録確認に使ったコードが「使用済み」として記録されず、同じ時間窓でログインと無効化に使えました（`tests/test_attack_regressions.py::TestPasswordGuessing::test_the_code_that_confirmed_enrollment_cannot_sign_in` で再現）。修正：確認に使ったステップを使用済みとして保存（PR #118） | `aegis/operators.py:815-833` |
| O5 | 診断ループ以外の状態変更には、処理の後に監査を書くものがあります（例：`assessment.start_requested`、`asset.registered`） | `aegis/server.py:1483-1486`, `aegis/assessment.py:2988` |

---

## 4. 手元での再現

### 前提

- Python 3.12（CI と同じ。3.15 でも動作した記録あり）、Node.js 20、Linux の項目は cgroup v2・`nft`・`iproute2`・root かパスワードなしの `sudo`。
- Python のテストは追加のパッケージなしで動きます（requirements ファイルはなく、CI も lint 用の `ruff==0.6.9` 以外は入れていません。`.github/workflows/ci.yml:33-36`）。ブラウザ E2E には Playwright（CI は `playwright==1.56.0`）。

### 必ず守ること（してはいけないこと）

| すること / しないこと | 理由 |
|---|---|
| すべてのコマンドに `VULNIX_NO_ENV_LOCAL=1` を付ける | `.env.local` の API キーなどを読み込まない（`aegis/server.py:1684-1698`） |
| サーバーを手で起動するときは `VULNIX_REAL_SERVICE_DIAGNOSIS=0` を付ける | 既定（`l1`）では、実サイトの所有確認（DNS・HTTPS）と読み取り専用の診断が有効（`aegis/server.py:67-75`） |
| `VULNIX_ABLITERATION_*` などの外部 API キーを設定しない | 有料の外部送信は範囲外 |
| 実在するサイトを登録・診断しない。対象は `lab.test`（`127.0.0.1:<lab_port>`）だけ | `SECURITY.md`「安全な検証の方針」 |
| 公開β版の環境や、運用中のサーバーを試験しない | 同上 |
| 全件テストは時間がかかるため、必要なときだけ | 領域ごとのモジュールで十分なことが多い |

### 領域ごとの単体テスト（macOS で実測した所要時間）

```sh
git checkout e977695
export VULNIX_NO_ENV_LOCAL=1

# (a) 認証とセッション
python3 -m unittest tests.test_operators tests.test_attack_regressions tests.test_server tests.test_grant_lease
# (b) 組織の分離（tests.test_tenancy は大きい）
python3 -m unittest tests.test_tenancy
# (c) 権限と失効・診断ループの操作
python3 -m unittest tests.test_diagnosis_actions tests.test_diagnosis_loop tests.test_adaptive_plan_runner
# (d) Worker の隔離（Linux 専用のクラスは他の OS では skip）
python3 -m unittest tests.test_gateway tests.test_egress_sentinel tests.test_worker_deadline \
                    tests.test_fail_closed tests.test_release_safety tests.test_netfilter
# (e) 監査
python3 -m unittest tests.test_audit_snapshot tests.test_audit_anchor tests.test_spend_cap \
                    tests.test_diagnosis_state tests.test_diagnosis_read_api
# 全件（AGENTS.md の完了条件）
python3 -m unittest discover -s tests
```

資料の作成時に手元（macOS）で実行した結果：`tests.test_operators` 16件 OK（5秒）、`tests.test_grant_lease` 4件 OK、`tests.test_audit_anchor` 39件 OK（21秒）、`tests.test_audit_snapshot` 8件 OK、`tests.test_gateway` OK（3秒）、`tests.test_diagnosis_actions` 38件 OK（34秒）、`tests.test_attack_regressions` 50件 OK（55秒）。そのほかのモジュールは §末尾の「この資料での確認」を参照してください。

### Web UI

```sh
npm --prefix web ci
npm --prefix web test        # web/tests/*.test.mjs
npm --prefix web run lint
npm --prefix web run build
```

### ブラウザ E2E（3本。CI の「Real ARTEX planner …」ジョブで実行しているもの）

各スクリプトは、一時データディレクトリ・ローカルのラボ・コントロールプレーン・Next.js の本番ビルド・ARTEX の代役（固定規則のプランナー）を自分で起動します。モデル・有料 API・実サイトには接続しません（各スクリプト冒頭の説明）。スクリプトの中で `AEGIS_ENV=development` と `VULNIX_EXTERNAL_PROPOSALS=0` を設定します（`scripts/check_diagnosis_actions.py:38-39`, `:78-80`）。

```sh
npm --prefix web ci && npm --prefix web run build
python3 -m pip install playwright==1.56.0 && python3 -m playwright install chromium
export VULNIX_NO_ENV_LOCAL=1
python3 -m scripts.check_diagnosis_ui      --production --chromium --screenshots ./out/diagnosis-ui      > ./out/diagnosis-ui.json
python3 -m scripts.check_diagnosis_actions --production --chromium --screenshots ./out/diagnosis-actions > ./out/diagnosis-actions.json
python3 -m scripts.check_first_run         --production --chromium --screenshots ./out/first-run         > ./out/first-run.json
# 判定：各 JSON の "ok" が true（CI と同じ。.github/workflows/ci.yml:440-459）
```

| スクリプト | 内容 |
|---|---|
| `scripts/check_diagnosis_ui.py` | 診断パネル（SSE、再起動、改ざん、別の組織） |
| `scripts/check_diagnosis_actions.py` | 開始・仕様・L2 承認・修正後の確認。依頼者の承認 403、同じキーの再送、別組織 403、実サイト 404 |
| `scripts/check_first_run.py` | 新規登録 → 開始 → 承認者の招待 → 390px での承認 → 修正後の確認 |

### Linux だけで確かめられるもの

```sh
# カーネル隔離の通し確認（skip は失敗とみなす。.github/workflows/ci.yml:103-110）
python3 -m unittest -v tests.test_release_safety.TestOnLinuxWithTheRealKernelConfinement \
                       tests.test_fail_closed.TestKernelConfinementOnLinux
# nftables / netns と緊急停止（P0）
sudo python3 -m aegis.control_verification
```

**監査アンカーを別の OS ユーザーで動かす**（CI「Local audit anchor as a separate OS user …」、`.github/workflows/ci.yml:112-137` と同じ手順）。補助プロセスは専用のシステムユーザーで動かし、テストを実行するユーザーはソケットのディレクトリのグループで接続だけできるようにします。同じユーザーで動かすと、`same_user`（保護なし）になり、この確認にはなりません。

```sh
set -euo pipefail
PY="$(command -v python3)"; GROUP="$(id -gn)"
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vulnix-anchor
sudo install -d -o root -g root -m 0755 /opt/vulnix-anchor
sudo install -o root -g root -m 0644 aegis/audit_anchor.py /opt/vulnix-anchor/audit_anchor.py
sudo install -d -o vulnix-anchor -g vulnix-anchor -m 0700 /var/lib/vulnix-anchor
sudo install -d -o vulnix-anchor -g "$GROUP" -m 0750 /run/vulnix-anchor
(cd / && sudo -u vulnix-anchor "$PY" /opt/vulnix-anchor/audit_anchor.py serve \
   --dir /var/lib/vulnix-anchor --socket /run/vulnix-anchor/anchor.sock --socket-mode 666 --allow-source ci) &
python3 scripts/audit_anchor_ci.py --socket /run/vulnix-anchor/anchor.sock \
   --anchor-dir /var/lib/vulnix-anchor --helper-uid "$(id -u vulnix-anchor)" --source-name ci
# 期待する最後の行：AUDIT ANCHOR CI: OK
(cd / && sudo -u vulnix-anchor "$PY" /opt/vulnix-anchor/audit_anchor.py verify --dir /var/lib/vulnix-anchor)
```

### サーバーを手で動かす（探索的な試験用）

```sh
export VULNIX_NO_ENV_LOCAL=1 VULNIX_REAL_SERVICE_DIAGNOSIS=0
python3 -m aegis.server --port 8787 --data-dir ./data-review          # 初回は初期アカウントの場所を表示
AEGIS_API=http://127.0.0.1:8787 npm --prefix web run start             # http://127.0.0.1:3000
```

| 環境変数 | 意味 |
|---|---|
| `VULNIX_NO_ENV_LOCAL=1` | `.env.local` を読まない（必須） |
| `VULNIX_REAL_SERVICE_DIAGNOSIS=0` | 実サイトへの通信をすべて止める（レビューでは必須） |
| `VULNIX_PUBLIC_SIGNUP=1` | 自己登録を有効にする（組織間の試験に使う。`DEVELOPMENT.md` の例） |
| `AEGIS_SEPARATE_L2_APPROVER=1`（または `--separate-l2-approver`） | 依頼者と承認者の分離を手動の ARTEX・自己登録アカウントにも適用（O1・O2 の比較に） |
| `VULNIX_MULTI_TENANT=0` | 組織なしの単一サービス（既定は組織あり） |
| `VULNIX_AUDIT_ANCHOR_SOCKET` / `_UID` / `_SOURCE` | 監査アンカー（3つとも実環境で設定。`.env.local` からは読まない） |
| `VULNIX_DIAGNOSIS_APPROVAL_TIMEOUT` / `_APPROVAL_VALID` / `_SPEC_TIMEOUT` | 承認待ち（900秒）・承認の有効期限（300秒）・仕様待ち（24時間） |
| `AEGIS_ENV=development` | 開発モード（自己登録・読み取り認証の無効化などが可能になる）。本番の挙動を見るときは付けない |

---

## 5. 所見の書式と報告の方法

**このリポジトリは公開されています。所見は公開の Issue や PR に書かないでください。** GitHub の Private vulnerability reporting（`SECURITY.md` のリンク）か、所有者が指定した非公開の連絡手段で送ってください。所有者は7日以内に返信します（`SECURITY.md`）。

```markdown
### [重大度] 一行の要約
- 重大度：Critical / High / Medium / Low / Info
- 領域：(a) 認証 / (b) 組織の分離 / (c) 権限と失効 / (d) Worker の隔離 / (e) 監査 / 診断ループ API / その他
- 対象コミット：e977695
- 場所：aegis/xxx.py:行（複数可）
- 前提：攻撃者の立場（§1 の脅威モデル）、必要な設定・環境変数、OS
- 再現手順：模擬ラボ（lab.test）での手順。テストコードの形だとありがたいです
- 結果：期待した結果と、実際の結果
- 影響：何が起きるか（例：他の組織の証拠が読める、承認なしで L2 が動く）
- 修正の案：（任意）
- 既知の制限との関係：各領域ファイルの「既知の制限」に含まれるかどうか
```

重大度の目安として、`SECURITY.md`「特に重要として扱うもの」（他組織へのアクセス、所有確認の流用、承認なしの L2、隔離の外への通信、停止後も続く処理、秘密情報の漏えい、公開β版の入口から API への到達）に当たるものは High 以上として扱ってください。

---

## 6. これまでの AI による独立レビュー（参考）

**以下はすべて AI エージェントによるレビューで、正式な GitHub の Approve でも、人によるセキュリティレビューの代わりでもありません**（`docs/V1_COMPLETION.md` Q5、A2）。出典はリポジトリ内の文書です。この資料の作成ではネットワークを使っていないため、GitHub 上の PR の説明は読んでいません。

| 時期・対象 | 主な指摘と修正 | 出典 |
|---|---|---|
| PR #85 の累積差分（2026-11-17〜19） | `Set-Cookie` の値が証拠・監査に残る問題、POST 応答・SSE・保護 GET での失効後の結果返却、所有確認の照会中の失効、停止応答の失効、管理者用接続確認の費用境界、監査 JSONL の切り戻しによる有料送信額の過少計上（予約ファイルを追加） | `docs/SECURITY_REVIEW.md` 3-76行 |
| `dd55f60` の再レビュー | **P1**：HTTP/1.1 の同じ接続に残った組織 ID がプラットフォーム API に効き、自己登録者の組織 owner 権限で L2 プロファイル承認が 200 になる（`18b38f2` で修正） | `docs/SECURITY_REVIEW.md` 120行 |
| 監査チェーン | 破損済みチェーンへの追記、別サービスの追記によるチェーン破損、同時の Worker 許可・予約の競合、有効な先頭部分への切り戻し | `docs/SECURITY_REVIEW.md` 109行, 112-116行 |
| 長い処理と失効 | ARTEX 計画中のモデル転送・Worker 起動が要求者の失効を見ない問題、外部 AI 解説の送信時の権限、Planner LLM Gateway の送信時のリース | `docs/SECURITY_REVIEW.md` 124行, 136-144行 |
| 診断ループ（統合前、2026-11-21） | 判定の監査が失敗したのに仮説が変わる、別の検査 ID での判定、状態と実行の結び付け、ARTEX への要求にラボの URL が含まれる、停止・失効後の反映 | `docs/DIAGNOSIS_LOOP.md` 142-155行 |
| 診断の表示 API | 後始末の監査失敗で計画が終わらない、表示 API がロックを持ったまま監査ログを読む、通知の失敗を変更の失敗として返す | `docs/DIAGNOSIS_READ_API.md` §6.1 |
| 診断の操作（PR-C） | 仕様の同時送信で L2 が2回実行され得る、仕様待ちの期限なし、承認の時間切れの瞬間の承認、手動の ARTEX との並行。マージ前に、Worker 起動直前の承認者の再確認、実行権の一本化、応答と永続状態の分離 | `docs/DIAGNOSIS_ACTIONS.md` §7, §8 |
| 監査アンカー（PR #115） | レビュアーの PoC（シンボリックリンクによる古いコピーへの差し替え）を回帰テストに | `tests/test_audit_anchor.py::TestSourceIdentity::test_reviewer_poc_scenario` |

これらのレビュー自身が、未確認の範囲を残しています（例：`docs/SECURITY_REVIEW.md` 81行「195ファイル全体の完全監査ではなく」、同 75行「残る150ファイルの全差分と実行時設定は未監査」）。

---

## この資料での確認

- 行番号は `e977695` のワークツリーで、該当箇所を読んで確かめました。
- 引用したテスト名は、`tests/` で定義を検索して存在を確かめました。テストの中身まで読んだのは一部です（`test_csrf_guard`、`test_l2_waits_for_human_and_stop_kills_worker` など）。
- 手元（macOS）で実行したテストは §4 に記載したものと、この下に追記したものだけです。Linux の隔離、監査アンカーの別ユーザーでの確認、ブラウザ E2E は、この資料の作成では**実行していません**（CI の記録は `docs/V1_COMPLETION.md` §6）。
- 追記（同じ macOS、`VULNIX_NO_ENV_LOCAL=1`）：`tests.test_tenancy` 619件 OK（434秒）、`tests.test_fail_closed` 83件 OK（4件 skip：Linux 専用）、`tests.test_release_safety` OK（6件 skip）、`tests.test_worker_deadline` 26件 OK、`tests.test_egress_sentinel` 4件 OK、`tests.test_server` 30件 OK。
