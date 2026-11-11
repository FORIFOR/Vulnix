# Vulnix（ヴァルニクス）

**Find. Prove. Secure. — AI Security Testing Platform**

**AI は提案する、実行はゲートウェイが裁く（AI proposes, Gateway disposes）** を第一原則とする、AI セキュリティ診断・実証プラットフォーム（旧称: Aegis AI）。

AI/エージェント（ARTEX / Abliteration AI）の出力は常に「信頼できない提案（データ）」として扱い、実行権限はサーバ側シークレット（HMAC トークン）を握る Gateway だけが持ちます。バナー検知（`detected`）と正式な人間承認下の再現証明（`proven`）、そしてパッチ適用後の再検証（`not_reproduced`）を明確に分離し、無認可・破壊的な攻撃は一切行いません。

> 🛡️ **スコープと安全性**: すべての診断・再現検証ワーカー（`http_probe`, `reproduction_probe`, `demo_verify`）は Gateway が DNS ピン留めした許可ターゲットに対し、プロセス内 `egress_sentinel`（`socket.connect` ホワイトリスト強制）下で非破壊・読み取り専用のリクエストのみを実行します。

---

## アーキテクチャ

```
┌──────────────────┐   提案(untrusted)   ┌──────────────┐   権限あり   ┌──────────┐
│ ARTEX Engine ×   │ ─────────────────▶ │ ProposalRouter│ ──────────▶ │ Gateway  │ ─▶ Worker
│ Abliteration AI  │   schema に正規化    │ (権限を持たない)│   token 発行  │ (6層制御) │   (egress_sentinel)
│ (OpenAI互換API)   │   authority鍵を除去  └──────────────┘             └──────────┘
└──────────────────┘
```

- **ARTEX Engine × Abliteration AI**（`aegis/router.py`） …
  - `AbliterationBackend`: OpenAI 互換 Chat Completions API（`messages` / `choices[0].message.content` + Markdown JSON コードブロック抽出）に対応した専用アダプター。提案生成（`propose()`）と診断コンテキスト連携 Q&A（`chat()`）を提供。
  - `ArtexEngine`: 診断フェーズごとのタスク計画（`recon` → `header_audit` → `cve_match` → `verification` → `defense_verify`）を管理。実行権限は一切持たず、すべての提案を `ProposalRouter` に送る。
- **ProposalRouter**（`aegis/router.py`） … 実行権限を一切持たない（`tokens`/`approvals` 属性を持たないことをテストで保証）。提案を strict schema `{tool, target_id, action, args, rationale}` に正規化し、権限詐称キーを除去して Gateway に転送するだけ。
- **Gateway**（`aegis/gateway.py`） … 唯一の実行権限保持者。6層制御を通過した提案のみ、発行済みトークンと照合して実行。

### 6層制御モデルと P0 実機セルフテスト（`aegis/control_verification.py`）
1. 認可（Authorization） 2. ポリシー（Policy） 3. ネットワーク（Network）
4. ランタイム（Runtime） 5. データ（Data） 6. 緊急停止（Emergency）

`GET/POST /api/system/verify-controls`（UIの設定画面または診断コンテキストパネルから実行可能）により、実機の Worker サブプロセス・ソケット・ProposalRouter・Gateway を使って以下の 5 項目をエンドツーエンドで実機検証できます：
1. **許可外通信の強制遮断（`egress_isolation`）**: `egress_sentinel` 下で許可 IP:Port への通信が成功し、スコープ外 IP:Port（`198.51.100.99:4444`）への `socket.connect` が `PermissionError` で即座に遮断されること
2. **権限逸脱・詐称キー無効化（`privilege_escalation_prevention`）**: AI 提案に `approved: true` / `token: "forged"` を注入しても `ProposalRouter` が除去し、スコープ外 URL を Gateway が拒否すること
3. **L2 人間承認ゲート（`l2_approval_gate`）**: 承認なしのトークン発行が `ValueError` で拒否され、承認者の署名後のみ発行されること
4. **緊急停止 SIGKILL（`emergency_stop_sigkill`）**: 実行中の Worker プロセスグループが `kill_all()` により SIGKILL で即座に強制終了されること
5. **OS ファイアウォール構文検証（`netfilter_ruleset`）**: `nftables` default-drop ルール生成とホスト環境（Linux+root でのカーネル適用可否）の正確な報告

---

## 必要要件

- **バックエンド**: Python 3.10+（標準ライブラリのみ。外部依存なし）
- **フロントエンド**: Node.js 18+ / Next.js（`web/`）
- テスト確認環境: Python 3.15 / Node 26

## セットアップと起動

### 1. コントロールプレーン（Python）
```bash
python3 -m aegis.server            # http://127.0.0.1:8787 で待受
# オプション: --port 8787 --lab-port 18081 --verify-seconds 20 --data-dir ./data
```
- 初回起動時に操作者アカウントを生成し、**ハッシュのみ** `operators.json` に保存。平文の初期ログイン情報は `0600` 権限の別ファイルに出力され、パスはコンソールに表示されます。

### 2. Web UI（Next.js）
```bash
cd web
npm install
npm run dev                        # http://localhost:3000
```
`web/` は `/api/*` を `AEGIS_API`（既定 `http://127.0.0.1:8787`）へプロキシします。

## 環境変数

| 変数 | 用途 | 既定 |
|------|------|------|
| `VULNIX_ABLITERATION_URL` / `AEGIS_MODEL_URL` | Abliteration AI（OpenAI 互換 `/v1/chat/completions` または `/v1/propose`）のエンドポイント。未設定なら内蔵 ARTEX プランナーで動作。 | なし |
| `VULNIX_ABLITERATION_KEY` / `AEGIS_MODEL_KEY` | 上記の Bearer API キー（実行時に環境変数で設定。リポジトリやログには保存しない）。 | なし |
| `VULNIX_ABLITERATION_MODEL` / `AEGIS_MODEL_MODEL` | 使用モデル名 | `"abliteration-security-v1"` |
| `VULNIX_ABLITERATION_TIMEOUT_SECONDS` / `AEGIS_MODEL_TIMEOUT_SECONDS` | 同じ接頭辞のモデルHTTP応答待ち。1〜120秒。未設定・不正値は30秒。必要な起動プロセスだけに設定。 | `30` |
| `VULNIX_NVD_FEED_URL` / `VULNIX_KEV_FEED_URL` | `POST /api/cve/sync` 実行時の NVD / CISA KEV フィード取得先 URL | 内蔵フィード |
| `AEGIS_API` | Web → コントロールプレーンのプロキシ先 | `http://127.0.0.1:8787` |

### AI連携とデモの検証範囲

- 標準設定では内蔵の決定的な ARTEX プランナーと診断情報に基づく内蔵解説を使用します。外部モデルは起動時に設定した場合だけ利用します。
- `VULNIX_ABLITERATION_*` を優先し、`AEGIS_MODEL_*`、`VULNIX_MODEL_*` も利用できます。URL・キー・モデル名は同じ接頭辞で設定してください。別の接続先のキーを流用しません。
- OpenAI互換アダプターの提案形式・解説QAは単体テストとループバックHTTPサーバーで確認しています。これらは実モデルの推論品質やAbliteration済みモデルの実動作を保証するテストではありません。
- 既定の対象はローカルHTTP模擬ラボです。脆弱箇所・影響・対策・証拠を学び、模擬的な防御前後を比較できます。本番環境の自動修正・パッチ配布や、任意のサイトを対象にした万能のペネトレーションテストは実装していません。

### 実サービスの診断（所有確認済みの対象のみ）

管理権限を証明できた自社サービス（ステージング想定）だけを、次の順で診断できます。

1. **URL登録** — `POST /api/assets/challenge`。インストールごとに異なる検証トークンを発行します（この時点では対象へ通信しません）。
2. **所有確認** — `POST /api/assets/verify-ownership`。DNS TXT（`_vulnix-verify.<host>`）または `https://<host>/.well-known/vulnix-verify.txt`。失敗した再確認は確定済みの範囲を取り消します。
3. **範囲・禁止事項の確認** — `POST /api/assets/confirm-scope`。対象はそのホスト・そのポートのみ、30日で失効。ループバック／プライベート／メタデータアドレスへ解決されるホストは拒否します。
4. **L1診断（読み取り専用）** — GET 1回の実測から TLS・HSTS/CSP/nosniff・Cookie属性・CORS・公開技術情報（NVD/KEV照合）・未認証JSON応答を検査します。
5. **L2検証（任意・項目ごとの承認）** — 検証専用アカウント（A／B／Freeプラン）を `POST /api/assets/secrets` で暗号化保存し、承認責任者が項目ごとに実行します。一括検証や所有確認だけではL2は実行されません。

判定の原則:

- トークンは該当チェックのWorkerプロセスの環境変数にだけ渡し、argv・監査ログ・`state.json`・レポート・動画用JSONには残しません（表示は SHA-256 先頭8桁の指紋のみ）。
- 「再現せず」は、チェックごとに定めた拒否ステータス（例: IDORは403/404、課金は402/403）かつ、所有者アカウントBが同じ模擬データを取得できた場合（所有者コントロール）にだけ付けます。401（検証用トークンの失効）やパス誤りによる404は「未完了・要確認」です。
- 未計測のL2候補は総合リスクに加点も減点もしません。
- `GET /api/assessments/<id>/remotion` は、架空データと未計測候補を除いた匿名化JSON（動画用）を返します。

検証範囲: 上記はループバックの模擬サービスに対するテスト（`tests/test_real_service.py`）で確認しています。DeepNote STG など実在サービスへの通信は自動テストでは行っておらず、L2の既定パスとマーカー（`DEEPNOTE_*`）は対象側に模擬データを用意する前提の仮の値です。

## テスト

```bash
python3 -m pytest tests/
cd web && npm run typecheck && npm run lint && npm run build
```

---

## 実装状況

| 優先度 | 項目 | 状態 |
|--------|------|------|
| **P0** | 実行制御の実機検証（`/api/system/verify-controls`: 通信遮断・権限逸脱防止・承認・SIGKILL緊急停止） | ✅ 完了・実機検証済み |
| **P1** | ARTEX 実行エンジン（`ArtexEngine`）× Abliteration AI 専用アダプター（`AbliterationBackend` OpenAI互換 Chat Completions 対応） | ✅ 完了・テスト済み |
| **P2** | NVD + CISA KEV 継続監視（`FeedMonitor`）・隔離ラボでの認可済み再現実証（`reproduction_probe` → `proven`）・修正前後の防御比較（`/verify-fix` → `not_reproduced`） | ✅ 完了・テスト済み |
| **P3** | 3タブUI（「診断」「問題」「ログ」）・「？」3段階学習・AIチャット連携・Markdownレポート・レスポンシブ対応 | ✅ 完了・ビルド検証済み |

詳細な要件定義は [REQUIREMENTS.md](REQUIREMENTS.md)、UI/UX詳細設計は [UI_UX_DESIGN.md](UI_UX_DESIGN.md) を参照。


