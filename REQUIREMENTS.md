# Vulnix — 要件定義

本書は Vulnix（ヴァルニクス / 旧称: Aegis AI）の機能要件・非機能要件・制約を定義する。設計の第一原則は
**「AI は提案する、実行はゲートウェイが裁く」**。AI/エージェント出力は信頼されない
データであり、実行権限はサーバ側シークレットを持つ Gateway のみが有する。

## 1. 背景と目的

- ARTEX（自律診断エージェント／**UNTRUSTED**）、Abliteration AI（提案専用の推論モデル／
  **PROPOSAL-ONLY**）、Vulnix（独立した安全制御プレーン + CVE 検証 + 可視化 UI）を
  組み合わせた AI Security Testing Platform（Find. Prove. Secure.）を提供する。
- 製品価値は「確かめられること」。偽の PASS や攻撃能力は実害と見なし、提供しない。

## 2. 機能要件

### FR-1 独立実行ゲートウェイ
- FR-1.1 AI 出力は strict schema `{tool, target_id, action, args, rationale}` に正規化する。
- FR-1.2 `approved` / `token` / `scope` 等の権限詐称キー、未知キーを除去する。
- FR-1.3 `rationale` は最大 500 文字に切り詰め、その内容は action を変更しない（プロンプト
  インジェクション無効化）。
- FR-1.4 `ProposalRouter` は実行権限（トークン・承認）を一切保持しない。
- FR-1.5 Gateway のみが 6層制御を通過した提案を、発行済みトークンと照合して実行する。

### FR-2 認証・認可
- FR-2.1 操作者認証は scrypt（N=2^15, r=8, p=1）でハッシュ化。平文は保存しない。
- FR-2.2 セッションは TTL 12h、アトミック書き込み（temp + `os.replace`, 0600）で永続化。
- FR-2.3 パスワード変更時、当該操作者の他セッションを失効させる。
- FR-2.4 TOTP（RFC 6238 / HOTP RFC 4226）による MFA を標準ライブラリのみで提供する。

### FR-3 ネットワーク egress 制御（3層）
- FR-3.1 アプリ層 `EgressGuard`: DNS ピンニング / CIDR 判定 / メタデータIP ハードdeny。
- FR-3.2 プロセス内 `egress_sentinel`: `socket.connect` をパッチし pin 済み (ip,port) のみ許可。
- FR-3.3 OS カーネル `netfilter`: nftables default-drop ルール生成と `nft -c` 構文チェック。
  適用は Linux+root でのみ可能（`supported()` が False のホストでは適用しない）。

### FR-4 CVE インテリジェンス（検知 ≠ 証明）
- FR-4.1 NVD CVE API 2.0 形式の JSON フィードをオフラインで取り込む（ネットワーク I/O は
  呼び出し側が担う）。
- FR-4.2 バナー（`Product/x.y.z`）を CPE 製品キーに解決（`PRODUCT_ALIASES`）し、バージョン
  範囲で候補 CVE を抽出する。
- FR-4.3 マッチ結果は `verdict="detected", verified=False`。決して "proven" にしない。
- FR-4.4 カタログはメタデータのみ（id, 影響バージョン, severity, remediation, 参照）。
  エクスプロイトコード・ペイロードを持たない。

### FR-5 可視化 UI（詳細は [UI_UX_DESIGN.md](UI_UX_DESIGN.md) を参照）
- FR-5.1 日常運用3タブ（「診断」「問題」「ログ」）、侵入実証テスト UI、「？」3段階学習、診断コンテキスト連携 AI チャット、履歴比較、Markdown レポート出力、学習履歴を提供する。
- FR-5.2 UI は `/api/*` をコントロールプレーンへプロキシする（127.0.0.1 限定）。

## 3. 非機能要件

- NFR-1 バックエンドは Python 標準ライブラリのみ（外部依存ゼロ）。Python 3.10+。
- NFR-2 フロントエンドは Next.js / React / TypeScript / Tailwind。
- NFR-3 テスト: `python3 -m pytest tests/`（94件）、Web は tsc + eslint + next build を通す。
- NFR-4 シークレット（`.env` / `*.key` / `data/` / `operators.json` / `sessions.json` /
  `audit.jsonl`）はコミットしない（`.gitignore` で除外）。
- NFR-5 変更を完了と報告する前に検証を実行し、未実行の確認は UNVERIFIED と記す。

## 4. 制約（やらないこと／ハードライン）

- C-1 攻撃・エクスプロイトのワーカーを実装・実行しない。ワーカーは非破壊。
- C-2 AI に実行権限を委譲しない。autonomous L2+ 実行は仕様で禁止（既定 OFF）。
- C-3 検知を「証明済み」と偽らない。
- C-4 非 Linux ホストでカーネル enforcement を「適用済み」と主張しない。
- C-5 API キー等の資格情報をコード・ログに保存しない。ユーザが実行時に環境変数で設定する。
- C-6 無認可の外部ネットワーク呼び出し（推論エンドポイント・フィード取得）を行わない。

## 5. 受け入れ基準

- AC-1 権限詐称キー付きの提案を Router 経由で送っても、Gateway がスコープ外として拒否する
  （エンドツーエンドのテストで検証済み）。
- AC-2 スコープ内の提案のみ Gateway が許可し、ワーカー結果を返す。
- AC-3 Apache 2.4.49 のバナーから CVE-2021-41773 / CVE-2021-42013 を検知（detected）する。
- AC-4 パッチ済みバージョン（2.4.52）では候補ゼロ。
- AC-5 `GET /api/router/status` が `autonomous_execution: false` を返す。
