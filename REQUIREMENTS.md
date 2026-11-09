# Vulnix — 要件定義

本書は Vulnix（ヴァルニクス / 旧称: Aegis AI）の機能要件・非機能要件・制約を定義する。設計の第一原則は
**「AI は提案する、実行はゲートウェイが裁く」**。AI/エージェント出力は信頼されない
データであり、実行権限はサーバ側シークレットを持つ Gateway のみが有する。

## 1. 背景と目的

- ARTEX（自律診断エージェント・タスクプランナー／**UNTRUSTED**）、Abliteration AI（提案専用の推論モデル／
  **PROPOSAL-ONLY**）、Vulnix（独立した安全制御プレーン + CVE/KEV 継続検証 + 実証型検証 + 可視化 UI）を
  組み合わせた AI Security Testing Platform（**Find. Prove. Secure.**）を提供する。
- 製品価値は「正式な許可と厳格な6層制御のもとで、侵入・悪用可能性が実際に成立するかを確かめ、修正前後の防御有効性まで証明できること」。偽の PASS や無認可・破壊的な攻撃能力は実害と見なし、提供しない。

## 2. 機能要件

### FR-1 独立実行ゲートウェイ & ARTEX × Abliteration 統合
- FR-1.1 AI 出力は strict schema `{tool, target_id, action, args, rationale}` に正規化する。
- FR-1.2 `approved` / `token` / `scope` 等の権限詐称キー、未知キーを除去する。
- FR-1.3 `rationale` は最大 500 文字に切り詰め、その内容は action を変更しない（プロンプト
  インジェクション無効化）。
- FR-1.4 `ProposalRouter`・`AbliterationBackend`・`ArtexEngine` は実行権限（トークン・承認）を一切保持しない。
- FR-1.5 Gateway のみが 6層制御を通過した提案を、発行済みトークンと照合して実行する。
- FR-1.6 `AbliterationBackend` は OpenAI 互換 Chat Completions API（`messages` / `choices[0].message.content` および Markdown JSON コードブロック抽出）に対応し、提案生成（`propose()`）と診断コンテキスト連携 Q&A（`chat()`）の両方を担う。
- FR-1.7 `ArtexEngine` は診断フェーズごとのタスク計画（recon → header_audit → cve_match → verification → defense_verify）を管理し、提案を `ProposalRouter` 経由で Gateway に提出する。

### FR-2 認証・認可
- FR-2.1 操作者認証は scrypt（N=2^15, r=8, p=1）でハッシュ化。平文は保存しない。
- FR-2.2 セッションは TTL 12h、アトミック書き込み（temp + `os.replace`, 0600）で永続化。
- FR-2.3 パスワード変更時、当該操作者の他セッションを失効させる。
- FR-2.4 TOTP（RFC 6238 / HOTP RFC 4226）による MFA を標準ライブラリのみで提供する。

### FR-3 ネットワーク egress 制御（3層）と P0 実機制御検証
- FR-3.1 アプリ層 `EgressGuard`: DNS ピンニング / CIDR 判定 / メタデータIP ハードdeny。
- FR-3.2 プロセス内 `egress_sentinel`: `socket.connect` をパッチし pin 済み (ip,port) のみ許可。
- FR-3.3 OS カーネル `netfilter`: nftables default-drop ルール生成と `nft -c` 構文チェック。
  適用は Linux+root でのみ可能（`supported()` が False のホストでは適用しない）。
- FR-3.4 `control_verification.py`（`GET/POST /api/system/verify-controls`）により、実機の Worker サブプロセス・ソケット・ProposalRouter・Gateway を用いて ①許可外通信遮断、②権限詐称キー無効化、③L2 人間承認ゲート、④緊急停止（SIGKILL）、⑤nftables 構文検証の 5 項目をセルフテストできる。

### FR-4 CVE / CISA KEV インテリジェンスと実証型検証（検知 ≠ 証明、修正前後比較）
- FR-4.1 NVD CVE API 2.0 形式および CISA KEV（Known Exploited Vulnerabilities）形式のフィードを取り込み、`FeedMonitor` で継続的な同期・資産バナー照合（`correlate_assets`）を行う。
- FR-4.2 バナー（`Product/x.y.z`）を CPE 製品キーに解決（`PRODUCT_ALIASES`）し、バージョン
  範囲で候補 CVE を抽出する。バナー一致時点では `verdict="detected", verified=False` とし、決して自動的に "proven" にしない。
- FR-4.3 人間の承認者（Approver）が L2 検証を承認した場合に限り、Gateway がスコープ固定・`egress_sentinel` 適用下の非破壊再現ワーカー（`reproduction_probe`）を起動し、脆弱性の成立（`verdict="proven", verified=True`）または不成立（`verdict="not_reproduced", verified=True`）を実測レスポンスと SHA-256 証拠ハッシュで記録する。
- FR-4.4 修正適用後の再検証（`POST /api/assessments/<id>/verify-fix`）を実行し、修正前（`proven`）と修正後（`not_reproduced`）のステータス・総合リスクスコア・HTTP ステータス変化を比較記録する。

### FR-5 可視化 UI（詳細は [UI_UX_DESIGN.md](UI_UX_DESIGN.md) を参照）
- FR-5.1 日常運用3タブ（「診断」「問題」「ログ」）、侵入実証テスト UI、修正前後の防御比較 UI、「？」3段階学習、診断コンテキスト連携 AI チャット、履歴比較、Markdown レポート出力、学習履歴、P0 安全制御セルフテスト、CVE/KEV 監視パネルを提供する。
- FR-5.2 UI は `/api/*` をコントロールプレーンへプロキシする（127.0.0.1 限定）。

## 3. 非機能要件

- NFR-1 バックエンドは Python 標準ライブラリのみ（外部依存ゼロ）。Python 3.10+。
- NFR-2 フロントエンドは Next.js / React / TypeScript / Tailwind。
- NFR-3 テスト: `python3 -m pytest tests/`、Web は tsc + eslint + next build を通す。
- NFR-4 シークレット（`.env` / `*.key` / `data/` / `operators.json` / `sessions.json` /
  `audit.jsonl`）はコミットしない（`.gitignore` で除外）。
- NFR-5 変更を完了と報告する前に検証を実行し、未実行の確認は UNVERIFIED と記す。

## 4. 制約（やらないこと／ハードライン）

- C-1 無認可のターゲットに対する攻撃や、データを破壊・改ざんするエクスプロイトワーカーを実装・実行しない。実証ワーカー（`reproduction_probe`）は Gateway がピン留めした許可スコープ内の非破壊検証（読み取り専用の境界確認・マーカー確認）に限定する。
- C-2 AI に実行権限を委譲しない。autonomous L2+ 実行は仕様で禁止（既定 OFF）。
- C-3 バナー検知のみを「証明済み（proven）」と偽らない。必ず L2 実証ワーカーの成立確認を経て `proven` に遷移させる。
- C-4 非 Linux ホストでカーネル enforcement を「適用済み」と主張しない。
- C-5 API キー等の資格情報をコード・ログに保存しない。ユーザが実行時に環境変数で設定する。
- C-6 無認可の外部ネットワーク呼び出しを行わない。

## 5. 受け入れ基準

- AC-1 権限詐称キー付きの提案を Router 経由で送っても、Gateway がスコープ外として拒否する
  （エンドツーエンドのテストおよび `/api/system/verify-controls` で検証済み）。
- AC-2 スコープ内の提案のみ Gateway が許可し、ワーカー結果を返す。
- AC-3 Apache 2.4.49 のバナーから CVE-2021-41773 / CVE-2021-42013 を検知（detected）し、CISA KEV 悪用確認フラグを付与する。
- AC-4 L2 承認後に `reproduction_probe` が隔離ラボに対して再現検証を行い、脆弱時は `proven`、パッチ適用後の再検証（`/verify-fix`）では `not_reproduced` へ遷移する。
- AC-5 `GET /api/router/status` が `autonomous_execution: false` と ARTEX タスク計画状態を返す。

