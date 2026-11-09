# Vulnix（ヴァルニクス）

**Find. Prove. Secure. — AI Security Testing Platform**

**AI は提案する、実行はゲートウェイが裁く（AI proposes, Gateway disposes）** を第一原則とする、防御志向の AI セキュリティ診断プラットフォーム（旧称: Aegis AI）。

AI/エージェントの出力は常に「信頼できない提案（データ）」として扱い、実行権限はサーバ側シークレット（HMAC トークン）を握る Gateway だけが持ちます。検知（detection）と証明（proof）を分離し、攻撃・エクスプロイトは一切実装・実行しません。

> ⚠️ **スコープ**: 本リポジトリは防御的なコントロールプレーンと UI のみを提供します。ワーカーは非破壊（`http_probe` は読み取り専用の HEAD/GET、`demo_verify` は攻撃を行わない）です。攻撃・エクスプロイトのワーカーは含みません。

---

## アーキテクチャ

```
┌─────────────┐   提案(untrusted)   ┌──────────────┐   権限あり   ┌──────────┐
│ ARTEX /     │ ─────────────────▶ │ ProposalRouter│ ──────────▶ │ Gateway  │ ─▶ Worker
│ Abliteration│   schema に正規化    │ (権限を持たない)│   token 発行  │ (6層制御) │   (非破壊)
│  = 提案のみ  │   authority鍵を除去  └──────────────┘             └──────────┘
└─────────────┘
```

- **ARTEX / Abliteration** … 提案生成源。信頼されない。`ProposalRouter` が strict schema `{tool, target_id, action, args, rationale}` に縮約し、`approved`/`token` 等の権限詐称キーを除去、rationale を 500 文字に切り詰める。
- **ProposalRouter**（`aegis/router.py`） … 実行権限を一切持たない（`tokens`/`approvals` 属性を持たないことをテストで保証）。提案を Gateway に転送するだけ。
- **Gateway**（`aegis/gateway.py`） … 唯一の実行権限保持者。6層制御を通過した提案のみ、発行済みトークンと照合して実行。

### 6層制御モデル
1. 認可（Authorization） 2. ポリシー（Policy） 3. ネットワーク（Network）
4. ランタイム（Runtime） 5. データ（Data） 6. 緊急停止（Emergency）

### ネットワーク egress の3層防御
| 層 | モジュール | 対象 | 本ホスト(macOS)での状態 |
|----|-----------|------|------------------------|
| アプリ層 | `aegis/network.py` `EgressGuard` | DNS ピンニング / CIDR / メタデータIP ハードdeny | 有効 |
| プロセス内 | `aegis/workers/egress_sentinel.py` | `socket.connect` をパッチし pin 済み (ip,port) のみ許可 | 有効 |
| OS カーネル | `aegis/netfilter.py` | nftables default-drop ルール生成 + `nft -c` 構文チェック | ルール生成/検査のみ。**カーネル適用は Linux+root が必要で未検証（UNVERIFIED）** |

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
- 初回起動時に操作者アカウントを生成し、**ハッシュのみ** `operators.json` に保存。平文の初期ログイン情報は `0600` 権限の別ファイルに出力され、パスはコンソールに表示されます（手元で確認してください）。
- 再生成するには `operators.json` と資格情報ファイルを削除して再起動。

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
| `AEGIS_MODEL_URL` | 推論バックエンド（`HttpModelBackend`）のエンドポイント。**未設定なら推論連携は無効**（既定で autonomous 実行は OFF）。 | なし |
| `AEGIS_MODEL_KEY` | 上記の Bearer API キー。**実行時にユーザが設定**。リポジトリやログには保存しない。 | なし |
| `AEGIS_MODEL_MODEL` | モデル名 | `""` |
| `AEGIS_API` | Web → コントロールプレーンのプロキシ先 | `http://127.0.0.1:8787` |

> 🔑 API キーはコードが読み書きしません。`GET /api/router/status` は接続状態と `autonomous_execution: false` を返します。自律実行は設計上 OFF です。

## テスト

```bash
python3 -m pytest tests/
cd web && npm run typecheck && npm run lint && npm run build
```

---

## 実装状況

| 優先度 | 項目 | 状態 |
|--------|------|------|
| P0 | 診断・問題・ログの3タブUI / 実行状態・一時停止・緊急停止 / 診断許可・承認表示 / 実証結果と証拠 / 6層制御・監査チェーン | ✅ 完了 |
| P1 | 「？」による3段階解説 / 最新CVEの影響・検証状況 / AIチャットと診断コンテキスト連携 / `ProposalRouter` | ✅ 完了 |
| P2 | 複数資産の管理・前回診断との履歴比較 / Markdown診断レポート出力・学習履歴の記録 | ✅ 完了 |

### 設計上の固定ライン（やらないこと）
- 攻撃・エクスプロイトのワーカーを実装しない
- AI に実行権限を委譲しない（autonomous L2+ 実行は仕様で禁止）
- 検知を「証明済み」と偽らない（CVE マッチは `verdict="detected", verified=False`）
- 非 Linux ホストでカーネル enforcement を「適用済み」と主張しない（偽の検証をしない）
- API キー等の資格情報をコード/ログに保存しない

詳細な要件定義は [REQUIREMENTS.md](REQUIREMENTS.md)、UI/UX詳細設計は [UI_UX_DESIGN.md](UI_UX_DESIGN.md) を参照。

