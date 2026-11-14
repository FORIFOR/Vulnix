# 開発環境の構築・起動・テスト

初めての方は、この手順で**模擬ラボ（ローカルの脆弱な練習用サイト）**に対して Vulnix を動かし、テストを通すところまで進められます。実在するサイトへの通信も、有料 API の利用も発生しません。

## 必要なもの
| 用途 | バージョン |
|---|---|
| Python | 3.12 以上（バックエンドは**標準ライブラリだけ**で動きます。pip でのインストールは不要です） |
| Node.js | 20 以上（Web UI） |
| macOS または Linux | Linux のカーネル隔離（L2 Worker・ARTEX）を試す場合は Linux が必要です。ほかの機能は macOS でも動きます |

## 1. 取得
```sh
git clone https://github.com/FORIFOR/Vulnix.git
cd Vulnix
(cd web && npm ci)
```

## 2. 起動（模擬ラボ・外部 AI なし）
ターミナルを2つ使います。
```sh
# ① コントロールプレーン（API）：模擬ラボ 127.0.0.1:18081 も一緒に起動します
VULNIX_NO_ENV_LOCAL=1 VULNIX_PUBLIC_SIGNUP=1 python3 -m aegis.server --port 8787 --data-dir ./data-dev

# ② Web UI
cd web && npm run dev     # → http://localhost:3000
```
- 初回起動時に、`./data-dev/operators.initial-credentials.txt`（パーミッション 0600）に管理者などの初期アカウントが作られます。
- `VULNIX_PUBLIC_SIGNUP=1` を付けると、画面の「新規アカウント登録」から自分のアカウントと組織を作れます。
- 外部 AI を使わずに AI 解説を試すときは、同梱の模擬サーバーを使います：
  ```sh
  python3 -c "from aegis.abliteration_server import start_abliteration_server as s; import time; s(18190); time.sleep(1e9)"
  # ①に追加: VULNIX_ABLITERATION_URL=http://127.0.0.1:18190/v1/chat/completions VULNIX_ABLITERATION_MODEL=mock
  ```
- `data-dev/` は `.gitignore` の対象です。秘密情報を含むため、コミットしないでください。

## 3. テスト
```sh
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests -p "test_*.py"   # バックエンド（約10分）
(cd web && npm test && npm run lint && npm run build)                        # Web UI
pip install ruff==0.6.9 && ruff check aegis tests                        # Python の静的チェック（CI と同じ）
```
- `VULNIX_NO_ENV_LOCAL=1` を付けると、手元の `.env.local`（実 API のキーなど）を読み込みません。**テストでは必ず付けてください。**
- Linux でしか動かないテスト（nftables・cgroup v2 による隔離）は、macOS では自動的にスキップされます。CI では必ず実行されます。

## 4. 設定
`.env.example` に、使える環境変数とその意味を書いています。必要なものだけを `.env.local`（Git の管理外・パーミッション 0600）にコピーしてください。

## 5. よく使う場所
| 何をしたいか | 場所 |
|---|---|
| API のルートを追加・変更する | `aegis/server.py`（組織ごとのルートは `_get_org` / `_dispatch`） |
| 診断の流れ・証拠・判定 | `aegis/assessment.py` |
| 組織・招待・役割 | `aegis/tenancy.py` |
| 実行の許可（Gateway） | `aegis/gateway.py`、`aegis/policy.py` |
| ARTEX との連携 | `aegis/artex_bridge.py`、`integrations/artex/` |
| AI 解説の表示前チェック | `aegis/chat_guard.py` |
| 画面 | `web/src/app/*`、`web/src/components/*` |

全体の構成は [ARCHITECTURE.md](ARCHITECTURE.md)、PR の出し方は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。
