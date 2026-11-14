# 公開β版（閲覧専用ページ）の公開手順

インターネットから閲覧できるのは、**紹介ページだけ**です。診断・ログイン・管理画面・API は公開しません。

## 構成
```
ブラウザ ──HTTPS──▶ Cloudflare Quick Tunnel ──▶ Mac 127.0.0.1:3100
                                                 Next.js（production build・VULNIX_PUBLIC_MODE=1）
```
- 3100 番のインスタンスが返すのは、`/`（紹介ページ）、`/_next/static/*`、`/media/*.{png,jpg,mp4}` だけです。
  - `/api/*` は、エンコードや `..` を使った書き方も含めて、すべて **404** を返します。
  - それ以外のページ（`/dashboard`、`/login` など）は `/` へ転送します（`web/src/proxy.ts`、`web/src/lib/publicMode.ts`）。
- 3100 番の API の転送先は、使われていないポート（`127.0.0.1:9`）にしてあります。上の関所が破られても、コントロールプレーンには届きません。
- 次のものはトンネルの外にあり、公開されません。
  - 運用者用の UI（3000 番）
  - コントロールプレーン（8787 番。もともとループバックの Host 名しか受け付けません）
  - Colima VM、ARTEX、Worker

## 起動・停止
```sh
scripts/public-beta.sh start    # 公開 URL（https://….trycloudflare.com）が表示されます
scripts/public-beta.sh status
scripts/public-beta.sh stop
```
- Quick Tunnel の URL は、起動するたびに変わります。固定のホスト名にするには、Cloudflare の名前付きトンネルと DNS の設定が必要です。DNS の変更には承認が必要です。
- Mac がスリープしたり、電源が切れたり、プロセスが止まったりすると、閲覧できなくなります。

## 再起動後の復旧
1. `scripts/public-beta.sh start` を実行します。ビルドが残っていれば、すぐに起動します。
2. 表示された新しい URL を共有し直します。

## 公開前の確認（実施済み・2026-11-14）
- 外部の URL 経由で、次を確認しました。
  - `/` が 200
  - `/api/auth/me`、`/api/health`、`/api/assets`、`POST /api/auth/login` が 404
  - `/dashboard`、`/login`、`/welcome` が `/` へ 307 転送
- 配信している HTML と JS に、API キー、内部 IP（127.0.0.1、8787、10.x、192.168.x）、ホスト名、診断結果、`AEGIS_API` の値が含まれていないことを確認しました。
- 動画と画面写真は、ローカルの模擬ラボで録画したものです。内部 IP や秘密情報が写っていない画像を選んでいます。

## まだ公開しないもの
一般ユーザーの登録と診断は、組織ごとのデータ分離・権限・所有確認の検証が終わるまで無効にしています。有効にするには所有者の承認が必要です。

---

# 公開β版（操作できるアプリ）

紹介ページとは別に、**登録・ログイン・組織・サイト管理・模擬ラボでの診断・L2 承認・診断履歴・AI 解説**を、インターネットから操作できます。

## 構成
```
ブラウザ ─HTTPS─▶ Cloudflare Quick Tunnel ─▶ Mac 127.0.0.1:3200（Next.js 本番ビルド・VULNIX_APP_LANDING=1）
                                                │  同一オリジン・CSRF・許可ホスト名・接続元 IP ごとの制限
                                                ▼
                                   VM 127.0.0.1:8788（コントロールプレーン・公開用）
                                   データ /var/lib/vulnix-public、ARTEX の DB は artex_planner_public
```
- **外から入れるのは 3200 番の Next.js だけです。** 次のものは公開しません。
  - コントロールプレーン（8788）
  - ARTEX、Worker、PostgreSQL
  - 開発用のバックエンド（8787）と、運用者用の UI（3000）
- コントロールプレーンは、ループバックの Host 名だけを受け付けます。また、組織分離が無効のときは公開を始めません（`scripts/public-app.sh` が確認します）。

## 公開時の設定（VM の `~/vmscripts/start_public.sh`）
| 設定 | 値 | 意味 |
|---|---|---|
| `VULNIX_PUBLIC_SIGNUP` | 1 | だれでも登録できます。登録した人には、その人だけの組織が作られます |
| `VULNIX_REAL_SERVICE_DIAGNOSIS` | l1 | **`l1`：所有確認が済んだサイトに限り、読み取り専用の診断（ページを1回取得して設定を調べる）だけを許可します。** 所有確認の実行は組織ごとに1時間20回まで。L2・ARTEX・修正後の再検証など、それ以外の操作は実在サイトでは拒否します。`0` にすると実在サイトへの通信をすべて拒否します（サイトの登録と確認用の値の発行まではできます） |
| `VULNIX_ARTEX_LLM_PLANS_PER_HOUR` | 0 | 実モデルを使う ARTEX の計画を無効にします（プレビューのみ） |
| `VULNIX_CHAT_PER_DAY` | 200 | AI 解説の1日あたりの上限（プラットフォーム全体） |
| `AEGIS_SEPARATE_L2_APPROVER` | 1 | 実在サイトの L2 は、依頼者と承認者が別の人である必要があります |
| （開発モード） | 無効 | 本番モードで動かします（ARTEX の SHA-256 固定と隔離が必須） |

利用制限の一覧は、ARCHITECTURE.md の「公開β版の利用制限」を参照してください。

## 起動・停止・状態の確認
```sh
# VM（公開用のコントロールプレーン）
colima ssh -p vulnix-artex -- sh ~/vmscripts/start_public.sh
colima ssh -p vulnix-artex -- sh -c 'kill $(cat /var/lib/vulnix-public/backend.pid)'

# Mac（公開アプリとトンネル）
scripts/public-app.sh start     # 公開 URL を表示します
scripts/public-app.sh status
scripts/public-app.sh stop
```

## 再起動後の復旧（Mac や VM を再起動したとき）
1. `colima start -p vulnix-artex` で VM を起動します。
2. `colima ssh -p vulnix-artex -- sh ~/vmscripts/start_public.sh` で公開用のコントロールプレーンを起動します。
3. `scripts/public-app.sh start` を実行し、新しく表示された URL を共有し直します（Quick Tunnel の URL は起動するたびに変わります）。

## 既知の制約
- **Quick Tunnel は、更新の受信（SSE）を途中で溜め込みます。** そのため画面は、受信が途切れているあいだ、4 秒ごとに状態を読み直します（表示が数秒遅れることがあります）。固定ドメインの名前付きトンネルを使えば、この制約はなくなります。
- Mac がスリープしたり停止したりすると、利用できなくなります。常時稼働させるには、別途ホスティングを検討する必要があります。
- 接続元 IP ごとの制限は、Next.js の入口で行っています（`CF-Connecting-IP` を使用）。プラットフォーム全体の上限を、ひとりが使い切れる問題については、SECURITY.md の「受け入れているリスク」を参照してください。
