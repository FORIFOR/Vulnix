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
