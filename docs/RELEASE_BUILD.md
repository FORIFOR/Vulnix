# Webリリース候補を組み立てる

`scripts/build-release-web.sh` は、macOS arm64で現在のGitコミットから非公開のサーバー用アーカイブとSBOMを作る。Node.js 22.23.5、ロック済みnpmパッケージを保持したローカルキャッシュ、[Next.js 16.4.5の公式ロック](https://github.com/vercel/next.js/blob/v16.4.5/pnpm-lock.yaml) が必要。スクリプトはロックのSHA-256を照合し、ビルドをネットワーク遮断下で実行する。

```sh
sh scripts/build-release-web.sh /path/to/next-upstream-pnpm-lock.yaml /path/to/private-output
```

`web/next.config.ts` のリリース設定は、公式のOutput File Tracingで対象ランタイムに不要なモジュールを除外する。Vulnixが使う静的画像経路を維持し、未使用のNext.js画像最適化は停止する。検査には本番と同じアーカイブを展開して用いる。起動時に `HOSTNAME=127.0.0.1` を指定し、公開プロキシの許可HostとループバックのAPI接続先を明示する。

公式CVE取得にはホストの `python3` と公式NVD・OSVへのHTTPS通信が必要。アーカイブ内の `catalog/public_catalog.py` を使うため、ソースツリーとの同居は不要。診断対象のコードと依存関係資料はブラウザ内で照合する。

出力の `source-sha.txt`、`build-inputs.sha256`、`build-runtime.txt`、`web.cdx.json` と `SHA256SUMS` が、ソース、依存、設定、ランタイム、SBOMと出来上がったアーカイブを対応付ける。SBOMは配備ツリーで確認できる名前付きマニフェストを対象とし、Next.jsのキャッシュやコンパイル済みバンドル内の全サブ依存を識別するものではない。検査報告は独立スキャナーの版とDBの日付を記し、同じアーカイブのハッシュにひも付ける。

生成されたNext.jsのサーバー専用鍵がアーカイブに入るため、出力ディレクトリは権限0700で作成する。成果物と作業ディレクトリは非公開で保管する。再ビルドで生成鍵やアーカイブのハッシュが変わる場合も、配備対象のSHA-256は検査済みアーカイブに一致させる。
