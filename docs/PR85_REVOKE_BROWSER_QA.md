# PR #85 権限失効の模擬ブラウザ確認

2026-11-19（JST）のローカル単発測定。`VULNIX_NO_ENV_LOCAL=1`、Next.js本番ビルド、Playwright Chromium、ループバックの模擬対象と模擬プランナーを使用した。実DNS・実サイト・実Abliteration AIの検証ではない。対象への通信は各条件に記したローカルGETだけ。

| 条件 | 390px | 1280px | 確認した境界 |
| --- | --- | --- | --- |
| 結果画面からログアウト、SSE接続中 | 旧所見非表示0.122秒 | 0.115秒 | 新規の診断GETは401、再訪はログイン画面。ページエラー0 |
| 別組織へ切替後に旧診断・レポートへアクセス | 元の所見非表示、別組織のレポートは元の対象名・Apache所見を含まない | 同じ | 切替後の診断・レポートGETは別組織の内容。元組織を明示指定したアクセスは、同じアカウントがなおメンバーなら許可され得る |
| 診断中に実行者を組織から除名 | 元組織を明示した新規GETは403、観測1.681秒 | 403、1.695秒 | 画面に元組織の所見なし、ページエラー0。開始済み診断は組織の作業として進み、模擬対象GET2回。除名で診断が自動停止する保証はない |
| レポート生成中にセッション失効 | 応答401、旧所見非表示7.830秒 | 応答401、7.826秒 | レポート本文は送信せず、ページエラー0 |
| 所有確認のDNS照会中にセッション失効 | 応答401 | 応答401 | 証明保存なし、模擬対象GET0、完了表示なし、ページエラー0 |
| SSE接続の初回切断・再接続、後からセッション失効 | 再接続5回、旧所見非表示8.339秒 | 再接続5回、8.342秒 | レポート出力成功、ページエラー0。Cloudflare等の中継を含む遅延保証ではない |
| SSE再接続後、イベントを出さずに所見を更新 | 新所見へ23.898秒で収束 | 23.887秒 | 再接続2回、正式状態取得で古い所見を上書き。単発測定であり30秒以内の一般保証ではない |

再現コマンドの例（幅は`390`と`1280`をそれぞれ指定）:

```sh
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --reconnect-events --logout-after-result --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --org-switch --remove-member-during-scan --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --revoke-during-report --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --revoke-during-ownership --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --reconnect-events --report-export --org-switch --revoke-session --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --reconnect-events --silent-change --viewport-width 390
```

サーバー側で新たに見つけた停止応答の競合は`tests/test_tenancy.py`で修正前の200を再現した。`/pause`と`/emergency-stop`は失効後も安全停止を行うが、診断情報を含む応答だけを401/403に変更した。ブラウザのこの表は停止ボタンの競合そのものを実測したものではない。

残る範囲: 公開βの実DNS・所有確認・実サイトE2E、モデルを含む診断、Cloudflare中継でのSSE・失効遅延、重いレポートや長いWorkerにおける性能上限。失効後に開始済みの診断を自動停止すべきかは、組織の承認済み診断権限との関係を別途検討する。
