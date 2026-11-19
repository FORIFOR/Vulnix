# PR #85 権限失効の模擬ブラウザ確認

2026-11-19（JST）のローカル単発測定。`VULNIX_NO_ENV_LOCAL=1`、Next.js本番ビルド、Playwright Chromium、ループバックの模擬対象と模擬プランナーを使用した。実DNS・実サイト・実Abliteration AIの検証ではない。対象への通信は各条件に記したローカルGETだけ。

追加のログアウト競合検証では、既にHTTP 200となった`/api/auth/me`のJavaScript応答だけを保持し、ログアウト処理中は保護画面とログインフォームが見えないことを確認した。ログアウト完了後に旧200を解放しても、390px・1280pxともログイン画面のままで旧セッションは復活しなかった。両幅とも結果まで8操作、対象GET2回、ページエラー0、模擬プランナー・実モデル呼出し0。診断開始から可視所見まで0.915/0.910秒、追加の組織切替・設定画面・失効操作を含むAPI要求は35/37回。単発の約800ms観測窓であり、HTTP応答やSet-Cookie自体の到着順、別タブ同時操作を証明しない。出力は`/tmp/vulnix-pr85-stale-auth-390.json`と`/tmp/vulnix-pr85-stale-auth-1280.json`。

別タブは旧コードでログアウト後2秒を超えてもApache所見が表示された。既存の`SessionProvider`に同一オリジンのログアウト開始・成功・失敗通知を追加した後、390px/1280pxの2タブ模擬では所見が0.049/0.017秒で非表示となり、成功後の新規診断GETは401だった。失敗を模擬してログアウトPOSTをブラウザ側で遮断した390px条件では別タブに警告が出て認証を再照会し、GET200の有効なセッション表示へ戻った。16秒間POSTを送らずに保持した390px条件でも所見は再表示されず、解放後に401とログイン画面へ移った。開始通知後に2番目のタブを開いた旧コードは完了後2秒を超えても所見が残った。完了通知のIDが未登録でも保護表示を隠してサーバーへ再照会する修正後、390px/1280pxで0.029/0.025秒で非表示、新規GET401だった。開始通知だけを送って開始タブの消失を模擬した390px/1280px条件では、所見が0.025/0.001秒で消え、30秒後に再読み込み案内が表示された。利用者が再読み込みを選ぶと現行の有効な認証をサーバーへ再確認し、GET200の所見へ復帰した。最終コードの390px成功は0.013秒・通信遮断は0.053秒。別タブへの通知はブラウザの`storage`イベントに依存し、異なるブラウザ・端末間の即時同期は未検証。API13回は主タブが数えた要求で、別タブの初期取得と手動GETは含まない。単発ローカル測定のため遅延保証ではない。

```sh
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --org-switch --stale-auth-after-logout --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --org-switch --stale-auth-after-logout --viewport-width 1280
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-logout --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-logout --viewport-width 1280
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-logout-failure --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-logout --cross-tab-logout-delay-ms 16000 --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-start-only --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-start-only --viewport-width 1280
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-open-late --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --cross-tab-open-late --viewport-width 1280
```

最終コード`084fb44`でも代表経路を再実行した。390pxの結果画面ログアウトでは旧所見非表示0.126秒、結果まで8操作、模擬対象GET2回、ページエラー0。1280pxのレポート生成中失効では応答401、旧所見非表示7.885秒、模擬対象GET2回、ページエラー0。以下の全条件表は直前コード`f6608da`での単発測定値であり、今回再実行した2条件と区別する。

所有確認応答の修正後`5217969`では、390px・1280pxの通常経路を再実行した。両幅ともURL入力から結果表示まで8操作、API要求12回、模擬対象GET2回、ページエラー0。診断開始から所見表示は0.903秒/0.904秒。DNSはプロセス内置換、モデル呼出し0回であり、実DNS・公開βの確認ではない。

POST応答の失効修正後`bfdb8c9`では、両幅の通常経路が各8操作・API12回・模擬対象GET2回・ページエラー0、診断開始から可視所見まで0.924秒/0.926秒。追加の390px所有確認中失効はHTTP 401・証明保存なし・模擬対象GET0、1280pxレポート生成中失効はHTTP 401・旧所見非表示7.852秒・ページエラー0。いずれも単発・ループバック測定であり、旧測定との速度差を改善/悪化の一般値としない。

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

`e806ecf`の製品コードと本番ビルドを使用した通常経路の再測定では、390px/1280pxとも8操作・API12回・対象GET2回・ページエラー0件、診断開始から可視所見まで0.922/0.924秒だった。診断元の表示は`unverified`、実モデル呼出し0回。この再測定は失効ケースを再実行したものではなく、上記の失効ケースは`bfdb8c9`でのループバック証拠に限定する。実サイト・公開βの証拠ではない。
