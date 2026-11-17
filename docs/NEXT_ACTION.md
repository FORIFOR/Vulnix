# 次の作業と再開手順

進捗の正本は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリーは `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、既知のコード基点 `ae40576`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。最新コミットは開始時に `git rev-parse HEAD` で照合し、`git status --short --branch` と `git diff --check` も確認する。未コミット変更を破棄しない。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後に成功したローカル全件はコード `ae40576` のバックエンド1,384件成功・27件スキップ・ResourceWarning 0件（953.678秒）、ログは `/tmp/vulnix-pr85-head-ae405-full.log`。Web118件成功、Lintエラー0・警告5、ビルド成功。資料 `eca36b3` の[Linux CI #44121761288](https://github.com/FORIFOR/Vulnix/actions/runs/44121761288)はPython/Web/実ARTEXの3ジョブ成功。390pxの模擬ブラウザ再確認は8操作、API12回、対象GET2回、ページエラー0件。実行元表示は`unverified`であり実ARTEXのブラウザ証明ではない。

## 直近の順番

1. HTTPログアウトと実Gateway/Workerの競合2件を追加した差分について、`VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests` と `gh pr checks 85` を最終コミットで確認する。関連`tests.test_tenancy tests.test_gateway`275件と最新個別2件は成功。資料`abd1fc2`のLinux Python失敗はGitHub runner停止信号によるキャンセルで、テスト失敗ではない。
2. 承認不要の次項目は、モデル送信直前の権限競合、CORS・Cookie・情報露出の未知条件、未読累積差分の監査。必要なテストは先に書き、修正後に全件とCIを再確認する。
3. 390pxの模擬ブラウザは結果まで確認済み。SSE再接続・証拠ID付きレポート・組織切替・修正後再確認の過去の隔離確認と、公開βの実DNS・実モデル・実サイトE2Eを混同しない。
5. `VULNIX_ABLITERATION_KEY` は現在の作業環境にない。安全に利用可能となった場合だけ、承認済み固定14条件のSHA-256、モデル、匿名入力、1回・US$0.01・2,000トークン、監査・消費記録を照合し、1回実行する。

外部承認待ちは [BLOCKERS.md](BLOCKERS.md)。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。実サイトL2は禁止する。mainマージ、本番反映、DNS変更、実サイト診断、新たな有料API呼び出しは事前承認まで行わない。
