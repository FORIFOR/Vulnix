# 次の作業と再開手順

進捗の正本は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリーは `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、コードヘッド `ae40576`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。開始時に `git status --short --branch` と `git diff --check` を確認し、未コミット変更を破棄しない。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後に成功したローカル全件は `50dcaae` のバックエンド1,375件成功・27件スキップ・ResourceWarning 0件（958.696秒）、ログは `/tmp/vulnix-pr85-head-50dc-full.log`。`27cd18c` の関連 `tests.test_real_service tests.test_artex_bridge tests.test_gateway` は215件成功・17件スキップ。Web118件成功、Lintエラー0・警告5、ビルド成功、Linux実ARTEXジョブ成功。`ae40576`の隔離関連10件も成功。最新全バックエンドは `/tmp/vulnix-pr85-head-ae405-full.log` で実行中。最終CIは未確認。

## 直近の順番

1. 最新全件ログ `/tmp/vulnix-pr85-head-ae405-full.log` と `gh pr checks 85` を確認する。失敗があれば原因を修正する。旧Linux実ARTEXの3件は`27cd18c`で修正され同ジョブ成功。
2. `web/` の `npm test`、`npm run lint`、`npm run build` はローカル成功。Linux CIと同じ最終コミットで3ジョブ成功を確認する。
3. `docs/GOAL_COMPLETION_MATRIX.md` を実測に更新し、`AUTONOMOUS_PROGRESS.md`、`BLOCKERS.md`、`RELEASE_READINESS.md`、`SECURITY_REVIEW.md` も整合させる。PR #85の説明にも未完了ゲートを反映する。
4. 承認不要の次項目は、実Gateway/Workerとログアウトの同時隔離E2E、モデル送信直前の権限競合、CORS・Cookie・情報露出の未知条件、未読累積差分の監査。必要なテストは先に書き、修正後に全件とCIを再確認する。
5. `VULNIX_ABLITERATION_KEY` は現在の作業環境にない。安全に利用可能となった場合だけ、承認済み固定14条件のSHA-256、モデル、匿名入力、1回・US$0.01・2,000トークン、監査・消費記録を照合し、1回実行する。

外部承認待ちは [BLOCKERS.md](BLOCKERS.md)。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。実サイトL2は禁止する。mainマージ、本番反映、DNS変更、実サイト診断、新たな有料API呼び出しは事前承認まで行わない。
