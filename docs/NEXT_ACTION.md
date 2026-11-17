# 次の作業と再開手順

進捗の正本は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリー `/Users/shuhei/Projects/Vulnix-integration-readiness` はブランチ `codex/goal-integration-readiness`、現在のコードコミット `50dcaae`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。開始時に `git status` を確認し、**未コミット変更を破棄しない。** 現在このツリーには進捗資料6ファイルの未コミット変更がある。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後に成功したローカル全件は `f85b3b5` のバックエンド1,372件成功・27件スキップ・ResourceWarning 0件（959.455秒）。同じコードのLinux CI #44105345262は3/3成功。`50dcaae` の個別4件と関連324件は成功し、同じコミットの全件は `/tmp/vulnix-pr85-head-50dc-full.log`、Linux CI #44112452006で進行中。**このコミットの全件・CIは未確認。**

## 直近の順番

1. `git status --short --branch` と `git diff --check` を確認。`50dcaae` の全件 `/tmp/vulnix-pr85-head-50dc-full.log` と[Linux CI #44112452006](https://github.com/FORIFOR/Vulnix/actions/runs/44112452006)を確認する。前の `f85b3b5` の全件成功は `/tmp/vulnix-pr85-head-f85-full.log` に記録済み。
2. `VULNIX_NO_ENV_LOCAL=1 python3 -m unittest tests.test_access_fresh_holdout tests.test_access_control_lab tests.test_access_holdout tests.test_initial_mixed_holdout` は21件成功済み。`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_access_fresh_holdout` も再測定済みで、観測選択TP2/FP0/FN0/TN2、対象GET8。
3. 最新コードで全バックエンドテスト、`web/` の `npm test`・`npm run lint`・`npm run build`、必要な実ブラウザ回帰を完了する。`ResourceWarning` が残る場合は発生源を分類して閉じる。
4. `docs/GOAL_COMPLETION_MATRIX.md`、`docs/AUTONOMOUS_PROGRESS.md`、`docs/BLOCKERS.md`、`docs/RELEASE_READINESS.md`、`docs/SECURITY_REVIEW.md` を実測と一致させてコミットする。最新ブランチを開発リモートへpushし、PR #85のLinux Python/Web/実ARTEX CIを最終コミットで確認する。CI失敗時は修正して再実行する。
5. PASS以外で承認不要の最重要項目へ進む。前景Workerの認可leaseは `50dcaae` で追加済み。実Gateway/Workerとログアウトを同時に動かす隔離E2E、モデル転送直前の競合、CORS・Cookie・情報露出の未知条件、未読累積差分の監査へ進む。実モデルの鍵が利用可能な場合のみ、承認済み固定14条件1回をハッシュ・予算・消費記録を照合して実行する。

外部承認待ちは [BLOCKERS.md](BLOCKERS.md)。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。実サイトL2は禁止する。
