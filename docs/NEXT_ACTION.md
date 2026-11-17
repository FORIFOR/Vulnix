# 次の作業と再開手順

進捗の正本は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリー `/Users/shuhei/Projects/Vulnix-integration-readiness` はブランチ `codex/goal-integration-readiness`、現在のコードコミット `4dfe137`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。開始時に `git status` を確認し、**未コミット変更を破棄しない。** 別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後に成功したゲートは、公開ヘッド `a75212b` のWeb・実ARTEX Linux CI 2ジョブ成功（Python実行中）、監査修正前のローカルバックエンド1,274件成功・27件スキップ、Web118件成功・Lintエラー0/警告5・ビルド成功。追加修正では所有確認関連435件、モデル経路関連116件、Gateway/監査関連88件、390px/1280pxブラウザ5条件が成功。**最新コードの全バックエンドテストとLinux CIは未確認。**

## 直近の順番

1. `git status --short --branch` と `git diff --check` を確認。`VULNIX_NO_ENV_LOCAL=1 PYTHONWARNINGS=always::ResourceWarning python3 -m unittest discover -s tests` の結果を確認する。直前の全件1,274件成功・27件スキップは `/tmp/vulnix-pr85-full-unittest.log` に記録。次の実行ログは `/tmp/vulnix-pr85-latest-unittest.log` で、監査破損修正と再確認ブラウザを取り込む前に開始されたため、成功しても最終差分のゲートとは扱わない。
2. `VULNIX_NO_ENV_LOCAL=1 python3 -m unittest tests.test_access_fresh_holdout tests.test_access_control_lab tests.test_access_holdout tests.test_initial_mixed_holdout` は21件成功済み。`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_access_fresh_holdout` も再測定済みで、観測選択TP2/FP0/FN0/TN2、対象GET8。
3. 最新コードで全バックエンドテスト、`web/` の `npm test`・`npm run lint`・`npm run build`、必要な実ブラウザ回帰を完了する。`ResourceWarning` が残る場合は発生源を分類して閉じる。
4. `docs/GOAL_COMPLETION_MATRIX.md`、`docs/AUTONOMOUS_PROGRESS.md`、`docs/BLOCKERS.md`、`docs/RELEASE_READINESS.md`、`docs/SECURITY_REVIEW.md` を実測と一致させてコミットする。最新ブランチを開発リモートへpushし、PR #85のLinux Python/Web/実ARTEX CIを最終コミットで確認する。CI失敗時は修正して再実行する。
5. PASS以外で承認不要の最重要項目へ進む。優先候補は未読累積差分の監査、CORS・Cookie・情報露出の新しいブラインド条件。修正後再確認の390pxブラウザ操作は `86a0ee7` で完了。実モデルの鍵が利用可能になった場合のみ、承認済み固定14条件1回をハッシュ・予算・消費記録を照合して実行する。

外部承認待ちは [BLOCKERS.md](BLOCKERS.md)。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。実サイトL2は禁止する。
