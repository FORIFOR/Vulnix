# 次の作業と再開手順

進捗の唯一の判定表は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリーは `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、最新コードコミット `4f1ac7b`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。`origin/main` は `5ecfc51`。再開時は `git rev-parse HEAD`、`git status --short --branch`、`git diff --check` を確認し、未コミット変更を保持する。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

直前コード`d1b7289`のバックエンド全1,700件成功・27件スキップ・ResourceWarning 0件（`/tmp/vulnix-pr85-d1b-full.log`、1189.994秒）。Web118件、Lintエラー0/警告5、ビルド成功。[Linux CI #44172152275](https://github.com/FORIFOR/Vulnix/actions/runs/44172152275)はPython・Web・実ARTEXの3/3成功。新コード`4f1ac7b`のローカル全1,727件成功・27件スキップ・ResourceWarning 0件（1206.795秒、`/tmp/vulnix-pr85-snapshot-status-full.log`）。[Linux CI #44178305443](https://github.com/FORIFOR/Vulnix/actions/runs/44178305443)はPython・Web・実ARTEXの3/3成功。正式GitHubレビューは0件。

## 次に実行する作業

1. `gh pr checks 85` と `git status --short --branch` で最新ヘッドのCIと作業ツリーを確認する。コード`4f1ac7b`の全件・Linux CI #44178305443、資料`d95bba8`のLinux CI #44184695350は3/3成功。残る保護GET・5,000件バックログの単発除名待ち0.0017秒を観測済み。厳密な遅延保証、残る保護GET、正式レビュー資料を追加監査する。
2. `aegis/server.py` のSSE大量履歴、残る保護GET、組織/管理者操作の失効境界を模擬環境で測る。変更した場合は関連テスト→全件→Linux CIを再実行する。今回の差分ではoverlayを変更していない。
3. [実モデル初回評価](ABLITERATION_SELECTION_REAL_RESULT.md)は承認済み1回を消費し、出力384トークンがすべて推論でJSON採用0/1。鍵は元ツリーの保護された設定から利用できた。出力上限1,024の未送信候補は別SHAでローカル検証済み。追加の有料送信は行わず、模擬テストと新しい明示承認後にのみ評価する。
4. 正式独立GitHubレビュー、採用可能な実モデル回答、実DNS、許可済み実サイトE2Eが揃うまで、公開βとGoalの完了判定を行わない。外部の必要条件は [BLOCKERS.md](BLOCKERS.md)。

新たな実サイト診断、有料API、DNS変更、mainマージ、本番反映は事前承認まで行わない。実サイトL2は禁止を維持する。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。
