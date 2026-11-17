# 次の作業と再開手順

進捗の唯一の判定表は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリーは `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、最新コードコミット `d1b7289`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。`origin/main` は `5ecfc51`。再開時は `git rev-parse HEAD`、`git status --short --branch`、`git diff --check` を確認し、未コミット変更を保持する。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後の成功したコード全件は `f60f7fe` のバックエンド1,436件成功・27件スキップ・ResourceWarning 0件（`/tmp/vulnix-pr85-planner-send-f60-full.log`）。直前資料ヘッド`a985b8d`のLinux CI #44164211471は3/3成功。**これらは新コード`d1b7289`の証拠ではない。** 新コードのログアウト/除名競合の個別テスト、Ruff、Web118件、Lintエラー0/警告5、ビルドは成功。

## 次に実行する作業

1. 最新コードのバックエンド全件は `VULNIX_NO_ENV_LOCAL=1 PYTHONWARNINGS=always::ResourceWarning python3 -m unittest discover -s tests` で実行中。ログ `/tmp/vulnix-pr85-d1b-full.log` の末尾とプロセス終了状態を確認する。競合テストは `tests/test_tenancy.py`、単一組織は `tests/test_server.py`、L2文言は `tests/test_real_service.py`。
2. `gh pr checks 85` で最新ヘッドのLinux Python/Web/実ARTEXの3ジョブを確認。失敗時は原因を直して再実行する。今回の差分では overlay を変更していない。
3. `aegis/server.py` の保護GET、SSE、管理者・組織・自己アカウント変更のロック順を追加監査。重いレポート/ログ/映像用出力はロック外生成へ変更済み。大きなイベント履歴・巨大監査ログの実測と残る保護GETの失効境界を検証する。
4. 正式独立GitHubレビュー、実モデル、実DNS、許可済み実サイトE2Eが揃うまで、公開βとGoalの完了判定を行わない。外部の必要条件は [BLOCKERS.md](BLOCKERS.md)。

新たな実サイト診断、有料API、DNS変更、mainマージ、本番反映は事前承認まで行わない。実サイトL2は禁止を維持する。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。
