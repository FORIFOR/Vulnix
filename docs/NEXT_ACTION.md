# 次の作業と再開手順

進捗の正本は [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md)。作業ツリーは `/Users/shuhei/Projects/Vulnix-integration-readiness`、ブランチ `codex/goal-integration-readiness`、今回のコードヘッド `6e0a4ab`、Draft PR [#85](https://github.com/FORIFOR/Vulnix/pull/85)。コミット直後の作業ツリーはclean。再開時は `git rev-parse HEAD`、`git status --short --branch` と `git diff --check` で照合する。未コミット変更を破棄しない。別ツリー `/Users/shuhei/Projects/Vulnix-access-control-blind-eval` の未コミット `docs/CORS_390_RESULT.png` も保持する。

最後に成功したローカル全件は `e3afa5d` のバックエンド1,410件成功・27件スキップ・ResourceWarning 0件（991.616秒）、ログは `/tmp/vulnix-pr85-head-e3afa-full.log`。Web118件成功、Lintエラー0・警告5、ビルド成功。[Linux CI #44129291316](https://github.com/FORIFOR/Vulnix/actions/runs/44129291316)はPython/Web/実ARTEXの3ジョブ成功。390pxの模擬ブラウザ再確認は8操作、API12回、対象GET2回、ページエラー0件。実行元表示は`unverified`であり実ARTEXのブラウザ証明ではない。

## 直近の順番

1. `gh pr checks 85` で`6e0a4ab`のLinux CIを確認する。ローカル全件は`VULNIX_NO_ENV_LOCAL=1 PYTHONWARNINGS=always::ResourceWarning python3 -m unittest discover -s tests`で1,427件成功・27件スキップ・ResourceWarning 0件（982.811秒）、ログは`/tmp/vulnix-pr85-ai-send-full.log`。Webの`npm test && npm run lint && npm run build`は118件成功、Lintエラー0・警告5、ビルド成功。
2. `6e0a4ab`は実サイト外部AI解説の送信前に生存権限・停止・所有確認範囲を再確認する。関連`tests.test_ai_advisor`62件と個別5件成功。ただし送信境界チェックとtransport開始の間に短いP2競合が残る。`aegis/ai_advisor.py`の送信開始、`aegis/assessment.py`の安全ゲート、`aegis/server.py`の停止・認可を調べ、緊急停止の応答性を落とさず直列化する設計を先にテストする。現状を安全完了として扱わない。
3. 次の承認不要項目はCORS・Cookie・情報露出の未知条件、未読累積差分の監査。必要なテストは先に書き、修正後に全件とCIを再確認する。
3. 390pxの模擬ブラウザは結果まで確認済み。SSE再接続・証拠ID付きレポート・組織切替・修正後再確認の過去の隔離確認と、公開βの実DNS・実モデル・実サイトE2Eを混同しない。
4. `VULNIX_ABLITERATION_KEY` は現在の作業環境にない。安全に利用可能となった場合だけ、承認済み固定14条件のSHA-256、モデル、匿名入力、1回・US$0.01・2,000トークン、監査・消費記録を照合し、1回実行する。

外部承認待ちは [BLOCKERS.md](BLOCKERS.md)。秘密ファイルを読まず、模擬テストには `VULNIX_NO_ENV_LOCAL=1` を付ける。実サイトL2は禁止する。mainマージ、本番反映、DNS変更、実サイト診断、新たな有料API呼び出しは事前承認まで行わない。
