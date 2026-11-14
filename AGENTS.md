# AI 開発エージェント向けの指示

このリポジトリで作業する AI エージェント（Claude Code、Codex など）は、人の開発者と同じ [CONTRIBUTING.md](CONTRIBUTING.md) に加えて、次の点を守ってください。

## 絶対に守ること
- **実在するサービスに通信しない。** 診断・所有確認・L2 検証は、所有者が明示的に承認した対象に対してだけ行います。テストと検証は模擬ラボ（`lab.test`）で行います。
- **有料の外部 API（Abliteration AI など）を呼ばない。** 所有者の承認がない限り呼びません。テストでは `VULNIX_NO_ENV_LOCAL=1` を付け、同梱の模擬サーバーを使います。
- **秘密情報を読まない・表示しない・コミットしない。** 対象は `.env*`、`data*/` 配下、`*.key`、初期アカウントのファイルです。
- **安全制御を弱めない。** 所有確認、診断範囲、L2 の承認（依頼者と承認者の分離）、ARTEX と Worker の隔離、緊急停止、監査ログ、組織間の分離が対象です。必要と思われる場合は、実装せずに提案だけしてください。
- **AI の出力を信頼しない。** ARTEX・モデル・AI 解説の出力は、外から来たデータとして扱います。実行の権限は Gateway だけが持ちます。
- **ARTEX の overlay（`integrations/artex/overlay/`）を変えたら**、Linux CI の `artex-real-planner` ジョブが通ることを確認してください。

## 進め方
- 変更は小さな PR に分け、テストを先に書きます。
- 完了と報告する前に、次をすべて通します。
  - バックエンドのテスト（`python3 -m unittest discover -s tests`）
  - Web UI の `npm test`、`npm run lint`、`npm run build`
- 実行していない確認は「未確認」と書きます。
- `main` へのマージ、本番への公開、DNS の変更、課金を伴う操作は、所有者の承認を得てから行います。

## 構成の要点
[ARCHITECTURE.md](ARCHITECTURE.md) を参照してください。特に次の3点が重要です。
- 組織ごとのデータは `TenantRegistry` が返す、その組織の `AssessmentService` からしか読み書きしません。
- 組織に関わる API ルートは `aegis/server.py` の `_get_org` / `_dispatch` を通り、`_bind` がメンバーかどうかを確認します。プラットフォーム全体に関わるルートは `PLATFORM_POST_ROUTES` で区別しています。
- 新しいルートを追加したら、**他の組織のメンバーが読めない・操作できないこと**を `tests/test_tenancy.py` に追加してください。
