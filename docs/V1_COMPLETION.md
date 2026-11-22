# Vulnix v1.0（認可ラボ版）完成判定表

2026-11-22。判定の対象は、統合ブランチ `claude/v1-integration` です。main `be3a945` に、PR #103〜#115 を依存関係の順に merge commit で取り込み、統合用の修正を2つ加えたものです（[V1_MERGE_PLAN.md](V1_MERGE_PLAN.md)）。

- **v1.0 の範囲**：登録済みの認可ラボで行う、AI セキュリティ診断の一連の流れです。診断の開始 → 所有者の仕様 → L1 → L2 の個別承認 → 仮説の支持・反証 → 所見 → 修正方法 → 修正後の確認 → レポート。
- **v1.0 から外したもの**：実サイトでの L2、外部の AI モデルとの比較、判定器の追加の研究、外部の監査アンカー（案B）。これらは v1.1 以降に回します（[BACKLOG_V1_1.md](BACKLOG_V1_1.md)）。

**判定の記号**

| 記号 | 意味 |
| --- | --- |
| ✅ 合格 | 証拠となるテスト・E2E・CI が成功している |
| ❌ 未合格 | 証拠がない、または失敗している |
| ⛔ 承認待ち | 所有者の承認がないと実施・完了できない |

## 1. 機能

| # | 要件 | 判定 | 証拠 |
| --- | --- | --- | --- |
| F1 | 認可ラボだけでの診断の開始（実サイトは 404） | ✅ | `tests/test_diagnosis_actions.py`、`TestDiagnosisActionsOverHttp.test_a_real_service_has_no_diagnosis_operations`、E2E `check_diagnosis_actions`（`real_site_404`） |
| F2 | 所有者の仕様（認証必須／公開の2択）を、監査ログに記録してから反映する。判定のあとの変更は、新しい世代が必要 | ✅ | `TestSpecChange`、`TestAuditFailure.test_a_spec_that_cannot_be_audited_changes_nothing` |
| F3 | L1 の検査、L2 の個別承認（手順ごとの nonce、承認は使い回さない） | ✅ | `TestStartSpecApproveFind`、`TestIdempotency.test_a_duplicate_approval_runs_one_worker`、E2E `check_first_run` |
| F4 | 仮説の支持・反証を、決まった判定規則で判定する。モデルの文は判定に使わない | ✅ | `tests/test_diagnosis_loop.py`、`tests/test_diagnosis_judge_owner_record.py`、`tests/test_judge_identity_match.py`、`tests/test_judge_api_envelopes.py` |
| F5 | 所見と修正方法（固定の手順） | ✅ | 既存のレポートのテスト、`tests/test_report_diagnosis.py` |
| F6 | 修正後の確認（新しい世代、初期観測からやり直す。過去の証拠と承認は使い回さない） | ✅ | `TestFixCheck.test_fix_check_new_generation_fresh_evidence_new_approval`、E2E（3本とも） |
| F7 | 診断レポート：何を・なぜ・判定の規則・修正の前後・判断できなかった項目・事実と AI の区別 | ✅ | `tests/test_report_diagnosis.py`（7件）、`tests/test_report_labels.py` |
| F8 | 初めての利用者が、新規登録から修正後の確認までを、画面の操作だけで終えられる | ✅ | E2E `scripts/check_first_run.py`（統合ブランチで ok。手順は、新規登録 → 開始 → 仕様 → L1 → 承認者の招待 → 390px での承認 → 所見とレポート → 修正後の確認） |
| F9 | 監査ハッシュから、証拠の記録を直接開く | ✅ | E2E `check_diagnosis_actions`（`step_opens_the_finding_evidence`） |

## 2. 安全性の最終確認

| # | 要件 | 判定 | 証拠 |
| --- | --- | --- | --- |
| S1 | 判断不能を「安全」と表示しない | ✅ | `tests/test_v1_no_false_safe.py`（文言、レポートの §5、未診断の表示、v4・v5 で「誤った安全判定0」）、`test_what_could_not_be_decided_is_listed_with_why` |
| S2 | 監査に失敗したら、結果を確定しない（「監査が先、反映は後」） | ✅ | 監査失敗のテスト13件。例：`test_a_judgement_that_cannot_be_audited_changes_nothing`、`test_a_request_that_cannot_be_audited_is_not_accepted` |
| S3 | 監査アンカーが有効なら、アンカーへの記録に失敗したとき、診断の変更や判定を確定しない | ✅ | `tests/test_audit_anchor.py`（`TestFindingVerdictEndToEnd`、`test_diagnosis_change_is_not_applied_without_the_anchor`） |
| S4 | 依頼者と L2 の承認者を分ける（画面・API・実行の3か所で確かめる） | ✅ | `test_the_requester_cannot_approve_their_own_l2_step`、`test_the_requester_cannot_approve_its_own_l2`、E2E（依頼者の承認は 403） |
| S5 | 権限：4つの権限を、サーバー側で、そのときの権限で確かめる。失効のあとは結果を返さない | ✅ | `TestPermissions`、`test_authority_lost_right_after_the_operation_withholds_the_result_and_never_reruns`、`test_the_approver_revoked_right_before_the_worker_starts_launches_nothing` |
| S6 | 組織の分離 | ✅ | `tests/test_tenancy.py`（診断の操作と表示を含む）、E2E（別の組織からは 403 で、状態は変わらない） |
| S7 | 緊急停止（承認待ち・Worker の実行中・修正後の確認の途中でも、結果を採用しない） | ✅ | 緊急停止のテスト16件。例：`test_an_emergency_stop_while_the_l2_worker_runs_adopts_nothing`、`test_after_an_emergency_stop_nothing_runs` |
| S8 | 二重送信・同時実行・再起動・強制終了でも、Worker を2回起動しない | ✅ | `TestIdempotency`、`TestCrashAtEachBoundary`、`TestRemainingRisks`（手動の ARTEX との排他） |
| S9 | Linux のカーネルによる隔離、緊急停止の確認（CI ではスキップしても失敗扱い） | ✅ | CI の Python ジョブの「Linux kernel confinement end to end」 |
| S10 | 監査アンカーを別のユーザーで動かす（Linux で実際に確認） | ✅ | CI run 44976944609 の「Local audit anchor as a separate OS user」：`AUDIT ANCHOR CI: OK`。サービス側から書けないこと、偽の補助プロセスを拒否すること、2ファイルの同時の巻き戻しとシンボリックリンクへの差し替えを検出することを確認 |
| S11 | 費用の上限 | ✅（範囲に注意） | `tests/test_spend_cap.py`、予算台帳。**アンカーで守っているのは組織ごとの予約額ファイル（`.advisor-budget`）だけ**です。プラットフォーム全体の `platform-advisor-spend.json` と `platform-audit.jsonl` は対象外です（[AUDIT_ANCHOR.md](AUDIT_ANCHOR.md)） |
| S12 | 実サイトへの通信がないこと（ラボへの通信だけ） | ✅ | E2E 3本とも、ラボへの通信は `/` と `/api/accounts/B/secret` だけ。評価では、外部への接続の試みが0件 |

## 3. 品質

| # | 要件 | 判定 | 証拠 |
| --- | --- | --- | --- |
| Q1 | アクセシビリティ（WCAG 2.1 A/AA、ライトとダーク、390px と 1280px） | ✅ | axe-core：E2E 3本の合計22画面で、重大な違反0件 |
| Q2 | スマートフォンでの表示 | ✅ | 390px で横にはみ出さない（E2E） |
| Q3 | 判定器の正確さ（判定器を凍結したあとの未見ケース v5、40件） | ✅（AI の2人の判定者まで） | 適合率 1.00、**再現率 0.65（95%CI 0.41〜0.83）**、誤検知0、誤った「安全」判定0（[HOLDOUT_V5.md](evaluation/HOLDOUT_V5.md)）。正解ラベルの人による署名は ⛔（下の A1） |
| Q4 | Python の全件、Web、Linux の隔離、実 ARTEX の CI | 確認中 | 統合ブランチで CI を実行中。手元の全件テストも実行中 |
| Q5 | 独立レビュー | ✅（AI による。人のレビューは ⛔） | 各 PR で実施し、重要な指摘はすべて修正した（各 PR の説明に記録） |

## 4. 承認待ち（v1.0 の判定に含めるもの）

| # | 内容 | v1.0 との関係 |
| --- | --- | --- |
| A1 | 未見ケースの正解ラベルの、人による確認と署名（v1〜v5） | Q3 の数値を「人が確認した」と言うために必要。署名がなくても、ラボ版の機能は動く |
| A2 | 人による正式なセキュリティレビュー（Gate D） | 公開の前に必要 |
| A3 | main へのマージ（[V1_MERGE_PLAN.md](V1_MERGE_PLAN.md) の順） | v1.0 を main として確定するために必要 |
| A4 | #93 の、公開済みの正解キーへの対処（[PR93_KEY_EXPOSURE.md](PR93_KEY_EXPOSURE.md)） | v1.0 の評価（v1〜v5）には影響しない。履歴の書き換えには承認が必要 |

## 5. 判定（2026-11-22 時点）

- **機能（F1〜F9）、安全性（S1〜S12）、品質（Q1〜Q3、Q5）は、すべて合格です。**
- Q4（統合ブランチの CI と全件テスト）は、結果を待っています。結果が出たら、この表を更新します。
- v1.0 を**完成と宣言するには、A3（main へのマージの承認）が必要です。** A1 と A2 は、公開や外部への説明の前に必要です。
