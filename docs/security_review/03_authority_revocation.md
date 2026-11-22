# (c) 要求時点の権限と失効

## 設計（要約）

1. HTTP の入口では、`_bind` の時点の役割（スナップショット）に加えて、`_dispatch` の入口で現在のセッションと組織の役割を読み直します（`aegis/server.py:1237-1258`）。
2. 長く続く処理には、関数 `live_request_authority(sess, org, approver=...)` を渡します（`aegis/server.py:220-239`）。これは呼ぶたびに `live_grant_roles`（アカウント → 組織の順にロックを取り、現在の役割を確かめる。`:189-208`）を短く取り直します。`.lease()` は、Worker の起動の間だけ両方のリースを持ち続けるためのものです。
3. Gateway は Worker を起動する直前に `late_launch_guard`（`AssessmentService._late_launch_guard`、`aegis/assessment.py:1210-1215`）を呼びます。`WorkerPool.run` は、そのリースを持ったまま `Popen` を登録します（`aegis/runtime.py:130-153`）。ログアウトや除名は、登録が終わるまで待ちます（`aegis/grant_lease.py:54-71`）。
4. Worker が終わった後、結果を採用する前に、依頼者の権限をもう一度確かめます。失効していれば `result.discarded` を記録して捨てます（`aegis/assessment.py:5080-5085`）。
5. 診断ループ（`AdaptivePlanRunner`）は、各手順の前後で、停止・リセット・一時停止・依頼者の権限・期限を確かめます（`aegis/adaptive_plan_runner.py:108-118`, `:325-345`）。
6. L2 の承認は、手順ごとに1回限りの nonce に結び付けます（`aegis/diagnosis_ops.py:518-566`）。承認の API は、依頼者本人を 403 `self_approval` で拒否します（`:631-637`）。承認を監査に記録してから、ループに渡します（`:640-650`）。
7. 承認された1手順の Worker には `_step_authority` を渡します（`aegis/diagnosis_ops.py:568-607`）。依頼者と承認者の両方のセッション・所属、承認者の approver 役割、依頼者≠承認者、nonce・項目・診断・世代・実行世代、承認の期限（既定300秒）、ループが実行権（`_exec_owner`）を持っていること、停止中でないことを確かめます。起動の間は両者のリースを持ちます（`:595-604`）。
8. 応答を返す直前に、操作の権限をもう一度確かめます。失効していれば、受け付け済みかどうか（`committed`）だけを返し、ジョブ・項目・証拠は返しません（`aegis/server.py:373-397`）。
9. 手動の ARTEX 実行と診断ループは、`_exec_owner` という1つの実行権をサービスのロックの下で取り合います（`aegis/assessment.py:2652-2663`, `aegis/diagnosis_ops.py:335-338`）。

## 主なコードの場所

| 内容 | 場所 |
|---|---|
| 現在の権限の確認とリース | `aegis/server.py:189-239` |
| `_dispatch` 入口の再確認 | `aegis/server.py:1237-1258` |
| 応答時の再確認 | `aegis/server.py:357-371`（`_authorized_org_read`）、`:373-397`（`_deliver_diagnosis_op`）、`:399-412`（`_authorized_platform_read`） |
| 診断操作のルート | `aegis/server.py:1528-1541` |
| Worker 起動直前 | `aegis/assessment.py:1210-1250`（`_late_launch_guard`, `_launch_guard`）、`aegis/gateway.py:288-314`、`aegis/runtime.py:130-153` |
| 結果の破棄 | `aegis/assessment.py:5080-5085` |
| 承認・手順ごとの権限 | `aegis/diagnosis_ops.py:518-652` |
| 手動の ARTEX の L2（approver 役割、条件付きの依頼者≠承認者） | `aegis/assessment.py:2664-2725` |
| 旧来の実行の承認（`/approvals/{id}`） | `aegis/server.py:1603-1609`, `aegis/assessment.py:3980-3988`, `:5247-5266` |

## 証拠となるテスト

| テスト | 確かめていること |
|---|---|
| `tests/test_diagnosis_actions.py::TestPermissionChecks::test_the_requester_cannot_approve_their_own_l2_step` | 依頼者の承認は 403 |
| `tests/test_diagnosis_loop.py` と `tests/test_adaptive_plan_runner.py` の `test_the_requester_cannot_approve_its_own_l2` | ループの層でも依頼者は承認できない |
| `tests/test_diagnosis_actions.py::TestRemainingRisks::test_the_approver_revoked_right_before_the_worker_starts_launches_nothing` | 起動直前の確認の中で承認者を失効させると、Worker は起動しない |
| `…::TestRemainingRisks::test_an_expired_approval_launches_nothing` | 期限切れの承認では起動しない |
| `…::TestRemainingRisks::test_a_manual_artex_run_cannot_take_a_step_the_loop_holds`, `test_a_manual_run_checked_before_the_loop_started_is_refused_at_its_claim`, `test_a_running_manual_item_keeps_the_loop_from_starting` | 実行権の取り合い |
| `…::TestStopAndRoleChangeDuringTheWorker::test_the_approver_losing_the_role_while_the_worker_runs_discards_its_result` | 実行中に承認者が役割を失うと結果を捨てる |
| `tests/test_diagnosis_loop.py::…::test_revocation_while_the_worker_runs_discards_the_result` | 実行中に依頼者が失効すると結果を捨てる |
| `tests/test_tenancy.py::TestDiagnosisActionsOverHttp::test_authority_lost_right_after_the_operation_withholds_the_result_and_never_reruns` | 操作の保存直後・応答前に除名すると、結果を返さず、再送でも再実行しない |
| `…::TestDiagnosisActionsOverHttp::test_the_start_route_hands_over_the_live_authority` | ルートが生きた権限の関数を渡し、ログアウト後は偽になる |
| `tests/test_tenancy.py::TestTenantIsolationOverHttp::test_logout_before_gateway_worker_launch_starts_no_process`, `test_logout_waits_for_gateway_worker_launch_registration` | 実 Gateway/Worker とログアウトの競合（起動前の失効は Popen 0、登録中のログアウトは待つ） |
| `…::test_long_plan_receives_live_request_authority`, `test_foreground_worker_routes_receive_live_request_authority`, `test_logout_cannot_pass_between_authorization_and_scan_start` | 長い処理への受け渡し、開始との直列化 |
| `tests/test_gateway.py::TestLateWorkerAuthority` | Gateway の起動直前の確認 |
| `tests/test_fail_closed.py::TestRequestsThatOutliveTheirAuthority` | 権限より長生きする要求 |
| `tests/test_attack_regressions.py::TestL2ApprovalFromTheInside::test_an_approver_whose_role_is_revoked_mid_session_cannot_run_or_configure` | セッションの途中で approver を外すと実行・設定できない |
| E2E `scripts/check_diagnosis_actions.py` | 依頼者の承認は 403（画面にボタンなし）、同じキーの再送は `replayed` で Worker 1回 |

## 既知の制限（文書に記載済み）

- 最後の確認から実際の `Popen`・モデルへの送信までに短い競合窓が残ります（`docs/SECURITY_REVIEW.md` 124行・138-142行）。`Popen` の登録はリースの中ですが、Worker がすでに送った通信は取り消せません。
- 承認を取り消す専用の操作はありません。実行中の手順を止める手段は緊急停止です（`docs/DIAGNOSIS_ACTIONS.md` §9）。
- 期限切れの判定は、評価を読み書きしたときに行います（同 §9）。
- 開始済みのプラットフォーム共通ジョブ（`/api/system/verify-controls` など）は、失効しても取り消しません。応答を返さないだけです（`docs/SECURITY_REVIEW.md` 53行）。

## コードを読んで気づいた点（要確認。脆弱性とは断定していません）

1. **手動の ARTEX と旧来の実行では、依頼者≠承認者が条件付き**です。手動の ARTEX 計画の L2 項目は、`separate_l2_approver` が真のときだけ依頼者本人を拒否します（`aegis/assessment.py:2700-2703`）。この値は `AEGIS_SEPARATE_L2_APPROVER=1` か `--separate-l2-approver` のときだけ真です（`aegis/assessment.py:353-355`, `aegis/server.py:1745-1746`）。既定では、組織の owner（サービスの operator と approver を両方持つ、`aegis/tenancy.py:42`）が、自分で計画し、自分で L2 を実行できます。旧来の実行の承認（`/approvals/{id}`、`aegis/server.py:1603-1609` → `aegis/assessment.py:3980-3988`）には、依頼者との比較がありません。`tests/test_server.py::TestServer::test_l2_waits_for_human_and_stop_kills_worker` では、同じアカウント `appr` が開始と承認を行っています。`docs/DIAGNOSIS_ACTIONS.md` §1 は「既存の `execute_artex_item`（計画を依頼した本人は承認できない）」と書いていますが、コードでは条件付きです。対象はどちらも登録済みラボだけです（実サイトの L2 は無効）。
2. **自己登録アカウントによる承認**：診断ループの承認 API で自己登録アカウントを拒否するのも、`separate_l2_approver` が真のときだけです（`aegis/server.py:1533-1535`）。依頼者≠承認者の比較はアカウント名だけです（`aegis/diagnosis_ops.py:582`, `:631`）。公開登録が有効なら、1人が2つ目のアカウントを作り、招待して approver にすれば、分離を満たせます（`docs/PUBLIC_BETA.md` 71行は公開β版で `AEGIS_SEPARATE_L2_APPROVER=1` を設定する前提です）。

## 試してほしいこと

1. **起動直前の窓**：`_step_authority.allowed()`（`aegis/diagnosis_ops.py:578-593`）がロックを離した後、`lease()` の中で再確認するまでの間（`:595-604`）に、承認の差し替え・世代の更新・緊急停止を挟めないか。
2. **応答の秘匿**：`_deliver_diagnosis_op`（`aegis/server.py:373-397`）以外の POST 応答で、失効後にスナップショットや証拠が返る経路がないか。特に `/start`・`/resume` の既定の応答（`aegis/server.py:1633-1638`）と例外経路（`:1619-1635`）。
3. **再送（Idempotency-Key）**：同じキーで、別のアカウント・別の組織から送ったとき、保存した結果が返らないか。指紋は操作・送り手・本文から作ります（`aegis/diagnosis_ops.py:79-82`, `:256-301`）。キー空間は組織（サービス）ごとです。
4. **承認の流用**：nonce・項目 ID・世代を変えて、前の世代の承認や他の項目の承認で Worker を起動できないか（`aegis/diagnosis_ops.py:518-566`）。
5. **結果の取り違え**：`_exec` は Worker の後、監査ログの**最後の** `result` 記録を、その実行の記録として使います（`aegis/assessment.py:5097`）。同じ組織で2つの Worker（例：診断ループと `/verify-finding`）が並行したときに、別の実行の `result` を所見の証拠に結び付けられないか。
6. 上の「気づいた点」1・2 が、意図した設計か、修正すべきものかの判断。
