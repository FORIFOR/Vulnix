# 診断状態の保存と、監査済みの読み取り API（PR-A）

2026-11-21。[DIAGNOSIS_UI_IMPLEMENTATION_PLAN.md](DIAGNOSIS_UI_IMPLEMENTATION_PLAN.md)（PR #99）の PR-A を実装したものです。**この PR は読み取りだけです。** 所有者の仕様の入力と、修正後の確認の開始は PR-C で行います。

## 1. 何を作ったか

| 項目 | 内容 |
| --- | --- |
| 診断状態の持ち主 | `AssessmentService.diagnosis_state()`。作業領域ごとに1つ、サービスが持ちます。ラボ以外（実サイト・所有確認中）では作れません。 |
| 変更の記録 | 状態を変える操作はすべて、**先に監査ログに書き、書けたときだけ反映**します（`diagnosis.*`、下の表）。書けなければ何も変わりません。 |
| 保存 | 変更のたびに `diagnosis.json`（権限 0600、fsync 後に置き換え）へ書きます。 |
| 再起動後の復元 | 監査ログだけから状態を組み立て直し、保存した状態と完全に一致したときだけ、**読み取り専用の履歴**として復元します。 |
| 表示 API | `GET /api/assessments/{id}/diagnosis`。表示のたびに、監査ログから組み立て直した状態と、今の状態を比べます。 |
| SSE | 状態が変わるたび、また計画の状態が変わるたびに、`diagnosis.updated` を送ります。中身は表示 API の返す内容と同じです。 |

### 監査ログに書く記録

| 記録 | 内容 |
| --- | --- |
| `diagnosis.opened` / `diagnosis.closed` | 診断状態の開始と終了（`diag_id`、終了の理由：`reset`、`replaced_after_restart`、`target_changed`） |
| `diagnosis.bound` | 実行世代とルート URL への結びつけ |
| `diagnosis.observed` | 観測（所有者の仕様は、入力した人 `recorded_by` も記録。計画者には渡しません） |
| `diagnosis.discarded` | 判定に使えなかった観測の破棄 |
| `diagnosis.generation` | 世代の開始と取り消し |
| `diagnosis.proposed` | 仮説の追加 |
| `diagnosis.applied` | 判定の反映（どの `diagnosis.judged` によるものか） |
| `diagnosis.restore_refused` | 再起動時に復元を拒否した理由 |

既存の `diagnosis.judged` には、`diag_id`・選んだ理由（契約の reason）・承認者・観測 ID を加えました。`adaptive_plan.transition` には、診断ループのときだけ `diag_id` と手順の上限を加えました。

## 2. 表示を拒否する条件

次のどれかに当たると、`status: "unverified"` と理由だけを返し、仮説・手順・観測は1件も返しません。推測で埋めることはしません。

| 理由 | 起きること |
| --- | --- |
| `audit_chain_invalid` | 監査ログのハッシュの鎖が壊れている |
| `state_audit_mismatch` | 今の状態（または保存した状態）が、監査ログから組み立て直した状態と一致しない |
| `journal_unreadable` | 監査ログの記録から状態を組み立てられない |
| `evidence_not_in_audit` | 観測が指す Worker の結果が、検証済みの監査ログにない |
| `judgement_not_in_audit` / `result_not_in_audit` / `observation_not_the_result` | 手順の判定・Worker の結果・観測の対応が、監査ログと合わない |
| `snapshot_missing` / `snapshot_unreadable` / `snapshot_mismatch` | 再起動時に、開いている診断の保存ファイルがない・読めない・別の診断のもの |

再起動時に拒否した場合は、新しい診断も始められません。作業領域のリセット（監査に記録されます）で解除します。

## 3. 返す内容

```json
{
  "schema_version": 1, "lab_only": true, "assessment_id": "scan_001",
  "status": "ok", "restored": false, "persisted": true,
  "diag_id": "dg_…", "generation": 2,
  "plan": {"plan_id": "ap_…", "state": "COMPLETED", "reason": "all_settled", "steps_used": 1, "steps_max": 3},
  "hypotheses": [{"id": "H2", "claim": "other_account_read", "target_ref": "T2", "state": "supported",
                  "purpose": "diagnose", "generation": 1, "supersedes": null,
                  "basis": ["E2"], "supporting": ["E5"], "contradicting": [], "inconclusive": []}],
  "steps": [{"plan_id": "ap_…", "step_id": "S2", "catalog_id": "l2_idor", "level": "L2", "hypothesis_id": "H2",
             "target_ref": "T2", "reason": "test_hypothesis", "evidence_refs": ["E2"],
             "approved_by": "approver-human", "generation": 1,
             "observation": {"evidence_id": "E5", "attrs": {"status": 200, "control": "established",
                                                          "reproduction": "proven"}},
             "judgement": {"from": "open", "to": "supported", "rule": "cross_account_read"},
             "result_audit_hash": "…", "judged_audit_hash": "…", "at": "2026-11-21T10:42:00Z"}],
  "evidence": [{"evidence_id": "E3", "kind": "owner_spec", "source": "owner_spec", "target_ref": "T2",
                "attrs": {"requirement": "authentication_required"}, "recorded_by": "owner-alice",
                "audit_hash": null, "journal_hash": "…"}],
  "fix_comparison": [{"hypothesis_id": "H4", "supersedes": "H2", "catalog_id": "l2_idor",
                      "before": {"generation": 1, "to": "supported", "rule": "cross_account_read", "judged_audit_hash": "…"},
                      "after": {"generation": 2, "to": "contradicted", "rule": "denied", "judged_audit_hash": "…"},
                      "result": "fixed"}],
  "next": {"kind": "plan_ended", "state": "COMPLETED", "reason": "all_settled"}
}
```

- **`next.kind`**：`approve_l2`（計画の実行中だけ）、`needs_spec`、`prepare_accounts`（所有者の対照が取れなかった）、`confirm_fix_available`、`plan_ended`、`check_audit`（表示を拒否した）、`none`。
- **含めないもの**：ARTEX の intent 本文、advisory、モデルの出力・トークン数・費用、Worker の生の応答本文、URL。観測の値は、短い単語と小さな整数だけに絞ります（計画者に渡すときと同じ規則）。計画の終了理由は、例外の文を落として ID だけにします（例：`planner_failed: …` → `planner_failed`）。
- 手順は古い順に返します。新しい順に並べるのは画面側です。

## 4. 経路と権限

- 組織の経路です。`_bind` で組織とメンバーかどうかを確かめ、`live_grant_roles` で返す直前に権限をもう一度確かめます。監査ログを読むので、`/logs` と同じく、アカウントのロックを持ったまま組み立てません。
- ログインしていなければ 401、他の組織のメンバーは 403（既存の経路と同じです。計画書では 404 としていましたが、組織の経路の既存の動作に合わせました）、実サイトと所有確認中の評価では 404 です。
- SSE は組織ごとのイベントの流れなので、他の組織の `diagnosis.updated` は届きません。

## 5. 再起動とリセット

- 再起動の後、`_run_generation` は 0 から数え直します。そのため、復元した履歴は**読み取り専用**にし（`frozen`）、実行器はこれを `state_from_another_run` で拒否します。次に診断を始めると、古い履歴は `diagnosis.closed`（`replaced_after_restart`）で閉じ、新しい状態を作ります。
- 作業領域のリセットでは、履歴を `diagnosis.closed`（`reset`）で閉じ、保存ファイルを消します。閉じた診断は、再起動しても復元しません。

## 6. 計画書との違いと、残っていること

- 修正の前後の比較（`fix_comparison`）には、所見の判定の変化（`f_idor: proven → not_reproduced`）を含めていません。所見は既存の評価の画面に出ているため、PR-B で並べて表示します。
- 監査ログは、秘密の鍵を使わないハッシュの鎖です。データディレクトリに書き込める人が、監査ログと保存ファイルの両方を矛盾なく作り直した場合は、検出できません（既存の監査ログと同じ前提です）。
- 所有者の仕様の入力と、修正後の確認の開始の経路は、PR-C で追加します。
- 監査ログへの書き込みと保存ファイルの書き込みの間でプロセスが落ちた場合も、再起動時には `state_audit_mismatch` か `snapshot_missing` として拒否します（安全側です）。改ざんとの区別はつかないため、監査ログで経緯を確かめてからリセットしてください。
- 状態が変わるたびに、監査ログ全体を読み直して SSE の内容を作ります。ラボの1回の診断は手順が最大10件なので問題になりませんが、監査ログが大きくなると遅くなります。表示 API は、サービスのロックを状態の写しを取る間だけ持ち、監査ログの読み込みはロックの外で行います（読み取りが緊急停止を待たせないようにするため）。

## 6.1 独立レビューで直した点

| # | 指摘 | 修正 | 回帰テスト |
| --- | --- | --- | --- |
| 1 | 監査に書けなかった判定の後始末（観測の破棄）も監査への書き込みになったため、それも失敗すると実行器が例外で抜け、計画が終わらない | 後始末の失敗は握りつぶし、計画は必ず FAILED などで終える（残った観測は監査済みで、仮説は動かさない） | `test_a_cleanup_that_cannot_be_journaled_still_ends_the_plan` |
| 2 | 表示 API が、サービスのロックを持ったまま監査ログ全体を読み、緊急停止を待たせうる | ロックは状態の写しを取る間だけ持つ。監査ログは、状態の最後の記録の位置で切って照合する（読む間の変更を不一致と誤判定しない） | `test_a_reader_does_not_hold_the_service_lock_while_reading_the_log`、`test_a_change_journaled_while_the_view_is_built_is_not_a_mismatch` |
| 3 | 反映した後の通知（保存・SSE）の失敗が、変更の失敗として返る。壊れた行があると 500 になる | 通知の失敗は変更の結果に影響させない。読めない行は `audit_chain_invalid` | `test_a_failed_notification_…`、`test_an_unreadable_log_line_is_a_broken_log` |
| 5 | リセットで `diagnosis.closed` を書けなくても、拒否が解除される | 監査に書けたときだけ解除する | `test_only_an_audited_close_clears_a_disputed_history` |
| 6 | L1 の手順で、依頼者が承認者として表示される | 承認者は L2 の人の承認だけ。L1 は `null` | `test_the_view_shows_audited_steps_…` |

1 と 2 のテストは、修正を戻すと失敗することを確かめました。4（落ちた場合の扱い）は上の注記のとおりです。

## 7. テスト

- `tests/test_diagnosis_read_api.py`：表示の内容、含めないもの、SSE、先に監査に書くこと、再起動後の復元、保存ファイルの改ざん・削除、監査ログの改ざん（鎖の破損と、鎖を作り直した書き換え）、メモリ上の状態の改ざん、リセット、権限の失効、実サイト、計画者の例外の文。
- `tests/test_tenancy.py::TestDiagnosisReadApiOverHttp`：ログインなし 401、他の組織 403（監査に記録）、メンバーからの削除とログアウトの後 401/403、実サイト 404、SSE が他の組織に届かないこと。
- `tests/test_diagnosis_state.py::TestJournal`：監査ログからの組み立て直しが今の状態と一致すること、記録に失敗した変更は起きないこと、復元した状態は変更できないこと。
