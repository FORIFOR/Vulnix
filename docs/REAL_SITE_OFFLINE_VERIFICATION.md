# 実サイト向けの、通信を伴わない部分の検証（ローカルの模擬環境）

2026-11-22、main `be3a945` で実施しました。**実サイトへの通信、DNS の変更、外部 LLM への送信は行っていません。** 名前解決、所有確認、範囲、同意、上限、緊急停止は、テスト内の模擬（解決器、模擬サーバー、時計）で確かめています。

## 実行したもの

```
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest -v tests.test_real_service tests.test_google_ownership \
  tests.test_fail_closed tests.test_release_safety tests.test_spend_cap
```

- 結果：**477件成功、失敗0件、スキップ10件**
- スキップした10件は、Linux カーネルの隔離（cgroup v2・nft・root）が必要なテストです。CI の「Python Suite + Linux」ジョブで実行され、そこではスキップ自体が失敗扱いになります（`ci.yml` の「Linux kernel confinement end to end」）。
- 組織ごとの上限は、`tests/test_tenancy.py` で確かめています（下の表）。

## 要件と、それを確かめているテスト

| 要件 | 成功したテストの数（名前で分類） | 代表的なテスト |
| --- | --- | --- |
| 所有確認（DNS、`.well-known`、Google） | 50 | `test_ownership_expiry_at_final_result_adoption_fails_closed`、`test_inconclusive_rerun_keeps_an_earlier_proof_and_its_risk` |
| 診断範囲と有効期限 | 33 | `test_scope_window_expiry_stops_resolution`、`test_late_scope_reconfirmation_cannot_upgrade_existing_run` |
| 署名付きの同意（追加の GET は別の同意が必要） | 21 | `test_second_fixed_get_requires_separate_signed_consent`、`test_concurrent_read_only_requests_share_one_signed_allowance` |
| 上限（費用、実行の回数） | 10＋組織ごと | `test_spend_cap`、`test_real_site_runs_are_capped_per_org`、`test_ownership_checks_are_rate_limited_per_org`（tenancy） |
| 緊急停止と、停止を確認できないときの遮断 | 29 | `test_scope_window_expiry_stops_resolution`、`test_insufficient_conditions_are_unverified_and_stop_before_the_cross_account_request` |
| 実サイトで L2 を実行しない | 8 | `test_bulk_verify_never_runs_l2_on_a_real_service`、`test_l1_run_is_read_only_and_leaves_l2_as_unmeasured_candidates` |
| 名前解決の固定、内部アドレスの拒否、リダイレクト | 4 | `test_private_address_blocked_and_failed_reverification_revokes_scope`、`test_not_configured_without_an_https_redirect` |
| ログアウトや組織からの除外による権限の失効 | 142 | `test_initial_plan_revocation_does_not_complete`、`test_approver_revocation_after_binding_cannot_read_planner_preview` |
| 診断ループ（PR-C）を実サイトで使えないこと | — | `TestDiagnosisActionsOverHttp.test_a_real_service_has_no_diagnosis_operations`（404） |

分類は、テストの名前に含まれる語で機械的に数えたものです。1つのテストが複数の行に数えられていることがあります。

## まだ確かめていないこと（承認が必要）

- 実際の DNS を使った所有確認と、実サイトでの L1 の通し実行は、まだ1回も行っていません（Gate E・F）。対象サイトと実行についての承認が必要です。
- 公開βのサーバーでの設定の照合（`VULNIX_REAL_SERVICE_DIAGNOSIS=l1`）も、まだ行っていません。
- 実サイトでの L2 は禁止しています。有効にするには、別の安全審査と個別の承認が必要です。
