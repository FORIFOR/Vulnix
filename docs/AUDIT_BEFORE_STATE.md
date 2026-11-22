# 監査ログと状態変更の順序（セキュリティレビュー O5）

診断ループ（`aegis/diagnosis_ops.py`）と同じく、診断ループの外の状態変更も次の規則に従います。
テストは `tests/test_audit_before_state.py`（監査ログへの書き込みを1種類ずつ失敗させ、何が変わったかを確かめます）。

## 権限を与える・作業を始める変更：監査ログが先

監査ログに記録してから変更します。記録できなければ（ディスク、チェーン、アンカーの失敗）、何も変更せずにエラーを返します
（`AuditWriteFailed`。HTTP では 409 または 503、`applied: false`）。

| 操作 | イベント |
|---|---|
| 資産の登録（模擬ラボ） / 対象の切り替え | `asset.registered` / `asset.selected` |
| 実サービスの登録・所有確認の成功・診断範囲の確定 | `asset.challenge_issued` / `asset.ownership_verified` / `asset.scope_confirmed` |
| 検証用アカウントの保存 / L2 の依頼 / プロファイルの承認 | `secrets.configured` / `l2.run_requested` / `l2.profile_accepted` |
| 診断の開始・再診断・再開 | `assessment.start_requested` / `assessment.restarted` / `resume` |
| 承認（以前から監査ログが先） | `approval.approved` |
| 組織の招待の作成・受け入れ、組織ロールの付与 | `tenancy.invite_created` / `tenancy.invite_accepted` / `tenancy.member_roles_changed` |
| アカウントのロールの付与 | `operator.roles_changed` |

記録のあとで権限台帳や秘密情報の保存に失敗した場合は、変更は巻き戻り、`grant.not_committed` を記録します（できる範囲で）。

## 権限を減らす・作業を止める変更：監査ログの失敗で止めない

止めること・取り消すことが安全な方向なので、監査ログに書けなくても変更は必ず行います。そのうえで、記録できなかったことを
呼び出し元に返します（`AuditWriteFailed(applied=True)`、HTTP では 503 と `applied: true`）。

| 操作 | 失敗の伝え方 |
|---|---|
| 緊急停止（承認待ちの却下を含む） | 停止は完了。停止レポートは `confirmed: false`、`audit_incomplete: true` |
| 一時停止 / 承認の却下 | 状態は変更済み。エラーで報告 |
| 資産の削除 / 所有確認の失敗による取り消し | 権限は取り消し済み。エラーで報告（Worker の停止未確認がある場合はそちらを優先） |
| 組織メンバーの削除 / 招待の取り消し / ロールを減らすだけの変更 | 変更済み。503 と `applied: true` |

## 対象外（理由つき）

- 組織の作成（`tenancy.org_created`）：記録先が新しい組織の監査ログで、組織ができるまで存在しません。作成者に与えるのは空の組織のオーナーだけです。
- アカウントの登録・作成、ログイン、パスワード・二要素認証の変更、ロック解除（プラットフォーム監査ログ）：変更は `OperatorStore` の中で保存され、記録はそのあとです。今後の課題です。
- 診断の内部で使う承認参照（`approval_store.approve` のあとに `approval.approved`）：メモリ上だけの参照で、記録に失敗すると Worker を起動する前に処理が止まります。Worker の起動は Gateway の `allow` が監査ログを先に書きます。
- 模擬ラボのモード切り替え（`lab.mode_changed`）と CVE フィードの取り込み（`cve.synced`）：権限や対象を変えないため、記録は変更のあとのままです。
