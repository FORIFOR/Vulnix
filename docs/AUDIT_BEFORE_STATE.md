# 監査ログと状態変更の順序（セキュリティレビュー O5）

診断ループ（`aegis/diagnosis_ops.py`）と同じく、診断ループの外の状態変更も次の規則に従います。
テストは `tests/test_audit_before_state.py`（監査ログへの書き込みを1種類ずつ失敗させ、何が変わったかを確かめます）。

## 権限を与える・作業を始める・保護を弱める変更：監査ログが先

監査ログに記録してから変更します。記録できなければ（ディスク、チェーン、アンカーの失敗）、何も変更せずにエラーを返します
（`AuditWriteFailed`。HTTP では 503 と `applied: false`）。

| 操作 | イベント |
|---|---|
| 資産の登録（模擬ラボ） / 対象の切り替え | `asset.registered` / `asset.selected` |
| 実サービスの登録・所有確認の成功・診断範囲の確定 | `asset.challenge_issued` / `asset.ownership_verified` / `asset.scope_confirmed` |
| 名前の解決先が変わったときの新しいアドレスの受け入れ | `asset.addresses_reverified`（記録できなければ送信しない） |
| 検証用アカウントの保存 / L2 の依頼 / プロファイルの承認 | `secrets.configured` / `l2.run_requested` / `l2.profile_accepted` |
| 診断の開始・再診断・再開 | `assessment.start_requested` / `assessment.restarted` / `resume` |
| 承認（人の承認・診断内部の承認参照・自動承認・実モデル送信の承認） | `approval.approved` / `approval.auto` / `planner_llm.approved`（記録してから承認参照を作る・preview を使用済みにする） |
| 組織の作成・招待の作成と受け入れ・組織ロールの付与 | `tenancy.org_created`（プラットフォーム監査ログに先に記録し、作成後に組織の監査ログにも写す） / `tenancy.invite_created` / `tenancy.invite_accepted` / `tenancy.member_roles_changed` |
| アカウントのロールの付与 | `operator.roles_changed` |
| パスワードの変更 / 二要素認証の無効化 | `auth.password_changed` / `auth.mfa_disabled` |
| 管理者によるロック解除 / 二要素認証のリセット（他人のアカウントの保護を弱める） | `operator.unlocked` / `operator.mfa_reset` |

管理者による二要素認証のリセットは、認証情報を保存できない間に許される「権限を減らす操作」の例外から外しました（保護を弱める操作のため）。
**アカウントファイルを保存できない間は、管理者も他人の二要素認証をリセットできません**（安全側に止める。復旧の方法は、ディスク・書き込み権限を直すこと）。
管理者が他人のパスワードを設定する機能はありません。

アカウントの変更（二要素認証の無効化・リセット、ロールの付与）は、記録のあとでアカウントファイルを保存できなかった場合、
メモリ上でも元に戻します（`ChangeNotSaved`。サーバーはこのときだけ `grant.not_committed` を記録）。他の端末のログアウトとロールの削除は、
減らす方向なのでそのまま有効です。ロック解除はもともとファイルに保存しない（再起動で消える）ため、元に戻すものはありません。
パスワードの変更だけは元に戻しません：古いパスワードが知られている可能性があり、変更はアカウントを守る方向だからです。新しいパスワードは
次の再試行で保存され、それまでは誰もログインできません（`trusted()` が偽）。記録はそのまま有効です。

記録のあとで変更が成り立たなかった場合（権限台帳・秘密情報・組織情報・アカウント情報の保存の失敗、記録のあとでしか分からない拒否、
アンカーの更新の失敗）は、変更は行わず（巻き戻し）、`grant.not_committed`（アンカーの場合は `audit.record_not_anchored`）を記録します（できる範囲で）。
検証用アカウントは、保存できなかったときメモリ上でも元に戻します。

## 権限を減らす・作業を止める変更：監査ログの失敗で止めない

止めること・取り消すことが安全な方向なので、監査ログに書けなくても変更は必ず行います。そのうえで:

- 呼び出し元に返します（`AuditWriteFailed(applied=True)`、HTTP では 503 と `applied: true`。組織の権限の再確認を通してから返します）。
- **監査の欠落（audit gap）** として残します。データディレクトリの `audit-gaps.json` に保存され（再起動後も残る）、
  `snapshot` と `system_status` の `audit_gaps` に表示されます。次に監査ログへの記録が成功したとき
  （このサービスの監査ログが先の記録・取り消しの記録、組織の取り消しの記録）に、`audit.gap_recorded` として遅れて書き込み、欠落を消します。
- ディスクがいっぱいなどで `audit-gaps.json` にも保存できないときは、欠落を `persisted: false` として表示し、標準エラーに
  `AUDIT GAP NOT PERSISTED` を出します。読めない・壊れた・一覧でない `audit-gaps.json` は上書きせず `audit-gaps.json.corrupt-<時刻>` に移して
  `audit_gaps.corrupt` として表示します（移せない場合は以後このファイルに書き込みません）。`event` のない項目も捨てずに `audit_gaps.invalid_entry`（`invalid: true`）として残します。
- アカウントの操作（プラットフォーム監査ログ）の欠落は、既定の組織のサービスが持ちますが、組織の `snapshot` / `system_status` には出さず、
  プラットフォームの管理者が見る `/api/system/status` の `platform_audit_gaps` にだけ表示します。プラットフォーム監査ログへの記録が成功するたびに書き込みます。

| 操作 | 失敗の伝え方 |
|---|---|
| 緊急停止（承認待ちの却下を含む） | 停止は完了。停止レポートは `confirmed: false`、`audit_incomplete: true`。欠落として残す |
| 一時停止 / 承認の却下 | 状態は変更済み。503 と `applied: true`。欠落として残す |
| 資産の削除 / 所有確認の失敗による取り消し / アドレス変更による取り消し | 権限は取り消し済み。503 と `applied: true`（Worker の停止未確認がある場合はそちらを優先して返すが、欠落は残す） |
| 組織メンバーの削除 / 招待の取り消し / ロールを減らすだけの変更 | 変更済み。503 と `applied: true`。欠落として残す |

## 記録があとのままの操作（理由つき）

- ログイン、自己登録（`auth.registered`）、二要素認証の有効化：アカウントに新しい権限を与えない、または保護を強める操作です。
  自己登録の記録に失敗しても、応答は通常どおり返し（`audit_failed: true`）、欠落として残します。
- 模擬ラボのモード切り替え（`lab.mode_changed`）と CVE フィードの取り込み（`cve.synced`）：権限や対象を変えないため、記録は変更のあとのままです。
- 監査ログ自体の内部の記録（権限台帳のイベント、保存失敗の記録など）：できる範囲での記録です。
