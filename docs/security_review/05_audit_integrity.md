# (e) 監査の完全性

## 設計（要約）

1. 監査ログ（`audit.jsonl`、組織ごとに別ファイル）は、1行1記録の SHA-256 ハッシュチェーンです。各記録は `{ts, event, fields, prev}` を正規化した JSON のハッシュを持ちます（`aegis/audit.py:21`, `:85-119`, `:311-312`）。**鍵は使いません**（HMAC ではない）。ファイルを書き換えられる者は、チェーン全体を作り直せます。
2. 書き込みは、プロセス内のロックとファイルの `flock`（排他）の下で行います。同じデータディレクトリを使う複数のサービスオブジェクトの間でも、検証・予算計算・追記をひとまとまりにします（`aegis/audit.py:64-83`）。`flock` がなければ `AuditLog` を作りません（`:41-42`）。
3. Worker の許可（`allow`）と有料送信（`planner_llm.forwarding`）の前、またはファイルが外から変わったときは、ログ全体のチェーンを検証し、このオブジェクトが前に書いた末尾が残っていること（切り戻しでないこと）を確かめます（`aegis/audit.py:88-103`, `:292-294`）。
4. **監査が先、反映は後**：診断ループの状態変更は、監査に書けたときだけ反映します（`aegis/diagnosis_state.py:105-121`、`aegis/assessment.py:1844-1850`）。診断の操作の要求も、監査 → 要求ファイル、の順です（`aegis/diagnosis_ops.py:274-279`）。L2 の承認は、承認の記録を書いてから「承認済み」にします（`aegis/assessment.py:5250-5258`）。Gateway は `allow` を書いてから Worker を起動し、`result` を書いてから結果を返します（`aegis/gateway.py:282-283`, `:394-396`）。
5. 有料の外部送信の予約は、累積額を別ファイル `audit.jsonl.advisor-budget`（0600、原子的な置き換え）に**先に**書き、ログの合計と一致しなければ拒否します（`aegis/audit.py:204-272`）。単独の JSONL の切り戻しは、これで検出します。
6. **ローカル監査アンカー（任意）**：サービスとは別の OS ユーザーで動く補助プロセスが、記録元ごとの先頭（件数とハッシュ）を、自分だけが書ける追記専用ファイル（それ自体もハッシュチェーン）に残します（`aegis/audit_anchor.py:81-253`）。サービスは Unix ソケットで `head` と `anchor` だけを頼めます（`:255-282`）。補助プロセスは先頭の後退（`rollback`）と同じ位置での別ハッシュ（`fork`）を拒否します（`:228-243`）。
7. アンカーが有効なとき、重要な記録（`allow`、`planner_llm.forwarding`、`advisor.safe_send_requested`、`result`、`approval.approved`、`artex.item_approved`、`diagnosis.*`。`aegis/audit.py:28-32`）は、照合 → 追記 → アンカーへの記録、の順で行い、どれかが失敗すれば呼び出し元にエラーを返します（`aegis/audit.py:96-98`, `:113-118`, `:125-165`）。
8. すり替え対策：接続ごとに相手の UID を確かめる（Linux `SO_PEERCRED`、macOS `LOCAL_PEERCRED`。`aegis/audit_anchor.py:334-347`, `:366-379`）。記録元 ID は `<名前>:<データルートからの相対パス>` で、パスは解決しません。経路上のシンボリックリンクは拒否し、ログは `O_NOFOLLOW` で読みます（`aegis/audit.py:130-131`, `:274-290`）。補助プロセスは起動時に登録した名前だけを受け付けます（`aegis/audit_anchor.py:266-268`）。`VULNIX_AUDIT_ANCHOR_*` は `.env.local` から読みません（`aegis/server.py:1714-1718`）。
9. アンカーと同じユーザーで動く補助プロセスは「保護なし（`same_user`）」と表示します（`aegis/audit.py:193-202`）。

## 主なコードの場所

| 内容 | 場所 |
|---|---|
| チェーン・ロック・追記 | `aegis/audit.py:39-119` |
| アンカーとの照合・記録 | `aegis/audit.py:121-202` |
| 有料送信の予約と予約ファイル | `aegis/audit.py:204-272` |
| 読み取りと検証 | `aegis/audit.py:274-308` |
| 補助プロセス・クライアント | `aegis/audit_anchor.py:81-440` |
| 監査が先の状態変更 | `aegis/diagnosis_state.py:105-121`, `aegis/assessment.py:1844-1850`, `aegis/diagnosis_ops.py:256-301` |
| プラットフォーム全体の記録（アンカーの対象外） | `aegis/tenancy.py:317`（`platform-audit.jsonl`）、`:324`（`platform-advisor-spend.json`、`aegis/spend_cap.py:35-`） |

## 証拠となるテストと CI

| テスト / CI ステップ | 確かめていること |
|---|---|
| `tests/test_audit_snapshot.py::TestConcurrentValidAuditAppend`（`test_simultaneous_worker_authorizations_keep_one_valid_chain`, `test_simultaneous_paid_reservations_cannot_exceed_cap`, `test_valid_prefix_rollback_cannot_authorize_worker_or_paid_send` など7件） | 同時追記、同時予約、有効な先頭部分への切り戻し |
| `tests/test_audit_anchor.py::TestTamperAndRollback`（`test_tampered_entry_refuses_critical_record`, `test_truncated_log_is_a_rollback`, `test_rewritten_tail_at_an_anchored_position_is_a_fork`, `test_rollback_of_log_and_reservation_file_together`） | 改ざん・切り詰め・fork・2ファイルの同時切り戻し |
| `…::TestAnchorFailures`, `TestPermissions`, `TestRestartAndConcurrency`, `TestSourceIdentity`（`test_symlink_swap_to_an_older_copy`, `test_reviewer_poc_scenario` など）, `TestPeerIdentity`（`test_peer_uid_mismatch_is_refused`, `test_env_local_cannot_configure_the_anchor`）, `TestDisabled` | 補助プロセスの停止・破損、権限、再起動、すり替え、相手の確認、無効時 |
| `…::TestServiceIntegration::test_diagnosis_change_is_not_applied_without_the_anchor`, `TestFindingVerdictEndToEnd`（`test_verdict_is_not_applied_when_the_result_cannot_be_anchored`, `test_approval_is_not_applied_when_it_cannot_be_anchored`） | アンカーに書けなければ、診断の変更・判定・承認を反映しない |
| `tests/test_diagnosis_actions.py::TestAuditFailure`（`test_a_request_that_cannot_be_audited_is_not_accepted`, `test_a_spec_that_cannot_be_audited_changes_nothing`） | 監査に書けない要求・仕様は何も変えない |
| `tests/test_diagnosis_loop.py::…::test_a_judgement_that_cannot_be_audited_changes_nothing` | 監査に書けない判定は何も変えない |
| `tests/test_diagnosis_state.py::TestJournal`, `tests/test_diagnosis_read_api.py`（`test_a_broken_audit_chain_shows_nothing` など） | 監査ログからの組み立て直し、改ざんの検出 |
| `tests/test_spend_cap.py::TestDurableSpendCap` | プラットフォーム全体の上限ファイル |
| CI「Local audit anchor as a separate OS user (rollback of log + reservation file detected)」（`.github/workflows/ci.yml:112-137`、`scripts/audit_anchor_ci.py`） | 別ユーザー `vulnix-anchor` の補助プロセスに対し、サービス側が記録・照合できる、記録ファイルを読み書きできない、2ファイルの同時切り戻しとシンボリックリンクのすり替えを検出する。前提が欠ければ失敗（skip しない） |

## 既知の制限（`docs/AUDIT_ANCHOR.md`「守れないもの」、`docs/SECURITY_REVIEW.md`）

- アンカーは**既定で無効**です（`VULNIX_AUDIT_ANCHOR_SOCKET` 未設定）。無効のとき、サービスの OS ユーザーは監査ログと予約ファイルを**両方**古い状態に戻せ、検出できません（`docs/AUDIT_ANCHOR.md` 3-6行、`docs/SECURITY_REVIEW.md` 37-39行）。
- root、または補助プロセスのユーザーとして動ける攻撃者は対象外です。
- 最後に照合した位置より後の、重要でない記録だけを消すことは検出できません。偽の記録を**追加**することも防げません（サービスは記録を書く立場です）。
- 有効にした時点のログを正しいものとして始めます。
- `platform-audit.jsonl`（ログイン・登録・MFA・ロール・組織へのアクセス拒否）と `platform-advisor-spend.json`（全組織合計の有料送信額）はアンカーの対象外です。後者を巻き戻すと、全体の上限に対する使用額を少なく見せられます（組織ごとの上限は守られます）。
- 監査ファイルを外から別の inode に置き換えると、`flock` は別のファイルのロックになり得ます（`docs/SECURITY_REVIEW.md` 122行）。
- Windows（`flock` なし）では動きません（同上）。
- 大きなログでの照合の遅延は未測定です（同 109行、112行）。

## 試してほしいこと

1. **アンカーなしでのチェーンの作り直し**：サービスのユーザーとして `audit.jsonl` を書き換え、チェーンを全部作り直し、`.advisor-budget` も合わせる。再起動後に、Worker の許可・有料送信・診断の状態が、書き換えた履歴に基づいて進むか（進むことは文書化された制限です。**画面やレポートが「改ざんなし」「保護あり」と誤って表示しないか**を確かめてください。`aegis/audit.py:185-202`、レポートの「監査チェーン検証」）。
2. **アンカーありでの迂回**：`fork` / `rollback` の判定（`aegis/audit.py:139-147`）を、記録元 ID の付け替え（`<data>/orgs/<id>` の改名、新しい組織 ID）、データルートの付け替え、`--data-dir` の別名で避けられないか。新しい組織は新しい記録元として seq 0 から始まります。
3. **重要な記録の分類漏れ**：Worker の起動・承認・判定・有料送信につながる記録で、`ANCHORED_EVENTS` / `ANCHORED_PREFIXES`（`aegis/audit.py:28-32`）に入っていないものがないか。例：`approval.auto`（自動の L1 承認、`aegis/assessment.py:5060-5061`）、`assessment.start_requested`（処理の**後**に書く、`aegis/server.py:1483-1486`）。
4. **監査が先、の抜け**：`diagnosis.*` 以外の状態変更（資産の登録・削除・選択、所有確認、ロール変更）で、反映が先・監査が後になっていて、監査の失敗が無視される経路がないか（例：`aegis/assessment.py:2988-2992` の `asset.registered` は保存の後）。
5. **ソケットの権限**：文書の例はソケットを `--socket-mode 666` にし、ディレクトリのグループで接続を絞ります（`docs/AUDIT_ANCHOR.md` 126-138行）。同じホストの別ユーザーが接続できる構成で、先頭を先に進めて（偽の `anchor`）サービスを止める（DoS）ことができるか。登録した記録元の名前さえ分かれば可能に見えます（`aegis/audit_anchor.py:255-282`）。
