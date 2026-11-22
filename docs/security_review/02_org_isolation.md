# (b) 組織（テナント）の分離

## 設計（要約）

1. `VULNIX_MULTI_TENANT` が `0` でなければ（既定は有効）、`OrgStore`（`<data>/orgs.json`）と `TenantRegistry` を作ります（`aegis/server.py:1646-1654`）。
2. 組織ごとに別の `AssessmentService` オブジェクトを持ちます。データは `<data>/orgs/<org_id>/`（0700）です（`aegis/tenancy.py:327-344`）。秘密値・所有確認用の秘密・監査ログ・イベントバス・緊急停止はそのオブジェクトに属します（`aegis/assessment.py:361-366`）。
3. **既定の組織（`default`）だけは例外**で、プロセスが最初から持つサービス、つまりデータルートそのものを使います（`aegis/tenancy.py:327-329`、`aegis/server.py:1761-1763`）。
4. 組織に関わる要求は `_bind` を通ります。組織の指定は `X-Vulnix-Org` ヘッダー → クエリ `org` → Cookie `vulnix_org` の順です（`aegis/server.py:315-320`）。ID の形（`org_[0-9a-f]{12}|default`、`aegis/tenancy.py:54`）とメンバーかどうかを確かめ、メンバーでなければ 403 と `tenancy.access_denied`（プラットフォーム監査）です（`aegis/server.py:322-355`）。組織の役割はサービスの役割に変換します（`aegis/tenancy.py:41-47`, `:61-67`）。
5. 存在しない組織と所属していない組織は、同じ 403 です（`aegis/server.py:340-344`。`valid_org_id` に通らない ID も同じ分岐）。
6. `_bind` の後、`_dispatch` の入口で、現在のセッションと組織の役割を**もう一度**読みます（`aegis/server.py:1237-1258`）。保護された応答は `_authorized_org_read` の中で送ります。送出中は権限のリース（共有）を持ちます（`aegis/server.py:357-371`）。
7. プラットフォーム全体の POST（`PLATFORM_POST_ROUTES`、`aegis/server.py:104-105`）は `_bind` を通らず、アカウント自身の役割で判定します（`aegis/server.py:842`, `:947`, `:1446-1482`）。例外時は固定のエラー文にします（`:1620-1625`）。
8. SSE（`/api/assessments/{id}/events`）は、その組織のサービスの `bus` だけを読みます（`aegis/server.py:527-528`, `:671-709`）。イベント1件ごとに権限のリースを取り直し、ログアウト・除名は 401/403 で切断します（`aegis/server.py:686-703`, `:733-750`）。1アカウント4本・全体200本の上限（`aegis/server.py:63`, `:96`, `:674-681`）。
9. アカウントに関わるイベントは `platform-audit.jsonl` に書き、どの組織の監査ログにも出しません（`aegis/tenancy.py:315-317`）。
10. 共有の模擬ラボのモード切り替えは、テナントありでは拒否します（`aegis/server.py:837-841`, `aegis/tenancy.py:320`, `:341`）。

## 主なコードの場所

| 内容 | 場所 |
|---|---|
| 役割の変換 | `aegis/tenancy.py:41-47`, `:61-67` |
| メンバーの管理（自分の権限を増やせない、owner は owner だけ、最後の owner は外せない） | `aegis/tenancy.py:187-222` |
| 招待（ハッシュだけ保存、1回限り、自分の招待は使えない、上限20件） | `aegis/tenancy.py:224-279` |
| 組織ごとのサービスとディレクトリ | `aegis/tenancy.py:304-356` |
| 組織の選択と所属確認 | `aegis/server.py:315-355`（`_org_requested`, `_bind`） |
| GET の組織データ | `aegis/server.py:520-575`, `:624-669`（`_get_org`） |
| POST の振り分け | `aegis/server.py:826-947`（`do_POST` のテナント分岐）、`:1237-1641`（`_dispatch`） |
| 組織管理 API | `aegis/server.py:1158-1232`（`_org_for_management`, `_tenancy_get`, `_tenancy_post`） |
| SSE | `aegis/server.py:671-751` |

## 証拠となるテスト

| テスト | 確かめていること |
|---|---|
| `tests/test_tenancy.py::TestTenantIsolationOverHttp::test_each_signup_gets_its_own_org_and_sees_only_its_own_data` | 登録ごとに別の組織、ほかの組織のデータは見えない |
| `…::test_the_ui_cookie_selects_the_org_and_is_still_membership_checked` | Cookie で選んでも所属を確かめる |
| `…::test_org_owner_role_does_not_become_platform_admin_on_one_connection` | HTTP/1.1 の同じ接続で、組織の owner 権限がプラットフォーム API に漏れない |
| `…::test_platform_functions_keep_global_roles` | プラットフォーム API はアカウントの役割で判定 |
| `…::test_ownership_challenges_differ_per_org`、`TestPublicReadOnlyRealSites::test_another_org_cannot_use_my_proof` | 所有確認の値は組織ごとに異なり、流用できない |
| `…::test_invite_roles_viewer_read_only_and_promotion`, `test_signup_with_an_invite_joins_that_org_only` | 招待の役割、閲覧者は読むだけ |
| `TestReviewFixes::test_nobody_adds_roles_to_themselves`, `test_accepting_your_own_invite_is_refused` | 自分の権限を増やせない |
| `TestReviewFixesOverHttp::test_a_removed_member_loses_the_event_stream`, `test_account_events_go_to_the_platform_audit_not_the_default_org` | 除名で SSE が切れる。アカウントの記録はプラットフォーム監査へ |
| `TestTenantIsolationOverHttp::test_member_removal_waits_for_an_inflight_event_write` | 除名は送出中のイベントを待つ（送出後に新しいイベントは届かない） |
| `TestSecondReviewFixes::test_event_streams_per_account_are_capped`, `TestThirdReviewFixes::test_platform_wide_stream_cap` | SSE の上限 |
| `TestReviewFixesOverHttp::test_system_status_is_the_callers_own_org`, `test_planner_status_is_the_callers_own_org` | 状態 API は自分の組織だけ |
| `TestDiagnosisReadApiOverHttp::test_diagnosis_updates_reach_only_the_organizations_own_stream` | 診断のイベントは自分の組織の SSE だけ |
| `TestDiagnosisActionsOverHttp::test_login_organization_permission_and_key` | 診断の操作：未ログイン 401、別組織 403、閲覧者 403、キーなし 400 |
| `TestTenantIsolationOverHttp::test_membership_removal_after_*`, `test_logout_after_*`（約30件） | `_bind` の後に失効すると、結果・スナップショット・ログ・レポートを返さない |
| E2E `scripts/check_diagnosis_actions.py`, `scripts/check_first_run.py` | 別の組織の `outsider` からの操作が 403 で状態が変わらない（`docs/DIAGNOSIS_ACTIONS.md` §6） |

`AGENTS.md` は、新しいルートを追加したら `tests/test_tenancy.py` に「他の組織のメンバーが読めない・操作できない」テストを足すことを求めています。

## 既知の制限

- 模擬ラボ（`lab.test`、`127.0.0.1:<lab_port>`）は全組織で1つです（`ARCHITECTURE.md`「公開β版の利用制限」の後の注記、`aegis/tenancy.py:318-320`）。ある組織の L2 がラボの状態（SQLite・ファイル）を変えると、別の組織の観測に影響し得ます（ラボ自体は共有資源として設計されています）。
- プラットフォーム全体の上限（登録・SSE・AI 解説）は、1人が使い切ると他人も使えなくなります（`SECURITY.md` で受け入れたリスク）。
- 既定の組織のデータはデータルートにあり、`orgs.json`・`operators.json`・`sessions.json`・`platform-audit.jsonl` と同じ階層です（`aegis/server.py:1758-1763`）。

## 試してほしいこと

1. **組織の取り違え**：同じ HTTP/1.1 接続で、組織 A の GET → 組織 B（非メンバー）の POST → プラットフォーム POST、の順に送り、`self._bound_org`（`aegis/server.py:350`）が前の要求の値のまま使われる経路がないか。`_dispatch` は `getattr(self, "_bound_org", DEFAULT_ORG)` を多用します（例 `:1275`, `:1484`, `:1531`）。
2. **ID の検証**：`X-Vulnix-Org` / `org` / `vulnix_org` に、`default`、大文字、40文字超、`../` を入れたとき。`_org_requested` は `[:40]` で切ってから `valid_org_id` を通します（`aegis/server.py:320`, `:340`）。`TenantRegistry.service` のパス結合（`aegis/tenancy.py:335`）に到達する値がないか。
3. **権限の昇格**：org admin（owner でない）が、第二のアカウントを招待して approver を付け、自分の L2 を承認させる（`aegis/tenancy.py:194-210`, `:224-240`）。診断ループの依頼者≠承認者はアカウント名の比較です（`aegis/diagnosis_ops.py:631`）。自己登録アカウントの承認拒否は `AEGIS_SEPARATE_L2_APPROVER=1` のときだけ効きます（`aegis/server.py:1533`）。これが許容範囲かどうか（[03_authority_revocation.md](03_authority_revocation.md) の観察2）。
4. **SSE**：`Last-Event-ID` やクエリ `after` を操作して、他組織のイベントや、除名前のバックログを読めないか（`aegis/server.py:664-668`, `:731-743`）。
5. **新しいルートの取りこぼし**：`do_POST` で `PLATFORM_POST_ROUTES` に入っていないパスはすべて `_bind` を通ります。逆に、`_dispatch` の中で `svc` が `default_svc` に落ちる経路（`aegis/server.py:1261`）を、テナントありで踏めないか。
