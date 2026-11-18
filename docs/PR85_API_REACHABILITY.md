# PR #85 API到達性と失効境界

基準: `aegis/server.py`、`web/src`、`tests/test_tenancy.py`を照合。対象はPR #85の公開β用HTTP経路。静的な呼出し元の照合であり、実行時に設定される外部送信先や全分岐の到達性を証明しない。実DNS、Google、実サイト、実モデルには通信していない。

追加照合: `aegis/server.py`の文字列リテラルに含まれる`/api/`経路を抽出し、この表との差分が0件であることを確認した。診断ID、承認ID、ARTEX itemを組み立てる動的分岐は下表と`do_GET`/`do_POST`の条件式を別途照合した。これは実行時の全経路到達を証明しない。

## 共通境界

- Python側はHostをループバックに限定する。WebのAPI中継は許可済みHostから固定の`AEGIS_API`へ転送する。`AEGIS_API`の実運用値は未確認。
- Web経由のPOSTは同一Originと`X-Aegis-Request: 1`を要求する。Python側も同ヘッダーとOrigin許可リスト、JSONオブジェクト・本文上限を確認する。GETはCSRFヘッダーを要求しない。
- 組織データのGET/POSTは原則`_bind`で所属と当該組織の`AssessmentService`を選ぶ。`/api/orgs*`は`_tenancy_get/_tenancy_post`で別途組織権限を確認する。全体管理ルートは組織データ用`_bind`を通らない。
- 表の「失効」は応答時に確かめた範囲を示す。`読取再検査`は送信時に401（セッション失効）/403（組織権限失効）。`開始時`は`_dispatch`入口で401/403。`操作時`は個別の生存権限ガードも使う。操作後の応答まで必ず401/403になると書いていない行は、その競合が未実証である。
- Web画面に利用元が見つからないAPIは「画面なし」と記す。`GET /api/health`と`GET /api/auth/me`はログイン前にも呼べる。その他のGETは公開βの読み取り認証設定を前提とする。

## 認証・組織・管理

| API | 権限・組織 | 要求値 | 失効時の確認範囲 | Web利用元 |
| --- | --- | --- | --- | --- |
| `GET /api/auth/me` | 匿名可、本人のセッション | cookie | 送信直前の現行セッションを反映。失効後は`session:null` | `SessionProvider` |
| `GET /api/health` | 匿名可 | なし | 非保護情報 | 画面なし |
| `POST /api/auth/login` | 匿名、CSRF | name/password | 新規ログイン。ログイン前の失効対象なし | ログイン |
| `POST /api/auth/register` | 登録設定または管理者、CSRF | name/display/password等 | 登録権限はサーバー側で判定 | ログイン、管理者設定 |
| `POST /api/auth/logout` | cookie、CSRF | なし | セッション失効とcookie消去 | `SessionProvider` |
| `POST /api/auth/password` | 本人、CSRF | 現在/新パスワード | 操作時のセッション再検査を既存テストで確認 | パスワード設定 |
| `POST /api/auth/totp/enroll` | 本人、CSRF | なし | 操作時のセッション再検査 | MFA設定 |
| `POST /api/auth/totp/confirm` | 本人、CSRF | code | 操作時のセッション再検査 | MFA設定 |
| `POST /api/auth/totp/disable` | 本人、CSRF | current/code | 操作時のセッション再検査 | MFA設定 |
| `GET /api/operators` | 全体admin | なし | 送信時に本人とadminを再検査、401/403 | 管理者設定 |
| `POST /api/operators/roles` | 全体admin、CSRF | name/roles | 操作時の管理者権限を再検査 | 管理者設定 |
| `POST /api/operators/unlock` | 全体admin、CSRF | name | 操作時の管理者権限を再検査 | 管理者設定 |
| `POST /api/operators/reset-mfa` | 全体admin、CSRF | name | 操作時の管理者権限を再検査 | 管理者設定 |
| `GET /api/orgs` | 本人の所属一覧 | cookie | 送信時に本人を再検査、401 | 組織切替 |
| `GET /api/orgs/members` | 選択組織のメンバー | org query/cookie | 送信時に所属を再検査、401/403 | 組織設定 |
| `GET /api/orgs/invites` | 選択組織owner/admin | org query/cookie | 送信時に所属と役割を再検査、401/403 | 組織設定 |
| `POST /api/orgs` | 本人、CSRF | name | セッションをロックして作成 | 組織設定 |
| `POST /api/invites/accept` | 本人、CSRF | token | セッションをロックして参加 | 招待ページ |
| `POST /api/orgs/members/roles` | 選択組織の管理者、CSRF | org/name/roles | セッションと組織権限を操作時に確認 | 組織設定 |
| `POST /api/orgs/members/remove` | 選択組織の管理者、CSRF | org/name | セッションと組織権限を操作時に確認 | 組織設定 |
| `POST /api/orgs/invites` | 選択組織owner/admin、CSRF | org/roles/ttl_hours | セッションと組織権限を操作時に確認 | 組織設定 |
| `POST /api/orgs/invites/revoke` | 選択組織owner/admin、CSRF | org/id | セッションと組織権限を操作時に確認 | 組織設定 |

## 対象登録・所有確認

この表のGETは選択組織へ結合し、送信時に読み取り権限を再検査する。POSTは共通CSRF、組織結合、少なくとも`operator/approver/admin`の操作権限を通す。所有確認や範囲確定の長い処理には個別の`grant_guard`があり、結果保存時の失効を拒否する。`5217969`で登録・証明・範囲確定とGoogle開始/完了の成功応答にも現行権限確認を加えた。通常の失効エラー応答など、すべてのPOST分岐の送信時競合は未証明。

| API | 追加権限・要求値 | 失効時の確認範囲 | Web利用元 |
| --- | --- | --- | --- |
| `GET /api/assets` | なし | 読取再検査 | ダッシュボード、対象一覧 |
| `GET /api/assets/secrets-status` | host query | 読取再検査 | 画面なし |
| `POST /api/assets` | name/kind/environment/authorization_ref等 | 開始時。実サイト権限はサービスでも判定 | 対象登録 |
| `POST /api/assets/challenge` | url/sow_id。既確認対象の再登録はapprover | 保存時の`grant_guard`、送信時の操作権限。ログアウト401・役割降格403を模擬確認 | 所有確認 |
| `POST /api/assets/google/start` | url/host、Google設定済み、短期state | state発行後の送信時に操作権限を再確認。実Google環境は未実証 | 所有確認 |
| `POST /api/assets/google/finish` | code/state、同一アカウント・組織・期限 | 外部照会後、証明保存から応答まで生存権限リース。既承認の保存中ログアウトは応答後に完了 | Google戻り画面 |
| `POST /api/assets/verify-ownership` | url/host/method。既確認対象の再確認はapprover | DNS/ファイル照会後の保存時`grant_guard`、送信時の操作権限。ログアウト401を模擬確認 | 所有確認 |
| `POST /api/assets/confirm-scope` | url/host、禁止事項への同意、approver | 保存時`grant_guard`、送信時の承認者権限。ログアウト401を模擬確認 | 所有確認 |
| `POST /api/assets/secrets` | host/tokens等、approver | 開始時とサービス側の範囲確認 | 診断設定 |
| `POST /api/assets/delete` | id。実サイトはapprover | 開始時とサービス側の対象確認 | ダッシュボード、対象一覧 |
| `POST /api/assets/select` | id | 開始時とサービス側の対象確認 | ダッシュボード、対象一覧 |

## 診断・証拠・イベント

`{id}`は選択組織の診断IDと一致しなければ404。GETは組織読み取り権限、POSTは共通CSRFと組織操作権限を通す。実サイトの読み取り専用モードは追加L2、修正後再現、未許可のARTEX操作を拒否する。`lab-mode`は複数組織モードで結合前に403となる。

| API | 追加権限・要求値 | 失効時の確認範囲 | Web利用元 |
| --- | --- | --- | --- |
| `GET /api/assessments/{id}` | id | 生成前後の読取再検査、401/403 | 結果画面`useAssessment` |
| `GET /api/assessments/{id}/logs` | id | 生成前後の読取再検査、401/403 | 結果画面`useAssessment` |
| `GET /api/assessments/{id}/report` | id | 生成前後の読取再検査、401/403 | 結果画面・報告書 |
| `GET /api/assessments/{id}/remotion` | anonymize query。無匿名はapprover/admin | 生成前後の権限と無匿名権限を再検査、401/403 | 実サイト設定 |
| `GET /api/assessments/{id}/artex/llm-preview` | approver | 読取再検査、401/403 | 画面なし |
| `GET /api/assessments/{id}/events` | Last-Event-ID/after | 接続後も各イベント・心拍で再検査。失効後は配信終了 | 結果画面`useAssessment` |
| `POST /api/assessments/{id}/start` | id、対象権限・範囲・期限 | 開始時と起動時の生存権限 | 所有確認、実行操作 |
| `POST /api/assessments/{id}/restart` | id、対象権限・範囲・期限 | 開始時と起動時の生存権限 | 実行操作 |
| `POST /api/assessments/{id}/resume` | id | 開始時と再開時の生存権限 | 実行操作 |
| `POST /api/assessments/{id}/pause` | id。閲覧者も安全停止可 | 停止は実行、応答直前の読取再検査で失効401/403。認証状態の保存障害時は詳細なし200 | 実行操作 |
| `POST /api/assessments/{id}/emergency-stop` | id。閲覧者も安全停止可 | 停止は実行、応答直前の読取再検査で失効401/403。認証状態の保存障害時は詳細なし200 | 実行操作 |
| `POST /api/assessments/{id}/verify-finding` | finding_id、サービス側の承認判定 | 開始時と検証要求時の権限。応答時競合は未実証 | 所見詳細、結果画面 |
| `POST /api/assessments/{id}/artex/plan` | llm_mode/llm_approval。承認時はapprover | 開始時、モデル送信前の生存権限 | ARTEX計画 |
| `POST /api/assessments/{id}/artex/items/{item}/execute` | itemは英数字/下線80字以内、Gateway再審査 | 開始時、Worker起動直前の生存権限 | ARTEX計画 |
| `POST /api/assessments/{id}/request-l2` | finding_id。依頼者と承認者を分ける設定では自己登録アカウントは禁止 | 開始時とサービス側の依頼権限 | 所見詳細 |
| `POST /api/assessments/{id}/lab-mode` | mode。複数組織では403 | 複数組織では実行不可 | 結果画面の模擬ラボ操作 |
| `POST /api/assessments/{id}/verify-fix` | approver | 開始時とサービス側の権限確認 | 実行操作 |
| `POST /api/assessments/{id}/chat` | question、任意term/finding_id/safe_advice | 開始時、外部送信時の生存権限 | 解説画面 |
| `POST /api/assessments/{id}/approvals/{req_id}` | req_+16進ID、decision=approve/reject、approver | 開始時とサービス側の承認権限 | AgentActivity |

## 全体管理・運用

| API | 権限・要求値 | 失効時の確認範囲 | Web利用元 |
| --- | --- | --- | --- |
| `GET /api/system/status` | 組織別状態 | 生成前後の読取再検査、401/403 | サイドバー |
| `GET /api/router/status` | 組織別モデル状態 | 送信時の読取再検査、401/403 | 画面なし |
| `GET /api/l2-profiles` | 全体admin/approver | 送信時の役割再検査、401/403 | 設定 |
| `GET /api/cve/status` | 認証済み（公開β設定） | 生成後の送信時に現行セッションを再検査。ログアウト後401を模擬確認 | 画面なし |
| `POST /api/l2-profiles/accept` | 全体admin、id/sha256 | 開始時とサービス側のプロファイル照合 | 設定 |
| `POST /api/router/verify` | 全体admin/approver | 開始時。実行時の外部先は設定依存・未照合 | 画面なし |
| `POST /api/cve/sync` | 全体admin/approver、nvd/kev/source | 開始時。HTTP入力を取り込む。外部URL取得は通常経路にない | 設定 |
| `POST /api/system/verify-controls` | 全体admin/approver | 開始時。隔離検証ジョブ | 設定 |
| `POST /api/cve/real-software-verify` | 全体admin/approver | 開始時。ローカルソフト比較ジョブ | 画面なし |

## 残る到達性検証

1. `AEGIS_API`、モデル上流、Google、対象URLは実行時設定から決まる。静的文字列から実運用の送信先を確定しない。
2. 所有確認の保存後から成功応答までのログアウト・登録時の役割降格は赤/緑テスト済み。Google開始/完了の送信時権限はコードと既存模擬テストで照合したが、実Googleは未確認。通常POSTの残る処理中失効は追加テストが必要。`/api/cve/status`の生成中ログアウトは赤テストの200から401へ修正した。
3. 390px/1280pxの模擬ブラウザでは結果、報告書、組織切替、SSE再接続、失効後の非表示に加え、診断中の除名、所有確認中の失効、レポート生成中の失効も確認した。公開β、中継、長時間Workerの境界は未検証。
4. 正式GitHubレビューと公開βの実DNS・実サイト経路は別ゲート。
