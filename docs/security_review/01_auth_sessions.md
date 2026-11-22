# (a) 認証とセッション

対象コード：`main e977695`（コードは `9ce0571` と同一。`git diff 9ce0571 e977695` は `docs/V1_COMPLETION.md` だけ）。行番号はこのコミットで確認したものです。

## 設計（要約）

1. アカウントは `OperatorStore`（`aegis/operators.py`）にあります。パスワードは scrypt（N=2^15, r=8, p=1）のハッシュだけを保存します（`aegis/operators.py:48`, `:133-149`）。
2. ログインに成功すると `secrets.token_urlsafe(32)` のトークンを発行します。保存するのは SHA-256 だけです（`aegis/operators.py:79-83`, `:643-645`）。有効期限は 12 時間（`:43`）。ディスクに保存できなければ、トークンを渡しません（`:646-653`）。
3. ロールはセッションに固定しません。解決のたびに、アカウントの現在のロールを読み直します（`aegis/operators.py:662-677`）。
4. セッションは Cookie `aegis_session`（`HttpOnly; SameSite=Strict; Path=/`。`Secure` はなし）で渡します（`aegis/server.py:1018`, `:1098`）。`Authorization: Bearer` も受け付けます（`aegis/server.py:264-272`）。
5. CSRF 対策は2段です。Next.js のプロキシは、`X-Aegis-Request: 1`、Origin あり、Origin のホストと Host が一致、許可されたローカル名、をすべて求めます（`web/src/app/api/[...path]/route.ts:102-115`）。コントロールプレーンは `X-Aegis-Request: 1` を求め、Origin があれば `ALLOWED_ORIGINS` との一致を求めます（`aegis/server.py:43`, `:757-759`）。Host がループバック名でなければ、GET・POST とも 421 で拒否します（`aegis/server.py:414-420`, `:431`, `:755`）。
6. ロックアウトはアカウント名ごとです（存在しない名前も同じ扱い）。15分に5回失敗すると15分止めます（`aegis/operators.py:72-74`）。パスワードを照合する**前に**試行を予約するので、並列に投げても回数は増えません（`:515-540`）。名前が存在しなくても scrypt を1回行います（`:628-632`）。
7. TOTP（RFC 6238、30秒、前後1ステップ）は**利用者が登録した場合だけ**必須になります（`aegis/operators.py:633-640`）。受け入れた時間ステップを保存し、再利用を拒否します（`:604-617`）。無効化にはパスワードと現在のコードの両方が要ります（`:835-854`）。
8. ログアウト・パスワード変更・ロール変更・MFA リセットは `GrantLease` の排他側で動きます。応答の送出中（共有側）が終わるのを待ち、待つ間は新しい送出を始めません（`aegis/operators.py:172-179`, `aegis/grant_lease.py:32-71`）。
9. 認証状態をディスクに保存できないとき（`trusted()` が偽）は、新しいログインを拒否し、権限を減らす操作（停止・一時停止・MFA リセット・ロールの削減）以外の POST を 503 にします（`aegis/operators.py:304-321`, `:620-624`, `aegis/server.py:804-813`）。前回の終了が正常でなければ、起動時に全セッションを失効させます（`aegis/server.py:1656-1659`）。

## 主なコードの場所

| 内容 | 場所 |
|---|---|
| ログイン・TOTP・ロックアウト | `aegis/operators.py:515-570`（試行予約・失敗記録）、`:604-654`（TOTP・login） |
| セッション解決（ロールは毎回読み直し） | `aegis/operators.py:656-688` |
| ログイン/ログアウト/登録の HTTP | `aegis/server.py:785-799`（logout）、`:1002-1021`（login）、`:1023-1105`（register） |
| CSRF（プロキシ） | `web/src/app/api/[...path]/route.ts:23-30`（hostAllowed）、`:102-115` |
| CSRF・Host（コントロールプレーン） | `aegis/server.py:414-420`, `:754-760` |
| 公開モードで `/api/*` を 404 | `web/src/proxy.ts:8-22`、判定は `web/src/lib/publicMode.ts` |
| 読み取りにも認証を要求（既定） | `aegis/server.py:163-170`（`AEGIS_REQUIRE_READ_AUTH=0` は開発モードだけ）、`:1748-1755` |
| 権限を減らす操作は保存失敗中も許す | `aegis/server.py:804-813` |

## 証拠となるテスト

| テスト | 確かめていること |
|---|---|
| `tests/test_server.py::TestServer::test_csrf_guard` | `X-Aegis-Request: 0` と `Origin: http://evil.example` の POST が 403、状態は変わらない |
| `tests/test_attack_regressions.py::TestVerificationJobsCannotBeTriggeredByALink::test_get_never_starts_a_job_and_post_needs_csrf_header_origin_and_role` | GET でジョブが始まらない。POST にはヘッダー・Origin・ロールが要る |
| `tests/test_attack_regressions.py::TestThirdReviewFindingsStayFixed::test_requests_addressed_by_another_host_name_are_refused` | ループバック以外の Host は拒否 |
| `tests/test_attack_regressions.py::TestPasswordGuessing`（9件。例 `test_parallel_guesses_get_no_more_tries_than_sequential_ones`, `test_name_variants_neither_lock_the_real_account_nor_reset_its_counter`, `test_second_factor_guessing_is_throttled_and_cannot_be_switched_off_with_the_password_alone`） | ロックアウト、並列試行、名前の表記ゆれ、2要素の推測 |
| `tests/test_attack_regressions.py::TestStolenSessionFile` | セッションファイルに使えるトークンがない。旧形式の平文は失効 |
| `tests/test_fail_closed.py::TestSignInThrottleDoesNotRevealAccounts` | ロックの応答から存在するアカウントが分からない |
| `tests/test_final_review.py::TestSignInEdgeCases::test_a_used_totp_code_stays_used_after_a_restart` | 使った TOTP は再起動後も使えない |
| `tests/test_operators.py`（16件） | ハッシュ、TOTP の窓、期限、ログアウトの永続化、パスワード変更で他セッション失効 |
| `tests/test_release_safety.py::TestAuthStateAcrossSaveFailuresAndRestarts`, `TestUntrustedAuthStateOverHttp`, `TestUncleanShutdownSignsEveryoneOut` | 保存失敗中の拒否、異常終了後の全失効 |
| `tests/test_tenancy.py::TestTenantIsolationOverHttp::test_logout_before_*`（パスワード・TOTP 登録/確認/無効化・ロール変更など） | 認証の後、実行点の前にログアウトすると、変更しない |
| `web/tests/publicMode.test.mjs` | 公開モードの許可・拒否の判定 |

**テストが見つからなかったもの**：Next.js プロキシ（`route.ts`）の CSRF・Host 判定そのものを単体で確かめるテストは `web/tests/` に見当たりませんでした（`csrf`・`hostAllowed` で検索）。E2E（`scripts/check_*.py`）はこのプロキシを経由しますが、拒否側は確かめていません（未確認）。

## 既知の制限（コードと文書で確認したもの）

- **MFA は任意**です。approver・admin・組織の owner にも必須ではありません（`aegis/operators.py:633-634` のコメント）。
- ロックアウトは名前ごとだけです。コントロールプレーンからは接続元が分からないため、IP ごとの制限は Next.js プロキシ（`cf-connecting-ip` がある場合だけ、`route.ts:35-42`）と前段の Cloudflare に任せています（`SECURITY.md`「公開登録と共有の上限」）。
- 公開登録を有効にすると、ユーザー名の存在が分かります（`SECURITY.md` で受け入れたリスク）。
- セッション Cookie に `Secure` 属性はありません（`aegis/server.py:1018`）。API はループバックと、公開モードでは 404（`web/src/proxy.ts`）という前提です。
- TOTP の登録確認（`confirm_totp`）は `verify_totp` で照合し、そのステップを「使用済み」として記録しません（`aegis/operators.py:821`）。確認に使ったコードは、同じ時間窓の中なら1回ログインに使える可能性があります。→ 再現テストで確認し、PR #118 で修正しました（README の O4）。

## 試してほしいこと

1. **CSRF の迂回**：ブラウザから `http://localhost:3000/api/...` へ、`Origin` なし・`null`・別ポートの `localhost` で POST できないか。`route.ts:106-115` は `originHost !== host` を見ます。`AEGIS_UI_ALLOWED_HOSTS` を設定した場合の挙動も。
2. **コントロールプレーン直結**：`127.0.0.1:8787` は Origin なしの POST を受け付けます（`aegis/server.py:757-758`）。ブラウザからの DNS リバインディングは `_host_ok` で、通常のクロスオリジンはカスタムヘッダーのプリフライト（`do_OPTIONS` なし）で止まる想定です。これが崩れる経路はないか。
3. **ロックアウトと列挙**：`_slot_locked` の上限 5,000 件と 4,096 個の共有バケット（`aegis/operators.py:446-470`）を使って、特定アカウントのロックを解除したり、存在を推定したりできないか。
4. **失効の競合**：ログアウト・ロール削除と、同時に進む POST・SSE の間に、古い権限で結果が返る窓がないか。`GrantLease`（`aegis/grant_lease.py`）と `locked_session`（`aegis/operators.py:679-688`）。`Bearer` ヘッダーでの再利用も含めて。
5. **保存失敗の扱い**：データディレクトリを読み取り専用にしたとき、`reduces_power`（`aegis/server.py:804-806`）の判定で、権限を**増やす**ロール変更が通らないか（`set(roles) <= ops.roles_of(name)` の比較）。
