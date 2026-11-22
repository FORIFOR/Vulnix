# 実サイトへの初回 L1 診断（限定実施）運用手順書

この手順書は、Vulnix が**実在するサイトに初めて通信する**ときの運用手順です。対象は、所有者が承認した1つのサイトへの、読み取り専用の L1 診断1回だけです。

- 行番号は、この文書を作成した `main` `060678c` のものです。挙動についての記述には、読んだコードかテストの `ファイル:行` を付けています。
- 手順は、ローカルの模擬サイトで通しで練習できます（§9、`scripts/rehearse_real_l1.py`）。練習では実サイト・実 DNS・外部 LLM・有料 API に一切通信しません。
- **この文書を書いた時点で、実サイトへの通信は一度も行っていません。** 実サイトでしか確かめられない点は §10 に「未確認」として挙げています。

---

## 0. この手順書で行うこと・行わないこと

| 行うこと | 行わないこと |
|---|---|
| 所有者が承認した1サイトの登録 → DNS TXT による所有確認 → 範囲確認 → L1 を1回 → 監視 → 緊急停止の訓練 → 監査の検証 → レポートの回収 → 範囲の取り消し | L2（侵入の実証）、修正後の再検証、追加の固定検査（`/server-status?auto`）、ARTEX・外部 LLM による計画や解説、2回目以降の実行 |

---

## 1. 前提条件（すべて満たすまで始めない）

### 1.1 所有者の承認（書面）

承認書には、少なくとも次を書いてもらいます。どれか1つでも欠けていれば始めません。

| 項目 | 内容 | 補足 |
|---|---|---|
| 対象サイト | スキーム・ホスト名・ポート（例 `https://stg.example.com`） | 登録した URL のパスは捨てられ、診断は常にサイトの `/` に対して行います（`aegis/ownership.py:71-77`）。`/app` だけを診断することはできません |
| 日時の枠 | 開始と終了の日時（JST） | **コードはこの枠を強制しません。** 範囲確認の有効期限は確認から30日に固定です（`aegis/assessment.py:3586-3587`）。枠の終了時に §3 Step 9 で手動で取り消します |
| 実行回数の上限 | **1回** | **コードは「承認ごとの回数」を強制しません。** 強制されるのは、1回の診断で GET 1回（§4）と、組織ごとに1時間10回の上限だけです（`aegis/server.py:92`）。2回目を始めないことは運用で守ります |
| 送信元 | Vulnix のコントロールプレーンの送信元 IP | 所有者がアクセスログで照合するために使います |
| 停止の連絡先 | 所有者側で「止めて」と言える人と連絡手段 | |
| 承認者 | Vulnix 側で範囲確認と取り消しを行う人（承認責任者の役割） | §2 |

### 1.2 セキュリティレビューの状態

- 外部の人による正式なレビュー（Gate D）は、公開の前に必要とされ、まだ完了していません（`docs/V1_COMPLETION.md:62`）。
- レビュー資料（ブランチ `claude/security-review-packet` の `docs/security_review/README.md:45`）は、**実サイトの所有確認と読み取り専用の L1 を、レビューの5領域に含めていません。**
- したがって、初回の実施には「この L1 の経路は外部レビューの対象外である」ことを所有者が承知していることを、承認書に明記してもらいます。明記がなければ始めません。

### 1.3 設定値（コントロールプレーンを起動する環境で設定し、起動ログと `/api/auth/me` で確認する）

| 設定 | 値 | 理由（コード） |
|---|---|---|
| `VULNIX_REAL_SERVICE_DIAGNOSIS` | `l1` | `l1` は所有確認と読み取り専用 L1 だけを許す（`aegis/server.py:67-75`）。`1`（旧来の広い設定）は使わない。`0` は実サイトへの通信をすべて拒否（`aegis/server.py:858-866`） |
| `AEGIS_SEPARATE_L2_APPROVER` | `1` | 依頼者と承認者を分ける（`aegis/assessment.py:351-355`）。L1 自体はこの設定に依存しませんが、誤設定の検出のために揃えます |
| `VULNIX_REAL_SITE_LOCAL_ARTEX` | `0`（未設定） | `1` のときだけ実サイト向け ARTEX 計画の経路が開く（`aegis/assessment.py:447`、`aegis/server.py:306-309`） |
| `VULNIX_REAL_SITE_INITIAL_ARTEX` | `0`（未設定） | `1` かつ他の条件が揃うと、ARTEX が `/server-status?auto` の追加 GET を計画できる（`aegis/assessment.py:4759-4811`） |
| `VULNIX_REAL_SITE_SAFE_AI` | `0`（未設定） | `1` のときだけ実サイトの所見を（固定項目で）外部モデルに送る経路が開く（`aegis/assessment.py:444`, `:5456-5458`） |
| `VULNIX_ABLITERATION_*`、`VULNIX_MODEL_*`、`AEGIS_MODEL_*` | 未設定 | 外部モデルの接続先（`aegis/router.py:176-192`）。実サイトの計画は内蔵プランナーだけ（`aegis/assessment.py:4664-4666`）ですが、初回は外部モデル自体を設定しない |
| `VULNIX_EXTERNAL_PROPOSALS` | `0` | 外部モデルからの提案を使わない（`aegis/assessment.py:432-439`） |
| `AEGIS_ENV` | 未設定（本番モード） | `development` は開発専用の緩和を有効にする（`aegis/server.py:53-56`） |
| `VULNIX_TEST_CA_FILE` | 未設定 | 開発モード以外で実サービスに私設 CA を使わない（`aegis/assessment.py:1168-1173`） |
| `VULNIX_AUDIT_ANCHOR_SOCKET` / `_UID` / `_SOURCE` | 別 OS ユーザーの監査アンカーを指す（`docs/AUDIT_ANCHOR.md`「動かし方」） | 監査ログの巻き戻しを検知する。起動時に「照合済み（保護あり）」と表示されること（`aegis/server.py:1764-1767`）。表示されない場合は、そのことを承認書に書いて所有者の判断を得る |

範囲確認の画面・API では、追加の固定検査（`allow_status_probe`）を**有効にしない**でください。上の ARTEX の設定がない限り、API は 409 で拒否します（`aegis/server.py:1393-1396`）。

### 1.4 監査アンカーの起点（anchor）

開始前に、アンカーの現在の先頭を記録します（`python3 -m aegis.audit_anchor verify --dir <アンカーのディレクトリ>`、`aegis/audit_anchor.py:489-499`）。この値を「開始前の起点」として §7 の記録に残します。

---

## 2. 役割

| 役割 | 担当すること | Vulnix の役割（`ARCHITECTURE.md:40-46`） |
|---|---|---|
| 所有者 | 承認書の作成、DNS TXT の設置と撤去、アクセスログの提供、いつでも停止を求める | （Vulnix のアカウントは不要） |
| 承認責任者 | 範囲確認（`/api/assets/confirm-scope` は approver が必須、`aegis/server.py:1390-1392`）、範囲の取り消し（実サービスの削除は approver が必須、`aegis/server.py:1430-1434`） | approver |
| 実施者 | サイトの登録、所有確認の実行、診断の開始（operator 以上が必要、`aegis/server.py:869-872`） | runner（operator） |
| 監視者 | 画面とアクセスログの監視、中止条件を見たら緊急停止 | viewer で可（緊急停止と一時停止は全メンバーに開いている、`aegis/server.py:869-872`、`:291`） |
| 記録者 | §7 の記録 | viewer |

承認責任者と実施者は別の人にします（L1 についてはコードが強制しないため、運用で守ります）。

---

## 3. 手順

> 各 Step の「確認」がすべて満たされなければ、次へ進まず §5 の中止条件に従います。

### Step 1：サイトを登録する（実施者）

- 操作：サイト管理で URL を入力（`POST /api/assets/challenge`、`aegis/server.py:1277-1298` → `issue_ownership_challenge`、`aegis/assessment.py:3190-3331`）。
- 起きること：所有確認待ちの資産が作られ、確認用の値が発行されます。**サイトへの通信は起きません。**
  - 確認用の値は組織ごとの秘密値から作られるため、同じサイトでも組織ごとに異なります（`aegis/assessment.py:362-364`, `:3205`、`aegis/ownership.py:82-91`）。
  - 所有確認と範囲確認が済むまで、名前は解決されず（`aegis/assessment.py:1040-1047`）、ワークスペースにも切り替えられません（`aegis/assessment.py:3051-3054`）。
- 確認：資産の状態が「所有確認待ち」。監査ログに `asset.challenge_issued`。

### Step 2：所有確認（所有者が DNS TXT を置き、実施者が確認を実行）

- **方式は DNS TXT を使います。** 所有者は次のレコードを置きます（`aegis/ownership.py:82-91`）。

  | 名前 | 種類 | 値 |
  |---|---|---|
  | `_vulnix-verify.<ホスト名>` | TXT | `vulnix-verify=<24桁の16進>`（画面に表示された値をそのまま） |

  - TXT の文字列が値と**完全一致**したときだけ確認になります（`aegis/ownership.py:198-215`）。
  - Vulnix は `nslookup -q=txt _vulnix-verify.<ホスト名>.` を実行します（`aegis/ownership.py:94-103`）。**サイト自体への HTTP 通信はありません。**
- 検証ファイル方式（`/.well-known/vulnix-verify.txt`）は使いません。サイトへの GET が増え（`aegis/ownership.py:147-168`、初回の接続先の照合でも取得し直す `aegis/assessment.py:1117-1122`）、https の443番以外を診断できない（`aegis/assessment.py:3568-3572`）ためです。Google での確認は、設定がない環境では使えません（`docs/PUBLIC_BETA.md:93-106`）。
- 操作：「所有確認」（`POST /api/assets/verify-ownership`、`aegis/server.py:1370-1389` → `verify_asset_ownership`、`aegis/assessment.py:3333-3485`）。組織ごとに1時間20回まで（`aegis/server.py:90`, `:886-889`）。
- 確認：`verified: true`、`l2_auto_approved: false`（`aegis/assessment.py:3479-3485`）。監査ログに `asset.ownership_verified`。
- **TXT レコードは Step 9 が終わるまで消さないよう所有者に依頼します。** 初回の L1 の直前に、Vulnix は同じ TXT をもう一度確かめます（接続先のアドレスが未確認のため、`aegis/assessment.py:1092-1128`）。確かめられなければ範囲は取り消され、何も送りません（`aegis/assessment.py:1150-1160`）。

### Step 3：範囲を確認する（承認責任者）

- 操作：「範囲を確認」（`POST /api/assets/confirm-scope`、`confirmed_prohibited: true` が必須、`aegis/server.py:1390-1410` → `confirm_asset_scope`、`aegis/assessment.py:3487-3624`）。
  - 所有確認から24時間以内であること（`aegis/assessment.py:285`, `:3542-3543`）。
  - 確認したスキーム・ポートは、所有確認時のものと一致する必要があります（`aegis/assessment.py:3551-3566`）。
  - 禁止事項（本番データの取得、データの変更・削除、高負荷、リダイレクト先の自動追加、L2 の自動承認）が範囲の条件として表示されます（`aegis/ownership.py:25-31`）。
- 確認：
  - 画面・スナップショットの許可範囲が、承認書のホスト1つだけ（`authorization.scope.hosts`）。
  - `real_site_read_only: true`（組織の API では常に true、`aegis/server.py:350-354`）。
  - `allow_status_probe: false`。
  - 監査ログに `asset.scope_confirmed`（`l2_auto_approved: false`、`allow_status_probe: false`）。
  - **この時点でもサイトへの通信は0件**（アクセスログで所有者と確認）。

### Step 4：L1 を1回だけ実行する（実施者）

- 操作：「診断を開始」（`POST /api/assessments/{id}/start`、`aegis/server.py:1483-1486` → `start`、`aegis/assessment.py:3857-3868`）。組織ごとに1時間10回・全体で200回まで（`aegis/server.py:92-93`, `:890-893`）。
- 開始時に、この実行だけの通信枠（GET `/` を1回）が署名付きの台帳に作られます（`aegis/assessment.py:1278-1298`）。

#### 4.1 L1 が送るリクエスト（これ以外は送らない）

<!-- rehearsal:l1-requests:begin -->
```text
GET /
```
<!-- rehearsal:l1-requests:end -->

上のブロックは練習スクリプトが読み取り、模擬サイトが受けたリクエストと照合します（§9）。

| 項目 | 値 | 根拠 |
|---|---|---|
| 回数 | 1回の診断につき **1回** | 実行する手順は固定の GET 1つだけ（`aegis/assessment.py:4719-4731`）。通信枠は `/` を1回だけ許し、2回目は Worker を起動せずに拒否（`aegis/assessment.py:1242-1268`、テスト `tests/test_real_service.py:1213-1250`） |
| メソッド | `GET` | `aegis/assessment.py:4730`。ツールが許すのは `HEAD` と `GET` だけ（`aegis/gateway.py:80-81`） |
| パス | `/`（登録 URL のパスは使わない） | `aegis/ownership.py:71-77`、通信枠は `dest.path == "/"` のときだけ（`aegis/assessment.py:1253-1255`） |
| 宛先 | 登録したホストを名前解決し、**そのアドレスに固定**して接続。Worker 自身は名前解決しない | `aegis/network.py:73-112`、`aegis/workers/http_probe.py:3-4`, `:324` |
| 宛先の制限 | 公開アドレス以外（プライベート・ループバックなど）に解決されたら送らない | `aegis/assessment.py:1060-1063`、テスト `tests/test_real_service.py:558-570` |
| 送信制限 | Worker は固定したアドレスとポート以外へ接続できない（egress sentinel） | `aegis/gateway.py:74-76` |
| ヘッダー | `Host: <ホスト名>`、`User-Agent: aegis-probe/0.1`、`Origin: https://untrusted-origin.example`（CORS の確認用）。`Authorization`・`Cookie` は送らない | `aegis/workers/http_probe.py:336-340`, `:520`（Gateway は `--origin` を渡さない、`aegis/gateway.py:67-71`） |
| 本文 | なし | `aegis/workers/http_probe.py:347` |
| リダイレクト | **追わない**（`Location` を記録するだけ） | `aegis/workers/http_probe.py:3-4`, `:395` |
| TLS | https のときは証明書を検証。失敗すれば送信前に失敗として終わる | `aegis/workers/http_probe.py:326-335`, `:233-234` |
| 受信量 | 本文は先頭 4 KiB まで | `aegis/workers/http_probe.py:358` |
| タイムアウト | 接続 8 秒・TLS 8 秒・最初の応答バイトまで 30 秒・全体 45 秒。Gateway は 50 秒で Worker を終了 | `aegis/workers/http_probe.py:44-47`、`aegis/gateway.py:82-84` |
| 同時実行 | Worker は最大2つ（この手順では1つ） | `aegis/assessment.py:408` |
| 名前解決 | 範囲の照合とGatewayの送信前に、それぞれ名前解決する（DNS の問い合わせで、サイトへの HTTP ではない） | `aegis/assessment.py:4701-4702`、`aegis/gateway.py:270`、`aegis/network.py:39-40` |
| 応答の扱い | `Set-Cookie` の値は保存前に `[REDACTED]` に置き換える | `aegis/workers/http_probe.py:83-138`, `:376-382` |

送らないもの：L2 の検査（模擬ラボの `idor` / `cve_2021_41773` / `sqli` は実サイトでは最後の段階でも拒否、`aegis/assessment.py:5051-5056`）、再検証・L2 の依頼（`aegis/assessment.py:3969-3978` を `request_l2_run`・`verify_finding`・`verify_fix` が呼ぶ、`:4008`, `:4063`, `:4421`）、計画からの L2（`aegis/assessment.py:2686-2690`）。HTTP 層でも、L1 以外の操作は 403 になります（`aegis/server.py:298-311`, `:858-866`）。

- 確認：状態が「診断済み」（`completed`）、検証フェーズが `skipped`（`aegis/assessment.py:4824-4833`）。

### Step 5：監視する（監視者）

実行中と完了後に、次を確認します。

| 見るもの | 期待する値 |
|---|---|
| 画面の「いま行っていること」 | 「公開設定を検査（GET 1回・非破壊）」（`aegis/assessment.py:4707`） |
| 所有者のアクセスログ（送信元 IP で絞る） | `GET /` が1件だけ。`User-Agent: aegis-probe/0.1` |
| 監査ログ（`GET /api/assessments/{id}/logs`、`aegis/server.py:549-550`） | `approval.auto`（`policy:auto-L1`）→ `allow`（`dest.path` が `/`）→ `scan.request_reserved`（`check: root_l1`）→ `result` がそれぞれ1件（`aegis/assessment.py:5057-5061`、`aegis/gateway.py:282-283`、`aegis/assessment.py:1267-1268`） |
| 承認（`approvals`） | 空 |
| 所見の証拠 | すべてに `audit_hash` が付いている（`aegis/assessment.py:5118-5129`） |

**完了したら、この時点でレポートを保存します**（Step 8 と同じ操作）。Step 6 の訓練のあとは、レポートの診断状態が「中止」と表示されるためです（`aegis/assessment.py:3963`, `:6044-6046`）。

### Step 6：緊急停止の訓練（監視者）

- **完了後に行います。** 実行中に止める訓練は、サイトへの通信を増やさないためにローカルの練習（§9 の手順12）でだけ行います。
- 操作：「緊急停止」（`POST /api/assessments/{id}/emergency-stop`、`aegis/server.py:1506-1512` → `emergency_stop`、`aegis/assessment.py:3923-3967`）。
- 起きること（`aegis/gateway.py:439-469`）：新しい操作の遮断 → トークンの失効 → 送信の遮断 → Worker の終了 → 監査への記録 → 確認。
- 確認：
  - 停止報告の `confirmed: true`、`survivors` が空。手順名が `1_block_new_actions` から `6_confirmed` まで。
  - 状態が「中止」（`stopped`）。
  - 停止中は、所有確認（`aegis/assessment.py:3355-3358`）・開始（`aegis/assessment.py:3859-3860`）・送信（`aegis/network.py:73-75`）が拒否される。
- **「再診断を実行」を押さないこと。** 停止を解除する唯一の操作で（`aegis/assessment.py:3887`）、新しい通信枠を作り GET `/` をもう1回送ります（`aegis/assessment.py:3892`、テスト `tests/test_real_service.py:1236-1250`）。

### Step 7：監査チェーンとアンカーを検証する（記録者）

1. 組織の監査ログ（`<data>/orgs/<組織ID>/audit.jsonl`、`ARCHITECTURE.md:12`, `:36`）のハッシュチェーンを検証します（`aegis/audit.py:296-308`）。
   ```sh
   VULNIX_NO_ENV_LOCAL=1 python3 -c 'import sys; from aegis.audit import AuditLog; e, ok = AuditLog(sys.argv[1]).verified_entries(); print(len(e), ok)' <audit.jsonl のパス>
   ```
   `True` であること。
2. アンカーの先頭を表示し（`aegis/audit_anchor.py:489-499`）、`seq` 番目（1始まり）の記録の `hash` が一致することを確かめます。§1.4 の起点より `seq` が進んでいること。
3. 画面またはスナップショットの `audit_anchor` が `protected: true`、`error: null`（`docs/AUDIT_ANCHOR.md`「状態表示」、`aegis/audit.py:193-203`）。

### Step 8：レポートを回収する（記録者）

- 操作：`GET /api/assessments/{id}/report`（`aegis/server.py:561-563`）。Step 5 で保存したもの（診断済み）と、この時点のもの（中止）の両方を保存します。
- 確認：「所有確認済みの実サービス」「L2はこの公開βで実行しません」と書かれていること（テスト `tests/test_real_service.py:595-600`）。ファイルの SHA-256 を記録します。

### Step 9：範囲を取り消す（承認責任者）

- 操作：サイト管理で対象を削除（`POST /api/assets/delete`、`aegis/server.py:1430-1439` → `delete_asset`、`aegis/assessment.py:3092-3150`）。実行中・一時停止中は削除できないので、先に停止します（`aegis/assessment.py:3094-3100`）。
- 起きること：範囲と所有確認の記録が消え、名前は実サービスとして記録されたまま残ります（ラボの別名にはならない、`aegis/assessment.py:3152-3165`）。以後、名前は解決されません（`aegis/assessment.py:1040-1047`）。
- **範囲だけを取り消して資産を残す操作はありません。** 取り消しは削除で行います（§8 の差異 D2）。
- 確認：監査ログに `asset.deleted`。所有者のアクセスログで、それ以降の通信が0件。
- 所有者に TXT レコードの撤去を依頼します。

---

## 4. L1 の要約（所有者への説明用）

1回の診断で、Vulnix は承認されたサイトの `/` に `GET` を1回だけ送ります。認証情報は送らず、リダイレクトは追わず、本文は先頭 4 KiB だけを読みます。45 秒（Gateway で 50 秒）で打ち切ります。そのほかの通信は、DNS の問い合わせ（TXT の確認とホスト名の解決）だけです。根拠は §3 Step 4 の表のとおりです。

---

## 5. 中止条件（1つでも当てはまれば、ただちに緊急停止 → Step 9）

| # | 条件 |
|---|---|
| A1 | 所有者のアクセスログに、`GET /` 以外のリクエスト、または1回の診断で2件以上の `GET /` が記録された |
| A2 | 所有者が停止を求めた。承認書の日時の枠を過ぎた |
| A3 | 診断が開始から 60 秒たっても「診断中」のまま（Worker は 50 秒で終了するはず、`aegis/gateway.py:84`） |
| A4 | 範囲が承認書のホスト以外を含む、ポート・スキームが違う、`allow_status_probe` が true、`real_site_read_only` が false |
| A5 | 監査ログに `asset.scope_revoked_address_change`（接続先が変わり再確認できなかった、`aegis/assessment.py:1154`）、`assessment.failed`、`approval.approved`、`artex.*`、`planner_llm.*` のいずれかが出た |
| A6 | 停止報告が `confirmed: false`、または `survivors` が空でない |
| A7 | 監査チェーンの検証が `False`、またはアンカーの `error` が `null` 以外 |
| A8 | 起動ログ・`/api/auth/me` の設定が §1.3 と違う（例：`real_service_diagnosis: true`、`aegis/server.py:442-443`） |
| A9 | 所有者のサイトでエラーや負荷の増加が見られた |

---

## 6. 戻し方（ロールバック）

1. 緊急停止（Step 6 の操作）。
2. 範囲の取り消し（Step 9 の操作）。実行中なら停止してから削除します。
3. コントロールプレーンを停止します。停止を確認できなかった場合、次の起動では実サービスの許可が保留され、承認者の再確認が必要になります（`aegis/server.py:1794-1800`、`aegis/assessment.py:980-981`）。
4. 実サイトへの通信を全面的に止めるには `VULNIX_REAL_SERVICE_DIAGNOSIS=0` で起動し直します（`aegis/server.py:858-866`）。
5. 所有者に TXT の撤去を依頼し、§7 の記録を共有します。

---

## 7. 記録すること

| 記録 | 内容 |
|---|---|
| 承認書 | 識別子、対象、日時の枠、回数（1）、署名者 |
| 版 | `git rev-parse HEAD`、起動時の設定値（秘密値は書かない） |
| アンカー | 開始前の起点（§1.4）と終了後の先頭（seq・hash） |
| 時刻 | Step 1〜9 の各操作の時刻（JST） |
| 監査ログ | `allow`・`scan.request_reserved`（`run_nonce`）・`result`・`emergency_stop`・`asset.deleted` のハッシュ |
| 停止報告 | `confirmed`、`killed_pids`、`survivors`、手順名 |
| レポート | 2つのファイルの SHA-256 |
| 所有者のアクセスログ | 送信元 IP で絞った該当時間帯の抜粋（件数・メソッド・パス・User-Agent） |
| 逸脱 | 中止条件に当てはまったもの、手順と違ったこと |

---

## 8. コードと運用の差異（この手順書を書いて気づいた点）

安全制御は変更していません。以下は提案です。

| # | 差異 | 場所 |
|---|---|---|
| D1 | 承認の「日時の枠」と「実行回数」はコードで強制されない。範囲の有効期限は30日固定、回数の上限は1時間10回だけ | `aegis/assessment.py:3586-3587`、`aegis/server.py:92` |
| D2 | 範囲だけを取り消す操作がない（削除で取り消す） | `aegis/assessment.py:3092-3165` |
| D3 | 登録 URL のパスは捨てられ、L1 は常に `/` を取得する。サイトの一部だけの承認には合わない | `aegis/ownership.py:71-77` |
| D4 | 完了後に緊急停止すると、完了した診断の状態とレポートが「中止」になる | `aegis/assessment.py:3963`, `:6044-6046` |
| D5 | L1 の範囲確認者と開始者を分けることは強制されない（`AEGIS_SEPARATE_L2_APPROVER` は L2 だけ） | `aegis/assessment.py:351-355` |
| D6 | 監査ログでは、Gateway の `allow` の記録が、通信枠の予約（`scan.request_reserved`）より先に書かれる。予約に失敗した場合も `allow` は残る（Worker は起動しない） | `aegis/gateway.py:282-292`、`aegis/assessment.py:1261-1268` |
| D7 | 監査ログ単体を検証するコマンドがない（§7 の1行で代用） | `aegis/audit.py:296-308` |
| D8 | `User-Agent` が `aegis-probe/0.1` で、Vulnix の名前を含まない。所有者がログで見分けるには送信元 IP と時刻が必要 | `aegis/workers/http_probe.py:338` |

---

## 9. ローカルでの練習（実サイトに通信しない）

```sh
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.rehearse_real_l1 --out ./out/rehearsal   # 結果は JSON、終了コード 0 が成功
VULNIX_NO_ENV_LOCAL=1 python3 -m unittest tests.test_real_l1_rehearsal
```

- 模擬サイトの名前は予約された `.test` の名前（`rehearsal-l1.vulnix.test`）で、サービスに差し込んだ解決器が `127.0.0.1` に対応付けます（`tests/test_real_service.py:449-455` と同じ方法）。`.test` 以外の名前、ループバック以外のアドレスが1つでもあれば、何も始めずに終了コード 2 で止まります。実行中も、このプロセスからの DNS 問い合わせとループバック以外への接続を拒否します（`scripts/rehearse_real_l1.py:84-163`）。
- 所有確認は、差し込んだ DNS TXT の答えで行います（DNS には問い合わせません）。
- 設定は §1.3 と同じ値をプロセス内で使い、外部モデル・ARTEX・Google・アンカーの環境変数を外します（`scripts/rehearse_real_l1.py:572-585`）。

| 練習の手順 | 手順書 | 確かめること |
|---|---|---|
| 0 | §1.3 | `l1` が L1 専用、旧来の L2 スイッチがオフ、上限 10回/時・20回/時 |
| 1 | Step 1 | 登録だけでは通信・名前解決・ワークスペースの切り替え・範囲確認がない |
| 2 | Step 2 | 違う TXT は拒否、正しい TXT で確認、L2 は自動承認されない、サイトへの通信 0 件 |
| 3 | Step 3 | 範囲はホスト1つ、読み取り専用、追加検査なし、通信 0 件 |
| 4 | Step 4 | 模擬サイトが受けたのは §4.1 のブロックと同じリクエストだけ。ヘッダーも表のとおり、接続も1回 |
| 5 | Step 5 | L2 のフェーズは skipped、承認なし、`allow` と `result` が1件ずつ、証拠に監査ハッシュ。レポートは「診断済み」 |
| 6 | §4.1 送らないもの | L2 の依頼・再検証は拒否、通信は増えない |
| 7 | Step 6 | 停止の確認、Gateway の停止、送信の遮断、開始・所有確認の拒否 |
| 8 | Step 7 | チェーンの検証、アンカーの先頭とチェーンの一致、1項目を変えた写しは検証に失敗 |
| 9 | Step 8 | レポートにサイト名と「L2はこの公開βで実行しません」、Cookie の値はない |
| 10 | Step 9 | 範囲と所有確認の記録が消え、名前は解決されず、範囲確認もできない |
| 11 | 全体 | 模擬サイトが受けたのは §4.1 のリクエストだけ |
| 12 | §5 | GET の応答待ちの最中に緊急停止：Worker を終了・確認、結果は採用しない、通信は増えない |
| 13 | §4.1 送らないもの | 模擬ラボの攻撃用検査（`idor`・`cve_2021_41773`・`sqli`）を直接呼んでも、Worker を起動せずに拒否 |

§4.1 のブロックを書き換えると、練習の手順4が失敗します（`tests/test_real_l1_rehearsal.py`）。手順書とコードのずれを見つけるためです。

---

## 10. 練習で確かめられないこと（未確認）

| 項目 | 理由 |
|---|---|
| 実 DNS での TXT の確認、ホスト名の解決 | 練習は差し込んだ答えを使う |
| 初回の接続先アドレスの再確認（`aegis/assessment.py:1079-1160`）と、公開アドレス以外の拒否 | 練習はループバックを許す `allow_loopback_test`（サービスの内部だけで設定でき、API からは設定できない）を使うため、この経路を通らない（`aegis/assessment.py:1051`, `:1060`, `:1065-1066`）。既存のテストでは確認済み（`tests/test_real_service.py:558-570`） |
| TLS（証明書の検証） | 練習は http |
| HTTP 層（組織の分離、403、回数の上限、役割） | 練習はサービスを直接呼ぶ。既存のテスト `tests/test_tenancy.py:1898`, `:2395`, `:2476` で確認済み |
| 別 OS ユーザーのアンカー（`protected: true`） | 練習は同じユーザーで動かすため `same_user`（`aegis/audit.py:198-201`）。Linux CI の別ジョブで確認（`docs/AUDIT_ANCHOR.md`） |
| 所有者のサイトの実際の応答・負荷 | 実サイトに通信していない |

---

## 11. チェックリスト

| # | 項目 | 担当 | 済 |
|---|---|---|---|
| 1 | 承認書（サイト・日時の枠・回数1・送信元・停止連絡先・承認者・レビュー対象外の承知） | 所有者 | ☐ |
| 2 | §1.3 の設定値を起動ログと `/api/auth/me` で確認 | 実施者 | ☐ |
| 3 | アンカーが「保護あり」、開始前の起点を記録 | 記録者 | ☐ |
| 4 | §9 の練習が成功（同じコミットで） | 実施者 | ☐ |
| 5 | Step 1：登録、通信0件 | 実施者 | ☐ |
| 6 | Step 2：TXT 設置、所有確認、`l2_auto_approved: false` | 所有者・実施者 | ☐ |
| 7 | Step 3：範囲はホスト1つ、`allow_status_probe: false`、通信0件 | 承認責任者 | ☐ |
| 8 | Step 4：開始（1回だけ） | 実施者 | ☐ |
| 9 | Step 5：アクセスログに `GET /` 1件、監査ログの順序、レポート保存（診断済み） | 監視者・記録者 | ☐ |
| 10 | Step 6：緊急停止 `confirmed: true`、再診断を押さない | 監視者 | ☐ |
| 11 | Step 7：チェーン `True`、アンカーの先頭が一致 | 記録者 | ☐ |
| 12 | Step 8：レポート保存（中止）、SHA-256 記録 | 記録者 | ☐ |
| 13 | Step 9：削除、`asset.deleted`、以後の通信0件、TXT 撤去の依頼 | 承認責任者 | ☐ |
| 14 | §7 の記録を所有者と共有 | 記録者 | ☐ |
