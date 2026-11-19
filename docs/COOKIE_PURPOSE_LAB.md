# Cookie用途別の独立ラボ

独立したループバック対象は `tests/fixtures/cookie_purpose_lab.py`、正解は `cookie_purpose_truth.json`、所有者が提供した用途・SameSite要件は `cookie_owner_specs.json` に分離した。診断器、ARTEX、Gateway、Workerは正解ファイルを参照しない。10条件は**Cookie設定の1分類**であり、10種類の脆弱性を診断できるという意味ではない。

現行の固定L1はCookie名や用途を問わず、属性不足を `detected` にしていた。修正後は、既存のサイト別プロファイルで承認済みの所有者仕様が認証セッション用途を示し、実際の応答属性が不足・不一致の場合だけ `detected` にする。所有者仕様で一般用途と確認されたCookieはセッション所見にしない。用途不明のCookie名から認証用途を推測せず `candidate` に留める。L1から `proven` は出さない。

既存のサイト別プロファイルに任意の `cookie_policy` を追加できる。`status`、認証セッションCookie名の `session`、一般用途として確認した `non_session`、要求する `same_site`、所有者仕様の `evidence` だけを受け付ける。`confirmed` には仕様の根拠が必要で、プロファイル内容のハッシュを管理者が承認していなければ `unaccepted` に戻す。新しい管理画面や診断通信は追加していない。

| 条件 | 正解 | 旧L1 | 修正後 |
| --- | --- | --- | --- |
| 言語設定・テーマ設定・JSで読むCSRF Cookie | 非検出（3条件） | detected×3 | 所見なし×3 |
| セッションのHttpOnly不足・HTTPSでSecure不足・SameSite不足 | detected（3条件） | detected×3 | detected×3 |
| 正常なセッションCookie | 非検出 | 所見なし | 所見なし |
| 所有者仕様Laxに対するSameSite=None | detected | 所見なし | detected |
| 所有者仕様Noneに一致するSameSite=None | 非検出 | 所見なし | 所見なし |
| session風の名前だが用途不明 | candidate | detected | candidate |

同一の10応答を旧コミット `83da580` と修正後の診断関数に適用した1回の測定：

| 指標 | 旧L1 | 修正後 |
| --- | ---: | ---: |
| TP / FP / FN / TN | 3 / 4 / 1 / 2 | 4 / 0 / 0 / 6 |
| Precision / Recall | 42.9% / 75% | 100% / 100% |
| candidate | 0 | 1 |
| 対象GET | 10 | 10 |
| Worker起動 / AI呼び出し / 有料費用 | 0 / 0 / US$0 | 0 / 0 / US$0 |
| 診断関数の合計時間（単発） | 1.495ms | 0.843ms |

時間は単発測定で高速化の証拠ではない。この10条件ラボへの取得はHTTPループバックで、Secure属性の評価にはHTTPSの対象URL条件を診断関数へ与えた。後述のローカルHTTPS検証を除き、Gateway・Workerを通したHTTPS Cookie測定、実サイト、ARTEXの検査選択、実Abliteration AIの品質は未検証である。既存の所有確認・範囲・組織分離・停止の制御は変更していない。

## 続く検証：混在応答とローカルHTTPS

認証Cookie、所有者仕様で一般用途と確認されたCookie、用途不明のCookieが同じ応答にある場合、`cookie_checks` に名前・用途・個別判定・不足属性を保存する。Cookie値は保存・表示しない。結果カードと詳細画面で個別判定を示す。実際の画面部品を本番ビルドのCSSとともに390pxのChromiumで表示し、3件の表示と横スクロールなしを確認した（`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.check_cookie_ui_390`）。これは部品の表示検証であり、公開βのログインから結果表示までの通し検証ではない。

`VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.check_cookie_https` は一時的な証明書を作り、ループバックHTTPS対象の応答を390pxのChromiumで各1 GET取得する。6条件すべてでL1判定と独立ラベルが一致した。HttpOnlyがあるCookieは `document.cookie` に出ず、ないCookieは出た。SecureとSameSiteの保存値も応答属性と一致した。SameSiteを省いた場合、ブラウザの保存値は既定のLaxだが、所有者仕様が要求する明示属性は応答にないため `detected` を維持する。実サイト、実HTTPSの隔離Worker経路、クロスサイト送信によるCSRF成立は未検証である。

## Set-Cookie秘密値の非保存と境界防御（P2解消）

独立読み取りで、対象サイトが新規発行した `Set-Cookie` の生値が `http_probe` Worker の JSON 出力（`headers["Set-Cookie"]` および `set_cookies`）に含まれ、`EncryptedSecretStore.redact` は事前登録済みのL2検証用トークンしかマスクしないため、証拠本文（`evidence[].content`）、`state.json`、`audit.jsonl` の `stdout_preview`、Remotion非匿名エクスポートに認証Cookie値が残り得るP2候補を特定した。

1. **修正前の赤テスト再現**: ローカルHTTPS模擬サイトから `Set-Cookie: session=CANARY_SECRET_VALUE_9f8e7d6c5b4a; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=Lax` と引用符付き `auth="CANARY_QUOTED_\"SECRET;Secure\"_VALUE"; Path=/; Secure; SameSite=Lax` を返し、Gateway→Worker→`AssessmentService`→`snapshot()` まで実行したところ、`snap_json` 内の `evidence[].content` に両秘密値が残ることを赤テスト（`test_newly_issued_set_cookie_secret_is_never_persisted_in_evidence_audit_or_exports`）で再現した。
2. **多層防御の実装**:
   - **Worker境界（`aegis/workers/http_probe.py`）**: `headers` マップに生の `Set-Cookie` / `Set-Cookie2` を入れず、`set_cookies` には各ヘッダーを個別に保持したまま Cookie値を `[REDACTED]` に置換し、名前（最大64文字）と検査用属性（`Secure`, `HttpOnly`, `SameSite`, `Max-Age`, `Path=/|[set]`, `Domain=[set]`, `Expires=[set]`, `Partitioned`）だけを出力する `sanitize_set_cookie_header()` を適用。引用符内のセミコロンを属性区切りと誤認しないパーサーを実装した。
   - **Gateway・Service・永続化境界（`aegis/gateway.py`, `aegis/assessment.py`, `aegis/service_diag.py`, `aegis/evidence.py`）**: Gatewayの `result` 監査記録前と `AssessmentService._exec` の証拠保存前に `sanitize_http_probe_payload()` を再適用し、`enforce_verdict()` で過去バージョンの保存済み証拠を読み込む際にも `Set-Cookie` 生値を除去する。秘密値マスキング（`secret_redactor`）が例外や非文字列を返した場合は安全側に失敗（fail-closed）とし、証拠や監査へ記録しない。
3. **修正後の検証**: 同じローカルHTTPSテストおよびエッジケーステスト（引用符内セミコロン、Expiresカンマ、大文字小文字、空値、重複Set-Cookie、重複属性の不一致検知、20KB巨大ヘッダー、マスキング失敗時の拒否）を含む `tests.test_cookie_purpose_lab` 全10件、`check_cookie_ui_390`、`check_cookie_https` がすべて成功した。
