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
| 診断関数の合計時間（単発） | 1.063ms | 0.682ms |

時間は単発測定で高速化の証拠ではない。ラボへの取得はHTTPループバックで、Secure属性の評価にはHTTPSの対象URL条件を診断関数へ与えた。実HTTPS、Gateway・Workerを通したCookie測定、実サイト、ARTEXの検査選択、実Abliteration AIの品質はこのラボでは未検証である。既存の所有確認・範囲・組織分離・停止の制御は変更していない。
