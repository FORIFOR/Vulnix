# 利用体験（6段階ユーザージャーニー）の通し検証と異常系E2E

更新日: 2026-11-19 JST
対応判定表: [GOAL_COMPLETION_MATRIX.md](GOAL_COMPLETION_MATRIX.md) / 失効詳細: [PR85_REVOKE_BROWSER_QA.md](PR85_REVOKE_BROWSER_QA.md) / ブラウザ回帰: [QA_BROWSER_INTEGRATION.md](QA_BROWSER_INTEGRATION.md)

本資料は、ユーザーがVulnixを利用する**6段階のジャーニー（①URL登録 → ②所有確認・範囲確定 → ③診断開始 → ④結果・証拠表示 → ⑤修正手順の確認 → ⑥再診断による改善確認）**を、ローカル模擬サイトおよび本番ビルド（Next.js `next build` / `next start` + Playwright Chromium）で通し検証した結果をまとめる。実サイト通信と有料API呼び出しはいずれも **0回** である。

---

## 1. 6段階ユーザージャーニーの通し検証（390px / 1280px）

再現コマンド:
```bash
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --viewport-width 390
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --chromium --viewport-width 1280
VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_lab_recheck
```

| 段階 | 画面・ユーザー操作 | バックエンドAPI / 処理 | 390px 実測 | 1280px 実測 | 確認した合格条件 |
| --- | --- | --- | --- | --- | --- |
| **1. URL登録** | ウィザードを開き対象URL（`http://owned-status.lab.test:<port>/`）を入力し確認コードを発行（操作1〜3） | `POST /api/assets/challenge` | 成功（対象通信0回） | 成功（対象通信0回） | 登録時点では対象へ通信せず、DNS TXT / `.well-known` トークンを発行 |
| **2. 所有確認・範囲確定** | 所有確認を実行し、禁止事項への同意と追加L1確認の同意を選択して範囲を確定（操作4〜6） | `POST /api/assets/verify-ownership`, `POST /api/assets/confirm-scope` | 成功（署名付き台帳保存） | 成功（署名付き台帳保存） | 所有証明とスコープ・期限・同意が署名付き台帳に記録される |
| **3. 診断開始** | 「診断を開始」を押下（操作7） | `POST /api/assessments/scan_001/start` → Gateway → `http_probe` / `status_marker` Worker | 開始から可視所見まで **0.923秒**（対象GET 2回: `/`, `/server-status?auto`） | 開始から可視所見まで **0.906秒**（対象GET 2回: `/`, `/server-status?auto`） | 許可された2パスのみGET、実サイトL2準備欄は非表示、ページエラー0 |
| **4. 結果・証拠表示** | 「結果」タブおよび所見詳細ページを開き、危険度・検証状態・観測事実・未実証事項・証拠ID・監査ハッシュ・出所を確認（操作8） | `GET /api/assessments/scan_001`, `/logs`, `/events` | 8操作・API 12回で到達、`status_finding=detected`、横スクロールなし | 8操作・API 12回で到達、`status_finding=detected`、横スクロールなし | `candidate` を問題件数に混ぜず、Set-Cookie秘密値を含まず、計画元 `unverified` を実ARTEXと誤表示しない |
| **5. 修正手順・学習確認** | 所見詳細の「この結果をひと目で理解」「どう直すか」「？」3段階解説ポップオーバーを確認 | `FindingLearningCard`, `RemediationPanel`, `ExplanationPanel` | 320〜720pxでポップオーバー見切れ0、3段階切替と修正後確認方法を表示 | 1280pxで全12項目と修正手順・確認方法を表示 | 初心者向けの解説と具体的な設定例・確認方法が表示される |
| **6. 再診断による改善確認** | 修正適用後に「防御パッチ適用・再検証」（または「再検証する」）を実行し、修正前後の証拠と状態遷移を確認 | `POST /api/assessments/scan_001/verify-fix` → Gateway → Worker | `proven`（HTTP 200）→ `not_reproduced`（HTTP 403）、新旧証拠ID両方表示、横スクロール0・エラー0 | バックエンド統合およびUIで `detected`/`proven` → `not_reproduced` とスコア低下を確認 | 修正前の証拠を保持したまま最新の証拠IDで `not_reproduced` に更新される |

- **Linux CI でのピン留め実ARTEXバイナリ通し検証**:
  - `VULNIX_NO_ENV_LOCAL=1 python3 -m scripts.bench_browser_owned_flow --production --real-artex --chromium`（CI #44419117701 `artex-real-planner` ジョブで PASS）：390px、8操作、API 12回、ローカル模擬モデル呼び出し2回、モデル入力に対象ホスト名・URLが含まれないこと（`model_input_excludes_host=true`）、画面に実ARTEXエンジンとモデル名が表示されること（`engine_and_model_visible=true`）、ページエラー0を確認済み。

---

## 2. テスト条件マトリクス（正常・脆弱・修正後・異常系13条件）

| テスト条件 | 検証手段 / 再現スクリプト・テスト | 確認結果（PASS / 観測値） |
| --- | --- | --- |
| **1. 390px（モバイル幅）** | `bench_browser_owned_flow --viewport-width 390`, `bench_browser_lab_recheck`, `check_cookie_ui_390` | **PASS**: 8操作・API 12回・0.923秒で結果到達、Cookie混在3判定・IDOR再確認・ヘルプポップオーバーすべて横スクロール0・ページエラー0。 |
| **2. 1280px（デスクトップ幅）** | `bench_browser_owned_flow --viewport-width 1280` | **PASS**: 8操作・API 12回・0.906秒で結果到達、横スクロール0・ページエラー0。 |
| **3. 正常サイト** | `test_final_review.py::test_clean_response_has_no_findings`, `test_cookie_purpose_lab.py`（`session_full`, `language_plain`）, `test_cors_policy_lab.py` | **PASS**: 保護属性が揃ったCookie、HSTS/CSP/XCTO設定済み、公開ワイルドカードCORS（資格情報なし）、HTTP 200認証拒否JSONでは誤検知（FP）0件、完了見出しは「問題を確認していません（未検査項目が安全という意味ではありません）」。 |
| **4. 問題のあるサイト** | `bench_browser_owned_flow`, `test_cookie_purpose_lab.py`, `test_cors_policy_lab.py`, `test_status_exposure_lab.py` | **PASS**: ヘッダー欠落・Cookie属性不足・資格情報付きCORS反射・Apache `mod_status` 露出を `detected`（L1観測）として検出し、隔離ラボのIDOR/SQLi/CVE-2021-41773再現のみを `proven`（L2実証）として記録。新規発行Set-Cookie秘密値は一切残らない。 |
| **5. 修正後サイト** | `bench_browser_lab_recheck`, `test_cookie_purpose_lab.py::test_fix_recheck_preserves_owner_cookie_purpose`, `test_cors_policy_lab.py` | **PASS**: 再診断により `detected` / `proven` から `not_reproduced` へ更新され、防御比較（`defense_comparison`）に修正前後の状態と最新証拠IDが記録される。 |
| **6. 所有確認失敗** | `test_real_service.py`, `test_google_ownership.py`, `test_tenancy.py` | **PASS**: DNS TXT不一致、`.well-known` ステータス/内容不一致、プライベートIP、Google権原なし時は所有証明を発行せず、診断開始を拒否（対象への診断GET 0回）。 |
| **7. セッション失効（単一タブ・遅延応答・複数タブ）** | `bench_browser_owned_flow --revoke-session`, `--logout-after-result`, `--stale-auth-after-logout`, `--cross-tab-logout`（390px/1280px） | **PASS**: ログアウト直後に保護画面を非表示（0.122/0.115秒）、新規GETは401。遅延した古い `/api/auth/me` 200が後から到着しても画面は復活しない。2タブ同時表示でも0.049/0.017秒で他タブの所見を隠す。 |
| **8. 組織切替・診断中の組織除名** | `bench_browser_owned_flow --org-switch`, `--remove-member-during-scan`（390px/1280px）, `test_tenancy.py`（590+件） | **PASS**: 別組織へ切り替えると元の対象名や所見・レポートは一切表示されず、元の組織へ戻すと再表示。診断中に除名された場合は元組織への新規GETが403で遮断され所見が消える。 |
| **9. SSE切断・再接続・無通知変更** | `bench_browser_owned_flow --reconnect-events`, `--block-events --silent-change`（390px/1280px） | **PASS**: 初回SSE切断後に自動再接続し、SSE完全遮断時もバックアップポーリングで結果到達。心拍中にイベント通知なしで所見が変化しても定期正式再取得で収束する。 |
| **10. AI応答失敗** | `test_planner_llm_gateway.py`, `test_real_service.py`, `test_ai_advisor.py` | **PASS**: ARTEXのモデルが `length` / `content_filter` / 本文なし / 過大usage で失敗した場合は計画を破棄し、初回に測定した固定L1所見と監査ハッシュを保持する。AI解説が失敗・不採用の場合は内蔵の日本語解説へ自動フォールバックする。 |
| **11. CVE資料未取得・期限超過・バージョン不明** | `test_cve.py`, `web/tests/labels.test.mjs` | **PASS**: CVEステータス未取得時は「脅威情報の件数を取得できていません。」、空カタログ時は「CVEフィード未取得のためCVE照合は未実施」、バージョン番号なしバナーは「バージョン番号が含まれないためCVE照合は未判定」と表示し、「脆弱性なし」と偽らない。 |
| **12. Worker停止・タイムアウト・未停止生存** | `test_gateway.py`, `test_worker_deadline.py`, `test_http_probe_timeouts.py` | **PASS**: 緊急停止で実行中Workerプロセスグループを即座にSIGKILL（ローカル実測約26ms、上限5秒以内）し、再開を拒否。タイムアウト時に停止確認できないWorkerがあれば `unstopped_workers` に記録し新規Worker起動を全面停止（fail-closed）。 |
| **13. 所有確認中・レポート生成中の権限失効** | `bench_browser_owned_flow --revoke-during-ownership`, `--revoke-during-report`（390px/1280px）, `test_tenancy.py` | **PASS**: DNS照会中の失効はHTTP 401・証明保存なし・対象GET 0回。レポート生成中の失効はHTTP 401・レポート本文非送信・旧所見非表示（7.830/7.826秒）。 |

---

## 3. 限界と未検証ゲート

- 上記はすべてループバック模擬サイト（`.test`）およびプロセス内DNS置換による検証であり、**公開β環境での実DNS TXT照会（Gate E）および許可済み実サイトに対するL1通し診断（Gate F）の代替とはしない**。
- 実Abliteration AIを用いた追加検査選択および日本語解説の実通信は、追加の有料API承認が得られるまで実行しない（Gate C）。
