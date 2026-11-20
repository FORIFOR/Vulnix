# CVE 診断の実用化・データ出所・鮮度・3条件照合

更新日: 2026-11-19 JST
関連コード: `aegis/cve.py`, `aegis/service_diag.py`, `aegis/assessment.py`, `web/src/lib/labels.ts`, `web/src/app/settings/page.tsx`
関連テスト: `tests/test_cve.py`, `tests/test_final_review.py`, `web/tests/labels.test.mjs`

---

## 1. CVE資料の取得・投入・検証・更新経路

| 経路 | 実装関数 / API | 動作と信頼境界 |
| --- | --- | --- |
| **同梱フィード初期化** | `cve.load_feed(FEED_PATH)` / `cve.load_kev_feed(KEV_PATH)` | `aegis/feeds/nvd-recent.json`（NVD CVE API 2.0形式）および `aegis/feeds/cisa-kev.json`（CISA KEV形式）を起動時に読み込み、ファイルの SHA-256（`nvd_sha256`, `kev_sha256`）を記録する。ファイル欠損時は最小限の `_BUILTIN` カタログへ安全にフォールバックする。 |
| **管理者による手動同期** | `POST /api/cve/sync` → `FeedMonitor.ingest_payloads` | プラットフォーム `admin` / `approver` 権限および送信時の生存セッション確認（`_authorized_platform_read`）を要求する。リクエストで与えられた JSON オブジェクトからアプリケーション CPE（`cpe:2.3:a:...`）のみを抽出し、ペイロードの正規化 SHA-256 と同期日時・出所（`sync_source`）を記録する。通常診断中に外部へ自動通信しない。 |
| **URL指定同期（運用・テスト用）** | `FeedMonitor.sync_from_urls` | 指定された NVD / KEV URL から取得して `ingest_payloads` へ渡す。通信失敗や不正 JSON 時は**既存のカタログ・前回同期日時・SHA-256 をそのまま保持**し、`last_sync_error` と `last_error_at` に失敗原因を記録する。 |
| **状態参照API・UI表示** | `GET /api/cve/status` → `FeedMonitor.status` → `threatFeedSummary` | 件数（`cve_count`, `kev_count`）、最終同期時刻（`last_synced_at`）、出所（`sync_source`）、鮮度（`fresh` / `stale` / `unfetched`）、7日超過フラグ（`stale`）、完全性ハッシュ（`nvd_sha256`, `kev_sha256`）、直近同期エラー（`last_sync_error`）を返す。 |

---

## 2. 管理項目と単一製品バージョン範囲の分離

- **管理項目**: 情報源（`sync_source`）、更新日時（`last_synced_at`）、完全性ハッシュ（`nvd_sha256`, `kev_sha256`）、CVE ID（`id`）、対象製品（CPE `product`、エイリアス `apache -> http_server`, `apache-coyote -> tomcat`）、重大度（CVSS v3.1/v3.0/v2 baseSeverity）、CWE ID、影響バージョン範囲（`eq`, `ge`, `gt`, `le`, `lt`）、修正方針（`remediation`）、CISA KEV 悪用確認フラグ（`in_kev`, `due_date`, `ransomware_use`）。
- **複数製品CPEの混線防止**: 1つのCVEエントリに複数の製品（例: メイン製品とバンドル先Webサーバー）が含まれる場合、最初のアプリケーション製品のバージョン範囲だけをその製品に紐付け、別製品のバージョン範囲が混ざって誤検知しないことを `tests/test_final_review.py::TestCveMatchingIsNotCrossWired` で保証している。
- **ホスト入力からの保護**: 診断対象が返す `Server` / `X-Powered-By` ヘッダーは最大512文字・線形正規表現（`_BANNER`）および最大8セグメント9桁のバージョンパーサー（`parse_version`）で処理し、巨大文字列やReDoSによる停止を防ぐ（`TestHostileResponses`）。

---

## 3. 証拠に基づく判定原則（バナー観測 ≠ 脆弱性実証）

1. **バナー一致だけで `proven` にしない**:
   - L1 の `http_probe` が観測した `Server` / `X-Powered-By` ヘッダーは自己申告文字列であり、バックポートパッチ適用やバナー偽装の可能性がある。
   - そのため CVE 一致時の検証状態は常に **`detected`（検出・未実証）** とし、`caveat` に「バナー段階では『検出（未実証）』であり、脆弱性の成立を断定するものではありません」と明記する。`aegis/evidence.py::enforce_verdict` も L1 証拠のみの所見が `proven` になることを禁止している。
2. **バージョン不明時は影響を断定しない**:
   - `Server: Apache` や `X-Powered-By: Express` のように製品名のみでバージョン番号が含まれない場合（`cve.banner_has_version(banner) == False`）、CVE 照合を行わず、所見概要に **「（バージョン番号が含まれないためCVE照合は未判定。既知CVEへの該当有無は断定できません）」** と明示する。
   - また、Cloudflare / Google Frontend / Vercel などのマネージドエッジがバージョンなしで返す標準 `Server` ヘッダー（`MANAGED_EDGE_SERVERS`）は情報露出の誤検知としない。
3. **CVE情報未取得・期限超過・同期失敗の明示**:
   - カタログが空（未取得）の場合は「脆弱性なし」とせず、所見概要に **「（CVEフィード未取得のためCVE照合は未実施）」** と明示する。
   - 設定画面（`threatFeedSummary`）では、ステータス未取得時に「脅威情報の件数を取得できていません。」、空カタログ時に「・フィード未取得」、最終同期から7日（`STALE_SECONDS`）超過時に「・更新期限超過（要同期）」、同期失敗時に「・直近の同期に失敗（以前のデータを保持）」を表示する。

---

## 4. ローカル固定CVE資料による4条件テスト（実証済み）

`tests/test_cve.py`（全21件 PASS）および `web/tests/labels.test.mjs` にて以下を検証済み：

| 条件 | 入力ヘッダー / フィード状態 | 検証結果（`verdict` / `severity` / `cve`） | 表示メッセージ |
| --- | --- | --- | --- |
| **1. 該当バージョン** | `Server: Apache/2.4.49`（同梱NVD/KEV） | `detected`（`proven` ではない）/ `high` / `["CVE-2021-41773", "CVE-2021-42013"]` | `関連CVE候補: CVE-2021-41773, CVE-2021-42013（バナー照合による検出・未実証）。` |
| **2. 非該当バージョン** | `Server: Apache/2.4.58`（同梱NVD/KEV） | `detected`（技術情報露出のみ）/ `low` / `[]` | `（現在のNVD/CISA KEVカタログ上の既知バナー一致なし。安全性の保証ではありません）` |
| **3. バージョン不明** | `Server: Apache`, `X-Powered-By: Express` | `detected`（技術情報露出のみ）/ `low` / `[]` | `（バージョン番号が含まれないためCVE照合は未判定。既知CVEへの該当有無は断定できません）` |
| **4. フィード未取得 / 同期失敗** | `Server: Apache/2.4.49`（空カタログ）または `sync_from_urls` 失敗 | 空カタログ時は `cve=[]`、同期失敗時は直前のカタログ・ハッシュ・同期日時を保持 | `（CVEフィード未取得のためCVE照合は未実施）` / UI: `・直近の同期に失敗（以前のデータを保持）` |

---

## 5. 公開βでの運用方針

- 公開βでは、診断実行のたびに外部 NVD / CISA サーバーへ通信せず、サーバー内に同期済みのカタログ（初期状態は検証済みの同梱フィード）を参照する。
- 外部フィードの定期取り込みを行う場合は、診断ワーカーとは分離された管理者バッチから署名・検証済み JSON を `POST /api/cve/sync` へ投入する運用とし、診断対象やAIモデルからフィードURLを指定させる経路は設けない。
