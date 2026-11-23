# アーキテクチャの簡素化：現状の調査と移行計画

2026-11-23。対象は main `cdb5fdb`。この文書は計画だけで、実装は含みません。行番号は、このコミットでのものです。

目的は次のとおりです。

- 安全性を保ったまま、コードの複雑さ、重複した処理の経路、開発のコストを減らす。
- 新しい TTP の検査を1つ足すときに、共通の実行基盤をほとんど変えずに済むようにする。

**独立した防御層は削りません**（§4）。

## 1. 目標の構成

| モジュール | 役割 | 主に入るもの（現在のファイル） |
|---|---|---|
| **AI Planner** | ARTEX と Abliteration AI による計画の提案。権限は持たない | `artex_bridge`（計画の実行と解析）、`planner_llm_gateway`、`router` のモデル側、`ai_advisor`、`chat_guard`、`plan_contract` |
| **Policy Engine** | 所有確認、範囲、承認、予算、停止 | `authz`、`policy`、`network`、`ownership`、`authority_ledger`、`grant_lease`、`spend_cap`、`tenancy`（所属の確認）、`_launch_guard` / `_late_launch_guard`、承認（新しく作る `ApprovalService`） |
| **Test Runner** | 隔離された Worker と、TTP 検査のプラグイン | `gateway`、`runtime`、`confinement`、`workers/*`、検査の登録表（新しく作る `aegis/checks/`） |
| **Evidence & Report** | 証拠、判定、監査、修正後の確認 | `evidence`、`audit`、`audit_anchor`、`diagnosis_judge` / `state` / `view`、`report_diagnosis`、`service_diag` の解析部分 |

```
            ┌──────────── AI Planner ────────────┐
提案だけ →  │ ARTEX / Abliteration / ProposalRouter │ ── 提案（データ）
            └──────────────────┬──────────────────┘
                               ▼
            ┌──────────── Policy Engine ─────────┐
            │ 所有確認・範囲・ApprovalService・予算・停止 │ ── 承認とトークン
            └──────────────────┬──────────────────┘
                               ▼
            ┌──────────── Test Runner ───────────┐
            │ Gateway → 隔離 Worker ← checks/<id>.py │ ── 結果
            └──────────────────┬──────────────────┘
                               ▼
            ┌──────── Evidence & Report ─────────┐
            │ 証拠・判定・監査（先に記録）・修正後の確認・レポート │
            └────────────────────────────────────┘
```

## 2. 現状

### 2.1 3つの実行の流れは、実行の中心を共有している

| 流れ | 入口 | 実行 |
|---|---|---|
| 通常の診断（旧来） | `/start` → `start` → `_run_inner`（`assessment.py:5041`） | `_exec` → `Gateway.execute` → Worker |
| 手動の ARTEX | `/artex/items/{id}/execute` → `execute_artex_item`（`:2909`）→ L2 は `verify_finding` | 同じ |
| 診断ループ | `/diagnosis/*` → `DiagnosisOperations.run` → `AdaptivePlanRunner` → `plan_with_artex` / `execute_artex_item` | 同じ（ルートの観測は `svc._exec` を直接呼ぶ） |

実行そのものは、すでに1本の経路（`_exec`）に集まっています。**重複しているのは、その周りの承認・判定・証拠の扱いです。**

| 手順 | 通常の診断 | 手動の ARTEX | 診断ループ |
|---|---|---|---|
| 依頼者 ≠ 承認者 | `:4291`（`started_by`） | `:2950`（`requested_by`）、実サイトは `:4357` | `diagnosis_ops:630, 582` のあと、ARTEX の確認がもう一度働く |
| 承認者のロール | server `:1750, 1774` | `:2942`、`:4516` | `diagnosis_ops:610` |
| 承認の発行 | `:5623`、`:5259/5290/5321`、`:4880-4888` | `verify_finding` の中（`:4556/4609/4649/4689`） | ARTEX と同じ |
| 判定 | `reproduction_verdict` | `reproduction_verdict` | `diagnosis_judge`（中で `reproduction_verdict` を呼ぶ） |
| レポート | `report_markdown` | 同じ | `diagnosis_lines` |

### 2.2 AssessmentService の責務（6,441行）

1つのクラスが、4つのモジュールのすべてにまたがっています。

- **Policy**：範囲、所有確認、台帳、送信先のアドレス、分離、開始・停止
- **Planner**：ARTEX の計画と項目、LLM のプレビュー、チャット
- **Runner**：旧来の L1・L2 の実行、Worker の後始末
- **Evidence**：状態の保存、監査の欠落、修正後の比較、レポート

切り出しが難しい理由は次のとおりです。

- 1つのロック（`RLock`、`:412`）を、121か所の `with` で使っている。
- `self.a.*` を375か所で書き換えている。
- `_persist_error` を、どの部分も拒否の条件として参照している。
- ラボのモードが、プロセス全体で1つしかない。
- `diagnosis_ops` と `server` が、内部の非公開のフィールドに直接触れている。

### 2.3 判定の重複：独立した防御層と、同じ層での偶然の重複

**独立した防御層（すべて残します）**

- **送信先**：次の4層です。
  1. EgressGuard（`network.py:73-112`）
  2. `_launch_guard` による、確認済みアドレスとの照合（`:1449`）
  3. `egress_sentinel`（`gateway.py:77/105/171`）
  4. nftables（`confinement.py:84-115`）
- **ツールと操作**：次の6段で確かめます。
  1. ARTEX の出力の許可リスト（`artex_bridge:522/534`）
  2. プランナーの使えるツール（`planner_llm_gateway:459`）
  3. カタログからの作り直し（`artex_bridge:578-646`）
  4. `sanitize_proposal`（`router:319`）
  5. `validate_proposal`（`policy:40`）
  6. トークンに結び付けた確認（`gateway:264`）
- **停止**：`_checkpoint`、Gateway の状態、`_still_current`、`block_all`、`_launch_guard`
- **要求者の権限**：起動の直前と、結果を採用する前の2回
- **予算**：Gateway、LLM、計画の上限、実サイトの枠。それぞれ別のものを数えています。

**同じ層での偶然の重複（まとめる候補）**

- 依頼者 ≠ 承認者：5か所。依頼者の出どころが3通りある。
- 承認者のロール：5か所
- 有効期間の確認（`assessment:5055`）：トークン側の確認と重なっている。
- 秘密情報の除去と `sanitize_http_probe_payload`：Gateway（`:388`、`:379`）と `_exec`（`:5462`、`:5467`）で2回ずつ
- 承認の監査ログ：`_audit_first` と、ふつうの `audit.record` が混在している。
- nftables の規則の生成：`netfilter.nft_ruleset` と `confinement.ruleset` の2つ
- 監査ログの関数の組（「先に記録」「縮小の後に記録」「未反映の記録」）：`assessment.py` と `server.py` にそれぞれある。
- 原子的なファイル書き込み：手書きのものが10か所ある。耐久性の扱いがまちまちで、`secrets.enc.json`、`orgs.json`、`planner_llm_previews.json` は fsync をしていない。

### 2.4 依存関係と循環

```
server → tenancy
server → assessment ─┬→ gateway → policy, authz, network, runtime, confinement, audit
                     ├→ router ⇢ chat_guard → ai_advisor → router        [循環]
                     ├→ artex_bridge ⇢ plan_contract → artex_bridge        [循環]
                     ├→ planner_llm_gateway → artex_bridge
                     ├⇢ diagnosis_ops → diagnosis_loop ⇢ assessment        [循環]
                     └→ authority_ledger, l2_rules, service_diag, evidence, report_diagnosis
diagnosis_state ⇢ diagnosis_judge → diagnosis_state                       [循環]
evidence ⇢ service_diag → workers.http_probe                              [層をまたぐ]
```

層をまたいでいる依存は次のとおりです。

- `server` が Worker の層を直接使っている（`control_verification`、`real_software_cve`）。
- `diagnosis_loop` が、サービスの非公開の `_exec`、`_tls`、`_lock` を使っている。
- 生の監査ログを、証拠の層の外で読んでいる（runner、`remotion_export`、`report_markdown`）。

### 2.5 使われていないコードと、古い互換の経路

呼び出し元がないことは、grep で確かめました。

| 対象 | 呼び出し元 | 扱い |
|---|---|---|
| `l2_rules.default_profile_dirs`、`path_keys`、`token_keys`、`profile_of_check` | なし | すぐに削除してよい |
| `_authority_epoch`、`finding_requires_human_l2_approval`、`set_verify_seconds`、`cve.correlate_assets`、`sync_from_urls`、`diagnosis_state.unresolved`、`check_ids`、`inspect_executable`、`secrets_store.has_any_token`、`remotion_export.public_strings` | テストだけ | テストと一緒に削除する |
| `netfilter.apply_ruleset`、`operators.verify_totp` | テストだけ | 安全のための部品かどうかを確かめてから決める |
| `--separate-l2-approver` | 既定と同じ効果 | 廃止を予告してから削除する（環境変数の確認は残す） |
| `chat_guard.check_answer(proven=)` | 引数を使っていない | 引数を削除する |
| 台帳への移行のコード（旧 `state.json` の取り込み、`legacy_marker_key` など） | 移行のため | **最後に削除する**。すべての環境で移行が済んだと確かめてから。先に消すと、権限が復活しうる |
| 旧来の診断（`/start`、`/restart`、`/verify-fix`） | 画面が今も使っている | 残す。移行計画の対象 |
| `demo_verify` | 停止のテストで使っている | 残す |

### 2.6 検査を1つ足すときのコスト（いま）

**過去の追加で変更したファイルの数**

| コミット | 内容 | 変更したファイル |
|---|---|---|
| `17d09d5` | mod_status | 6 |
| `00527bd` | 認可のラボ | 12 |
| `a904bd8` と `452d78a` | Cookie | 12 と、画面で 11 |
| `27d817c` | CORS | 6 |

**ラボ専用の L2 検査を1つ足す場合に、いま変更が必要な場所**（`sqli` で確かめました。**ソースだけで15〜18ファイル**）

- Gateway の許可リスト（`gateway.py:152`）
- Worker の要求の定義（`reproduction_probe.py:50`）
- 判定の印（`evidence.py:94`、`lab.py:82`）
- ラボの応答（`lab.py:198`）
- プランナーのカタログ（`artex_bridge.py:100`）
- `assessment.py` の中の分岐（約12か所）
- 助言のカタログ（`advisor_catalog.py`、`ai_advisor.py`）
- 模擬のモデル
- 動画の書き出し
- 画面とレポートの文言（`labels.ts`、`report_labels.json`）
- 判定器、用語集、そのほか

## 3. 減らせる候補と優先順位

| 優先 | 候補 | 減らせるもの | 残す安全制御 | 移行のリスク | 回帰テスト |
|---|---|---|---|---|---|
| **1** | **検査のプラグイン化**（`aegis/checks/<id>.py` と、生成する登録表） | `assessment.py` の分岐（約12か所）と、手書きの登録表5つ。検査の追加は1〜3ファイルで済む | Gateway の許可リスト（なくさず、生成する）。Worker が送る要求は固定のまま。L2 の承認と分離 | Worker が読み込める範囲（静的な JSON にしてハッシュで確かめる）。画面の文言の生成 | `test_lab_accuracy`、`test_evidence`、`test_status_exposure_lab`、`test_access_control_lab`、`test_report_labels`、E2E |
| **2** | **`ApprovalService` への一本化**（`grant(item, approver, requester)`） | 依頼者 ≠ 承認者の5か所、承認者のロールの5か所、ばらばらな承認の発行（約15か所） | ロール、自己登録の拒否、先に記録、1回限りの承認（ラボでも取り消すようにする） | 依頼者の出どころ（3通り）をそろえること | `test_l2_separation_default`、`test_diagnosis_actions`、`test_tenancy`、`test_fail_closed`、`test_artex_bridge` |
| **3** | **共通の部品**：`atomic_write_private` と `audit_policy`（先に記録、縮小の後に記録、未反映の記録、欠落の保存） | 書き込みの10か所、監査の関数の重複（約6組）。fsync をしていなかった3つのファイルが強くなる | 0600 の権限、読めない欠落ファイルを上書きしないこと、取り消しの目印 | ファイルの形式は変えない | `test_audit_before_state`、`test_authority_ledger`、`test_operators`、`test_spend_cap`、`test_tenancy` |
| **4** | **旧来の L2 の固定の手順をやめる**（`_run_inner:5223-5350`、`_verify_fix_body:4876-4970`）。カタログの項目として `execute_artex_item` 側に寄せる。表示だけの router の計画もやめる | 約250行と、承認を自分で発行している箇所 | 項目ごとの人の承認と、`LAB_REPRODUCTION_CHECKS` の確認 | 画面の段階と文言、E2E | `test_lab_accuracy`、`test_final_review`、`test_server`、`check_first_run` |
| **5** | **サービスに公開の Runner・Evidence の窓口を作る**（`run_check(entry, url, approval) → Evidence`）。そのうえで、`diagnosis_*` が非公開のフィールドに触れないようにする | 循環（`diagnosis_ops` と `assessment`）と、非公開のフィールドへの触れ方（10か所） | 要求者の権限の再確認、古い実行の結果を捨てること、保存できないときの拒否、結果を監査ログと照らし合わせること | スレッドローカルの `_tls` が、権限を暗黙のうちに渡していること | `test_diagnosis_loop`、`test_adaptive_plan_runner`、`test_report_diagnosis`、`test_evidence` |
| 6 | **同じ層での重複を除く**（`_exec` での2回目の秘密情報の除去、`:5055` の事前確認、`netfilter.nft_ruleset`） | 小さい | Gateway での秘密情報の除去と、送信先の4層 | 秘密情報の除去は、同じ出力を対象にしていると確かめてから外す | `test_gateway`、`test_exec_result_entry`、`test_netfilter` |
| 7 | **使われていないコードを削除する**（§2.5） | 数百行 | `separate_l2_approver_from_env` | 移行のコードは最後に消す | `test_l2_separation_default`、`test_authority_ledger` |

## 4. 削らないもの（独立した防御層）

- 送信先の4層：アプリ、起動の直前、プロセスの中のソケット、カーネル
- 提案の扱い：作り直し、`sanitize_proposal`、`validate_proposal`、トークンに結び付けた確認
- 要求者の権限の二重の確認：起動の直前と、結果を採用する前
- 停止の複数の経路
- 監査ログ：ハッシュチェーン、監査アンカー、先に記録する方式
- ARTEX と Worker の隔離：名前空間、cgroup、nftables、seccomp、最小構成のルート（#124）
- 組織ごとの分離：別のオブジェクト、別のディレクトリ、毎回の所属の確認

## 5. 調査の途中で見つかった点（安全に関わるもの）

1. **ラボの L2 を `/verify-finding` で実行すると、承認者のロールも、依頼者 ≠ 承認者も確かめていません**（`_verify_finding` のラボの分岐、`:4598-4720`）。実サイトの分岐（`:4516`）では確かめています。operator のロールしかないメンバーが、1人でラボの L2 を実行できます。対象は同梱のラボだけですが、「L2 には依頼者とは別の承認者が要る」という規則と食い違います。**別の小さな修正 PR を提案します。**
2. ラボの L2 で発行した承認（`:4609/4649/4689/4880-4888/5259-5321/5623`）を取り消していません。トークンは1回しか使えないので、すぐに悪用はできません。それでも、`ApprovalService` に一本化するときに取り消すようにします。
3. `secrets.enc.json`、`orgs.json`、`planner_llm_previews.json` の書き込みで、fsync をしていません。`orgs.json` は `O_NOFOLLOW` も付けていません。候補3で直します。

## 6. 段階的な移行計画

各段は小さな PR にします。どの段でも、Python 全件、Web、実 ARTEX、E2E の CI が通ることを条件にします。外から見える挙動は変えません。変える場合は、その段で明記します。

| 段 | 中身 | 依存 | 外から見える変化 |
|---|---|---|---|
| 0 | §5-1 の修正：ラボの L2 でもロールと分離を確かめる | なし | operator だけではラボの L2 を実行できなくなる |
| 1 | 共通の部品（候補3）と、使われていないコードの削除（候補7の「すぐに削除してよい」もの） | なし | なし（fsync が強くなる） |
| 2 | `ApprovalService`（候補2）。3つの流れの承認を、これに通す | 0 | なし（拒否の文言はそろえる） |
| 3 | 検査のプラグインの仕組み（候補1）。既存の検査（`idor`、`sqli`、`cve_2021_41773`、`mod_status`）を移しても、生成した登録表が今の手書きのものと一致することをテストで確かめる | 1 | なし |
| 4 | Runner・Evidence の公開の窓口（候補5）と、同じ層での重複の除去（候補6） | 2、3 | なし |
| 5 | 旧来の L2 の固定の手順をやめる（候補4）。画面の `/start` と `/verify-fix` を、カタログの項目による実行に切り替える | 2、3、4 | 画面の段階の表示（E2E を更新する） |
| 6 | AssessmentService を、Policy・Planner・Evidence の3つのクラスと、その前に置く1つの窓口に分ける（ロックは最初は共有する） | 4、5 | なし |
| 7 | 移行のコードを削除する（すべての環境が台帳の形式になったと確かめてから） | 6 | なし |

**ここまで進むと、新しい TTP の検査は「`aegis/checks/<id>.py`、そのラボの模擬データ、テスト」の1〜3ファイルで足せる見込みです。** Gateway の許可リストと画面の文言は、検査の定義から生成します。L2 の承認と証拠の扱いは、共通の基盤がそのまま受け持ちます。

**CrowdStrike の TTP の検査（`docs/ARTEX_TTP_COVERAGE.md` の P2〜P5）との関係**：段0から段3を先に済ませると、新しい検査をプラグインの形で足せます。段3の前に検査を足すと、上に書いた15〜18ファイルの変更が、検査ごとに繰り返し発生します。
