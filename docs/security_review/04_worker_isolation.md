# (d) Worker の隔離・Gateway・緊急停止

## 設計（要約）

1. **AI は Worker を直接起動しません。** ARTEX や AI の提案は、固定のカタログ（`CATALOG_BY_ID`）と登録済みの対象から作り直され、Gateway を通ってから Worker になります（`aegis/assessment.py:2664-2690`、`ARCHITECTURE.md` 主な約束事）。
2. Gateway（`aegis/gateway.py:253-400`）は順に、状態（RUNNING）→ 停止を確認できない Worker がないこと → 提案のスキーマ（`aegis/policy.py:40`）→ 単発トークン（HMAC-SHA256、`jti` は1回限り、`epoch` で一括失効、`aegis/authz.py:69-131`）→ 契約の期間 → 人の承認または自動の L1 承認（`aegis/authz.py:63-66`）→ 送信先（`EgressGuard.check`、`aegis/network.py:73-130`）→ 同一操作の重複（`aegis/gateway.py:272-277`）→ 予算 → 停止・リセットの世代（`_still_current`）を確かめ、`allow` を監査に書いてから Worker を起動します（`aegis/gateway.py:279-284`）。
3. 送信先の固定：スキーム・URL 内の認証情報・ポート・ホスト名を検査し、名前解決の結果を許可 CIDR と `HARD_DENY`（`aegis/network.py:26-30`）に照らして、1つの IP に固定します。ラボの対象は `127.0.0.1/32` と `lab_port` だけです（`aegis/assessment.py:399-400`）。Worker には固定した IP を引数で渡します（`aegis/gateway.py:67-78`）。
4. Worker の起動：環境変数は `PATH` と、Gateway が許した値だけ（`aegis/runtime.py:118-120`）。標準入力なし、新しいセッション（プロセスグループ）、`close_fds`、`RLIMIT_CPU`（`:143-147`）。Gateway の時計で期限を決め、過ぎたらグループごと止めます（`:163-182`）。グループの外にパイプを持つプロセスが残れば、その実行の出力は使いません（`:184-189`, `aegis/gateway.py:351-357`）。
5. **プロセス内の送信制限**（多層防御）：`http_probe`・`status_marker`・`reproduction_probe` は `egress_sentinel.py` 経由で起動し、`socket.connect` / `connect_ex` を固定した ip:port 以外で失敗させます（`aegis/gateway.py:77`, `:104`, `:175`, `aegis/workers/egress_sentinel.py:59-75`）。
6. **カーネルによる隔離（Linux）**は、次の2つにだけ適用します。
   - 実サイト向けの `reproduction_probe`（v1.0 では実サイトの L2 は無効）：cgroup v2 + nftables（固定した ip:port 以外を破棄）、別 UID、`no_new_privs`、能力なし、seccomp ランチャー。起動前にプローブで「破棄されること」をカーネルのカウンタで確かめます（`aegis/confinement.py:1-29`, `:362-389`, `aegis/assessment.py:1180-1208`）。テスト用アカウントの秘密値は、隔離が確認できた Worker にだけ渡します（`aegis/assessment.py:1177-1178`）。
   - ARTEX プランナー：専用の netns（`lo` だけ、ループバックへの中継）、mount/PID/IPC 名前空間、`/proc` の `hidepid`、データディレクトリを隠す（`aegis/confinement.py:403-435`, `aegis/artex_bridge.py:394-402`）。隔離できなければ、開発モードで `VULNIX_ARTEX_ALLOW_UNCONFINED=1` を明示しない限り起動しません（`aegis/assessment.py:2201-2212`）。本番では ARTEX バイナリの SHA-256 の固定が必須です（`:2189-2192`）。
   - **v1.0 の範囲である登録済みラボへの Worker（`http_probe`・ラボの `reproduction_probe`）には、カーネル隔離をかけません**（`aegis/assessment.py:1186-1193` で `None` を返す）。この経路の隔離は、上の 2〜5 です。
7. 緊急停止（`aegis/gateway.py:439-468`）：新規操作の遮断と世代の更新 → 全トークンの失効 → 送信の遮断 → Worker の終了（グループ・cgroup）→ 終了の確認（最大5秒）→ 監査記録。生き残りがあるか監査に書けなければ「停止を確認できず」と報告します。サービス側は、停止フラグのファイルを先に書き、ARTEX プランナーを終了し、Planner LLM Gateway を閉じ、生き残りを記録します（`aegis/assessment.py:3923-3967`）。
8. 停止を確認できない Worker の封じ込め：期限を過ぎて止まったと確認できない Worker は記録され、それが生きている間は新しい Worker を起動しません（`aegis/gateway.py:332-349`, `:410-422`, `aegis/assessment.py:845`, `:929-960`, `:1227-1228`）。

## 主なコードの場所

| 内容 | 場所 |
|---|---|
| Gateway 本体 | `aegis/gateway.py:180-400` |
| 道具の定義（argv の組み立て） | `aegis/gateway.py:62-178` |
| トークン・承認・契約 | `aegis/authz.py:31-131` |
| 送信先の固定 | `aegis/network.py:26-130` |
| Worker の起動・期限・強制終了 | `aegis/runtime.py:94-305` |
| プロセス内の送信制限 | `aegis/workers/egress_sentinel.py` |
| カーネル隔離 | `aegis/confinement.py`、`aegis/netfilter.py:37-56`（nftables のルール） |
| 起動直前の確認（範囲・アドレス・停止・生き残り） | `aegis/assessment.py:1210-1250` |
| 緊急停止 | `aegis/gateway.py:439-468`, `aegis/assessment.py:3923-3967` |
| Worker 出力の秘密値の除去 | `aegis/gateway.py:377-393`, `aegis/assessment.py:5098-5110` |

## 証拠となるテストと CI

| テスト / CI ステップ | 確かめていること |
|---|---|
| `tests/test_gateway.py`（`TestOutOfScope`, `TestExpiry`, `TestAIEscalation`, `TestDnsAndRedirect`, `TestConcurrency`, `TestEmergencyStop`, `TestBudgetAndAudit`, `TestLateWorkerAuthority`） | 範囲外・期限切れ・AI の昇格の試み・DNS とリダイレクト・同時実行・停止・予算 |
| `tests/test_egress_sentinel.py` | プロセス内の送信制限 |
| `tests/test_worker_deadline.py`（`TestStopRacesAndNoTrafficAfterTheStop`, `TestUnconfirmedStopFailsClosed`, `TestPipesHeldByAnEscapedDescendant`, `TestFailClosedWhenRecordingOrAuditFails`） | 停止後に通信しない、止まったと確認できなければ失敗扱い、逃げた子孫 |
| `tests/test_release_safety.py::TestAWorkerNotConfirmedStoppedAtItsDeadlineBlocksTheService`, `TestALeftoverConfinedRunStaysOnRecord`, `TestRestartKeepsTheStopWhileWorkersSurvive` | 生き残りの封じ込め、再起動後も維持 |
| `tests/test_fail_closed.py::TestKernelConfinementLogic`, `TestRealServiceL2NeedsKernelConfinement`, `TestMoreFailClosedDetails::test_tokens_are_not_released_to_a_worker_without_a_confinement_session` | 隔離の論理、隔離なしでは秘密値を渡さない |
| `tests/test_diagnosis_actions.py::TestStopAndRoleChangeDuringTheWorker::test_an_emergency_stop_while_the_l2_worker_runs_adopts_nothing` | L2 Worker の実行中の緊急停止で結果を採用しない |
| `tests/test_netfilter.py` | nftables ルールの生成と適用の条件 |
| CI「Linux kernel confinement end to end (confined L2 worker; stop, revocation, deletion, expiry)」 | `tests.test_release_safety.TestOnLinuxWithTheRealKernelConfinement` と `tests.test_fail_closed.TestKernelConfinementOnLinux` を実カーネルで実行。skip があれば失敗（`.github/workflows/ci.yml:103-110`） |
| CI「Verify Linux Kernel nftables NetNS Isolation & Emergency Stop (P0)」 | `sudo python3 -m aegis.control_verification`（`.github/workflows/ci.yml:139-141`） |
| CI「Overlay Go tests (tool allowlist, loopback-only LLM, deny hook)」 | ARTEX overlay 側の制限（`.github/workflows/ci.yml:244-246`） |

## 既知の制限

- ラボの Worker はカーネル隔離なしで、サービスと同じ OS ユーザーで動きます（上の 6）。Worker のコードは Vulnix 自身の固定コードで、AI が書いたコードではありません。
- プロセス内の送信制限は Python の `socket.connect` / `connect_ex` の差し替えだけです（`aegis/workers/egress_sentinel.py:59-75`）。ファイル冒頭の説明自体が「カーネルのファイアウォールではない」と書いています（`:10-14`）。
- カーネル隔離は Linux（cgroup v2、nft、root またはパスワードなしの sudo）だけです。それ以外では該当テストはスキップされ、CI の Linux ジョブで skip を失敗として扱って確認しています（`.github/workflows/ci.yml:105-110`。`docs/SECURITY_REVIEW.md` 130行も「隔離の実効性は CI の実行結果に依存する」と記載）。
- 緊急停止の確認時間は最大5秒です（`aegis/gateway.py:439`）。

## 試してほしいこと

1. **悪意のある対象サイト**：ラボ（`aegis/lab.py`）を改造したり、`127.0.0.1:<lab_port>` で別のサーバーを動かしたりして、`http_probe`（`aegis/workers/http_probe.py`）や `reproduction_probe` のパーサーに巨大・不正な応答、リダイレクト、遅い応答を返す。出力の上限（`aegis/runtime.py` の `_Capture`）、`Set-Cookie` の除去（`aegis/gateway.py:377-384`）、JSON の重複キー拒否（`_unique_json_object`、`:142-148`）を崩せないか。
2. **送信先の固定の迂回**：登録時に `ownership_verified: true` と任意の `authorization_ref` を送ると、そのホスト名がラボの許可リストに入ります（`aegis/server.py:1263-1270`, `aegis/assessment.py:2918`, `:2925`）。CIDR は `127.0.0.1/32` のままですが（`:399-400`）、名前解決・IPv6・`localhost` の別名・`127.0.0.2` などで、ラボ以外のループバックのサービス（例：コントロールプレーン `:8787`、Next.js `:3000`）に届かないか。ポートは `lab_port` に限られます。
3. **停止の競合**：緊急停止と `Popen` の登録（`aegis/runtime.py:130-153`）・隔離の適用中（`aegis/confinement.py:472-484`）を重ね、停止後に通信する Worker が残らないか。
4. **ARTEX からの脱出**（Linux）：プランナーが名前空間の外のファイル（データディレクトリ、`.env.local`）を読んだり、ループバックの中継以外に接続したりできないか。`planner_hidden_paths` と `forbidden_paths`（`aegis/assessment.py:2201-2204`, `aegis/artex_bridge.py:394-402`）。
5. **トークン**：`TokenAuthority` の秘密値はプロセス内だけです。同じプロセスの別組織のトークンを流用できないか（`eng`・`tgt`・`act`・`tool` の照合、`aegis/gateway.py:262-266`）。
