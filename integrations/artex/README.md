# ARTEX planner-only overlay

Files under `overlay/` are copied into a checkout of
[ARTEX](https://github.com/jiwoochris/artex-global) (Go module `github.com/Autumn-27/artex`)
at a pinned commit and built there (see the `artex-real-planner` job in
`.github/workflows/ci.yml`). They are **licensed AGPL-3.0-or-later**, like ARTEX itself,
and run as a separate program: Vulnix talks to it only through stdin/stdout JSON.

## What the overlay does

`cmd/vulnix-planner` runs **one real ARTEX planner round** (ARTEX's own planner prompt,
store and domain tools) and prints the intents it produced (`add_intent`) as JSON.

The planner gets only these ARTEX tools: `graph_overview`, `list_facts`, `list_findings`,
`node_detail`, `list_goals`, `add_intent`, `prove_goal`, `goal_met`.

It does **not** get: Bash / Read / Write / Edit / MultiEdit / LS / Glob / Grep, WebFetch,
WebSearch, custom or MCP tools, `add_company_scope`, `add_task_scope`, `report_finding`,
`list_assets`, `list_untested_assets`, `kill_work`, `steer_work`, worker output tools.
No permission bypass; a deny-by-default PreToolUse hook blocks and records any other
tool name. No workers are started. The LLM endpoint and the PostgreSQL store must be
loopback addresses.

## What Vulnix does with the output (`aegis/artex_bridge.py`)

- Rejects a run that reports any tool outside the allowlist as available or executed.
- Never uses an intent's target, URL, tool, action or arguments: an intent only selects
  an entry of Vulnix's allowed check catalog; target and arguments come from Vulnix's
  registered targets.
- Keeps unmappable intents as advisories (never executable).
- Sends rebuilt proposals through ProposalRouter and the Gateway; L2 needs an approver
  and runs in the isolated worker; nothing runs after an emergency stop.
- Labels a run "ARTEX 本体" only when the executable is a native Go binary carrying build
  info for `github.com/Autumn-27/artex/cmd/vulnix-planner`; anything else is shown as
  an unverified stand-in.

`OVERLAY_NOTES.md` lists, for each ARTEX identifier used, where it was verified in the
ARTEX source.

## 本番利用前の検討事項（未解決）

ARTEX プランナーは Linux カーネル隔離（専用 cgroup v2・nftables、専用のネットワーク／マウント／IPC／PID 名前空間、`pivot_root` による最小ルート、専用 uid・権限なし、planner 用 seccomp、プロセス・メモリ上限）の中でのみ起動します。CI で実機の ARTEX について検証済みです。ただし、次の点は本番利用の前に判断が必要です。

**最小ルート（1）と中継の uid・seccomp（2）は、Linux CI（`artex-real-planner` と Python Suite + Linux）での実行が通るまで未確認です。** macOS では計画の組み立てと seccomp 規則の単体テストだけを実行しています。

1. **ファイルの見え方は最小ルートです（2026-11-23 から）。** 固定の一覧を空の tmpfs で隠す方式をやめ、空の tmpfs ルートに必要なものだけを置いてから `pivot_root` し、元のルートを切り離します（`aegis/confinement.py` の `minimal_root_plan` / `minimal_root_script`）。ARTEX から見えるのは次だけです。
   - 読み書き可：実行用の作業ディレクトリ（ARTEX のバイナリのコピーと HOME）だけ（nosuid・nodev）。
   - 読み取り専用：起動用ランチャーの配置先、Python の実行ファイルと標準ライブラリ（専用プレフィックスのときはプレフィックス全体）、`/usr/lib/<multiarch>`（無ければ `/usr/lib`）、`/usr/lib64`、`/usr/bin/setpriv`、各実行ファイルの動的ローダー。`/lib` `/lib64` はホストと同じシンボリックリンク。
   - `/tmp` は実行ごとの空の専用 tmpfs（64MB、nosuid・nodev・noexec、mode 1777、ホストの `/tmp` ではない）。overlay は作業ディレクトリを `os.TempDir()` の `/tmp/vulnix-artex-planner`（プランナーのプロンプトに入る固定パス）に作るため必要です。`TMPDIR` は setuid の sudo を通る際に glibc が消すので、作業ディレクトリへ向け直せません。
   - `/dev` は `null` `zero` `full` `random` `urandom` だけ。`/proc` は ARTEX 自身の PID 名前空間の新しい proc（`hidepid=invisible,subset=pid`）。ルートの tmpfs は構築後に読み取り専用。
   - `/sys` `/etc` `/home` `/root` `/var` `/run` `/usr/share` `/usr/local` `/usr/sbin`、ホストの `/proc`、Vulnix のコードとデータディレクトリは存在しません。計画に `/` `/usr` `/usr/bin` `/etc` `/sys` `/proc` `/run` などを含めようとすると計画自体が拒否されます。
   - **fail closed：** 構築のどの手順が失敗しても（`set -eu`）ARTEX は起動せず、「最小ルート（pivot_root）を構築できなかった」と表示します。
   - **起動前のプローブ（ARTEX と同じ経路で起動）で確認：** マウント一覧が計画どおりのものだけであること、ルートが `vxroot` の tmpfs であること、切り離した元のルートが空であること、上の各パスと Vulnix のソース、制御プロセスの `/proc/<pid>` が存在しないこと。
   - **ARTEX が実行時に使うパス（overlay のソースで確認）：** 書き込みは `/tmp/vulnix-artex-planner` だけ。環境変数は `ARTEX_LLM_*` と `ARTEX_PG_DSN` だけを読みます。LLM と DB は平文の 127.0.0.1 なので、TLS 証明書（`/etc/ssl`）は不要です。ARTEX 本体（overlay 外のコード）が `$HOME`・XDG ディレクトリ・`/usr/share/zoneinfo` を使うかはローカルで確認できていません（`HOME` は作業ディレクトリ内で書き込み可能。zoneinfo が無ければ Go は UTC になります）。
   - **残る点：** `/usr/lib/<multiarch>` のライブラリ一式（Ubuntu では `/usr/lib/x86_64-linux-gnu` 全体）と Python の標準ライブラリは読み取れます。必要なライブラリだけに絞る（ldd 相当の解決）は未実装です。ARTEX が将来 `/etc`（TLS 証明書・タイムゾーン）や `/usr/share/zoneinfo` を必要とした場合は起動に失敗します（fail closed）。対応は merged-/usr の配置（Ubuntu 24.04 / Debian 12）で、それ以外は CI 未検証です。
2. **中継（relay）は ARTEX と別の uid で、専用の seccomp 許可リストの中で動きます（2026-11-23 から）。** 中継は ARTEX と別に払い出した uid で動き（ARTEX から中継へシグナルを送れません）、通信を扱う前に許可リスト方式の seccomp を入れます（`aegis/workers/_ns_relay.py` の `RELAY_ALLOW`）。許可は accept/accept4、AF_INET の socket、connect、send/recv 系、poll/ppoll、close、shutdown、get/setsockopt、スレッド作成（`CLONE_THREAD` のみ、名前空間フラグ不可）、メモリ管理、futex、シグナル復帰、exit、ioctl（FIONBIO/FIOCLEX のみ）です。ファイルを開く・プログラムの実行・fork・bind/listen・UNIX/netlink/IPv6 ソケット・ptrace・kill・mount などは EPERM、別 ABI はプロセスごと強制終了です。フィルタを入れられなければ中継は起動せず（exit 97）、Vulnix は起動後にカーネル側（`/proc/<pid>/status`）で uid・Seccomp=2・NoNewPrivs・権限なしを確認してから ARTEX を起動します。
   - **残る点：** 中継は Vulnix と同じ Python を使い、ホストのファイルシステムを見たまま動きます（ファイルは開けませんが、マウントは分離していません）。接続先の制限は seccomp ではなく、従来どおり cgroup に結び付いた nftables 規則です。ARTEX は中継への接続数を増やして中継を枯渇させることはできます（影響は ARTEX 自身の通信が止まることに限られます）。
3. **DB 権限の検査は、ハッシュ固定した overlay バイナリ自身が行います**（スーパーユーザー・CREATEROLE・サーバープログラム／ファイル権限・dblink/postgres_fdw を拒否）。
4. **動作要件：** cgroup v2、nftables、iproute2、util-linux（`unshare` `pivot_root` `umount` `setpriv`）、passwordless sudo、Linux 5.14 以降（`cgroup.kill` / `cgroup.freeze` / `subset=pid`）。満たさない環境では起動を拒否します（fail closed）。検証は GitHub の Ubuntu ランナーのみです。
5. **モデル：** ARTEX の計画生成の検証は、ローカル模擬 LLM による 1 計画ラウンドのみです。実モデルは未検証です。
