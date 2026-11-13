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

ARTEX プランナーは Linux カーネル隔離（専用 cgroup v2・nftables、専用のネットワーク／マウント／IPC／PID 名前空間、専用 uid・権限なし、planner 用 seccomp、プロセス・メモリ上限）の中でのみ起動します。CI で実機の ARTEX について検証済みです。ただし、次の点は本番利用の前に判断が必要です。

1. **ホストの一部ファイルは読み取れます。** マウントビューは固定の一覧（`/home` `/root` `/tmp` `/var` `/dev/shm` `/dev/mqueue` `/run` `/mnt` `/media` `/srv` `/opt` `/boot` `/snap`、Vulnix 本体、データディレクトリ）を空の tmpfs で隠す方式で、最小ルートへの `pivot_root` ではありません。`/etc` `/usr` `/lib*` `/sys` などは見えたままで、他ユーザーが読めるファイル（world-readable）は ARTEX から読めます。Vulnix の秘密情報とデータディレクトリは隠れています（起動前のプローブで確認）。
   - **本番で必要になり得る対策：** 最小ルート（tmpfs ルートに `/usr` `/lib*`、必要最小限の `/etc` と実行に必要なパスだけを読み取り専用でバインド）への `pivot_root`。または、ホスト上に機密ファイルを world-readable で置かない運用の確認。
2. **中継（relay）は ARTEX と同じ uid で、専用の seccomp がありません。** ARTEX が中継を停止・枯渇させることはできますが、影響は ARTEX 自身の通信が止まることに限られます。
3. **DB 権限の検査は、ハッシュ固定した overlay バイナリ自身が行います**（スーパーユーザー・CREATEROLE・サーバープログラム／ファイル権限・dblink/postgres_fdw を拒否）。
4. **動作要件：** cgroup v2、nftables、iproute2、passwordless sudo、Linux 5.14 以降（`cgroup.kill` / `cgroup.freeze` / `subset=pid`）。満たさない環境では起動を拒否します（fail closed）。検証は GitHub の Ubuntu ランナーのみです。
5. **モデル：** ARTEX の計画生成の検証は、ローカル模擬 LLM による 1 計画ラウンドのみです。実モデルは未検証です。
