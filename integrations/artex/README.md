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
