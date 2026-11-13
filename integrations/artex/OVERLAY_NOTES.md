# ARTEX planner-only overlay: verification notes

The overlay files are copied into an ARTEX checkout at the same relative paths before `go build`:

- `overlay/agent/vulnix_bridge.go` (package `agent`)
- `overlay/agent/vulnix_bridge_test.go` (package `agent`; run with `go test ./agent -run VulnixBridge`)
- `overlay/cmd/vulnix-planner/main.go` (package `main`)

Upstream: `jiwoochris/artex-global` at commit `d6964594a0221cd921b85056d604bce9d8ce54df`, module `github.com/Autumn-27/artex`, AGPL-3.0. `go.mod` says `go 1.26.3`, so CI needs that Go version or newer.

**Nothing here has been compiled.** No Go toolchain was available locally. Every ARTEX identifier was checked by reading the ARTEX source. The `github.com/Autumn-27/norma` module (`agentcore`, `hook`, `llm`, `tool`, `harness`), pinned at v0.4.3 in `go.mod`, was **not** available locally. Its API is inferred only from how ARTEX itself calls it; the file:line references below point to those call sites.

## Build and run

```
cp -R integrations/artex/overlay/. <artex-checkout>/
cd <artex-checkout>
go test ./agent -run VulnixBridge          # needs no database (agent TestMain skips the PG lock when no DSN is set)
go build -ldflags "-X main.artexCommit=$(git rev-parse HEAD)" -o vulnix-planner ./cmd/vulnix-planner
ARTEX_LLM_BASE_URL=http://127.0.0.1:PORT/v1 ARTEX_LLM_MODEL=mock ARTEX_LLM_API_KEY=x \
ARTEX_PG_DSN='postgres://artex:artex@127.0.0.1:5432/artex?sslmode=disable' ./vulnix-planner < request.json
```

**The run needs PostgreSQL.** ARTEX has no SQLite or in-memory store; see `db/db.go:1-2` ("PostgreSQL data source … 取代旧 graph 单文件 SQLite") and `db.Open` at `db/db.go:134`. `modernc.org/sqlite` is in `go.mod`, but the exploration store does not use it. CI needs a `postgres` service container. The CLI refuses a non-loopback DSN host.

The base URL should end at the API base, for example `/v1`. ARTEX's OpenAI provider appends `/chat/completions` itself (`agent/provider.go:209-210`).

## Identifiers used and where they were verified

### Planner logic (package agent)

| Identifier | Verified at | Notes |
|---|---|---|
| `NewToolSet(ts *db.ExplorationStore, worker string) *ToolSet` | agent/tools.go:163 | |
| `(*ToolSet).PlannerTools() []actool.CoreTool` | agent/tools.go:2033-2054 | The real list is filtered by name and nothing is reimplemented. `NewToolSet(nil,"").PlannerTools()` is safe without a DB (agent/toolcatalog.go:35-38 does the same). |
| `actool.CoreTool.Name()` | agent/tools.go:199 (`tool.Name()` in DropCoverageTools) | |
| `(*ToolSet).SetTaskID`, `SetCoverageEnabled`, `SetOwnerNode` | agent/tools.go:169, 177, 226 | |
| `(*ToolSet).graphOverviewData()` | agent/tools.go:354 | Unexported. Reachable because the overlay is in package agent. |
| `ToolSet.GoalMet` (exported field) | agent/tools.go:70 | Set by prove_goal (1196) and goal_met (1211). |
| Tool names `graph_overview`, `list_findings`, `list_facts`, `node_detail`, `add_intent`, `list_goals`, `prove_goal`, `goal_met` | agent/tools.go:342, 902, 940, 993, 1092, 1149, 1158, 1206 | All 8 are present in PlannerTools(). |
| Excluded names: `report_finding` (the tool behind addFinding), `kill_work`, `steer_work`, `add_company_scope`, `add_task_scope`, `list_assets` | agent/tools.go:1220, 1677, 1707; agent/tools_insert.go:379, 433, 532 | No tool is named `add_finding`. The finding tool is `report_finding`. The tests forbid both names. |
| `plannerSystem(goal, dataDir, workDir string) string` | agent/planner.go:342 | Called like Plan does (planner.go:393): dataDir = work root, workDir = task dir. |
| `renderTriggers(ts, []TriggerEvent)`, `renderGraphOverview(map[string]any)`, `renderPlannerTodos([]actool.Todo)` | agent/planner.go:173, 287, 129 | |
| User-turn strings `vulnixLeadHeartbeat` / `vulnixLeadStalled` / `vulnixInputTail` | agent/planner.go:454, 458, 461 | Plan builds these inline, so they were **copied verbatim** by a script that extracted the Go string literals from those lines. They are not imported. If upstream changes the wording, the overlay will not follow automatically. |
| `constraintBlock(ts)` | agent/constraints.go:14 | |
| `deferredSystem(string, DeferredInfo) ([]string, int)`, `DeferredInfo{}` | agent/deferred.go:18; agent/assembly.go:18 | Called with an empty DeferredInfo (no MCP or skills). AugmentTools is not called. |
| `ensureRunDir(base, taskID, intentID)`, `cmdOutDir(dir)` | agent/worker.go:276, 286 | |
| `compactionConfig(int) *compaction.Config` | agent/provider.go:131 | 0 means the 200K default. |
| `wrapupSettlement(agentKey, disabledTools) *harness.Settlement` | agent/wrapup.go:94 | DB overrides are nil-safe (wrapup.go:66-85). |
| `captureRun(ctx, agentcore.Options, input, emit func(db.Activity)) (string, harness.TerminalReason, error)` | agent/capture.go:28 | It emits `db.Activity{Kind:"tool_use", Tool:name}` for every model tool call (capture.go:101) and `Kind:"tool_result"` with IsError (capture.go:111). |
| `ConfigFrom(provider, model, baseURL, apiKey, proxy string) Config`, `Config.Stream`, `(Config).NewProvider() (llm.Provider, error)` | agent/provider.go:198, 61, 256 | Proxy "" means direct; HTTP_PROXY is not used (provider.go:403-404). |

### agentcore.Options fields (inferred from ARTEX call sites)

`Provider`, `SystemPrompt` ([]string), `DynamicBoundary`, `Tools`, `EnableWebFetch`, `EnableWebSearch`, `WorkingDir`, `ToolOutputDir`, `MaxTurns`, `Compaction`, `Settlement`, `NonStreaming`: all assigned in agent/planner.go:405-440.

`Hooks`: assigned a `*hook.Registry` in agent/chat.go:164 (`opts.Hooks = c.guard.Hooks()`). It is a `harness.HookRunner` per agent/worker.go:349, 472.

### hook package (inferred from guard)

- `hook.NewRegistry().On(hook.PreToolUse, func(context.Context, hook.Event) hook.Result) *hook.Registry`: guard/guard.go:48-50.
- `hook.Event.ToolName`: guard/guard.go:63 (`switch ev.ToolName`).
- `hook.Result{Decision: "block", Message: ...}` as the block form: guard/guard.go:187.
- `hook.Result{}` as allow: guard/guard.go:85.

### db package

| Identifier | Verified at |
|---|---|
| `db.Open(dsn) (*DB, error)`, `DB` embeds `*sql.DB` (so `Close()`) | db/db.go:134, 99 |
| `(*DB).CreateTaskWithOptions(description, goal string, TaskCreateOptions) (*Task, error)` | db/tasks.go:163. It creates the exploration, the origin fact (state='origin') and the tasks row in one transaction (tasks.go:181-220). |
| `TaskCreateOptions{}` zero value OK; `Task.ID`, `Task.ExplorationID` | db/tasks.go:146, 14, 22 |
| `(*DB).Exploration(id) *ExplorationStore` | db/exploration.go:185 |
| `OriginFactID`, `AddGoal(payload, origin)`, `Link(from, rel, to)`, `AddNode(kind, payload, priority, state, origin, anchors)`, `ListByKind(kind, limit)`, `HasActiveIntent()` | db/exploration.go:236, 228, 259, 197, 726, 1155 |
| Goal seeding pattern (AddGoal + `Link(origin, RelSpawns, goal)`) | server/goals_api.go:72-80 |
| `db.KindFact`, `db.KindIntent`, `db.KindGoal`, `db.RelSpawns` | db/constants.go:8, 7, 6, 35 |
| `db.Node{ID, Payload json.RawMessage, Priority, State}` | db/exploration.go:67-84 |
| `db.Activity{Kind, Tool, IsError, Summary}` | db/exploration.go:87-96 |
| `(*DB).Assets() *AssetStore`, `(*AssetStore).UpsertHTTPService(UpsertHTTPServiceReq{URL, TaskID})` | db/assets.go:94, 683, 669 |
| `exploration_anchors.asset_id REFERENCES assets(id)` | db/schema.sql:276-280. This is why targets are inserted as real asset rows. |
| Env `ARTEX_PG_DSN` | config/config.go:202 |

## Design decisions (defaults chosen without asking)

- **Tool set.** The agent gets `VulnixAllowedPlannerTools(tsx)`, which is the real `PlannerTools()` filtered to the 8 names, in allowlist order. The build fails at runtime if any of the 8 is missing upstream. Nothing else is passed: no `actool.DefaultTools()`, no `AugmentTools`, no MCP or skills. `EnableWebFetch=false` and `EnableWebSearch=false` are set. `Todos` is unset, so no TodoWrite store is wired. No kill/steer callbacks, finding recorder or asset store are set on the ToolSet.
- **Permission.** `PermissionMode` is left at its zero value, not `permission.ModeBypass`. A deny-by-default PreToolUse hook (`vulnixToolGate`) blocks any name outside the allowlist and records it.
- **Targets.** Each target URL is upserted as an ARTEX `service/http` asset, because intents can only anchor to existing asset rows. One fact per target is also seeded, saying "asset_id=<ARTEX id> url=… target_id=…". The planner learns the ids from that fact, since `list_assets` is not allowed. In the output, `asset_ids` are mapped back to the **Vulnix** asset ids. ARTEX asset ids that are not seeded targets are dropped and logged to stderr.
- **Observations.** Each observation is seeded as a `fact` node: summary=title, detail=detail, confidence=observed, state=confirmed, origin=vulnix.
- **Goal.** There is one goal node with `{"text": goal}`. `goal_met` is true if the round set `ToolSet.GoalMet` or every goal node is in state `met`.
- **Turns and time.** `max_turns` defaults to 8 and is clamped to 1..40. The whole run has a 10-minute context timeout.
- **Cleanup.** The temp work dir is removed at exit. DB rows are left in place, on the assumption that CI uses a throwaway PG container.
- **Output.** `tool_calls` come from captureRun's `tool_use` activities. `allowed` means the name is in the allowlist. `denied_tool_calls` lists every non-allowlisted call: ones the hook blocked, plus ones the harness may have rejected as unknown tools before the hook ran. The terminal reason is logged to stderr only, so stdout keeps exactly the specified fields.

## Unverified points: likely compile or runtime risks

1. **norma API shapes** (not readable locally). The following are known only from ARTEX usage:
   - field names and types of `agentcore.Options`
   - that `*hook.Registry` satisfies `Options.Hooks`
   - `hook.Event`/`hook.Result` field names
   - whether `hook.Result.Decision` is a plain `string` or a named string type. The test compares it to `"block"`, which compiles either way.

   If a compile error mentions these, check `norma@v0.4.3` in the CI module cache.
2. **Zero-value `PermissionMode`.** Its semantics are unknown. If it makes the harness "ask" before write tools and there is no asker, `add_intent`/`prove_goal` may be refused. ARTEX's own tools return `acperm.Allowed()` from their Permissions func (tools.go:285, 295), so this is expected to pass. The symptom would be `tool_result is_error` lines on stderr and no intents. The fix would be to choose an explicit non-bypass mode from norma's `permission` package after reading it.
3. **Implicit tools.** Whether agentcore adds any built-in tools itself, for example TodoWrite or ToolSearch, when they are not in `Tools` is unknown. `allowed_tools` reports what we passed. Any such tool the model calls would be blocked by the hook and would show up in `denied_tool_calls`.
4. **Hook coverage.** Whether the PreToolUse hook fires for a tool name that is not registered is unknown; the harness may reject it earlier. Either way the call does not execute and is counted as denied.
5. **Non-streaming.** `Options.NonStreaming=true` is set and `Config.Stream=false`. The mock must serve non-streaming `/chat/completions`, meaning `stream:false` and a single JSON response.
6. **Compaction and settlement.** `Compaction` uses the same provider for summaries, and the settlement round can spend up to `WrapupTurnsDefault("planner")` extra turns after `MaxTurns`. With a short mock script neither should trigger, but a mock that answers forever with tool calls will see the wrap-up prompt.
7. **`db.Open` side effects.** It creates the database if it is missing, applies `schema.sql`, and seeds builtin agents and a disabled browser MCP row (db/db.go:134-170). These are writes to the local PG only, and nothing is spawned.
8. **`UpsertHTTPService` side effects.** It also upserts root-domain and subdomain assets via `linkHostAssets` (db/assets.go:939-946) and resolves company scope. These are DB-only.
9. **Copied lead strings.** They match commit d6964594 exactly, but nothing checks them at build time.
