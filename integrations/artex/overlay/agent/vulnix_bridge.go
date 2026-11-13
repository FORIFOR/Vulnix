// Part of an overlay for ARTEX (AGPL-3.0); this file is licensed AGPL-3.0-or-later.
//
// It is copied into an ARTEX checkout (github.com/Autumn-27/artex) at agent/ before
// `go build`, so it lives in package agent and calls ARTEX's own planner pieces
// (ToolSet.PlannerTools, plannerSystem, renderGraphOverview, captureRun, ...)
// rather than reimplementing them. See integrations/artex/OVERLAY_NOTES.md in the
// Vulnix repository for where every identifier used here was verified.
//
// What this adds: one planner round, run through agentcore with a strictly
// restricted tool set, for local verification against a mock LLM. No workers are
// started, no shell/file/web tools are given to the model, and a deny-by-default
// PreToolUse hook rejects any tool name outside the allowlist.

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"
	actool "github.com/Autumn-27/norma/tool"
)

// VulnixLoopbackOnlyTransport makes every connection of the default HTTP transport -
// and of every transport cloned from it, such as ARTEX's LLM client - loopback only.
// Redirects or any other outbound HTTP to another host fail at dial time.
func VulnixLoopbackOnlyTransport() *http.Transport {
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.Proxy = nil
	d := &net.Dialer{Timeout: 10 * time.Second}
	base.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips := []net.IP{net.ParseIP(host)}
		if ips[0] == nil {
			found, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			ips = found
		}
		for _, ip := range ips {
			if ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("vulnix-planner: refusing non-loopback connection to %s", addr)
			}
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return base
}

// VulnixDisallowedTools are never available to the planner, whatever else is configured.
var VulnixDisallowedTools = []string{
	"Bash", "Read", "Write", "Edit", "MultiEdit", "LS", "Glob", "Grep", "WebFetch", "WebSearch",
	"TaskOutput", "TaskStop", "TaskList", "Monitor", "TodoWrite", "AskUserQuestion", "Skill",
	"add_company_scope", "add_task_scope", "report_finding", "list_assets", "list_untested_assets",
	"kill_work", "steer_work", "get_worker_output", "get_worker_trace", "search_all_worker_traces",
}

// VulnixPlannerAllowlist is the exact set of ARTEX planner tool names the
// planner-only run may use: read-only graph views plus intent generation and goal
// judgement. Names are the ones registered in agent/tools.go.
var VulnixPlannerAllowlist = []string{
	"graph_overview",
	"list_facts",
	"list_findings",
	"node_detail",
	"list_goals",
	"add_intent",
	"prove_goal",
	"goal_met",
}

func vulnixAllowSet() map[string]bool {
	m := make(map[string]bool, len(VulnixPlannerAllowlist))
	for _, n := range VulnixPlannerAllowlist {
		m[n] = true
	}
	return m
}

// VulnixAllowedPlannerTools takes the REAL planner tool list (tsx.PlannerTools())
// and keeps only the allowlisted tools, in allowlist order. It fails if any
// allowlisted name is missing from ARTEX's planner tool list (a rename upstream
// must not silently shrink the set) or appears twice.
func VulnixAllowedPlannerTools(tsx *ToolSet) ([]actool.CoreTool, error) {
	byName := map[string]actool.CoreTool{}
	for _, t := range tsx.PlannerTools() {
		name := t.Name()
		if !vulnixAllowSet()[name] {
			continue
		}
		if _, dup := byName[name]; dup {
			return nil, fmt.Errorf("planner tool %q registered twice", name)
		}
		byName[name] = t
	}
	out := make([]actool.CoreTool, 0, len(VulnixPlannerAllowlist))
	for _, name := range VulnixPlannerAllowlist {
		t, ok := byName[name]
		if !ok {
			return nil, fmt.Errorf("allowlisted tool %q is not in ARTEX PlannerTools()", name)
		}
		out = append(out, t)
	}
	return out, nil
}

// VulnixCheckLoopbackURL accepts only an http(s) URL whose host is literally
// 127.0.0.1, ::1 or localhost. This build is for local mock-LLM verification.
func VulnixCheckLoopbackURL(raw string) error {
	return vulnixCheckLoopback(raw, []string{"http", "https"})
}

// VulnixCheckLoopbackDSN applies the same rule to a postgres:// DSN.
func VulnixCheckLoopbackDSN(raw string) error {
	return vulnixCheckLoopback(raw, []string{"postgres", "postgresql"})
}

func vulnixCheckLoopback(raw string, schemes []string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("empty URL")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("unparseable URL: %v", err)
	}
	okScheme := false
	for _, s := range schemes {
		if strings.EqualFold(u.Scheme, s) {
			okScheme = true
		}
	}
	if !okScheme {
		return fmt.Errorf("scheme %q not allowed (want one of %v)", u.Scheme, schemes)
	}
	// pgx honours host/hostaddr query parameters, which would override the host above
	q := u.Query()
	for _, k := range []string{"host", "hostaddr", "service", "servicefile"} {
		if q.Has(k) {
			return fmt.Errorf("query parameter %q is not allowed (it can redirect the connection)", k)
		}
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "localhost":
		return nil
	case "":
		return fmt.Errorf("URL has no host")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q is not loopback (only 127.0.0.1, ::1, localhost)", host)
	}
	if ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.IPv6loopback) {
		return nil
	}
	return fmt.Errorf("host %q is not loopback (only 127.0.0.1, ::1, localhost)", host)
}

// vulnixToolGate is the deny-by-default PreToolUse hook: any tool whose name is
// not in the allowlist is blocked before it runs, and the denial is recorded.
type vulnixToolGate struct {
	mu      sync.Mutex
	allowed map[string]bool
	denied  []string
}

func newVulnixToolGate(names []string) *vulnixToolGate {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return &vulnixToolGate{allowed: m}
}

func (g *vulnixToolGate) preToolUse(_ context.Context, ev hook.Event) hook.Result {
	if g.allowed[ev.ToolName] {
		return hook.Result{}
	}
	g.mu.Lock()
	g.denied = append(g.denied, ev.ToolName)
	g.mu.Unlock()
	return hook.Result{Decision: "block", Message: "tool " + ev.ToolName + " is not available in this planner-only run"}
}

// Denied returns the tool names the hook blocked, in order.
func (g *vulnixToolGate) Denied() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.denied...)
}

func (g *vulnixToolGate) registry() *hook.Registry {
	return hook.NewRegistry().On(hook.PreToolUse, g.preToolUse)
}

// VulnixTarget is one Vulnix target the planner may plan against.
type VulnixTarget struct {
	AssetID  int64  `json:"asset_id"`
	TargetID string `json:"target_id"`
	URL      string `json:"url"`
}

// VulnixObservation is one prior observation, seeded as a fact.
type VulnixObservation struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// VulnixPlannerRequest is the CLI's stdin request.
type VulnixPlannerRequest struct {
	Goal         string              `json:"goal"`
	Targets      []VulnixTarget      `json:"targets"`
	Observations []VulnixObservation `json:"observations"`
	MaxTurns     int                 `json:"max_turns"`
	// EgressCanary (optional, loopback ip:port only): before planning, this process
	// tries ONE direct TCP connection there and reports the outcome - evidence that
	// the OS confinement around THIS process drops non-pinned traffic.
	EgressCanary string `json:"egress_canary"`
}

// VulnixEgressCanary tries one TCP connection (no data sent) to a loopback ip:port
// and reports "connected" or "blocked: <error>". It bypasses the HTTP transport on
// purpose: what is tested is the kernel, not Vulnix's own dialer.
func VulnixEgressCanary(addr string) string {
	if err := VulnixCheckLoopbackURL("http://" + addr); err != nil {
		return "refused: not a loopback address"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || net.ParseIP(host) == nil {
		return "refused: not an ip:port"
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "blocked: " + err.Error()
	}
	_ = conn.Close()
	return "connected"
}

// VulnixToolCall is one tool call the model made.
type VulnixToolCall struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

// VulnixIntent is one intent the planner wrote into the store. AssetIDs are
// Vulnix asset ids (mapped back from the ARTEX asset rows seeded for the targets).
type VulnixIntent struct {
	ID       int64   `json:"id"`
	Summary  string  `json:"summary"`
	AssetIDs []int64 `json:"asset_ids"`
	Priority int     `json:"priority"`
	// ARTEX asset ids the intent named that are not seeded Vulnix targets: Vulnix
	// treats such an intent as advisory (never executable).
	UnmappedAssetIDs []int64 `json:"unmapped_asset_ids"`
}

// VulnixPlannerResult is what one round produced.
type VulnixPlannerResult struct {
	AllowedTools    []string
	ToolCalls       []VulnixToolCall
	DeniedToolCalls []string
	Intents         []VulnixIntent
	GoalMet         bool
	TerminalReason  string
}

const (
	vulnixDefaultMaxTurns = 8
	vulnixMaxMaxTurns     = 40
)

// VulnixRunPlanner seeds a fresh ARTEX task with the request, runs ONE planner
// round with the allowlisted tools only, and reads back the intents and goal state.
// workDir must be a temp directory owned by the caller.
func VulnixRunPlanner(ctx context.Context, d *db.DB, prov llm.Provider, req VulnixPlannerRequest, workDir string, logf func(string, ...any)) (*VulnixPlannerResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	goal := strings.TrimSpace(req.Goal)
	if goal == "" {
		return nil, fmt.Errorf("goal is required")
	}
	maxTurns := req.MaxTurns
	if maxTurns <= 0 {
		maxTurns = vulnixDefaultMaxTurns
	}
	if maxTurns > vulnixMaxMaxTurns {
		maxTurns = vulnixMaxMaxTurns
	}

	// --- seed: the real task-creation path (exploration + origin fact + task row) ---
	task, err := d.CreateTaskWithOptions("Vulnix planner-only verification run", goal, db.TaskCreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}
	ts := d.Exploration(task.ExplorationID)
	origin, err := ts.OriginFactID()
	if err != nil {
		return nil, fmt.Errorf("origin fact: %w", err)
	}
	// one goal node, as the goals API does (server/goals_api.go): AddGoal + spawns edge.
	goalID, err := ts.AddGoal(map[string]any{"text": goal}, "human")
	if err != nil {
		return nil, fmt.Errorf("add goal: %w", err)
	}
	if origin > 0 {
		_ = ts.Link(origin, db.RelSpawns, goalID)
	}

	// Targets become real asset rows (exploration_anchors.asset_id has an FK to
	// assets.id, so add_intent's asset_ids must name existing assets). The planner
	// learns the ARTEX asset ids from one fact per target; we map them back after.
	as := d.Assets()
	artexToVulnix := map[int64][]int64{}
	for _, tg := range req.Targets {
		if strings.TrimSpace(tg.URL) == "" {
			continue
		}
		aid, err := as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: tg.URL, TaskID: task.ID})
		if err != nil {
			return nil, fmt.Errorf("seed target asset %q: %w", tg.URL, err)
		}
		artexToVulnix[aid] = append(artexToVulnix[aid], tg.AssetID)
		payload := map[string]any{
			"summary":    fmt.Sprintf("In-scope target: asset_id=%d url=%s (target_id=%s). Use asset_ids=[%d] for intents aimed at it.", aid, tg.URL, tg.TargetID, aid),
			"detail":     fmt.Sprintf("asset_id=%d\nurl=%s\ntarget_id=%s", aid, tg.URL, tg.TargetID),
			"confidence": "observed",
		}
		if _, err := ts.AddNode(db.KindFact, payload, 5, "confirmed", "vulnix", []int64{aid}); err != nil {
			return nil, fmt.Errorf("seed target fact: %w", err)
		}
	}
	for _, ob := range req.Observations {
		if strings.TrimSpace(ob.Title) == "" {
			continue
		}
		payload := map[string]any{"summary": ob.Title, "confidence": "observed"}
		if strings.TrimSpace(ob.Detail) != "" {
			payload["detail"] = ob.Detail
		}
		if _, err := ts.AddNode(db.KindFact, payload, 5, "confirmed", "vulnix", nil); err != nil {
			return nil, fmt.Errorf("seed observation fact: %w", err)
		}
	}

	// --- tool set: mirrors Planner.Plan's ToolSet wiring, minus the asset store,
	// kill/steer callbacks and finding recorder; then the allowlist filter. ---
	tsx := NewToolSet(ts, "planner")
	tsx.SetTaskID(task.ID)
	tsx.SetCoverageEnabled(true)
	if origin > 0 {
		tsx.SetOwnerNode(origin)
	}
	tools, err := VulnixAllowedPlannerTools(tsx)
	if err != nil {
		return nil, err
	}
	allowedNames := make([]string, 0, len(tools))
	for _, t := range tools {
		allowedNames = append(allowedNames, t.Name())
	}
	gate := newVulnixToolGate(allowedNames)

	// --- prompt: the planner's own system prompt + the same user-turn assembly
	// Planner.Plan uses for a no-trigger wake (lead strings copied verbatim). ---
	taskDir := ensureRunDir(workDir, task.ID, 0)
	sysBody := plannerSystem(goal, workDir, taskDir) + constraintBlock(ts)
	system, boundary := deferredSystem(sysBody, DeferredInfo{})
	situational := renderTriggers(ts, nil) + renderGraphOverview(tsx.graphOverviewData())
	lead := vulnixLeadHeartbeat
	if active, err := ts.HasActiveIntent(); err == nil && !active {
		lead = vulnixLeadStalled
	}
	input := lead + situational + vulnixInputTail + renderPlannerTodos(nil)

	opts := agentcore.Options{
		Provider:        prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		// PermissionMode deliberately left at its zero value (NOT permission.ModeBypass).
		EnableWebFetch:  false,
		EnableWebSearch: false,
		WorkingDir:      taskDir,
		ToolOutputDir:   cmdOutDir(taskDir),
		MaxTurns:        maxTurns,
		Compaction:      compactionConfig(0),
		Settlement:      wrapupSettlement("planner", nil),
		NonStreaming:    true,
		// norma injects background-task tools (TaskOutput/TaskStop/TaskList/Monitor) by
		// default; the planner gets none of them (found by the Vulnix CI check of the
		// tools actually offered to the model).
		DisableBackgroundTasks: true,
		// Denied at call time by norma's permission check (it does not remove a tool
		// from what the model is offered: that is done by Tools and
		// DisableBackgroundTasks above). Defence in depth with the deny hook.
		DisallowedTools: VulnixDisallowedTools,
	}
	opts.Hooks = gate.registry()

	var (
		callsMu sync.Mutex
		calls   []VulnixToolCall
	)
	allowSet := vulnixAllowSet()
	_, reason, runErr := captureRun(ctx, opts, input, func(r db.Activity) {
		switch r.Kind {
		case "tool_use":
			callsMu.Lock()
			calls = append(calls, VulnixToolCall{Name: r.Tool, Allowed: allowSet[r.Tool]})
			callsMu.Unlock()
			logf("tool_use %s", r.Tool)
		case "tool_result":
			if r.IsError {
				logf("tool_result %s is_error: %s", r.Tool, r.Summary)
			}
		case "result":
			if r.IsError {
				logf("run result error: %s", r.Summary)
			}
		}
	})
	if runErr != nil {
		return nil, fmt.Errorf("planner round: %w", runErr)
	}

	// --- read back ---
	nodes, err := ts.ListByKind(db.KindIntent, 1000)
	if err != nil {
		return nil, fmt.Errorf("list intents: %w", err)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })
	intents := make([]VulnixIntent, 0, len(nodes))
	for _, n := range nodes {
		var p struct {
			Summary  string  `json:"summary"`
			AssetIDs []int64 `json:"asset_ids"`
		}
		_ = json.Unmarshal(n.Payload, &p)
		mapped := []int64{}
		unmapped := []int64{}
		for _, aid := range p.AssetIDs {
			vs, ok := artexToVulnix[aid]
			if !ok {
				logf("intent %d references ARTEX asset %d that is not a seeded target", n.ID, aid)
				unmapped = append(unmapped, aid)
				continue
			}
			mapped = append(mapped, vs...)
		}
		intents = append(intents, VulnixIntent{ID: n.ID, Summary: p.Summary, AssetIDs: mapped,
			Priority: n.Priority, UnmappedAssetIDs: unmapped})
	}

	goalMet := tsx.GoalMet
	if goals, err := ts.ListByKind(db.KindGoal, 1000); err == nil && len(goals) > 0 {
		all := true
		for _, g := range goals {
			if g.State != "met" {
				all = false
			}
		}
		goalMet = goalMet || all
	}

	callsMu.Lock()
	defer callsMu.Unlock()
	return &VulnixPlannerResult{
		AllowedTools:    allowedNames,
		ToolCalls:       append([]VulnixToolCall{}, calls...),
		DeniedToolCalls: vulnixMergeDenied(calls, gate.Denied()),
		Intents:         intents,
		GoalMet:         goalMet,
		TerminalReason:  fmt.Sprintf("%v", reason),
	}, nil
}

// vulnixMergeDenied lists every non-allowed tool call: calls the model made to a
// name outside the allowlist (whether the harness rejected it as unknown or the
// hook blocked it), plus any hook denial not already accounted for.
func vulnixMergeDenied(calls []VulnixToolCall, hookDenied []string) []string {
	out := []string{}
	seen := map[string]int{}
	for _, c := range calls {
		if !c.Allowed {
			out = append(out, c.Name)
			seen[c.Name]++
		}
	}
	for _, n := range hookDenied {
		if seen[n] > 0 {
			seen[n]--
			continue
		}
		out = append(out, n)
	}
	return out
}

// VulnixTempWorkDir creates the per-run temp work dir.
func VulnixTempWorkDir() (string, error) {
	return os.MkdirTemp("", "vulnix-artex-planner-")
}

// The three user-turn strings below are copied verbatim from agent/planner.go
// (Planner.Plan, the no-trigger branch and the input tail) because Plan builds
// them inline rather than through a helper.
const vulnixLeadHeartbeat = "本轮是**定时巡检（心跳到点）/无具体变动信号**的唤醒——图不一定有新变动。顺带复查在跑意图：长时间无进展或跑偏的用 steer_work 纠偏、方向整个错的用 kill_work 止损；再判定目标、决定是否补方向："

const vulnixLeadStalled = "本轮是**定时巡检（心跳到点）**的唤醒,且当前**已没有任何 open 或 running 的意图**——没有 worker 在跑、也没有排队中的方向,探索已停摆。你**必须**在本轮产出一个或多个向目标推进、且与图中既有意图**互不重复**的新意图(不得产出 0 意图);先据下面的态势判定目标是否已达成,未达成则立即补方向："

const vulnixInputTail = "\n\n据上面的态势，判定目标。目标已【真正达成】（已拿到目标成果/已确认目标漏洞）时用 prove_goal 逐个标记。**硬底线：只要目标尚未达成、且当前没有任何 open 或 running 意图（frontier_open=0 且 running_intents 为空），本轮就必须产出至少一个向目标推进的意图——此时没有在跑的 work 可等、也没有在排队的方向，产出 0 意图=任务停摆。仅当已有 open/running 意图在推进、或目标已达成时，本轮才可以不产出新意图。**"
