// Part of an overlay for ARTEX (AGPL-3.0); this file is licensed AGPL-3.0-or-later.
//
// Command vulnix-planner runs ONE real ARTEX planner round with a restricted tool
// set and prints the intents it produced as a single JSON object on stdout.
//
// Input (stdin): {"goal": "...", "targets": [{"asset_id": 1, "target_id": "...",
// "url": "..."}], "observations": [{"title": "...", "detail": "..."}],
// "max_turns": 8}
//
// Environment:
//
//	ARTEX_LLM_BASE_URL  OpenAI-compatible endpoint; host must be 127.0.0.1, ::1 or localhost
//	ARTEX_LLM_MODEL     model id (required)
//	ARTEX_LLM_API_KEY   API key (any non-empty value for a mock; never printed)
//	ARTEX_PG_DSN        postgres:// DSN; host must be loopback (ARTEX's store is PostgreSQL)
//
// Diagnostics go to stderr. On any failure stdout gets {"engine":"artex","error":...}
// and the exit status is non-zero.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// artexCommit is injected at build time: -ldflags "-X main.artexCommit=<sha>".
var artexCommit = "unknown"

const artexModule = "github.com/Autumn-27/artex"

type toolCallOut struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

type intentOut struct {
	ID       int64   `json:"id"`
	Summary  string  `json:"summary"`
	AssetIDs []int64 `json:"asset_ids"`
	Priority int     `json:"priority"`
}

type output struct {
	Engine          string        `json:"engine"`
	ArtexModule     string        `json:"artex_module"`
	ArtexCommit     string        `json:"artex_commit"`
	GoVersion       string        `json:"go_version"`
	AllowedTools    []string      `json:"allowed_tools"`
	ToolCalls       []toolCallOut `json:"tool_calls"`
	DeniedToolCalls []string      `json:"denied_tool_calls"`
	Intents         []intentOut   `json:"intents"`
	GoalMet         bool          `json:"goal_met"`
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[vulnix-planner] "+format+"\n", args...)
}

func fail(err error) {
	msg := err.Error()
	if key := os.Getenv("ARTEX_LLM_API_KEY"); key != "" {
		msg = strings.ReplaceAll(msg, key, "[redacted]")
	}
	b, _ := json.Marshal(map[string]string{"engine": "artex", "error": msg})
	fmt.Fprintln(os.Stdout, string(b))
	os.Exit(1)
}

func main() {
	if err := run(); err != nil {
		fail(err)
	}
}

func run() error {
	baseURL := strings.TrimSpace(os.Getenv("ARTEX_LLM_BASE_URL"))
	model := strings.TrimSpace(os.Getenv("ARTEX_LLM_MODEL"))
	apiKey := os.Getenv("ARTEX_LLM_API_KEY")
	dsn := strings.TrimSpace(os.Getenv("ARTEX_PG_DSN"))

	if err := agent.VulnixCheckLoopbackURL(baseURL); err != nil {
		return fmt.Errorf("refusing to start: ARTEX_LLM_BASE_URL must be a loopback http(s) URL: %v", err)
	}
	if model == "" {
		return fmt.Errorf("ARTEX_LLM_MODEL is required")
	}
	if strings.TrimSpace(apiKey) == "" {
		return fmt.Errorf("ARTEX_LLM_API_KEY is required")
	}
	if err := agent.VulnixCheckLoopbackDSN(dsn); err != nil {
		return fmt.Errorf("refusing to start: ARTEX_PG_DSN must be a loopback postgres:// DSN: %v", err)
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var req agent.VulnixPlannerRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return fmt.Errorf("parse request JSON: %w", err)
	}

	// ARTEX's own provider construction (agent/provider.go). Proxy "" = direct
	// (it does not fall back to *_PROXY). Stream=false selects the non-streaming
	// path; the run also sets agentcore.Options.NonStreaming=true.
	// Before ARTEX builds its LLM client (a clone of the default transport): every
	// connection is loopback only, so a redirect cannot carry the request elsewhere.
	http.DefaultTransport = agent.VulnixLoopbackOnlyTransport()
	cfg := agent.ConfigFrom("openai", model, baseURL, apiKey, "")
	cfg.Stream = false
	prov, err := cfg.NewProvider()
	if err != nil {
		return fmt.Errorf("build LLM provider: %w", err)
	}

	d, err := db.Open(dsn)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer d.Close()

	workDir, err := agent.VulnixTempWorkDir()
	if err != nil {
		return fmt.Errorf("temp work dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	logf("model=%s targets=%d observations=%d max_turns=%d", model, len(req.Targets), len(req.Observations), req.MaxTurns)
	res, err := agent.VulnixRunPlanner(ctx, d, prov, req, workDir, logf)
	if err != nil {
		return err
	}
	logf("terminal_reason=%s tool_calls=%d intents=%d goal_met=%v", res.TerminalReason, len(res.ToolCalls), len(res.Intents), res.GoalMet)

	out := output{
		Engine:          "artex",
		ArtexModule:     artexModule,
		ArtexCommit:     artexCommit,
		GoVersion:       runtime.Version(),
		AllowedTools:    res.AllowedTools,
		ToolCalls:       []toolCallOut{},
		DeniedToolCalls: res.DeniedToolCalls,
		Intents:         []intentOut{},
		GoalMet:         res.GoalMet,
	}
	if out.DeniedToolCalls == nil {
		out.DeniedToolCalls = []string{}
	}
	for _, c := range res.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, toolCallOut{Name: c.Name, Allowed: c.Allowed})
	}
	for _, it := range res.Intents {
		ids := it.AssetIDs
		if ids == nil {
			ids = []int64{}
		}
		out.Intents = append(out.Intents, intentOut{ID: it.ID, Summary: it.Summary, AssetIDs: ids, Priority: it.Priority})
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(b))
	return nil
}
