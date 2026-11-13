// Part of an overlay for ARTEX (AGPL-3.0); this file is licensed AGPL-3.0-or-later.

package agent

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Autumn-27/norma/hook"
	actool "github.com/Autumn-27/norma/tool"
)

// (a) the tool set handed to the agent is exactly the allowlist, taken from the
// real PlannerTools(), and contains none of the shell/file/web/scope/worker tools.
func TestVulnixBridgeAllowlistedToolsAreExact(t *testing.T) {
	tools, err := VulnixAllowedPlannerTools(NewToolSet(nil, "planner"))
	if err != nil {
		t.Fatalf("VulnixAllowedPlannerTools: %v", err)
	}
	got := make([]string, 0, len(tools))
	for _, tool := range tools {
		got = append(got, tool.Name())
	}
	want := append([]string(nil), VulnixPlannerAllowlist...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("tool names = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("tool names = %v, want %v", got, want)
		}
	}

	forbidden := map[string]bool{
		"Bash": true, "Read": true, "Write": true, "Edit": true, "MultiEdit": true,
		"LS": true, "Glob": true, "Grep": true, "WebFetch": true, "WebSearch": true,
		"add_company_scope": true, "add_task_scope": true, "add_finding": true,
		"report_finding": true, "kill_work": true, "steer_work": true,
		"list_assets": true, "list_untested_assets": true,
		"get_worker_output": true, "get_worker_trace": true,
	}
	// Whatever ARTEX's default (shell/file) tools are named, none may be present.
	for _, d := range actool.DefaultTools() {
		forbidden[d.Name()] = true
	}
	for _, name := range got {
		if forbidden[name] {
			t.Errorf("forbidden tool %q is in the planner-only tool set", name)
		}
	}

	// The allowlist must not name a forbidden tool either.
	for _, name := range VulnixPlannerAllowlist {
		if forbidden[name] {
			t.Errorf("allowlist names forbidden tool %q", name)
		}
	}
}

// (b) the loopback check.
func TestVulnixBridgeLoopbackCheck(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8080/v1",
		"http://localhost:11434/v1",
		"http://[::1]:9000/v1",
		"https://127.0.0.1/v1",
	}
	for _, u := range ok {
		if err := VulnixCheckLoopbackURL(u); err != nil {
			t.Errorf("VulnixCheckLoopbackURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{
		"https://api.openai.com/v1",
		"http://example.com:8080/v1",
		"http://10.0.0.5:8080/v1",
		"http://127.0.0.1.evil.example/v1",
		"http://localhost.evil.example/v1",
		"http://0.0.0.0:8080/v1",
		"ftp://127.0.0.1/v1",
		"127.0.0.1:8080",
		"",
	}
	for _, u := range bad {
		if err := VulnixCheckLoopbackURL(u); err == nil {
			t.Errorf("VulnixCheckLoopbackURL(%q) = nil, want error", u)
		}
	}
	if err := VulnixCheckLoopbackDSN("postgres://artex:x@127.0.0.1:5432/artex?sslmode=disable"); err != nil {
		t.Errorf("loopback DSN rejected: %v", err)
	}
	if err := VulnixCheckLoopbackDSN("postgres://artex:x@db.example.com:5432/artex"); err == nil {
		t.Errorf("non-loopback DSN accepted")
	}
}

// (c) the deny-by-default hook blocks names outside the allowlist and records them.
func TestVulnixBridgeDenyHook(t *testing.T) {
	g := newVulnixToolGate(VulnixPlannerAllowlist)
	ctx := context.Background()
	for _, name := range []string{"Bash", "WebFetch", "add_company_scope"} {
		res := g.preToolUse(ctx, hook.Event{ToolName: name})
		if res.Decision != "block" {
			t.Errorf("hook decision for %q = %q, want block", name, res.Decision)
		}
	}
	if res := g.preToolUse(ctx, hook.Event{ToolName: "add_intent"}); res.Decision == "block" {
		t.Errorf("hook blocked allowlisted add_intent")
	}
	denied := g.Denied()
	want := []string{"Bash", "WebFetch", "add_company_scope"}
	if len(denied) != len(want) {
		t.Fatalf("Denied() = %v, want %v", denied, want)
	}
	for i := range want {
		if denied[i] != want[i] {
			t.Fatalf("Denied() = %v, want %v", denied, want)
		}
	}
	if g.registry() == nil {
		t.Fatalf("registry() returned nil")
	}
}

func TestVulnixBridgeMergeDenied(t *testing.T) {
	calls := []VulnixToolCall{{Name: "graph_overview", Allowed: true}, {Name: "Bash", Allowed: false}}
	got := vulnixMergeDenied(calls, []string{"Bash", "WebFetch"})
	if len(got) != 2 || got[0] != "Bash" || got[1] != "WebFetch" {
		t.Fatalf("vulnixMergeDenied = %v, want [Bash WebFetch]", got)
	}
}

func TestVulnixBridgeDSNHostOverridesAreRefused(t *testing.T) {
	for _, dsn := range []string{
		"postgres://u:p@127.0.0.1/db?host=db.example.com",
		"postgres://127.0.0.1/db?hostaddr=10.0.0.1",
		"postgresql://localhost/db?service=prod",
	} {
		if err := VulnixCheckLoopbackDSN(dsn); err == nil {
			t.Fatalf("DSN with a host override was accepted: %s", dsn)
		}
	}
	if err := VulnixCheckLoopbackDSN("postgres://artex:x@127.0.0.1:5432/artex?sslmode=disable"); err != nil {
		t.Fatalf("plain loopback DSN refused: %v", err)
	}
}

func TestVulnixBridgeTransportRefusesNonLoopback(t *testing.T) {
	tr := VulnixLoopbackOnlyTransport()
	for _, addr := range []string{"93.184.216.34:80", "10.0.0.1:443", "[2001:db8::1]:80"} {
		if _, err := tr.DialContext(context.Background(), "tcp", addr); err == nil ||
			!strings.Contains(err.Error(), "non-loopback") {
			t.Fatalf("dial to %s was not refused as non-loopback: %v", addr, err)
		}
	}
	if tr.Proxy != nil {
		t.Fatalf("transport must not use a proxy")
	}
}

func TestVulnixBridgeBackgroundAndExecToolsAreDisallowed(t *testing.T) {
	want := map[string]bool{}
	for _, n := range VulnixDisallowedTools {
		want[n] = true
	}
	for _, n := range []string{"Bash", "WebFetch", "TaskOutput", "TaskStop", "TaskList", "Monitor", "add_task_scope"} {
		if !want[n] {
			t.Fatalf("%s missing from VulnixDisallowedTools", n)
		}
	}
	for _, n := range VulnixPlannerAllowlist {
		if want[n] {
			t.Fatalf("%s is both allowed and disallowed", n)
		}
	}
}

func TestVulnixBridgeEgressCanaryIsLoopbackOnly(t *testing.T) {
	for _, addr := range []string{"93.184.216.34:80", "example.com:80", "10.0.0.1:5432"} {
		if got := VulnixEgressCanary(addr); !strings.HasPrefix(got, "refused:") {
			t.Fatalf("canary to %s was attempted: %s", addr, got)
		}
	}
}
