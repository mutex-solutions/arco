package mcp_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/registry"
)

// herdr returns "timeout" only after accepting a prompt, so a wait that
// expires must not read as a failure, or callers resend the prompt.
func TestPromptAgent_Outcomes(t *testing.T) {
	fh := fakeherdr.Start(t)
	code := "timeout"
	fh.On("agent.prompt", func(json.RawMessage) (any, *herdr.RPCError) {
		return nil, &herdr.RPCError{Code: code, Message: "herdr says " + code}
	})
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))
	prompt := func(args map[string]any) (string, bool) {
		args["machine"], args["target"], args["text"] = "vm0", "w1:p1", "go"
		return callText(t, cs, "prompt_agent", args)
	}

	txt, isErr := prompt(map[string]any{"wait_timeout_ms": 3000})
	if isErr || !strings.Contains(txt, `"delivered":true`) || !strings.Contains(txt, `"wait_timed_out":true`) || !strings.Contains(txt, "Do not resend") {
		t.Fatalf("timed-out wait: isErr=%v %s", isErr, txt)
	}

	code = "agent_prompt_stalled"
	if txt, isErr = prompt(map[string]any{"wait_timeout_ms": 3000}); !isErr || !strings.Contains(txt, "the prompt was submitted") {
		t.Fatalf("stalled: isErr=%v %s", isErr, txt)
	}
	code = "agent_blocked"
	if txt, isErr = prompt(map[string]any{}); !isErr || !strings.Contains(txt, "the prompt was not submitted") {
		t.Fatalf("blocked: isErr=%v %s", isErr, txt)
	}
	code = "agent_not_found"
	if txt, isErr = prompt(map[string]any{}); !isErr || strings.Contains(txt, "submitted") {
		t.Fatalf("other errors pass through unchanged: isErr=%v %s", isErr, txt)
	}
}

// herdr silently falls back to $HOME for a missing cwd; arco says so.
func TestCreateWorkspace_WarnsOnCwdFallback(t *testing.T) {
	fh := fakeherdr.Start(t)
	actual := "/home/me"
	fh.On("workspace.create", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type":      "workspace_created",
			"workspace": map[string]any{"workspace_id": "w2", "revision": 9007199254740993},
			"root_pane": map[string]any{"pane_id": "w2:p1", "cwd": actual},
		}, nil
	})
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	txt, isErr := callText(t, cs, "create_workspace", map[string]any{"machine": "vm0", "cwd": "/nonexistent/dir"})
	if isErr || !strings.Contains(txt, `"warning":"requested cwd`) || !strings.Contains(txt, `"pane_id":"w2:p1"`) || !strings.Contains(txt, "9007199254740993") {
		t.Fatalf("missing cwd warning: %s", txt)
	}
	actual = "/srv/app"
	for _, cwd := range []string{"/srv/app", "/srv/app/", ""} {
		args := map[string]any{"machine": "vm0"}
		if cwd != "" {
			args["cwd"] = cwd
		}
		if txt, _ := callText(t, cs, "create_workspace", args); strings.Contains(txt, "warning") {
			t.Fatalf("unexpected warning for cwd %q: %s", cwd, txt)
		}
	}
}
