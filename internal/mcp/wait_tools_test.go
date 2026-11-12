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

func TestWaitForOutput(t *testing.T) {
	fh := fakeherdr.Start(t)
	var got herdr.PaneWaitForOutputParams
	fh.On("pane.wait_for_output", func(p json.RawMessage) (any, *herdr.RPCError) {
		_ = json.Unmarshal(p, &got)
		if got.Match.Value == "never" {
			return nil, &herdr.RPCError{Code: "timeout", Message: "timed out waiting for output match"}
		}
		return map[string]any{
			"type": "output_matched", "pane_id": got.PaneID, "matched_line": "% ",
			"read": map[string]any{"truncated": true, "text": "PARTIALKEYTAIL0123456789abcdef\nlast line\n% "},
		}, nil
	})
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	txt, isErr := callText(t, cs, "wait_for_output", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "pattern": `[$%#]\s*$`, "regex": true})
	if isErr || !strings.Contains(txt, `"output_matched"`) || strings.Contains(txt, "PARTIALKEYTAIL") {
		t.Fatalf("wait_for_output: isErr=%v %s", isErr, txt)
	}
	if got.Source != "recent_unwrapped" || !got.StripANSI || got.Match.Type != "regex" || got.Lines != 21 || got.TimeoutMS != 30000 {
		t.Fatalf("params not forced/defaulted: %+v", got)
	}
	if txt, isErr = callText(t, cs, "wait_for_output", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "pattern": "never", "timeout_ms": 500}); !isErr || !strings.Contains(txt, "timeout") {
		t.Fatalf("timeout must be an error: %s", txt)
	}
	if got.Match.Type != "substring" || got.TimeoutMS != 500 {
		t.Fatalf("substring/timeout params: %+v", got)
	}
	for _, bad := range []map[string]any{
		{"machine": "vm0", "pane_id": "w1:p1", "pattern": ""},
		{"machine": "vm0", "pane_id": "w1:p1", "pattern": "x", "timeout_ms": 120001},
		{"machine": "vm0", "pane_id": "w1:p1", "pattern": "x", "source": "visible"},
	} {
		if _, isErr := callText(t, cs, "wait_for_output", bad); !isErr {
			t.Fatalf("accepted bad args %v", bad)
		}
	}
}

// herdr can leave an agent at launch_pending forever when the shell swallows
// the launch command. wait_agent must surface that as a timeout, never as ready.
func TestWaitAgent_LaunchPendingGhostTimesOut(t *testing.T) {
	fh := fakeherdr.Start(t)
	fh.On("agent.start", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{"type": "agent_started", "argv": []string{"claude"},
			"agent": map[string]any{"name": "ghost", "pane_id": "w1:p1", "agent_status": "unknown", "launch_pending": true}}, nil
	})
	var until []string
	fh.On("agent.wait", func(p json.RawMessage) (any, *herdr.RPCError) {
		var w herdr.AgentWaitParams
		_ = json.Unmarshal(p, &w)
		until = w.Until
		return nil, &herdr.RPCError{Code: "timeout", Message: "timed out waiting for agent status"}
	})
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	txt, isErr := callText(t, cs, "start_agent", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "kind": "claude", "name": "ghost"})
	if isErr || !strings.Contains(txt, `"launch_pending":true`) {
		t.Fatalf("start_agent must pass launch_pending through: %s", txt)
	}
	txt, isErr = callText(t, cs, "wait_agent", map[string]any{"machine": "vm0", "target": "w1:p1", "until": []string{"idle"}, "timeout_ms": 500})
	if !isErr || !strings.Contains(txt, "timeout") || len(until) != 1 || until[0] != "idle" {
		t.Fatalf("wait_agent on a ghost: isErr=%v %s until=%v", isErr, txt, until)
	}
	if _, isErr := callText(t, cs, "wait_agent", map[string]any{"machine": "vm0", "target": "w1:p1", "until": []string{"ready"}}); !isErr {
		t.Fatal("accepted an unknown agent state")
	}
}
