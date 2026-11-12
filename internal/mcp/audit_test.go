package mcp_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/auth"
	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
	arcomcp "github.com/mutex-solutions/arco/internal/mcp"
	"github.com/mutex-solutions/arco/internal/registry"
)

// Every HTTP tool call is attributed to its token; payloads never reach the log.
func TestAudit_HTTPAttributesCallsToTokens(t *testing.T) {
	f := newHTTPFixture(t)
	cs, err := f.connect(t, f.token(t, "ops", auth.ScopeReadWrite, "vm0"))
	if err != nil {
		t.Fatal(err)
	}
	secretText := "echo sk-proj-" + "AUDITPAYLOAD1234567890abcdefghij"
	callText(t, cs, "send_text", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "text": secretText})
	callText(t, cs, "workspaces", map[string]any{"machine": "vm1"})
	callText(t, cs, "peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "tail": 999})

	log := f.log.String()
	for _, want := range []string{
		`tool=send_text mutating=true machine=vm0 token=tok_`,
		`outcome=ok`,
		`tool=workspaces mutating=false machine=vm1`,
		`outcome=error`,
		`tool=peek mutating=false machine=vm0`,
		`outcome=invalid`,
	} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %q:\n%s", want, log)
		}
	}
	if strings.Contains(log, "AUDITPAYLOAD") || strings.Contains(log, "w1:p1") {
		t.Fatalf("audit log contains call arguments:\n%s", log)
	}
}

// stdio servers audit too when the serving context carries a logger.
func TestAudit_StdioContext(t *testing.T) {
	fh := fakeherdr.Start(t)
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	srv := arcomcp.NewMCPServer(reg, herdr.NewClient(reg), "test")

	var buf syncBuffer
	ctx, cancel := context.WithCancel(arcomcp.WithAudit(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), "stdio"))
	defer cancel()
	st, ct := sdkmcp.NewInMemoryTransports()
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ss.Close()
	cs, err := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "c", Version: "1"}, nil).Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	callText(t, cs, "agents", map[string]any{"machine": "vm0"})
	if !strings.Contains(buf.String(), "tool=agents mutating=false machine=vm0 token=stdio outcome=ok") {
		t.Fatalf("stdio audit line missing:\n%s", buf.String())
	}
}
