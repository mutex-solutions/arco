package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
	arcomcp "github.com/mutex-solutions/arco/internal/mcp"
	"github.com/mutex-solutions/arco/internal/registry"
)

func TestMain(m *testing.M) {
	fakeherdr.MaybeRunFakeSSH()
	os.Exit(m.Run())
}

func makeRegistry(t *testing.T, machines ...*registry.Machine) *registry.Registry {
	t.Helper()
	var sb strings.Builder
	for _, m := range machines {
		sb.WriteString("[[machine]]\n")
		sb.WriteString("id = \"" + m.ID() + "\"\n")
		sb.WriteString("transport = \"" + m.Transport() + "\"\n")
		if m.Host() != "" {
			sb.WriteString("host = \"" + m.Host() + "\"\n")
		}
		if m.User() != "" {
			sb.WriteString("user = \"" + m.User() + "\"\n")
		}
		sb.WriteString("socket = \"" + m.Socket() + "\"\n")
		sb.WriteString("timeout = \"" + m.Timeout().String() + "\"\n\n")
	}
	path := filepath.Join(t.TempDir(), "machines.toml")
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func startInMemorySession(t *testing.T, reg *registry.Registry, client *herdr.Client) *sdkmcp.ClientSession {
	t.Helper()
	srv := arcomcp.NewMCPServer(reg, client, "0.1.0-test")
	st, ct := sdkmcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	ss, err := srv.Connect(ctx, st, nil)
	if err != nil {
		cancel()
		t.Fatalf("server connect: %v", err)
	}
	mcpClient := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	cs, err := mcpClient.Connect(ctx, ct, nil)
	if err != nil {
		cancel()
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Close()
		cancel()
	})
	return cs
}

func callText(t *testing.T, cs *sdkmcp.ClientSession, name string, args any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(%s) protocol error: %v", name, err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("CallTool(%s): expected 1 content item, got %d", name, len(res.Content))
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("CallTool(%s): expected *TextContent, got %T", name, res.Content[0])
	}
	if res.StructuredContent != nil {
		t.Fatalf("CallTool(%s): StructuredContent must be nil so nothing bypasses the seam", name)
	}
	return tc.Text, res.IsError
}

func TestSeamEnforcement_GrepModule(t *testing.T) {
	addToolRe := regexp.MustCompile(`\bAddTool\b`)
	forbiddenRe := regexp.MustCompile(`\b(AddResource|AddResourceTemplate|AddPrompt|NotifyProgress|CreateMessage)\b|\.Log\(`)

	root := filepath.Clean("../..")
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "docs" || name == ".playwright-mcp" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if addToolRe.Match(data) && rel != "internal/mcp/seam.go" {
			t.Errorf("AddTool found outside internal/mcp/seam.go: %s", rel)
		}
		if m := forbiddenRe.Find(data); m != nil {
			t.Errorf("forbidden SDK bypass symbol %q found in %s", string(m), rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

type recordingWriteCloser struct {
	mu  sync.Mutex
	buf bytes.Buffer
	w   io.WriteCloser
}

func (r *recordingWriteCloser) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(p)
	r.mu.Unlock()
	return r.w.Write(p)
}

func (r *recordingWriteCloser) Close() error { return r.w.Close() }

func (r *recordingWriteCloser) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

func TestRawWire_NoLoggingAndCanaryScrubbing(t *testing.T) {
	fh := fakeherdr.Start(t)
	canaryPlain := "sk-proj-PLAIN_WIRE_CANARY_1234567890abcdefghij"
	canaryEscapedTail := "k-proj-ESCAPED_WIRE_CANARY_1234567890abcdefghij"

	fh.On("pane.read", func(json.RawMessage) (any, *herdr.RPCError) {
		return json.RawMessage(`{"type":"pane_read","read":{"text":"plain=` + canaryPlain + ` escaped=\` + `u0073` + canaryEscapedTail + `"}}`), nil
	})

	m, err := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reg := makeRegistry(t, m)
	client := herdr.NewClient(reg)
	srv := arcomcp.NewMCPServer(reg, client, "0.1.0-test")

	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	rec := &recordingWriteCloser{w: s2cW}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- arcomcp.ServeIO(ctx, srv, c2sR, rec)
	}()

	reader := bufio.NewReader(s2cR)
	sendLine := func(line string) {
		t.Helper()
		if _, err := io.WriteString(c2sW, line+"\n"); err != nil {
			t.Fatalf("write wire line: %v", err)
		}
	}
	readLine := func() string {
		t.Helper()
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read wire line: %v", err)
		}
		return line
	}

	sendLine(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`)
	initLine := readLine()
	if strings.Contains(initLine, `"logging"`) {
		t.Fatalf("server must not advertise logging capability; got: %s", initLine)
	}

	sendLine(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	sendLine(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"peek","arguments":{"machine":"vm0","pane_id":"w1:p1"}}}`)
	callLine := readLine()
	if !strings.Contains(callLine, "[REDACTED:openai-key]") {
		t.Fatalf("expected redaction marker on wire, got: %s", callLine)
	}

	_ = c2sW.Close()
	_ = s2cR.Close()
	cancel()
	<-done

	allBytes := string(rec.Bytes())
	if strings.Contains(allBytes, "PLAIN_WIRE_CANARY") || strings.Contains(allBytes, "ESCAPED_WIRE_CANARY") {
		t.Fatalf("canary leaked on raw MCP output stream: %s", allBytes)
	}
}

func TestAllTools_EndToEnd(t *testing.T) {
	fhUnix := fakeherdr.Start(t)
	fhSSH := fakeherdr.Start(t)
	sshBin := fakeherdr.FakeSSHPath(t)

	mUnix, _ := registry.NewMachine("vm0", "unix", "", "", fhUnix.Socket(), 2*time.Second)
	mSSH, _ := registry.NewMachine("laptop", "ssh", "ok", "long", fhSSH.Socket(), 2*time.Second)
	reg := makeRegistry(t, mUnix, mSSH)
	client := herdr.NewClientWithDialers(reg, nil, herdr.NewSSHDialer(sshBin))

	cs := startInMemorySession(t, reg, client)

	// Verify tools/list metadata.
	listRes, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listRes.Tools) != 13 {
		t.Fatalf("expected 13 tools, got %d", len(listRes.Tools))
	}
	for _, tool := range listRes.Tools {
		if !strings.HasPrefix(tool.Description, "[READ-ONLY]") && !strings.HasPrefix(tool.Description, "[MUTATING]") {
			t.Fatalf("tool %s description missing [READ-ONLY]/[MUTATING] prefix: %q", tool.Name, tool.Description)
		}
		if !strings.Contains(tool.Description, "untrusted data") {
			t.Fatalf("tool %s description missing untrusted data warning: %q", tool.Name, tool.Description)
		}
	}

	// 1. machines (both unix and ssh)
	txt, isErr := callText(t, cs, "machines", nil)
	if isErr || !strings.Contains(txt, `"id":"vm0"`) || !strings.Contains(txt, `"id":"laptop"`) || !strings.Contains(txt, `"protocol":22`) {
		t.Fatalf("machines failed (isErr=%v): %s", isErr, txt)
	}

	// 2. fleet_status
	txt, isErr = callText(t, cs, "fleet_status", map[string]any{})
	if isErr || !strings.Contains(txt, `"machine":"vm0"`) || !strings.Contains(txt, `"machine":"laptop"`) {
		t.Fatalf("fleet_status failed (isErr=%v): %s", isErr, txt)
	}

	// 3. workspaces
	txt, isErr = callText(t, cs, "workspaces", map[string]any{"machine": "vm0"})
	if isErr || !strings.Contains(txt, `"workspace_list"`) {
		t.Fatalf("workspaces failed: %s", txt)
	}

	// 4. panes (including uint64 > 2^53 check)
	txt, isErr = callText(t, cs, "panes", map[string]any{"machine": "vm0", "workspace_id": "w1"})
	if isErr || !strings.Contains(txt, "9007199254740993") {
		t.Fatalf("panes failed or lost uint64 precision: %s", txt)
	}

	// 5. agents
	txt, isErr = callText(t, cs, "agents", map[string]any{"machine": "laptop"})
	if isErr || !strings.Contains(txt, `"agent_list"`) {
		t.Fatalf("agents over ssh failed: %s", txt)
	}

	// 6. peek
	txt, isErr = callText(t, cs, "peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "tail": 25})
	if isErr || !strings.Contains(txt, `"strip_ansi":true`) || !strings.Contains(txt, `"lines":26`) || !strings.Contains(txt, `"source":"recent_unwrapped"`) {
		t.Fatalf("peek failed: %s", txt)
	}

	// 7. pane_detail
	txt, isErr = callText(t, cs, "pane_detail", map[string]any{"machine": "vm0", "pane_id": "w1:p1"})
	if isErr || !strings.Contains(txt, `"pane_info"`) {
		t.Fatalf("pane_detail failed: %s", txt)
	}

	// 8. send_text (including literal `"focus":true` inside user text to prove no-focus check is structural)
	txt, isErr = callText(t, cs, "send_text", map[string]any{
		"machine": "vm0",
		"pane_id": "w1:p1",
		"text":    `echo '{"focus":true}'`,
	})
	if isErr || !strings.Contains(txt, `"ok"`) {
		t.Fatalf("send_text failed: %s", txt)
	}

	// 9. prompt_agent
	txt, isErr = callText(t, cs, "prompt_agent", map[string]any{
		"machine":         "laptop",
		"target":          "w1:p1",
		"text":            "status report",
		"wait_timeout_ms": 5000,
	})
	if isErr || !strings.Contains(txt, `"agent_prompted"`) {
		t.Fatalf("prompt_agent failed: %s", txt)
	}

	// 10. create_workspace
	txt, isErr = callText(t, cs, "create_workspace", map[string]any{
		"machine": "vm0",
		"cwd":     "/work/new",
		"label":   "feat",
	})
	if isErr || !strings.Contains(txt, `"root_pane"`) || !strings.Contains(txt, `"w2:p1"`) {
		t.Fatalf("create_workspace failed: %s", txt)
	}

	// 11. start_agent
	txt, isErr = callText(t, cs, "start_agent", map[string]any{
		"machine": "vm0",
		"pane_id": "w2:p1",
		"kind":    "claude",
		"name":    "worker-1",
		"args":    []string{"--resume"},
	})
	if isErr || !strings.Contains(txt, `"agent_started"`) {
		t.Fatalf("start_agent failed: %s", txt)
	}

	// 12. close_pane
	txt, isErr = callText(t, cs, "close_pane", map[string]any{"machine": "vm0", "pane_id": "w2:p1"})
	if isErr || !strings.Contains(txt, `"ok"`) {
		t.Fatalf("close_pane failed: %s", txt)
	}

	// 13. close_workspace
	txt, isErr = callText(t, cs, "close_workspace", map[string]any{"machine": "vm0", "workspace_id": "w2"})
	if isErr || !strings.Contains(txt, `"ok"`) {
		t.Fatalf("close_workspace failed: %s", txt)
	}

	// Schema / input validation checks (all must return IsError=true, never crash).
	badCalls := []struct {
		tool string
		args map[string]any
	}{
		{"peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "tail": 0}},
		{"peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "tail": 201}},
		{"peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "source": "visible"}}, // wrapped sources split secrets past redaction
		{"send_text", map[string]any{"machine": "vm0", "pane_id": "w1:p1", "text": strings.Repeat("a", (64<<10)+1)}},
		{"prompt_agent", map[string]any{"machine": "vm0", "target": "w1:p1", "text": "hi", "wait_timeout_ms": 120001}},
		{"prompt_agent", map[string]any{"machine": "vm0", "target": "w1:p1", "text": "hi", "wait_timeout_ms": 0}},
	}
	for _, bc := range badCalls {
		msg, isErr := callText(t, cs, bc.tool, bc.args)
		if !isErr {
			t.Fatalf("expected validation error for %s(%v), got success: %s", bc.tool, bc.args, msg)
		}
	}
}

func TestInvariant1_OneSourceOfTruth(t *testing.T) {
	fh := fakeherdr.Start(t)
	status := "idle"
	fh.On("agent.list", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type": "agent_list",
			"agents": []map[string]any{
				{"pane_id": "w1:p1", "agent": "claude", "agent_status": status},
			},
		}, nil
	})

	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	// Case 1: Live state change is immediately visible on next call.
	txt1, isErr := callText(t, cs, "agents", map[string]any{"machine": "vm0"})
	if isErr || !strings.Contains(txt1, `"idle"`) {
		t.Fatalf("first call failed: %s", txt1)
	}
	status = "working"
	txt2, isErr := callText(t, cs, "agents", map[string]any{"machine": "vm0"})
	if isErr || !strings.Contains(txt2, `"working"`) {
		t.Fatalf("second call did not reflect live state change: %s", txt2)
	}

	// Case 2: Each tool call performs exactly one dial.
	if dials := fh.Dials.Load(); dials != 2 {
		t.Fatalf("expected 2 dials for 2 calls, got %d", dials)
	}

	// Case 3: Stopping herdr produces an error on the next call, never cached data.
	fh.Close()
	txt3, isErr := callText(t, cs, "agents", map[string]any{"machine": "vm0"})
	if !isErr || strings.Contains(txt3, `"working"`) {
		t.Fatalf("expected error after herdr stopped, got isErr=%v: %s", isErr, txt3)
	}
}

// A truncated pane.read window can open mid-line, inside a secret and past
// the prefix redaction keys on. peek drops that first line; an untruncated
// read is passed through whole.
func TestPeek_DropsPartialFirstLineOfTruncatedWindow(t *testing.T) {
	fh := fakeherdr.Start(t)
	truncated := true
	fh.On("pane.read", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type": "pane_read",
			"read": map[string]any{
				"truncated": truncated,
				"revision":  9007199254740993,
				"text":      "BAREKEYTAIL0123456789abcdefghijklmnopqrstuvwxyz^J\nline <two> & more\nline three",
			},
		}, nil
	})
	m, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	reg := makeRegistry(t, m)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	txt, isErr := callText(t, cs, "peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1"})
	if isErr || strings.Contains(txt, "BAREKEYTAIL") || !strings.Contains(txt, `"text":"line <two> & more\nline three"`) {
		t.Fatalf("partial first line not dropped: %s", txt)
	}
	if !strings.Contains(txt, "9007199254740993") {
		t.Fatalf("rewrite lost uint64 precision: %s", txt)
	}

	truncated = false
	txt, isErr = callText(t, cs, "peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1"})
	if isErr || !strings.Contains(txt, "BAREKEYTAIL") {
		t.Fatalf("untruncated read must pass through whole: %s", txt)
	}
}

func TestInvariant2_SingleResponseSeam(t *testing.T) {
	fh := fakeherdr.Start(t)
	sshBin := fakeherdr.FakeSSHPath(t)

	secret := "sk-proj-" + "SEAM_TEST_SECRET_1234567890abcdefghij"
	fh.On("workspace.list", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type":       "workspace_list",
			"workspaces": []map[string]any{{"workspace_id": "w1", "label": "leak " + secret}},
		}, nil
	})
	fh.On("pane.get", func(json.RawMessage) (any, *herdr.RPCError) {
		return nil, &herdr.RPCError{Code: "pane_error", Message: "failed with key " + secret}
	})
	// Construct a response where `secret` straddles the 256 KiB truncation boundary.
	fh.On("pane.read", func(json.RawMessage) (any, *herdr.RPCError) {
		pad := strings.Repeat("x", arcomcp.MaxResponseBytes-45) + "🔥"
		return map[string]any{
			"type": "pane_read",
			"read": map[string]any{"text": pad + " " + secret + " tail"},
		}, nil
	})

	mUnix, _ := registry.NewMachine("vm0", "unix", "", "", fh.Socket(), time.Second)
	mExit255, _ := registry.NewMachine("sshbad", "ssh", "exit255", "long", fh.Socket(), time.Second)
	reg := makeRegistry(t, mUnix, mExit255)
	client := herdr.NewClientWithDialers(reg, nil, herdr.NewSSHDialer(sshBin))
	cs := startInMemorySession(t, reg, client)

	// Case 1: Secret in normal response is scrubbed.
	wsTxt, isErr := callText(t, cs, "workspaces", map[string]any{"machine": "vm0"})
	if isErr || strings.Contains(wsTxt, "SEAM_TEST_SECRET") || !strings.Contains(wsTxt, "[REDACTED:openai-key]") {
		t.Fatalf("workspace secret not scrubbed: %s", wsTxt)
	}

	// Case 2: Secret in herdr RPCError is scrubbed; raw ssh stderr never reaches the client.
	errTxt1, isErr := callText(t, cs, "pane_detail", map[string]any{"machine": "vm0", "pane_id": "w1:p1"})
	if !isErr || strings.Contains(errTxt1, "SEAM_TEST_SECRET") || !strings.Contains(errTxt1, "[REDACTED:openai-key]") {
		t.Fatalf("RPCError secret not scrubbed: %s", errTxt1)
	}
	errTxt2, isErr := callText(t, cs, "agents", map[string]any{"machine": "sshbad"})
	if !isErr || strings.Contains(errTxt2, "abcdefghijklmnopqrstuvwxyz1234567890") || !strings.Contains(errTxt2, "ssh: authentication failed") {
		t.Fatalf("ssh stderr secret not scrubbed: %s", errTxt2)
	}

	// Case 3: Secret straddling the 256 KiB truncation boundary is scrubbed BEFORE truncation, and output is valid UTF-8.
	peekTxt, isErr := callText(t, cs, "peek", map[string]any{"machine": "vm0", "pane_id": "w1:p1"})
	if isErr {
		t.Fatalf("peek failed: %s", peekTxt)
	}
	if strings.Contains(peekTxt, "SEAM_TEST_SECRET") || strings.Contains(peekTxt, "sk-proj-") {
		t.Fatalf("boundary-straddling secret leaked: %s", peekTxt[len(peekTxt)-120:])
	}
	if !utf8.ValidString(peekTxt) {
		t.Fatal("truncated output is not valid UTF-8")
	}
	if len(peekTxt) > arcomcp.MaxResponseBytes {
		t.Fatalf("truncated output %d exceeds MaxResponseBytes %d", len(peekTxt), arcomcp.MaxResponseBytes)
	}
}

func TestInvariant3_MachineScopedAndFanOut(t *testing.T) {
	fhA := fakeherdr.Start(t)
	fhB := fakeherdr.Start(t)
	fhHung := fakeherdr.Start(t)
	fhHung.Fault("agent.list", fakeherdr.Fault{Delay: 2500 * time.Millisecond})

	mA, _ := registry.NewMachine("vma", "unix", "", "", fhA.Socket(), time.Second)
	mDead, _ := registry.NewMachine("vmdead", "unix", "", "", "/tmp/nonexistent-arco-inv3.sock", time.Second)
	mHung, _ := registry.NewMachine("vmhung", "unix", "", "", fhHung.Socket(), time.Second)
	mB, _ := registry.NewMachine("vmb", "unix", "", "", fhB.Socket(), time.Second)

	reg := makeRegistry(t, mA, mDead, mHung, mB)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	// Case 1: Mutating vma makes zero dials to vmb.
	_, isErr := callText(t, cs, "send_text", map[string]any{"machine": "vma", "pane_id": "w1:p1", "text": "hello"})
	if isErr {
		t.Fatal("send_text on vma failed")
	}
	if fhB.Dials.Load() != 0 {
		t.Fatalf("mutation on vma dialed vmb %d times", fhB.Dials.Load())
	}

	// Case 2: Unknown machine returns error listing known machines and makes zero dials.
	dialsBefore := fhA.Dials.Load()
	errTxt, isErr := callText(t, cs, "workspaces", map[string]any{"machine": "unknown-box"})
	if !isErr || !strings.Contains(errTxt, "vma") || !strings.Contains(errTxt, "vmb") {
		t.Fatalf("expected known machine list in error, got: %s", errTxt)
	}
	if fhA.Dials.Load() != dialsBefore || fhB.Dials.Load() != 0 {
		t.Fatal("unknown machine call dialed a registered machine")
	}

	// Case 3: fleet_status runs concurrently in registry order; dead/hung machines do not cancel healthy ones.
	start := time.Now()
	txt, isErr := callText(t, cs, "fleet_status", nil)
	elapsed := time.Since(start)
	if isErr {
		t.Fatalf("fleet_status should succeed with inline per-machine errors, got error: %s", txt)
	}
	if elapsed > 2200*time.Millisecond {
		t.Fatalf("fleet_status took %s (expected ~1s parallel timeout)", elapsed)
	}
	var entries []arcomcp.FleetMachineStatus
	if err := json.Unmarshal([]byte(txt), &entries); err != nil {
		t.Fatalf("unmarshal fleet_status: %v (%s)", err, txt)
	}
	if len(entries) != 4 ||
		entries[0].Machine != "vma" || entries[0].Error != "" || len(entries[0].Agents) == 0 ||
		entries[1].Machine != "vmdead" || entries[1].Error == "" ||
		entries[2].Machine != "vmhung" || !strings.Contains(entries[2].Error, "timed out after 1s") ||
		entries[3].Machine != "vmb" || entries[3].Error != "" || len(entries[3].Agents) == 0 {
		t.Fatalf("unexpected fleet_status entries: %+v", entries)
	}
}

func TestInvariant4_HonestLivenessAndVersionWarning(t *testing.T) {
	fhOld := fakeherdr.Start(t)
	fhOld.On("ping", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{"type": "pong", "version": "0.7.5", "protocol": 17}, nil
	})
	fhHang := fakeherdr.Start(t)
	fhHang.Fault("pane.send_text", fakeherdr.Fault{Delay: 2 * time.Second})

	mOld, _ := registry.NewMachine("vmold", "unix", "", "", fhOld.Socket(), time.Second)
	mDead, _ := registry.NewMachine("vmdead", "unix", "", "", "/tmp/nonexistent-arco-inv4.sock", time.Second)
	mHang, _ := registry.NewMachine("vmhang", "unix", "", "", fhHang.Socket(), time.Second)

	reg := makeRegistry(t, mOld, mDead, mHang)
	cs := startInMemorySession(t, reg, herdr.NewClient(reg))

	// Case 1: Missing socket reports machine, dial stage, cause, and "request was not sent",
	// but not the socket path (public errors never name the target).
	txt, isErr := callText(t, cs, "send_text", map[string]any{"machine": "vmdead", "pane_id": "w1:p1", "text": "x"})
	if !isErr || !strings.Contains(txt, `"vmdead"`) || strings.Contains(txt, "nonexistent-arco-inv4") || !strings.Contains(txt, ": dial: ") || !strings.Contains(txt, "no such file or directory") || !strings.Contains(txt, "request was not sent") {
		t.Fatalf("unexpected missing-socket error: %s", txt)
	}

	// Case 2: Timeout after write on mutating method reports "timed out after 1s" and "request was sent; outcome unknown".
	txt, isErr = callText(t, cs, "send_text", map[string]any{"machine": "vmhang", "pane_id": "w1:p1", "text": "x"})
	if !isErr || !strings.Contains(txt, "timed out after 1s") || !strings.Contains(txt, "request was sent; outcome unknown") {
		t.Fatalf("unexpected hang mutation error: %s", txt)
	}

	// Case 3: machines probe surfaces protocol < 22 warning and dead machine cause.
	txt, isErr = callText(t, cs, "machines", nil)
	if isErr || !strings.Contains(txt, "older than expected protocol 22") || !strings.Contains(txt, `"ok":false`) {
		t.Fatalf("unexpected machines probe output: %s", txt)
	}
}
