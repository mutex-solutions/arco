package mcp_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/auth"
	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
	arcomcp "github.com/mutex-solutions/arco/internal/mcp"
	"github.com/mutex-solutions/arco/internal/registry"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type httpFixture struct {
	srv    *httptest.Server
	tokens *auth.Store
	fh0    *fakeherdr.Server
	fh1    *fakeherdr.Server
	log    *syncBuffer
}

func newHTTPFixture(t *testing.T) *httpFixture {
	t.Helper()
	fh0, fh1 := fakeherdr.Start(t), fakeherdr.Start(t)
	m0, _ := registry.NewMachine("vm0", "unix", "", "", fh0.Socket(), time.Second)
	m1, _ := registry.NewMachine("vm1", "unix", "", "", fh1.Socket(), time.Second)
	reg := makeRegistry(t, m0, m1)
	tokens, err := auth.Open(filepath.Join(t.TempDir(), "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	log := &syncBuffer{}
	h := arcomcp.NewHTTPHandler(arcomcp.HTTPOptions{
		Registry: reg, Client: herdr.NewClient(reg), Tokens: tokens, Version: "test", Log: log,
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &httpFixture{srv: srv, tokens: tokens, fh0: fh0, fh1: fh1, log: log}
}

func (f *httpFixture) token(t *testing.T, name, scope string, machines ...string) string {
	t.Helper()
	raw, _, err := f.tokens.Create(auth.CreateOptions{Name: name, Scope: scope, Machines: machines})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

func (f *httpFixture) connect(t *testing.T, token string) (*sdkmcp.ClientSession, error) {
	t.Helper()
	transport := &sdkmcp.StreamableClientTransport{
		Endpoint:   f.srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token: token, base: http.DefaultTransport}},
		MaxRetries: -1,
	}
	cs, err := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "http-test", Version: "1"}, nil).Connect(context.Background(), transport, nil)
	if err == nil {
		t.Cleanup(func() { _ = cs.Close() })
	}
	return cs, err
}

func toolNames(t *testing.T, cs *sdkmcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	return names
}

func TestHTTP_ReadTokenSeesOnlyInspectionTools(t *testing.T) {
	f := newHTTPFixture(t)
	cs, err := f.connect(t, f.token(t, "checks", auth.ScopeRead, "*"))
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(toolNames(t, cs), ",")
	if got != "agents,fleet_status,machines,pane_detail,panes,peek,wait_agent,wait_for_output,workspaces" {
		t.Fatalf("read token tools: %s", got)
	}
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "send_text", Arguments: map[string]any{"machine": "vm0", "pane_id": "w1:p1", "text": "x"},
	})
	if err == nil && !res.IsError {
		t.Fatal("read token called send_text")
	}
	for _, r := range append(f.fh0.RecordedRequests(), f.fh1.RecordedRequests()...) {
		if r.Method == "pane.send_text" {
			t.Fatal("a read token reached herdr with a mutation")
		}
	}
}

func TestHTTP_MachineAllowlistIsEnforced(t *testing.T) {
	f := newHTTPFixture(t)
	cs, err := f.connect(t, f.token(t, "vm0-rw", auth.ScopeReadWrite, "vm0"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(toolNames(t, cs)); n != 15 {
		t.Fatalf("readwrite token sees %d tools, want 15", n)
	}

	txt, isErr := callText(t, cs, "machines", nil)
	if isErr || !strings.Contains(txt, `"vm0"`) || strings.Contains(txt, "vm1") {
		t.Fatalf("machines leaked outside the allowlist: %s", txt)
	}
	if strings.Contains(txt, f.fh0.Socket()) || strings.Contains(txt, `"target"`) {
		t.Fatalf("machines exposed the socket target: %s", txt)
	}
	txt, isErr = callText(t, cs, "fleet_status", nil)
	if isErr || strings.Contains(txt, "vm1") {
		t.Fatalf("fleet_status leaked outside the allowlist: %s", txt)
	}

	dials := f.fh1.Dials.Load()
	for _, call := range []struct {
		tool string
		args map[string]any
	}{
		{"workspaces", map[string]any{"machine": "vm1"}},
		{"send_text", map[string]any{"machine": "vm1", "pane_id": "w1:p1", "text": "x"}},
		{"close_workspace", map[string]any{"machine": "vm1", "workspace_id": "w1"}},
	} {
		txt, isErr := callText(t, cs, call.tool, call.args)
		if !isErr || !strings.Contains(txt, `unknown machine "vm1"`) || !strings.Contains(txt, "known machines: vm0") {
			t.Fatalf("%s on a machine outside the allowlist: isErr=%v %s", call.tool, isErr, txt)
		}
	}
	if f.fh1.Dials.Load() != dials {
		t.Fatal("a call outside the allowlist dialed vm1")
	}
}

func TestHTTP_UnknownAllowlistFailsClosed(t *testing.T) {
	f := newHTTPFixture(t)
	cs, err := f.connect(t, f.token(t, "ghost", auth.ScopeRead, "decommissioned"))
	if err != nil {
		t.Fatal(err)
	}
	txt, isErr := callText(t, cs, "machines", nil)
	if isErr || strings.TrimSpace(txt) != "[]" {
		t.Fatalf("token for an unknown machine must see nothing, got: %s", txt)
	}
	if f.fh0.Dials.Load()+f.fh1.Dials.Load() != 0 {
		t.Fatal("token for an unknown machine dialed a real one")
	}
}

func TestHTTP_AuthFailures(t *testing.T) {
	f := newHTTPFixture(t)
	good := f.token(t, "good", auth.ScopeRead, "*")
	for name, header := range map[string]string{
		"missing":      "",
		"wrong scheme": "Basic " + good,
		"unknown":      "Bearer arco_ro_" + strings.Repeat("A", 43),
		"garbage":      "Bearer hello",
	} {
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		req.Header.Set("Content-Type", "application/json")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != `Bearer realm="arco"` || strings.Contains(string(body), "resource_metadata") {
			t.Errorf("%s: status %d, challenge %q, body %s", name, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), body)
		}
	}
}

// Revocation must stop the very next call, even from a client that already
// connected and keeps reusing its HTTP connection.
func TestHTTP_RevocationIsImmediate(t *testing.T) {
	f := newHTTPFixture(t)
	cs, err := f.connect(t, f.token(t, "short-lived", auth.ScopeRead, "*"))
	if err != nil {
		t.Fatal(err)
	}
	if _, isErr := callTextNoFatal(cs, "agents", map[string]any{"machine": "vm0"}); isErr {
		t.Fatal("call before revoke failed")
	}
	cli, _ := auth.Open(f.tokens.Path()) // revoke through a separate handle, as the CLI would
	if _, err := cli.Revoke("short-lived"); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{
		Name: "agents", Arguments: map[string]any{"machine": "vm0"},
	}); err == nil || !strings.Contains(err.Error(), "401") && !strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
		t.Fatalf("call after revoke: %v", err)
	}
}

func callTextNoFatal(cs *sdkmcp.ClientSession, name string, args any) (string, bool) {
	res, err := cs.CallTool(context.Background(), &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil || len(res.Content) == 0 {
		return "", true
	}
	tc, _ := res.Content[0].(*sdkmcp.TextContent)
	if tc == nil {
		return "", true
	}
	return tc.Text, res.IsError
}

func TestHTTP_RoutesHeadersAndLogging(t *testing.T) {
	f := newHTTPFixture(t)
	tok := f.token(t, "raw", auth.ScopeRead, "*")

	get := func(path string) *http.Response {
		resp, err := http.Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if r := get("/healthz"); r.StatusCode != 200 || r.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("/healthz: %d %v", r.StatusCode, r.Header)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server", "/mcp/" + tok, "/"} {
		if r := get(p); r.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", p, r.StatusCode)
		}
	}

	// A raw POST without the Accept header the transport wants still works.
	post := func(body string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp, string(b)
	}
	resp, body := post(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	if resp.StatusCode != 200 || !strings.Contains(body, `"peek"`) {
		t.Fatalf("tools/list without Accept: %d %s", resp.StatusCode, body)
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(body), &parsed) != nil {
		t.Fatalf("JSONResponse mode should return plain JSON: %s", body)
	}

	resp, _ = post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"pad":"` + strings.Repeat("a", arcomcp.MaxHTTPBodyBytes) + `"}}`)
	if resp.StatusCode < 400 {
		t.Fatalf("oversized body accepted: %d", resp.StatusCode)
	}

	log := f.log.String()
	if strings.Contains(log, tok) || strings.Contains(log, tok[8:]) {
		t.Fatal("request log contains the raw token")
	}
	if !strings.Contains(log, "path=/mcp") || !strings.Contains(log, "token=tok_") || !strings.Contains(log, "status=200") {
		t.Fatalf("request log missing fields: %s", log)
	}
}

func TestHTTP_ResponsesAreScrubbed(t *testing.T) {
	f := newHTTPFixture(t)
	secret := "sk-proj-" + "HTTPSEAMSECRET1234567890abcdefghij"
	f.fh0.On("workspace.list", func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{"type": "workspace_list", "workspaces": []map[string]any{{"label": secret}}}, nil
	})
	cs, err := f.connect(t, f.token(t, "scrub", auth.ScopeRead, "vm0"))
	if err != nil {
		t.Fatal(err)
	}
	txt, isErr := callText(t, cs, "workspaces", map[string]any{"machine": "vm0"})
	if isErr || strings.Contains(txt, "HTTPSEAMSECRET") || !strings.Contains(txt, "[REDACTED:openai-key]") {
		t.Fatalf("HTTP response not scrubbed: %s", txt)
	}
}

// A client without a token must not hold a connection by trickling a body.
func TestHTTP_UnauthenticatedSlowBodyIsCutOff(t *testing.T) {
	f := newHTTPFixture(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := arcomcp.NewHTTPServer(ln.Addr().String(), f.srv.Config.Handler)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{")
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || !strings.Contains(line, "401") {
		t.Fatalf("expected an immediate 401, got %q (%v)", line, err)
	}
}

func TestHTTP_BrokenTokenFileIsLogged(t *testing.T) {
	f := newHTTPFixture(t)
	tok := f.token(t, "x", auth.ScopeRead, "*")
	if err := os.WriteFile(f.tokens.Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(f.log.String(), "token store unavailable") {
		t.Fatalf("status %d, log: %s", resp.StatusCode, f.log.String())
	}
	if strings.Contains(f.log.String(), tok[8:]) {
		t.Fatal("log contains the raw token")
	}
}
