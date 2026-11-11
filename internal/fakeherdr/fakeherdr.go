// Package fakeherdr provides an in-process herdr protocol-22 unix-socket responder
// and a re-exec fake ssh binary for unit and integration tests.
package fakeherdr

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mutex-solutions/arco/internal/herdr"
)

// Handler handles one herdr method call.
type Handler func(params json.RawMessage) (any, *herdr.RPCError)

// Fault configures fault injection for a specific method.
type Fault struct {
	Delay  time.Duration // delay after reading request before responding
	Raw    []byte        // write verbatim instead of a JSON response frame
	Events int           // number of {event,data} push frames to emit before responding
	Close  bool          // close connection without writing a response
}

// Recorded captures a single received request frame.
type Recorded struct {
	ID     string          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// Server is a fake herdr unix-socket NDJSON server.
type Server struct {
	sockPath string
	ln       net.Listener

	mu       sync.Mutex
	routes   map[string]Handler
	faults   map[string]Fault
	requests []Recorded
	conns    map[net.Conn]struct{}
	closed   bool

	Dials atomic.Int64
}

// Start launches a fakeherdr server on a short-path unix socket (safe for macOS 104-byte sun_path).
func Start(t testing.TB) *Server {
	t.Helper()
	dir, err := os.MkdirTemp("", "fh")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	sockPath := filepath.Join(dir, "h.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatalf("listen unix %s: %v", sockPath, err)
	}

	s := &Server{
		sockPath: sockPath,
		ln:       ln,
		routes:   make(map[string]Handler),
		faults:   make(map[string]Fault),
		conns:    make(map[net.Conn]struct{}),
	}
	s.installDefaults()

	go s.acceptLoop()

	t.Cleanup(func() {
		s.Close()
		_ = os.RemoveAll(dir)
		s.AssertNoFocus(t)
	})
	return s
}

func (s *Server) Socket() string { return s.sockPath }

func (s *Server) On(method string, h Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[method] = h
}

func (s *Server) Fault(method string, f Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults[method] = f
}

func (s *Server) RecordedRequests() []Recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Recorded(nil), s.requests...)
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
}

// AssertNoFocus verifies that no recorded request ever called a focus method
// or sent `"focus":true`, and that workspace.create always sent `"focus":false`.
func (s *Server) AssertNoFocus(t testing.TB) {
	t.Helper()
	for _, r := range s.RecordedRequests() {
		if strings.HasSuffix(r.Method, ".focus") || r.Method == "pane.focus_direction" {
			t.Fatalf("forbidden focus method recorded: %s", r.Method)
		}
		var v any
		if len(r.Params) > 0 && json.Unmarshal(r.Params, &v) == nil {
			if hasFocusTrue(v) {
				t.Fatalf("forbidden focus:true in %s params: %s", r.Method, string(r.Params))
			}
			if r.Method == "workspace.create" {
				m, ok := v.(map[string]any)
				if !ok {
					t.Fatalf("workspace.create params not an object: %s", string(r.Params))
				}
				fv, exists := m["focus"]
				if !exists || fv != false {
					t.Fatalf("workspace.create must explicitly send focus:false; got %s", string(r.Params))
				}
			}
		}
	}
}

func hasFocusTrue(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if k == "focus" && val == true {
				return true
			}
			if hasFocusTrue(val) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if hasFocusTrue(item) {
				return true
			}
		}
	}
	return false
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.Dials.Add(1)
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 64<<10), 8<<20)
	if !scanner.Scan() {
		return
	}
	line := append([]byte(nil), scanner.Bytes()...)
	var req Recorded
	if err := json.Unmarshal(line, &req); err != nil {
		return
	}

	s.mu.Lock()
	s.requests = append(s.requests, req)
	h := s.routes[req.Method]
	f, hasFault := s.faults[req.Method]
	s.mu.Unlock()

	if hasFault {
		if f.Delay > 0 {
			time.Sleep(f.Delay)
		}
		for i := 0; i < f.Events; i++ {
			ev := fmt.Sprintf(`{"event":"pane.agent_status_changed","data":{"type":"pane_agent_status_changed","pane_id":"w1:p1","status":"working","seq":%d}}`+"\n", i+1)
			if _, err := conn.Write([]byte(ev)); err != nil {
				return
			}
		}
		if f.Close {
			return
		}
		if f.Raw != nil {
			_, _ = conn.Write(f.Raw)
			return
		}
	}

	if h == nil {
		_ = writeError(conn, req.ID, &herdr.RPCError{
			Code:    "method_not_found",
			Message: "unknown method " + req.Method,
		})
		return
	}
	res, rpcErr := h(req.Params)
	if rpcErr != nil {
		_ = writeError(conn, req.ID, rpcErr)
		return
	}
	_ = writeResult(conn, req.ID, res)
}

func writeResult(w io.Writer, id string, res any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		ID     string `json:"id"`
		Result any    `json:"result"`
	}{ID: id, Result: res}); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func writeError(w io.Writer, id string, rpcErr *herdr.RPCError) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(struct {
		ID    string          `json:"id"`
		Error *herdr.RPCError `json:"error"`
	}{ID: id, Error: rpcErr}); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func (s *Server) installDefaults() {
	s.routes["ping"] = func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type":     "pong",
			"version":  "0.9.5",
			"protocol": 22,
			"capabilities": map[string]any{
				"live_handoff":     true,
				"health_check":     true,
				"surface_interest": true,
			},
		}, nil
	}
	s.routes["agent.list"] = func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type": "agent_list",
			"agents": []map[string]any{
				{
					"pane_id":      "w1:p1",
					"workspace_id": "w1",
					"agent":        "claude",
					"agent_status": "idle",
					"cwd":          "/work/repo",
				},
			},
		}, nil
	}
	s.routes["workspace.list"] = func(json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type": "workspace_list",
			"workspaces": []map[string]any{
				{
					"workspace_id": "w1",
					"label":        "main",
					"focused":      false,
					"pane_count":   1,
					"tab_count":    1,
				},
			},
		}, nil
	}
	s.routes["workspace.create"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			Cwd   string `json:"cwd"`
			Label string `json:"label"`
			Focus *bool  `json:"focus"`
		}
		_ = json.Unmarshal(params, &p)
		label := p.Label
		if label == "" {
			label = "ws-new"
		}
		return map[string]any{
			"type": "workspace_created",
			"workspace": map[string]any{
				"workspace_id": "w2",
				"label":        label,
				"focused":      false,
			},
			"tab": map[string]any{
				"tab_id":       "w2:t1",
				"workspace_id": "w2",
			},
			"root_pane": map[string]any{
				"pane_id":      "w2:p1",
				"workspace_id": "w2",
				"cwd":          p.Cwd,
				"focused":      false,
			},
		}, nil
	}
	s.routes["workspace.close"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			WorkspaceID string `json:"workspace_id"`
		}
		_ = json.Unmarshal(params, &p)
		if p.WorkspaceID == "missing" {
			return nil, &herdr.RPCError{Code: "workspace_not_found", Message: "workspace missing not found"}
		}
		return map[string]any{"type": "ok"}, nil
	}
	s.routes["pane.list"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		return map[string]any{
			"type": "pane_list",
			"panes": []map[string]any{
				{
					"pane_id":      "w1:p1",
					"workspace_id": "w1",
					"agent":        "claude",
					"agent_status": "idle",
					"revision":     uint64(9007199254740993), // > 2^53 to test uint64 precision preservation
				},
			},
		}, nil
	}
	s.routes["pane.get"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			PaneID string `json:"pane_id"`
		}
		_ = json.Unmarshal(params, &p)
		if p.PaneID == "missing" {
			return nil, &herdr.RPCError{Code: "pane_not_found", Message: "pane missing not found"}
		}
		return map[string]any{
			"type": "pane_info",
			"pane": map[string]any{
				"pane_id":      p.PaneID,
				"workspace_id": "w1",
				"agent":        "claude",
				"agent_status": "idle",
				"revision":     uint64(9007199254740993),
			},
		}, nil
	}
	s.routes["pane.read"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			PaneID    string `json:"pane_id"`
			Source    string `json:"source"`
			Lines     int    `json:"lines"`
			Format    string `json:"format"`
			StripANSI bool   `json:"strip_ansi"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"type": "pane_read",
			"read": map[string]any{
				"pane_id":    p.PaneID,
				"source":     p.Source,
				"lines":      p.Lines,
				"format":     p.Format,
				"strip_ansi": p.StripANSI,
				"text":       "hello from pane " + p.PaneID,
			},
		}, nil
	}
	s.routes["pane.send_text"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			PaneID string `json:"pane_id"`
			Text   string `json:"text"`
		}
		_ = json.Unmarshal(params, &p)
		if p.PaneID == "missing" {
			return nil, &herdr.RPCError{Code: "pane_not_found", Message: "pane missing not found"}
		}
		return map[string]any{"type": "ok"}, nil
	}
	s.routes["pane.close"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			PaneID string `json:"pane_id"`
		}
		_ = json.Unmarshal(params, &p)
		if p.PaneID == "missing" {
			return nil, &herdr.RPCError{Code: "pane_not_found", Message: "pane missing not found"}
		}
		return map[string]any{"type": "ok"}, nil
	}
	s.routes["agent.prompt"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			Target string `json:"target"`
			Text   string `json:"text"`
		}
		_ = json.Unmarshal(params, &p)
		if p.Target == "w1" {
			return nil, &herdr.RPCError{Code: "agent_not_found", Message: "agent target w1 not found"}
		}
		return map[string]any{
			"type": "agent_prompted",
			"agent": map[string]any{
				"pane_id":      p.Target,
				"agent":        "claude",
				"agent_status": "working",
			},
		}, nil
	}
	s.routes["agent.start"] = func(params json.RawMessage) (any, *herdr.RPCError) {
		var p struct {
			Name      string   `json:"name"`
			Kind      string   `json:"kind"`
			PaneID    string   `json:"pane_id"`
			Args      []string `json:"args"`
			TimeoutMS uint64   `json:"timeout_ms"`
		}
		_ = json.Unmarshal(params, &p)
		return map[string]any{
			"type": "agent_started",
			"agent": map[string]any{
				"pane_id":      p.PaneID,
				"name":         p.Name,
				"agent":        p.Kind,
				"agent_status": "idle",
			},
			"argv": append([]string{p.Kind}, p.Args...),
		}, nil
	}
}

// FakeSSHPath creates a symlink named "ssh" pointing to the current test executable.
func FakeSSHPath(t testing.TB) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	sshBin := filepath.Join(dir, "ssh")
	if err := os.Symlink(exe, sshBin); err != nil {
		t.Fatalf("symlink fake ssh: %v", err)
	}
	return sshBin
}

// MaybeRunFakeSSH intercepts execution when the test binary is invoked as "ssh".
// Call this at the top of TestMain before m.Run().
func MaybeRunFakeSSH() {
	if filepath.Base(os.Args[0]) != "ssh" {
		return
	}
	os.Exit(runFakeSSH(os.Args[1:]))
}

func runFakeSSH(args []string) int {
	// 1. Verify env scrubbing allowlist: only HOME, USER, LOGNAME, PATH, SSH_AUTH_SOCK
	// (plus Go/OS runtime vars like SYSTEMROOT on Windows if ever run there).
	allowed := map[string]bool{
		"HOME":          true,
		"USER":          true,
		"LOGNAME":       true,
		"PATH":          true,
		"SSH_AUTH_SOCK": true,
	}
	for _, kv := range os.Environ() {
		k, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if !allowed[k] {
			_, _ = fmt.Fprintf(os.Stderr, "fake-ssh: forbidden env var leaked: %s\n", k)
			return 97
		}
	}

	// 2. Verify required flags and extract -l user, -W socket, -- host.
	for _, must := range []string{"-T", "-a", "-x", "BatchMode=yes", "StrictHostKeyChecking=accept-new", "PermitLocalCommand=no", "ClearAllForwardings=yes", "ExitOnForwardFailure=yes"} {
		if !slices.Contains(args, must) {
			_, _ = fmt.Fprintf(os.Stderr, "fake-ssh: missing required arg %q in %v\n", must, args)
			return 97
		}
	}
	var user, sock, host string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-l":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "-W":
			if i+1 < len(args) {
				sock = args[i+1]
				i++
			}
		case "--":
			if i+1 != len(args)-1 {
				_, _ = fmt.Fprintf(os.Stderr, "fake-ssh: '--' must immediately precede final host arg, got %v\n", args)
				return 97
			}
			host = args[i+1]
			i++
		}
	}
	if user == "" || sock == "" || host == "" || !filepath.IsAbs(sock) {
		_, _ = fmt.Fprintf(os.Stderr, "fake-ssh: invalid user=%q sock=%q host=%q\n", user, sock, host)
		return 97
	}

	switch host {
	case "exit255":
		_, _ = fmt.Fprintf(os.Stderr, "Permission denied (publickey) for %s@%s token=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890\n", user, host)
		return 255
	case "hang":
		time.Sleep(30 * time.Second)
		return 0
	case "holdstderr":
		// Spawn a background child that inherits stderr and stays alive for 10s
		// (simulating an OpenSSH ControlMaster mux process holding stderr open).
		bg := exec.Command("sh", "-c", "sleep 10")
		bg.Stderr = os.Stderr
		_ = bg.Start()
		return relaySocket(sock, false, "")
	case "dropafterping":
		return relaySocket(sock, true, "Shared connection to remote closed unexpectedly.")
	case "keepalivedrop":
		// Forwarded, applied, then dropped with a message that names no
		// known mid-stream signature.
		return relaySocket(sock, true, "Timeout, server keepalivedrop not responding.")
	case "readtimeout":
		// Mid-session TCP failure: the errno text alone would look like a
		// connect failure.
		return relaySocket(sock, true, "Read from remote host readtimeout: Connection timed out")
	case "quiet255":
		// LogLevel QUIET: exit 255 with an empty stderr, request forwarded.
		return relaySocket(sock, true, "")
	default:
		return relaySocket(sock, false, "")
	}
}

func relaySocket(sock string, dropAfterFirst bool, dropMsg string) int {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "fake-ssh: dial unix %s: %v\n", sock, err)
		return 255
	}
	defer conn.Close()

	if dropAfterFirst {
		inScan := bufio.NewScanner(os.Stdin)
		inScan.Buffer(make([]byte, 64<<10), 8<<20)
		sockScan := bufio.NewScanner(conn)
		sockScan.Buffer(make([]byte, 64<<10), 8<<20)

		// Read the request frame from stdin, forward it to herdr so it applies,
		// and then simulate an unexpected mid-session ssh disconnect before returning the response.
		if inScan.Scan() {
			_, _ = conn.Write(append(inScan.Bytes(), '\n'))
			_ = sockScan.Scan()
		}
		if dropMsg != "" {
			_, _ = fmt.Fprintln(os.Stderr, dropMsg)
		}
		return 255
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
		if uc, ok := conn.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	go func() {
		_, _ = io.Copy(os.Stdout, conn)
		close(done)
	}()
	<-done
	return 0
}

// Unused error check helper for compilation cleanliness.
var _ = errors.New
