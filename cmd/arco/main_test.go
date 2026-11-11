package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
)

func TestMain(m *testing.M) {
	fakeherdr.MaybeRunFakeSSH()
	os.Exit(m.Run())
}

type nopCloserBuffer struct {
	bytes.Buffer
}

func (*nopCloserBuffer) Close() error { return nil }

func TestVersionCommand(t *testing.T) {
	var out nopCloserBuffer
	var errBuf bytes.Buffer
	code := run(context.Background(), []string{"version"}, io.NopCloser(strings.NewReader("")), &out, &errBuf, nil)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr = %s", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "arco ") {
		t.Fatalf("unexpected version output: %q", out.String())
	}
}

func TestMachinesCommand_TwoMachinesAndFailures(t *testing.T) {
	fhUnix := fakeherdr.Start(t)
	fhSSH := fakeherdr.Start(t)
	sshBin := fakeherdr.FakeSSHPath(t)

	cfgPath := filepath.Join(t.TempDir(), "machines.toml")
	cfg := `
[[machine]]
id = "vm0"
transport = "unix"
socket = "` + fhUnix.Socket() + `"

[[machine]]
id = "laptop"
transport = "ssh"
host = "ok"
user = "long"
socket = "` + fhSSH.Socket() + `"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	var out nopCloserBuffer
	var errBuf bytes.Buffer
	code := run(context.Background(), []string{"machines", "--machines", cfgPath}, io.NopCloser(strings.NewReader("")), &out, &errBuf, herdr.NewSSHDialer(sshBin))
	if code != 0 {
		t.Fatalf("expected exit 0, got %d (out=%q err=%q)", code, out.String(), errBuf.String())
	}
	got := out.String()
	if !strings.Contains(got, "vm0\tunix") || !strings.Contains(got, "laptop\tssh") || !strings.Contains(got, "2/2 ok") {
		t.Fatalf("unexpected machines output:\n%s", got)
	}
}

func TestMCPServeCommand_StdioSmoke(t *testing.T) {
	fh := fakeherdr.Start(t)
	cfgPath := filepath.Join(t.TempDir(), "machines.toml")
	cfg := `
[[machine]]
id = "vm0"
transport = "unix"
socket = "` + fh.Socket() + `"
`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	var errBuf bytes.Buffer

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"mcp", "serve", "--machines", cfgPath}, inR, outW, &errBuf, nil)
	}()

	reader := bufio.NewReader(outR)
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"cli-test","version":"1"}}}`+"\n")
	initResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read initialize response: %v", err)
	}
	if !strings.Contains(initResp, `"serverInfo":{"name":"arco"`) {
		t.Fatalf("unexpected initialize response: %s", initResp)
	}

	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`+"\n")
	_, _ = io.WriteString(inW, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`+"\n")
	listResp, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read tools/list response: %v", err)
	}
	if !strings.Contains(listResp, `"fleet_status"`) || !strings.Contains(listResp, `"create_workspace"`) {
		t.Fatalf("unexpected tools/list response: %s", listResp)
	}

	_ = inW.Close()
	_ = outR.Close()
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("expected exit 0 on cancel, got %d (stderr=%s)", code, errBuf.String())
	}
}
