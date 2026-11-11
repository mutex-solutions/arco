package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), args, nopReadCloser{}, nopWriteCloser{&out}, &errb, nil)
	return code, out.String(), errb.String()
}

type nopReadCloser struct{}

func (nopReadCloser) Read([]byte) (int, error) { return 0, nil }
func (nopReadCloser) Close() error             { return nil }

type nopWriteCloser struct{ *bytes.Buffer }

func (nopWriteCloser) Close() error { return nil }

func TestTokenLifecycleCLI(t *testing.T) {
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens.json")
	reg := filepath.Join(dir, "machines.toml")
	if err := os.WriteFile(reg, []byte("[[machine]]\nid=\"vm0\"\ntransport=\"unix\"\nsocket=\"/tmp/x.sock\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	code, out, errs := runCLI(t, "token", "create", "--name", "hermes", "--scope", "readwrite", "--machines", "vm0", "--ttl", "7d", "--tokens", tokens, "--registry", reg, "--json")
	if code != 0 {
		t.Fatalf("create: %d %s", code, errs)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create --json: %v %s", err, out)
	}
	raw, _ := created["token"].(string)
	if !strings.HasPrefix(raw, "arco_rw_") || created["hash"] != nil || !strings.Contains(errs, "shown once") {
		t.Fatalf("create output: %s / %s", out, errs)
	}
	exp, _ := time.Parse(time.RFC3339, created["expires_at"].(string))
	if d := time.Until(exp); d < 6*24*time.Hour || d > 7*24*time.Hour {
		t.Fatalf("7d ttl gave expiry in %s", d)
	}

	code, out, _ = runCLI(t, "token", "list", "--tokens", tokens)
	if code != 0 || !strings.Contains(out, "hermes") || !strings.Contains(out, "readwrite") || strings.Contains(out, raw) {
		t.Fatalf("list: %d %s", code, out)
	}
	code, out, _ = runCLI(t, "token", "list", "--tokens", tokens, "--json")
	if code != 0 || strings.Contains(out, `"hash"`) || strings.Contains(out, raw) {
		t.Fatalf("list --json leaks: %s", out)
	}

	code, out, _ = runCLI(t, "token", "revoke", "hermes", "--tokens", tokens)
	if code != 0 || !strings.Contains(out, "revoked hermes") {
		t.Fatalf("revoke: %d %s", code, out)
	}
	if code, _, _ = runCLI(t, "token", "revoke", "hermes", "--tokens", tokens); code != 1 {
		t.Fatalf("second revoke should fail, got %d", code)
	}
}

func TestTokenCreateRejectsCLI(t *testing.T) {
	dir := t.TempDir()
	tokens := filepath.Join(dir, "tokens.json")
	reg := filepath.Join(dir, "machines.toml")
	_ = os.WriteFile(reg, []byte("[[machine]]\nid=\"vm0\"\ntransport=\"unix\"\nsocket=\"/tmp/x.sock\"\n"), 0o600)
	for name, args := range map[string][]string{
		"no name":            {"--scope", "read"},
		"readwrite no scope": {"--name", "rw", "--scope", "readwrite"},
		"bad ttl":            {"--name", "x", "--ttl", "soon"},
		"typo machine":       {"--name", "x", "--machines", "vm9"},
		"rw over 90d":        {"--name", "x", "--scope", "readwrite", "--machines", "vm0", "--ttl", "91d"},
	} {
		code, _, errs := runCLI(t, append([]string{"token", "create", "--tokens", tokens, "--registry", reg}, args...)...)
		if code == 0 {
			t.Errorf("%s: accepted (%s)", name, errs)
		}
	}
	if _, err := os.Stat(tokens); err == nil {
		data, _ := os.ReadFile(tokens)
		if strings.Contains(string(data), `"name"`) {
			t.Fatalf("a rejected create wrote a token: %s", data)
		}
	}
}

func TestIsPrivateListener(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "[::1]:1": true, "10.1.2.3:1": true, "192.168.1.5:1": true,
		"100.101.102.103:1": true, "[fd00::1]:1": true,
		"0.0.0.0:1": false, "[::]:1": false, "8.8.8.8:1": false,
	} {
		a, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		if got := isPrivateListener(a); got != want {
			t.Errorf("isPrivateListener(%s) = %v, want %v", addr, got, want)
		}
	}
}
