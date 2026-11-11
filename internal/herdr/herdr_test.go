package herdr_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mutex-solutions/arco/internal/fakeherdr"
	"github.com/mutex-solutions/arco/internal/herdr"
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
	path := t.TempDir() + "/machines.toml"
	if err := os.WriteFile(path, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestUnixCall_SkipsPushEventsAndPreservesRawJSON(t *testing.T) {
	srv := fakeherdr.Start(t)
	srv.Fault("pane.list", fakeherdr.Fault{Events: 3})

	m, err := registry.NewMachine("vm0", "unix", "", "", srv.Socket(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	reg := makeRegistry(t, m)
	client := herdr.NewClient(reg)

	raw, err := client.Call(context.Background(), m, "pane.list", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Verify uint64 > 2^53 is preserved verbatim in RawMessage.
	if !strings.Contains(string(raw), "9007199254740993") {
		t.Fatalf("expected exact uint64 in raw JSON, got %s", string(raw))
	}
	// Verify nil params encoded as {} (not null).
	reqs := srv.RecordedRequests()
	if len(reqs) != 1 || string(reqs[0].Params) != "{}" {
		t.Fatalf("expected params {}, got %+v", reqs)
	}
	if srv.Dials.Load() != 1 {
		t.Fatalf("expected 1 dial, got %d", srv.Dials.Load())
	}
}

func TestProtocolErrors(t *testing.T) {
	tests := []struct {
		name    string
		fault   fakeherdr.Fault
		wantSub string
	}{
		{
			name:    "malformed json",
			fault:   fakeherdr.Fault{Raw: []byte("{not-json\n")},
			wantSub: "malformed response frame",
		},
		{
			name:    "unexpected id",
			fault:   fakeherdr.Fault{Raw: []byte(`{"id":"wrong","result":{"type":"ok"}}` + "\n")},
			wantSub: `unexpected response id "wrong"`,
		},
		{
			name:    "missing result and error",
			fault:   fakeherdr.Fault{Raw: []byte(`{"id":"arco-1"}` + "\n")},
			wantSub: "neither result nor error",
		},
		{
			name:    "frame exceeds 8MiB",
			fault:   fakeherdr.Fault{Raw: append(bytes.Repeat([]byte("a"), (8<<20)+1024), '\n')},
			wantSub: "response frame exceeded 8 MiB",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := fakeherdr.Start(t)
			srv.Fault("agent.list", tc.fault)
			m, _ := registry.NewMachine("vm0", "unix", "", "", srv.Socket(), 2*time.Second)
			client := herdr.NewClient(makeRegistry(t, m))

			_, err := client.Call(context.Background(), m, "agent.list", nil, 0)
			if err == nil {
				t.Fatal("expected error")
			}
			var hErr *herdr.Error
			if !errors.As(err, &hErr) {
				t.Fatalf("expected *herdr.Error, got %T: %v", err, err)
			}
			if hErr.Stage != "protocol" {
				t.Fatalf("expected stage protocol, got %q (%v)", hErr.Stage, err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected %q in %q", tc.wantSub, err.Error())
			}
		})
	}
}

func TestDialFailureVsMutateTimeout(t *testing.T) {
	// 1. Missing socket -> Stage="dial", Sent=false, "request was not sent".
	missing, err := registry.NewMachine("dead", "unix", "", "", "/tmp/nonexistent-arco-test.sock", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	srv := fakeherdr.Start(t)
	srv.Fault("pane.send_text", fakeherdr.Fault{Delay: 2 * time.Second})
	live, err := registry.NewMachine("live", "unix", "", "", srv.Socket(), time.Second)
	if err != nil {
		t.Fatal(err)
	}

	client := herdr.NewClient(makeRegistry(t, missing, live))

	_, err = client.Call(context.Background(), missing, "pane.send_text", herdr.PaneSendTextParams{PaneID: "w1:p1", Text: "hi"}, 0)
	if err == nil {
		t.Fatal("expected dial error")
	}
	if !strings.Contains(err.Error(), "request was not sent") {
		t.Fatalf("expected 'request was not sent', got: %v", err)
	}

	// 2. Timeout after request written on mutating method -> Stage="read", Sent=true, "request was sent; outcome unknown".
	_, err = client.Call(context.Background(), live, "pane.send_text", herdr.PaneSendTextParams{PaneID: "w1:p1", Text: "hi"}, 0)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "request was sent; outcome unknown") || !strings.Contains(err.Error(), "timed out after 1s") {
		t.Fatalf("expected sent/outcome-unknown timeout error, got: %v", err)
	}
}

func TestPerMachineSemaphoreLimit(t *testing.T) {
	srv := fakeherdr.Start(t)
	srv.Fault("agent.list", fakeherdr.Fault{Delay: 1500 * time.Millisecond})

	m, err := registry.NewMachine("vm0", "unix", "", "", srv.Socket(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := herdr.NewClient(makeRegistry(t, m))

	var wg sync.WaitGroup
	errs := make([]error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, errs[idx] = client.Call(context.Background(), m, "agent.list", nil, 2*time.Second)
		}(i)
	}
	wg.Wait()

	semTimeouts := 0
	for _, e := range errs {
		if e != nil && strings.Contains(e.Error(), "waited on per-machine concurrency limit 4") {
			semTimeouts++
		}
	}
	if semTimeouts != 1 {
		t.Fatalf("expected exactly 1 call to fail waiting on concurrency limit 4, got %d (%v)", semTimeouts, errs)
	}
}

func TestSSHTransport_ReadMutateAndFailureModes(t *testing.T) {
	// Plant a forbidden env var to verify newCmd's allowlist strips it before invoking fake ssh.
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-api03-forbidden-env-leak-check-1234567890")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/fake-agent.sock")

	srv := fakeherdr.Start(t)
	sshBin := fakeherdr.FakeSSHPath(t)

	mOK, _ := registry.NewMachine("remote-ok", "ssh", "ok", "long", srv.Socket(), 2*time.Second)
	mExit255, _ := registry.NewMachine("remote-255", "ssh", "exit255", "long", srv.Socket(), 2*time.Second)
	mDrop, _ := registry.NewMachine("remote-drop", "ssh", "dropafterping", "long", srv.Socket(), 2*time.Second)
	mHold, _ := registry.NewMachine("remote-hold", "ssh", "holdstderr", "long", srv.Socket(), 2*time.Second)

	reg := makeRegistry(t, mOK, mExit255, mDrop, mHold)
	client := herdr.NewClientWithDialers(reg, nil, herdr.NewSSHDialer(sshBin))

	// 1. Successful read + mutation over fake ssh (proves argv + env allowlist + -W socket relay).
	raw, err := client.Call(context.Background(), mOK, "agent.list", nil, 0)
	if err != nil {
		t.Fatalf("ssh agent.list failed: %v", err)
	}
	if !strings.Contains(string(raw), `"agent_list"`) {
		t.Fatalf("unexpected ssh response: %s", string(raw))
	}

	_, err = client.Call(context.Background(), mOK, "pane.send_text", herdr.PaneSendTextParams{
		PaneID: "w1:p1",
		Text:   "echo 'hello <world> & friends'",
	}, 0)
	if err != nil {
		t.Fatalf("ssh pane.send_text failed: %v", err)
	}

	// 2. exit255 with a pre-forward failure (Permission denied) on a mutation -> Stage="dial", Sent=false.
	_, err = client.Call(context.Background(), mExit255, "pane.send_text", herdr.PaneSendTextParams{
		PaneID: "w1:p1",
		Text:   "should not be sent",
	}, 0)
	if err == nil {
		t.Fatal("expected ssh exit 255 error")
	}
	var hErr *herdr.Error
	if !errors.As(err, &hErr) || hErr.Stage != "dial" || hErr.Sent {
		t.Fatalf("expected dial stage with Sent=false on ssh exit 255, got %+v (%v)", hErr, err)
	}
	if !strings.Contains(err.Error(), "ssh: authentication failed") || !strings.Contains(err.Error(), "request was not sent") || strings.Contains(err.Error(), "request written") {
		t.Fatalf("unexpected error text: %v", err)
	}

	// 3. dropafterping on a mutation: mutation is forwarded, then ssh drops -> Sent=true, outcome unknown.
	_, err = client.Call(context.Background(), mDrop, "pane.send_text", herdr.PaneSendTextParams{
		PaneID: "w1:p1",
		Text:   "did this land?",
	}, 0)
	if err == nil {
		t.Fatal("expected dropafterping error")
	}
	if !errors.As(err, &hErr) || hErr.Stage != "read" || !hErr.Sent {
		t.Fatalf("expected read stage with Sent=true after drop, got %+v (%v)", hErr, err)
	}
	if !strings.Contains(err.Error(), "request was sent; outcome unknown") {
		t.Fatalf("expected outcome unknown message, got: %v", err)
	}

	// 4. holdstderr: child holds stderr open for 10s, WaitDelay=2s ensures Call+Close finishes quickly.
	start := time.Now()
	if _, err := client.Call(context.Background(), mHold, "ping", nil, 0); err != nil {
		t.Fatalf("holdstderr call failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("WaitDelay failed to bound background stderr holder: took %s", elapsed)
	}
}

// A mutation that ssh forwarded before dying must never be reported as
// "not sent", whatever ssh printed (or didn't). A false "not sent" invites a
// retry that types the text twice.
func TestSSHExit255AfterForwardIsOutcomeUnknown(t *testing.T) {
	srv := fakeherdr.Start(t)
	sshBin := fakeherdr.FakeSSHPath(t)
	for _, host := range []string{"keepalivedrop", "quiet255", "readtimeout"} {
		t.Run(host, func(t *testing.T) {
			m, err := registry.NewMachine("remote-"+host, "ssh", host, "long", srv.Socket(), 2*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			client := herdr.NewClientWithDialers(makeRegistry(t, m), nil, herdr.NewSSHDialer(sshBin))
			before := len(srv.RecordedRequests())
			_, err = client.Call(context.Background(), m, "pane.send_text", herdr.PaneSendTextParams{PaneID: "w1:p1", Text: "once"}, 0)
			if got := len(srv.RecordedRequests()) - before; got != 1 {
				t.Fatalf("fake herdr should have applied the request once, recorded %d", got)
			}
			var hErr *herdr.Error
			if !errors.As(err, &hErr) || !hErr.Sent {
				t.Fatalf("forwarded mutation reported as not sent: %+v (%v)", hErr, err)
			}
			if !strings.Contains(err.Error(), "request was sent; outcome unknown") {
				t.Fatalf("unexpected error text: %v", err)
			}
		})
	}
}

// Ported shellQuote & shellJoin injection corpus from internal/vm/ssh_test.go.
func TestShellQuote_RoundTripViaRealShell(t *testing.T) {
	evilTokens := []string{
		"plain",
		"hello world",
		"it's",
		`a"b`,
		"a;b", "a|b", "a&b",
		"a&&b||c",
		"$(rm -rf /)",
		"`rm -rf /`",
		"a\nb",
		"a\tb",
		"*", "?", "[abc]", "~",
		"$HOME", "${PATH}",
		`\`, `\\`,
		"-rf", "--evil",
		"",
		"'", "'''", `'\''`,
		"a'b'c\"d\"e",
		"\x01\x02",
		"$'x'",
		"a>b", "a<b",
		"  x  ",
		"日本語",
		"a!(b)",
	}
	for _, tok := range evilTokens {
		cmd := exec.Command("sh", "-c", "printf '%s\\0' "+herdr.ExportShellQuote(tok))
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("token %q failed: %v", tok, err)
		}
		if string(out) != tok+"\x00" {
			t.Fatalf("token %q round-tripped as %q", tok, string(out))
		}
	}
	joined := herdr.ExportShellJoin(append([]string{"herdr", "api"}, evilTokens...))
	out, err := exec.Command("sh", "-c", "printf '%s\\0' "+joined).Output()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join(append([]string{"herdr", "api"}, evilTokens...), "\x00") + "\x00"
	if string(out) != want {
		t.Fatalf("shellJoin mismatch")
	}
}
