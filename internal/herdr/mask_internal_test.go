package herdr

import (
	"errors"
	"strings"
	"testing"
)

func TestErrorPublicTextNamesMachineOnly(t *testing.T) {
	const target = "s@s:/home/alice/.config/herdr/herdr.sock"
	cases := map[string]struct {
		e    *Error
		want []string
	}{
		"id equals a short host": {
			e: &Error{Machine: "s", Method: "pane.send_text", Stage: "read", Sent: true, Target: target,
				socket: "/home/alice/.config/herdr/herdr.sock", Err: errors.New("boom")},
			want: []string{`machine "s": pane.send_text: read: boom (request was sent; outcome unknown)`},
		},
		"ssh pre-forward failure": {
			e: &Error{Machine: "vm0", Method: "ping", Stage: "dial", Target: target,
				Err:    errors.New("ssh exit 255 before forwarding the request (ssh exit 255: ssh: Could not resolve hostname vm0.corp.example.com: Name or service not known)"),
				public: sshSummary(255, "ssh: Could not resolve hostname vm0.corp.example.com: Name or service not known")},
			want: []string{`machine "vm0": ping: dial: ssh: could not resolve the host (request was not sent)`},
		},
		"unix dial error": {
			e: &Error{Machine: "local", Method: "ping", Stage: "dial", Target: "/home/alice/.config/herdr/herdr.sock",
				socket: "/home/alice/.config/herdr/herdr.sock",
				Err:    errors.New("dial unix /home/alice/.config/herdr/herdr.sock: connect: no such file or directory")},
			want: []string{"dial unix <socket>: connect: no such file or directory"},
		},
	}
	for name, tc := range cases {
		pub := tc.e.Error()
		for _, w := range tc.want {
			if !strings.Contains(pub, w) {
				t.Errorf("%s: public text %q missing %q", name, pub, w)
			}
		}
		for _, leak := range []string{"alice", "corp.example.com", "herdr.sock", "<target>"} {
			if strings.Contains(pub, leak) {
				t.Errorf("%s: public text leaks %q: %s", name, leak, pub)
			}
		}
		if !strings.Contains(tc.e.Detail(), target) && !strings.Contains(tc.e.Detail(), "/home/alice") {
			t.Errorf("%s: Detail() must keep the target: %s", name, tc.e.Detail())
		}
	}
}

// Raw ssh stderr never reaches public text; each known failure maps to a fixed cause.
func TestSSHSummary(t *testing.T) {
	for diag, want := range map[string]string{
		"ssh: Could not resolve hostname vm0.corp.example.com: Name or service not known":                           "ssh: could not resolve the host",
		"ssh: connect to host 10.255.255.1 port 22: Connection timed out":                                           "ssh: connection timed out",
		"ssh: connect to host 127.0.0.1 port 2222: Connection refused":                                              "ssh: connection refused",
		"bob@192.168.1.5: Permission denied (publickey,password).":                                                  "ssh: authentication failed",
		"@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nOffending key in /home/alice/.ssh/known_hosts:3": "ssh: host key verification failed",
		"channel 0: open failed: connect failed: open failed\nstdio forwarding failed":                              "ssh: could not open the herdr socket (is herdr running?)",
		"Read from remote host vm0.corp.example.com: Connection reset by peer":                                      "ssh: connection lost",
		"Timeout, server vm0.corp.example.com not responding.":                                                      "ssh: server stopped responding",
		"": "ssh exited with code 255; run `arco machines` for details",
	} {
		if got := sshSummary(255, diag); got != want {
			t.Errorf("sshSummary(%q) = %q, want %q", diag, got, want)
		}
	}
}

func TestMaskCauseKeepsOrdinaryText(t *testing.T) {
	for _, keep := range []string{"16:31:05", "pane w1:p1", "herdr 0.9.5", "pane_not_found"} {
		if got := maskCause("at "+keep+" end", ""); got != "at "+keep+" end" {
			t.Errorf("maskCause mangled %q into %q", keep, got)
		}
	}
}
