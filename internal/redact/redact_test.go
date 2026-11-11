package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoldenCorpus(t *testing.T) {
	cases := []struct{ name, in, secret string }{
		{"github-pat", "token github_pat_11ABCDEFG0abcdefghijklmnop qrstuv end", "github_pat_11ABCDEFG0abcdefghijklmnop"},
		{"github-classic", "use ghp_abcdefghijklmnopqrstuvwxyz0123456789 now", "ghp_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"anthropic", "ANTHROPIC=sk-ant-api03-abcdefghijklmnop1234567890 x", "sk-ant-api03-abcdefghijklmnop1234567890"},
		{"openai", "key sk-abcdefghijklmnopqrstuvwxyz012345 done", "sk-abcdefghijklmnopqrstuvwxyz012345"},
		{"aws", "AKIAIOSFODNN7EXAMPLE creds", "AKIAIOSFODNN7EXAMPLE"},
		{"google-api-key", "key AI" + "za" + "SyA1234567890abcdefghijklmnopqrstuv end", "AI" + "za" + "SyA1234567890abcdefghijklmnopqrstuv"},
		{"openai-proj", "key sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 done", "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"},
		{"openai-proj-underscore-dash", "OPENAI=sk-proj-AAAA1111_bbbb2222-CCCC3333dddd4444EEEE end", "sk-proj-AAAA1111_bbbb2222-CCCC3333dddd4444EEEE"},
		{"openai-svcacct", "k sk-svcacct-ZZZZ0000_yyyy1111-XXXX2222wwww3333 x", "sk-svcacct-ZZZZ0000_yyyy1111-XXXX2222wwww3333"},
		{"slack-browser", "cookie xox" + "c-abcdefghij0123456789 end", "xox" + "c-abcdefghij0123456789"},
		{"slack-refresh", "tok xox" + "e-synthetic0123456789 end", "xox" + "e-synthetic0123456789"},
		{"url-creds", "clone https://alice:s3cr3tpw@github.com/x/y.git", "s3cr3tpw"},
		{"url-creds-colon", "https://alice:s3:cr3t@github.com/x/y.git", "s3:cr3t"},
		{"aws-secret-env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"aws-secret-ini", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"aws-secret-json", `{"SecretAccessKey":"x","aws_secret_access_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"jwt", "token=eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
		{"bearer", "Authorization: Bearer abcDEF1234567890opaqueTOKEN", "abcDEF1234567890opaqueTOKEN"},
		{"slack-app", "xa" + "pp-1-A0123456789-0123456789-abcdef0123456789", "A0123456789-0123456789-abcdef0123456789"},
		{"gitlab", "gl" + "pat-abcdefghij0123456789 x", "abcdefghij0123456789"},
		{"huggingface", "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH x", "hf_abcdefghijklmnopqrstuvwxyzABCDEFGH"},
		{"npm", "npm_abcdefghijklmnopqrstuvwxyz0123456789 x", "npm_abcdefghijklmnopqrstuvwxyz0123456789"},
		{"stripe", "sk_" + "live_abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx"},
		{"arco-token", "arco_rw_" + strings.Repeat("Ab0_-", 8) + "xyz", strings.Repeat("Ab0_-", 8)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, n := New().Scrub(tc.in)
			if n == 0 || strings.Contains(out, tc.secret) || !strings.Contains(out, "[REDACTED:") {
				t.Fatalf("n=%d output=%q", n, out)
			}
		})
	}
}

func TestURLCredentialsKeepHost(t *testing.T) {
	out, n := New().Scrub("git remote add o https://u:p@example.com/r.git")
	if n != 1 || !strings.Contains(out, "example.com/r.git") || strings.Contains(out, "u:p@") {
		t.Fatalf("n=%d output=%q", n, out)
	}
}

func TestNormalTextUnchanged(t *testing.T) {
	for _, in := range []string{
		"Refactored the parser; see PR #42. path=/home/x/a.go",
		`{"deadline":"1700000000:abcdefghijklmnopqrstuvwxyz01234"}`,
		"clone ssh://git@github.com/x/y.git",
		"remote git@github.com:org/repo.git",
		"task-force-alpha-bravo-charlie-delta-echo-foxtrot",
	} {
		out, n := New().Scrub(in)
		if n != 0 || out != in {
			t.Fatalf("input %q became %q (%d)", in, out, n)
		}
	}
}

func TestPrivateKeyBlock(t *testing.T) {
	in := "cfg\n-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----\ntail"
	out, n := New().Scrub(in)
	if n != 1 || strings.Contains(out, "b3BlbnNzaC1rZXktdjEAAAA") || !strings.HasPrefix(out, "cfg\n") || !strings.HasSuffix(out, "\ntail") {
		t.Fatalf("n=%d output=%q", n, out)
	}
}

// A peek window can cut a key block on either side; the body must not leak.
func TestPrivateKeyOrphanMarkers(t *testing.T) {
	body := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDhBODY2Mjg5MTIxNjU3MDQ1NjMyMzU0ODQ0NTY4Nzg5MjE0NTY3OA=="
	for name, in := range map[string]string{
		"begin-only": "$ cat id\n-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + body,
		"end-only":   body + "\n-----END OPENSSH PRIVATE KEY-----\n$ ls",
	} {
		t.Run(name, func(t *testing.T) {
			out, n := New().Scrub(in)
			if n == 0 || strings.Contains(out, "b3BlbnNzaC1rZXkt") || strings.Contains(out, "QyNTUxOQAAAC") {
				t.Fatalf("n=%d output=%q", n, out)
			}
		})
	}
	// Through the seam: a JSON pane.read result stays valid and loses the body.
	js, _ := json.Marshal(map[string]any{"read": map[string]any{"text": "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + body + "\n$ ", "revision": 1}})
	got := Scrub(js)
	if !json.Valid(got) || strings.Contains(string(got), "b3BlbnNzaC1rZXkt") {
		t.Fatalf("seam scrub: valid=%v %s", json.Valid(got), got)
	}
	// Text after the key body survives.
	out, _ := New().Scrub("-----BEGIN RSA " + "PRIVATE KEY-----\n" + body + "\n$ echo done ✓")
	if !strings.Contains(out, "echo done ✓") {
		t.Fatalf("orphan BEGIN swallowed trailing prompt: %q", out)
	}
}

func TestScrubPreservesValidJSON(t *testing.T) {
	escapedJSON := `{"escaped":"\` + `u0073k-proj-abcdefghijklmnopqrstuvwxyz1234567890","n":9007199254740993}`
	inputs := []string{
		`{"key":"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890","ok":true}`,
		escapedJSON,
		`{"nested":["-----BEGIN OPENSSH ` + `PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"]}`,
		`{"url":"https://alice:secret@example.com","n":9007199254740993}`,
	}
	for _, in := range inputs {
		out := Scrub([]byte(in))
		if !json.Valid(out) {
			t.Fatalf("invalid JSON after scrub: %s", out)
		}
		if strings.Contains(string(out), "abcdefghijklmnopqrstuvwxyz1234567890") {
			t.Fatalf("escaped secret survived scrub: %s", out)
		}
	}
	escapedOut := string(Scrub([]byte(escapedJSON)))
	if !strings.Contains(escapedOut, "9007199254740993") {
		t.Fatalf("uint64 precision lost during JSON scrub: %s", escapedOut)
	}
}

func FuzzScrubPreservesValidJSON(f *testing.F) {
	for _, seed := range []string{
		`{"s":"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"}`,
		`{"s":"normal text"}`,
		`{"s":"https://u:p@example.com"}`,
		`{"s":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"}`,
		`{"s":"quote \" backslash \\ newline \n"}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if !json.Valid([]byte(in)) {
			t.Skip()
		}
		if out := Scrub([]byte(in)); !json.Valid(out) {
			t.Fatalf("invalid JSON: %q -> %q", in, out)
		}
	})
}
