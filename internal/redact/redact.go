// Package redact removes known secret shapes before data leaves arco.
package redact

import (
	"bytes"
	"encoding/json"
	"regexp"
)

const version = "redact-v1"

type pattern struct {
	name string
	re   *regexp.Regexp
}

// Ordered and intentionally conservative. Replacements contain no JSON string
// delimiters or backslashes, so scrubbing cannot manufacture invalid JSON.
var patterns = []pattern{
	{"github-pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)},
	{"github-token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{"gitlab-token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"anthropic-key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"openai-key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}`)},
	{"stripe-key", regexp.MustCompile(`\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b`)},
	{"google-api-key", regexp.MustCompile(`\bAIza[A-Za-z0-9_-]{35}\b`)},
	{"huggingface-token", regexp.MustCompile(`\bhf_[A-Za-z0-9]{30,}\b`)},
	{"npm-token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"arco-token", regexp.MustCompile(`\barco_r[ow]_[A-Za-z0-9_-]{43}`)},
	{"aws-access-key", regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
	// The secret, not the id, is what grants access. Matches env/ini/JSON
	// forms; the key name and separator are kept.
	{"aws-secret-key", regexp.MustCompile(`(?i)\b(aws_secret_access_key|aws_secret_key|secret_access_key)(["']?\s*[=:]\s*["']?)[A-Za-z0-9/+=]{40}`)},
	{"slack-token", regexp.MustCompile(`\bxox[abceprs]-[A-Za-z0-9-]{10,}\b`)},
	{"slack-app-token", regexp.MustCompile(`\bxapp-[0-9]+-[A-Za-z0-9-]{10,}`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"bearer-token", regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{16,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)},
	// A peek window can cut a key block on either side. Orphan markers take
	// the adjacent key-body lines with them; the character classes exclude
	// quotes and backslashes, so a raw-JSON pass cannot run past a string.
	{"private-key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?:[ \t]*\r?\n[A-Za-z0-9+/=:, -]*)*`)},
	{"private-key", regexp.MustCompile(`(?m)(?:^[A-Za-z0-9+/=]+\r?\n)*-----END [A-Z ]*PRIVATE KEY-----`)},
	{"url-credentials", regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@"\\]+:[^\s/@"\\]+@`)},
}

// keep maps pattern names whose leading capture groups survive replacement.
var keep = map[string]string{
	"url-credentials": "${1}[REDACTED:url-credentials]@",
	"aws-secret-key":  "${1}${2}[REDACTED:aws-secret-key]",
	"bearer-token":    "${1}[REDACTED:bearer-token]",
}

type Redactor struct{}

func New() Redactor { return Redactor{} }

// Scrub replaces known secret shapes and returns the cleaned string and count.
func (Redactor) Scrub(s string) (string, int) {
	n := 0
	out := s
	for _, p := range patterns {
		hits := len(p.re.FindAllStringIndex(out, -1))
		if hits == 0 {
			continue
		}
		n += hits
		repl, ok := keep[p.name]
		if !ok {
			repl = "[REDACTED:" + p.name + "]"
		}
		out = p.re.ReplaceAllString(out, repl)
	}
	return out, n
}

func (Redactor) Version() string { return version }

// Scrub is the single response-seam entry point. If data is valid JSON, it first
// scrubs decoded string values (catching JSON-escaped secrets such as \u0073k-proj-…)
// while preserving exact integer digits via json.Number, and then applies a raw
// byte-level pass as defense-in-depth.
func Scrub(data []byte) []byte {
	r := New()
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[' || trimmed[0] == '"') && json.Valid(trimmed) {
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			v, changed := scrubJSONValue(r, v)
			if changed {
				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				if err := enc.Encode(v); err == nil {
					data = bytes.TrimRight(buf.Bytes(), "\n")
				}
			}
		}
	}
	out, _ := r.Scrub(string(data))
	return []byte(out)
}

func scrubJSONValue(r Redactor, v any) (any, bool) {
	switch x := v.(type) {
	case string:
		s, n := r.Scrub(x)
		return s, n > 0
	case map[string]any:
		changed := false
		out := make(map[string]any, len(x))
		for k, val := range x {
			sk, kn := r.Scrub(k)
			sval, vc := scrubJSONValue(r, val)
			if kn > 0 || vc {
				changed = true
			}
			out[sk] = sval
		}
		return out, changed
	case []any:
		changed := false
		for i, item := range x {
			sitem, ic := scrubJSONValue(r, item)
			if ic {
				changed = true
				x[i] = sitem
			}
		}
		return x, changed
	default:
		return v, false
	}
}
