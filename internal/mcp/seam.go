// Package mcp wires arco's tool surface onto the official MCP Go SDK.
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/jsonschema-go/jsonschema"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/redact"
)

const (
	MaxResponseBytes    = 256 << 10 // 256 KiB cap at the response seam
	MaxTextPayloadBytes = 64 << 10  // 64 KiB cap on send_text / prompt_agent text
)

const defaultTruncationMarker = "\n...[truncated at 256 KiB]"

// register is the ONLY function in the repository allowed to call s.AddTool.
// Every tool result and every tool error passes through respond() (scrub-then-truncate)
// and handlers never return a non-nil Go error to the SDK.
func register[In any](
	s *sdkmcp.Server,
	t *sdkmcp.Tool,
	customize func(*jsonschema.Schema),
	validate func(In) error,
	truncMarker string,
	fn func(context.Context, In) (any, error),
) {
	schema, err := jsonschema.For[In](nil)
	if err != nil {
		panic(fmt.Sprintf("mcp schema for %s: %v", t.Name, err))
	}
	if customize != nil {
		customize(schema)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		panic(fmt.Sprintf("mcp resolve schema for %s: %v", t.Name, err))
	}
	t.InputSchema = schema

	s.AddTool(t, func(ctx context.Context, req *sdkmcp.CallToolRequest) (res *sdkmcp.CallToolResult, _ error) {
		defer func() {
			if r := recover(); r != nil {
				res = respond(nil, fmt.Errorf("internal error: %v", r), truncMarker)
			}
		}()

		start := time.Now()
		var argsObj map[string]any
		outcome := "invalid"
		defer func() { audit(ctx, t.Name, !t.Annotations.ReadOnlyHint, argsObj, start, outcome) }()

		raw := bytes.TrimSpace(req.Params.Arguments)
		if len(raw) == 0 || string(raw) == "null" {
			raw = []byte("{}")
		}

		if err := json.Unmarshal(raw, &argsObj); err != nil || argsObj == nil {
			if err == nil {
				err = fmt.Errorf("arguments must be a JSON object")
			}
			return respond(nil, fmt.Errorf("invalid arguments for %s: %w", t.Name, err), truncMarker), nil
		}
		var anyMap any = argsObj
		if err := resolved.Validate(&anyMap); err != nil {
			return respond(nil, fmt.Errorf("invalid arguments for %s: %w", t.Name, err), truncMarker), nil
		}

		var in In
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			return respond(nil, fmt.Errorf("invalid arguments for %s: %w", t.Name, err), truncMarker), nil
		}
		if validate != nil {
			if err := validate(in); err != nil {
				return respond(nil, fmt.Errorf("invalid arguments for %s: %w", t.Name, err), truncMarker), nil
			}
		}

		outcome = "panic" // replaced below unless fn panics
		val, callErr := fn(ctx, in)
		outcome = "ok"
		if callErr != nil {
			outcome = "error"
		}
		return respond(val, callErr, truncMarker), nil
	})
}

func respond(v any, err error, truncMarker string) *sdkmcp.CallToolResult {
	var body []byte
	if err != nil {
		body = []byte(err.Error())
	} else {
		body = marshalNoHTMLEscape(v)
	}
	// Scrub FIRST, then truncate at a UTF-8 rune boundary so a secret straddling
	// the truncation boundary can never be split before redaction.
	body = redact.Scrub(body)
	body = truncateUTF8(body, MaxResponseBytes, truncMarker)

	return &sdkmcp.CallToolResult{
		IsError: err != nil,
		Content: []sdkmcp.Content{
			&sdkmcp.TextContent{Text: string(body)},
		},
	}
}

func marshalNoHTMLEscape(v any) []byte {
	switch raw := v.(type) {
	case json.RawMessage:
		return append([]byte(nil), raw...)
	case []byte:
		return append([]byte(nil), raw...)
	case string:
		return []byte(raw)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(fmt.Sprintf("marshal tool response: %v", err))
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

func truncateUTF8(b []byte, limit int, marker string) []byte {
	if len(b) <= limit {
		return b
	}
	if marker == "" {
		marker = defaultTruncationMarker
	}
	mb := []byte(marker)
	if limit <= len(mb) {
		return mb[:limit]
	}
	keep := limit - len(mb)
	for keep > 0 && !utf8.RuneStart(b[keep]) {
		keep--
	}
	// If the last rune starting before `keep` is incomplete at `keep`, step back to its start.
	if keep > 0 {
		r, width := utf8.DecodeLastRune(b[:keep])
		if r == utf8.RuneError && width == 1 {
			keep--
			for keep > 0 && !utf8.RuneStart(b[keep]) {
				keep--
			}
		}
	}
	out := make([]byte, 0, keep+len(mb))
	out = append(out, b[:keep]...)
	out = append(out, mb...)
	return out
}
