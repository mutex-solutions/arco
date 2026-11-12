package mcp

import (
	"context"
	"log/slog"
	"time"

	"github.com/mutex-solutions/arco/internal/registry"
)

type auditKey struct{}

type auditInfo struct {
	log   *slog.Logger
	token string
}

// WithAudit makes every tool call served under ctx write one audit line to l:
// tool, machine, token id, outcome, and duration. Arguments and results are
// never logged; they can carry pane text and secrets.
func WithAudit(ctx context.Context, l *slog.Logger, tokenID string) context.Context {
	return context.WithValue(ctx, auditKey{}, auditInfo{log: l, token: tokenID})
}

func audit(ctx context.Context, tool string, mutating bool, args map[string]any, start time.Time, outcome string) {
	info, ok := ctx.Value(auditKey{}).(auditInfo)
	if !ok || info.log == nil {
		return
	}
	machine := "-"
	if id, ok := args["machine"].(string); ok {
		machine = "<invalid>"
		if registry.ValidID(id) {
			machine = id
		}
	}
	info.log.Info("tool call",
		"tool", tool,
		"mutating", mutating,
		"machine", machine,
		"token", info.token,
		"outcome", outcome,
		"duration", time.Since(start).Round(time.Millisecond))
}
