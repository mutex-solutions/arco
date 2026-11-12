package herdr

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mutex-solutions/arco/internal/registry"
)

const (
	MinProtocolVersion  = 22
	DefaultStartTimeout = 10000 // ms (> 3000 and <= 300000 per herdr schema)
)

// MachineStatus is one machine's reachability and protocol probe result.
type MachineStatus struct {
	ID        string `json:"id"`
	Transport string `json:"transport"`
	OK        bool   `json:"ok"`
	Version   string `json:"version,omitempty"`
	Protocol  int    `json:"protocol,omitempty"`
	Warning   string `json:"warning,omitempty"`
	Cause     string `json:"cause,omitempty"`

	// Operator-only: never serialized into MCP responses.
	Target      string `json:"-"`
	CauseDetail string `json:"-"`
}

type pongResult struct {
	Version  string `json:"version"`
	Protocol int    `json:"protocol"`
}

// ProbeMachines probes every machine in reg concurrently in registry order.
func (c *Client) ProbeMachines(ctx context.Context, reg *registry.Registry) []MachineStatus {
	machines := reg.Machines()
	out := make([]MachineStatus, len(machines))
	var wg sync.WaitGroup
	wg.Add(len(machines))
	for i, m := range machines {
		go func(idx int, mach *registry.Machine) {
			defer wg.Done()
			st := MachineStatus{
				ID:        mach.ID(),
				Transport: mach.Transport(),
				Target:    mach.Target(),
			}
			raw, err := c.Call(ctx, mach, "ping", struct{}{}, 0)
			if err != nil {
				st.OK = false
				st.Cause = err.Error()
				st.CauseDetail = st.Cause
				var he *Error
				if errors.As(err, &he) {
					st.CauseDetail = he.Detail()
				}
				out[idx] = st
				return
			}
			st.OK = true
			var pong pongResult
			if err := json.Unmarshal(raw, &pong); err == nil {
				st.Version = pong.Version
				st.Protocol = pong.Protocol
				if pong.Protocol > 0 && pong.Protocol < MinProtocolVersion {
					st.Warning = fmt.Sprintf("herdr protocol %d is older than expected protocol %d (version %s)", pong.Protocol, MinProtocolVersion, pong.Version)
				}
			}
			out[idx] = st
		}(i, m)
	}
	wg.Wait()
	return out
}

// WorkspaceCreateParams encodes workspace.create parameters.
// Focus intentionally omits `omitempty` so `"focus":false` is always sent on the wire.
type WorkspaceCreateParams struct {
	Cwd   *string `json:"cwd,omitempty"`
	Label *string `json:"label,omitempty"`
	Focus bool    `json:"focus"`
}

// PaneListParams encodes pane.list parameters.
type PaneListParams struct {
	WorkspaceID *string `json:"workspace_id,omitempty"`
}

// PaneTargetParams encodes pane.get and pane.close parameters.
type PaneTargetParams struct {
	PaneID string `json:"pane_id"`
}

// WorkspaceCloseParams encodes workspace.close parameters (close_group is intentionally unexposed).
type WorkspaceCloseParams struct {
	WorkspaceID string `json:"workspace_id"`
}

// PaneReadParams encodes pane.read parameters.
// Format and StripANSI are forced to "text" and true respectively.
type PaneReadParams struct {
	PaneID    string `json:"pane_id"`
	Source    string `json:"source"`
	Lines     int    `json:"lines"`
	Format    string `json:"format"`
	StripANSI bool   `json:"strip_ansi"`
}

// PaneSendTextParams encodes pane.send_text parameters.
type PaneSendTextParams struct {
	PaneID string `json:"pane_id"`
	Text   string `json:"text"`
}

// AgentWaitOptions encodes wait options for agent.prompt.
type AgentWaitOptions struct {
	TimeoutMS uint64   `json:"timeout_ms,omitempty"`
	Until     []string `json:"until,omitempty"`
}

// AgentWaitParams encodes agent.wait parameters.
type AgentWaitParams struct {
	Target    string   `json:"target"`
	TimeoutMS uint64   `json:"timeout_ms"`
	Until     []string `json:"until,omitempty"`
}

// OutputMatch is a pane.wait_for_output match: type "substring" or "regex".
type OutputMatch struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// PaneWaitForOutputParams encodes pane.wait_for_output parameters.
// Source and StripANSI are forced the same way as for peek.
type PaneWaitForOutputParams struct {
	PaneID    string      `json:"pane_id"`
	Source    string      `json:"source"`
	Match     OutputMatch `json:"match"`
	Lines     int         `json:"lines"`
	TimeoutMS uint64      `json:"timeout_ms"`
	StripANSI bool        `json:"strip_ansi"`
}

// AgentPromptParams encodes agent.prompt parameters.
type AgentPromptParams struct {
	Target string            `json:"target"`
	Text   string            `json:"text"`
	Wait   *AgentWaitOptions `json:"wait"`
}

// AgentStartParams encodes agent.start parameters.
type AgentStartParams struct {
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	PaneID    string   `json:"pane_id"`
	Args      []string `json:"args,omitempty"`
	TimeoutMS uint64   `json:"timeout_ms"`
}

// StartTimeoutExtra returns the extra deadline budget for agent.start.
func StartTimeoutExtra() time.Duration {
	return time.Duration(DefaultStartTimeout) * time.Millisecond
}
