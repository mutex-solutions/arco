package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/registry"
)

const fleetTruncationMarker = "\n...[truncated at 256 KiB; use the agents tool per machine]"

// FleetMachineStatus is one entry in fleet_status's registry-ordered response.
type FleetMachineStatus struct {
	Machine string          `json:"machine"`
	Agents  json.RawMessage `json:"agents,omitempty"`
	Error   string          `json:"error,omitempty"`
}

func registerReadTools(s *sdkmcp.Server, reg *registry.Registry, client *herdr.Client) {
	register[emptyInput](
		s,
		readTool("machines", "Probe all registered machines via herdr ping and report reachability, version, and protocol."),
		nil,
		nil,
		"",
		func(ctx context.Context, _ emptyInput) (any, error) {
			return client.ProbeMachines(ctx, reg), nil
		},
	)

	register[emptyInput](
		s,
		readTool("fleet_status", "Query agent.list concurrently across all registered machines in registry order; unreachable machines are reported inline with their error."),
		nil,
		nil,
		fleetTruncationMarker,
		func(ctx context.Context, _ emptyInput) (any, error) {
			machines := reg.Machines()
			results := make([]FleetMachineStatus, len(machines))
			var wg sync.WaitGroup
			wg.Add(len(machines))
			for i, m := range machines {
				go func(idx int, mach *registry.Machine) {
					defer wg.Done()
					raw, err := client.Call(ctx, mach, "agent.list", struct{}{}, 0)
					if err != nil {
						results[idx] = FleetMachineStatus{
							Machine: mach.ID(),
							Error:   err.Error(),
						}
						return
					}
					var env struct {
						Agents json.RawMessage `json:"agents"`
					}
					if json.Unmarshal(raw, &env) == nil && len(env.Agents) > 0 {
						results[idx] = FleetMachineStatus{
							Machine: mach.ID(),
							Agents:  env.Agents,
						}
						return
					}
					results[idx] = FleetMachineStatus{
						Machine: mach.ID(),
						Agents:  raw,
					}
				}(i, m)
			}
			wg.Wait()
			return results, nil
		},
	)

	register[machineInput](
		s,
		readTool("workspaces", "List workspaces on a single registered machine via workspace.list."),
		requireNonEmptyProps("machine"),
		nil,
		"",
		func(ctx context.Context, in machineInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "workspace.list", struct{}{}, 0)
		},
	)

	register[panesInput](
		s,
		readTool("panes", "List panes on a single registered machine via pane.list, optionally filtered by workspace_id."),
		requireNonEmptyProps("machine"),
		nil,
		"",
		func(ctx context.Context, in panesInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			var params herdr.PaneListParams
			if in.WorkspaceID != "" {
				ws := in.WorkspaceID
				params.WorkspaceID = &ws
			}
			return client.Call(ctx, m, "pane.list", params, 0)
		},
	)

	register[machineInput](
		s,
		readTool("agents", "List agents on a single registered machine via agent.list."),
		requireNonEmptyProps("machine"),
		nil,
		"",
		func(ctx context.Context, in machineInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "agent.list", struct{}{}, 0)
		},
	)

	register[peekInput](
		s,
		readTool("peek", "Read recent plain-text output from a pane via pane.read (source=recent_unwrapped, strip_ansi=true, format=text forced, 1-200 logical lines). A new pane can be empty until its shell prints a prompt."),
		customizePeekSchema,
		nil,
		"",
		func(ctx context.Context, in peekInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			tail := in.Tail
			if tail == 0 {
				tail = 50
			}
			// recent_unwrapped joins soft-wrapped rows back into logical
			// lines. The wrapped sources (recent, visible) split a long
			// secret across rows, and the redaction patterns then miss
			// the continuation (verified live: sk-proj- keys leaked their
			// tail). Not exposed as a knob for the same reason as strip_ansi.
			// One extra line is requested because a truncated window can
			// start mid-line; dropPartialFirstLine removes that line.
			raw, err := client.Call(ctx, m, "pane.read", herdr.PaneReadParams{
				PaneID:    in.PaneID,
				Source:    "recent_unwrapped",
				Lines:     tail + 1,
				Format:    "text",
				StripANSI: true,
			}, 0)
			if err != nil {
				return nil, err
			}
			return dropPartialFirstLine(raw)
		},
	)

	register[waitForOutputInput](
		s,
		readTool("wait_for_output", "Block until a pane's recent output matches a pattern, via pane.wait_for_output, then return the matched line and recent text. "+
			"Use it to wait for a shell prompt before typing into a new pane (for example pattern `[$%#>❯➜]\\s*$` with regex=true), or for a command's output. "+
			"Times out with a remote timeout error; nothing is changed either way."),
		customizeWaitForOutputSchema,
		nil,
		"",
		func(ctx context.Context, in waitForOutputInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			match := herdr.OutputMatch{Type: "substring", Value: in.Pattern}
			if in.Regex {
				match.Type = "regex"
			}
			timeout := orDefault(in.TimeoutMS, defaultWaitMS)
			// Same safety rules as peek: unwrapped text, one extra line,
			// and the partial first line of a truncated window dropped.
			raw, err := client.Call(ctx, m, "pane.wait_for_output", herdr.PaneWaitForOutputParams{
				PaneID:    in.PaneID,
				Source:    "recent_unwrapped",
				Match:     match,
				Lines:     orDefault(in.Tail, 20) + 1,
				TimeoutMS: uint64(timeout),
				StripANSI: true,
			}, time.Duration(timeout)*time.Millisecond)
			if err != nil {
				return nil, err
			}
			return dropPartialFirstLine(raw)
		},
	)

	register[waitAgentInput](
		s,
		readTool("wait_agent", "Block until an agent reaches one of the given states (default idle, done, or blocked), via agent.wait. "+
			"Use it after start_agent or prompt_agent instead of polling agents. Times out with a remote timeout error; nothing is changed either way."),
		customizeWaitAgentSchema,
		nil,
		"",
		func(ctx context.Context, in waitAgentInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			timeout := orDefault(in.TimeoutMS, defaultWaitMS)
			return client.Call(ctx, m, "agent.wait", herdr.AgentWaitParams{
				Target:    in.Target,
				TimeoutMS: uint64(timeout),
				Until:     in.Until,
			}, time.Duration(timeout)*time.Millisecond)
		},
	)

	register[paneTargetInput](
		s,
		readTool("pane_detail", "Get full pane details and agent state on a registered machine via pane.get."),
		requireNonEmptyProps("machine", "pane_id"),
		nil,
		"",
		func(ctx context.Context, in paneTargetInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "pane.get", herdr.PaneTargetParams{PaneID: in.PaneID}, 0)
		},
	)
}

// dropPartialFirstLine removes the first line of a truncated pane.read. herdr
// cuts the window at a row, not a logical-line boundary, so the first line can
// begin in the middle of a secret, past the prefix the redaction patterns key
// on (verified live: a window opening inside an sk-proj- key returned its bare
// tail). Everything else in the result passes through untouched.
func dropPartialFirstLine(raw json.RawMessage) (json.RawMessage, error) {
	var res map[string]json.RawMessage
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("pane.read: decode result: %w", err)
	}
	var read map[string]json.RawMessage
	if err := json.Unmarshal(res["read"], &read); err != nil {
		return nil, fmt.Errorf("pane.read: decode read: %w", err)
	}
	var truncated bool
	var text string
	if err := json.Unmarshal(read["truncated"], &truncated); err != nil || !truncated {
		return raw, nil
	}
	if err := json.Unmarshal(read["text"], &text); err != nil {
		return nil, fmt.Errorf("pane.read: decode text: %w", err)
	}
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[i+1:]
	} else {
		text = ""
	}
	enc, err := marshalNoEscape(text)
	if err != nil {
		return nil, err
	}
	read["text"] = enc
	if res["read"], err = marshalNoEscape(read); err != nil {
		return nil, err
	}
	return marshalNoEscape(res)
}

func marshalNoEscape(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
