package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/mutex-solutions/arco/internal/herdr"
	"github.com/mutex-solutions/arco/internal/registry"
)

func registerMutateTools(s *sdkmcp.Server, reg *registry.Registry, client *herdr.Client) {
	register[sendTextInput](
		s,
		mutateTool("send_text", "Send raw text into a pane via pane.send_text without stealing focus. End the text with a newline to press Enter.", false),
		requireNonEmptyProps("machine", "pane_id"),
		validateSendText,
		"",
		func(ctx context.Context, in sendTextInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "pane.send_text", herdr.PaneSendTextParams{
				PaneID: in.PaneID,
				Text:   in.Text,
			}, 0)
		},
	)

	register[promptAgentInput](
		s,
		mutateTool("prompt_agent", "Submit a prompt to an agent in a pane via agent.prompt, with optional bounded wait. "+
			"If the wait expires, the result has delivered=true and wait_timed_out=true: the prompt was submitted, so do not resend it. "+
			"Without a wait, the returned agent state is from the moment of submission and may not reflect the new prompt yet. "+
			"With a wait, it is the first idle, done, or blocked state seen after submission; if the agent was already working, that can be the previous turn finishing.", false),
		customizePromptAgentSchema,
		validatePromptAgent,
		"",
		func(ctx context.Context, in promptAgentInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			params := herdr.AgentPromptParams{
				Target: in.Target,
				Text:   in.Text,
			}
			var extra time.Duration
			if in.WaitTimeoutMS > 0 {
				params.Wait = &herdr.AgentWaitOptions{
					TimeoutMS: uint64(in.WaitTimeoutMS),
				}
				extra = time.Duration(in.WaitTimeoutMS) * time.Millisecond
			}
			raw, err := client.Call(ctx, m, "agent.prompt", params, extra)
			if err != nil {
				return promptOutcome(err, in.WaitTimeoutMS)
			}
			return raw, nil
		},
	)

	register[createWorkspaceInput](
		s,
		mutateTool("create_workspace", "Create a new herdr workspace via workspace.create (always sends focus=false and returns root_pane). "+
			"If herdr starts the pane somewhere other than the requested cwd (for example because it does not exist), the result has a warning field. "+
			"A new pane may show nothing until its shell is ready; peek before typing into it.", false),
		requireNonEmptyProps("machine"),
		nil,
		"",
		func(ctx context.Context, in createWorkspaceInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			params := herdr.WorkspaceCreateParams{
				Focus: false,
			}
			if in.Cwd != "" {
				cwd := in.Cwd
				params.Cwd = &cwd
			}
			if in.Label != "" {
				label := in.Label
				params.Label = &label
			}
			raw, err := client.Call(ctx, m, "workspace.create", params, 0)
			if err != nil {
				return nil, err
			}
			return warnOnCwdMismatch(raw, in.Cwd), nil
		},
	)

	register[startAgentInput](
		s,
		mutateTool("start_agent", "Start an agent in a pane via agent.start. "+
			"herdr can report agent_started with launch_pending=true before the agent is running. "+
			"Confirm with agents (launch_pending gone, agent_status not unknown) or peek before prompting. "+
			"If the pane's shell was not ready, the launch command can be mangled and the agent stays launch_pending until the pane is closed.", false),
		requireNonEmptyProps("machine", "pane_id", "kind", "name"),
		nil,
		"",
		func(ctx context.Context, in startAgentInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "agent.start", herdr.AgentStartParams{
				Name:      in.Name,
				Kind:      in.Kind,
				PaneID:    in.PaneID,
				Args:      in.Args,
				TimeoutMS: herdr.DefaultStartTimeout,
			}, herdr.StartTimeoutExtra())
		},
	)

	register[paneTargetInput](
		s,
		mutateTool("close_pane", "Close a pane on a registered machine via pane.close.", true),
		requireNonEmptyProps("machine", "pane_id"),
		nil,
		"",
		func(ctx context.Context, in paneTargetInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "pane.close", herdr.PaneTargetParams{PaneID: in.PaneID}, 0)
		},
	)

	register[closeWorkspaceInput](
		s,
		mutateTool("close_workspace", "Close a workspace on a registered machine via workspace.close.", true),
		requireNonEmptyProps("machine", "workspace_id"),
		nil,
		"",
		func(ctx context.Context, in closeWorkspaceInput) (any, error) {
			m, err := reg.Resolve(in.Machine)
			if err != nil {
				return nil, err
			}
			return client.Call(ctx, m, "workspace.close", herdr.WorkspaceCloseParams{WorkspaceID: in.WorkspaceID}, 0)
		},
	)
}

// promptWaitTimedOut is returned when herdr accepted a prompt but the caller's
// wait expired before the agent reached a matching state.
type promptWaitTimedOut struct {
	Type          string `json:"type"`
	Delivered     bool   `json:"delivered"`
	WaitTimedOut  bool   `json:"wait_timed_out"`
	WaitTimeoutMS int    `json:"wait_timeout_ms"`
	Note          string `json:"note"`
}

// promptOutcome interprets agent.prompt failures. herdr rejects a blocked
// agent before sending any input, and returns "timeout" or
// "agent_prompt_stalled" only after it accepted the prompt. Without this, a
// timed-out wait reads as a failure and callers resend the prompt.
func promptOutcome(err error, waitMS int) (any, error) {
	var he *herdr.Error
	if !errors.As(err, &he) || he.Remote == nil {
		return nil, err
	}
	switch he.Remote.Code {
	case "timeout":
		if waitMS > 0 {
			return promptWaitTimedOut{
				Type:          "agent_prompt_submitted",
				Delivered:     true,
				WaitTimedOut:  true,
				WaitTimeoutMS: waitMS,
				Note:          "herdr accepted the prompt, but the agent did not reach idle, done, or blocked within wait_timeout_ms. Do not resend; check progress with agents or peek.",
			}, nil
		}
	case "agent_prompt_stalled":
		return nil, fmt.Errorf("%w (the prompt was submitted, but the agent did not start working within 5 s; do not resend blindly)", err)
	case "agent_blocked":
		return nil, fmt.Errorf("%w (the prompt was not submitted: the agent is waiting for input)", err)
	}
	return nil, err
}

// warnOnCwdMismatch adds a warning when herdr started the root pane outside
// the requested absolute cwd. herdr falls back to $HOME without an error when
// the directory does not exist.
func warnOnCwdMismatch(raw json.RawMessage, requested string) any {
	if requested == "" || !filepath.IsAbs(requested) {
		return raw
	}
	var res map[string]json.RawMessage
	if json.Unmarshal(raw, &res) != nil {
		return raw
	}
	var pane struct {
		Cwd *string `json:"cwd"`
	}
	if json.Unmarshal(res["root_pane"], &pane) != nil || pane.Cwd == nil || filepath.Clean(*pane.Cwd) == filepath.Clean(requested) {
		return raw
	}
	warning, _ := json.Marshal(fmt.Sprintf("requested cwd %q, but the pane started in %q; the directory may not exist", requested, *pane.Cwd))
	res["warning"] = warning
	return res
}
