package mcp

import (
	"context"
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
		mutateTool("prompt_agent", "Submit a prompt to an agent in a pane via agent.prompt, with optional bounded wait.", false),
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
			return client.Call(ctx, m, "agent.prompt", params, extra)
		},
	)

	register[createWorkspaceInput](
		s,
		mutateTool("create_workspace", "Create a new herdr workspace via workspace.create (always sends focus=false and returns root_pane).", false),
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
			return client.Call(ctx, m, "workspace.create", params, 0)
		},
	)

	register[startAgentInput](
		s,
		mutateTool("start_agent", "Start an agent in a pane via agent.start.", false),
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
