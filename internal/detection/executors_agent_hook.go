package detection

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// AgentHookBlockExecutor installs a persistent, connector-scoped pre-tool
// gate. It requires an authenticated pre-call hook event as evidence; an
// after-the-fact sensor event cannot prove that a hook can prevent a call.
type AgentHookBlockExecutor struct{ Store *audit.Store }

func (AgentHookBlockExecutor) Point() string { return audit.EnforcementPointAgentHook }

func (e AgentHookBlockExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if e.Store == nil {
		return "", "", fmt.Errorf("Agent Hook policy store unavailable")
	}
	if req.Decision.DetectionID == "" {
		return "", "", fmt.Errorf("explicit tool blacklist detection is required for a persistent tool block")
	}
	detection, _, err := e.Store.GetRuntimeDetectionDetail(req.Decision.DetectionID)
	if err != nil {
		return "", "", fmt.Errorf("load detection for Agent Hook block: %w", err)
	}
	if detection.Attributes["blacklist_target_type"] != "tool" {
		return "", "", fmt.Errorf("only an explicit tool blacklist can justify a persistent whole-tool block")
	}
	var tool, connector string
	for _, item := range req.Evidence {
		ev := item.Event
		if ev.EventSource != audit.RuntimeSourceAgentHook || ev.EventType != audit.RuntimeEventToolPreCall {
			continue
		}
		name := strings.TrimSpace(ev.ToolName)
		scope, _ := ev.Attributes["connector"].(string)
		scope = strings.TrimSpace(scope)
		if name == "" || scope == "" || ev.Attributes["pre_call_block_capable"] != true {
			continue
		}
		if tool != "" && (tool != name || connector != scope) {
			return "", "", fmt.Errorf("ambiguous pre-tool evidence: multiple tools or connectors")
		}
		tool, connector = name, scope
	}
	if tool == "" {
		return "", "", fmt.Errorf("no block-capable connector-scoped pre-tool hook evidence is available")
	}
	policy := enforce.NewPolicyEngine(e.Store)
	if err := policy.BlockToolForConnector(tool, connector, "runtime decision "+req.Decision.DecisionID); err != nil {
		return tool, "", err
	}
	blocked, err := policy.IsToolBlockedForConnector(tool, connector)
	if err != nil {
		return tool, "", fmt.Errorf("Agent Hook block verification failed: %w", err)
	}
	if !blocked {
		return tool, "", fmt.Errorf("Agent Hook block was not effective after writing policy")
	}
	return tool, "persistent connector-scoped pre-tool gate verified for future calls; prior calls cannot be reversed", nil
}
