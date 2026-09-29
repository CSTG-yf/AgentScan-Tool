package detection

import (
	"context"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// MCPBlockExecutor installs a persistent gate consumed by the Gateway's
// pre-tool MCP check. It blocks future calls; it cannot undo the call that
// produced an already-observed detection.
type MCPBlockExecutor struct{ Store *audit.Store }

func (MCPBlockExecutor) Point() string { return audit.EnforcementPointMCP }

func (e MCPBlockExecutor) Execute(ctx context.Context, req RuntimeExecutionRequest) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if e.Store == nil {
		return "", "", fmt.Errorf("MCP policy store unavailable")
	}
	if req.Decision.DetectionID == "" {
		return "", "", fmt.Errorf("MCP risk detection is required for a persistent server block")
	}
	detection, _, err := e.Store.GetRuntimeDetectionDetail(req.Decision.DetectionID)
	if err != nil {
		return "", "", fmt.Errorf("load detection for MCP block: %w", err)
	}
	if detection.Attributes["blacklist_target_type"] != "mcp" &&
		!(detection.DetectionType == "known_malicious_resource_invocation" && detection.Attributes["resource_type"] == "mcp") {
		return "", "", fmt.Errorf("only an explicit MCP blacklist or known-malicious MCP resource can justify a persistent server block")
	}
	var server, connector string
	sawServer := false
	for _, evidence := range req.Evidence {
		ev := evidence.Event
		name := strings.TrimSpace(ev.MCPServer)
		if name == "" {
			continue
		}
		sawServer = true
		if ev.EventType != audit.RuntimeEventToolPreCall || ev.Attributes["pre_call_block_capable"] != true ||
			!(ev.EventSource == audit.RuntimeSourceAgentHook ||
				(ev.EventSource == audit.RuntimeSourceGuardrail && ev.Attributes["connector"] == "agentrange" && ev.Attributes["proxy_kind"] == "mcp" && ev.Attributes["phase"] == "pre")) {
			continue
		}
		if server != "" && server != name {
			return "", "", fmt.Errorf("ambiguous MCP evidence: more than one server")
		}
		server = name
		if value, ok := ev.Attributes["connector"].(string); ok {
			value = strings.TrimSpace(value)
			if connector != "" && value != "" && connector != value {
				return "", "", fmt.Errorf("ambiguous MCP evidence: more than one connector")
			}
			if value != "" {
				connector = value
			}
		}
	}
	if server == "" {
		if sawServer {
			return "", "", fmt.Errorf("no confirmed block-capable pre-call MCP evidence")
		}
		return "", "", fmt.Errorf("no explicit MCP server in detection evidence")
	}
	if detection.DetectionType == "known_malicious_resource_invocation" {
		resource, _ := detection.Attributes["resource_name"].(string)
		if resource == "" || !strings.EqualFold(strings.TrimSpace(resource), server) {
			return server, "", fmt.Errorf("MCP evidence does not match the known-malicious resource")
		}
	}
	if connector == "" {
		return "", "", fmt.Errorf("no connector identity in MCP evidence; refusing a global block")
	}
	policy := enforce.NewPolicyEngine(e.Store)
	reason := "runtime decision " + req.Decision.DecisionID
	if err := policy.BlockForConnector("mcp", server, connector, reason); err != nil {
		return server, "", err
	}
	blocked, err := policy.IsBlockedForConnector("mcp", server, connector)
	if err != nil {
		return server, "", fmt.Errorf("MCP block verification failed: %w", err)
	}
	if !blocked {
		return server, "", fmt.Errorf("MCP block was not effective after writing policy")
	}
	return server, "persistent pre-tool MCP gate verified for future calls; prior calls cannot be reversed", nil
}
