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
	var server, connector string
	for _, evidence := range req.Evidence {
		name := strings.TrimSpace(evidence.Event.MCPServer)
		if name == "" {
			continue
		}
		if server != "" && server != name {
			return "", "", fmt.Errorf("ambiguous MCP evidence: more than one server")
		}
		server = name
		if value, ok := evidence.Event.Attributes["connector"].(string); ok {
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
		return "", "", fmt.Errorf("no explicit MCP server in detection evidence")
	}
	policy := enforce.NewPolicyEngine(e.Store)
	reason := "runtime decision " + req.Decision.DecisionID
	if connector != "" {
		if err := policy.BlockForConnector("mcp", server, connector, reason); err != nil {
			return server, "", err
		}
	} else if err := policy.Block("mcp", server, reason); err != nil {
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
