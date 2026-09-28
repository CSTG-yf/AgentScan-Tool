package detection

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestMCPBlockExecutorRequiresIdentifiedServer(t *testing.T) {
	policy := NewPolicyEngine(newDetectionTestStore(t))
	decision := audit.RuntimeDecision{DecisionID: "D-missing", EnforcementPoint: audit.EnforcementPointMCP}
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", nil, true)
	if status != audit.ResponseStatusFailed || !strings.Contains(result, "no explicit MCP server") {
		t.Fatalf("unexpected result: %s %s", status, result)
	}
}

func TestMCPBlockExecutorPersistsScopedGate(t *testing.T) {
	store := newDetectionTestStore(t)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-jira", EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		MCPServer: "jira", Attributes: map[string]any{"connector": "codex"},
	}}}
	status, target, result := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted || target != "jira" || !strings.Contains(result, "future calls") {
		t.Fatalf("unexpected result: %s %s %s", status, target, result)
	}
	gate := enforce.NewPolicyEngine(store)
	blocked, err := gate.IsBlockedForConnector("mcp", "jira", "codex")
	if err != nil || !blocked {
		t.Fatalf("codex gate = %v, %v", blocked, err)
	}
	blocked, err = gate.IsBlockedForConnector("mcp", "jira", "claudecode")
	if err != nil || blocked {
		t.Fatalf("other connector gate = %v, %v", blocked, err)
	}
}
