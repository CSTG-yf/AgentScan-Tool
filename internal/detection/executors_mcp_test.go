package detection

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestMCPBlockExecutorRequiresIdentifiedServer(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitMCPDetection(t, store)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-missing", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", nil, true)
	if status != audit.ResponseStatusFailed || !strings.Contains(result, "no explicit MCP server") {
		t.Fatalf("unexpected result: %s %s", status, result)
	}
}

func TestMCPBlockExecutorRejectsUncontrolledEvidence(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitMCPDetection(t, store)
	decision := audit.RuntimeDecision{DecisionID: "D-uncontrolled", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	for _, ev := range []audit.BehaviorEvent{
		{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceOSSensor, MCPServer: "jira", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true}},
		{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook, MCPServer: "jira", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": false}},
		{EventType: audit.RuntimeEventToolPostCall, EventSource: audit.RuntimeSourceAgentHook, MCPServer: "jira", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true}},
	} {
		status, _, result := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", []audit.DetectionEvidence{{Event: ev}}, true)
		if status != audit.ResponseStatusFailed || !strings.Contains(result, "no confirmed block-capable") {
			t.Fatalf("uncontrolled MCP evidence reported success: %s %s", status, result)
		}
	}
}

func TestMCPBlockExecutorAcceptsAuthenticatedAgentRangePreCall(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitMCPDetection(t, store)
	decision := audit.RuntimeDecision{DecisionID: "D-range", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceGuardrail,
		MCPServer: "jira", Attributes: map[string]any{"connector": "agentrange", "proxy_kind": "mcp", "phase": "pre", "pre_call_block_capable": true},
	}}}
	status, _, _ := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted {
		t.Fatalf("authenticated AgentRange pre-call gate = %s", status)
	}
}

func TestMCPBlockExecutorPersistsScopedGate(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitMCPDetection(t, store)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-jira", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		MCPServer: "jira", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
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

func TestMCPBlockExecutorRejectsAmbiguousGlobalScope(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitMCPDetection(t, store)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-jira", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook, MCPServer: "jira", Attributes: map[string]any{"pre_call_block_capable": true}}}}
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed || !strings.Contains(result, "no connector identity") {
		t.Fatalf("unexpected result: %s %s", status, result)
	}
}

func TestMCPBlockExecutorRejectsMaliciousSkillAsServer(t *testing.T) {
	store := newDetectionTestStore(t)
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "known_malicious_resource_invocation",
		Attributes:    map[string]any{"resource_type": "skill"},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-skill", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		MCPServer: "jira", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
	}}}
	status, _, _ := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed {
		t.Fatalf("skill incorrectly blocked as MCP server: %s", status)
	}
}

func TestMCPBlockExecutorRequiresMatchingMaliciousResource(t *testing.T) {
	store := newDetectionTestStore(t)
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "known_malicious_resource_invocation",
		Attributes: map[string]any{
			"resource_type": "mcp", "resource_name": "jira",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-resource", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointMCP}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		MCPServer: "github", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
	}}}
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed || !strings.Contains(result, "does not match") {
		t.Fatalf("wrong resource was blocked: %s %s", status, result)
	}
	evidence[0].Event.MCPServer = "jira"
	status, _, _ = policy.ExecuteNonProxy(context.Background(), decision, "MCP_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted {
		t.Fatalf("matching malicious MCP was not blocked: %s", status)
	}
}

func explicitMCPDetection(t *testing.T, store *audit.Store) audit.RuntimeDetection {
	t.Helper()
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "configured_blacklist", Attributes: map[string]any{"blacklist_target_type": "mcp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
