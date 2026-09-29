package detection

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

func TestAgentHookExecutorRequiresPreCallEvidence(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitToolDetection(t, store)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-tool", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointAgentHook}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceOSSensor,
		ToolName: "Read", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
	}}}
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "TOOL_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed || !strings.Contains(result, "no block-capable connector-scoped pre-tool") {
		t.Fatalf("unexpected result: %s %s", status, result)
	}
}

func TestAgentHookExecutorPersistsScopedGate(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitToolDetection(t, store)
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-tool", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointAgentHook}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		ToolName: "Read", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
	}}}
	status, target, result := policy.ExecuteNonProxy(context.Background(), decision, "TOOL_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted || target != "Read" || !strings.Contains(result, "future calls") {
		t.Fatalf("unexpected result: %s %s %s", status, target, result)
	}
	gate := enforce.NewPolicyEngine(store)
	blocked, err := gate.IsToolBlockedForConnector("Read", "codex")
	if err != nil || !blocked {
		t.Fatalf("codex gate = %v, %v", blocked, err)
	}
	blocked, err = gate.IsToolBlockedForConnector("Read", "claudecode")
	if err != nil || blocked {
		t.Fatalf("other connector gate = %v, %v", blocked, err)
	}
}

func TestAgentHookExecutorRejectsNonBlockingHook(t *testing.T) {
	store := newDetectionTestStore(t)
	d := explicitToolDetection(t, store)
	decision := audit.RuntimeDecision{DecisionID: "D-unblockable", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointAgentHook}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		ToolName: "Read", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": false},
	}}}
	status, _, _ := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "TOOL_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed {
		t.Fatalf("non-blocking hook reported success: %s", status)
	}
	blocked, err := enforce.NewPolicyEngine(store).IsToolBlockedForConnector("Read", "codex")
	if err != nil || blocked {
		t.Fatalf("non-blocking hook changed policy: blocked=%v err=%v", blocked, err)
	}
}

func TestAgentHookExecutorDoesNotPermanentlyBlockGenericRead(t *testing.T) {
	store := newDetectionTestStore(t)
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "credential_access", Attributes: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := NewPolicyEngine(store)
	decision := audit.RuntimeDecision{DecisionID: "D-credential", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointAgentHook}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType: audit.RuntimeEventToolPreCall, EventSource: audit.RuntimeSourceAgentHook,
		ToolName: "Read", Attributes: map[string]any{"connector": "codex", "pre_call_block_capable": true},
	}}}
	status, _, _ := policy.ExecuteNonProxy(context.Background(), decision, "TOOL_BLOCK", evidence, true)
	if status != audit.ResponseStatusFailed {
		t.Fatalf("generic Read block status = %s, want failed", status)
	}
}

func explicitToolDetection(t *testing.T, store *audit.Store) audit.RuntimeDetection {
	t.Helper()
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "configured_blacklist", Attributes: map[string]any{"blacklist_target_type": "tool"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
