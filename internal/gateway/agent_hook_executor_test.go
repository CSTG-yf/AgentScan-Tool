package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/detection"
)

func TestRuntimeDecisionHookExecutorBlocksNextToolCall(t *testing.T) {
	api, store := toolPolicyAPI(t, "action")
	engine := detection.NewPolicyEngine(store)
	d, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		DetectionType: "configured_blacklist", Attributes: map[string]any{"blacklist_target_type": "tool"},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision := audit.RuntimeDecision{DecisionID: "D-hook-gate", DetectionID: d.DetectionID, EnforcementPoint: audit.EnforcementPointAgentHook}
	evidence := []audit.DetectionEvidence{{Event: audit.BehaviorEvent{
		EventType:   audit.RuntimeEventToolPreCall,
		EventSource: audit.RuntimeSourceAgentHook,
		ToolName:    "Read",
		Attributes:  map[string]any{"connector": "codex"},
	}}}
	status, _, _ := engine.ExecuteNonProxy(context.Background(), decision, "TOOL_BLOCK", evidence, true)
	if status != audit.ResponseStatusExecuted {
		t.Fatalf("hook executor status = %s", status)
	}
	_, blocked := postInspect(t, api, `{"tool":"Read","connector":"codex","args":{}}`)
	if blocked.Action != "block" {
		t.Fatalf("next tool call action = %s; expected block", blocked.Action)
	}
	_, other := postInspect(t, api, `{"tool":"Read","connector":"claudecode","args":{}}`)
	if other.Action == "block" {
		t.Fatal("connector-scoped block leaked to another connector")
	}
}
