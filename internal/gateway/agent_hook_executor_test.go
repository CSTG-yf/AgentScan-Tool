package gateway

import (
	"context"
	"encoding/json"
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
	SetRuntimeEventStore(store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })
	api.recordHookRuntimeEvent(context.Background(), agentHookRequest{
		ConnectorName: "codex", HookEventName: "PreToolUse", ToolName: "Read",
		ToolArgs: json.RawMessage(`{"file_path":"README.md"}`),
	}, agentHookResponse{Action: "allow", Mode: "action"})
	rows, err := store.ListRuntimeEvents(audit.RuntimeEventFilter{EventSource: audit.RuntimeSourceAgentHook, Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Attributes["pre_call_block_capable"] != true {
		t.Fatalf("hook capability evidence = %+v, %v", rows, err)
	}
	evidence := []audit.DetectionEvidence{{Event: rows[0]}}
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
