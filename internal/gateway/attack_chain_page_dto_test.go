package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestPageChainStepsSerializesStackAsArray(t *testing.T) {
	steps, _, _ := pageChainStepsFromRuntime([]audit.AttackChainEvent{{
		EventID:  1,
		Sequence: 1,
		Event: audit.BehaviorEvent{
			ID:        1,
			EventType: "tool.call",
		},
	}})
	if len(steps) != 1 || steps[0].Stack == nil {
		t.Fatalf("steps=%+v", steps)
	}
	payload, err := json.Marshal(steps[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if stack, ok := decoded["stack"].([]any); !ok || len(stack) != 0 {
		t.Fatalf("stack must be an empty JSON array, payload=%s", payload)
	}
	if decoded["stackStatus"] != "not_collected" {
		t.Fatalf("missing frames must be explicit, payload=%s", payload)
	}
}

func TestPageChainStepsUsesOnlyCapturedRuntimeFrames(t *testing.T) {
	steps, _, _ := pageChainStepsFromRuntime([]audit.AttackChainEvent{{
		EventID: 1,
		Event: audit.BehaviorEvent{
			ID:        1,
			EventType: audit.RuntimeEventToolPreCall,
			Attributes: map[string]any{
				"stack_source": "python.traceback",
				"stack_frames": []any{
					map[string]any{"file": "api/app.py", "function": "call_mcp", "line": float64(389)},
					map[string]any{"file": "api/app.py", "function": "run_agent", "line": float64(291)},
				},
			},
		},
	}})
	if len(steps) != 1 || steps[0].StackStatus != "captured" || steps[0].StackSource != "python.traceback" {
		t.Fatalf("runtime stack provenance = %+v", steps)
	}
	if len(steps[0].Stack) != 2 || steps[0].Stack[0] != "call_mcp (api/app.py:389)" {
		t.Fatalf("stack frames = %+v", steps[0].Stack)
	}
}

func TestPageChainLegacyStackDoesNotInventFrames(t *testing.T) {
	step := pageStepFromEvent(pageEvent{Source: "agent_hook", Category: "tool", Subtype: "mcp", Runtime: "python"}, 1)
	if len(step.Stack) != 0 || step.StackStatus != "not_collected" {
		t.Fatalf("legacy event labels must not be presented as a call stack: %+v", step)
	}
}
