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
}
