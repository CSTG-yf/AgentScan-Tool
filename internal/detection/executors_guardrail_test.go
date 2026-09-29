package detection

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestGuardrailExecutorRequiresConfirmedProxyReceipt(t *testing.T) {
	store := newDetectionTestStore(t)
	detection, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{DetectionType: "prompt_injection"})
	if err != nil {
		t.Fatal(err)
	}
	decision := audit.RuntimeDecision{DecisionID: "D-prompt", DetectionID: detection.DetectionID, EnforcementPoint: audit.EnforcementPointGuardrail}
	event := audit.BehaviorEvent{
		EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail,
		Outcome: "blocked", Attributes: map[string]any{"direction": "prompt"},
	}
	policy := NewPolicyEngine(store)
	for _, proof := range []any{nil, false} {
		event.Attributes["proxy_pre_upstream_blocked"] = proof
		status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "PROMPT_BLOCK", []audit.DetectionEvidence{{Event: event}}, true)
		if status != audit.ResponseStatusFailed || !strings.Contains(result, "no confirmed") {
			t.Fatalf("reported block without proxy receipt: %s %s", status, result)
		}
	}
	event.Attributes["proxy_pre_upstream_blocked"] = true
	status, _, result := policy.ExecuteNonProxy(context.Background(), decision, "PROMPT_BLOCK", []audit.DetectionEvidence{{Event: event}}, true)
	if status != audit.ResponseStatusExecuted || !strings.Contains(result, "no-upstream") {
		t.Fatalf("confirmed proxy block result: %s %s", status, result)
	}
}

func TestGuardrailExecutorRejectsReportedAndPostCallBlocks(t *testing.T) {
	store := newDetectionTestStore(t)
	detection, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{DetectionType: "prompt_injection"})
	if err != nil {
		t.Fatal(err)
	}
	decision := audit.RuntimeDecision{DecisionID: "D-prompt", DetectionID: detection.DetectionID, EnforcementPoint: audit.EnforcementPointGuardrail}
	for _, ev := range []audit.BehaviorEvent{
		{EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceAgentHook, Outcome: "blocked", Attributes: map[string]any{"direction": "prompt", "proxy_pre_upstream_blocked": true}},
		{EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail, Outcome: "blocked", Attributes: map[string]any{"direction": "completion", "proxy_pre_upstream_blocked": true}},
	} {
		status, _, _ := NewPolicyEngine(store).ExecuteNonProxy(context.Background(), decision, "PROMPT_BLOCK", []audit.DetectionEvidence{{Event: ev}}, true)
		if status != audit.ResponseStatusFailed {
			t.Fatalf("untrusted or post-call event reported success: %+v", ev)
		}
	}
}
