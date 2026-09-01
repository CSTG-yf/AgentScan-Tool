// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

func TestListRuntimeDecisionsJoinsDetectionMetadata(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	seenAt := time.Now().UTC().Add(-time.Minute)
	detection, err := store.RecordRuntimeDetection(RuntimeDetectionInput{
		AgentID:       "agent-runtime-test",
		AgentName:     "Runtime Test Agent",
		SessionID:     "session-runtime-test",
		TraceID:       "trace-runtime-test",
		DetectionType: "prompt_injection",
		Category:      "attack",
		Severity:      "HIGH",
		Confidence:    0.91,
		RuleID:        "RT-001",
		Title:         "Prompt injection detected",
		SeenAt:        seenAt,
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDetection: %v", err)
	}

	decision, recorded, err := store.RecordRuntimeDecision(RuntimeDecisionInput{
		DetectionID:      detection.DetectionID,
		AgentID:          detection.AgentID,
		AgentName:        detection.AgentName,
		SessionID:        detection.SessionID,
		TraceID:          detection.TraceID,
		Decision:         RuntimeDecisionBlock,
		RiskScore:        0.94,
		Confidence:       0.93,
		PolicyID:         "policy-runtime-test",
		Reason:           "high risk",
		EnforcementPoint: EnforcementPointAgentHook,
		Mode:             RuntimeSecurityModeAction,
		WouldBlock:       true,
		CreatedAt:        seenAt.Add(time.Second),
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDecision: %v", err)
	}
	if !recorded || decision.DecisionID == "" {
		t.Fatalf("expected a recorded decision, got recorded=%v decision=%+v", recorded, decision)
	}

	decisions, detections, err := store.ListRuntimeDecisions(RuntimeDecisionFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeDecisions: %v", err)
	}
	if len(decisions) != 1 || len(detections) != 1 {
		t.Fatalf("expected one decision and detection, got %d and %d", len(decisions), len(detections))
	}
	if decisions[0].DecisionID != decision.DecisionID || decisions[0].DetectionID != detection.DetectionID {
		t.Fatalf("decision join = %+v, want decision=%s detection=%s", decisions[0], decision.DecisionID, detection.DetectionID)
	}
	joined := detections[0]
	if joined.DetectionID != detection.DetectionID || joined.DetectionType != detection.DetectionType || joined.Category != detection.Category || joined.Title != detection.Title {
		t.Fatalf("joined detection = %+v, want %+v", joined, detection)
	}
	if joined.Confidence != detection.Confidence || joined.EventCount != detection.EventCount {
		t.Fatalf("joined detection metrics = confidence=%v events=%d, want confidence=%v events=%d", joined.Confidence, joined.EventCount, detection.Confidence, detection.EventCount)
	}
}
