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

func TestRuntimeDetectionAndAttackChainFilterByAgentType(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	const agentTypeID = int64(701)
	if _, err := store.db.Exec(`
INSERT INTO agent_types (id, type_key, name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)`, agentTypeID, "test-agent-type", "Test Agent Type", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert agent type: %v", err)
	}
	if _, err := store.EnsureAgent(AgentIdentityInput{
		AgentID: "typed-runtime-agent", AgentTypeID: agentTypeID,
		AgentName: "Typed Runtime Agent", ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	detection, err := store.RecordRuntimeDetection(RuntimeDetectionInput{
		AgentID: "typed-runtime-agent", AgentName: "Typed Runtime Agent",
		DetectionType: "type_filter_test", Category: "attack", Severity: "HIGH",
		RuleID: "type-filter-rule", Title: "type filter", SeenAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDetection: %v", err)
	}

	detections, err := store.ListRuntimeDetections(RuntimeDetectionFilter{AgentTypeID: agentTypeID, Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeDetections by type: %v", err)
	}
	if len(detections) != 1 || detections[0].AgentTypeID != agentTypeID || detections[0].AgentTypeName != "Test Agent Type" {
		t.Fatalf("detection type projection = %+v", detections)
	}

	chain, err := store.UpsertRuntimeAttackChain(RuntimeAttackChain{
		AgentID: "typed-runtime-agent", AgentName: "Typed Runtime Agent",
		AttackType: "type_filter_test", Severity: "HIGH", Status: AttackChainStatusActive,
		StartTime: time.Now().UTC(), EndTime: time.Now().UTC(), DetectionID: detection.DetectionID,
	}, nil)
	if err != nil {
		t.Fatalf("UpsertRuntimeAttackChain: %v", err)
	}
	chains, err := store.ListRuntimeAttackChains(AttackChainFilter{AgentTypeID: agentTypeID, Keyword: chain.AttackChainID, Sort: "time_asc", Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeAttackChains by type: %v", err)
	}
	if len(chains) != 1 || chains[0].AgentTypeID != agentTypeID || chains[0].AgentTypeName != "Test Agent Type" {
		t.Fatalf("chain type projection = %+v", chains)
	}
}
