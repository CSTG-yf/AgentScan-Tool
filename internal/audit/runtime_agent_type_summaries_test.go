package audit

import (
	"testing"
	"time"
)

func TestRuntimeAgentTypeSummariesAggregateDynamicValues(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	now := time.Now().UTC().Add(-time.Minute)
	const (
		codexTypeID  = int64(801)
		claudeTypeID = int64(802)
	)
	for _, item := range []struct {
		id   int64
		key  string
		name string
	}{
		{codexTypeID, "summary-codex", "Summary Codex"},
		{claudeTypeID, "summary-claude", "Summary Claude"},
	} {
		if _, err := store.db.Exec(`
INSERT INTO agent_types (id, type_key, name, created_at, updated_at)
VALUES (?, ?, ?, ?, ?)`, item.id, item.key, item.name, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("insert agent type %d: %v", item.id, err)
		}
	}
	for _, item := range []struct {
		id     string
		typeID int64
		name   string
	}{
		{"summary-one-agent", codexTypeID, "Summary One Agent"},
		{"summary-two-agent", claudeTypeID, "Summary Two Agent"},
	} {
		if _, err := store.EnsureAgent(AgentIdentityInput{
			AgentID: item.id, AgentTypeID: item.typeID, AgentName: item.name, ObservedAt: now,
		}); err != nil {
			t.Fatalf("EnsureAgent %s: %v", item.id, err)
		}
	}

	detections := make([]RuntimeDetection, 0, 3)
	for _, item := range []struct {
		agentID, agentName, detectionType, severity string
		typeID                                      int64
	}{
		{"summary-one-agent", "Summary One Agent", "dynamic_high", "HIGH", codexTypeID},
		{"summary-one-agent", "Summary One Agent", "dynamic_custom", "vendor-specific", codexTypeID},
		{"summary-two-agent", "Summary Two Agent", "dynamic_low", "LOW", claudeTypeID},
	} {
		detection, err := store.RecordRuntimeDetection(RuntimeDetectionInput{
			AgentID: item.agentID, AgentName: item.agentName, DetectionType: item.detectionType,
			Category: "attack", Severity: item.severity, RuleID: "summary-" + item.detectionType,
			Title: item.detectionType, SeenAt: now,
		})
		if err != nil {
			t.Fatalf("RecordRuntimeDetection %s: %v", item.detectionType, err)
		}
		if detection.DetectionID == "" {
			t.Fatalf("RecordRuntimeDetection %s returned empty id", item.detectionType)
		}
		detections = append(detections, detection)
		_ = item.typeID // documents the intended AgentType binding in the fixture
	}

	eventSummary, err := store.ListRuntimeDetectionAgentTypeSummaries(RuntimeDetectionFilter{})
	if err != nil {
		t.Fatalf("ListRuntimeDetectionAgentTypeSummaries: %v", err)
	}
	if len(eventSummary) != 2 {
		t.Fatalf("event summary len = %d, want 2: %+v", len(eventSummary), eventSummary)
	}
	codexEvents := findRuntimeDetectionAgentTypeSummary(eventSummary, codexTypeID)
	if codexEvents == nil {
		t.Fatalf("missing codex event summary: %+v", eventSummary)
	}
	if codexEvents.AgentType != "summary-codex" || codexEvents.AgentTypeKey != "summary-codex" || codexEvents.AgentTypeName != "Summary Codex" {
		t.Fatalf("codex type projection = %+v", codexEvents)
	}
	if codexEvents.TotalEvents != 2 || codexEvents.RiskCounts["high"] != 1 || codexEvents.RiskCounts["vendor-specific"] != 1 {
		t.Fatalf("codex event aggregate = %+v, want 2 events with dynamic risk keys", codexEvents)
	}
	if _, ok := codexEvents.RiskCounts["critical"]; ok {
		t.Fatalf("event risk counts unexpectedly contains hardcoded critical bucket: %+v", codexEvents.RiskCounts)
	}
	if filtered, err := store.ListRuntimeDetectionAgentTypeSummaries(RuntimeDetectionFilter{AgentTypeID: claudeTypeID}); err != nil {
		t.Fatalf("filtered event summary: %v", err)
	} else if len(filtered) != 1 || filtered[0].AgentTypeID != claudeTypeID || filtered[0].TotalEvents != 1 {
		t.Fatalf("filtered event summary = %+v", filtered)
	}

	for i, item := range detections {
		status := AttackChainStatusActive
		if i == 1 {
			status = AttackChainStatusContained
		}
		if _, err := store.UpsertRuntimeAttackChain(RuntimeAttackChain{
			AgentID: item.AgentID, AgentName: item.AgentName, AttackType: item.DetectionType,
			Severity: item.Severity, Status: status, StartTime: now.Add(time.Duration(i) * time.Second),
			EndTime: now.Add(time.Duration(i+1) * time.Second), DetectionID: item.DetectionID,
		}, nil); err != nil {
			t.Fatalf("UpsertRuntimeAttackChain %s: %v", item.DetectionType, err)
		}
	}

	chainSummary, err := store.ListRuntimeAttackChainAgentTypeSummaries(AttackChainFilter{})
	if err != nil {
		t.Fatalf("ListRuntimeAttackChainAgentTypeSummaries: %v", err)
	}
	if len(chainSummary) != 2 {
		t.Fatalf("chain summary len = %d, want 2: %+v", len(chainSummary), chainSummary)
	}
	codexChains := findRuntimeAttackChainAgentTypeSummary(chainSummary, codexTypeID)
	if codexChains == nil {
		t.Fatalf("missing codex chain summary: %+v", chainSummary)
	}
	if codexChains.TotalChains != 2 || codexChains.StatusCounts[AttackChainStatusActive] != 1 || codexChains.StatusCounts[AttackChainStatusContained] != 1 {
		t.Fatalf("codex chain aggregate = %+v", codexChains)
	}
	if codexChains.SeverityCounts["vendor-specific"] != 1 || codexChains.SeverityCounts["high"] != 1 {
		t.Fatalf("codex chain dynamic severity aggregate = %+v", codexChains.SeverityCounts)
	}
	if filtered, err := store.ListRuntimeAttackChainAgentTypeSummaries(AttackChainFilter{AgentTypeID: claudeTypeID}); err != nil {
		t.Fatalf("filtered chain summary: %v", err)
	} else if len(filtered) != 1 || filtered[0].AgentTypeID != claudeTypeID || filtered[0].TotalChains != 1 {
		t.Fatalf("filtered chain summary = %+v", filtered)
	}
}

func findRuntimeDetectionAgentTypeSummary(items []RuntimeDetectionAgentTypeSummary, id int64) *RuntimeDetectionAgentTypeSummary {
	for i := range items {
		if items[i].AgentTypeID == id {
			return &items[i]
		}
	}
	return nil
}

func findRuntimeAttackChainAgentTypeSummary(items []RuntimeAttackChainAgentTypeSummary, id int64) *RuntimeAttackChainAgentTypeSummary {
	for i := range items {
		if items[i].AgentTypeID == id {
			return &items[i]
		}
	}
	return nil
}
