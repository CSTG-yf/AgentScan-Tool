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
		category := "attack"
		if item.detectionType == "dynamic_custom" {
			category = "suspicious"
		}
		detection, err := store.RecordRuntimeDetection(RuntimeDetectionInput{
			AgentID: item.agentID, AgentName: item.agentName, DetectionType: item.detectionType,
			Category: category, Severity: item.severity, RuleID: "summary-" + item.detectionType,
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
	if codexEvents.AttackEvents != 1 || codexEvents.OpenEvents != 2 {
		t.Fatalf("full attack/open counts: %+v", codexEvents)
	}
	if filtered, err := store.ListRuntimeDetectionAgentTypeSummaries(RuntimeDetectionFilter{AgentTypeID: codexTypeID, Limit: 1, Offset: 100}); err != nil {
		t.Fatal(err)
	} else if len(filtered) != 1 || filtered[0].TotalEvents != 2 || filtered[0].AttackEvents != 1 {
		t.Fatalf("summary incorrectly paginated: %+v", filtered)
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
	if codexChains.CoveredAgents != 1 || len(codexChains.Agents) != 1 || codexChains.Agents[0].TotalChains != 2 || codexChains.Agents[0].HighOrAbove != 1 {
		t.Fatalf("one instance across multiple risk/status buckets was counted incorrectly: %+v", codexChains)
	}
	if filtered, err := store.ListRuntimeAttackChainAgentTypeSummaries(AttackChainFilter{AgentTypeID: claudeTypeID}); err != nil {
		t.Fatalf("filtered chain summary: %v", err)
	} else if len(filtered) != 1 || filtered[0].AgentTypeID != claudeTypeID || filtered[0].TotalChains != 1 {
		t.Fatalf("filtered chain summary = %+v", filtered)
	}
	// Display names are not identities. A second instance of the same type
	// and name must contribute its own sidebar entry and covered-agent count.
	if _, err := store.EnsureAgent(AgentIdentityInput{AgentID: "summary-third-agent", AgentTypeID: codexTypeID, AgentName: "Summary One Agent", ObservedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertRuntimeAttackChain(RuntimeAttackChain{
		AgentID: "summary-third-agent", AgentName: "Summary One Agent", AttackType: "another-chain",
		Severity: "HIGH", Status: AttackChainStatusActive, StartTime: now, EndTime: now,
	}, nil); err != nil {
		t.Fatal(err)
	}
	filtered, err := store.ListRuntimeAttackChainAgentTypeSummaries(AttackChainFilter{AgentTypeID: codexTypeID, Severity: "HIGH", Limit: 1, Offset: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 || filtered[0].TotalChains != 2 || filtered[0].CoveredAgents != 2 || len(filtered[0].Agents) != 2 {
		t.Fatalf("filtered instance counts must ignore pagination: %+v", filtered)
	}
	for _, agent := range filtered[0].Agents {
		if agent.TotalChains != 1 || agent.HighOrAbove != 1 {
			t.Fatalf("filtered sidebar count: %+v", agent)
		}
	}
	filtered, err = store.ListRuntimeAttackChainAgentTypeSummaries(AttackChainFilter{AgentTypeID: claudeTypeID, AgentID: "summary-third-agent"})
	if err != nil || len(filtered) != 0 {
		t.Fatalf("instance/type filters must intersect: %+v, %v", filtered, err)
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
