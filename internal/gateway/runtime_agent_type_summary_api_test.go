package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestRuntimeAgentTypeSummaryAPIs(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	created, err := store.CreateGovernanceAgentType(audit.GovernanceAgentTypeInput{
		TypeKey: "api-summary-codex", Name: "API Summary Codex", Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateGovernanceAgentType: %v", err)
	}
	if _, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID: "api-summary-agent", AgentTypeID: created.ID, AgentName: "API Summary Agent", ObservedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	first, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		AgentID: "api-summary-agent", AgentName: "API Summary Agent", DetectionType: "api-summary-high",
		Category: "attack", Severity: "HIGH", RuleID: "api-summary-high", Title: "high", SeenAt: now,
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDetection high: %v", err)
	}
	second, err := store.RecordRuntimeDetection(audit.RuntimeDetectionInput{
		AgentID: "api-summary-agent", AgentName: "API Summary Agent", DetectionType: "api-summary-custom",
		Category: "attack", Severity: "custom-risk", RuleID: "api-summary-custom", Title: "custom", SeenAt: now,
	})
	if err != nil {
		t.Fatalf("RecordRuntimeDetection custom: %v", err)
	}
	for i, detection := range []audit.RuntimeDetection{first, second} {
		status := audit.AttackChainStatusActive
		if i == 1 {
			status = audit.AttackChainStatusContained
		}
		if _, err := store.UpsertRuntimeAttackChain(audit.RuntimeAttackChain{
			AgentID: "api-summary-agent", AgentName: "API Summary Agent", AttackType: detection.DetectionType,
			Severity: detection.Severity, Status: status, StartTime: now, EndTime: now.Add(time.Second), DetectionID: detection.DetectionID,
		}, nil); err != nil {
			t.Fatalf("UpsertRuntimeAttackChain: %v", err)
		}
	}

	api := &APIServer{store: store}
	var eventResponse struct {
		Items []audit.RuntimeDetectionAgentTypeSummary `json:"items"`
		Total int                                      `json:"total"`
	}
	rec := httptest.NewRecorder()
	api.handleRuntimeDetections(rec, httptest.NewRequest(http.MethodGet, "/api/v1/runtime-detections/summary/agent-types?category=attack", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("event summary status = %d body = %s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&eventResponse); err != nil {
		t.Fatalf("decode event summary: %v", err)
	}
	if eventResponse.Total != 1 || len(eventResponse.Items) != 1 {
		t.Fatalf("event summary = %+v, want one AgentType", eventResponse)
	}
	eventItem := eventResponse.Items[0]
	if eventItem.AgentTypeID != created.ID || eventItem.AgentType != "api-summary-codex" || eventItem.TotalEvents != 2 {
		t.Fatalf("event summary item = %+v", eventItem)
	}
	if eventItem.RiskCounts["high"] != 1 || eventItem.RiskCounts["custom-risk"] != 1 {
		t.Fatalf("event risk counts = %+v", eventItem.RiskCounts)
	}

	// The runtime-security namespace and group_by query are compatibility
	// aliases for the same grouped endpoint.
	var groupedResponse struct {
		Items []audit.RuntimeDetectionAgentTypeSummary `json:"items"`
	}
	grouped := httptest.NewRecorder()
	api.handleRuntimeSecuritySummary(grouped, httptest.NewRequest(http.MethodGet, "/api/v1/runtime-security/summary?group_by=agent_type", nil))
	if grouped.Code != http.StatusOK {
		t.Fatalf("runtime-security grouped status = %d body = %s", grouped.Code, grouped.Body.String())
	}
	if err := json.NewDecoder(grouped.Body).Decode(&groupedResponse); err != nil {
		t.Fatalf("decode runtime-security grouped response: %v", err)
	}
	if len(groupedResponse.Items) != 1 || groupedResponse.Items[0].TotalEvents != 2 {
		t.Fatalf("runtime-security grouped response = %+v", groupedResponse)
	}

	var chainResponse struct {
		Items []audit.RuntimeAttackChainAgentTypeSummary `json:"items"`
		Total int                                        `json:"total"`
	}
	chainRec := httptest.NewRecorder()
	api.handleAttackChains(chainRec, httptest.NewRequest(http.MethodGet, "/api/v1/attack-chains/summary/agent-types", nil))
	if chainRec.Code != http.StatusOK {
		t.Fatalf("chain summary status = %d body = %s", chainRec.Code, chainRec.Body.String())
	}
	if err := json.NewDecoder(chainRec.Body).Decode(&chainResponse); err != nil {
		t.Fatalf("decode chain summary: %v", err)
	}
	if chainResponse.Total != 1 || len(chainResponse.Items) != 1 || chainResponse.Items[0].TotalChains != 2 {
		t.Fatalf("chain summary = %+v, want one AgentType with two chains", chainResponse)
	}
	chainItem := chainResponse.Items[0]
	if chainItem.StatusCounts[audit.AttackChainStatusActive] != 1 || chainItem.StatusCounts[audit.AttackChainStatusContained] != 1 {
		t.Fatalf("chain status counts = %+v", chainItem.StatusCounts)
	}

	filtered := httptest.NewRecorder()
	api.handleRuntimeDetectionAgentTypeSummary(filtered, httptest.NewRequest(http.MethodGet, "/api/v1/runtime-detections/summary/agent-types?agent_type=api-summary-codex", nil))
	if filtered.Code != http.StatusOK {
		t.Fatalf("filtered event summary status = %d body = %s", filtered.Code, filtered.Body.String())
	}
	var filteredResponse struct {
		Items []audit.RuntimeDetectionAgentTypeSummary `json:"items"`
	}
	if err := json.NewDecoder(filtered.Body).Decode(&filteredResponse); err != nil {
		t.Fatalf("decode filtered event summary: %v", err)
	}
	if len(filteredResponse.Items) != 1 || filteredResponse.Items[0].AgentTypeID != created.ID {
		t.Fatalf("filtered event summary = %+v", filteredResponse)
	}
}
