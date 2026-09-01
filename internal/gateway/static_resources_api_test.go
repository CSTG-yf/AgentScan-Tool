// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

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

func newStaticResourcesAPITest(t *testing.T) (*APIServer, string) {
	t.Helper()

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	agent, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:    "codex",
		AgentName:  "Codex CLI",
		Kind:       "terminal-agent",
		Source:     "test",
		ObservedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	if _, err := store.EnsureStaticResource(audit.StaticResourceInput{
		CanonicalAgentID: agent.ID,
		ResourceType:     "skill",
		Name:             "review",
		Target:           filepath.Join(t.TempDir(), "skills", "review"),
		Source:           "test",
		ObservedAt:       time.Now().UTC(),
		MaxSeverity:      "high",
		FindingCount:     1,
	}); err != nil {
		t.Fatalf("EnsureStaticResource: %v", err)
	}

	return &APIServer{store: store}, agent.ID
}

func TestStaticResourcesAPIRoutesReservedCollectionEndpoints(t *testing.T) {
	api, agentID := newStaticResourcesAPITest(t)

	agentsRec := httptest.NewRecorder()
	api.handleStaticResourcesAPI(
		agentsRec,
		httptest.NewRequest(http.MethodGet, "/api/v1/static-resources/agents", nil),
	)
	if agentsRec.Code != http.StatusOK {
		t.Fatalf("agents status = %d body = %s", agentsRec.Code, agentsRec.Body.String())
	}
	var agentsResp struct {
		Items []audit.AgentResourceSummary `json:"items"`
	}
	if err := json.NewDecoder(agentsRec.Body).Decode(&agentsResp); err != nil {
		t.Fatalf("decode agents response: %v", err)
	}
	if len(agentsResp.Items) != 1 || agentsResp.Items[0].AgentID != agentID || agentsResp.Items[0].ResourceCount != 1 {
		t.Fatalf("agents response = %+v, want one summary for %s", agentsResp, agentID)
	}

	summaryRec := httptest.NewRecorder()
	api.handleStaticResourcesAPI(
		summaryRec,
		httptest.NewRequest(http.MethodGet, "/api/v1/static-resources/summary?agent_id="+agentID, nil),
	)
	if summaryRec.Code != http.StatusOK {
		t.Fatalf("summary status = %d body = %s", summaryRec.Code, summaryRec.Body.String())
	}
	var summary audit.AgentResourceTypeSummary
	if err := json.NewDecoder(summaryRec.Body).Decode(&summary); err != nil {
		t.Fatalf("decode summary response: %v", err)
	}
	if summary.Agent.AgentID != agentID || summary.TotalResources != 1 || len(summary.ByType) != 1 || summary.ByType[0].ResourceType != "skill" {
		t.Fatalf("summary response = %+v, want one skill resource for %s", summary, agentID)
	}
}
