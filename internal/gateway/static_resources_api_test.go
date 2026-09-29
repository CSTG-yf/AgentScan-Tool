// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestStaticResourceListUsesServerPaginationAndFilteredTotal(t *testing.T) {
	api, agentID := newStaticResourcesAPITest(t)
	now := time.Now().UTC()
	if _, err := api.store.EnsureStaticResource(audit.StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "config",
		Name:             "old-config",
		Target:           filepath.Join(t.TempDir(), "old", "config.yaml"),
		Source:           "test",
		ObservedAt:       now.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("EnsureStaticResource: %v", err)
	}

	request := func(rawQuery string) (*httptest.ResponseRecorder, audit.StaticResourcePage) {
		t.Helper()
		recorder := httptest.NewRecorder()
		api.handleStaticResourcesAPI(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/static-resources?"+rawQuery, nil))
		var page audit.StaticResourcePage
		if recorder.Code == http.StatusOK {
			if err := json.Unmarshal(recorder.Body.Bytes(), &page); err != nil {
				t.Fatalf("decode list response: %v", err)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
				t.Fatalf("decode list envelope: %v", err)
			}
			if _, ok := envelope["pageSize"]; !ok {
				t.Fatalf("list response does not contain pageSize: %s", recorder.Body.String())
			}
		}
		return recorder, page
	}
	defaults, defaultPage := request("agent_id=" + url.QueryEscape(agentID))
	if defaults.Code != http.StatusOK || defaultPage.Page != 1 || defaultPage.PageSize != 20 || defaultPage.Total != 2 {
		t.Fatalf("default page = status %d, %+v", defaults.Code, defaultPage)
	}

	first, firstPage := request("agent_id=" + url.QueryEscape(agentID) + "&page=1&page_size=1")
	if first.Code != http.StatusOK || firstPage.Total != 2 || firstPage.Page != 1 || firstPage.PageSize != 1 || len(firstPage.Items) != 1 {
		t.Fatalf("first page = status %d, %+v", first.Code, firstPage)
	}
	second, secondPage := request("agent_id=" + url.QueryEscape(agentID) + "&page=2&page_size=1")
	if second.Code != http.StatusOK || secondPage.Total != 2 || secondPage.Page != 2 || secondPage.PageSize != 1 || len(secondPage.Items) != 1 {
		t.Fatalf("second page = status %d, %+v", second.Code, secondPage)
	}
	if firstPage.Items[0].ID == secondPage.Items[0].ID {
		t.Fatalf("page 1 and page 2 returned the same resource %q", firstPage.Items[0].ID)
	}
	typeFiltered, typePage := request("agent_id=" + url.QueryEscape(agentID) + "&resource_type=config")
	if typeFiltered.Code != http.StatusOK || typePage.Total != 1 || len(typePage.Items) != 1 || typePage.Items[0].Name != "old-config" {
		t.Fatalf("type-filtered page = status %d, %+v", typeFiltered.Code, typePage)
	}

	filtered, filteredPage := request("agent_id=" + url.QueryEscape(agentID) + "&end_time=" + url.QueryEscape(now.Add(-time.Hour).Format(time.RFC3339)))
	if filtered.Code != http.StatusOK || filteredPage.Total != 1 || len(filteredPage.Items) != 1 || filteredPage.Items[0].Name != "old-config" {
		t.Fatalf("time-filtered page = status %d, %+v", filtered.Code, filteredPage)
	}

	for _, rawQuery := range []string{
		"page=0",
		"page=100001",
		"page_size=-1",
		"page=not-a-number",
		"start_time=invalid",
		"start_time=2026-01-02T00%3A00%3A00Z&end_time=2026-01-01T00%3A00%3A00Z",
	} {
		recorder, _ := request(rawQuery)
		if recorder.Code != http.StatusBadRequest {
			t.Errorf("query %q status = %d, want %d", rawQuery, recorder.Code, http.StatusBadRequest)
		}
	}
	_, capped := request("page_size=999")
	if capped.PageSize != 200 {
		t.Fatalf("capped pageSize = %d, want 200", capped.PageSize)
	}
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
