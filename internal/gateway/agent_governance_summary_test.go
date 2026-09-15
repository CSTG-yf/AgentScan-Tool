package gateway

import (
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
)

func TestAgentGovernanceSummary(t *testing.T) {
	api := newAgentGovernanceAPITest(t)
	read := func() map[string]int {
		t.Helper()
		// List filters and pagination must not change global header counts.
		rec := agentGovernanceRequest(t, api, http.MethodGet, agentGovernancePrefix+"/summary?keyword=nonexistent&page_size=1&enabled=true", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("summary: %d %s", rec.Code, rec.Body.String())
		}
		var counts map[string]int
		if err := json.Unmarshal(rec.Body.Bytes(), &counts); err != nil {
			t.Fatal(err)
		}
		if len(counts) != 11 {
			t.Fatalf("expected eleven counts covering all tabs, got %v", counts)
		}
		return counts
	}
	before := read()
	for field, endpoints := range map[string][]string{
		"decision_profile_count": {"pre-scan-profiles", "post-scan-profiles"},
		"risk_rule_count":        {"risk-severity-mappings", "risk-rule-prefix-matches", "risk-category-matches"},
	} {
		total := 0
		for _, endpoint := range endpoints {
			rec := agentGovernanceRequest(t, api, http.MethodGet, agentGovernancePrefix+"/"+endpoint+"?page_size=1", nil)
			var page struct {
				Total int `json:"total"`
			}
			if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
				t.Fatalf("list %s: %s", endpoint, rec.Body.String())
			}
			total += page.Total
		}
		if before[field] != total {
			t.Fatalf("%s = %d, want %d", field, before[field], total)
		}
	}
	schedules, err := api.store.ListScanSchedules()
	if err != nil {
		t.Fatal(err)
	}
	if before["scan_schedule_count"] != len(schedules) || before["page_refresh_policy_count"] != 8 {
		t.Fatalf("scan/refresh policy counts: %v", before)
	}
	for _, field := range []string{"runtime_rule_count", "runtime_blacklist_count", "runtime_risk_policy_count"} {
		if value, ok := before[field]; !ok || value < 0 {
			t.Fatalf("invalid %s: %v", field, before)
		}
	}
	globalRules, err := api.store.ListRuntimeDetectionRules(0)
	if err != nil {
		t.Fatal(err)
	}
	types, err := api.store.ListRuntimeDetectionAgentTypes()
	if err != nil {
		t.Fatal(err)
	}
	ruleCount, blacklistCount := len(globalRules), 0
	for _, item := range types {
		ruleCount += item.SpecificRuleCount
		blacklistCount += item.BlacklistCount
	}
	if before["runtime_rule_count"] != ruleCount || before["runtime_blacklist_count"] != blacklistCount {
		t.Fatalf("runtime counts differ from configuration lists: %v", before)
	}
	for field, endpoint := range map[string]string{
		"agent_type_count": "agent-types", "discovery_rule_count": "discovery-rules",
		"resource_rule_count": "resource-rules", "scan_profile_count": "scan-profiles",
	} {
		rec := agentGovernanceRequest(t, api, http.MethodGet, agentGovernancePrefix+"/"+endpoint+"?page_size=1", nil)
		var page struct {
			Total int `json:"total"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Fatalf("list %s: %d %s", endpoint, rec.Code, rec.Body.String())
		}
		if count, ok := before[field]; !ok || count != page.Total {
			t.Fatalf("%s = %d, list total = %d", field, count, page.Total)
		}
	}
	created := agentGovernanceRequest(t, api, http.MethodPost, agentGovernancePrefix+"/agent-types", map[string]any{
		"type_key": "summary-disabled", "name": "Summary disabled type", "kind": "cli", "runtime": "node", "enabled": false,
	})
	var row struct {
		ID int64 `json:"id"`
	}
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &row) != nil {
		t.Fatalf("create disabled type: %d %s", created.Code, created.Body.String())
	}
	if got := read()["agent_type_count"]; got != before["agent_type_count"]+1 {
		t.Fatalf("disabled entry missing: got %d", got)
	}
	deleted := agentGovernanceRequest(t, api, http.MethodDelete, agentGovernancePrefix+"/agent-types/"+strconv.FormatInt(row.ID, 10), nil)
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete: %s", deleted.Body.String())
	}
	if got := read()["agent_type_count"]; got != before["agent_type_count"] {
		t.Fatalf("deleted entry counted: got %d", got)
	}
	if rec := agentGovernanceRequest(t, api, http.MethodPost, agentGovernancePrefix+"/summary", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST should return 405, got %d", rec.Code)
	}
	if rec := agentGovernanceRequest(t, api, http.MethodGet, agentGovernancePrefix+"/summary/invalid", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("invalid subpath should return 404, got %d", rec.Code)
	}
}
