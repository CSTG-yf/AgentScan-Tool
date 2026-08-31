// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func newAgentGovernanceAPITest(t *testing.T) *APIServer {
	t.Helper()

	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return &APIServer{store: store, logger: audit.NewLogger(store)}
}

func agentGovernanceRequest(t *testing.T, api *APIServer, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		reader = bytes.NewReader(payload)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	api.handleAgentGovernanceAPI(rec, req)
	return rec
}

func TestAgentGovernanceAgentTypeCRUD(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	createRec := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/agent-types", map[string]any{
		"type_key":    "test-agent-type",
		"name":        "Test Agent Type",
		"vendor":      "Test Vendor",
		"kind":        "cli",
		"runtime":     "go",
		"description": "created by gateway test",
		"enabled":     true,
	})
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", createRec.Code, createRec.Body.String())
	}
	var created audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(createRec.Body).Decode(&created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.ID == 0 || created.TypeKey != "test-agent-type" || !created.Enabled {
		t.Fatalf("created row = %+v", created)
	}

	listRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/agent-types?keyword=test-agent-type", nil)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRec.Code, listRec.Body.String())
	}
	var page audit.GovernanceAgentTypePage
	if err := json.NewDecoder(listRec.Body).Decode(&page); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("list page = %+v, want created row", page)
	}

	idPath := strconv.FormatInt(created.ID, 10)
	updateRec := agentGovernanceRequest(t, api, http.MethodPatch, "/api/v1/agent-governance/agent-types/"+idPath, map[string]any{
		"name":    "Updated Test Agent Type",
		"runtime": "node",
	})
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d body = %s", updateRec.Code, updateRec.Body.String())
	}
	var updated audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(updateRec.Body).Decode(&updated); err != nil {
		t.Fatalf("decode update response: %v", err)
	}
	if updated.Name != "Updated Test Agent Type" || updated.Runtime != "node" {
		t.Fatalf("updated row = %+v", updated)
	}

	deleteRec := agentGovernanceRequest(t, api, http.MethodDelete, "/api/v1/agent-governance/agent-types/"+idPath, nil)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d body = %s", deleteRec.Code, deleteRec.Body.String())
	}
	var disabled audit.GovernanceAgentTypeRow
	if err := json.NewDecoder(deleteRec.Body).Decode(&disabled); err != nil {
		t.Fatalf("decode delete response: %v", err)
	}
	if !disabled.Deleted {
		t.Fatalf("delete should mark row deleted, got %+v", disabled)
	}

	listAfterDeleteRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/agent-types?keyword=test-agent-type", nil)
	if listAfterDeleteRec.Code != http.StatusOK {
		t.Fatalf("list after delete status = %d body = %s", listAfterDeleteRec.Code, listAfterDeleteRec.Body.String())
	}
	var afterDelete audit.GovernanceAgentTypePage
	if err := json.NewDecoder(listAfterDeleteRec.Body).Decode(&afterDelete); err != nil {
		t.Fatalf("decode list after delete response: %v", err)
	}
	if afterDelete.Total != 0 || len(afterDelete.Items) != 0 {
		t.Fatalf("deleted row should be hidden from list, got %+v", afterDelete)
	}
}

func TestAgentGovernanceReadEndpointsSmoke(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	for _, path := range []string{
		"/api/v1/agent-governance",
		"/api/v1/agent-governance/agent-types",
		"/api/v1/agent-governance/discovery-rules",
		"/api/v1/agent-governance/resource-rules",
		"/api/v1/agent-governance/scan-profiles",
		"/api/v1/agent-governance/scan-capabilities",
		"/api/v1/agent-governance/resource-actions",
		"/api/v1/agent-governance/pre-scan-profiles",
		"/api/v1/agent-governance/post-scan-profiles",
		"/api/v1/agent-governance/risk-severity-mappings",
		"/api/v1/agent-governance/risk-rule-prefix-matches",
		"/api/v1/agent-governance/risk-category-matches",
		"/api/v1/agent-governance/admission-matrix",
		"/api/v1/agent-governance/risk-model",
	} {
		t.Run(path, func(t *testing.T) {
			rec := agentGovernanceRequest(t, api, http.MethodGet, path, nil)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body = %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAgentGovernanceRiskExplainEndpoints(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	severityRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/risk-severity-mappings?page=1&pageSize=2&keyword=high&risk_level=high&enabled=true", nil)
	if severityRec.Code != http.StatusOK {
		t.Fatalf("severity mapping status = %d body = %s", severityRec.Code, severityRec.Body.String())
	}
	var severityPage audit.GovernanceRiskSeverityMappingPage
	if err := json.NewDecoder(severityRec.Body).Decode(&severityPage); err != nil {
		t.Fatalf("decode severity mappings: %v", err)
	}
	if severityPage.Total != 1 || len(severityPage.Items) != 1 || severityPage.Items[0].RiskLevel != "high" {
		t.Fatalf("severity mappings = %+v", severityPage)
	}

	prefixRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/risk-rule-prefix-matches?keyword=CS-MAL&page_size=5", nil)
	if prefixRec.Code != http.StatusOK {
		t.Fatalf("prefix mapping status = %d body = %s", prefixRec.Code, prefixRec.Body.String())
	}
	var prefixPage audit.GovernanceRiskRulePrefixMatchPage
	if err := json.NewDecoder(prefixRec.Body).Decode(&prefixPage); err != nil {
		t.Fatalf("decode prefix mappings: %v", err)
	}
	if prefixPage.Total != 1 || prefixPage.Items[0].RuleIDPrefix != "CS-MAL-" {
		t.Fatalf("prefix mappings = %+v", prefixPage)
	}

	categoryRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/risk-category-matches?keyword=credential&page_size=20", nil)
	if categoryRec.Code != http.StatusOK {
		t.Fatalf("category mapping status = %d body = %s", categoryRec.Code, categoryRec.Body.String())
	}
	var categoryPage audit.GovernanceRiskCategoryMatchPage
	if err := json.NewDecoder(categoryRec.Body).Decode(&categoryPage); err != nil {
		t.Fatalf("decode category mappings: %v", err)
	}
	if categoryPage.Total < 2 {
		t.Fatalf("category mappings = %+v", categoryPage)
	}

	prefixEval := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/risk-explain/evaluate", map[string]any{
		"resource_type": "prompt",
		"severity":      "LOW",
		"rule_id":       "CS-MAL-001",
	})
	if prefixEval.Code != http.StatusOK {
		t.Fatalf("prefix evaluate status = %d body = %s", prefixEval.Code, prefixEval.Body.String())
	}
	var prefixResult audit.GovernanceRiskEvaluateResult
	if err := json.NewDecoder(prefixEval.Body).Decode(&prefixResult); err != nil {
		t.Fatalf("decode prefix evaluate: %v", err)
	}
	if prefixResult.RiskLevel != "critical" || prefixResult.MatchedType != "rule_id_prefix" {
		t.Fatalf("prefix result = %+v", prefixResult)
	}

	categoryEval := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/risk-explain/evaluate", map[string]any{
		"resource_type": "skill",
		"severity":      "LOW",
		"category":      "malware",
	})
	if categoryEval.Code != http.StatusOK {
		t.Fatalf("category evaluate status = %d body = %s", categoryEval.Code, categoryEval.Body.String())
	}
	var categoryResult audit.GovernanceRiskEvaluateResult
	if err := json.NewDecoder(categoryEval.Body).Decode(&categoryResult); err != nil {
		t.Fatalf("decode category evaluate: %v", err)
	}
	if categoryResult.RiskLevel != "critical" || categoryResult.MatchedType != "category" {
		t.Fatalf("category result = %+v", categoryResult)
	}

	severityEval := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/risk-explain/evaluate", map[string]any{
		"resource_type": "plugin",
		"severity":      "HIGH",
	})
	if severityEval.Code != http.StatusOK {
		t.Fatalf("severity evaluate status = %d body = %s", severityEval.Code, severityEval.Body.String())
	}
	var severityResult audit.GovernanceRiskEvaluateResult
	if err := json.NewDecoder(severityEval.Body).Decode(&severityResult); err != nil {
		t.Fatalf("decode severity evaluate: %v", err)
	}
	if severityResult.RiskLevel != "high" || severityResult.MatchedType != "severity" {
		t.Fatalf("severity result = %+v", severityResult)
	}
}

func TestAgentGovernanceDecisionProfileCRUD(t *testing.T) {
	api := newAgentGovernanceAPITest(t)

	var agentTypes audit.GovernanceAgentTypePage
	agentTypeRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/agent-types?page_size=1", nil)
	if agentTypeRec.Code != http.StatusOK {
		t.Fatalf("agent type list status = %d body = %s", agentTypeRec.Code, agentTypeRec.Body.String())
	}
	if err := json.NewDecoder(agentTypeRec.Body).Decode(&agentTypes); err != nil {
		t.Fatalf("decode agent types: %v", err)
	}
	if len(agentTypes.Items) == 0 {
		t.Fatal("expected seeded agent type")
	}
	agentTypeID := agentTypes.Items[0].ID

	preCreate := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/pre-scan-profiles", map[string]any{
		"profile_key": "pre-test",
		"name":        "Pre Test",
		"description": "pre profile test",
		"enabled":     true,
		"rules": []map[string]any{{
			"rule_name":      "scan all",
			"priority":       10,
			"agent_type_id":  agentTypeID,
			"resource_type":  "all",
			"decision":       "scan",
			"install_action": "none",
			"file_action":    "none",
			"runtime_action": "allow",
			"enabled":        true,
		}},
	})
	if preCreate.Code != http.StatusCreated {
		t.Fatalf("pre profile create status = %d body = %s", preCreate.Code, preCreate.Body.String())
	}
	var preProfile audit.GovernancePreScanProfileRow
	if err := json.NewDecoder(preCreate.Body).Decode(&preProfile); err != nil {
		t.Fatalf("decode pre profile: %v", err)
	}
	if preProfile.ID == 0 || preProfile.RuleCount != 1 {
		t.Fatalf("created pre profile = %+v", preProfile)
	}

	preRulesRec := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/pre-scan-profiles/"+strconv.FormatInt(preProfile.ID, 10)+"/rules", nil)
	if preRulesRec.Code != http.StatusOK {
		t.Fatalf("pre rule list status = %d body = %s", preRulesRec.Code, preRulesRec.Body.String())
	}
	var preRules audit.GovernancePreScanRulePage
	if err := json.NewDecoder(preRulesRec.Body).Decode(&preRules); err != nil {
		t.Fatalf("decode pre rules: %v", err)
	}
	if preRules.Total != 1 || len(preRules.Items) != 1 {
		t.Fatalf("pre rules = %+v", preRules)
	}

	postCreate := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/post-scan-profiles", map[string]any{
		"profile_key": "post-test",
		"name":        "Post Test",
		"description": "post profile test",
		"enabled":     true,
		"rules": []map[string]any{{
			"rule_name":        "high blocks",
			"priority":         10,
			"resource_type":    "all",
			"severity":         "HIGH",
			"risk_level":       "high",
			"malicious":        false,
			"finding_category": "prompt_injection",
			"decision":         "block",
			"install_action":   "block",
			"file_action":      "quarantine",
			"runtime_action":   "block",
			"enabled":          true,
		}},
	})
	if postCreate.Code != http.StatusCreated {
		t.Fatalf("post profile create status = %d body = %s", postCreate.Code, postCreate.Body.String())
	}
	var postProfile audit.GovernancePostScanProfileRow
	if err := json.NewDecoder(postCreate.Body).Decode(&postProfile); err != nil {
		t.Fatalf("decode post profile: %v", err)
	}
	if postProfile.ID == 0 || postProfile.RuleCount != 1 {
		t.Fatalf("created post profile = %+v", postProfile)
	}

	resourceRuleRec := agentGovernanceRequest(t, api, http.MethodPost, "/api/v1/agent-governance/resource-rules", map[string]any{
		"agent_type_id":        agentTypeID,
		"name":                 "decision-bound-rule",
		"resource_type":        "skill",
		"path_pattern":         "${CONFIG_ROOT}/decision-bound-rule",
		"enumeration_mode":     "exact",
		"scan_profile_id":      0,
		"pre_scan_profile_id":  preProfile.ID,
		"post_scan_profile_id": postProfile.ID,
		"enabled":              true,
		"priority":             100,
	})
	if resourceRuleRec.Code != http.StatusCreated {
		t.Fatalf("resource rule create status = %d body = %s", resourceRuleRec.Code, resourceRuleRec.Body.String())
	}
	var resourceRule audit.GovernanceResourceRuleRow
	if err := json.NewDecoder(resourceRuleRec.Body).Decode(&resourceRule); err != nil {
		t.Fatalf("decode resource rule: %v", err)
	}
	if resourceRule.PreScanProfileID != preProfile.ID || resourceRule.PostScanProfileID != postProfile.ID {
		t.Fatalf("resource rule decision profiles = %+v", resourceRule)
	}

	preDelete := agentGovernanceRequest(t, api, http.MethodDelete, "/api/v1/agent-governance/pre-scan-rules/"+strconv.FormatInt(preRules.Items[0].ID, 10), nil)
	if preDelete.Code != http.StatusOK {
		t.Fatalf("pre rule delete status = %d body = %s", preDelete.Code, preDelete.Body.String())
	}
	postDelete := agentGovernanceRequest(t, api, http.MethodDelete, "/api/v1/agent-governance/post-scan-profiles/"+strconv.FormatInt(postProfile.ID, 10), nil)
	if postDelete.Code != http.StatusOK {
		t.Fatalf("post profile delete status = %d body = %s", postDelete.Code, postDelete.Body.String())
	}

	defaultDelete := agentGovernanceRequest(t, api, http.MethodGet, "/api/v1/agent-governance/pre-scan-profiles?keyword=default-pre-scan", nil)
	if defaultDelete.Code != http.StatusOK {
		t.Fatalf("default pre profile lookup status = %d body = %s", defaultDelete.Code, defaultDelete.Body.String())
	}
	var defaults audit.GovernancePreScanProfilePage
	if err := json.NewDecoder(defaultDelete.Body).Decode(&defaults); err != nil {
		t.Fatalf("decode default pre profile: %v", err)
	}
	if len(defaults.Items) == 0 {
		t.Fatal("expected default pre-scan profile")
	}
	deleteDefaultRec := agentGovernanceRequest(t, api, http.MethodDelete, "/api/v1/agent-governance/pre-scan-profiles/"+strconv.FormatInt(defaults.Items[0].ID, 10), nil)
	if deleteDefaultRec.Code != http.StatusBadRequest {
		t.Fatalf("default pre profile delete status = %d body = %s", deleteDefaultRec.Code, deleteDefaultRec.Body.String())
	}
}
