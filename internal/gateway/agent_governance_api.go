// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

const agentGovernancePrefix = "/api/v1/agent-governance"

func (a *APIServer) handleAgentGovernanceAPI(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit store unavailable"})
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, agentGovernancePrefix), "/")
	if rest == "" {
		a.handleAgentGovernanceOverview(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	switch parts[0] {
	case "agent-types":
		a.handleGovernanceAgentTypes(w, r, parts[1:])
	case "discovery-rules":
		a.handleGovernanceDiscoveryRules(w, r, parts[1:])
	case "discovery-conditions":
		a.handleGovernanceDiscoveryConditions(w, r, parts[1:])
	case "resource-rules":
		a.handleGovernanceResourceRules(w, r, parts[1:])
	case "scan-profiles":
		a.handleGovernanceScanProfiles(w, r, parts[1:])
	case "scan-capabilities":
		a.handleGovernanceScanCapabilities(w, r)
	case "resource-actions":
		a.handleGovernanceResourceActions(w, r, parts[1:])
	case "admission-matrix":
		a.handleGovernanceAdmissionMatrix(w, r)
	case "admission":
		if len(parts) == 2 && parts[1] == "evaluate" {
			a.handleGovernanceAdmissionEvaluate(w, r)
			return
		}
		http.NotFound(w, r)
	case "risk-model":
		a.handleGovernanceRiskModel(w, r)
	case "risk":
		if len(parts) == 2 && parts[1] == "evaluate" {
			a.handleGovernanceRiskEvaluate(w, r)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *APIServer) handleAgentGovernanceOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	enabled := true
	agentTypes, err := a.store.ListGovernanceAgentTypes(a.governanceFilter(r, true))
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	resourceRules, err := a.store.ListGovernanceResourceRules(audit.GovernancePageFilter{Enabled: &enabled, PageSize: 1})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	profiles, err := a.store.ListGovernanceScanProfiles(audit.GovernancePageFilter{Enabled: &enabled, PageSize: 1})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	actions, err := a.store.ListGovernanceResourceActions(audit.GovernancePageFilter{PageSize: 1})
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"agent_type_count":      agentTypes.Total,
		"resource_rule_count":   resourceRules.Total,
		"scan_profile_count":    profiles.Total,
		"resource_action_count": actions.Total,
	})
}

func (a *APIServer) handleGovernanceAgentTypes(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			page, err := a.store.ListGovernanceAgentTypes(a.governanceFilter(r, true))
			a.writeGovernanceResult(w, page, err)
		case http.MethodPost:
			var body audit.GovernanceAgentTypeInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.CreateGovernanceAgentType(body)
			a.writeGovernanceCreated(w, r, row, err, "agent-type")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	id, ok := parseGovernanceID(parts[0])
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a positive integer"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceAgentType(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceAgentTypePatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceAgentType(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "agent-type")
	case http.MethodDelete:
		row, found, err := a.store.DeleteGovernanceAgentType(id)
		a.writeGovernanceMutated(w, r, row, found, err, "agent-type")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceDiscoveryRules(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			page, err := a.store.ListGovernanceDiscoveryRules(a.governanceFilter(r, true))
			a.writeGovernanceResult(w, page, err)
		case http.MethodPost:
			var body audit.GovernanceDiscoveryRuleInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.CreateGovernanceDiscoveryRule(body)
			a.writeGovernanceCreated(w, r, row, err, "discovery-rule")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "conditions" {
		ruleID, ok := parseGovernanceID(parts[0])
		if !ok {
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rule id must be a positive integer"})
			return
		}
		switch r.Method {
		case http.MethodGet:
			rows, err := a.store.ListGovernanceDiscoveryConditions(ruleID)
			a.writeGovernanceResult(w, map[string]any{"items": rows}, err)
		case http.MethodPost:
			var body audit.GovernanceDiscoveryConditionInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.CreateGovernanceDiscoveryCondition(ruleID, body)
			a.writeGovernanceCreated(w, r, row, err, "discovery-condition")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	id, ok := parseGovernanceID(parts[0])
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a positive integer"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceDiscoveryRule(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceDiscoveryRulePatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceDiscoveryRule(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "discovery-rule")
	case http.MethodDelete:
		row, found, err := a.store.DisableGovernanceDiscoveryRule(id)
		a.writeGovernanceMutated(w, r, row, found, err, "discovery-rule")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceDiscoveryConditions(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	id, ok := parseGovernanceID(parts[0])
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a positive integer"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceDiscoveryCondition(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceDiscoveryConditionPatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceDiscoveryCondition(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "discovery-condition")
	case http.MethodDelete:
		found, err := a.store.DeleteGovernanceDiscoveryCondition(id)
		a.writeGovernanceDeleted(w, r, found, err, "discovery-condition")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceResourceRules(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 1 && parts[0] == "preview" {
		a.handleGovernanceResourceRulePreview(w, r)
		return
	}
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			page, err := a.store.ListGovernanceResourceRules(a.governanceFilter(r, true))
			a.writeGovernanceResult(w, page, err)
		case http.MethodPost:
			var body audit.GovernanceResourceRuleInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.CreateGovernanceResourceRule(body)
			a.writeGovernanceCreated(w, r, row, err, "resource-rule")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	id, ok := parseGovernanceID(parts[0])
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a positive integer"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceResourceRule(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceResourceRulePatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceResourceRule(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "resource-rule")
	case http.MethodDelete:
		row, found, err := a.store.DisableGovernanceResourceRule(id)
		a.writeGovernanceMutated(w, r, row, found, err, "resource-rule")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceScanProfiles(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			page, err := a.store.ListGovernanceScanProfiles(a.governanceFilter(r, true))
			a.writeGovernanceResult(w, page, err)
		case http.MethodPost:
			var body audit.GovernanceScanProfileInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.CreateGovernanceScanProfile(body)
			a.writeGovernanceCreated(w, r, row, err, "scan-profile")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	id, ok := parseGovernanceID(parts[0])
	if !ok {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id must be a positive integer"})
		return
	}
	if len(parts) == 2 && parts[1] == "capabilities" {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body struct {
			Capabilities []audit.GovernanceProfileCapabilityInput `json:"capabilities"`
		}
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.ReplaceGovernanceScanProfileCapabilities(id, body.Capabilities)
		a.writeGovernanceMutated(w, r, row, found, err, "scan-profile-capabilities")
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceScanProfile(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceScanProfilePatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceScanProfile(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "scan-profile")
	case http.MethodDelete:
		row, found, err := a.store.DisableGovernanceScanProfile(id)
		a.writeGovernanceMutated(w, r, row, found, err, "scan-profile")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceScanCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items, err := a.store.ListGovernanceScanCapabilities(a.governanceFilter(r, true))
	a.writeGovernanceResult(w, map[string]any{"items": items}, err)
}

func (a *APIServer) handleGovernanceResourceActions(w http.ResponseWriter, r *http.Request, parts []string) {
	if len(parts) == 0 {
		switch r.Method {
		case http.MethodGet:
			page, err := a.store.ListGovernanceResourceActions(a.governanceFilter(r, true))
			a.writeGovernanceResult(w, page, err)
		case http.MethodPost:
			var body audit.GovernanceResourceActionInput
			if !a.decodeGovernanceBody(w, r, &body) {
				return
			}
			row, err := a.store.UpsertGovernanceResourceAction(body)
			a.writeGovernanceCreated(w, r, row, err, "resource-action")
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) != 1 {
		http.NotFound(w, r)
		return
	}
	id := strings.TrimSpace(parts[0])
	if id == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		row, found, err := a.store.GetGovernanceResourceActionByID(id)
		a.writeGovernanceMaybe(w, row, found, err)
	case http.MethodPatch:
		var body audit.GovernanceResourceActionPatch
		if !a.decodeGovernanceBody(w, r, &body) {
			return
		}
		row, found, err := a.store.UpdateGovernanceResourceAction(id, body)
		a.writeGovernanceMutated(w, r, row, found, err, "resource-action")
	case http.MethodDelete:
		found, err := a.store.DeleteGovernanceResourceAction(id)
		a.writeGovernanceDeleted(w, r, found, err, "resource-action")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *APIServer) handleGovernanceAdmissionMatrix(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": governanceAdmissionMatrix()})
}

func (a *APIServer) handleGovernanceAdmissionEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ResourceType string                  `json:"resource_type"`
		TargetName   string                  `json:"target_name"`
		Path         string                  `json:"path"`
		ScanResult   *policy.ScanResultInput `json:"scan_result,omitempty"`
	}
	if !a.decodeGovernanceBody(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.ResourceType) == "" || strings.TrimSpace(body.TargetName) == "" {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "resource_type and target_name are required"})
		return
	}
	regoDir := ""
	if a.scannerCfg != nil {
		regoDir = a.scannerCfg.PolicyDir
	}
	input := policy.AdmissionInput{
		TargetType: strings.ToLower(strings.TrimSpace(body.ResourceType)),
		TargetName: strings.TrimSpace(body.TargetName),
		Path:       strings.TrimSpace(body.Path),
		BlockList:  a.policyListEntries(true),
		AllowList:  a.policyListEntries(false),
		ScanResult: body.ScanResult,
	}
	out := policy.EvaluateAdmissionFallback(input, policy.LoadFallbackProfile(regoDir))
	a.writeJSON(w, http.StatusOK, out)
}

func (a *APIServer) handleGovernanceRiskModel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"severity_mapping":     governanceSeverityMapping(),
		"malicious_indicators": governanceMaliciousIndicators(),
	})
}

func (a *APIServer) handleGovernanceRiskEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		ResourceType string                   `json:"resource_type"`
		Findings     []governanceFindingInput `json:"findings"`
	}
	if !a.decodeGovernanceBody(w, r, &body) {
		return
	}
	maxSeverity := "INFO"
	for _, f := range body.Findings {
		if audit.SeverityRank(f.Severity) > audit.SeverityRank(maxSeverity) {
			maxSeverity = strings.ToUpper(strings.TrimSpace(f.Severity))
		}
	}
	matched := matchedGovernanceMaliciousIndicators(body.Findings)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"risk_level":         audit.ResourceRiskLevel(maxSeverity),
		"malicious":          len(matched) > 0,
		"max_severity":       maxSeverity,
		"finding_count":      len(body.Findings),
		"matched_indicators": matched,
	})
}

func (a *APIServer) handleGovernanceResourceRulePreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		AgentID         string `json:"agent_id"`
		AgentTypeID     int64  `json:"agent_type_id"`
		PathPattern     string `json:"path_pattern"`
		EnumerationMode string `json:"enumeration_mode"`
	}
	if !a.decodeGovernanceBody(w, r, &body) {
		return
	}
	agent, found, err := a.store.GetGovernanceAgentResourceContext(body.AgentID, body.AgentTypeID)
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "matching agent not found"})
		return
	}
	paths := expandGovernanceResourcePattern(agent, body.PathPattern)
	targets := previewGovernanceTargets(paths, body.EnumerationMode)
	a.writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":       agent.ID,
		"agent_type_id":  agent.AgentTypeID,
		"agent_type_key": agent.TypeKey,
		"expanded_paths": paths,
		"targets":        targets,
	})
}

func (a *APIServer) governanceFilter(r *http.Request, includeEnabled bool) audit.GovernancePageFilter {
	q := r.URL.Query()
	f := audit.GovernancePageFilter{
		Keyword:       strings.TrimSpace(q.Get("keyword")),
		Kind:          strings.TrimSpace(q.Get("kind")),
		Runtime:       strings.TrimSpace(q.Get("runtime")),
		TypeKey:       strings.TrimSpace(q.Get("type_key")),
		ResourceType:  strings.TrimSpace(q.Get("resource_type")),
		TargetType:    strings.TrimSpace(q.Get("target_type")),
		TargetName:    strings.TrimSpace(q.Get("target_name")),
		Connector:     strings.TrimSpace(q.Get("connector")),
		ActionField:   strings.TrimSpace(q.Get("action_field")),
		ActionValue:   strings.TrimSpace(q.Get("action_value")),
		Page:          queryInt(q.Get("page"), 1),
		PageSize:      queryInt(q.Get("page_size"), 20),
		AgentTypeID:   int64(queryInt(q.Get("agent_type_id"), 0)),
		ScanProfileID: int64(queryInt(q.Get("scan_profile_id"), 0)),
	}
	if includeEnabled {
		if v, ok := queryBool(q.Get("enabled")); ok {
			f.Enabled = &v
		}
	}
	return f
}

func (a *APIServer) decodeGovernanceBody(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := json.NewDecoder(r.Body).Decode(out); err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (a *APIServer) writeGovernanceResult(w http.ResponseWriter, payload any, err error) {
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	a.writeJSON(w, http.StatusOK, payload)
}

func (a *APIServer) writeGovernanceMaybe(w http.ResponseWriter, payload any, found bool, err error) {
	if err != nil {
		a.writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
		return
	}
	a.writeJSON(w, http.StatusOK, payload)
}

func (a *APIServer) writeGovernanceCreated(w http.ResponseWriter, r *http.Request, payload any, err error, target string) {
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	a.logGovernanceMutation(r, "create", target)
	a.writeJSON(w, http.StatusCreated, payload)
}

func (a *APIServer) writeGovernanceMutated(w http.ResponseWriter, r *http.Request, payload any, found bool, err error, target string) {
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
		return
	}
	a.logGovernanceMutation(r, "update", target)
	a.writeJSON(w, http.StatusOK, payload)
}

func (a *APIServer) writeGovernanceDeleted(w http.ResponseWriter, r *http.Request, found bool, err error, target string) {
	if err != nil {
		a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		a.writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
		return
	}
	a.logGovernanceMutation(r, "delete", target)
	a.writeJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
}

func (a *APIServer) logGovernanceMutation(r *http.Request, op, target string) {
	if a.logger == nil {
		return
	}
	_ = a.logger.LogActionCtx(r.Context(), string(audit.ActionPolicyUpdate), target, "agent-governance "+op)
}

func parseGovernanceID(raw string) (int64, bool) {
	id, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	return id, err == nil && id > 0
}

func queryInt(raw string, fallback int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func queryBool(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "true", "1", "yes", "enabled":
		return true, true
	case "false", "0", "no", "disabled":
		return false, true
	default:
		return false, false
	}
}

type governanceAdmissionMatrixItem struct {
	ResourceType  string `json:"resource_type"`
	Severity      string `json:"severity"`
	Verdict       string `json:"verdict"`
	InstallAction string `json:"install_action"`
	FileAction    string `json:"file_action"`
	RuntimeAction string `json:"runtime_action"`
	Phase         string `json:"phase"`
	Source        string `json:"source"`
}

func governanceAdmissionMatrix() []governanceAdmissionMatrixItem {
	resourceTypes := []string{"skill", "mcp", "plugin", "config", "prompt", "credential", "environment"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	items := []governanceAdmissionMatrixItem{{
		ResourceType:  "*",
		Severity:      "",
		Verdict:       "scan",
		InstallAction: "none",
		FileAction:    "none",
		RuntimeAction: "allow",
		Phase:         "pre_scan",
		Source:        "fallback-profile",
	}}
	for _, rtype := range resourceTypes {
		for _, sev := range severities {
			item := governanceAdmissionMatrixItem{
				ResourceType:  rtype,
				Severity:      sev,
				Verdict:       "warning",
				InstallAction: "none",
				FileAction:    "none",
				RuntimeAction: "allow",
				Phase:         "post_scan",
				Source:        "fallback-profile",
			}
			if sev == "CRITICAL" || sev == "HIGH" {
				item.Verdict = "rejected"
				item.InstallAction = "block"
				item.FileAction = "quarantine"
				item.RuntimeAction = "block"
			}
			if sev == "INFO" {
				item.Verdict = "clean"
			}
			if rtype == "mcp" && (sev == "MEDIUM" || sev == "LOW") {
				item.Verdict = "rejected"
				item.RuntimeAction = "block"
				if sev == "MEDIUM" {
					item.InstallAction = "block"
					item.FileAction = "quarantine"
				}
			}
			items = append(items, item)
		}
	}
	return items
}

type governanceRiskMappingItem struct {
	Severity  string `json:"severity"`
	RiskLevel string `json:"risk_level"`
}

func governanceSeverityMapping() []governanceRiskMappingItem {
	return []governanceRiskMappingItem{
		{Severity: "CRITICAL", RiskLevel: "critical"},
		{Severity: "HIGH", RiskLevel: "high"},
		{Severity: "MEDIUM", RiskLevel: "medium"},
		{Severity: "LOW", RiskLevel: "low"},
		{Severity: "INFO", RiskLevel: "clean"},
	}
}

type governanceMaliciousIndicator struct {
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
}

func governanceMaliciousIndicators() []governanceMaliciousIndicator {
	values := []governanceMaliciousIndicator{{MatchType: "rule_id_prefix", MatchValue: "CS-MAL-"}}
	for _, v := range []string{"malware", "reverse_shell", "credential_harvest", "credential_exfiltration", "cryptominer", "c2", "command_execution", "prompt_injection", "malicious_mcp_tool", "data_exfiltration"} {
		values = append(values, governanceMaliciousIndicator{MatchType: "category", MatchValue: v})
	}
	for _, v := range []string{"malware", "reverse_shell", "credential_harvest", "cryptominer", "c2", "zip_slip", "role_override", "instruction_injection", "delimiter_injection"} {
		values = append(values, governanceMaliciousIndicator{MatchType: "tag", MatchValue: v})
	}
	for _, v := range []string{"malware", "reverse shell", "credential harvest", "credential exfiltration", "cryptominer", "command execution", "prompt injection", "malicious mcp", "data exfiltration", "zip slip"} {
		values = append(values, governanceMaliciousIndicator{MatchType: "title_keyword", MatchValue: v})
	}
	return values
}

type governanceFindingInput struct {
	RuleID   string   `json:"rule_id"`
	Category string   `json:"category"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Tags     []string `json:"tags"`
}

func matchedGovernanceMaliciousIndicators(findings []governanceFindingInput) []governanceMaliciousIndicator {
	var out []governanceMaliciousIndicator
	seen := map[string]bool{}
	add := func(item governanceMaliciousIndicator) {
		key := item.MatchType + "\x00" + item.MatchValue
		if !seen[key] {
			seen[key] = true
			out = append(out, item)
		}
	}
	for _, f := range findings {
		ruleID := strings.TrimSpace(f.RuleID)
		if strings.HasPrefix(ruleID, "CS-MAL-") {
			add(governanceMaliciousIndicator{MatchType: "rule_id_prefix", MatchValue: "CS-MAL-"})
		}
		category := strings.ToLower(strings.TrimSpace(f.Category))
		for _, item := range governanceMaliciousIndicators() {
			if item.MatchType == "category" && item.MatchValue == category {
				add(item)
			}
		}
		for _, tag := range f.Tags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			for _, item := range governanceMaliciousIndicators() {
				if item.MatchType == "tag" && item.MatchValue == tag {
					add(item)
				}
			}
		}
		title := strings.ToLower(strings.TrimSpace(f.Title))
		for _, item := range governanceMaliciousIndicators() {
			if item.MatchType == "title_keyword" && strings.Contains(title, item.MatchValue) {
				add(item)
			}
		}
	}
	return out
}

type governancePreviewTarget struct {
	Name   string `json:"name"`
	Target string `json:"target"`
	Exists bool   `json:"exists"`
	Type   string `json:"type"`
}

func expandGovernanceResourcePattern(agent audit.AgentResourceRecord, pattern string) []string {
	path := strings.TrimSpace(pattern)
	if path == "" {
		return nil
	}
	replacements := map[string]string{
		"${INSTALL_ROOT}":   agent.InstallRoot,
		"${CONFIG_ROOT}":    agent.ConfigRoot,
		"${WORKSPACE_ROOT}": agent.WorkspaceRoot,
	}
	if home, err := os.UserHomeDir(); err == nil {
		replacements["${HOME}"] = home
	}
	for token, value := range replacements {
		if strings.Contains(path, token) {
			if strings.TrimSpace(value) == "" {
				return nil
			}
			path = strings.ReplaceAll(path, token, value)
		}
	}
	if strings.HasPrefix(path, "~/") || path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(path, "~"), string(filepath.Separator)))
		}
	}
	if abs, err := filepath.Abs(path); err == nil && !strings.Contains(path, "*") {
		path = abs
	}
	return []string{filepath.Clean(path)}
}

func previewGovernanceTargets(paths []string, mode string) []governancePreviewTarget {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "children"
	}
	var out []governancePreviewTarget
	add := func(path string) {
		if len(out) >= 200 {
			return
		}
		info, err := os.Stat(path)
		kind := "missing"
		if err == nil {
			if info.IsDir() {
				kind = "directory"
			} else {
				kind = "file"
			}
		}
		out = append(out, governancePreviewTarget{
			Name:   filepath.Base(path),
			Target: path,
			Exists: err == nil,
			Type:   kind,
		})
	}
	for _, path := range paths {
		switch mode {
		case "exact":
			add(path)
		case "glob":
			matches, err := filepath.Glob(path)
			if err != nil || len(matches) == 0 {
				add(path)
				continue
			}
			for _, match := range matches {
				add(match)
			}
		case "recursive":
			_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
				if err != nil || p == path {
					return nil
				}
				add(p)
				if len(out) >= 200 {
					return filepath.SkipAll
				}
				return nil
			})
		default:
			entries, err := os.ReadDir(path)
			if err != nil {
				add(path)
				continue
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				add(filepath.Join(path, entry.Name()))
			}
		}
	}
	if out == nil {
		out = []governancePreviewTarget{}
	}
	return out
}
