// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const runtimeSettingsPrefix = "/api/v1/runtime-detection-settings"

func (a *APIServer) runtimeSettingsError(w http.ResponseWriter, err error, status int) {
	if errors.Is(err, audit.ErrRuntimeSettingsNotFound) {
		status = http.StatusNotFound
	}
	if errors.Is(err, audit.ErrRuntimeSettingsConflict) {
		status = http.StatusConflict
	}
	a.writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (a *APIServer) decodeRuntimeSettings(w http.ResponseWriter, r *http.Request, dst any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	var raw json.RawMessage
	if err := d.Decode(&raw); err != nil {
		a.runtimeSettingsError(w, err, http.StatusBadRequest)
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		a.runtimeSettingsError(w, fmt.Errorf("exactly one JSON object required"), http.StatusBadRequest)
		return false
	}
	if trimmed := bytes.TrimSpace(raw); len(trimmed) == 0 || trimmed[0] != '{' {
		a.runtimeSettingsError(w, fmt.Errorf("JSON object required"), http.StatusBadRequest)
		return false
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		a.runtimeSettingsError(w, err, http.StatusBadRequest)
		return false
	}
	return true
}

func runtimeSettingsID(raw string) (int64, error) {
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("positive integer ID required")
	}
	return id, nil
}

func runtimeSettingsBoolean(raw string) (*bool, error) {
	switch raw {
	case "", "all":
		return nil, nil
	case "true":
		v := true
		return &v, nil
	case "false":
		v := false
		return &v, nil
	}
	return nil, fmt.Errorf("boolean filter must be true, false or all")
}

type runtimeSettingsFilter struct {
	page, size int
	keyword    string
	enabled    *bool
}

func parseRuntimeSettingsFilter(r *http.Request) (runtimeSettingsFilter, error) {
	f := runtimeSettingsFilter{page: 1, size: 20, keyword: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("keyword")))}
	var err error
	f.enabled, err = runtimeSettingsBoolean(r.URL.Query().Get("enabled"))
	if err != nil {
		return f, err
	}
	for key, dest := range map[string]*int{"page": &f.page, "page_size": &f.size} {
		raw := r.URL.Query().Get(key)
		if key == "page_size" && raw == "" {
			raw = r.URL.Query().Get("pageSize")
		}
		if raw == "" {
			continue
		}
		v, err := strconv.Atoi(raw)
		if err != nil || v <= 0 {
			return f, fmt.Errorf("%s must be a positive integer", key)
		}
		*dest = v
	}
	if f.size > 200 {
		f.size = 200
	}
	return f, nil
}
func (f runtimeSettingsFilter) matches(enabled bool, values ...string) bool {
	return (f.enabled == nil || *f.enabled == enabled) && (f.keyword == "" || strings.Contains(strings.ToLower(strings.Join(values, " ")), f.keyword))
}
func runtimeSettingsPage[T any](items []T, f runtimeSettingsFilter) map[string]any {
	start := len(items)
	// Divide before multiplying so hostile page values cannot overflow.
	if f.page-1 <= len(items)/f.size {
		start = (f.page - 1) * f.size
	}
	end := start + f.size
	if end > len(items) {
		end = len(items)
	}
	return map[string]any{"items": items[start:end], "total": len(items), "page": f.page, "page_size": f.size}
}

func (a *APIServer) handleRuntimeDetectionSettingsAPI(w http.ResponseWriter, r *http.Request) {
	if a.store == nil {
		a.runtimeSettingsError(w, fmt.Errorf("audit store unavailable"), http.StatusServiceUnavailable)
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, runtimeSettingsPrefix), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "overview":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		a.runtimeSettingsOverview(w)
	case parts[0] == "rules":
		a.runtimeSettingsRules(w, r, 0, parts[1:])
	case rest == "risk-policy/global":
		if r.Method != http.MethodGet {
			a.runtimeSettingsError(w, fmt.Errorf("global risk policy is read-only"), http.StatusMethodNotAllowed)
			return
		}
		p, err := a.store.GetRuntimeRiskPolicy(0)
		if err != nil {
			a.runtimeSettingsError(w, err, http.StatusInternalServerError)
			return
		}
		a.writeJSON(w, http.StatusOK, p)
	case parts[0] == "agent-types":
		if len(parts) == 1 {
			a.runtimeSettingsTypes(w, r)
			return
		}
		typeID, err := runtimeSettingsID(parts[1])
		if err != nil {
			a.runtimeSettingsError(w, err, http.StatusBadRequest)
			return
		}
		typeRow, ok, err := a.store.GetGovernanceAgentType(typeID)
		if err != nil {
			a.runtimeSettingsError(w, err, http.StatusInternalServerError)
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		if len(parts) == 2 {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			a.runtimeSettingsTypeDetail(w, typeRow)
			return
		}
		switch parts[2] {
		case "rules":
			a.runtimeSettingsRules(w, r, typeID, parts[3:])
		case "blacklist":
			a.runtimeSettingsBlacklist(w, r, typeID, parts[3:])
		case "settings", "risk-policy", "effective", "evaluate":
			if len(parts) != 3 {
				http.NotFound(w, r)
				return
			}
			switch parts[2] {
			case "settings":
				a.runtimeSettingsTypePatch(w, r, typeID)
			case "risk-policy":
				a.runtimeSettingsRisk(w, r, typeID)
			case "effective":
				a.runtimeSettingsEffective(w, r, typeID)
			case "evaluate":
				a.runtimeSettingsEvaluate(w, r, typeID)
			}
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (a *APIServer) runtimeSettingsOverview(w http.ResponseWriter) {
	rules, err := a.store.ListRuntimeDetectionRules(0)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	types, err := a.store.ListRuntimeDetectionAgentTypes()
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	enabled, custom, blacklist, policies := 0, 0, 0, 0
	updated := ""
	for _, r := range rules {
		if r.Enabled {
			enabled++
		}
		if r.UpdatedAt > updated {
			updated = r.UpdatedAt
		}
	}
	for _, t := range types {
		if t.HasCustomConfiguration {
			custom++
		}
		blacklist += t.BlacklistCount
		policies += t.CustomRiskPolicyCount
		if t.UpdatedAt > updated {
			updated = t.UpdatedAt
		}
	}
	a.writeJSON(w, 200, map[string]any{"global_rule_count": len(rules), "enabled_global_rule_count": enabled, "agent_type_count": len(types), "custom_agent_type_count": custom, "blacklist_count": blacklist, "custom_risk_policy_count": policies, "updated_at": updated})
}

func (a *APIServer) runtimeSettingsTypes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	f, err := parseRuntimeSettingsFilter(r)
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	inherit, err := runtimeSettingsBoolean(r.URL.Query().Get("inherit_global_rules"))
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	risk := r.URL.Query().Get("risk_policy")
	if risk != "" && risk != "all" && risk != "global" && risk != "custom" {
		a.runtimeSettingsError(w, fmt.Errorf("invalid risk_policy filter"), 400)
		return
	}
	rows, err := a.store.ListRuntimeDetectionAgentTypes()
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	items := []audit.RuntimeDetectionAgentTypeRow{}
	for _, row := range rows {
		if !f.matches(row.Enabled, row.AgentTypeKey, row.AgentTypeName, row.Vendor, row.Runtime) || (inherit != nil && row.InheritGlobalRules != *inherit) || (risk != "" && risk != "all" && risk != row.RiskPolicyMode) {
			continue
		}
		items = append(items, row)
	}
	a.writeJSON(w, 200, runtimeSettingsPage(items, f))
}

func (a *APIServer) runtimeSettingsRules(w http.ResponseWriter, r *http.Request, typeID int64, parts []string) {
	if len(parts) > 1 {
		http.NotFound(w, r)
		return
	}
	scope := "global"
	if typeID > 0 {
		scope = "agent_type"
	}
	if given := r.URL.Query().Get("scope"); given != "" && given != scope {
		a.runtimeSettingsError(w, fmt.Errorf("scope does not match route"), 400)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodGet {
		f, err := parseRuntimeSettingsFilter(r)
		if err != nil {
			a.runtimeSettingsError(w, err, 400)
			return
		}
		source := r.URL.Query().Get("source")
		if source != "" && source != "builtin" && source != "custom" {
			a.runtimeSettingsError(w, fmt.Errorf("invalid source filter"), 400)
			return
		}
		rules, err := a.store.ListRuntimeDetectionRules(typeID)
		if err != nil {
			a.runtimeSettingsError(w, err, 500)
			return
		}
		items := []audit.RuntimeDetectionRule{}
		for _, rule := range rules {
			if f.matches(rule.Enabled, rule.RuleID, rule.RuleName, rule.DetectionType, rule.Category) && (source == "" || source == rule.Source) {
				items = append(items, rule)
			}
		}
		a.writeJSON(w, 200, runtimeSettingsPage(items, f))
		return
	}
	item := audit.RuntimeDetectionRule{Source: "custom", Scope: scope, Category: "suspicious", Severity: "MEDIUM", Confidence: .8, Priority: 100, Enabled: true}
	if typeID > 0 {
		item.AgentTypeID = &typeID
	}
	if len(parts) == 1 {
		id, err := runtimeSettingsID(parts[0])
		if err != nil {
			a.runtimeSettingsError(w, err, 400)
			return
		}
		item, err = a.store.GetRuntimeDetectionRule(typeID, id)
		if err != nil {
			a.runtimeSettingsError(w, err, 500)
			return
		}
		if r.Method == http.MethodDelete {
			if err = a.store.DeleteRuntimeDetectionRule(typeID, id); err != nil {
				a.runtimeSettingsError(w, err, 500)
				return
			}
			a.writeJSON(w, 200, map[string]any{"deleted": !item.System, "enabled": false})
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(405)
			return
		}
	} else if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	id, source, system := item.ID, item.Source, item.System
	if !a.decodeRuntimeSettings(w, r, &item) {
		return
	}
	if item.ID != id || item.Scope != scope || item.Source != source || item.System != system || (typeID == 0 && item.AgentTypeID != nil) || (typeID > 0 && (item.AgentTypeID == nil || *item.AgentTypeID != typeID)) {
		a.runtimeSettingsError(w, fmt.Errorf("rule identity and ownership must match route"), 409)
		return
	}
	saved, err := a.store.SaveRuntimeDetectionRule(item)
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	status := 200
	if len(parts) == 0 {
		status = 201
	}
	a.writeJSON(w, status, saved)
}

func (a *APIServer) runtimeSettingsBlacklist(w http.ResponseWriter, r *http.Request, typeID int64, parts []string) {
	if len(parts) > 1 {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 0 && r.Method == http.MethodGet {
		f, err := parseRuntimeSettingsFilter(r)
		if err != nil {
			a.runtimeSettingsError(w, err, 400)
			return
		}
		target := r.URL.Query().Get("target_type")
		if target != "" && !strings.Contains("|command|path|tool|mcp|domain|url|process|", "|"+target+"|") {
			a.runtimeSettingsError(w, fmt.Errorf("invalid target_type filter"), 400)
			return
		}
		rows, err := a.store.ListRuntimeBlacklist(typeID)
		if err != nil {
			a.runtimeSettingsError(w, err, 500)
			return
		}
		items := []audit.RuntimeDetectionBlacklistItem{}
		for _, item := range rows {
			if f.matches(item.Enabled, item.Value, item.Reason, item.DetectionType) && (target == "" || target == item.TargetType) {
				items = append(items, item)
			}
		}
		a.writeJSON(w, 200, runtimeSettingsPage(items, f))
		return
	}
	item := audit.RuntimeDetectionBlacklistItem{AgentTypeID: typeID, Category: "attack", Severity: "HIGH", Confidence: .9, Priority: 50, Enabled: true}
	if len(parts) == 1 {
		id, err := runtimeSettingsID(parts[0])
		if err != nil {
			a.runtimeSettingsError(w, err, 400)
			return
		}
		item, err = a.store.GetRuntimeBlacklistItem(typeID, id)
		if err != nil {
			a.runtimeSettingsError(w, err, 500)
			return
		}
		if r.Method == http.MethodDelete {
			if err = a.store.DeleteRuntimeBlacklist(typeID, id); err != nil {
				a.runtimeSettingsError(w, err, 500)
				return
			}
			a.writeJSON(w, 200, map[string]bool{"deleted": true})
			return
		}
		if r.Method != http.MethodPatch {
			w.WriteHeader(405)
			return
		}
	} else if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	id := item.ID
	if !a.decodeRuntimeSettings(w, r, &item) {
		return
	}
	if item.ID != id || item.AgentTypeID != typeID {
		a.runtimeSettingsError(w, fmt.Errorf("blacklist identity and ownership must match route"), 409)
		return
	}
	saved, err := a.store.SaveRuntimeBlacklist(item)
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	status := 200
	if len(parts) == 0 {
		status = 201
	}
	a.writeJSON(w, status, saved)
}

func (a *APIServer) runtimeSettingsTypePatch(w http.ResponseWriter, r *http.Request, typeID int64) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(405)
		return
	}
	var patch struct {
		Enabled             *bool `json:"enabled"`
		InheritGlobalRules  *bool `json:"inherit_global_rules"`
		UseGlobalRiskPolicy *bool `json:"use_global_risk_policy"`
	}
	if !a.decodeRuntimeSettings(w, r, &patch) {
		return
	}
	settings, err := a.store.GetRuntimeDetectionAgentTypeSettings(typeID)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	if patch.Enabled != nil {
		settings.Enabled = *patch.Enabled
	}
	if patch.InheritGlobalRules != nil {
		settings.InheritGlobalRules = *patch.InheritGlobalRules
	}
	if patch.UseGlobalRiskPolicy != nil {
		settings.UseGlobalRiskPolicy = *patch.UseGlobalRiskPolicy
	}
	saved, err := a.store.SaveRuntimeDetectionAgentTypeSettings(settings)
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	a.writeJSON(w, 200, saved)
}

func (a *APIServer) runtimeSettingsRiskData(typeID int64) (map[string]any, error) {
	c, err := a.store.EffectiveRuntimeDetectionConfig(typeID)
	if err != nil {
		return nil, err
	}
	mode := "global"
	var policy any
	if !c.UseGlobalRiskPolicy {
		mode = "custom"
		policy = c.RiskPolicy
	}
	// Keep the saved custom policy available to editors while global inheritance
	// is active, without presenting it as the policy used for evaluation.
	var customPolicy any
	custom, err := a.store.GetRuntimeRiskPolicy(typeID)
	if err == nil {
		customPolicy = custom
	} else if !errors.Is(err, audit.ErrRuntimeSettingsNotFound) {
		return nil, err
	}
	return map[string]any{"mode": mode, "use_global_risk_policy": c.UseGlobalRiskPolicy, "policy": policy, "custom_policy": customPolicy, "effective_policy": c.RiskPolicy}, nil
}

func (a *APIServer) runtimeSettingsRisk(w http.ResponseWriter, r *http.Request, typeID int64) {
	if r.Method == http.MethodPut {
		var input struct {
			UseGlobal *bool `json:"use_global_risk_policy"`
			Policy    *struct {
				Name  string                        `json:"name"`
				Rules []audit.RuntimeRiskPolicyRule `json:"rules"`
			} `json:"policy"`
		}
		if !a.decodeRuntimeSettings(w, r, &input) {
			return
		}
		if input.UseGlobal == nil || (!*input.UseGlobal && input.Policy == nil) {
			a.runtimeSettingsError(w, fmt.Errorf("use_global_risk_policy and custom policy required"), 400)
			return
		}
		name := ""
		var rules []audit.RuntimeRiskPolicyRule
		if input.Policy != nil {
			name = input.Policy.Name
			rules = input.Policy.Rules
		}
		if err := a.store.SaveRuntimeRiskPolicy(typeID, *input.UseGlobal, name, rules); err != nil {
			a.runtimeSettingsError(w, err, 400)
			return
		}
	} else if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	data, err := a.runtimeSettingsRiskData(typeID)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	a.writeJSON(w, 200, data)
}

func (a *APIServer) runtimeSettingsTypeDetail(w http.ResponseWriter, row audit.GovernanceAgentTypeRow) {
	id := row.ID
	settings, err := a.store.GetRuntimeDetectionAgentTypeSettings(id)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	rules, err := a.store.ListRuntimeDetectionRules(id)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	blacklist, err := a.store.ListRuntimeBlacklist(id)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	risk, err := a.runtimeSettingsRiskData(id)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	c, err := a.store.EffectiveRuntimeDetectionConfig(id)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	global, specific := 0, 0
	for _, r := range c.Rules {
		if r.Scope == "global" {
			global++
		} else {
			specific++
		}
	}
	a.writeJSON(w, 200, map[string]any{"agent_type": map[string]any{"agent_type_id": id, "agent_type_key": row.TypeKey, "agent_type_name": row.Name}, "settings": settings, "specific_rules": rules, "blacklist": blacklist, "risk_policy": risk, "effective_summary": map[string]int{"global_rule_count": global, "specific_rule_count": specific, "blacklist_count": len(c.Blacklist), "effective_rule_count": len(c.Rules) + len(c.Blacklist)}})
}

func (a *APIServer) runtimeSettingsEffective(w http.ResponseWriter, r *http.Request, typeID int64) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	c, err := a.store.EffectiveRuntimeDetectionConfig(typeID)
	if err != nil {
		a.runtimeSettingsError(w, err, 500)
		return
	}
	rules := []any{}
	for _, rule := range c.Rules {
		rules = append(rules, struct {
			audit.RuntimeDetectionRule
			Source     string `json:"source"`
			RuleSource string `json:"rule_source"`
		}{rule, rule.Scope, rule.Source})
	}
	for _, item := range c.Blacklist {
		rules = append(rules, map[string]any{"rule_id": fmt.Sprintf("blacklist-%d", item.ID), "source": "blacklist", "enabled": item.Enabled, "blacklist": item})
	}
	source := "global"
	if !c.UseGlobalRiskPolicy {
		source = "agent_type"
	}
	policy := struct {
		audit.RuntimeRiskPolicy
		Source string `json:"source"`
	}{c.RiskPolicy, source}
	a.writeJSON(w, 200, map[string]any{"agent_type_id": typeID, "enabled": c.Enabled, "inherit_global_rules": c.InheritGlobalRules, "use_global_risk_policy": c.UseGlobalRiskPolicy, "rules": rules, "risk_policy": policy})
}

func (a *APIServer) runtimeSettingsEvaluate(w http.ResponseWriter, r *http.Request, typeID int64) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	engine := activeDetectionEngine()
	if engine == nil || activeRuntimeEventStore() != a.store {
		a.runtimeSettingsError(w, fmt.Errorf("detection engine unavailable"), 503)
		return
	}
	var input struct {
		Event struct {
			EventType       string         `json:"event_type"`
			EventCategory   string         `json:"event_category"`
			EventSource     string         `json:"event_source"`
			ToolName        string         `json:"tool_name"`
			MCPServer       string         `json:"mcp_server"`
			Target          string         `json:"target"`
			Detail          string         `json:"detail"`
			Path            string         `json:"path"`
			Operation       string         `json:"operation"`
			Severity        string         `json:"severity"`
			Confidence      float64        `json:"confidence"`
			Outcome         string         `json:"outcome"`
			ActorExecutable string         `json:"actor_executable"`
			Attributes      map[string]any `json:"attributes"`
		} `json:"event"`
	}
	if !a.decodeRuntimeSettings(w, r, &input) {
		return
	}
	ev := input.Event
	result, err := engine.EvaluatePreview(typeID, audit.BehaviorEvent{EventType: ev.EventType, EventCategory: ev.EventCategory, EventSource: ev.EventSource, ToolName: ev.ToolName, MCPServer: ev.MCPServer, Target: ev.Target, Detail: ev.Detail, Path: ev.Path, Operation: ev.Operation, Severity: ev.Severity, Confidence: ev.Confidence, Outcome: ev.Outcome, ActorExecutable: ev.ActorExecutable, Attributes: ev.Attributes}, nil)
	if err != nil {
		a.runtimeSettingsError(w, err, 400)
		return
	}
	matches := []map[string]any{}
	for _, match := range result.MatchedRules {
		source, _ := match.Detection.Attributes["rule_scope"].(string)
		if match.Source == "blacklist" {
			source = "blacklist"
		}
		matches = append(matches, map[string]any{"rule_id": match.RuleID, "rule_version": match.RuleVersion, "source": source, "rule_source": match.Source, "severity": match.Detection.Severity, "confidence": match.Detection.Confidence, "detection_type": match.Detection.DetectionType, "detail": match.Detection.Detail})
	}
	a.writeJSON(w, 200, map[string]any{"matched": result.Matched, "matched_rules": matches, "risk_score": result.RiskScore, "risk_level": result.RiskLevel, "decision": result.Decision})
}
