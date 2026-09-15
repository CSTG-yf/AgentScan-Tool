// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const runtimeConfigTTL = 5 * time.Second

type configuredRule struct {
	metadata        audit.RuntimeDetectionRule
	builtin         Rule
	match           func(audit.BehaviorEvent) bool
	blacklistTarget string
}

func (r configuredRule) ID() string   { return r.metadata.RuleID }
func (r configuredRule) Name() string { return r.metadata.RuleName }
func (r configuredRule) Version() string {
	return fmt.Sprintf("%s/%s-%d-v%d", RuleVersion, r.metadata.Source, r.metadata.ID, r.metadata.Version)
}
func (r configuredRule) Evaluate(ctx *EvalContext) []DetectionResult {
	var results []DetectionResult
	if r.builtin != nil {
		results = r.builtin.Evaluate(ctx)
	} else if r.match != nil && r.match(ctx.Event) {
		results = []DetectionResult{{DetectionType: r.metadata.DetectionType, Category: r.metadata.Category, Severity: r.metadata.Severity, Confidence: r.metadata.Confidence, Title: r.Name(), Detail: r.metadata.Detail, Remediation: r.metadata.Remediation, Evidence: triggerEvidence(ctx.Event)}}
	}
	for i := range results {
		res := &results[i]
		if r.builtin != nil {
			if r.metadata.OverrideSeverity {
				res.Severity = r.metadata.Severity
			}
			if r.metadata.OverrideConfidence {
				res.Confidence = r.metadata.Confidence
			}
			if r.metadata.Detail != "" {
				res.Detail = r.metadata.Detail
			}
			if r.metadata.Remediation != "" {
				res.Remediation = r.metadata.Remediation
			}
		}
		attrs := make(map[string]any, len(res.Attributes)+5)
		for k, v := range res.Attributes {
			attrs[k] = v
		}
		attrs["rule_source"] = r.metadata.Source
		attrs["rule_scope"] = r.metadata.Scope
		attrs["rule_config_id"] = r.metadata.ID
		attrs["rule_version"] = r.Version()
		if r.blacklistTarget != "" {
			attrs["blacklist_target_type"] = r.blacklistTarget
		}
		res.Attributes = attrs
	}
	return results
}

type runtimeConfigEntry struct {
	config   audit.EffectiveRuntimeDetectionConfig
	rules    []configuredRule
	revision uint64
	readAt   time.Time
}

// Defaults describe the builtins in the editor. Their actual verdicts stay
// event-dependent until an operator explicitly overrides a field.
func builtinConfiguration(rules []Rule) []audit.RuntimeDetectionRule {
	defaults := map[string]struct {
		kind, category, severity string
		confidence               float64
	}{
		"inspect-findings":              {"inspection_risk", "suspicious", "MEDIUM", .8},
		"prompt-injection":              {"prompt_injection", "attack", "HIGH", .9},
		"credential-access":             {"credential_access", "attack", "HIGH", .85},
		"sensitive-file":                {"sensitive_file_access", "suspicious", "MEDIUM", .7},
		"ssrf-defense":                  {"ssrf_blocked", "attack", "HIGH", .9},
		"untrusted-network":             {"untrusted_network_access", "suspicious", "MEDIUM", .75},
		"dangerous-command":             {"dangerous_command", "attack", "HIGH", .85},
		"suspicious-process":            {"suspicious_process", "suspicious", "HIGH", .8},
		"tool-abuse":                    {"tool_abuse", "suspicious", "MEDIUM", .7},
		"known-malicious-resource":      {"known_malicious_resource_invocation", "attack", "CRITICAL", .95},
		"credential-exfiltration":       {"credential_exfiltration", "attack", "CRITICAL", .9},
		"injection-driven-exfiltration": {"prompt_injection_driven_exfiltration", "attack", "CRITICAL", .96},
		"exploit-behavior":              {"possible_runtime_exploitation", "attack", "HIGH", .75},
	}
	out := make([]audit.RuntimeDetectionRule, 0, len(rules))
	for i, r := range rules {
		d, ok := defaults[r.ID()]
		if !ok {
			d.kind = r.ID()
			d.category = "suspicious"
			d.severity = "MEDIUM"
			d.confidence = .8
		}
		out = append(out, audit.RuntimeDetectionRule{RuleID: r.ID(), RuleName: r.Name(), Source: "builtin", Scope: "global", DetectionType: d.kind, Category: d.category, Severity: d.severity, Confidence: d.confidence, Matcher: audit.RuntimeMatcher{Kind: "builtin", BuiltinRuleID: r.ID()}, Priority: 100 + i, Enabled: true, System: true})
	}
	return out
}

func (e *Engine) configured(typeID int64) (runtimeConfigEntry, error) {
	if e == nil || e.store == nil {
		return runtimeConfigEntry{}, fmt.Errorf("runtime detection store unavailable")
	}
	e.configMu.Lock()
	defer e.configMu.Unlock()
	// Retry an unsuccessful startup seed on the next request, without running
	// unconfigured algorithms or claiming the save/evaluation succeeded.
	if !e.configSeeded {
		if err := e.store.EnsureRuntimeBuiltinRules(builtinConfiguration(e.rules)); err != nil {
			return runtimeConfigEntry{}, err
		}
		e.configSeeded = true
	}
	revision := e.store.RuntimeSettingsRevision()
	if entry, ok := e.configCache[typeID]; ok && entry.revision == revision && time.Since(entry.readAt) < runtimeConfigTTL {
		return entry, nil
	}
	config, err := e.store.EffectiveRuntimeDetectionConfig(typeID)
	if err != nil {
		return runtimeConfigEntry{}, err
	}
	entry := runtimeConfigEntry{config: config, revision: revision, readAt: time.Now()}
	builtins := map[string]Rule{}
	for _, r := range e.rules {
		builtins[r.ID()] = r
	}
	for _, metadata := range config.Rules {
		r := configuredRule{metadata: metadata}
		if metadata.Source == "builtin" {
			r.builtin = builtins[metadata.Matcher.BuiltinRuleID]
			// A binary may have removed a builtin still retained in the DB.
			if r.builtin == nil {
				continue
			}
		} else {
			r.match, err = compileEventMatcher(metadata.Matcher)
			if err != nil {
				return runtimeConfigEntry{}, fmt.Errorf("rule %s: %w", metadata.RuleID, err)
			}
		}
		entry.rules = append(entry.rules, r)
	}
	for _, item := range config.Blacklist {
		match, err := compilePattern(audit.RuntimePattern{MatchType: item.MatchType, Value: item.Value})
		if err != nil {
			return runtimeConfigEntry{}, err
		}
		targetType := item.TargetType
		r := configuredRule{metadata: audit.RuntimeDetectionRule{ID: item.ID, RuleID: fmt.Sprintf("blacklist-%d", item.ID), RuleName: item.Reason, Source: "blacklist", Scope: "agent_type", AgentTypeID: &typeID, DetectionType: item.DetectionType, Category: item.Category, Severity: item.Severity, Confidence: item.Confidence, Detail: item.Reason, Priority: item.Priority, Version: item.Version}, blacklistTarget: targetType}
		if r.metadata.RuleName == "" {
			r.metadata.RuleName = "命中 " + targetType + " 黑名单"
		}
		r.match = func(ev audit.BehaviorEvent) bool {
			for _, value := range blacklistValues(targetType, ev) {
				if value != "" && match(value) {
					return true
				}
			}
			return false
		}
		entry.rules = append(entry.rules, r)
	}
	sort.SliceStable(entry.rules, func(i, j int) bool { return entry.rules[i].metadata.Priority < entry.rules[j].metadata.Priority })
	if e.configCache == nil {
		e.configCache = map[int64]runtimeConfigEntry{}
	}
	e.configCache[typeID] = entry
	return entry, nil
}

func compilePattern(p audit.RuntimePattern) (func(string) bool, error) {
	if err := audit.ValidateRuntimePattern(p); err != nil {
		return nil, err
	}
	switch p.MatchType {
	case "exact":
		return func(s string) bool { return s == p.Value }, nil
	case "contains":
		return func(s string) bool { return strings.Contains(s, p.Value) }, nil
	case "prefix":
		return func(s string) bool { return strings.HasPrefix(s, p.Value) }, nil
	case "glob":
		// Portable wildcard syntax: * spans any characters (including path
		// separators), ? spans one. All other characters are literal.
		pattern := regexp.QuoteMeta(p.Value)
		pattern = strings.ReplaceAll(strings.ReplaceAll(pattern, `\*`, ".*"), `\?`, ".")
		r, err := regexp.Compile("(?s)^(?:" + pattern + ")$")
		if err != nil {
			return nil, err
		}
		return r.MatchString, nil
	default:
		r, err := regexp.Compile(p.Value)
		if err != nil {
			return nil, err
		}
		return r.MatchString, nil
	}
}

func compileEventMatcher(m audit.RuntimeMatcher) (func(audit.BehaviorEvent) bool, error) {
	if err := audit.ValidateRuntimeMatcher(m); err != nil {
		return nil, err
	}
	if m.Kind != "event_match" {
		return nil, fmt.Errorf("expected event_match")
	}
	type condition struct {
		pattern *audit.RuntimePattern
		value   func(audit.BehaviorEvent) string
	}
	conditions := []condition{
		{m.Target, func(e audit.BehaviorEvent) string { return e.Target }},
		{m.ToolName, func(e audit.BehaviorEvent) string { return e.ToolName }},
		{m.MCPServer, func(e audit.BehaviorEvent) string { return e.MCPServer }},
		{m.Detail, func(e audit.BehaviorEvent) string { return e.Detail }},
		{m.Path, func(e audit.BehaviorEvent) string { return e.Path }},
		{m.Operation, func(e audit.BehaviorEvent) string { return e.Operation }},
	}
	tests := []func(audit.BehaviorEvent) bool{}
	for _, c := range conditions {
		if c.pattern == nil {
			continue
		}
		match, err := compilePattern(*c.pattern)
		if err != nil {
			return nil, err
		}
		value := c.value
		tests = append(tests, func(ev audit.BehaviorEvent) bool { return match(value(ev)) })
	}
	return func(ev audit.BehaviorEvent) bool {
		if (m.EventType != "" && ev.EventType != m.EventType) || (m.EventCategory != "" && ev.EventCategory != m.EventCategory) || (m.EventSource != "" && ev.EventSource != m.EventSource) {
			return false
		}
		for _, test := range tests {
			if !test(ev) {
				return false
			}
		}
		return true
	}, nil
}

func blacklistValues(kind string, ev audit.BehaviorEvent) []string {
	attr := func(key string) string { value, _ := ev.Attributes[key].(string); return value }
	switch kind {
	case "tool":
		return []string{ev.ToolName}
	case "mcp":
		return []string{ev.MCPServer}
	case "path":
		values := []string{ev.Path, attr("path"), attr("file_path")}
		if ev.EventCategory == audit.RuntimeCategoryFile || ev.EventCategory == audit.RuntimeCategoryTool {
			values = append(values, ev.Target)
		}
		return values
	case "command":
		if ev.EventCategory != audit.RuntimeCategoryTool && ev.EventCategory != audit.RuntimeCategoryProcess {
			return nil
		}
		return []string{attr("command"), attr("command_line"), attr("commandLine"), ev.Target, ev.Detail}
	case "process":
		if ev.EventCategory != audit.RuntimeCategoryProcess {
			return nil
		}
		return []string{ev.ActorExecutable, ev.Target}
	case "url":
		return []string{ev.Target, attr("url")}
	case "domain":
		values := []string{}
		candidates := []string{attr("url"), attr("host"), attr("domain")}
		if ev.EventCategory == audit.RuntimeCategoryNetwork || strings.Contains(ev.Target, "://") || strings.HasPrefix(ev.Target, "//") {
			candidates = append(candidates, ev.Target)
		}
		for _, raw := range candidates {
			if raw == "" {
				continue
			}
			if !strings.Contains(raw, "://") {
				raw = "//" + raw
			}
			if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
				values = append(values, strings.ToLower(strings.TrimSuffix(parsed.Hostname(), ".")))
			}
		}
		return values
	}
	return nil
}

type RuntimeEvaluationMatch struct {
	RuleID      string          `json:"rule_id"`
	RuleVersion string          `json:"rule_version"`
	Source      string          `json:"source"`
	Detection   DetectionResult `json:"detection"`
}

type RuntimeEvaluation struct {
	Matched      bool                     `json:"matched"`
	MatchedRules []RuntimeEvaluationMatch `json:"matched_rules"`
	RiskScore    float64                  `json:"risk_score"`
	RiskLevel    string                   `json:"risk_level"`
	Decision     string                   `json:"decision"`
}

// EvaluatePreview runs the same configured rules and risk map as live
// evaluation. It neither inserts events/findings nor invokes an executor.
// Correlation context is explicit, so a hypothetical event cannot pull an
// unrelated session from storage.
func (e *Engine) EvaluatePreview(typeID int64, event audit.BehaviorEvent, window []audit.BehaviorEvent) (RuntimeEvaluation, error) {
	out := RuntimeEvaluation{MatchedRules: []RuntimeEvaluationMatch{}, RiskLevel: "LOW", Decision: audit.RuntimeDecisionAllow}
	entry, err := e.configured(typeID)
	if err != nil {
		return out, err
	}
	if strings.TrimSpace(event.EventType) == "" {
		return out, fmt.Errorf("event_type required")
	}
	now := time.Now().UTC()
	normalize := func(ev audit.BehaviorEvent, id int64) audit.BehaviorEvent {
		// Preview evidence IDs are temporary and negative; they cannot be
		// mistaken for persisted behavior_events rows or collide with one
		// another when callers omit IDs in a hypothetical correlation chain.
		ev.ID = id
		ev.EventType = strings.TrimSpace(ev.EventType)
		if ev.EventCategory == "" {
			ev.EventCategory = audit.RuntimeCategoryForEventType(ev.EventType)
		}
		if ev.EventSource == "" {
			ev.EventSource = audit.RuntimeSourceDesktop
		}
		if ev.Outcome == "" {
			ev.Outcome = "observed"
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = now
		}
		return ev
	}
	contextWindow := make([]audit.BehaviorEvent, 0, len(window)+1)
	for i, prior := range window {
		contextWindow = append(contextWindow, normalize(prior, -int64(i)-1))
	}
	event = normalize(event, -int64(len(window))-1)
	contextWindow = append(contextWindow, event)
	ctx := &EvalContext{Event: event, Window: contextWindow, Now: now, MaliciousResources: e.loadMaliciousResources()}
	for _, rule := range entry.rules {
		for _, res := range rule.Evaluate(ctx) {
			out.Matched = true
			out.MatchedRules = append(out.MatchedRules, RuntimeEvaluationMatch{RuleID: rule.ID(), RuleVersion: rule.Version(), Source: rule.metadata.Source, Detection: res})
			score := RiskScore(res.Severity, res.Category, res.Confidence)
			if score > out.RiskScore {
				out.RiskScore = score
			}
		}
	}
	if out.Matched {
		out.RiskLevel, out.Decision, out.RiskScore = entry.config.RiskPolicy.Evaluate(out.RiskScore)
	}
	return out, nil
}
