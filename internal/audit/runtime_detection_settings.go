// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
)

const RuntimeDetectionSettingsDomain = "runtime_detection_settings"

var (
	ErrRuntimeSettingsNotFound = errors.New("runtime detection settings: not found")
	ErrRuntimeSettingsConflict = errors.New("runtime detection settings: conflict")
)

// RuntimePattern uses Go's bounded RE2 implementation. Patterns and input
// lengths are limited independently; no expression evaluates executable code.
type RuntimePattern struct {
	MatchType string `json:"match_type"`
	Value     string `json:"value"`
}

type RuntimeMatcher struct {
	Kind          string          `json:"kind"`
	BuiltinRuleID string          `json:"builtin_rule_id,omitempty"`
	EventType     string          `json:"event_type,omitempty"`
	EventCategory string          `json:"event_category,omitempty"`
	EventSource   string          `json:"event_source,omitempty"`
	Target        *RuntimePattern `json:"target,omitempty"`
	ToolName      *RuntimePattern `json:"tool_name,omitempty"`
	MCPServer     *RuntimePattern `json:"mcp_server,omitempty"`
	Detail        *RuntimePattern `json:"detail,omitempty"`
	Path          *RuntimePattern `json:"path,omitempty"`
	Operation     *RuntimePattern `json:"operation,omitempty"`
}

type RuntimeDetectionRule struct {
	ID            int64          `json:"id"`
	RuleID        string         `json:"rule_id"`
	RuleName      string         `json:"rule_name"`
	Source        string         `json:"source"`
	Scope         string         `json:"scope"`
	AgentTypeID   *int64         `json:"agent_type_id"`
	DetectionType string         `json:"detection_type"`
	Category      string         `json:"category"`
	Severity      string         `json:"severity"`
	Confidence    float64        `json:"confidence"`
	Matcher       RuntimeMatcher `json:"matcher"`
	Detail        string         `json:"detail"`
	Remediation   string         `json:"remediation"`
	Priority      int            `json:"priority"`
	Enabled       bool           `json:"enabled"`
	System        bool           `json:"system"`
	Version       int            `json:"version"`
	// Unmodified builtins keep their event-dependent severity/confidence.
	OverrideSeverity   bool   `json:"override_severity"`
	OverrideConfidence bool   `json:"override_confidence"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
}

type RuntimeDetectionAgentTypeSettings struct {
	AgentTypeID         int64  `json:"agent_type_id"`
	Enabled             bool   `json:"enabled"`
	InheritGlobalRules  bool   `json:"inherit_global_rules"`
	UseGlobalRiskPolicy bool   `json:"use_global_risk_policy"`
	CustomRiskPolicyID  *int64 `json:"custom_risk_policy_id"`
	CreatedAt           string `json:"created_at"`
	UpdatedAt           string `json:"updated_at"`
}

type RuntimeDetectionBlacklistItem struct {
	ID            int64   `json:"id"`
	AgentTypeID   int64   `json:"agent_type_id"`
	TargetType    string  `json:"target_type"`
	MatchType     string  `json:"match_type"`
	Value         string  `json:"value"`
	DetectionType string  `json:"detection_type"`
	Category      string  `json:"category"`
	Severity      string  `json:"severity"`
	Confidence    float64 `json:"confidence"`
	Reason        string  `json:"reason"`
	Priority      int     `json:"priority"`
	Enabled       bool    `json:"enabled"`
	Version       int     `json:"version"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type RuntimeRiskPolicyRule struct {
	RiskLevel       string  `json:"risk_level"`
	MinScore        float64 `json:"min_score"`
	MaxScore        float64 `json:"max_score"`
	Decision        string  `json:"decision"`
	DisplayDecision string  `json:"display_decision"`
	Priority        int     `json:"priority"`
	Enabled         bool    `json:"enabled"`
}

type RuntimeRiskPolicy struct {
	PolicyID    int64                   `json:"policy_id"`
	PolicyKey   string                  `json:"policy_key"`
	Name        string                  `json:"name"`
	Scope       string                  `json:"scope"`
	AgentTypeID *int64                  `json:"agent_type_id"`
	Editable    bool                    `json:"editable"`
	Version     int                     `json:"version"`
	Rules       []RuntimeRiskPolicyRule `json:"rules"`
	UpdatedAt   string                  `json:"updated_at"`
}

type EffectiveRuntimeDetectionConfig struct {
	AgentTypeID         int64                           `json:"agent_type_id"`
	Enabled             bool                            `json:"enabled"`
	InheritGlobalRules  bool                            `json:"inherit_global_rules"`
	UseGlobalRiskPolicy bool                            `json:"use_global_risk_policy"`
	Rules               []RuntimeDetectionRule          `json:"rules"`
	Blacklist           []RuntimeDetectionBlacklistItem `json:"blacklist"`
	RiskPolicy          RuntimeRiskPolicy               `json:"risk_policy"`
}

func DefaultRuntimeRiskPolicyRules() []RuntimeRiskPolicyRule {
	return []RuntimeRiskPolicyRule{
		{RiskLevel: "LOW", MinScore: 0, MaxScore: .39, Decision: RuntimeDecisionAllow, DisplayDecision: "ALLOW", Enabled: true},
		{RiskLevel: "MEDIUM", MinScore: .4, MaxScore: .69, Decision: RuntimeDecisionAlert, DisplayDecision: "ALERT", Enabled: true},
		{RiskLevel: "HIGH", MinScore: .7, MaxScore: .89, Decision: RuntimeDecisionConfirm, DisplayDecision: "ASK", Enabled: true},
		{RiskLevel: "CRITICAL", MinScore: .9, MaxScore: 1, Decision: RuntimeDecisionBlock, DisplayDecision: "BLOCK", Enabled: true},
	}
}

// Risk policies operate on hundredths, as shown by the editor. Quantizing
// before interval selection avoids holes between .39 and .40 for raw scores.
func (p RuntimeRiskPolicy) Evaluate(score float64) (level, decision string, rounded float64) {
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return "unknown", RuntimeDecisionAlert, 0
	}
	rounded = math.Round(math.Max(0, math.Min(1, score))*100) / 100
	for _, r := range p.Rules {
		if r.Enabled && rounded >= r.MinScore && rounded <= r.MaxScore {
			return r.RiskLevel, r.Decision, rounded
		}
	}
	return "unknown", RuntimeDecisionAlert, rounded
}

func ValidateRuntimeRiskPolicy(rules []RuntimeRiskPolicyRule) error {
	if len(rules) != 4 {
		return fmt.Errorf("risk policy requires LOW, MEDIUM, HIGH and CRITICAL intervals")
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].MinScore < rules[j].MinScore })
	levels := map[string]bool{}
	next := 0
	for i := range rules {
		r := &rules[i]
		r.RiskLevel = strings.ToUpper(strings.TrimSpace(r.RiskLevel))
		r.Decision = strings.ToUpper(strings.TrimSpace(r.Decision))
		if r.Decision == "ASK" {
			r.Decision = RuntimeDecisionConfirm
		}
		if !oneOf(r.RiskLevel, "LOW", "MEDIUM", "HIGH", "CRITICAL") || levels[r.RiskLevel] {
			return fmt.Errorf("risk levels must occur exactly once")
		}
		levels[r.RiskLevel] = true
		if !oneOf(r.Decision, RuntimeDecisionAllow, RuntimeDecisionAlert, RuntimeDecisionConfirm, RuntimeDecisionBlock) {
			return fmt.Errorf("invalid risk decision %q", r.Decision)
		}
		if !r.Enabled || !validScore(r.MinScore) || !validScore(r.MaxScore) || r.MinScore > r.MaxScore {
			return fmt.Errorf("risk intervals must be enabled and within 0..1")
		}
		lo, hi := int(math.Round(r.MinScore*100)), int(math.Round(r.MaxScore*100))
		if math.Abs(r.MinScore*100-float64(lo)) > 1e-8 || math.Abs(r.MaxScore*100-float64(hi)) > 1e-8 {
			return fmt.Errorf("risk interval precision is two decimals")
		}
		if lo != next {
			return fmt.Errorf("risk intervals overlap or leave a gap at %.2f", float64(next)/100)
		}
		next = hi + 1
		r.DisplayDecision = r.Decision
		if r.Decision == RuntimeDecisionConfirm {
			r.DisplayDecision = "ASK"
		}
	}
	if next != 101 {
		return fmt.Errorf("risk intervals must cover 0.00 through 1.00")
	}
	return nil
}

func validScore(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 && v <= 1 }
func oneOf(v string, options ...string) bool {
	for _, o := range options {
		if v == o {
			return true
		}
	}
	return false
}

func ValidateRuntimePattern(p RuntimePattern) error {
	if p.Value == "" || len(p.Value) > 1024 {
		return fmt.Errorf("match value must contain 1..1024 bytes")
	}
	if !oneOf(p.MatchType, "exact", "contains", "prefix", "glob", "regex") {
		return fmt.Errorf("unsupported match_type %q", p.MatchType)
	}
	if p.MatchType == "regex" {
		if _, err := regexp.Compile(p.Value); err != nil {
			return fmt.Errorf("invalid RE2 regular expression: %w", err)
		}
	}
	return nil
}

func ValidateRuntimeMatcher(m RuntimeMatcher) error {
	if m.Kind == "builtin" {
		if m.BuiltinRuleID == "" {
			return fmt.Errorf("builtin_rule_id required")
		}
		return nil
	}
	if m.Kind != "event_match" || m.BuiltinRuleID != "" {
		return fmt.Errorf("custom matcher kind must be event_match")
	}
	conditions := 0
	for _, s := range []string{m.EventType, m.EventCategory, m.EventSource} {
		if len(s) > 128 {
			return fmt.Errorf("event selector exceeds 128 bytes")
		}
		if s != "" {
			conditions++
		}
	}
	for _, p := range []*RuntimePattern{m.Target, m.ToolName, m.MCPServer, m.Detail, m.Path, m.Operation} {
		if p != nil {
			conditions++
			if err := ValidateRuntimePattern(*p); err != nil {
				return err
			}
		}
	}
	if conditions == 0 {
		return fmt.Errorf("event_match requires at least one condition")
	}
	return nil
}

func ValidateRuntimeDetectionRule(r *RuntimeDetectionRule) error {
	r.RuleID = strings.TrimSpace(r.RuleID)
	r.RuleName = strings.TrimSpace(r.RuleName)
	if r.RuleID == "" || len(r.RuleID) > 128 || r.RuleName == "" || len(r.RuleName) > 256 {
		return fmt.Errorf("rule_id and rule_name required (128 / 256 byte limits)")
	}
	if !oneOf(r.Source, "builtin", "custom") {
		return fmt.Errorf("invalid rule source")
	}
	if r.Scope == "global" {
		if r.AgentTypeID != nil {
			return fmt.Errorf("global rules cannot have agent_type_id")
		}
	} else if r.Scope != "agent_type" || r.AgentTypeID == nil || *r.AgentTypeID <= 0 {
		return fmt.Errorf("agent_type scope requires a positive agent_type_id")
	}
	if r.Source == "builtin" && (!r.System || r.Scope != "global" || r.Matcher.Kind != "builtin") {
		return fmt.Errorf("invalid builtin rule scope")
	}
	if r.Source == "custom" && (r.System || r.Matcher.Kind != "event_match") {
		return fmt.Errorf("custom rules must use event_match")
	}
	if err := validateRuntimeVerdict(r.DetectionType, r.Category, &r.Severity, r.Confidence, r.Priority); err != nil {
		return err
	}
	if len(r.Detail) > 8192 || len(r.Remediation) > 8192 {
		return fmt.Errorf("rule description exceeds 8192 bytes")
	}
	return ValidateRuntimeMatcher(r.Matcher)
}

func ValidateRuntimeBlacklist(r *RuntimeDetectionBlacklistItem) error {
	if r.AgentTypeID <= 0 {
		return fmt.Errorf("agent_type_id required")
	}
	if !oneOf(r.TargetType, "command", "path", "tool", "mcp", "domain", "url", "process") {
		return fmt.Errorf("invalid blacklist target_type")
	}
	if len(r.Reason) > 8192 {
		return fmt.Errorf("blacklist reason exceeds 8192 bytes")
	}
	if err := validateRuntimeVerdict(r.DetectionType, r.Category, &r.Severity, r.Confidence, r.Priority); err != nil {
		return err
	}
	return ValidateRuntimePattern(RuntimePattern{MatchType: r.MatchType, Value: r.Value})
}

func validateRuntimeVerdict(kind, category string, severity *string, confidence float64, priority int) error {
	*severity = strings.ToUpper(strings.TrimSpace(*severity))
	if kind == "" || len(kind) > 128 {
		return fmt.Errorf("detection_type required (maximum 128 bytes)")
	}
	if !oneOf(category, "attack", "suspicious", "hygiene") {
		return fmt.Errorf("invalid detection category")
	}
	if !oneOf(*severity, "LOW", "MEDIUM", "HIGH", "CRITICAL") || !validScore(confidence) {
		return fmt.Errorf("invalid severity or confidence")
	}
	if priority < 0 || priority > 100000 {
		return fmt.Errorf("priority must be in 0..100000")
	}
	return nil
}

// DecodeRuntimeMatcher rejects unknown conditions rather than silently
// broadening a rule when an operator mistypes a field name.
func DecodeRuntimeMatcher(raw []byte) (RuntimeMatcher, error) {
	var m RuntimeMatcher
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, fmt.Errorf("matcher must contain exactly one JSON object")
	}
	return m, ValidateRuntimeMatcher(m)
}
