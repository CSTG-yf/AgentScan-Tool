// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package detection

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func configurationAgent(t *testing.T, s *audit.Store, key string) (int64, string) {
	t.Helper()
	kind, err := s.CreateGovernanceAgentType(audit.GovernanceAgentTypeInput{TypeKey: key, Name: key, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	agent, err := s.EnsureAgent(audit.AgentIdentityInput{AgentID: key + "-instance", AgentTypeID: kind.ID, AgentName: key, Source: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return kind.ID, agent.ID
}

func TestConfiguredEngineLivePolicyAndPreviewDoNotWrite(t *testing.T) {
	s := newDetectionTestStore(t)
	typeID, agentID := configurationAgent(t, s, "configured-a")
	e := NewEngine(s, DefaultRules())
	settings, err := s.GetRuntimeDetectionAgentTypeSettings(typeID)
	if err != nil {
		t.Fatal(err)
	}
	settings.InheritGlobalRules = false
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(settings); err != nil {
		t.Fatal(err)
	}
	rule, err := s.SaveRuntimeDetectionRule(audit.RuntimeDetectionRule{RuleID: "custom-command", RuleName: "Custom command", Source: "custom", Scope: "agent_type", AgentTypeID: &typeID, DetectionType: "dangerous_command", Category: "attack", Severity: "HIGH", Confidence: .9, Enabled: true, Matcher: audit.RuntimeMatcher{Kind: "event_match", EventType: audit.RuntimeEventToolPreCall, ToolName: &audit.RuntimePattern{MatchType: "exact", Value: "shell"}, Target: &audit.RuntimePattern{MatchType: "contains", Value: "restricted"}}})
	if err != nil {
		t.Fatal(err)
	}
	riskRules := audit.DefaultRuntimeRiskPolicyRules()
	riskRules[2].Decision = audit.RuntimeDecisionBlock
	if err = s.SaveRuntimeRiskPolicy(typeID, false, "High blocks", riskRules); err != nil {
		t.Fatal(err)
	}
	if err = e.Policy().SetMode(audit.RuntimeSecurityModeAction); err != nil {
		t.Fatal(err)
	}
	before, err := s.ChangesSince(0, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.BehaviorEvent{EventType: audit.RuntimeEventToolPreCall, EventCategory: audit.RuntimeCategoryTool, CanonicalAgentID: agentID, ToolName: "shell", Target: "restricted command"}
	preview, err := e.EvaluatePreview(typeID, ev, nil)
	if err != nil || !preview.Matched || preview.Decision != audit.RuntimeDecisionBlock || len(preview.MatchedRules) != 1 {
		t.Fatalf("preview: %+v %v", preview, err)
	}
	if preview.MatchedRules[0].RuleID != rule.RuleID || !strings.Contains(preview.MatchedRules[0].RuleVersion, "v1") {
		t.Fatalf("rule provenance: %+v", preview)
	}
	changes, err := s.ChangesSince(before.NextCursor, nil, 100)
	if err != nil || changes.NextCursor != before.NextCursor {
		t.Fatalf("preview wrote data: %+v %v", changes, err)
	}
	events, err := s.ListBehaviorEvents(10)
	if err != nil || len(events) != 0 {
		t.Fatalf("preview events: %+v %v", events, err)
	}
	responses, err := s.ListResponseActionsAll(10, 0)
	if err != nil || len(responses) != 0 {
		t.Fatalf("preview responses: %+v %v", responses, err)
	}
	if err = e.Policy().SetMode(audit.RuntimeSecurityModeObserve); err != nil {
		t.Fatal(err)
	}
	fire(t, s, e, audit.RuntimeEventInput{EventType: ev.EventType, EventCategory: ev.EventCategory, EventSource: audit.RuntimeSourceAgentHook, CanonicalAgentID: agentID, SessionID: "configured-session", ToolName: ev.ToolName, Target: ev.Target})
	decisions, _, err := s.ListRuntimeDecisions(audit.RuntimeDecisionFilter{AgentID: agentID, Limit: 10})
	if err != nil || len(decisions) != 1 || decisions[0].Decision != preview.Decision || decisions[0].RiskScore != preview.RiskScore {
		t.Fatalf("live/preview mismatch: %+v %+v %v", decisions, preview, err)
	}
	if !strings.Contains(decisions[0].PolicyID, "agent-type-") || !strings.HasSuffix(decisions[0].PolicyID, ":v1") {
		t.Fatalf("policy identity: %+v", decisions[0])
	}
	responses, err = s.ListResponseActions(decisions[0].DecisionID)
	if err != nil || len(responses) != 1 || responses[0].Status != audit.ResponseStatusWouldBlock {
		t.Fatalf("observe response: %+v %v", responses, err)
	}
	// A policy edit with the same verdict must still retain its new version.
	// It must not retroactively rewrite the decision already recorded.
	if err = s.SaveRuntimeRiskPolicy(typeID, false, "High still blocks", riskRules); err != nil {
		t.Fatal(err)
	}
	fire(t, s, e, audit.RuntimeEventInput{EventType: ev.EventType, EventCategory: ev.EventCategory, EventSource: audit.RuntimeSourceAgentHook, CanonicalAgentID: agentID, SessionID: "configured-session", ToolName: ev.ToolName, Target: ev.Target})
	decisions, _, err = s.ListRuntimeDecisions(audit.RuntimeDecisionFilter{AgentID: agentID, Limit: 10})
	if err != nil || len(decisions) != 2 {
		t.Fatalf("policy versions deduplicated: %+v %v", decisions, err)
	}
	versions := map[string]bool{}
	for _, decision := range decisions {
		versions[decision.PolicyVersion] = true
	}
	if len(versions) != 2 {
		t.Fatalf("policy history not retained: %+v", decisions)
	}
}

func TestConfiguredEngineInventoryIsolationAndImmediateInvalidation(t *testing.T) {
	s := newDetectionTestStore(t)
	a, agentA := configurationAgent(t, s, "configured-a")
	b, agentB := configurationAgent(t, s, "configured-b")
	e := NewEngine(s, DefaultRules())
	settings, err := s.GetRuntimeDetectionAgentTypeSettings(a)
	if err != nil {
		t.Fatal(err)
	}
	settings.Enabled = false
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(settings); err != nil {
		t.Fatal(err)
	}
	fire(t, s, e, audit.RuntimeEventInput{EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail, CanonicalAgentID: agentA, Severity: "CRITICAL", Attributes: map[string]any{"agent_type_id": b}})
	items, err := s.ListRuntimeDetections(audit.RuntimeDetectionFilter{AgentID: agentA, Limit: 10})
	if err != nil || len(items) != 0 {
		t.Fatalf("untrusted type bypassed settings: %+v %v", items, err)
	}
	fire(t, s, e, audit.RuntimeEventInput{EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail, CanonicalAgentID: agentB, Severity: "CRITICAL", Attributes: map[string]any{"agent_type_id": a}})
	items, err = s.ListRuntimeDetections(audit.RuntimeDetectionFilter{AgentID: agentB, Limit: 10})
	if err != nil || len(items) != 1 || items[0].Severity != "CRITICAL" {
		t.Fatalf("builtin event severity not preserved: %+v %v", items, err)
	}
	rules, err := s.ListRuntimeDetectionRules(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rules {
		if r.RuleID == "prompt-injection" {
			r.Enabled = false
			if _, err = s.SaveRuntimeDetectionRule(r); err != nil {
				t.Fatal(err)
			}
		}
	}
	preview, err := e.EvaluatePreview(b, audit.BehaviorEvent{EventType: audit.RuntimeEventContentInjection, Severity: "CRITICAL"}, nil)
	if err != nil || preview.Matched {
		t.Fatalf("stale enabled rule after save: %+v %v", preview, err)
	}
	settings.Enabled = true
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(settings); err != nil {
		t.Fatal(err)
	}
	item, err := s.SaveRuntimeBlacklist(audit.RuntimeDetectionBlacklistItem{AgentTypeID: a, TargetType: "path", MatchType: "glob", Value: `C:\secret\*`, DetectionType: "blacklisted_path", Category: "attack", Severity: "CRITICAL", Confidence: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	pathEvent := audit.BehaviorEvent{EventType: audit.RuntimeEventFileRead, EventCategory: audit.RuntimeCategoryFile, Path: `C:\secret\nested\token.txt`}
	preview, err = e.EvaluatePreview(a, pathEvent, nil)
	if err != nil || !preview.Matched {
		t.Fatalf("blacklist save not active: %+v %v", preview, err)
	}
	preview, err = e.EvaluatePreview(b, pathEvent, nil)
	if err != nil || preview.Matched {
		t.Fatalf("cross-type blacklist: %+v %v", preview, err)
	}
	if err = s.DeleteRuntimeBlacklist(a, item.ID); err != nil {
		t.Fatal(err)
	}
	preview, err = e.EvaluatePreview(a, pathEvent, nil)
	if err != nil || preview.Matched {
		t.Fatalf("deleted blacklist still active: %+v %v", preview, err)
	}
}

func TestConfiguredEngineRuleRevisionPreservesHistoricalVerdict(t *testing.T) {
	s := newDetectionTestStore(t)
	_, agent := configurationAgent(t, s, "configured-version")
	e := NewEngine(s, []Rule{NewPromptInjectionRule()})
	input := audit.RuntimeEventInput{EventType: audit.RuntimeEventContentInjection, EventSource: audit.RuntimeSourceGuardrail, CanonicalAgentID: agent, SessionID: "version-session", Severity: "CRITICAL"}
	fire(t, s, e, input)
	rules, err := s.ListRuntimeDetectionRules(0)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules: %+v %v", rules, err)
	}
	r := rules[0]
	r.Severity = "LOW"
	r.Confidence = .1
	if _, err = s.SaveRuntimeDetectionRule(r); err != nil {
		t.Fatal(err)
	}
	items, err := s.ListRuntimeDetections(audit.RuntimeDetectionFilter{AgentID: agent, Limit: 10})
	if err != nil || len(items) != 1 || items[0].Severity != "CRITICAL" {
		t.Fatalf("save rewrote history: %+v %v", items, err)
	}
	fire(t, s, e, input)
	items, err = s.ListRuntimeDetections(audit.RuntimeDetectionFilter{AgentID: agent, Limit: 10})
	if err != nil || len(items) != 2 {
		t.Fatalf("versions merged: %+v %v", items, err)
	}
	severities := map[string]bool{}
	versions := map[string]bool{}
	for _, d := range items {
		severities[d.Severity] = true
		versions[d.RuleVersion] = true
	}
	if !severities["LOW"] || !severities["CRITICAL"] || len(versions) != 2 {
		t.Fatalf("version evidence: %+v", items)
	}
}

func TestConfiguredMatcherConjunctionAndPortablePatterns(t *testing.T) {
	for _, tc := range []struct {
		kind, value, input string
		want               bool
	}{
		{"exact", "abc", "abc", true}, {"exact", "abc", "xabc", false},
		{"contains", "abc", "xabcx", true}, {"prefix", "abc", "abcx", true}, {"prefix", "abc", "xabc", false},
		{"glob", `C:\secret\*.?xt`, `C:\secret\nested\token.txt`, true},
		{"glob", "a.b*", "axb", false}, {"regex", `^curl\s+https://`, "curl https://test", true},
	} {
		match, err := compilePattern(audit.RuntimePattern{MatchType: tc.kind, Value: tc.value})
		if err != nil || match(tc.input) != tc.want {
			t.Errorf("%+v: %v", tc, err)
		}
	}
	match, err := compileEventMatcher(audit.RuntimeMatcher{Kind: "event_match", EventType: audit.RuntimeEventToolPreCall, EventCategory: "tool", EventSource: "agent_hook", ToolName: &audit.RuntimePattern{MatchType: "exact", Value: "shell"}, Target: &audit.RuntimePattern{MatchType: "prefix", Value: "curl "}})
	if err != nil {
		t.Fatal(err)
	}
	ev := audit.BehaviorEvent{EventType: audit.RuntimeEventToolPreCall, EventCategory: "tool", EventSource: "agent_hook", ToolName: "shell", Target: "curl https://test"}
	if !match(ev) {
		t.Fatal("all conditions failed")
	}
	ev.ToolName = "read"
	if match(ev) {
		t.Fatal("conjunction treated as disjunction")
	}
	got := blacklistValues("domain", audit.BehaviorEvent{Target: "https://Example.TEST.:8443/a"})
	if !reflect.DeepEqual(got, []string{"example.test"}) {
		t.Fatalf("domain extraction: %+v", got)
	}
}
