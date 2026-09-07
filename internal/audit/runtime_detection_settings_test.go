// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"math"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func runtimeSettingsTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "settings.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	return s
}

func runtimeSettingsTestType(t *testing.T, s *Store, key string) int64 {
	t.Helper()
	r, err := s.CreateGovernanceAgentType(GovernanceAgentTypeInput{TypeKey: key, Name: key, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func runtimeSettingsTestRule(key string, typeID int64) RuntimeDetectionRule {
	r := RuntimeDetectionRule{RuleID: key, RuleName: key, Source: "custom", Scope: "global", DetectionType: "dangerous_command", Category: "attack", Severity: "HIGH", Confidence: .9, Enabled: true, Priority: 100, Matcher: RuntimeMatcher{Kind: "event_match", EventType: "tool.pre_call"}}
	if typeID > 0 {
		r.Scope = "agent_type"
		r.AgentTypeID = &typeID
	}
	return r
}

func TestRuntimeSettingsRuleOwnershipAndVersions(t *testing.T) {
	s := runtimeSettingsTestStore(t)
	a, b := runtimeSettingsTestType(t, s, "type-a"), runtimeSettingsTestType(t, s, "type-b")
	r, err := s.SaveRuntimeDetectionRule(runtimeSettingsTestRule("same-id", a))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveRuntimeDetectionRule(runtimeSettingsTestRule("same-id", b)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveRuntimeDetectionRule(runtimeSettingsTestRule("same-id", a)); !errors.Is(err, ErrRuntimeSettingsConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err = s.GetRuntimeDetectionRule(b, r.ID); !errors.Is(err, ErrRuntimeSettingsNotFound) {
		t.Fatalf("cross-type read: %v", err)
	}
	if err = s.DeleteRuntimeDetectionRule(b, r.ID); !errors.Is(err, ErrRuntimeSettingsNotFound) {
		t.Fatalf("cross-type delete: %v", err)
	}
	stale := r
	r.Enabled = false
	r, err = s.SaveRuntimeDetectionRule(r)
	if err != nil || r.Version != 2 {
		t.Fatalf("update: %+v %v", r, err)
	}
	if _, err = s.SaveRuntimeDetectionRule(stale); !errors.Is(err, ErrRuntimeSettingsConflict) {
		t.Fatalf("stale save: %v", err)
	}
	if err = s.DeleteRuntimeDetectionRule(a, r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.GetRuntimeDetectionRule(a, r.ID); !errors.Is(err, ErrRuntimeSettingsNotFound) {
		t.Fatalf("deleted visible: %v", err)
	}
	var deleted, version int
	if err = s.db.QueryRow(`SELECT "delete",version FROM runtime_detection_rules WHERE id=?`, r.ID).Scan(&deleted, &version); err != nil || deleted != 1 || version != 3 {
		t.Fatalf("soft delete: %d %d %v", deleted, version, err)
	}
}

func TestRuntimeSettingsBuiltinSurvivesRestartWithoutResurrection(t *testing.T) {
	s := runtimeSettingsTestStore(t)
	seed := runtimeSettingsTestRule("builtin-command", 0)
	seed.Source = "builtin"
	seed.System = true
	seed.Matcher = RuntimeMatcher{Kind: "builtin", BuiltinRuleID: seed.RuleID}
	if err := s.EnsureRuntimeBuiltinRules([]RuntimeDetectionRule{seed}); err != nil {
		t.Fatal(err)
	}
	rules, err := s.ListRuntimeDetectionRules(0)
	if err != nil || len(rules) != 1 {
		t.Fatalf("seed: %+v %v", rules, err)
	}
	r := rules[0]
	edited := r
	edited.RuleID = "changed"
	if _, err = s.SaveRuntimeDetectionRule(edited); err == nil {
		t.Fatal("builtin identity edited")
	}
	r.Severity = "CRITICAL"
	r.Confidence = .99
	r, err = s.SaveRuntimeDetectionRule(r)
	if err != nil || !r.OverrideSeverity || !r.OverrideConfidence {
		t.Fatalf("overrides: %+v %v", r, err)
	}
	if err = s.DeleteRuntimeDetectionRule(0, r.ID); err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	if err = s.EnsureRuntimeBuiltinRules([]RuntimeDetectionRule{seed}); err != nil {
		t.Fatal(err)
	}
	r, err = s.GetRuntimeDetectionRule(0, r.ID)
	if err != nil || r.Enabled || r.Severity != "CRITICAL" || r.Version != 3 {
		t.Fatalf("restart reset builtin: %+v %v", r, err)
	}
	policy, err := s.GetRuntimeRiskPolicy(0)
	if err != nil || policy.Editable || len(policy.Rules) != 4 {
		t.Fatalf("global policy: %+v %v", policy, err)
	}
}

func TestRuntimeSettingsEffectiveInheritanceAndBlacklist(t *testing.T) {
	s := runtimeSettingsTestStore(t)
	a, b := runtimeSettingsTestType(t, s, "type-a"), runtimeSettingsTestType(t, s, "type-b")
	for _, r := range []RuntimeDetectionRule{runtimeSettingsTestRule("global", 0), runtimeSettingsTestRule("specific", a)} {
		if _, err := s.SaveRuntimeDetectionRule(r); err != nil {
			t.Fatal(err)
		}
	}
	item, err := s.SaveRuntimeBlacklist(RuntimeDetectionBlacklistItem{AgentTypeID: a, TargetType: "command", MatchType: "contains", Value: "danger", DetectionType: "blacklisted_command", Category: "attack", Severity: "CRITICAL", Confidence: 1, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	assertConfig := func(id int64, enabled bool, rules, blacklist int) {
		t.Helper()
		c, err := s.EffectiveRuntimeDetectionConfig(id)
		if err != nil || c.Enabled != enabled || len(c.Rules) != rules || len(c.Blacklist) != blacklist {
			t.Fatalf("type %d: %+v %v", id, c, err)
		}
	}
	assertConfig(0, true, 1, 0)
	assertConfig(a, true, 2, 1)
	assertConfig(b, true, 1, 0)
	settings, err := s.GetRuntimeDetectionAgentTypeSettings(a)
	if err != nil {
		t.Fatal(err)
	}
	settings.InheritGlobalRules = false
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(settings); err != nil {
		t.Fatal(err)
	}
	assertConfig(a, true, 1, 1)
	if err = s.DeleteRuntimeBlacklist(b, item.ID); !errors.Is(err, ErrRuntimeSettingsNotFound) {
		t.Fatalf("blacklist isolation: %v", err)
	}
	item.Enabled = false
	if _, err = s.SaveRuntimeBlacklist(item); err != nil {
		t.Fatal(err)
	}
	assertConfig(a, true, 1, 0)
	settings.Enabled = false
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(settings); err != nil {
		t.Fatal(err)
	}
	assertConfig(a, false, 0, 0)
	assertConfig(b, true, 1, 0)
	if _, err = s.SaveRuntimeDetectionAgentTypeSettings(RuntimeDetectionAgentTypeSettings{Enabled: true, UseGlobalRiskPolicy: true}); !errors.Is(err, ErrRuntimeSettingsNotFound) {
		t.Fatalf("type zero write: %v", err)
	}
}

func TestRuntimeSettingsRiskPolicyAtomicityAndChangeEvidence(t *testing.T) {
	s := runtimeSettingsTestStore(t)
	id := runtimeSettingsTestType(t, s, "type-a")
	before, err := s.ChangesSince(0, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	revision := s.RuntimeSettingsRevision()
	rules := DefaultRuntimeRiskPolicyRules()
	rules[2].Decision = "ASK"
	if err = s.SaveRuntimeRiskPolicy(id, false, "Custom", rules); err != nil {
		t.Fatal(err)
	}
	c, err := s.EffectiveRuntimeDetectionConfig(id)
	if err != nil || c.UseGlobalRiskPolicy || !c.RiskPolicy.Editable || c.RiskPolicy.Rules[2].Decision != RuntimeDecisionConfirm {
		t.Fatalf("custom policy: %+v %v", c, err)
	}
	if s.RuntimeSettingsRevision() != revision+1 {
		t.Fatal("cache invalidation missing")
	}
	changes, err := s.ChangesSince(before.NextCursor, []string{RuntimeDetectionSettingsDomain}, 100)
	if err != nil || !reflect.DeepEqual(changes.ChangedDomains, []string{RuntimeDetectionSettingsDomain}) {
		t.Fatalf("change cursor: %+v %v", changes, err)
	}
	var count int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE actor='runtime-detection-settings' AND action=?`, string(ActionConfigUpdate)).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit: %d %v", count, err)
	}
	if err = s.SaveRuntimeRiskPolicy(id, true, "", nil); err != nil {
		t.Fatal(err)
	}
	before, err = s.ChangesSince(0, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	revision = s.RuntimeSettingsRevision()
	rules[1].MinScore = .3
	if err = s.SaveRuntimeRiskPolicy(id, false, "Bad", rules); err == nil {
		t.Fatal("overlap accepted")
	}
	settings, err := s.GetRuntimeDetectionAgentTypeSettings(id)
	if err != nil || !settings.UseGlobalRiskPolicy {
		t.Fatalf("failed save changed inheritance: %+v %v", settings, err)
	}
	p, err := s.GetRuntimeRiskPolicy(id)
	if err != nil || p.Name != "Custom" || p.Version != 1 {
		t.Fatalf("failed save changed policy: %+v %v", p, err)
	}
	changes, err = s.ChangesSince(before.NextCursor, []string{RuntimeDetectionSettingsDomain}, 100)
	if err != nil || len(changes.ChangedDomains) != 0 || s.RuntimeSettingsRevision() != revision {
		t.Fatalf("failed save emitted changes: %+v %v", changes, err)
	}
	if err = s.SaveRuntimeRiskPolicy(0, false, "Mutated", DefaultRuntimeRiskPolicyRules()); err == nil {
		t.Fatal("global risk policy was writable")
	}
}

func TestRuntimeSettingsRiskBoundariesAndInvalidMatchers(t *testing.T) {
	p := RuntimeRiskPolicy{Rules: DefaultRuntimeRiskPolicyRules()}
	for _, tc := range []struct {
		score float64
		want  string
	}{{0, "ALLOW"}, {.39, "ALLOW"}, {.395, "ALERT"}, {.69, "ALERT"}, {.7, "CONFIRM"}, {.89, "CONFIRM"}, {.9, "BLOCK"}, {1, "BLOCK"}} {
		_, got, _ := p.Evaluate(tc.score)
		if got != tc.want {
			t.Errorf("score %g: %s want %s", tc.score, got, tc.want)
		}
	}
	for _, mutate := range []func([]RuntimeRiskPolicyRule){func(r []RuntimeRiskPolicyRule) { r[1].MinScore = .41 }, func(r []RuntimeRiskPolicyRule) { r[0].MaxScore = .4 }, func(r []RuntimeRiskPolicyRule) { r[3].MaxScore = .99 }, func(r []RuntimeRiskPolicyRule) { r[0].MinScore = math.NaN() }, func(r []RuntimeRiskPolicyRule) { r[0].Decision = "EXECUTE" }, func(r []RuntimeRiskPolicyRule) { r[1].Enabled = false }} {
		r := DefaultRuntimeRiskPolicyRules()
		mutate(r)
		if ValidateRuntimeRiskPolicy(r) == nil {
			t.Errorf("invalid risk policy accepted: %+v", r)
		}
	}
	for _, raw := range []string{`{"kind":"event_match"}`, `{"kind":"event_match","unknown":"x"}`, `{"kind":"event_match","target":{"match_type":"regex","value":"["}}`, `{"kind":"event_match","event_type":"tool.pre_call"} {}`} {
		if _, err := DecodeRuntimeMatcher([]byte(raw)); err == nil {
			t.Errorf("invalid matcher accepted: %s", raw)
		}
	}
}

func TestRuntimeSettingsAuditFailureRollsBackConfiguration(t *testing.T) {
	s := runtimeSettingsTestStore(t)
	before, err := s.ChangesSince(0, nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	revision := s.RuntimeSettingsRevision()
	_, err = s.db.Exec(`CREATE TRIGGER reject_settings_audit BEFORE INSERT ON audit_events WHEN NEW.actor='runtime-detection-settings' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.SaveRuntimeDetectionRule(runtimeSettingsTestRule("must-rollback", 0)); err == nil {
		t.Fatal("save succeeded without audit evidence")
	}
	rules, err := s.ListRuntimeDetectionRules(0)
	if err != nil || len(rules) != 0 {
		t.Fatalf("partial configuration save: %+v %v", rules, err)
	}
	changes, err := s.ChangesSince(before.NextCursor, nil, 100)
	if err != nil || changes.NextCursor != before.NextCursor || s.RuntimeSettingsRevision() != revision {
		t.Fatalf("rolled-back mutation emitted invalidation: %+v %v", changes, err)
	}
}

func TestRuntimeSettingsUpgradePreservesExistingInventoryAndEvents(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "upgrade.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err = s.db.Exec(`CREATE TABLE schema_version(version INTEGER PRIMARY KEY,applied_at DATETIME NOT NULL,"delete" INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, m := range migrations {
		if strings.HasPrefix(m.description, "runtime detection settings:") {
			found = true
			break
		}
		if err = s.applyMigration(i+1, m); err != nil {
			t.Fatal(err)
		}
	}
	if !found {
		t.Fatal("runtime settings migration missing")
	}
	typeID := runtimeSettingsTestType(t, s, "before-upgrade")
	agent, err := s.EnsureAgent(AgentIdentityInput{AgentID: "before-upgrade-instance", AgentTypeID: typeID, AgentName: "Before upgrade"})
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := s.RecordRuntimeEvent(RuntimeEventInput{CanonicalAgentID: agent.ID, EventType: RuntimeEventToolPreCall, ToolName: "read", Target: "report.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	event, ok, err := s.GetRuntimeEvent(eventID)
	if err != nil || !ok || event.Target != "report.txt" || event.CanonicalAgentID != agent.ID {
		t.Fatalf("upgrade altered event: %+v %v", event, err)
	}
	resolved, err := s.RuntimeAgentTypeID(agent.ID)
	if err != nil || resolved != typeID {
		t.Fatalf("upgrade altered type: %d %v", resolved, err)
	}
	config, err := s.EffectiveRuntimeDetectionConfig(typeID)
	if err != nil || !config.Enabled || !config.InheritGlobalRules || !config.UseGlobalRiskPolicy || len(config.RiskPolicy.Rules) != 4 {
		t.Fatalf("upgrade defaults: %+v %v", config, err)
	}
	version, err := s.SchemaVersion()
	if err != nil || version != len(migrations) {
		t.Fatalf("migration version: %d %v", version, err)
	}
}
