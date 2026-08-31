// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ensureRuleTestAgent creates one agent row so static_resources FK targets
// exist, returning the canonical agent id.
func ensureRuleTestAgent(t *testing.T, store *Store, agentID string) string {
	t.Helper()
	agent, err := store.EnsureAgent(AgentIdentityInput{
		AgentID:   agentID,
		AgentName: agentID,
		Source:    "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if agent.ID == "" {
		t.Fatal("expected canonical agent id")
	}
	return agent.ID
}

// MarkMissingResources must only flip rule-produced rows whose last_seen_at
// predates the enumeration timestamp; legacy rows (no resource_rule_id) and
// re-observed rows stay untouched, and repeated sweeps are idempotent.
func TestMarkMissingResources(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentID := ensureRuleTestAgent(t, store, "mark-missing-test-agent")
	old := time.Now().UTC().Add(-time.Hour)
	fresh := time.Now().UTC()

	ruleResource, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "old-skill",
		Target:           filepath.Join("C:", "skills", "old-skill"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
		ObservedAt:       old,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyResource, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "config",
		Name:             "config.json",
		Target:           filepath.Join("C:", "agents", "config.json"),
		Source:           "test",
		ObservedAt:       old,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "fresh-skill",
		Target:           filepath.Join("C:", "skills", "fresh-skill"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
		ObservedAt:       fresh,
	}); err != nil {
		t.Fatal(err)
	}

	n, err := store.MarkMissingResources(agentID, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 row to flip to missing, got %d", n)
	}
	if status, _ := store.StaticResourceStatus(ruleResource); status != "missing" {
		t.Fatalf("rule resource should be missing, got %q", status)
	}
	if status, _ := store.StaticResourceStatus(legacyResource); status == "missing" {
		t.Fatal("legacy resource (no rule id) must never be marked missing by the rule sweep")
	}

	// Idempotent: a second sweep reports no new transitions.
	n, err = store.MarkMissingResources(agentID, fresh)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second sweep should mark nothing, got %d", n)
	}
}

// MarkResourceMissingByPath flags one precise row; a later
// EnsureStaticResource observation resurrects it to discovered.
func TestMarkResourceMissingByPath_Resurrection(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentID := ensureRuleTestAgent(t, store, "by-path-test-agent")
	target := filepath.Join("C:", "work", "skills", "gone-skill")
	resourceID, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "gone-skill",
		Target:           target,
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.MarkResourceMissingByPath(agentID, target); err != nil {
		t.Fatal(err)
	}
	if status, _ := store.StaticResourceStatus(resourceID); status != "missing" {
		t.Fatalf("expected missing, got %q", status)
	}

	// Re-observation resurrects the row (enumeration upsert path, no scan).
	if _, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "gone-skill",
		Target:           target,
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
	}); err != nil {
		t.Fatal(err)
	}
	if status, _ := store.StaticResourceStatus(resourceID); status != "discovered" {
		t.Fatalf("expected discovered after resurrection, got %q", status)
	}
}

// ScanProfileFingerprint covers the profile row + bound capabilities: it
// must be stable when nothing changes and change when a capability's
// config, the capability set, or the profile row changes — that change is
// what forces re-scans of byte-identical resources after admin edits.
func TestScanProfileFingerprint(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	// Seeded profile 1 (skill full) exists after migrations.
	fp1, err := store.ScanProfileFingerprint(1)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == "" || !strings.Contains(fp1, "cap=skill_security") {
		t.Fatalf("expected fingerprint with seeded capabilities, got %q", fp1)
	}

	// Stable when unchanged.
	fp1Again, err := store.ScanProfileFingerprint(1)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp1Again {
		t.Fatal("fingerprint must be stable when nothing changed")
	}

	// Capability config edit changes the fingerprint.
	if _, err := store.db.Exec(`UPDATE resource_scan_profile_capabilities
		SET config_json = '{"threshold": 0.9}' WHERE profile_id = 1 AND capability_id = (
			SELECT id FROM security_scan_capabilities WHERE capability_key = 'skill_security')`); err != nil {
		t.Fatal(err)
	}
	fpCfg, err := store.ScanProfileFingerprint(1)
	if err != nil {
		t.Fatal(err)
	}
	if fpCfg == fp1 {
		t.Fatal("capability config edit must change the fingerprint")
	}

	// Disabling a capability changes the fingerprint (detection plan shrank).
	if _, err := store.db.Exec(`UPDATE resource_scan_profile_capabilities
		SET enabled = 0 WHERE profile_id = 1 AND capability_id = (
			SELECT id FROM security_scan_capabilities WHERE capability_key = 'secret_detection')`); err != nil {
		t.Fatal(err)
	}
	fpDisabled, err := store.ScanProfileFingerprint(1)
	if err != nil {
		t.Fatal(err)
	}
	if fpDisabled == fpCfg {
		t.Fatal("disabling a capability must change the fingerprint")
	}
	if strings.Contains(fpDisabled, "cap=secret_detection") {
		t.Fatal("disabled capability must drop out of the fingerprint")
	}

	// Profile row edit (name) changes the fingerprint.
	if _, err := store.db.Exec(`UPDATE resource_scan_profiles SET name = 'skill-full-renamed' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	fpRenamed, err := store.ScanProfileFingerprint(1)
	if err != nil {
		t.Fatal(err)
	}
	if fpRenamed == fpDisabled {
		t.Fatal("profile row edit must change the fingerprint")
	}

	// Unknown profile yields "".
	if fp, err := store.ScanProfileFingerprint(99999); err != nil || fp != "" {
		t.Fatalf("unknown profile should yield empty fingerprint, got %q (%v)", fp, err)
	}
}

func TestListResourceRulesByAgentTypeReturnsDecisionProfiles(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentType, err := store.CreateGovernanceAgentType(GovernanceAgentTypeInput{
		TypeKey:     "decision-profile-test",
		Name:        "Decision Profile Test",
		Vendor:      "test",
		Kind:        "workspace",
		Runtime:     "local",
		Description: "test agent type",
		Enabled:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := store.CreateGovernancePreScanProfile(GovernancePreScanProfileInput{
		ProfileKey: "list-resource-rules-pre",
		Name:       "List Resource Rules Pre",
		Enabled:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	post, err := store.CreateGovernancePostScanProfile(GovernancePostScanProfileInput{
		ProfileKey: "list-resource-rules-post",
		Name:       "List Resource Rules Post",
		Enabled:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.CreateGovernanceResourceRule(GovernanceResourceRuleInput{
		AgentTypeID:       agentType.ID,
		Name:              "Prompts",
		ResourceType:      "prompt",
		PathPattern:       "${WORKSPACE_ROOT}/prompts/*.md",
		EnumerationMode:   "glob",
		ScanProfileID:     1,
		PreScanProfileID:  pre.ID,
		PostScanProfileID: post.ID,
		Enabled:           true,
		Priority:          10,
	})
	if err != nil {
		t.Fatal(err)
	}

	rules, err := store.ListResourceRulesByAgentType(agentType.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected one runtime resource rule, got %d", len(rules))
	}
	if rules[0].ID != created.ID || rules[0].PreScanProfileID != pre.ID || rules[0].PostScanProfileID != post.ID {
		t.Fatalf("expected pre/post profile lineage in runtime rule, got %+v", rules[0])
	}
}
