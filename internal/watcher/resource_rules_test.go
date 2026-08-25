// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
)

// seededWorkspaceRuleType finds a seeded agent type whose rules all expand
// from ${WORKSPACE_ROOT}, so tests can point the workspace anywhere (or at
// a nonexistent path) without hitting real HOME/CONFIG directories.
func seededWorkspaceRuleType(t *testing.T, store *audit.Store) (int64, []audit.AgentResourceRule) {
	t.Helper()
	for id := int64(1); id <= 80; id++ {
		rules, err := store.ListResourceRulesByAgentType(id)
		if err != nil || len(rules) == 0 {
			continue
		}
		allWorkspace := true
		for _, r := range rules {
			if !strings.Contains(r.PathPattern, "${WORKSPACE_ROOT}") {
				allWorkspace = false
				break
			}
		}
		if allWorkspace {
			return id, rules
		}
	}
	t.Fatal("no seeded ${WORKSPACE_ROOT}-only agent type found")
	return 0, nil
}

// Fallback semantics: an agent HAS enabled rules but they enumerate nothing
// (workspace root doesn't exist) — the empty result is authoritative and the
// legacy fixed-directory enumeration must NOT kick in and hunt elsewhere.
func TestEnumerateTargets_RulesExistButEmpty_NoLegacyFallback(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	// A real skill exists under the legacy directory.
	if err := os.MkdirAll(filepath.Join(skillDir, "legacy-skill"), 0o700); err != nil {
		t.Fatal(err)
	}

	typeID, _ := seededWorkspaceRuleType(t, store)
	if _, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:     "agentrange-fallback-test",
		AgentTypeID: typeID,
		AgentName:   "AgentRange Fallback Test",
		Source:      "test",
		Metadata:    map[string]any{"workspace_root": filepath.Join(t.TempDir(), "does-not-exist")},
	}); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

	_, anyRules := w.enumerateRuleDrivenTargets()
	if !anyRules {
		t.Fatal("expected anyRules=true: the agent has enabled rules")
	}

	for _, tgt := range w.enumerateTargets() {
		if strings.Contains(tgt.Path, "legacy-skill") {
			t.Fatalf("legacy enumeration must not run when rules exist (even if they enumerate nothing): found %s", tgt.Path)
		}
	}
}

// Fallback semantics: with no agents (and therefore no rules) anywhere, the
// legacy fixed-directory enumeration applies.
func TestEnumerateTargets_NoRules_LegacyFallback(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	if err := os.MkdirAll(filepath.Join(skillDir, "legacy-skill"), 0o700); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, shell, nil, nil, nil)

	_, anyRules := w.enumerateRuleDrivenTargets()
	if anyRules {
		t.Fatal("expected anyRules=false on a fresh store with no agents")
	}

	found := false
	for _, tgt := range w.enumerateTargets() {
		if strings.Contains(tgt.Path, "legacy-skill") {
			found = true
		}
	}
	if !found {
		t.Fatal("legacy enumeration expected when no rules exist")
	}
}

// Resource lifecycle: enumerated → disappeared (status=missing, row kept)
// → reappeared (resurrected to discovered).
func TestResourceLifecycle_MissingAndResurrection(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	workspace := t.TempDir()
	skills := filepath.Join(workspace, "skills")
	if err := os.MkdirAll(filepath.Join(skills, "skill-a"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(skills, "skill-b"), 0o700); err != nil {
		t.Fatal(err)
	}

	typeID, _ := seededWorkspaceRuleType(t, store)
	if _, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:     "agentrange-lifecycle-test",
		AgentTypeID: typeID,
		AgentName:   "AgentRange Lifecycle Test",
		Source:      "test",
		Metadata:    map[string]any{"workspace_root": workspace},
	}); err != nil {
		t.Fatal(err)
	}
	agents, err := store.ListActiveAgents()
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected 1 active agent, got %d (%v)", len(agents), err)
	}

	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	events := w.enumerateResourcesForAgent(agents[0])
	if len(events) != 2 {
		t.Fatalf("expected 2 skill resources, got %d", len(events))
	}
	byPath := map[string]InstallEvent{}
	for _, evt := range events {
		byPath[evt.Path] = evt
	}
	skillB := byPath[filepath.Join(skills, "skill-b")]
	if skillB.ResourceID == "" {
		t.Fatal("expected ResourceID on rule-produced event")
	}
	if status, _ := store.StaticResourceStatus(skillB.ResourceID); status != "discovered" {
		t.Fatalf("expected status=discovered, got %q", status)
	}

	// skill-b disappears: the next enumeration marks it missing; the row is
	// kept (not deleted) so the asset history stays complete.
	if err := os.RemoveAll(filepath.Join(skills, "skill-b")); err != nil {
		t.Fatal(err)
	}
	events2 := w.enumerateResourcesForAgent(agents[0])
	if len(events2) != 1 {
		t.Fatalf("expected 1 skill resource after removal, got %d", len(events2))
	}
	if status, _ := store.StaticResourceStatus(skillB.ResourceID); status != "missing" {
		t.Fatalf("expected status=missing for removed skill-b, got %q", status)
	}

	// skill-b comes back: the resource resurrects to discovered.
	if err := os.MkdirAll(filepath.Join(skills, "skill-b"), 0o700); err != nil {
		t.Fatal(err)
	}
	events3 := w.enumerateResourcesForAgent(agents[0])
	if len(events3) != 2 {
		t.Fatalf("expected 2 skill resources after resurrection, got %d", len(events3))
	}
	if status, _ := store.StaticResourceStatus(skillB.ResourceID); status != "discovered" {
		t.Fatalf("expected status=discovered after resurrection, got %q", status)
	}
}

// Realtime classification: fsnotify paths under a rule watch root produce
// lineage-carrying admission events, and Remove events flag the resource
// missing immediately.
func TestRuleEventClassification(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	workspace := t.TempDir()
	skills := filepath.Join(workspace, "skills")
	if err := os.MkdirAll(skills, 0o700); err != nil {
		t.Fatal(err)
	}

	typeID, _ := seededWorkspaceRuleType(t, store)
	if _, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:     "agentrange-rt-test",
		AgentTypeID: typeID,
		AgentName:   "AgentRange RT Test",
		Source:      "test",
		Metadata:    map[string]any{"workspace_root": workspace},
	}); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.ruleWatchContexts = w.buildResourceWatchContexts()
	if len(w.ruleWatchContexts) == 0 {
		t.Fatal("expected rule watch contexts from seeded rules")
	}

	// New skill dir appears under the rule root → admission event with the
	// full lineage and an ensured static_resources row.
	newSkill := filepath.Join(skills, "brand-new-skill")
	if err := os.MkdirAll(newSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	evt, ok := w.ruleEventForPath(newSkill)
	if !ok {
		t.Fatal("expected rule event for new child dir under rule root")
	}
	if evt.AgentID == "" || evt.Type != InstallSkill {
		t.Fatalf("unexpected event: %+v", evt)
	}
	if evt.ResourceID == "" || evt.ResourceRuleID == 0 {
		t.Fatalf("expected lineage on event: %+v", evt)
	}
	if evt.ScanProfileID == 0 {
		t.Fatalf("expected scan profile on event (seeded rules bind profiles): %+v", evt)
	}

	// A loose file directly under the root is not a children-mode resource.
	if err := os.WriteFile(filepath.Join(skills, "README.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.ruleEventForPath(filepath.Join(skills, "README.md")); ok {
		t.Fatal("loose file under children-mode root must not classify as a resource")
	}

	// Remove of the resource dir flags it missing immediately.
	if err := os.RemoveAll(newSkill); err != nil {
		t.Fatal(err)
	}
	if !w.markRemovedRuleResource(newSkill) {
		t.Fatal("expected Remove event to map onto the rule resource")
	}
	if status, _ := store.StaticResourceStatus(evt.ResourceID); status != "missing" {
		t.Fatalf("expected status=missing after Remove, got %q", status)
	}
}

// Malicious verdict priority: structured fields (RuleID prefix → Category →
// Tags → finding ID) decide; Title is only the legacy fallback. Rewording a
// title must never change the verdict.
func TestIsMaliciousFindingPriority(t *testing.T) {
	cases := []struct {
		name  string
		f     scanner.Finding
		want  bool
		reason string
	}{
		{
			name:  "rule id prefix (ClawShield malware family)",
			f:     scanner.Finding{RuleID: "CS-MAL-RS-DEVTCP", Severity: scanner.SeverityCritical},
			want:  true,
		},
		{
			name:  "structured category",
			f:     scanner.Finding{Category: "command_execution"},
			want:  true,
		},
		{
			name:  "category survives title rewording",
			f:     scanner.Finding{Category: "command_execution", Title: "Dangerous shell invocation"},
			want:  true,
		},
		{
			name:  "structured tag",
			f:     scanner.Finding{Tags: []string{"clawshield", "reverse_shell"}},
			want:  true,
		},
		{
			name:  "finding id prefix without rule id",
			f:     scanner.Finding{ID: "CS-MAL-MAGIC-ELF"},
			want:  true,
		},
		{
			name:  "title fallback keyword",
			f:     scanner.Finding{Title: "Possible command execution risk"},
			want:  true,
		},
		{
			name:  "benign title no structured fields",
			f:     scanner.Finding{Title: "Outdated dependency: requests 2.31"},
			want:  false,
		},
		{
			name:  "weak heuristic injection tag alone is not malicious",
			f:     scanner.Finding{Title: "Suspicious imperative verb density: 12.0%", Tags: []string{"injection", "statistical", "clawshield"}},
			want:  false,
		},
		{
			name:  "concrete injection pattern tag is malicious",
			f:     scanner.Finding{Title: "Prompt injection: instruction override attempt", Tags: []string{"injection", "instruction_injection", "clawshield"}},
			want:  true,
		},
		{
			name:  "risk-only finding stays non-malicious",
			f:     scanner.Finding{Category: "weak_config", Severity: scanner.SeverityMedium},
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMaliciousFinding(tc.f); got != tc.want {
				t.Fatalf("isMaliciousFinding(%+v) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
}

// The scanner fingerprint must include the scan profile: same kind, same
// target bytes, different profile ⇒ different fingerprint ⇒ re-scan.
func TestScannerFingerprint_IncludesScanProfile(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)

	plain := InstallEvent{Type: InstallSkill, Path: "x"}
	profiled := InstallEvent{Type: InstallSkill, Path: "x", ScanProfileID: 1}

	fpPlain := w.scannerFingerprint(plain)
	fpProfiled := w.scannerFingerprint(profiled)
	if fpPlain == "" || fpProfiled == "" {
		t.Fatal("expected non-empty fingerprints")
	}
	if fpPlain == fpProfiled {
		t.Fatal("fingerprint must change when a scan profile is attached")
	}
}
