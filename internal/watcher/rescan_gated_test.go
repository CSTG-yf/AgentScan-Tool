// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// countingScanner is a scanner.Scanner test double that records how many times
// Scan was invoked so tests can assert the watcher only scans on real drift.
type countingScanner struct {
	name     string
	calls    int
	findings []scanner.Finding
}

func (s *countingScanner) Name() string               { return s.name }
func (s *countingScanner) Version() string            { return "fake-1" }
func (s *countingScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *countingScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.calls++
	return &scanner.ScanResult{
		Scanner:   s.name,
		Target:    target,
		Timestamp: time.Now().UTC(),
		Findings:  s.findings,
	}, nil
}

type typedCountingScanner struct {
	name       string
	targetType InstallType
	calls      map[InstallType]int
}

func (s *typedCountingScanner) Name() string               { return s.name }
func (s *typedCountingScanner) Version() string            { return "fake-1" }
func (s *typedCountingScanner) SupportedTargets() []string { return []string{string(s.targetType)} }

func (s *typedCountingScanner) Scan(_ context.Context, target string) (*scanner.ScanResult, error) {
	s.calls[s.targetType]++
	return &scanner.ScanResult{
		Scanner:   s.name,
		Target:    target,
		Timestamp: time.Now().UTC(),
	}, nil
}

func TestShouldRescan(t *testing.T) {
	const fp = "fingerprint-A"
	snap := &TargetSnapshot{ContentHash: "hash-1"}

	tests := []struct {
		name     string
		baseline *audit.SnapshotRow
		snap     *TargetSnapshot
		fp       string
		gated    bool
		want     bool
	}{
		{
			name:     "gating disabled always scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    false,
			want:     true,
		},
		{
			name:     "nil baseline scans",
			baseline: nil,
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "baseline without scan recovers",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "content changed scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-OLD", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "empty baseline content hash scans",
			baseline: &audit.SnapshotRow{ContentHash: "", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "fingerprint changed scans",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: "fingerprint-OLD"},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     true,
		},
		{
			name:     "unchanged skips",
			baseline: &audit.SnapshotRow{ContentHash: "hash-1", ScanID: "s1", ScannerFingerprint: fp},
			snap:     snap,
			fp:       fp,
			gated:    true,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := shouldRescan(tt.baseline, tt.snap, tt.fp, tt.gated)
			if got != tt.want {
				t.Fatalf("shouldRescan() = %v (%s), want %v", got, reason, tt.want)
			}
			if reason == "" {
				t.Error("shouldRescan() returned empty reason")
			}
		})
	}
}

func TestRescan_PreScanDecisionControlsScanner(t *testing.T) {
	tests := []struct {
		name      string
		decision  string
		wantCalls int
		want      rescanOutcome
		wantMark  bool
	}{
		{name: "block", decision: "block", wantCalls: 0, want: rescanSkipped, wantMark: true},
		{name: "skip", decision: "skip", wantCalls: 0, want: rescanSkipped, wantMark: true},
		{name: "scan", decision: "scan", wantCalls: 1, want: rescanScanned},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			installAction := "none"
			if tc.decision == "block" {
				installAction = "block"
			}
			profile, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
				ProfileKey: "rescan-pre-" + tc.name,
				Name:       "Rescan Pre " + tc.name,
				Enabled:    true,
				Rules: []audit.GovernancePreScanRuleInput{{
					RuleName:      "rescan " + tc.name,
					Priority:      1,
					ResourceType:  "prompt",
					PathPattern:   "*resource*",
					Decision:      tc.decision,
					InstallAction: installAction,
					FileAction:    "none",
					RuntimeAction: "allow",
					Enabled:       true,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}

			fake := &countingScanner{name: "rescan-decision-scanner"}
			w := New(cfg, nil, nil, store, logger, nil, nil, nil, nil)
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

			target := filepath.Join(t.TempDir(), "resource.prompt")
			if err := os.WriteFile(target, []byte("prompt"), 0o600); err != nil {
				t.Fatal(err)
			}
			outcome := w.rescanTarget(context.Background(), InstallEvent{
				Type:             InstallPrompt,
				Name:             filepath.Base(target),
				Path:             target,
				PreScanProfileID: profile.ID,
				Timestamp:        time.Now(),
			}, map[string]string{})

			if outcome != tc.want {
				t.Fatalf("rescan outcome = %v, want %v", outcome, tc.want)
			}
			if fake.calls != tc.wantCalls {
				t.Fatalf("scanner calls = %d, want %d", fake.calls, tc.wantCalls)
			}
			baseline, err := store.GetTargetSnapshot(string(InstallPrompt), target)
			if err != nil {
				t.Fatal(err)
			}
			hasMarker := strings.HasPrefix(baseline.ScanID, rescanPreScanSnapshotIDPrefix)
			if hasMarker != tc.wantMark {
				t.Fatalf("pre-scan snapshot marker = %v in %q, want %v", hasMarker, baseline.ScanID, tc.wantMark)
			}
		})
	}
}

func TestRescan_PreScanDisabledAndDeletedRulesFallbackToScanner(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	profile, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
		ProfileKey: "rescan-pre-disabled",
		Name:       "Rescan Pre Disabled",
		Enabled:    true,
		Rules: []audit.GovernancePreScanRuleInput{{
			RuleName:      "disabled block",
			Priority:      1,
			ResourceType:  "prompt",
			PathPattern:   "*",
			Decision:      "block",
			InstallAction: "block",
			RuntimeAction: "allow",
			Enabled:       false,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedRule, err := store.CreateGovernancePreScanRule(profile.ID, audit.GovernancePreScanRuleInput{
		RuleName:      "deleted block",
		Priority:      2,
		ResourceType:  "prompt",
		PathPattern:   "*",
		Decision:      "block",
		InstallAction: "block",
		RuntimeAction: "allow",
		Enabled:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.DeleteGovernancePreScanRule(deletedRule.ID); err != nil || !ok {
		t.Fatalf("delete pre-scan rule ok=%v err=%v", ok, err)
	}

	fake := &countingScanner{name: "rescan-decision-scanner"}
	w := New(cfg, nil, nil, store, logger, nil, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "fallback.prompt")
	if err := os.WriteFile(target, []byte("prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome := w.rescanTarget(context.Background(), InstallEvent{
		Type:             InstallPrompt,
		Name:             filepath.Base(target),
		Path:             target,
		PreScanProfileID: profile.ID,
		Timestamp:        time.Now(),
	}, map[string]string{})

	if outcome != rescanScanned {
		t.Fatalf("rescan outcome = %v, want %v", outcome, rescanScanned)
	}
	if fake.calls != 1 {
		t.Fatalf("disabled/deleted pre-scan rules must fall back to scanner, got %d calls", fake.calls)
	}
}

func TestRescan_PostScanDecisionAppliesAfterScanner(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	profile, err := store.CreateGovernancePostScanProfile(audit.GovernancePostScanProfileInput{
		ProfileKey: "rescan-post-block",
		Name:       "Rescan Post Block",
		Enabled:    true,
		Rules: []audit.GovernancePostScanRuleInput{{
			RuleName:        "critical malware block",
			Priority:        1,
			ResourceType:    "prompt",
			Severity:        "all",
			RiskLevel:       "critical",
			FindingCategory: "malware",
			Scanner:         "rescan-decision-scanner",
			Decision:        "block",
			InstallAction:   "block",
			FileAction:      "none",
			RuntimeAction:   "allow",
			Enabled:         true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	fake := &countingScanner{
		name: "rescan-decision-scanner",
		findings: []scanner.Finding{{
			Severity: scanner.SeverityLow,
			Category: "malware",
			Title:    "malware category should be critical by risk config",
		}},
	}
	w := New(cfg, nil, nil, store, logger, nil, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "malware.prompt")
	if err := os.WriteFile(target, []byte("prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome := w.rescanTarget(context.Background(), InstallEvent{
		Type:              InstallPrompt,
		Name:              filepath.Base(target),
		Path:              target,
		PostScanProfileID: profile.ID,
		Timestamp:         time.Now(),
	}, map[string]string{})

	if outcome != rescanScanned {
		t.Fatalf("rescan outcome = %v, want %v", outcome, rescanScanned)
	}
	if fake.calls != 1 {
		t.Fatalf("post-scan must run after scanner, got %d scanner calls", fake.calls)
	}
	blocked, err := store.HasAction(string(InstallPrompt), filepath.Base(target), "install", "block")
	if err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("expected post-scan block action to be persisted")
	}
}

func TestRescan_UpdatesStaticResourceRiskFromConfiguredRiskTables(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	agent, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:   "rescan-risk-agent",
		AgentName: "Rescan Risk Agent",
		Source:    "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "risk.prompt")
	if err := os.WriteFile(target, []byte("prompt"), 0o600); err != nil {
		t.Fatal(err)
	}
	resourceID, err := store.EnsureStaticResource(audit.StaticResourceInput{
		CanonicalAgentID: agent.ID,
		ResourceType:     "prompt",
		Name:             filepath.Base(target),
		Target:           target,
		Source:           "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	fake := &countingScanner{
		name: "rescan-decision-scanner",
		findings: []scanner.Finding{{
			Severity: scanner.SeverityLow,
			Category: "malware",
			Title:    "low severity finding mapped by category",
		}},
	}
	w := New(cfg, nil, nil, store, logger, nil, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	outcome := w.rescanTarget(context.Background(), InstallEvent{
		Type:       InstallPrompt,
		Name:       filepath.Base(target),
		Path:       target,
		AgentID:    agent.ID,
		ResourceID: resourceID,
		Timestamp:  time.Now(),
	}, map[string]string{})
	if outcome != rescanScanned {
		t.Fatalf("rescan outcome = %v, want %v", outcome, rescanScanned)
	}

	detail, err := store.GetStaticResourceDetail(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("expected static resource detail")
	}
	if detail.RiskLevel != "critical" {
		t.Fatalf("risk_level = %q, want critical", detail.RiskLevel)
	}
	if !detail.Malicious {
		t.Fatal("expected configured category risk to mark resource malicious")
	}
}

func TestScannerFingerprintStableAndChanges(t *testing.T) {
	// Empty PATH makes the best-effort `<binary> --version` probe fail
	// deterministically, so the fingerprint depends only on config + provenance.
	t.Setenv("PATH", "")

	cfg, _, _, _ := setupTestEnv(t)
	w := &InstallWatcher{cfg: cfg}
	evt := InstallEvent{Type: InstallSkill, Name: "demo", Path: "/skills/demo"}

	base := w.scannerFingerprint(evt)
	if base == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	if again := w.scannerFingerprint(evt); again != base {
		t.Fatalf("fingerprint not stable for identical config: %q != %q", again, base)
	}

	// A scan-affecting config change must change the fingerprint.
	cfg.Scanners.SkillScanner.UseLLM = !cfg.Scanners.SkillScanner.UseLLM
	if changed := w.scannerFingerprint(evt); changed == base {
		t.Error("fingerprint did not change after toggling use_llm")
	}

	// A different target kind must produce a different fingerprint.
	mcpEvt := InstallEvent{Type: InstallMCP, Name: "demo", Path: "demo"}
	if w.scannerFingerprint(mcpEvt) == base {
		t.Error("expected distinct fingerprint for MCP scanner kind")
	}
}

func TestRescanIntervalOverridesInheritGlobal(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanIntervalMin = 60
	cfg.Watch.RescanSkillIntervalMin = 5
	cfg.Watch.RescanMCPIntervalMin = 10
	cfg.Watch.RescanPromptIntervalMin = 15
	cfg.Watch.RescanCredentialIntervalMin = 3
	cfg.Watch.RescanEnvironmentIntervalMin = 20

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)

	if got := w.rescanIntervalFor(InstallSkill); got != 5*time.Minute {
		t.Fatalf("skill interval = %s, want 5m", got)
	}
	if got := w.rescanIntervalFor(InstallMCP); got != 10*time.Minute {
		t.Fatalf("mcp interval = %s, want 10m", got)
	}
	if got := w.rescanIntervalFor(InstallPlugin); got != 60*time.Minute {
		t.Fatalf("plugin interval = %s, want inherited 60m", got)
	}
	if got := w.rescanIntervalFor(InstallPrompt); got != 15*time.Minute {
		t.Fatalf("prompt interval = %s, want 15m", got)
	}
	if got := w.rescanIntervalFor(InstallCredential); got != 3*time.Minute {
		t.Fatalf("credential interval = %s, want 3m", got)
	}
	if got := w.rescanIntervalFor(InstallEnvironment); got != 20*time.Minute {
		t.Fatalf("environment interval = %s, want 20m", got)
	}

	schedules := w.rescanSchedules()
	if len(schedules) != 6 {
		t.Fatalf("schedules = %+v, want 6 interval groups", schedules)
	}
}

func TestRunRescanCycleForTypesFiltersTargets(t *testing.T) {
	t.Setenv("PATH", "")

	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = false

	skillPath := filepath.Join(skillDir, "demo-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "skill.py"), []byte("print('skill')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	pluginDir := filepath.Join(cfg.DataDir, "plugins")
	pluginPath := filepath.Join(pluginDir, "demo-plugin")
	if err := os.MkdirAll(pluginPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginPath, "package.json"), []byte(`{"name":"demo-plugin"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	ocData := `{"mcp":{"servers":{"demo-mcp":{"url":"https://example.com/mcp"}}}}`
	if err := os.WriteFile(ocPath, []byte(ocData), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	w := New(cfg, []string{skillDir}, []string{pluginDir}, store, logger, nil, nil, nil, nil)
	calls := map[InstallType]int{}
	w.scannerFactory = func(evt InstallEvent) scanner.Scanner {
		return &typedCountingScanner{name: string(evt.Type) + "-scanner", targetType: evt.Type, calls: calls}
	}

	w.runRescanCycleForTypes(context.Background(), InstallSkill)
	if calls[InstallSkill] != 1 {
		t.Fatalf("skill calls = %d, want 1", calls[InstallSkill])
	}
	if calls[InstallPlugin] != 0 || calls[InstallMCP] != 0 {
		t.Fatalf("unexpected non-skill calls: %+v", calls)
	}

	w.runRescanCycleForTypes(context.Background(), InstallPlugin, InstallMCP)
	if calls[InstallPlugin] != 1 {
		t.Fatalf("plugin calls = %d, want 1", calls[InstallPlugin])
	}
	if calls[InstallMCP] != 1 {
		t.Fatalf("mcp calls = %d, want 1", calls[InstallMCP])
	}
}

func TestEnumerateTargetsIncludesAuxiliaryStaticResources(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	if err := os.MkdirAll(cfg.PolicyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(cfg.PolicyDir, "rules.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dotenvPath := filepath.Join(cfg.DataDir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("OPENAI_API_KEY=sk-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)
	targets := w.enumerateTargets()

	seen := map[InstallType]bool{}
	for _, target := range targets {
		seen[target.Type] = true
	}

	for _, want := range []InstallType{InstallPrompt, InstallCredential, InstallEnvironment} {
		if !seen[want] {
			t.Fatalf("expected %s target in %+v", want, targets)
		}
	}
}

func TestEnumerateTargetsKeepsAuxiliaryWhenMCPConfigInvalid(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	t.Setenv("PATH", "")

	cfg.Claw.ConfigFile = filepath.Join(cfg.DataDir, "missing-openclaw.json")

	if err := os.MkdirAll(cfg.PolicyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(cfg.PolicyDir, "rules.yaml")
	if err := os.WriteFile(policyPath, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dotenvPath := filepath.Join(cfg.DataDir, ".env")
	if err := os.WriteFile(dotenvPath, []byte("OPENAI_API_KEY=sk-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)
	targets := w.enumerateTargets()

	seen := map[InstallType]bool{}
	for _, target := range targets {
		seen[target.Type] = true
	}

	for _, want := range []InstallType{InstallPrompt, InstallCredential, InstallEnvironment} {
		if !seen[want] {
			t.Fatalf("expected %s target despite invalid MCP config in %+v", want, targets)
		}
	}
}

func TestRescanCycleGatedSkipsUnchangedTargets(t *testing.T) {
	// Deterministic fingerprint probe (no real scanner binary on PATH).
	t.Setenv("PATH", "")

	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = true

	// Pin MCP enumeration to an empty server set so only the skill target
	// drives the cycle.
	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	skillPath := filepath.Join(skillDir, "demo-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join(skillPath, "skill.py")
	if err := os.WriteFile(scriptPath, []byte("print('v1')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)
	fake := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	ctx := context.Background()

	// First cycle establishes the baseline -> exactly one scan.
	w.runRescanCycleForTypes(ctx, InstallSkill)
	if fake.calls != 1 {
		t.Fatalf("after first cycle: scanner calls = %d, want 1", fake.calls)
	}

	// Repeated no-change cycles must not re-scan.
	for i := 0; i < 3; i++ {
		w.runRescanCycleForTypes(ctx, InstallSkill)
	}
	if fake.calls != 1 {
		t.Fatalf("after no-change cycles: scanner calls = %d, want 1", fake.calls)
	}

	// A content change triggers exactly one more scan.
	if err := os.WriteFile(scriptPath, []byte("print('v2 changed contents')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	w.runRescanCycleForTypes(ctx, InstallSkill)
	if fake.calls != 2 {
		t.Fatalf("after content change: scanner calls = %d, want 2", fake.calls)
	}

	// Stable again — no extra scan.
	w.runRescanCycleForTypes(ctx, InstallSkill)
	if fake.calls != 2 {
		t.Fatalf("after stable cycle: scanner calls = %d, want 2", fake.calls)
	}

	// A scanner fingerprint change (config toggle) re-scans byte-identical
	// content so updated rules take effect.
	cfg.Scanners.SkillScanner.UseLLM = !cfg.Scanners.SkillScanner.UseLLM
	w.runRescanCycleForTypes(ctx, InstallSkill)
	if fake.calls != 3 {
		t.Fatalf("after fingerprint change: scanner calls = %d, want 3", fake.calls)
	}
}

func TestRescanCycleUngatedScansEveryCycle(t *testing.T) {
	t.Setenv("PATH", "")

	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Watch.RescanContentGated = false

	ocPath := filepath.Join(cfg.DataDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(`{"mcp":{"servers":{}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Claw.ConfigFile = ocPath

	skillPath := filepath.Join(skillDir, "demo-skill")
	if err := os.MkdirAll(skillPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skillPath, "skill.py"), []byte("print('v1')\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil, nil)
	fake := &countingScanner{name: "skill-scanner"}
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		w.runRescanCycleForTypes(ctx, InstallSkill)
	}
	if fake.calls != 3 {
		t.Fatalf("ungated: scanner calls = %d, want 3 (one per cycle)", fake.calls)
	}
}
