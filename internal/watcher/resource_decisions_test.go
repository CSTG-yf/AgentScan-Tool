// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestAdmission_PreScanBlockSkipsScanner(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	profile, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
		ProfileKey:  "test-pre-block",
		Name:        "Test Pre Block",
		Description: "blocks prompts before scanner invocation",
		Enabled:     true,
		Rules: []audit.GovernancePreScanRuleInput{{
			RuleName:      "block prompt",
			Priority:      1,
			ResourceType:  "prompt",
			PathPattern:   "*blocked*",
			Decision:      "block",
			InstallAction: "block",
			FileAction:    "none",
			RuntimeAction: "allow",
			Enabled:       true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	fake := &countingScanner{name: "decision-scanner"}
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "blocked.prompt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{
		Type:             InstallPrompt,
		Name:             filepath.Base(target),
		Path:             target,
		PreScanProfileID: profile.ID,
		Timestamp:        time.Now(),
	})

	if result.Verdict != VerdictBlocked {
		t.Fatalf("expected pre-scan block verdict, got %q (%s)", result.Verdict, result.Reason)
	}
	if fake.calls != 0 {
		t.Fatalf("pre-scan block must skip scanner, got %d calls", fake.calls)
	}
}

func TestAdmission_PreScanScanContinuesToScanner(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	profile, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
		ProfileKey: "test-pre-scan",
		Name:       "Test Pre Scan",
		Enabled:    true,
		Rules: []audit.GovernancePreScanRuleInput{{
			RuleName:      "scan prompt",
			Priority:      1,
			ResourceType:  "prompt",
			PathPattern:   "*",
			Decision:      "scan",
			InstallAction: "none",
			FileAction:    "none",
			RuntimeAction: "allow",
			Enabled:       true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	fake := &countingScanner{name: "decision-scanner"}
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "scan.prompt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{
		Type:             InstallPrompt,
		Name:             filepath.Base(target),
		Path:             target,
		PreScanProfileID: profile.ID,
		Timestamp:        time.Now(),
	})

	if fake.calls != 1 {
		t.Fatalf("pre-scan scan must invoke scanner once, got %d calls", fake.calls)
	}
	if result.Verdict != VerdictClean {
		t.Fatalf("expected clean after empty scan result, got %q (%s)", result.Verdict, result.Reason)
	}
}

func TestAdmission_PreScanDisabledAndDeletedRulesDoNotApply(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	profile, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
		ProfileKey: "test-pre-disabled",
		Name:       "Test Pre Disabled",
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

	fake := &countingScanner{name: "decision-scanner"}
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "not-blocked.prompt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{
		Type:             InstallPrompt,
		Name:             filepath.Base(target),
		Path:             target,
		PreScanProfileID: profile.ID,
		Timestamp:        time.Now(),
	})

	if fake.calls != 1 {
		t.Fatalf("disabled/deleted rules must not stop scanning, got %d scanner calls", fake.calls)
	}
	if result.Verdict != VerdictClean {
		t.Fatalf("expected legacy fallback clean when no DB rule matches, got %q (%s)", result.Verdict, result.Reason)
	}
}

func TestAdmission_PostScanRulesMatchSeverityRiskCategoryAndScanner(t *testing.T) {
	tests := []struct {
		name        string
		rule        audit.GovernancePostScanRuleInput
		finding     scanner.Finding
		wantVerdict Verdict
	}{
		{
			name: "severity and risk",
			rule: audit.GovernancePostScanRuleInput{
				RuleName:      "high risk block",
				Priority:      1,
				ResourceType:  "prompt",
				Severity:      "HIGH",
				RiskLevel:     "high",
				Decision:      "block",
				InstallAction: "block",
				FileAction:    "quarantine",
				RuntimeAction: "block",
				Enabled:       true,
			},
			finding:     scanner.Finding{Severity: scanner.SeverityHigh, Category: "weak_config", Title: "High risk"},
			wantVerdict: VerdictRejected,
		},
		{
			name: "category",
			rule: audit.GovernancePostScanRuleInput{
				RuleName:        "malware category block",
				Priority:        1,
				ResourceType:    "prompt",
				Severity:        "all",
				RiskLevel:       "all",
				FindingCategory: "malware",
				Decision:        "block",
				InstallAction:   "block",
				FileAction:      "quarantine",
				RuntimeAction:   "block",
				Enabled:         true,
			},
			finding:     scanner.Finding{Severity: scanner.SeverityLow, Category: "malware", Title: "Low severity malware category"},
			wantVerdict: VerdictRejected,
		},
		{
			name: "scanner",
			rule: audit.GovernancePostScanRuleInput{
				RuleName:      "scanner warning",
				Priority:      1,
				ResourceType:  "prompt",
				Severity:      "all",
				RiskLevel:     "all",
				Scanner:       "decision-scanner",
				Decision:      "alert",
				InstallAction: "none",
				FileAction:    "none",
				RuntimeAction: "allow",
				Enabled:       true,
			},
			finding:     scanner.Finding{Severity: scanner.SeverityLow, Category: "weak_config", Title: "Low risk"},
			wantVerdict: VerdictWarning,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, store, logger, _ := setupTestEnv(t)
			shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
			profile, err := store.CreateGovernancePostScanProfile(audit.GovernancePostScanProfileInput{
				ProfileKey: "test-post-" + tc.name,
				Name:       "Test Post " + tc.name,
				Enabled:    true,
				Rules:      []audit.GovernancePostScanRuleInput{tc.rule},
			})
			if err != nil {
				t.Fatal(err)
			}

			fake := &countingScanner{name: "decision-scanner", findings: []scanner.Finding{tc.finding}}
			w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
			w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

			target := filepath.Join(t.TempDir(), "finding.prompt")
			if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			result := w.runAdmission(context.Background(), InstallEvent{
				Type:              InstallPrompt,
				Name:              filepath.Base(target),
				Path:              target,
				PostScanProfileID: profile.ID,
				Timestamp:         time.Now(),
			})

			if fake.calls != 1 {
				t.Fatalf("expected one scanner call, got %d", fake.calls)
			}
			if result.Verdict != tc.wantVerdict {
				t.Fatalf("expected verdict %q, got %q (%s)", tc.wantVerdict, result.Verdict, result.Reason)
			}
		})
	}
}

func TestAdmission_PostScanDisabledAndDeletedRulesDoNotApply(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	profile, err := store.CreateGovernancePostScanProfile(audit.GovernancePostScanProfileInput{
		ProfileKey: "test-post-disabled",
		Name:       "Test Post Disabled",
		Enabled:    true,
		Rules: []audit.GovernancePostScanRuleInput{{
			RuleName:      "disabled block",
			Priority:      1,
			ResourceType:  "prompt",
			Severity:      "all",
			RiskLevel:     "all",
			Scanner:       "decision-scanner",
			Decision:      "block",
			InstallAction: "block",
			FileAction:    "quarantine",
			RuntimeAction: "block",
			Enabled:       false,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	deletedRule, err := store.CreateGovernancePostScanRule(profile.ID, audit.GovernancePostScanRuleInput{
		RuleName:      "deleted block",
		Priority:      2,
		ResourceType:  "prompt",
		Severity:      "all",
		RiskLevel:     "all",
		Scanner:       "decision-scanner",
		Decision:      "block",
		InstallAction: "block",
		FileAction:    "quarantine",
		RuntimeAction: "block",
		Enabled:       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := store.DeleteGovernancePostScanRule(deletedRule.ID); err != nil || !ok {
		t.Fatalf("delete post-scan rule ok=%v err=%v", ok, err)
	}
	if _, err := store.CreateGovernancePostScanRule(profile.ID, audit.GovernancePostScanRuleInput{
		RuleName:      "active alert",
		Priority:      3,
		ResourceType:  "prompt",
		Severity:      "all",
		RiskLevel:     "all",
		Scanner:       "decision-scanner",
		Decision:      "alert",
		InstallAction: "none",
		FileAction:    "none",
		RuntimeAction: "allow",
		Enabled:       true,
	}); err != nil {
		t.Fatal(err)
	}

	fake := &countingScanner{
		name:     "decision-scanner",
		findings: []scanner.Finding{{Severity: scanner.SeverityLow, Category: "weak_config", Title: "Low risk"}},
	}
	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.scannerFactory = func(InstallEvent) scanner.Scanner { return fake }

	target := filepath.Join(t.TempDir(), "post-disabled.prompt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := w.runAdmission(context.Background(), InstallEvent{
		Type:              InstallPrompt,
		Name:              filepath.Base(target),
		Path:              target,
		PostScanProfileID: profile.ID,
		Timestamp:         time.Now(),
	})

	if result.Verdict != VerdictWarning {
		t.Fatalf("expected active alert after disabled/deleted block rules are ignored, got %q (%s)", result.Verdict, result.Reason)
	}
}

func TestUpdateResourceRiskUsesConfiguredRiskTables(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)

	agent, err := store.EnsureAgent(audit.AgentIdentityInput{
		AgentID:   "risk-table-agent",
		AgentName: "Risk Table Agent",
		Source:    "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "malware.prompt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
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

	w := New(cfg, nil, nil, store, logger, shell, nil, nil, nil)
	w.updateResourceRisk(InstallEvent{ResourceID: resourceID}, &scanner.ScanResult{
		Scanner:   "decision-scanner",
		Target:    target,
		Timestamp: time.Now(),
		Findings: []scanner.Finding{{
			Severity: scanner.SeverityLow,
			Category: "malware",
			Title:    "Low severity finding with critical configured category",
		}},
	}, "scan-risk-table")

	detail, err := store.GetStaticResourceDetail(resourceID)
	if err != nil {
		t.Fatal(err)
	}
	if detail == nil {
		t.Fatal("expected static resource detail")
	}
	if detail.RiskLevel != "critical" {
		t.Fatalf("expected category mapping to write critical risk, got %q", detail.RiskLevel)
	}
	if !detail.Malicious {
		t.Fatal("expected category mapping at critical risk to mark resource malicious")
	}
}
