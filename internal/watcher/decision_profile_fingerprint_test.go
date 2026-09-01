// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestScannerFingerprintChangesWhenDecisionProfilesChange(t *testing.T) {
	t.Setenv("PATH", "")
	cfg, store, _, _ := setupTestEnv(t)

	pre, err := store.CreateGovernancePreScanProfile(audit.GovernancePreScanProfileInput{
		ProfileKey: "fingerprint-pre",
		Name:       "Fingerprint Pre",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("CreateGovernancePreScanProfile: %v", err)
	}
	preRule, err := store.CreateGovernancePreScanRule(pre.ID, audit.GovernancePreScanRuleInput{
		RuleName:      "initial decision",
		Priority:      1,
		ResourceType:  "prompt",
		PathPattern:   "*",
		Decision:      "skip",
		InstallAction: "none",
		FileAction:    "none",
		RuntimeAction: "allow",
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("CreateGovernancePreScanRule: %v", err)
	}
	post, err := store.CreateGovernancePostScanProfile(audit.GovernancePostScanProfileInput{
		ProfileKey: "fingerprint-post",
		Name:       "Fingerprint Post",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("CreateGovernancePostScanProfile: %v", err)
	}
	postRule, err := store.CreateGovernancePostScanRule(post.ID, audit.GovernancePostScanRuleInput{
		RuleName:      "initial verdict",
		Priority:      1,
		ResourceType:  "prompt",
		Severity:      "all",
		RiskLevel:     "all",
		Decision:      "alert",
		InstallAction: "none",
		FileAction:    "none",
		RuntimeAction: "allow",
		Enabled:       true,
	})
	if err != nil {
		t.Fatalf("CreateGovernancePostScanRule: %v", err)
	}

	w := New(cfg, nil, nil, store, nil, nil, nil, nil, nil)
	evt := InstallEvent{
		Type:              InstallPrompt,
		Path:              "C:\\workspace\\prompt.md",
		PreScanProfileID:  pre.ID,
		PostScanProfileID: post.ID,
	}
	initial := w.scannerFingerprint(evt)
	if initial == "" {
		t.Fatal("expected a decision-aware scanner fingerprint")
	}

	decision := "scan"
	if _, ok, err := store.UpdateGovernancePreScanRule(preRule.ID, audit.GovernancePreScanRulePatch{Decision: &decision}); err != nil || !ok {
		t.Fatalf("update pre-scan rule ok=%v: %v", ok, err)
	}
	preChanged := w.scannerFingerprint(evt)
	if preChanged == initial {
		t.Fatal("pre-scan policy edit must change scanner fingerprint")
	}

	decision = "block"
	if _, ok, err := store.UpdateGovernancePostScanRule(postRule.ID, audit.GovernancePostScanRulePatch{Decision: &decision}); err != nil || !ok {
		t.Fatalf("update post-scan rule ok=%v: %v", ok, err)
	}
	postChanged := w.scannerFingerprint(evt)
	if postChanged == preChanged {
		t.Fatal("post-scan policy edit must change scanner fingerprint")
	}
}
