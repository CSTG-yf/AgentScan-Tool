// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
	"time"
)

// SetStaticResourceStatus records the manual review decision; unknown
// resources report ok=false, and a manual "ignored" mark survives both
// re-observation (no scan attached) and missing sweeps.
func TestSetStaticResourceStatus_ReviewLoop(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentID := ensureRuleTestAgent(t, store, "review-loop-agent")
	old := time.Now().UTC().Add(-time.Hour)
	resourceID, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "review-me",
		Target:           filepath.Join("C:", "skills", "review-me"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
		ObservedAt:       old,
	})
	if err != nil {
		t.Fatal(err)
	}

	ok, err := store.SetStaticResourceStatus(resourceID, "review")
	if err != nil || !ok {
		t.Fatalf("expected status update ok=true, got ok=%v err=%v", ok, err)
	}
	if status, _ := store.StaticResourceStatus(resourceID); status != "review" {
		t.Fatalf("expected review, got %q", status)
	}

	if ok, err := store.SetStaticResourceStatus("does-not-exist", "review"); err != nil || ok {
		t.Fatalf("unknown resource must report ok=false, got ok=%v err=%v", ok, err)
	}

	// Re-observation without a scan must not clear the manual mark.
	if _, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "review-me",
		Target:           filepath.Join("C:", "skills", "review-me"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
	}); err != nil {
		t.Fatal(err)
	}
	if status, _ := store.StaticResourceStatus(resourceID); status != "review" {
		t.Fatalf("manual mark must survive re-observation, got %q", status)
	}

	// Missing sweeps skip ignored rows.
	if _, err := store.SetStaticResourceStatus(resourceID, "ignored"); err != nil {
		t.Fatal(err)
	}
	n, err := store.MarkMissingResources(agentID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("ignored rows must not flip to missing, got %d transitions", n)
	}
	if status, _ := store.StaticResourceStatus(resourceID); status != "ignored" {
		t.Fatalf("ignored must survive the missing sweep, got %q", status)
	}
}

// ListStaticResourceScanHistory returns every scan of a resource, newest
// first, with the total unaffected by the limit.
func TestListStaticResourceScanHistory(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentID := ensureRuleTestAgent(t, store, "scan-history-agent")
	resourceID, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "history-skill",
		Target:           filepath.Join("C:", "skills", "history-skill"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	base := time.Now().UTC().Add(-2 * time.Hour)
	scans := []struct {
		id       string
		offset   time.Duration
		severity string
		findings int
	}{
		{"scan-old", 0, "LOW", 1},
		{"scan-mid", time.Hour, "HIGH", 3},
		{"scan-new", 2 * time.Hour, "CRITICAL", 5},
	}
	for _, scan := range scans {
		if _, err := store.db.Exec(`INSERT INTO scan_results
			(id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, static_resource_id)
			VALUES (?, ?, ?, ?, ?, ?, ?, '{}', ?)`,
			scan.id, "skill-scanner", filepath.Join("C:", "skills", "history-skill"),
			base.Add(scan.offset), 1200, scan.findings, scan.severity, resourceID,
		); err != nil {
			t.Fatal(err)
		}
	}

	history, err := store.ListStaticResourceScanHistory(resourceID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if history == nil || history.Total != 3 || len(history.Items) != 3 {
		t.Fatalf("expected 3 recorded scans, got total=%d items=%d", history.Total, len(history.Items))
	}
	if history.Items[0].ScanID != "scan-new" || history.Items[2].ScanID != "scan-old" {
		t.Fatalf("expected newest-first ordering, got %q..%q", history.Items[0].ScanID, history.Items[2].ScanID)
	}
	if history.Items[0].MaxSeverity != "CRITICAL" || history.Items[0].FindingCount != 5 {
		t.Fatalf("unexpected newest scan payload: %+v", history.Items[0])
	}
	if history.Items[0].DurationMs == nil || *history.Items[0].DurationMs != 1200 {
		t.Fatalf("expected duration 1200ms, got %v", history.Items[0].DurationMs)
	}

	limited, err := store.ListStaticResourceScanHistory(resourceID, 2)
	if err != nil {
		t.Fatal(err)
	}
	if limited.Total != 3 || len(limited.Items) != 2 {
		t.Fatalf("limit must cap items but not total, got total=%d items=%d", limited.Total, len(limited.Items))
	}
}

// GetStaticResourceDetail resolves the scan profile lineage including the
// configured security capabilities of the resource's profile.
func TestGetStaticResourceDetail_ScanCapabilities(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agentID := ensureRuleTestAgent(t, store, "detail-caps-agent")
	resourceID, err := store.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     "skill",
		Name:             "caps-skill",
		Target:           filepath.Join("C:", "skills", "caps-skill"),
		ResourceRuleID:   1,
		ScanProfileID:    1,
		Source:           "test",
	})
	if err != nil {
		t.Fatal(err)
	}

	detail, err := store.GetStaticResourceDetail(resourceID)
	if err != nil || detail == nil {
		t.Fatalf("expected detail, got %v err=%v", detail, err)
	}
	if detail.ScanProfile == nil || detail.ScanProfile.ProfileID != 1 {
		t.Fatalf("expected seeded scan profile 1, got %+v", detail.ScanProfile)
	}
	if len(detail.ScanCapabilities) == 0 {
		t.Fatal("expected the seeded profile to expose its configured capabilities")
	}
	var hasSkillSecurity bool
	for _, capability := range detail.ScanCapabilities {
		if capability.CapabilityID == 0 || capability.Name == "" {
			t.Fatalf("capability rows must carry id and name, got %+v", capability)
		}
		if capability.Key == "skill_security" && capability.Enabled {
			hasSkillSecurity = true
		}
	}
	if !hasSkillSecurity {
		t.Fatalf("expected an enabled skill_security capability, got %+v", detail.ScanCapabilities)
	}

	if detail, err := store.GetStaticResourceDetail("does-not-exist"); err != nil || detail != nil {
		t.Fatalf("unknown resource must return nil detail, got %v err=%v", detail, err)
	}
}
