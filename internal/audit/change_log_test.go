// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestChangesSinceReturnsMonotonicDomainCursor(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	if err := store.CreateScanJob(ScanJob{JobID: "scan-change-1", Kind: "agent_discovery"}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	first, err := store.ChangesSince(0, nil, 10)
	if err != nil {
		t.Fatalf("ChangesSince initial: %v", err)
	}
	if first.NextCursor <= 0 {
		t.Fatalf("initial cursor = %d, want positive", first.NextCursor)
	}
	found := false
	for _, domain := range first.ChangedDomains {
		if domain == "scan_jobs" {
			found = true
		}
	}
	if !found {
		t.Fatalf("initial domains = %v, want scan_jobs", first.ChangedDomains)
	}

	second, err := store.ChangesSince(first.NextCursor, []string{"scan_jobs"}, 10)
	if err != nil {
		t.Fatalf("ChangesSince caught up: %v", err)
	}
	if second.NextCursor != first.NextCursor || len(second.ChangedDomains) != 0 {
		t.Fatalf("caught-up result = %+v, want no changes", second)
	}

	if err := store.UpdateScanJob(ScanJob{JobID: "scan-change-1", Kind: "agent_discovery", Status: "completed", Progress: 100}); err != nil {
		t.Fatalf("UpdateScanJob: %v", err)
	}
	third, err := store.ChangesSince(first.NextCursor, []string{"scan_jobs"}, 10)
	if err != nil {
		t.Fatalf("ChangesSince update: %v", err)
	}
	if third.NextCursor <= first.NextCursor || len(third.ChangedDomains) != 1 || third.ChangedDomains[0] != "scan_jobs" {
		t.Fatalf("updated result = %+v", third)
	}
}
