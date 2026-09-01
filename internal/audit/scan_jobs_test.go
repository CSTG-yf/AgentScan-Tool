// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestScanJobLifecycleAndPagination(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	if err := store.CreateScanJob(ScanJob{
		JobID: "scan_agents_1", Kind: "agent_discovery", Mode: "full",
		Status: "running", Progress: 25, StartedAt: "2026-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	if err := store.CreateScanJob(ScanJob{
		JobID: "scan_resources_1", Kind: "resource_scan", Mode: "rescan",
		Status: "completed", Progress: 100, StartedAt: "2026-01-01T00:01:00Z",
	}); err != nil {
		t.Fatalf("CreateScanJob second: %v", err)
	}

	job, ok, err := store.GetScanJob("scan_agents_1")
	if err != nil || !ok {
		t.Fatalf("GetScanJob: ok=%v err=%v", ok, err)
	}
	if job.Kind != "agent_discovery" || job.Status != "running" || job.Progress != 25 {
		t.Fatalf("unexpected job: %+v", job)
	}
	job.Status = "completed"
	job.Progress = 100
	job.FinishedAt = "2026-01-01T00:00:10Z"
	if err := store.UpdateScanJob(job); err != nil {
		t.Fatalf("UpdateScanJob: %v", err)
	}
	updated, ok, err := store.GetScanJob(job.JobID)
	if err != nil || !ok || updated.Status != "completed" || updated.Progress != 100 {
		t.Fatalf("updated job: ok=%v err=%v job=%+v", ok, err, updated)
	}

	rows, err := store.ListScanJobs("", "completed", 1, 0)
	if err != nil {
		t.Fatalf("ListScanJobs: %v", err)
	}
	if len(rows) != 1 || rows[0].Status != "completed" {
		t.Fatalf("completed jobs = %+v", rows)
	}
}

func TestMarkRunningScanJobsFailedOnRestart(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	for _, status := range []string{"queued", "running", "completed"} {
		if err := store.CreateScanJob(ScanJob{JobID: "scan_" + status, Kind: "agent_discovery", Status: status}); err != nil {
			t.Fatalf("CreateScanJob(%s): %v", status, err)
		}
	}
	if err := store.MarkRunningScanJobsFailed(); err != nil {
		t.Fatalf("MarkRunningScanJobsFailed: %v", err)
	}
	for _, status := range []string{"queued", "running"} {
		job, ok, err := store.GetScanJob("scan_" + status)
		if err != nil || !ok {
			t.Fatalf("GetScanJob(%s): ok=%v err=%v", status, ok, err)
		}
		if job.Status != "failed" || job.Error == "" || job.FinishedAt == "" {
			t.Errorf("recovered %s job = %+v", status, job)
		}
	}
	completed, ok, err := store.GetScanJob("scan_completed")
	if err != nil || !ok {
		t.Fatalf("GetScanJob(completed): ok=%v err=%v", ok, err)
	}
	if completed.Status != "completed" {
		t.Fatalf("completed job changed after recovery: %+v", completed)
	}
}
