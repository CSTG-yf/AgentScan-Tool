package watcher

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestTrackedWatcherRescanCreatesCanonicalJob(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	w := &InstallWatcher{cfg: &config.Config{}, store: store}
	w.runTrackedRescan(context.Background(), "watcher", InstallSkill)

	jobs, err := store.ListScanJobsFiltered(audit.ScanJobFilter{TaskType: "static_assets", Trigger: "watcher", Limit: 10})
	if err != nil {
		t.Fatalf("ListScanJobsFiltered: %v", err)
	}
	if len(jobs) != 1 || jobs[0].TaskType != "static_assets" || jobs[0].Status != "completed" || jobs[0].Progress != 100 {
		t.Fatalf("tracked jobs = %+v", jobs)
	}
}

func TestTrackedWatcherJobObservesDurableCancellation(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	job := audit.ScanJob{JobID: "watcher-cancel", Kind: "resource_scan", Status: "running", Trigger: "watcher"}
	if err := store.CreateScanJob(job); err != nil {
		t.Fatal(err)
	}
	w := &InstallWatcher{store: store}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go w.watchTrackedJobCancellation(ctx, job.JobID, cancel, done)
	job.Status, job.CancelRequested = "cancelled", true
	if err := store.UpdateScanJob(job); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		close(done)
		t.Fatal("watcher job did not observe durable cancellation")
	}
}
