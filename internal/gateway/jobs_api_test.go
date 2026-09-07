// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func TestJobsAPICancelWinsOverLateWorkerCompletion(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	started := make(chan struct{})
	release := make(chan struct{})
	api := &APIServer{store: store}
	status := api.startAPIScan("unit_test", "", "", "", func() error {
		close(started)
		<-release
		return nil
	})
	<-started

	cancelRec := httptest.NewRecorder()
	api.handleJobsAPI(cancelRec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs/"+status.ScanID+"/cancel", nil))
	if cancelRec.Code != http.StatusOK {
		t.Fatalf("cancel status = %d body = %s", cancelRec.Code, cancelRec.Body.String())
	}
	close(release)

	job, ok, err := store.GetScanJob(status.ScanID)
	if err != nil || !ok {
		t.Fatalf("GetScanJob after cancel: ok=%v err=%v", ok, err)
	}
	if job.Status != "cancelled" {
		t.Fatalf("job status = %q, want cancelled", job.Status)
	}

	listRec := httptest.NewRecorder()
	api.handleJobsAPI(listRec, httptest.NewRequest(http.MethodGet, "/api/v1/jobs?status=cancelled", nil))
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d body = %s", listRec.Code, listRec.Body.String())
	}
}

func TestJobsAPICreateRejectsUnknownKind(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	api := &APIServer{store: store}
	rec := httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"kind":"not-a-real-job"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestJobsAPICreateAndFilterByCanonicalTaskType(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	api := &APIServer{store: store}
	rec := httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"agent_discovery","mode":"full","trigger":"scheduled"}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create status = %d body = %s", rec.Code, rec.Body.String())
	}
	var accepted apiScanStatus
	if err := json.NewDecoder(rec.Body).Decode(&accepted); err != nil {
		t.Fatalf("decode accepted job: %v", err)
	}
	if accepted.TaskType != "agent_discovery" || accepted.Kind != "agent_discovery" || accepted.Trigger != "scheduler" {
		t.Fatalf("accepted job = %+v", accepted)
	}

	list := httptest.NewRecorder()
	api.handleJobsAPI(list, httptest.NewRequest(http.MethodGet, "/api/v1/jobs?task_type=agent_discovery&trigger=scheduler", nil))
	if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), `"task_type":"agent_discovery"`) {
		t.Fatalf("filtered list status=%d body=%s", list.Code, list.Body.String())
	}
}

func TestJobsAPICreateRejectsConflictingTaskAliases(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	api := &APIServer{store: store}
	rec := httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"static_assets","kind":"event_replay"}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "different tasks") {
		t.Fatalf("conflict status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"agent_discovery","mode":"magic"}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported scan mode") {
		t.Fatalf("mode status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"agent_discovery","trigger":"sometimes"}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unsupported scan trigger") {
		t.Fatalf("trigger status = %d body = %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"agent_discovery","scope":{"agent_id":42}}`)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "scope.agent_id") {
		t.Fatalf("scope status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func TestJobsAPICreateReadsCanonicalScopeFields(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	called := make(chan string, 1)
	api := &APIServer{store: store}
	api.SetStaticScanTrigger(nil, func(agentID string) error { called <- agentID; return nil })
	rec := httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"static_assets","scope":{"agent_id":"agent-from-scope"}}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var accepted apiScanStatus
	if err := json.NewDecoder(rec.Body).Decode(&accepted); err != nil || accepted.AgentID != "agent-from-scope" || accepted.Mode != "full" {
		t.Fatalf("accepted=%+v err=%v", accepted, err)
	}
	select {
	case agentID := <-called:
		if agentID != "agent-from-scope" {
			t.Fatalf("runner agent = %q", agentID)
		}
	case <-time.After(time.Second):
		t.Fatal("static resource runner was not called")
	}
}

func TestJobsAPICreateReturnsExistingRunningTask(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api := &APIServer{store: store}
	release := make(chan struct{})
	first := api.startAPIScanWithOptions("attack_chain_rebuild", "rebuild", "", "", "scheduler", nil, "", func(context.Context, string) error {
		<-release
		return nil
	})
	t.Cleanup(func() { close(release) })

	rec := httptest.NewRecorder()
	api.handleJobsAPI(rec, httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(`{"task_type":"attack_chains","mode":"rebuild"}`)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got apiScanStatus
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil || got.JobID != first.JobID {
		t.Fatalf("existing job=%+v err=%v, want %s", got, err, first.JobID)
	}
}

func TestBackgroundSchedulerRunsEnabledTaskFromScanSchedules(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api := &APIServer{store: store}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go api.RunBackgroundJobs(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		jobs, listErr := store.ListScanJobsFiltered(audit.ScanJobFilter{TaskType: "agent_discovery", Trigger: "scheduler", Limit: 10})
		if listErr != nil {
			t.Fatal(listErr)
		}
		if len(jobs) > 0 {
			if jobs[0].TaskType != "agent_discovery" || jobs[0].Trigger != "scheduler" {
				t.Fatalf("scheduled job = %+v", jobs[0])
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("enabled agent_discovery schedule did not create a job")
}

func TestChangesAPIProvidesCursorInvalidations(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := store.CreateScanJob(audit.ScanJob{JobID: "scan-change-api", Kind: "agent_discovery"}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}

	api := &APIServer{store: store}
	rec := httptest.NewRecorder()
	api.handleChangesAPI(rec, httptest.NewRequest(http.MethodGet, "/api/v1/changes?domains=scan_jobs", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("changes status = %d body = %s", rec.Code, rec.Body.String())
	}
	var response struct {
		NextCursor     int64    `json:"next_cursor"`
		ChangedDomains []string `json:"changed_domains"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode changes response: %v", err)
	}
	if response.NextCursor <= 0 || len(response.ChangedDomains) != 1 || response.ChangedDomains[0] != "scan_jobs" {
		t.Fatalf("changes response = %+v", response)
	}
}

func TestStartAPIScanIdempotencyReturnsExistingDurableJob(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	started := make(chan struct{})
	api := &APIServer{store: store}
	first := api.startAPIScanWithOptions("event_replay", "full", "agent-a", "", "manual", map[string]any{"agent_id": "agent-a"}, "retry-key-1", func(ctx context.Context, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	<-started
	second := api.startAPIScanWithOptions("event_replay", "full", "agent-a", "", "manual", map[string]any{"agent_id": "agent-a"}, "retry-key-1", func(context.Context, string) error {
		t.Fatal("idempotent retry started a second worker")
		return nil
	})
	if first.JobID == "" || second.JobID != first.JobID {
		t.Fatalf("idempotent jobs = first=%+v second=%+v", first, second)
	}
	j := audit.ScanJobFilter{Kind: "event_replay", Limit: 10}
	jobs, err := store.ListScanJobsFiltered(j)
	if err != nil {
		t.Fatalf("ListScanJobsFiltered: %v", err)
	}
	if len(jobs) != 1 || jobs[0].IdempotencyKey != "retry-key-1" {
		t.Fatalf("durable jobs = %+v, want one idempotent job", jobs)
	}
	if _, ok, err := store.FindScanJobByIdempotencyKey("retry-key-1"); err != nil || !ok {
		t.Fatalf("FindScanJobByIdempotencyKey: ok=%v err=%v", ok, err)
	}
	api.handleJobCancel(httptest.NewRecorder(), first.JobID)
}
