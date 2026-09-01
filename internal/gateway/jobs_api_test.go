// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
