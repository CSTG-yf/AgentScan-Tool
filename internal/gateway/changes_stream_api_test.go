// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type cancelOnFlushWriter struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnFlushWriter) Flush() {
	w.ResponseRecorder.Flush()
	w.cancel()
}

func TestChangeStreamResumesAndEmitsDomainInvalidation(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := store.CreateScanJob(audit.ScanJob{JobID: "stream-change-job", Kind: "agent_discovery"}); err != nil {
		t.Fatalf("CreateScanJob: %v", err)
	}
	api := &APIServer{store: store}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stream?domains=jobs,scan_jobs", nil).WithContext(ctx)
	rec := &cancelOnFlushWriter{ResponseRecorder: httptest.NewRecorder(), cancel: cancel}
	api.handleChangeStreamAPI(rec, req)

	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/event-stream; charset=utf-8" {
		t.Fatalf("stream response status=%d headers=%v", rec.Code, rec.Header())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "event: change\n") || !strings.Contains(body, `"changed_domains":["scan_jobs"]`) {
		t.Fatalf("stream did not emit the requested change: %s", body)
	}
	if !strings.Contains(body, "id: ") {
		t.Fatalf("stream event omitted resume cursor: %s", body)
	}
}

func TestChangeStreamRejectsInvalidResumeCursor(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api := &APIServer{store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stream?cursor=-1", nil)
	rec := httptest.NewRecorder()
	api.handleChangeStreamAPI(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor status=%d body=%s", rec.Code, rec.Body.String())
	}
}
