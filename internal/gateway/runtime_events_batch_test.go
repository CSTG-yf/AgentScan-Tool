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

func TestRuntimeEventsBatchPersistsValidItemsAndReportsItemErrors(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	SetRuntimeEventStore(store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })

	api := &APIServer{store: store}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-events/batch", strings.NewReader(`{
		"events": [
			{"event_type":"process.exec","agent_id":"codex","pid":321,"target":"codex.exe"},
			{"event_type":"file.read","agent_id":"codex","path":"C:\\Users\\tester\\.aws\\credentials","target":"C:\\Users\\tester\\.aws\\credentials"},
			{"agent_id":"codex","target":"missing event type"}
		]
	}`))
	rec := httptest.NewRecorder()
	api.handleRuntimeEvents(rec, req)
	if rec.Code != http.StatusMultiStatus {
		t.Fatalf("batch status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Items  []map[string]any `json:"items"`
		Count  int              `json:"count"`
		Failed int              `json:"failed"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode batch response: %v", err)
	}
	if response.Count != 3 || len(response.Items) != 3 || response.Failed != 1 {
		t.Fatalf("batch response = %+v, want three results and one failure", response)
	}
	events, err := store.ListRuntimeEvents(audit.RuntimeEventFilter{IncludeDesktop: true, Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("persisted events = %d, want 2 valid events", len(events))
	}
	detections, err := store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 20})
	if err != nil {
		t.Fatalf("ListRuntimeDetections: %v", err)
	}
	if len(detections) == 0 {
		t.Fatal("expected file credential event to feed the detection engine")
	}
}

func TestRuntimeEventsBatchAcceptsBareArray(t *testing.T) {
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	SetRuntimeEventStore(store)
	t.Cleanup(func() { SetRuntimeEventStore(nil) })

	api := &APIServer{store: store}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-events/batch", strings.NewReader(`[{"event_type":"agent.session_start","agent_id":"codex"}]`))
	rec := httptest.NewRecorder()
	api.handleRuntimeEvents(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("bare-array batch status = %d body=%s", rec.Code, rec.Body.String())
	}
}
