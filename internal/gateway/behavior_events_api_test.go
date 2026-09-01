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

func TestBehaviorEventsPOSTNormalizesAndEvaluates(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/behavior-events", strings.NewReader(`{
        "eventType":"fileRead",
        "source":"process-guard",
        "agentPid":1200,
        "agentExecutable":"codex.exe",
        "actorPid":1200,
        "actorExecutable":"codex.exe",
        "path":"C:\\Users\\tester\\.aws\\credentials",
        "action":"read",
        "outcome":"observed",
        "detail":"credential file read"
    }`))
	rec := httptest.NewRecorder()
	api.handleBehaviorEvents(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		EventType   string `json:"eventType"`
		EventSource string `json:"eventSource"`
		EventID     int64  `json:"event_id"`
		Evaluated   bool   `json:"evaluated"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.EventType != audit.RuntimeEventFileRead || response.EventSource != audit.RuntimeSourceOSSensor {
		t.Fatalf("response = %+v, want normalized file.read/os-sensor", response)
	}
	if response.EventID <= 0 || !response.Evaluated {
		t.Fatalf("response = %+v, want persisted/evaluated event", response)
	}

	rows, err := store.ListRuntimeEvents(audit.RuntimeEventFilter{EventSource: audit.RuntimeSourceOSSensor, Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeEvents: %v", err)
	}
	if len(rows) != 1 || rows[0].EventType != audit.RuntimeEventFileRead || rows[0].Target == "" {
		t.Fatalf("runtime rows = %+v, want one normalized file.read row", rows)
	}
	detections, err := store.ListRuntimeDetections(audit.RuntimeDetectionFilter{Limit: 20})
	if err != nil {
		t.Fatalf("ListRuntimeDetections: %v", err)
	}
	if len(detections) == 0 {
		t.Fatal("expected credential/sensitive-file detection from legacy fileRead event")
	}
}

func TestLegacyBehaviorRuntimeInputVocabulary(t *testing.T) {
	tests := []struct {
		native string
		want   string
	}{
		{"agentProcessStart", audit.RuntimeEventProcessExec},
		{"agentCommandStart", audit.RuntimeEventProcessExec},
		{"fileRead", audit.RuntimeEventFileRead},
		{"fileWrite", audit.RuntimeEventFileWrite},
		{"fileDelete", audit.RuntimeEventFileDelete},
		{"blacklistFileAccess", audit.RuntimeEventFileRead},
	}
	for _, test := range tests {
		got := legacyBehaviorRuntimeInput(audit.BehaviorEvent{EventType: test.native}).EventType
		if got != test.want {
			t.Errorf("%s -> %s, want %s", test.native, got, test.want)
		}
	}
}
