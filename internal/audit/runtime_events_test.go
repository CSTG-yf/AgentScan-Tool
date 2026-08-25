// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"
)

// TestRecordRuntimeEventTimeline verifies the Phase-1 completion
// criterion: querying one agent + session + trace returns the unified
// event chain in chronological order —
//
//	prompt.submit → content.prompt_injection → tool.pre_call →
//	network.request → network.blocked
func TestRecordRuntimeEventTimeline(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	base := time.Now().UTC().Add(-time.Minute)
	events := []RuntimeEventInput{
		{
			EventType: RuntimeEventPromptSubmit, EventSource: RuntimeSourceAgentHook,
			AgentName: "Claude Code", SessionID: "S001", TraceID: "T001",
			Outcome: "allowed", Timestamp: base,
		},
		{
			EventType: RuntimeEventContentInjection, EventSource: RuntimeSourceGuardrail,
			AgentName: "Claude Code", SessionID: "S001", TraceID: "T001",
			Severity: "HIGH", Outcome: "blocked", Timestamp: base.Add(1 * time.Second),
			Detail: "instruction injection detected",
		},
		{
			EventType: RuntimeEventToolPreCall, EventSource: RuntimeSourceAgentHook,
			AgentName: "Claude Code", SessionID: "S001", TraceID: "T001",
			ToolName: "Read", Outcome: "allowed", Timestamp: base.Add(2 * time.Second),
		},
		{
			EventType: RuntimeEventNetworkRequest, EventSource: RuntimeSourceProxy,
			AgentName: "Claude Code", SessionID: "S001", TraceID: "T001",
			Target: "evil.example.com/exfil", Severity: "INFO", Outcome: "allowed",
			Timestamp: base.Add(3 * time.Second),
		},
		{
			EventType: RuntimeEventNetworkBlocked, EventSource: RuntimeSourceProxy,
			AgentName: "Claude Code", SessionID: "S001", TraceID: "T001",
			Target: "evil.example.com/exfil", Severity: "HIGH", Outcome: "blocked",
			Detail: "ssrf defense", Timestamp: base.Add(3 * time.Second + 500 * time.Millisecond),
		},
	}
	for _, e := range events {
		if _, err := store.RecordRuntimeEvent(e); err != nil {
			t.Fatalf("RecordRuntimeEvent(%s): %v", e.EventType, err)
		}
	}

	// The agent gets a canonical id from EnsureAgent; find it via the
	// first timeline row.
	all, err := store.ListRuntimeEvents(RuntimeEventFilter{TraceID: "T001", Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeEvents: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("expected 5 events for trace T001, got %d", len(all))
	}
	wantOrder := []string{
		RuntimeEventPromptSubmit,
		RuntimeEventContentInjection,
		RuntimeEventToolPreCall,
		RuntimeEventNetworkRequest,
		RuntimeEventNetworkBlocked,
	}
	for i, want := range wantOrder {
		if all[i].EventType != want {
			t.Errorf("timeline[%d] = %s, want %s", i, all[i].EventType, want)
		}
		if all[i].SessionID != "S001" {
			t.Errorf("timeline[%d] session_id = %q, want S001", i, all[i].SessionID)
		}
		if all[i].TraceID != "T001" {
			t.Errorf("timeline[%d] trace_id = %q, want T001", i, all[i].TraceID)
		}
	}
	if all[0].CanonicalAgentID == "" {
		t.Error("timeline rows missing canonical_agent_id binding")
	}

	// Filter by agent + session yields the same chain.
	byAgent, err := store.ListRuntimeEvents(RuntimeEventFilter{
		AgentID:   all[0].CanonicalAgentID,
		SessionID: "S001",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("ListRuntimeEvents by agent/session: %v", err)
	}
	if len(byAgent) != 5 {
		t.Fatalf("expected 5 events for agent/session, got %d", len(byAgent))
	}

	// The runtime session inventory reflects the run.
	sessions, err := store.ListRuntimeSessions(all[0].CanonicalAgentID, 10)
	if err != nil {
		t.Fatalf("ListRuntimeSessions: %v", err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "S001" {
		t.Fatalf("expected one session S001, got %+v", sessions)
	}
	if sessions[0].EventCount != 5 {
		t.Errorf("session event count = %d, want 5", sessions[0].EventCount)
	}
	if sessions[0].Status != "active" {
		t.Errorf("session status = %q, want active", sessions[0].Status)
	}
}

// TestEnsureRuntimeSessionLifecycle verifies started_at stability and
// the ended transition on agent.stop.
func TestEnsureRuntimeSessionLifecycle(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	agent, err := store.EnsureAgent(AgentIdentityInput{AgentName: "Codex", Source: "test"})
	if err != nil {
		t.Fatalf("EnsureAgent: %v", err)
	}
	t0 := time.Now().UTC().Add(-time.Hour)
	if err := store.EnsureRuntimeSession(EnsureRuntimeSessionInput{
		SessionID: "S100", CanonicalAgentID: agent.ID,
		StartedAt: t0, WorkingDirectory: "C:\\work",
	}); err != nil {
		t.Fatalf("EnsureRuntimeSession: %v", err)
	}
	// Second sighting later in the run must NOT move started_at and
	// must not flip the session to ended.
	if err := store.EnsureRuntimeSession(EnsureRuntimeSessionInput{
		SessionID: "S100", CanonicalAgentID: agent.ID,
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("EnsureRuntimeSession refresh: %v", err)
	}
	sessions, err := store.ListRuntimeSessions(agent.ID, 10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListRuntimeSessions: %v len=%d", err, len(sessions))
	}
	if !sessions[0].StartedAt.Equal(t0) {
		t.Errorf("started_at moved: %v, want %v", sessions[0].StartedAt, t0)
	}
	if sessions[0].Status != "active" {
		t.Errorf("status = %q, want active", sessions[0].Status)
	}

	// agent.stop marks the run ended with ended_at set.
	endedAt := time.Now().UTC()
	if err := store.EnsureRuntimeSession(EnsureRuntimeSessionInput{
		SessionID: "S100", CanonicalAgentID: agent.ID,
		StartedAt: endedAt, Status: "ended",
	}); err != nil {
		t.Fatalf("EnsureRuntimeSession end: %v", err)
	}
	sessions, err = store.ListRuntimeSessions(agent.ID, 10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("ListRuntimeSessions after end: %v len=%d", err, len(sessions))
	}
	if sessions[0].Status != "ended" {
		t.Errorf("status after end = %q, want ended", sessions[0].Status)
	}
	if sessions[0].EndedAt == nil || sessions[0].EndedAt.Before(endedAt.Add(-time.Minute)) {
		t.Errorf("ended_at = %v, want ~%v", sessions[0].EndedAt, endedAt)
	}
}

// TestRecordRuntimeEventLegacyCompatibility verifies legacy
// desktop-behavior inserts still work and default to the
// desktop-behavior event source.
func TestRecordRuntimeEventLegacyCompatibility(t *testing.T) {
	store, done := newTestStore(t)
	defer done()

	// Legacy desktop path via InsertBehaviorEvent.
	if _, err := store.InsertBehaviorEvent(BehaviorEvent{
		EventType: "process.start",
		Source:    "desktop-behavior",
		Detail:    "observed claude.exe",
	}); err != nil {
		t.Fatalf("InsertBehaviorEvent: %v", err)
	}
	// Unified runtime path.
	if _, err := store.RecordRuntimeEvent(RuntimeEventInput{
		EventType: RuntimeEventPromptSubmit, EventSource: RuntimeSourceAgentHook,
		AgentName: "Claude Code", SessionID: "S002",
	}); err != nil {
		t.Fatalf("RecordRuntimeEvent: %v", err)
	}

	events, err := store.ListRuntimeEvents(RuntimeEventFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListRuntimeEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected only the unified runtime event in the timeline, got %d", len(events))
	}
	if events[0].EventSource != RuntimeSourceAgentHook {
		t.Errorf("event_source = %q, want %q", events[0].EventSource, RuntimeSourceAgentHook)
	}
	if events[0].EventCategory != RuntimeCategoryPrompt {
		t.Errorf("event_category = %q, want %q", events[0].EventCategory, RuntimeCategoryPrompt)
	}

	// Legacy list keeps both rows and tags the desktop row with the
	// legacy event source.
	legacy, err := store.ListBehaviorEvents(10)
	if err != nil {
		t.Fatalf("ListBehaviorEvents: %v", err)
	}
	if len(legacy) != 2 {
		t.Fatalf("expected 2 behavior rows, got %d", len(legacy))
	}
	sources := map[string]int{}
	for _, e := range legacy {
		sources[e.EventSource]++
	}
	if sources[RuntimeSourceDesktop] != 1 || sources[RuntimeSourceAgentHook] != 1 {
		t.Errorf("event source split = %v, want 1 desktop + 1 agent_hook", sources)
	}
}
