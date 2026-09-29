// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func agentRangeTestEvent(key, session string) RuntimeEventInput {
	return RuntimeEventInput{
		IngestKey: key, EventType: RuntimeEventPromptSubmit,
		EventSource: RuntimeSourceGuardrail, AgentName: "AgentRange / OpsPilot",
		SessionID: session, TraceID: "trace-1", Outcome: "observed",
		Attributes: map[string]any{"connector": "agentrange"},
	}
}

func installAgentRangeWriteCounters(t *testing.T, store *Store) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE agentrange_write_counts (name TEXT PRIMARY KEY, count INTEGER NOT NULL DEFAULT 0)`,
		`INSERT INTO agentrange_write_counts(name) VALUES ('agents'), ('sessions')`,
		`CREATE TRIGGER agentrange_agent_insert AFTER INSERT ON agents BEGIN UPDATE agentrange_write_counts SET count = count + 1 WHERE name = 'agents'; END`,
		`CREATE TRIGGER agentrange_agent_update AFTER UPDATE ON agents BEGIN UPDATE agentrange_write_counts SET count = count + 1 WHERE name = 'agents'; END`,
		`CREATE TRIGGER agentrange_session_insert AFTER INSERT ON agent_runtime_sessions BEGIN UPDATE agentrange_write_counts SET count = count + 1 WHERE name = 'sessions'; END`,
		`CREATE TRIGGER agentrange_session_update AFTER UPDATE ON agent_runtime_sessions BEGIN UPDATE agentrange_write_counts SET count = count + 1 WHERE name = 'sessions'; END`,
		`CREATE TRIGGER agentrange_require_identity BEFORE INSERT ON behavior_events
WHEN NEW.agent_name = 'AgentRange / OpsPilot' BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM agents WHERE id = NEW.canonical_agent_id
  ) OR NOT EXISTS (
    SELECT 1 FROM agent_aliases WHERE agent_id = NEW.canonical_agent_id
  ) OR NOT EXISTS (
    SELECT 1 FROM agent_runtime_sessions
    WHERE session_id = NEW.session_id AND agent_id = NEW.canonical_agent_id
  ) THEN RAISE(FAIL, 'identity/session missing before event insert') END;
END`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("install write counter: %v", err)
		}
	}
}

func agentRangeWriteCount(t *testing.T, store *Store, name string) int {
	t.Helper()
	var count int
	if err := store.db.QueryRow(`SELECT count FROM agentrange_write_counts WHERE name = ?`, name).Scan(&count); err != nil {
		t.Fatalf("read %s count: %v", name, err)
	}
	return count
}

func TestAgentRangeRuntimeCacheConcurrentFirstSighting(t *testing.T) {
	store, done := newTestStore(t)
	defer done()
	installAgentRangeWriteCounters(t, store)

	const workers = 24
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := store.RecordAgentRangeRuntimeEvent(agentRangeTestEvent(fmt.Sprintf("agentrange-%d", i), "session-1"))
			errors <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent record: %v", err)
		}
	}
	agentWrites := agentRangeWriteCount(t, store, "agents")
	sessionWrites := agentRangeWriteCount(t, store, "sessions")
	if agentWrites < 1 || agentWrites > workers || sessionWrites < 1 || sessionWrites > workers {
		t.Fatalf("unexpected concurrent ensure writes: agents=%d sessions=%d", agentWrites, sessionWrites)
	}
	if _, err := store.RecordAgentRangeRuntimeEvent(agentRangeTestEvent("cached", "session-1")); err != nil {
		t.Fatalf("cached record: %v", err)
	}
	if got := agentRangeWriteCount(t, store, "agents"); got != agentWrites {
		t.Fatalf("cached record rewrote agent: before=%d after=%d", agentWrites, got)
	}
	if got := agentRangeWriteCount(t, store, "sessions"); got != sessionWrites {
		t.Fatalf("cached record rewrote session: before=%d after=%d", sessionWrites, got)
	}
	var events, aliases, sessions int
	for _, query := range []struct {
		sql string
		out *int
	}{
		{`SELECT count(*) FROM behavior_events WHERE session_id = 'session-1'`, &events},
		{`SELECT count(*) FROM agent_aliases WHERE agent_id = 'agentrange-opspilot'`, &aliases},
		{`SELECT count(*) FROM agent_runtime_sessions WHERE session_id = 'session-1'`, &sessions},
	} {
		if err := store.db.QueryRow(query.sql).Scan(query.out); err != nil {
			t.Fatalf("read durable rows: %v", err)
		}
	}
	if events != workers+1 || aliases == 0 || sessions != 1 {
		t.Fatalf("durable rows: events=%d aliases=%d sessions=%d", events, aliases, sessions)
	}

	// A caller-controlled connector attribute cannot select this fast path.
	if _, err := store.RecordRuntimeEvent(agentRangeTestEvent("ordinary-event", "session-1")); err != nil {
		t.Fatalf("ordinary runtime record: %v", err)
	}
	if got := agentRangeWriteCount(t, store, "agents"); got != agentWrites+1 {
		t.Fatalf("ordinary event skipped agent ensure: writes=%d", got)
	}
	if got := agentRangeWriteCount(t, store, "sessions"); got != sessionWrites+1 {
		t.Fatalf("ordinary event skipped session ensure: writes=%d", got)
	}
}

func TestAgentRangeRuntimeCacheSessionLifecycleAndBound(t *testing.T) {
	store, done := newTestStore(t)
	defer done()
	if _, err := store.RecordAgentRangeRuntimeEvent(agentRangeTestEvent("first", "session-1")); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := store.EnsureRuntimeSession(EnsureRuntimeSessionInput{
		SessionID: "session-1", CanonicalAgentID: "agentrange-opspilot",
		Status: "ended", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("end session: %v", err)
	}
	if _, err := store.RecordAgentRangeRuntimeEvent(agentRangeTestEvent("after-end", "session-1")); err != nil {
		t.Fatalf("record after end: %v", err)
	}
	var status string
	if err := store.db.QueryRow(`SELECT status FROM agent_runtime_sessions WHERE session_id = 'session-1'`).Scan(&status); err != nil {
		t.Fatalf("read session status: %v", err)
	}
	if status != "active" {
		t.Fatalf("session status after new event = %q, want active", status)
	}

	store.agentrangeRuntimeCache.mu.Lock()
	store.agentrangeRuntimeCache.sessions = make(map[agentrangeSessionKey]time.Time, agentrangeRuntimeSessionLimit)
	for i := 0; i < agentrangeRuntimeSessionLimit; i++ {
		store.agentrangeRuntimeCache.sessions[agentrangeSessionKey{agentID: "agentrange-opspilot", sessionID: fmt.Sprintf("old-%d", i)}] = time.Now().Add(time.Hour)
	}
	store.agentrangeRuntimeCache.mu.Unlock()
	if _, err := store.RecordAgentRangeRuntimeEvent(agentRangeTestEvent("bounded", "new-session")); err != nil {
		t.Fatalf("record at cache capacity: %v", err)
	}
	store.agentrangeRuntimeCache.mu.Lock()
	got := len(store.agentrangeRuntimeCache.sessions)
	store.agentrangeRuntimeCache.mu.Unlock()
	if got != 1 {
		t.Fatalf("session cache entries = %d, want 1 after eviction", got)
	}
}

func TestEnsureRuntimeSessionConcurrentUpsert(t *testing.T) {
	store, done := newTestStore(t)
	defer done()
	agent, err := store.EnsureAgent(AgentIdentityInput{AgentName: "Codex", Source: "test"})
	if err != nil {
		t.Fatalf("ensure agent: %v", err)
	}
	const workers = 32
	started := time.Now().UTC().Add(-time.Minute)
	start := make(chan struct{})
	errors := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errors <- store.EnsureRuntimeSession(EnsureRuntimeSessionInput{
				SessionID: "first-sighting", CanonicalAgentID: agent.ID, StartedAt: started,
			})
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent session upsert: %v", err)
		}
	}
	sessions, err := store.ListRuntimeSessions(agent.ID, 10)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("sessions: len=%d err=%v", len(sessions), err)
	}
	if !sessions[0].StartedAt.Equal(started) || sessions[0].Status != "active" {
		t.Fatalf("session changed under concurrent first sighting: %+v", sessions[0])
	}
}
