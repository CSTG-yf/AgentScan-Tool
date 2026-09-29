// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestAgentInventoryCanonicalizesScansAndEvents(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), ".codex", "skills", "danger.yaml")
	now := time.Now().UTC()
	if err := store.InsertScanSummary(scanner.ScanSummaryParams{
		ScanID:       "scan-codex-1",
		Scanner:      "skill-scanner",
		Target:       target,
		Timestamp:    now,
		FindingCount: 1,
		MaxSeverity:  "HIGH",
		RawJSON:      `{}`,
		AgentID:      "openai-codex",
		AgentName:    "codex",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.LogEvent(Event{
		Action:    "guardrail.block",
		Target:    target,
		Severity:  "HIGH",
		AgentName: "codex",
		Connector: "codex",
	}); err != nil {
		t.Fatal(err)
	}

	agents, err := store.ListAgents(10)
	if err != nil {
		t.Fatal(err)
	}
	var codex *CanonicalAgent
	for i := range agents {
		if agents[i].ID == "codex" {
			codex = &agents[i]
			break
		}
	}
	if codex == nil {
		t.Fatalf("codex canonical agent missing: %+v", agents)
	}
	if codex.DisplayName != "OpenAI Codex" {
		t.Fatalf("display name = %q, want OpenAI Codex", codex.DisplayName)
	}
	if codex.StaticResourceCount != 1 || codex.RiskResourceCount != 1 {
		t.Fatalf("resource counts = (%d,%d), want (1,1)", codex.StaticResourceCount, codex.RiskResourceCount)
	}

	scans, err := store.ListLatestStaticScans(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(scans) != 1 {
		t.Fatalf("latest static scans = %d, want 1", len(scans))
	}
	if scans[0].CanonicalAgentID != "codex" || scans[0].AgentDisplayName != "OpenAI Codex" {
		t.Fatalf("scan agent = (%q,%q), want codex/OpenAI Codex", scans[0].CanonicalAgentID, scans[0].AgentDisplayName)
	}
	if scans[0].StaticResourceID == "" {
		t.Fatal("scan static_resource_id was empty")
	}

	events, err := store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].CanonicalAgentID != "codex" || events[0].AgentName != "OpenAI Codex" {
		t.Fatalf("event agent = (%q,%q), want codex/OpenAI Codex", events[0].CanonicalAgentID, events[0].AgentName)
	}
}

func TestAuditAgentBackfillSkipsBoundEvents(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"already-bound", "missing-binding"} {
		if err := store.LogEvent(Event{Action: action, AgentName: "codex", Connector: "codex"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET agent_name = 'custom display' WHERE action = 'already-bound'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET canonical_agent_id = NULL WHERE action = 'missing-binding'`); err != nil {
		t.Fatal(err)
	}
	if err := store.backfillAuditEventAgents(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ action, agentID, agentName string }{
		{"already-bound", "codex", "custom display"},
		{"missing-binding", "codex", "OpenAI Codex"},
	} {
		var agentID, agentName string
		if err := store.db.QueryRow(`SELECT canonical_agent_id, agent_name FROM audit_events WHERE action = ?`, tc.action).Scan(&agentID, &agentName); err != nil {
			t.Fatal(err)
		}
		if agentID != tc.agentID || agentName != tc.agentName {
			t.Errorf("%s: got (%q, %q), want (%q, %q)", tc.action, agentID, agentName, tc.agentID, tc.agentName)
		}
	}
}

func TestEnsureAgentRollsBackWhenAliasWriteFails(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DROP TABLE agent_aliases`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureAgent(AgentIdentityInput{AgentName: "unique-transaction-agent"}); err == nil {
		t.Fatal("expected alias write to fail")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM agents WHERE id = 'unique-transaction-agent'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("agent upsert was committed without its aliases")
	}
}
