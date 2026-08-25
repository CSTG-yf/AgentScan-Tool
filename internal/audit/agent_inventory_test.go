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
