package audit

import (
	"path/filepath"
	"testing"
	"time"
)

func newEventPageStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err = s.Init(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRuntimeEventPageQueries(t *testing.T) {
	s := newEventPageStore(t)
	base := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	agent, err := s.EnsureAgent(AgentIdentityInput{AgentID: "agent-1", AgentName: "Codex", Kind: "terminal-agent", ObservedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	emptyAgent, err := s.EnsureAgent(AgentIdentityInput{AgentID: "agent-empty", AgentName: "No Events", Kind: "editor-agent", ObservedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	inputs := []RuntimeEventInput{
		{EventType: "tool.call", EventSource: RuntimeSourceAgentHook, EventCategory: RuntimeCategoryTool, CanonicalAgentID: agent.ID, AgentName: "Codex", Outcome: "allowed", PID: 10, ActorPID: 11, Target: "shell", Detail: "safe operation", Timestamp: base},
		{EventType: "file.read", EventSource: RuntimeSourceOSSensor, EventCategory: RuntimeCategoryFile, CanonicalAgentID: agent.ID, AgentName: "Codex", Outcome: "blocked", PID: 10, ActorPID: 12, Target: "credentials", Severity: "HIGH", Timestamp: base.Add(time.Minute)},
		{EventType: "file.write", EventSource: RuntimeSourceDesktop, EventCategory: RuntimeCategoryFile, Outcome: "observed", ActorPID: 99, Target: "legacy", Timestamp: base.Add(2 * time.Minute)},
	}
	for _, in := range inputs {
		if _, err := s.RecordRuntimeEvent(in); err != nil {
			t.Fatal(err)
		}
	}
	rows, totalErr := s.ListRuntimeEvents(RuntimeEventFilter{IncludeDesktop: true, Sort: "timestamp_desc", Limit: 2})
	if totalErr != nil {
		t.Fatal(totalErr)
	}
	if len(rows) != 2 || rows[0].Target != "legacy" {
		t.Fatalf("descending page = %+v", rows)
	}
	if n, err := s.CountRuntimeEvents(RuntimeEventFilter{}); err != nil || n != 2 {
		t.Fatalf("default count=%d err=%v", n, err)
	}
	if n, err := s.CountRuntimeEvents(RuntimeEventFilter{IncludeDesktop: true}); err != nil || n != 3 {
		t.Fatalf("inclusive count=%d err=%v", n, err)
	}
	if n, err := s.CountRuntimeEvents(RuntimeEventFilter{EventSource: RuntimeSourceDesktop}); err != nil || n != 0 {
		t.Fatalf("desktop exclusion count=%d err=%v", n, err)
	}
	filtered, err := s.ListRuntimeEvents(RuntimeEventFilter{IncludeDesktop: true, ActorPID: 12, Outcome: "blocked", Keyword: "credentials", Limit: 10})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("filtered=%+v err=%v", filtered, err)
	}
	filtered, err = s.ListRuntimeEvents(RuntimeEventFilter{AgentID: agent.ID, EventCategory: RuntimeCategoryFile, EventSource: RuntimeSourceOSSensor, Severity: "HIGH", AgentPID: 10, Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second), Sort: "timestamp_asc", Limit: 10})
	if err != nil || len(filtered) != 1 || filtered[0].Target != "credentials" {
		t.Fatalf("compound runtime filter=%+v all=%+v err=%v", filtered, rows, err)
	}
	ascending, err := s.ListRuntimeEvents(RuntimeEventFilter{IncludeDesktop: true, Sort: "timestamp_asc", Limit: 10})
	if err != nil || ascending[0].Target != "shell" {
		t.Fatalf("ascending=%+v err=%v", ascending, err)
	}
	summary, err := s.RuntimeEventSummary(RuntimeEventFilter{IncludeDesktop: true})
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalEvents != 3 || summary.ActiveAgentCount != 1 || summary.ToolEventCount != 1 || summary.FileEventCount != 2 {
		t.Fatalf("summary=%+v", summary)
	}
	agents, err := s.RuntimeEventAgents(RuntimeEventFilter{IncludeDesktop: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) < 3 {
		t.Fatalf("agents=%+v", agents)
	}
	var foundEmpty bool
	for _, item := range agents {
		if item.AgentID == emptyAgent.ID {
			foundEmpty = true
			if item.EventCount != 0 || item.LatestEventAt != "" {
				t.Fatalf("empty runtime agent=%+v", item)
			}
		}
	}
	if !foundEmpty {
		t.Fatalf("empty runtime agent missing: %+v", agents)
	}
	facets, err := s.RuntimeEventFacetValues(RuntimeEventFilter{IncludeDesktop: true})
	if err != nil || len(facets.Outcomes) != 3 {
		t.Fatalf("facets=%+v err=%v", facets, err)
	}
}

func TestAuditEventPageQueries(t *testing.T) {
	s := newEventPageStore(t)
	base := time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)
	agent, err := s.EnsureAgent(AgentIdentityInput{AgentID: "agent-a", AgentName: "Claude", Kind: "terminal-agent", ObservedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	emptyAgent, err := s.EnsureAgent(AgentIdentityInput{AgentID: "agent-a-empty", AgentName: "No Audits", Kind: "editor-agent", ObservedAt: base})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []Event{{ID: "audit-1", Timestamp: base, Action: "tool.inspect", Target: "shell", Actor: "gateway", Details: "allowed request", Severity: "INFO", CanonicalAgentID: agent.ID, AgentName: "Claude", Connector: "claude", ToolName: "bash", RequestID: "req-1"}, {ID: "audit-2", Timestamp: base.Add(time.Minute), Action: "guardrail.block", Target: "secret", Actor: "gateway", Details: "blocked request", Severity: "HIGH", CanonicalAgentID: agent.ID, AgentName: "Claude", Connector: "claude", ToolName: "read", RequestID: "req-2", Enforced: true}, {ID: "audit-3", Timestamp: base.Add(2 * time.Minute), Action: "admin.reload", Actor: "operator", Details: "system action", Severity: "LOW"}} {
		if err := s.LogEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	rows, total, err := s.QueryAuditEvents(AuditEventFilter{Connector: "claude", Sort: "timestamp_desc", Limit: 1})
	if err != nil || total != 2 || len(rows) != 1 || rows[0].ID != "audit-2" {
		t.Fatalf("rows=%+v total=%d err=%v", rows, total, err)
	}
	blocked, total, err := s.QueryAuditEvents(AuditEventFilter{Enforced: func() *bool { v := true; return &v }(), Keyword: "secret", Limit: 20})
	if err != nil || total != 1 || blocked[0].RequestID != "req-2" {
		t.Fatalf("blocked=%+v total=%d err=%v", blocked, total, err)
	}
	blocked, total, err = s.QueryAuditEvents(AuditEventFilter{AgentID: agent.ID, Action: "guardrail.block", Severity: "HIGH", Connector: "claude", Since: base.Add(30 * time.Second), Until: base.Add(90 * time.Second), Limit: 20})
	if err != nil || total != 1 || blocked[0].ID != "audit-2" {
		t.Fatalf("compound audit filter=%+v total=%d err=%v", blocked, total, err)
	}
	summary, err := s.AuditEventSummary(AuditEventFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalEvents != 3 || summary.RelatedAgentCount != 1 || summary.HighOrAboveCount != 1 || summary.EnforcedCount != 1 {
		t.Fatalf("summary=%+v", summary)
	}
	agents, err := s.AuditEventAgents(AuditEventFilter{})
	if err != nil || len(agents) < 3 {
		t.Fatalf("agents=%+v err=%v", agents, err)
	}
	var foundEmpty bool
	for _, item := range agents {
		if item.AgentID == emptyAgent.ID {
			foundEmpty = true
			if item.EventCount != 0 || item.HighOrAboveCount != 0 || item.LatestEventAt != "" {
				t.Fatalf("empty audit agent=%+v", item)
			}
		}
	}
	if !foundEmpty {
		t.Fatalf("empty audit agent missing: %+v", agents)
	}
	facets, err := s.AuditEventFacetValues(AuditEventFilter{})
	if err != nil || len(facets.Actions) != 3 {
		t.Fatalf("facets=%+v err=%v", facets, err)
	}
	detail, ok, err := s.GetAuditEvent("audit-2")
	if err != nil || !ok || detail.Action != "guardrail.block" {
		t.Fatalf("detail=%+v ok=%v err=%v", detail, ok, err)
	}
}
