// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Unified runtime event vocabulary (Phase 1). Connectors emit wildly
// different native event names (UserPromptSubmit / PreToolUse / Stop,
// codex notify stages, ...); adapters in internal/gateway translate
// them onto this stable vocabulary BEFORE the Detection Engine or the
// page API ever sees them. Agent-specific naming differences must stay
// inside the adapter layer.
const (
	RuntimeEventPromptSubmit      = "prompt.submit"
	RuntimeEventToolPreCall       = "tool.pre_call"
	RuntimeEventToolPostCall      = "tool.post_call"
	RuntimeEventAgentStop         = "agent.stop"
	RuntimeEventAgentSessionStart = "agent.session_start"
	RuntimeEventAgentSessionEnd   = "agent.session_end"

	RuntimeEventContentInjection   = "content.prompt_injection"
	RuntimeEventContentSecret      = "content.secret"
	RuntimeEventContentPII         = "content.pii"
	RuntimeEventContentExfilSignal = "content.exfiltration_signal"
	RuntimeEventContentInspected   = "content.inspected"

	RuntimeEventNetworkRequest  = "network.request"
	RuntimeEventNetworkConnect  = "network.connect"
	RuntimeEventNetworkSend     = "network.send"
	RuntimeEventNetworkBlocked  = "network.blocked"
	RuntimeEventNetworkDownload = "network.download"

	// OS Runtime Sensor vocabulary (Phase 2 first version): the
	// process/file/network activity that never passes through Prompt,
	// LLM, or Tool Hook paths — the classic exploit chain
	// (vuln → shell → curl → write payload → exec payload) is only
	// visible here.
	RuntimeEventProcessExec = "process.exec"
	RuntimeEventProcessExit = "process.exit"
	RuntimeEventFileRead    = "file.read"
	RuntimeEventFileWrite   = "file.write"
	RuntimeEventFileDelete  = "file.delete"
)

// RuntimeEventSource identifies which of the three runtime pipelines
// produced the event. scan_findings is deliberately NOT a source here —
// static scan results remain static risk context, not runtime events.
const (
	RuntimeSourceGuardrail = "guardrail"
	RuntimeSourceAgentHook = "agent_hook"
	RuntimeSourceProxy     = "proxy"
	RuntimeSourceOSSensor  = "os-sensor"
	RuntimeSourceDesktop   = "desktop-behavior"
)

// RuntimeEventCategory groups events for page filtering.
const (
	RuntimeCategoryPrompt    = "prompt"
	RuntimeCategoryTool      = "tool"
	RuntimeCategoryLifecycle = "lifecycle"
	RuntimeCategoryContent   = "content"
	RuntimeCategoryNetwork   = "network"
	RuntimeCategoryProcess   = "process"
	RuntimeCategoryFile      = "file"
)

// RuntimeEventInput is the adapter-facing shape for the Event
// Normalizer. Every runtime pipeline (Guardrail / Agent Hook / Proxy)
// translates its native payload into this struct and calls
// RecordRuntimeEvent — the single choke point that binds the event to
// the canonical Agent Inventory, the runtime session, and the unified
// behavior_events table.
type RuntimeEventInput struct {
	// Core identity. EventType must come from the unified vocabulary;
	// EventSource from the RuntimeSource* constants.
	EventType     string
	EventSource   string
	EventCategory string

	// Attribution: who (agent), which run (session), which call chain.
	CanonicalAgentID string
	AgentName        string
	SessionID        string
	TraceID          string
	SpanID           string
	ParentSpanID     string

	// Process identity when observable.
	PID             uint32
	PPID            uint32
	AgentExecutable string
	ActorPID        uint32
	ActorExecutable string
	AgentInstanceID string
	Path            string
	Action          string

	// What happened, on what.
	Operation string
	Target    string
	ToolName  string
	MCPServer string

	// Detection outcome (guardrail/hook verdicts, egress decisions).
	Severity   string
	Confidence float64
	Outcome    string // observed | allowed | blocked | flagged | error

	// Detail is a short human-readable summary (already redacted by
	// the adapter — the normalizer does not re-run PII scrubbing).
	Detail string

	// Attributes carries structured, non-sensitive key/value pairs
	// (direction, action, branch, decision, rule_ids, ...).
	Attributes map[string]any

	// RawData is optional and must already be safe to persist; the
	// normalizer truncates it to runtimeEventRawMaxBytes.
	RawData map[string]any

	Timestamp time.Time
}

const runtimeEventRawMaxBytes = 16 * 1024

// RecordRuntimeEvent normalizes one runtime event, ensures the Agent
// Inventory binding and the runtime session row exist, and appends the
// unified event to behavior_events. It returns the inserted
// behavior_events.id so the Phase-2 detection engine can link
// evidence. It is intentionally forgiving: pipeline callers must never
// fail a request because observability persistence hiccupped.
func (s *Store) RecordRuntimeEvent(in RuntimeEventInput) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	in.EventType = strings.TrimSpace(in.EventType)
	if in.EventType == "" {
		return 0, nil
	}
	if in.EventSource == "" {
		in.EventSource = RuntimeSourceDesktop
	}
	if in.EventCategory == "" {
		in.EventCategory = runtimeCategoryForType(in.EventType)
	}
	if in.Outcome == "" {
		in.Outcome = "observed"
	}
	if in.Timestamp.IsZero() {
		in.Timestamp = time.Now().UTC()
	}
	if in.SpanID == "" {
		in.SpanID = uuid.NewString()
	}

	agent, err := s.EnsureAgent(AgentIdentityInput{
		AgentID:    in.CanonicalAgentID,
		AgentName:  firstNonEmpty(in.AgentName, in.AgentExecutable),
		Source:     "runtime_events:" + in.EventSource,
		Status:     "running",
		ObservedAt: in.Timestamp,
	})
	if err != nil {
		return 0, err
	}
	if agent.ID != "" {
		in.CanonicalAgentID = agent.ID
		if agent.DisplayName != "" {
			in.AgentName = agent.DisplayName
		}
	}

	// A runtime event that carries a session id implies the session is
	// (or was) live for this agent. Upsert keeps started_at stable.
	if in.SessionID != "" && in.CanonicalAgentID != "" {
		if err := s.EnsureRuntimeSession(EnsureRuntimeSessionInput{
			SessionID:        in.SessionID,
			CanonicalAgentID: in.CanonicalAgentID,
			StartedAt:        in.Timestamp,
		}); err != nil {
			return 0, err
		}
	}

	attrsJSON := ""
	if len(in.Attributes) > 0 {
		if b, err := json.Marshal(in.Attributes); err == nil {
			attrsJSON = string(b)
		}
	}
	rawJSON := ""
	if len(in.RawData) > 0 {
		if b, err := json.Marshal(in.RawData); err == nil && len(b) <= runtimeEventRawMaxBytes {
			rawJSON = string(b)
		}
	}

	result, err := s.execDB(context.Background(), "runtime_event_insert", `
INSERT INTO behavior_events (
  timestamp, event_type, source, event_source, event_category,
  event_id, span_id, parent_span_id,
  agent_pid, agent_executable, actor_pid, actor_executable, path, action,
  ppid, operation, target, tool_name, mcp_server,
  severity, confidence, outcome, detail,
  agent_name, canonical_agent_id, agent_instance_id, session_id, trace_id,
  attributes_json, raw_data_json, sidecar_instance_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Timestamp.UTC().Format(time.RFC3339Nano),
		in.EventType,
		// source is the legacy NOT NULL column; keep it aligned with
		// the unified event source so legacy readers stay consistent.
		in.EventSource,
		in.EventSource,
		in.EventCategory,
		uuid.NewString(),
		nullStr(in.SpanID),
		nullStr(in.ParentSpanID),
		in.PID,
		// The legacy behavior_events schema declares executable columns
		// NOT NULL. Preserve an empty string when the sensor did not expose
		// process metadata instead of binding SQL NULL.
		in.AgentExecutable,
		in.ActorPID,
		in.ActorExecutable,
		nullStr(in.Path),
		nullStr(in.Action),
		in.PPID,
		nullStr(in.Operation),
		nullStr(in.Target),
		nullStr(in.ToolName),
		nullStr(in.MCPServer),
		nullStr(in.Severity),
		nullFloat64(in.Confidence),
		in.Outcome,
		in.Detail,
		nullStr(in.AgentName),
		nullStr(in.CanonicalAgentID),
		nullStr(in.AgentInstanceID),
		nullStr(in.SessionID),
		nullStr(in.TraceID),
		nullStr(attrsJSON),
		nullStr(rawJSON),
		nullStr(ProcessAgentInstanceID()),
	)
	if err != nil {
		return 0, err
	}
	id, _ := result.LastInsertId()
	return id, nil
}

// GetRuntimeEvent loads one unified runtime event by behavior_events
// id. The detection engine uses it to evaluate the triggering event
// after persistence.
func (s *Store) GetRuntimeEvent(id int64) (BehaviorEvent, bool, error) {
	if s == nil || s.db == nil || id <= 0 {
		return BehaviorEvent{}, false, nil
	}
	rows, err := s.queryDB(context.Background(), "runtime_event_get", `
SELECT id, timestamp, event_type, source,
       COALESCE(event_source, ''), COALESCE(event_category, ''),
       COALESCE(event_id, ''), COALESCE(span_id, ''), COALESCE(parent_span_id, ''),
       agent_pid, COALESCE(agent_executable, ''), COALESCE(actor_pid, 0),
       COALESCE(actor_executable, ''), COALESCE(path, ''), COALESCE(action, ''),
       COALESCE(ppid, 0),
       COALESCE(operation, ''), COALESCE(target, ''), COALESCE(tool_name, ''), COALESCE(mcp_server, ''),
       COALESCE(severity, ''), COALESCE(confidence, 0), outcome, detail,
       COALESCE(agent_name, ''), COALESCE(canonical_agent_id, ''), COALESCE(agent_instance_id, ''),
       COALESCE(session_id, ''), COALESCE(trace_id, ''), COALESCE(attributes_json, '')
FROM behavior_events WHERE id = ? AND "delete" = 0`, id)
	if err != nil {
		return BehaviorEvent{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return BehaviorEvent{}, false, nil
	}
	e, err := scanRuntimeEventRow(rows)
	if err != nil {
		return BehaviorEvent{}, false, err
	}
	return e, true, rows.Err()
}

// runtimeCategoryForType derives the page-filter category from the
// unified event type vocabulary.
func runtimeCategoryForType(eventType string) string {
	switch {
	case strings.HasPrefix(eventType, "prompt."):
		return RuntimeCategoryPrompt
	case strings.HasPrefix(eventType, "tool."):
		return RuntimeCategoryTool
	case strings.HasPrefix(eventType, "agent."):
		return RuntimeCategoryLifecycle
	case strings.HasPrefix(eventType, "content."):
		return RuntimeCategoryContent
	case strings.HasPrefix(eventType, "network."):
		return RuntimeCategoryNetwork
	case strings.HasPrefix(eventType, "process."):
		return RuntimeCategoryProcess
	case strings.HasPrefix(eventType, "file."):
		return RuntimeCategoryFile
	default:
		return RuntimeCategoryLifecycle
	}
}

// RuntimeCategoryForEventType exposes the normalizer's category mapping to
// compatibility adapters without duplicating the vocabulary rules.
func RuntimeCategoryForEventType(eventType string) string {
	return runtimeCategoryForType(eventType)
}

// nullFloat64 mirrors nullStr for the REAL confidence column.
func nullFloat64(v float64) sql.NullFloat64 {
	if v == 0 {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: v, Valid: true}
}

// EnsureRuntimeSessionInput upserts one agent runtime session row.
type EnsureRuntimeSessionInput struct {
	SessionID        string
	CanonicalAgentID string
	RootPID          uint32
	StartedAt        time.Time
	WorkingDirectory string
	User             string
	// Status defaults to "active"; pass "ended" when the adapter knows
	// the run finished (agent.stop / session_end events).
	Status   string
	Metadata map[string]any
}

// EnsureRuntimeSession creates or refreshes the agent_runtime_sessions
// row for one actual agent run. Re-sighting an active session never
// rewrites started_at, so session duration stays truthful; a session
// previously marked ended transitions back to active when a genuinely
// new event for the same session id arrives (agents resume sessions).
func (s *Store) EnsureRuntimeSession(in EnsureRuntimeSessionInput) error {
	if s == nil || s.db == nil {
		return nil
	}
	in.SessionID = strings.TrimSpace(in.SessionID)
	if in.SessionID == "" {
		return nil
	}
	if in.StartedAt.IsZero() {
		in.StartedAt = time.Now().UTC()
	}
	if in.Status == "" {
		in.Status = "active"
	}

	var (
		status    string
		startedAt string
		ended     sql.NullString
		wd        sql.NullString
		user      sql.NullString
		rootPID   int64
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT status, started_at, ended_at, working_directory, user, root_pid
FROM agent_runtime_sessions WHERE session_id = ?`, in.SessionID,
	).Scan(&status, &startedAt, &ended, &wd, &user, &rootPID)
	if err == nil {
		newStatus := status
		if in.Status == "ended" {
			newStatus = "ended"
		} else if status != "active" {
			newStatus = "active"
		}
		newWD := strings.TrimSpace(wd.String)
		if newWD == "" {
			newWD = in.WorkingDirectory
		}
		newUser := strings.TrimSpace(user.String)
		if newUser == "" {
			newUser = in.User
		}
		newPID := rootPID
		if in.RootPID != 0 {
			newPID = int64(in.RootPID)
		}
		endedExpr := "ended_at"
		endedArg := ""
		if in.Status == "ended" {
			endedExpr = "?"
			endedArg = in.StartedAt.UTC().Format(time.RFC3339Nano)
		}
		_, err := s.execDB(context.Background(), "runtime_session_refresh", `
UPDATE agent_runtime_sessions
SET status = ?, working_directory = ?, user = ?, root_pid = ?,
    ended_at = `+endedExpr+`
WHERE session_id = ?`,
			newStatus, nullStr(newWD), nullStr(newUser), newPID, endedArg, in.SessionID,
		)
		return err
	}
	if err != sql.ErrNoRows {
		return err
	}

	metaJSON := ""
	if len(in.Metadata) > 0 {
		if b, err := json.Marshal(in.Metadata); err == nil {
			metaJSON = string(b)
		}
	}
	_, err = s.execDB(context.Background(), "runtime_session_insert", `
INSERT INTO agent_runtime_sessions (
  session_id, agent_id, root_pid, started_at, ended_at,
  working_directory, user, status, metadata_json
) VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
		in.SessionID,
		in.CanonicalAgentID,
		in.RootPID,
		in.StartedAt.UTC().Format(time.RFC3339Nano),
		nullStr(in.WorkingDirectory),
		nullStr(in.User),
		in.Status,
		nullStr(metaJSON),
	)
	return err
}

// RuntimeSession is the read model for agent_runtime_sessions.
type RuntimeSession struct {
	SessionID        string     `json:"session_id"`
	AgentID          string     `json:"agent_id"`
	AgentName        string     `json:"agent_name,omitempty"`
	RootPID          uint32     `json:"root_pid"`
	StartedAt        time.Time  `json:"started_at"`
	EndedAt          *time.Time `json:"ended_at,omitempty"`
	WorkingDirectory string     `json:"working_directory,omitempty"`
	User             string     `json:"user,omitempty"`
	Status           string     `json:"status"`
	EventCount       int        `json:"event_count"`
}

// ListRuntimeSessions returns recent runtime sessions, newest first,
// with the per-session event count for the page timeline.
func (s *Store) ListRuntimeSessions(agentID string, limit int) ([]RuntimeSession, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	where := `WHERE s."delete" = 0`
	args := []any{}
	if agentID != "" {
		where += " AND s.agent_id = ?"
		args = append(args, agentID)
	}
	args = append(args, limit)
	rows, err := s.queryDB(context.Background(), "runtime_sessions_list", `
SELECT s.session_id, s.agent_id, COALESCE(a.display_name, ''),
       s.root_pid, s.started_at, s.ended_at,
       COALESCE(s.working_directory, ''), COALESCE(s.user, ''), s.status,
       (SELECT COUNT(*) FROM behavior_events b WHERE b.session_id = s.session_id AND b."delete" = 0)
FROM agent_runtime_sessions s
LEFT JOIN agents a ON a.id = s.agent_id
`+where+`
ORDER BY s.started_at DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuntimeSession
	for rows.Next() {
		var rs RuntimeSession
		var startedAt string
		var ended sql.NullString
		var rootPID int64
		if err := rows.Scan(&rs.SessionID, &rs.AgentID, &rs.AgentName, &rootPID,
			&startedAt, &ended, &rs.WorkingDirectory, &rs.User, &rs.Status, &rs.EventCount); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, startedAt); err == nil {
			rs.StartedAt = t
		}
		if ended.Valid && ended.String != "" {
			if t, err := time.Parse(time.RFC3339Nano, ended.String); err == nil {
				rs.EndedAt = &t
			}
		}
		rs.RootPID = uint32(rootPID)
		out = append(out, rs)
	}
	return out, rows.Err()
}

// RuntimeEventFilter selects unified runtime events for the timeline
// query. Zero fields return the newest events across all agents.
// Since bounds the correlation window from below (events at or after
// Since) — the detection engine uses it to load the recent
// same-session chain around a triggering event.
type RuntimeEventFilter struct {
	AgentID       string
	AgentTypeID   int64
	SessionID     string
	TraceID       string
	EventType     string
	EventCategory string
	EventSource   string
	Severity      string
	PID           uint32
	Keyword       string
	Since         time.Time
	Until         time.Time
	// IncludeDesktop includes legacy desktop-behavior rows. Normal page
	// timelines omit them, while historical replay can opt in explicitly.
	IncludeDesktop bool
	Offset         int
	Limit          int
}

func runtimeEventWhereClause(f RuntimeEventFilter) (string, []any) {
	var conds []string
	var args []any
	conds = append(conds, `"delete" = 0`)
	// The unified timeline carries Guardrail / Agent Hook / Proxy
	// runtime events. Legacy desktop-behavior rows stay out unless the
	// caller explicitly asks for that source.
	if f.EventSource != "" {
		conds = append(conds, "COALESCE(NULLIF(event_source, ''), source, '') = ?")
		args = append(args, f.EventSource)
	} else if !f.IncludeDesktop {
		// Legacy rows written before event_source was introduced have
		// source=desktop-behavior but a NULL event_source. Treat both
		// representations identically so they do not leak into the
		// unified runtime timeline.
		conds = append(conds, "COALESCE(NULLIF(event_source, ''), source, '') != '"+RuntimeSourceDesktop+"'")
	}
	if f.AgentID != "" {
		conds = append(conds, "canonical_agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.AgentTypeID > 0 {
		conds = append(conds, `EXISTS (SELECT 1 FROM agents a WHERE a.id=behavior_events.canonical_agent_id AND a.agent_type_id=? AND a."delete"=0)`)
		args = append(args, f.AgentTypeID)
	}
	if f.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.TraceID != "" {
		conds = append(conds, "trace_id = ?")
		args = append(args, f.TraceID)
	}
	if f.EventType != "" {
		conds = append(conds, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.EventCategory != "" {
		conds = append(conds, "event_category = ?")
		args = append(args, f.EventCategory)
	}
	if f.Severity != "" {
		conds = append(conds, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.PID > 0 {
		conds = append(conds, "agent_pid = ?")
		args = append(args, f.PID)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "timestamp <= ?")
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if keyword := strings.ToLower(strings.TrimSpace(f.Keyword)); keyword != "" {
		like := "%" + keyword + "%"
		conds = append(conds, `(
LOWER(event_type) LIKE ? OR LOWER(COALESCE(event_category, '')) LIKE ?
OR LOWER(COALESCE(event_source, '')) LIKE ? OR LOWER(COALESCE(agent_name, '')) LIKE ?
OR LOWER(COALESCE(canonical_agent_id, '')) LIKE ? OR LOWER(COALESCE(session_id, '')) LIKE ?
OR LOWER(COALESCE(trace_id, '')) LIKE ? OR LOWER(COALESCE(operation, '')) LIKE ?
OR LOWER(COALESCE(target, '')) LIKE ? OR LOWER(COALESCE(tool_name, '')) LIKE ?
OR LOWER(COALESCE(mcp_server, '')) LIKE ? OR LOWER(COALESCE(detail, '')) LIKE ?
)`)
		for i := 0; i < 12; i++ {
			args = append(args, like)
		}
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ListRuntimeEvents returns unified runtime events in chronological
// order for the "who did what, when, through which pipeline" timeline.
func (s *Store) ListRuntimeEvents(f RuntimeEventFilter) ([]BehaviorEvent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if f.Limit <= 0 {
		f.Limit = 300
	}
	where, args := runtimeEventWhereClause(f)
	if f.Offset < 0 {
		f.Offset = 0
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.queryDB(context.Background(), "runtime_events_list", `
SELECT id, timestamp, event_type, source,
       COALESCE(event_source, ''), COALESCE(event_category, ''),
       COALESCE(event_id, ''), COALESCE(span_id, ''), COALESCE(parent_span_id, ''),
       agent_pid, COALESCE(agent_executable, ''), COALESCE(actor_pid, 0),
       COALESCE(actor_executable, ''), COALESCE(path, ''), COALESCE(action, ''),
       COALESCE(ppid, 0),
       COALESCE(operation, ''), COALESCE(target, ''), COALESCE(tool_name, ''), COALESCE(mcp_server, ''),
       COALESCE(severity, ''), COALESCE(confidence, 0), outcome, detail,
       COALESCE(agent_name, ''), COALESCE(canonical_agent_id, ''), COALESCE(agent_instance_id, ''),
       COALESCE(session_id, ''), COALESCE(trace_id, ''), COALESCE(attributes_json, '')
FROM behavior_events
`+where+`
ORDER BY timestamp ASC, id ASC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []BehaviorEvent
	for rows.Next() {
		e, err := scanRuntimeEventRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountRuntimeEvents returns the number of active runtime events matching the
// same filters as ListRuntimeEvents, without applying pagination. It lets the
// API distinguish a page size from the total event count.
func (s *Store) CountRuntimeEvents(f RuntimeEventFilter) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	where, args := runtimeEventWhereClause(f)
	var total int
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM behavior_events `+where, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// scanRuntimeEventRow scans the unified runtime event projection into
// the shared BehaviorEvent struct.
func scanRuntimeEventRow(rows *sql.Rows) (BehaviorEvent, error) {
	var (
		e          BehaviorEvent
		ts         string
		ppid       int64
		actorPID   int64
		confidence float64
		attrs      string
	)
	if err := rows.Scan(
		&e.ID, &ts, &e.EventType, &e.Source,
		&e.EventSource, &e.EventCategory, &e.EventID, &e.SpanID, &e.ParentSpanID,
		&e.AgentPID, &e.AgentExecutable, &actorPID, &e.ActorExecutable, &e.Path, &e.Action,
		&ppid, &e.Operation, &e.Target, &e.ToolName, &e.MCPServer,
		&e.Severity, &confidence, &e.Outcome, &e.Detail,
		&e.AgentName, &e.CanonicalAgentID, &e.AgentInstanceID, &e.SessionID, &e.TraceID, &attrs,
	); err != nil {
		return e, err
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		e.Timestamp = t
	}
	e.PPID = uint32(ppid)
	e.ActorPID = uint32(actorPID)
	e.Confidence = confidence
	if attrs != "" {
		_ = json.Unmarshal([]byte(attrs), &e.Attributes)
	}
	return e, nil
}
