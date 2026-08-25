// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// BehaviorEvent is the Go-owned record for local desktop behavior tracing.
// Tauri/Windows code may observe the process/file activity, but persistence and
// Agent identity binding belong to the backend audit store.
//
// Phase-1 unified runtime events (Guardrail / Agent Hook / Proxy) are
// stored in the same table: EventSource distinguishes the pipeline and
// the EventType carries the unified vocabulary (prompt.submit,
// content.prompt_injection, network.blocked, ...). The legacy
// desktop-behavior fields (AgentExecutable/Actor*/Path/Action) stay for
// the Tauri process observer and are empty for runtime events.
type BehaviorEvent struct {
	ID                int64     `json:"id"`
	Timestamp         time.Time `json:"timestamp"`
	EventType         string    `json:"event_type"`
	Source            string    `json:"source"`
	AgentPID          uint32    `json:"agent_pid"`
	AgentExecutable   string    `json:"agent_executable"`
	ActorPID          uint32    `json:"actor_pid"`
	ActorExecutable   string    `json:"actor_executable"`
	Path              string    `json:"path,omitempty"`
	Action            string    `json:"action,omitempty"`
	Outcome           string    `json:"outcome"`
	Detail            string    `json:"detail"`
	AgentName         string    `json:"agent_name,omitempty"`
	CanonicalAgentID  string    `json:"canonical_agent_id,omitempty"`
	AgentInstanceID   string    `json:"agent_instance_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	TraceID           string    `json:"trace_id,omitempty"`
	SidecarInstanceID string    `json:"sidecar_instance_id,omitempty"`

	// Unified runtime event fields (Phase 1).
	EventID       string         `json:"event_id,omitempty"`
	EventSource   string         `json:"event_source,omitempty"`
	EventCategory string         `json:"event_category,omitempty"`
	SpanID        string         `json:"span_id,omitempty"`
	ParentSpanID  string         `json:"parent_span_id,omitempty"`
	PPID          uint32         `json:"ppid,omitempty"`
	Operation     string         `json:"operation,omitempty"`
	Target        string         `json:"target,omitempty"`
	ToolName      string         `json:"tool_name,omitempty"`
	MCPServer     string         `json:"mcp_server,omitempty"`
	Severity      string         `json:"severity,omitempty"`
	Confidence    float64        `json:"confidence,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

// InsertBehaviorEvent appends one behavior trace event and binds it to the
// canonical Agent Inventory when the executable/name is recognizable.
func (s *Store) InsertBehaviorEvent(e BehaviorEvent) (BehaviorEvent, error) {
	if s == nil || s.db == nil {
		return e, nil
	}
	if strings.TrimSpace(e.EventType) == "" {
		return e, fmt.Errorf("audit: behavior event: event_type is required")
	}
	if strings.TrimSpace(e.Source) == "" {
		e.Source = "desktop-behavior"
	}
	if strings.TrimSpace(e.Outcome) == "" {
		e.Outcome = "observed"
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.SidecarInstanceID == "" {
		e.SidecarInstanceID = ProcessAgentInstanceID()
	}

	agent, err := s.EnsureAgent(AgentIdentityInput{
		AgentID:    e.CanonicalAgentID,
		AgentName:  firstNonEmpty(e.AgentName, e.AgentExecutable),
		Target:     e.Path,
		Source:     "behavior_events",
		Status:     behaviorAgentStatus(e.EventType, e.Outcome),
		ObservedAt: e.Timestamp,
	})
	if err != nil {
		return e, err
	}
	if agent.ID != "" {
		e.CanonicalAgentID = agent.ID
		e.AgentName = agent.DisplayName
	}

	result, err := s.execDB(context.Background(), "behavior_event_insert", `
INSERT INTO behavior_events (
  timestamp, event_type, source, agent_pid, agent_executable, actor_pid, actor_executable,
  path, action, outcome, detail, agent_name, canonical_agent_id, agent_instance_id,
  session_id, trace_id, sidecar_instance_id,
  event_source, event_category, tool_name, target, severity
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.EventType,
		e.Source,
		e.AgentPID,
		e.AgentExecutable,
		e.ActorPID,
		e.ActorExecutable,
		nullStr(e.Path),
		nullStr(e.Action),
		e.Outcome,
		e.Detail,
		nullStr(e.AgentName),
		nullStr(e.CanonicalAgentID),
		nullStr(e.AgentInstanceID),
		nullStr(e.SessionID),
		nullStr(e.TraceID),
		nullStr(e.SidecarInstanceID),
		// Legacy desktop-behavior inserts keep "desktop-behavior" as the
		// unified event source so page filters can separate them from
		// Guardrail / Agent Hook / Proxy runtime events.
		nullStr(firstNonEmpty(e.EventSource, RuntimeSourceDesktop)),
		nullStr(e.EventCategory),
		nullStr(e.ToolName),
		nullStr(e.Target),
		nullStr(e.Severity),
	)
	if err != nil {
		return e, fmt.Errorf("audit: insert behavior event: %w", err)
	}
	if id, err := result.LastInsertId(); err == nil {
		e.ID = id
	}
	return e, nil
}

func behaviorAgentStatus(eventType, outcome string) string {
	combined := strings.ToLower(eventType + " " + outcome)
	if strings.Contains(combined, "start") {
		return "running"
	}
	if strings.Contains(combined, "terminated") || strings.Contains(combined, "termination") {
		return "observed"
	}
	return "observed"
}

// ListBehaviorEvents returns recent behavior events in newest-first order.
func (s *Store) ListBehaviorEvents(limit int) ([]BehaviorEvent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 300
	}
	rows, err := s.queryDB(context.Background(), "behavior_events_list", `
SELECT id,
       timestamp,
       event_type,
       source,
       agent_pid,
       agent_executable,
       actor_pid,
       actor_executable,
       COALESCE(path, ''),
       COALESCE(action, ''),
       outcome,
       detail,
       COALESCE(agent_name, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(agent_instance_id, ''),
       COALESCE(session_id, ''),
       COALESCE(trace_id, ''),
       COALESCE(sidecar_instance_id, ''),
       COALESCE(event_source, ''),
       COALESCE(event_category, ''),
       COALESCE(tool_name, ''),
       COALESCE(target, ''),
       COALESCE(severity, '')
FROM behavior_events
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list behavior events: %w", err)
	}
	defer rows.Close()

	var out []BehaviorEvent
	for rows.Next() {
		var e BehaviorEvent
		var ts string
		var agentPID, actorPID int64
		if err := rows.Scan(
			&e.ID,
			&ts,
			&e.EventType,
			&e.Source,
			&agentPID,
			&e.AgentExecutable,
			&actorPID,
			&e.ActorExecutable,
			&e.Path,
			&e.Action,
			&e.Outcome,
			&e.Detail,
			&e.AgentName,
			&e.CanonicalAgentID,
			&e.AgentInstanceID,
			&e.SessionID,
			&e.TraceID,
			&e.SidecarInstanceID,
			&e.EventSource,
			&e.EventCategory,
			&e.ToolName,
			&e.Target,
			&e.Severity,
		); err != nil {
			return nil, fmt.Errorf("audit: scan behavior event row: %w", err)
		}
		if parsed, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.Timestamp = parsed
		}
		e.AgentPID = uint32(agentPID)
		e.ActorPID = uint32(actorPID)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneBehaviorEvents applies the Go-owned retention policy for behavior
// traces. It intentionally only affects behavior_events, not audit_events or
// scan history.
func (s *Store) PruneBehaviorEvents(retentionDays int, maxRows int) error {
	if s == nil || s.db == nil {
		return nil
	}
	if retentionDays > 0 {
		cutoff := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).Format(time.RFC3339Nano)
		if _, err := s.execDB(context.Background(), "behavior_events_prune_time",
			`DELETE FROM behavior_events WHERE timestamp < ?`, cutoff,
		); err != nil {
			return fmt.Errorf("audit: prune behavior events by time: %w", err)
		}
	}
	if maxRows > 0 {
		if _, err := s.execDB(context.Background(), "behavior_events_prune_rows", `
DELETE FROM behavior_events
WHERE id IN (
  SELECT id FROM behavior_events
  WHERE id NOT IN (SELECT id FROM behavior_events ORDER BY id DESC LIMIT ?)
)`, maxRows); err != nil {
			return fmt.Errorf("audit: prune behavior events by row count: %w", err)
		}
	}
	return nil
}

func behaviorEventFromNullable(
	id int64,
	timestamp string,
	eventType string,
	source string,
	agentPID int64,
	agentExecutable string,
	actorPID int64,
	actorExecutable string,
	path sql.NullString,
	action sql.NullString,
	outcome string,
	detail string,
) BehaviorEvent {
	e := BehaviorEvent{
		ID:              id,
		EventType:       eventType,
		Source:          source,
		AgentPID:        uint32(agentPID),
		AgentExecutable: agentExecutable,
		ActorPID:        uint32(actorPID),
		ActorExecutable: actorExecutable,
		Outcome:         outcome,
		Detail:          detail,
	}
	if parsed, err := time.Parse(time.RFC3339Nano, timestamp); err == nil {
		e.Timestamp = parsed
	}
	if path.Valid {
		e.Path = path.String
	}
	if action.Valid {
		e.Action = action.String
	}
	return e
}
