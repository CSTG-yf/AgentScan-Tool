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

// Detection status values. "open" risks are live; "mitigated" means
// every supporting event was blocked by an enforcement layer before
// the risky action completed; "resolved" is operator-acknowledged.
const (
	RuntimeDetectionStatusOpen      = "open"
	RuntimeDetectionStatusMitigated = "mitigated"
	RuntimeDetectionStatusResolved  = "resolved"
)

// Evidence link roles describe how a behavior event participates in a
// detection: the "trigger" event fired the rule, "supporting" events
// complete the correlated chain, "corroborating" events add context.
const (
	DetectionRoleTrigger      = "trigger"
	DetectionRoleSupporting   = "supporting"
	DetectionRoleCorroborating = "corroborating"
)

// RuntimeDetection is the structured answer to "这里有什么安全问题？".
// behavior_events answers "发生了什么？" — a detection is the risk
// verdict derived from one or more events by a generic detection rule.
type RuntimeDetection struct {
	DetectionID   string         `json:"detection_id"`
	AgentID       string         `json:"agent_id"`
	AgentName     string         `json:"agent_name,omitempty"`
	SessionID     string         `json:"session_id,omitempty"`
	TraceID       string         `json:"trace_id,omitempty"`
	DetectionType string         `json:"detection_type"`
	Category      string         `json:"category"`
	Severity      string         `json:"severity"`
	Confidence    float64        `json:"confidence"`
	RuleID        string         `json:"rule_id"`
	Status        string         `json:"status"`
	Title         string         `json:"title"`
	Detail        string         `json:"detail,omitempty"`
	Remediation   string         `json:"remediation,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
	FirstSeenAt   time.Time      `json:"first_seen_at"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
	EventCount    int            `json:"event_count"`
}

// DetectionEvidenceLink binds one behavior event to a detection.
type DetectionEvidenceLink struct {
	DetectionID string    `json:"detection_id"`
	EventID     int64     `json:"event_id"`
	Role        string    `json:"role"`
	Sequence    int       `json:"sequence"`
	LinkedAt    time.Time `json:"linked_at"`
}

// DetectionEvidence is an evidence link joined with its behavior
// event, ready for the page detail view ("哪些 Event 支撑这个
// Detection？").
type DetectionEvidence struct {
	DetectionEvidenceLink
	Event BehaviorEvent `json:"event"`
}

// RuntimeDetectionInput is the detection engine's write shape.
type RuntimeDetectionInput struct {
	AgentID       string
	AgentName     string
	SessionID     string
	TraceID       string
	DetectionType string
	Category      string
	Severity      string
	Confidence    float64
	RuleID        string
	Title         string
	Detail        string
	Remediation   string
	Attributes    map[string]any
	// Evidence events supporting this detection, in chain order. Must
	// reference behavior_events.id rows that already exist.
	Evidence []DetectionEvidenceInput
	SeenAt   time.Time
}

// DetectionEvidenceInput is the evidence part of RuntimeDetectionInput.
type DetectionEvidenceInput struct {
	EventID  int64
	Role     string
	Sequence int
	// Outcome of the evidence event (allowed / blocked / ...). When
	// every evidence event was blocked, the detection is recorded as
	// mitigated instead of open.
	Outcome string
}

// detectionReopenWindow: a matching open detection is reused (its
// last_seen_at bumped, evidence appended) when the rule re-fires
// within this window; after that a fresh detection row starts so
// first_seen_at/last_seen_at stay meaningful per incident.
const detectionReopenWindow = 15 * time.Minute

// RecordRuntimeDetection upserts a detection with dedup semantics:
// identity is (rule_id, agent_id, session_id, detection_type) among
// open detections re-seen within detectionReopenWindow. Re-firing
// bumps last_seen_at, merges severity/confidence upward, appends new
// evidence links, and recomputes the mitigated status from evidence
// outcomes.
func (s *Store) RecordRuntimeDetection(in RuntimeDetectionInput) (RuntimeDetection, error) {
	if s == nil || s.db == nil {
		return RuntimeDetection{}, nil
	}
	in.DetectionType = strings.TrimSpace(in.DetectionType)
	if in.DetectionType == "" {
		return RuntimeDetection{}, nil
	}
	if in.RuleID == "" {
		in.RuleID = in.DetectionType
	}
	if in.Category == "" {
		in.Category = "suspicious"
	}
	if in.Severity == "" {
		in.Severity = "medium"
	}
	if in.SeenAt.IsZero() {
		in.SeenAt = time.Now().UTC()
	}

	sessionKey := nullStr(in.SessionID)
	cutoff := in.SeenAt.Add(-detectionReopenWindow).UTC().Format(time.RFC3339Nano)

	// Find the most recent matching open detection inside the reopen
	// window. NULL-safe session comparison keeps the WHERE tight.
	var (
		existingID  string
		firstSeen   string
		lastSeen    string
		severity    string
		confidence  float64
		status      string
		eventCount  int
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT detection_id, first_seen_at, last_seen_at, severity, confidence, status, event_count
FROM runtime_detections
WHERE rule_id = ? AND agent_id = ? AND detection_type = ?
  AND ((? IS NULL AND session_id IS NULL) OR session_id = ?)
  AND status != ? AND last_seen_at >= ?
ORDER BY last_seen_at DESC
LIMIT 1`,
		in.RuleID, in.AgentID, in.DetectionType,
		sessionKey, sessionKey,
		RuntimeDetectionStatusResolved, cutoff,
	).Scan(&existingID, &firstSeen, &lastSeen, &severity, &confidence, &status, &eventCount)

	nowStr := in.SeenAt.UTC().Format(time.RFC3339Nano)
	if err == nil {
		// Merge into the existing detection.
		newSeverity := severity
		if SeverityRank(in.Severity) > SeverityRank(severity) {
			newSeverity = strings.ToUpper(in.Severity)
		}
		if in.Confidence > confidence {
			confidence = in.Confidence
		}
		if len(in.Evidence) > 0 {
			eventCount += len(in.Evidence)
		}
		if _, err := s.execDB(context.Background(), "runtime_detection_update", `
UPDATE runtime_detections
SET last_seen_at = ?, severity = ?, confidence = ?,
    status = ?, event_count = ?,
    detail = CASE WHEN ? != '' THEN ? ELSE detail END,
    trace_id = COALESCE(NULLIF(?, ''), trace_id)
WHERE detection_id = ?`,
			nowStr, strings.ToUpper(newSeverity), confidence,
			in.detectionStatusFromEvidence(status), eventCount,
			in.Detail, in.Detail,
			in.TraceID,
			existingID,
		); err != nil {
			return RuntimeDetection{}, err
		}
		s.linkDetectionEvidence(existingID, in.Evidence, in.SeenAt)
		d := in.toDetection(existingID)
		d.Severity = newSeverity
		d.FirstSeenAt = parseTimeOrDefault(firstSeen, in.SeenAt)
		d.Status = in.detectionStatusFromEvidence(status)
		d.EventCount = eventCount
		return d, nil
	}
	if err != sql.ErrNoRows {
		return RuntimeDetection{}, err
	}

	// Fresh detection.
	detectionID := "D" + uuid.NewString()[:8]
	attrsJSON := ""
	if len(in.Attributes) > 0 {
		if b, err := json.Marshal(in.Attributes); err == nil {
			attrsJSON = string(b)
		}
	}
	if _, err := s.execDB(context.Background(), "runtime_detection_insert", `
INSERT INTO runtime_detections (
  detection_id, agent_id, agent_name, session_id, trace_id,
  detection_type, category, severity, confidence, rule_id, status,
  title, detail, remediation, attributes_json,
  first_seen_at, last_seen_at, event_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		detectionID, in.AgentID, nullStr(in.AgentName), nullStr(in.SessionID), nullStr(in.TraceID),
		in.DetectionType, in.Category, strings.ToUpper(in.Severity), in.Confidence, in.RuleID,
		in.detectionStatusFromEvidence(RuntimeDetectionStatusOpen),
		in.Title, nullStr(in.Detail), nullStr(in.Remediation), nullStr(attrsJSON),
		nowStr, nowStr, len(in.Evidence),
	); err != nil {
		return RuntimeDetection{}, err
	}
	s.linkDetectionEvidence(detectionID, in.Evidence, in.SeenAt)
	d := in.toDetection(detectionID)
	return d, nil
}

// detectionStatusFromEvidence derives the mitigated flag: when every
// evidence event was blocked by an enforcement layer, the risk was
// contained and the detection shows as mitigated rather than open.
func (in RuntimeDetectionInput) detectionStatusFromEvidence(fallback string) string {
	if len(in.Evidence) == 0 {
		return fallback
	}
	allBlocked := true
	for _, ev := range in.Evidence {
		if !strings.EqualFold(strings.TrimSpace(ev.Outcome), "blocked") {
			allBlocked = false
			break
		}
	}
	if allBlocked {
		return RuntimeDetectionStatusMitigated
	}
	return RuntimeDetectionStatusOpen
}

// linkDetectionEvidence appends evidence links. Duplicates are ignored
// so re-firing rules never double-link the same event.
func (s *Store) linkDetectionEvidence(detectionID string, evidence []DetectionEvidenceInput, seenAt time.Time) {
	if len(evidence) == 0 {
		return
	}
	linkedAt := seenAt.UTC().Format(time.RFC3339Nano)
	for _, ev := range evidence {
		if ev.EventID <= 0 {
			continue
		}
		if ev.Role == "" {
			ev.Role = DetectionRoleSupporting
		}
		_, _ = s.execDB(context.Background(), "runtime_detection_event_link", `
INSERT OR IGNORE INTO runtime_detection_events (detection_id, event_id, role, sequence, linked_at)
VALUES (?, ?, ?, ?, ?)`,
			detectionID, ev.EventID, ev.Role, ev.Sequence, linkedAt,
		)
	}
}

func (in RuntimeDetectionInput) toDetection(detectionID string) RuntimeDetection {
	return RuntimeDetection{
		DetectionID:   detectionID,
		AgentID:       in.AgentID,
		AgentName:     in.AgentName,
		SessionID:     in.SessionID,
		TraceID:       in.TraceID,
		DetectionType: in.DetectionType,
		Category:      in.Category,
		Severity:      strings.ToUpper(in.Severity),
		Confidence:    in.Confidence,
		RuleID:        in.RuleID,
		Status:        in.detectionStatusFromEvidence(RuntimeDetectionStatusOpen),
		Title:         in.Title,
		Detail:        in.Detail,
		Remediation:   in.Remediation,
		Attributes:    in.Attributes,
		FirstSeenAt:   in.SeenAt,
		LastSeenAt:    in.SeenAt,
		EventCount:    len(in.Evidence),
	}
}

// RuntimeDetectionFilter selects detections for the page and API.
type RuntimeDetectionFilter struct {
	AgentID       string
	SessionID     string
	TraceID       string
	DetectionType string
	Category      string
	Severity      string
	Status        string
	Limit         int
}

// ListRuntimeDetections returns detections newest-first.
func (s *Store) ListRuntimeDetections(f RuntimeDetectionFilter) ([]RuntimeDetection, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	var conds []string
	var args []any
	if f.AgentID != "" {
		conds = append(conds, "agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.TraceID != "" {
		conds = append(conds, "trace_id = ?")
		args = append(args, f.TraceID)
	}
	if f.DetectionType != "" {
		conds = append(conds, "detection_type = ?")
		args = append(args, f.DetectionType)
	}
	if f.Category != "" {
		conds = append(conds, "category = ?")
		args = append(args, strings.ToLower(f.Category))
	}
	if f.Severity != "" {
		conds = append(conds, "severity = ?")
		args = append(args, strings.ToUpper(f.Severity))
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, strings.ToLower(f.Status))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit)
	rows, err := s.queryDB(context.Background(), "runtime_detections_list", `
SELECT detection_id, agent_id, COALESCE(agent_name, ''), COALESCE(session_id, ''),
       COALESCE(trace_id, ''), detection_type, category, severity, confidence,
       rule_id, status, title, COALESCE(detail, ''), COALESCE(remediation, ''),
       COALESCE(attributes_json, ''), first_seen_at, last_seen_at, event_count
FROM runtime_detections
`+where+`
ORDER BY last_seen_at DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuntimeDetection
	for rows.Next() {
		var (
			d          RuntimeDetection
			firstSeen  string
			lastSeen   string
			attrs      string
			confidence float64
			eventCount int64
		)
		if err := rows.Scan(
			&d.DetectionID, &d.AgentID, &d.AgentName, &d.SessionID, &d.TraceID,
			&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID,
			&d.Status, &d.Title, &d.Detail, &d.Remediation, &attrs,
			&firstSeen, &lastSeen, &eventCount,
		); err != nil {
			return nil, err
		}
		d.Confidence = confidence
		d.EventCount = int(eventCount)
		d.FirstSeenAt = parseTimeOrDefault(firstSeen, time.Time{})
		d.LastSeenAt = parseTimeOrDefault(lastSeen, time.Time{})
		if attrs != "" {
			_ = json.Unmarshal([]byte(attrs), &d.Attributes)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetRuntimeDetectionDetail returns one detection plus its evidence
// events (joined with behavior_events) in chain order — the answer to
// "哪些 Event 支撑这个 Detection？".
func (s *Store) GetRuntimeDetectionDetail(detectionID string) (RuntimeDetection, []DetectionEvidence, error) {
	var (
		d          RuntimeDetection
		firstSeen  string
		lastSeen   string
		attrs      string
		confidence float64
		eventCount int64
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT detection_id, agent_id, COALESCE(agent_name, ''), COALESCE(session_id, ''),
       COALESCE(trace_id, ''), detection_type, category, severity, confidence,
       rule_id, status, title, COALESCE(detail, ''), COALESCE(remediation, ''),
       COALESCE(attributes_json, ''), first_seen_at, last_seen_at, event_count
FROM runtime_detections WHERE detection_id = ?`, detectionID,
	).Scan(
		&d.DetectionID, &d.AgentID, &d.AgentName, &d.SessionID, &d.TraceID,
		&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID,
		&d.Status, &d.Title, &d.Detail, &d.Remediation, &attrs,
		&firstSeen, &lastSeen, &eventCount,
	)
	if err == sql.ErrNoRows {
		return RuntimeDetection{}, nil, nil
	}
	if err != nil {
		return RuntimeDetection{}, nil, err
	}
	d.Confidence = confidence
	d.EventCount = int(eventCount)
	d.FirstSeenAt = parseTimeOrDefault(firstSeen, time.Time{})
	d.LastSeenAt = parseTimeOrDefault(lastSeen, time.Time{})
	if attrs != "" {
		_ = json.Unmarshal([]byte(attrs), &d.Attributes)
	}

	evidence, err := s.ListDetectionEvidence(detectionID)
	return d, evidence, err
}

// ListDetectionEvidence returns the evidence chain of one detection,
// each link joined with its behavior event, ordered by sequence.
func (s *Store) ListDetectionEvidence(detectionID string) ([]DetectionEvidence, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "runtime_detection_evidence", `
SELECT l.detection_id, l.event_id, l.role, l.sequence, l.linked_at,
       b.id, b.timestamp, b.event_type, b.source,
       COALESCE(b.event_source, ''), COALESCE(b.event_category, ''),
       COALESCE(b.event_id, ''), COALESCE(b.span_id, ''), COALESCE(b.parent_span_id, ''),
       b.agent_pid, COALESCE(b.ppid, 0),
       COALESCE(b.operation, ''), COALESCE(b.target, ''), COALESCE(b.tool_name, ''), COALESCE(b.mcp_server, ''),
       COALESCE(b.severity, ''), COALESCE(b.confidence, 0), b.outcome, b.detail,
       COALESCE(b.agent_name, ''), COALESCE(b.canonical_agent_id, ''),
       COALESCE(b.session_id, ''), COALESCE(b.trace_id, ''), COALESCE(b.attributes_json, '')
FROM runtime_detection_events l
JOIN behavior_events b ON b.id = l.event_id
WHERE l.detection_id = ?
ORDER BY l.sequence ASC, b.timestamp ASC`, detectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DetectionEvidence
	for rows.Next() {
		var (
			link    DetectionEvidenceLink
			linkedAt string
			e       BehaviorEvent
			ts      string
			ppid    int64
			confidence float64
			attrs   string
		)
		if err := rows.Scan(
			&link.DetectionID, &link.EventID, &link.Role, &link.Sequence, &linkedAt,
			&e.ID, &ts, &e.EventType, &e.Source,
			&e.EventSource, &e.EventCategory, &e.EventID, &e.SpanID, &e.ParentSpanID,
			&e.AgentPID, &ppid, &e.Operation, &e.Target, &e.ToolName, &e.MCPServer,
			&e.Severity, &confidence, &e.Outcome, &e.Detail,
			&e.AgentName, &e.CanonicalAgentID, &e.SessionID, &e.TraceID, &attrs,
		); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.Timestamp = t
		}
		if t, err := time.Parse(time.RFC3339Nano, linkedAt); err == nil {
			link.LinkedAt = t
		}
		e.PPID = uint32(ppid)
		e.Confidence = confidence
		if attrs != "" {
			_ = json.Unmarshal([]byte(attrs), &e.Attributes)
		}
		out = append(out, DetectionEvidence{DetectionEvidenceLink: link, Event: e})
	}
	return out, rows.Err()
}

// DetectionIDsForEvents maps behavior event ids to the detections
// they support. Used by the page snapshot so event classification
// (attack / blocked) comes from structured detection data instead of
// string matching on titles.
func (s *Store) DetectionIDsForEvents(eventIDs []int64) (map[int64][]RuntimeDetection, error) {
	out := map[int64][]RuntimeDetection{}
	if s == nil || s.db == nil || len(eventIDs) == 0 {
		return out, nil
	}
	// Cap the IN list; callers pass bounded page event sets.
	if len(eventIDs) > 500 {
		eventIDs = eventIDs[:500]
	}
	placeholders := make([]string, len(eventIDs))
	args := make([]any, 0, len(eventIDs)+0)
	for i, id := range eventIDs {
		placeholders[i] = "?"
		args = append(args, id)
	}
	rows, err := s.queryDB(context.Background(), "runtime_detection_event_map", `
SELECT l.event_id,
       d.detection_id, d.agent_id, COALESCE(d.agent_name, ''), COALESCE(d.session_id, ''),
       COALESCE(d.trace_id, ''), d.detection_type, d.category, d.severity, d.confidence,
       d.rule_id, d.status, d.title, COALESCE(d.detail, ''), COALESCE(d.remediation, ''),
       '' AS attributes, d.first_seen_at, d.last_seen_at, d.event_count
FROM runtime_detection_events l
JOIN runtime_detections d ON d.detection_id = l.detection_id
WHERE l.event_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			eventID   int64
			d         RuntimeDetection
			firstSeen string
			lastSeen  string
			confidence float64
			eventCount int64
		)
		if err := rows.Scan(
			&eventID,
			&d.DetectionID, &d.AgentID, &d.AgentName, &d.SessionID, &d.TraceID,
			&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID,
			&d.Status, &d.Title, &d.Detail, &d.Remediation,
			&firstSeen, &lastSeen, &eventCount,
		); err != nil {
			return out, err
		}
		d.Confidence = confidence
		d.EventCount = int(eventCount)
		d.FirstSeenAt = parseTimeOrDefault(firstSeen, time.Time{})
		d.LastSeenAt = parseTimeOrDefault(lastSeen, time.Time{})
		out[eventID] = append(out[eventID], d)
	}
	return out, rows.Err()
}

// UpdateRuntimeDetectionStatus transitions a detection (open →
// resolved, or reopen). Future phases can wire this to operator
// actions from the frontend.
func (s *Store) UpdateRuntimeDetectionStatus(detectionID, status string) error {
	if s == nil || s.db == nil {
		return nil
	}
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case RuntimeDetectionStatusOpen, RuntimeDetectionStatusMitigated, RuntimeDetectionStatusResolved:
	default:
		return nil
	}
	_, err := s.execDB(context.Background(), "runtime_detection_status", `
UPDATE runtime_detections SET status = ? WHERE detection_id = ?`, status, detectionID)
	return err
}

func parseTimeOrDefault(value string, fallback time.Time) time.Time {
	if value == "" {
		return fallback
	}
	if t, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return t
	}
	return fallback
}
