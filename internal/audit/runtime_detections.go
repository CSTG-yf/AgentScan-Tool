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
	DetectionRoleTrigger       = "trigger"
	DetectionRoleSupporting    = "supporting"
	DetectionRoleCorroborating = "corroborating"
)

// RuntimeDetection is the structured answer to "这里有什么安全问题？".
// behavior_events answers "发生了什么？" — a detection is the risk
// verdict derived from one or more events by a generic detection rule.
type RuntimeDetection struct {
	DetectionID     string         `json:"detection_id"`
	AgentID         string         `json:"agent_id"`
	AgentName       string         `json:"agent_name,omitempty"`
	SessionID       string         `json:"session_id,omitempty"`
	TraceID         string         `json:"trace_id,omitempty"`
	DetectionType   string         `json:"detection_type"`
	Category        string         `json:"category"`
	Severity        string         `json:"severity"`
	Confidence      float64        `json:"confidence"`
	RuleID          string         `json:"rule_id"`
	RuleVersion     string         `json:"rule_version,omitempty"`
	Source          string         `json:"source,omitempty"`
	EvaluationJobID string         `json:"evaluation_job_id,omitempty"`
	Status          string         `json:"status"`
	Title           string         `json:"title"`
	Detail          string         `json:"detail,omitempty"`
	Remediation     string         `json:"remediation,omitempty"`
	Attributes      map[string]any `json:"attributes,omitempty"`
	FirstSeenAt     time.Time      `json:"first_seen_at"`
	LastSeenAt      time.Time      `json:"last_seen_at"`
	EventCount      int            `json:"event_count"`
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
	AgentID         string
	AgentName       string
	SessionID       string
	TraceID         string
	DetectionType   string
	Category        string
	Severity        string
	Confidence      float64
	RuleID          string
	RuleVersion     string
	Source          string
	EvaluationJobID string
	Title           string
	Detail          string
	Remediation     string
	Attributes      map[string]any
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
	if strings.TrimSpace(in.Source) == "" {
		if value, ok := in.Attributes["source"].(string); ok && strings.TrimSpace(value) != "" {
			in.Source = strings.TrimSpace(value)
		} else {
			in.Source = "runtime_detection"
		}
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
		existingID string
		firstSeen  string
		lastSeen   string
		severity   string
		confidence float64
		status     string
		eventCount int
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT detection_id, first_seen_at, last_seen_at, severity, confidence, status, event_count
FROM runtime_detections
WHERE rule_id = ? AND agent_id = ? AND detection_type = ? AND "delete" = 0
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
    rule_version = CASE WHEN ? != '' THEN ? ELSE rule_version END,
    source = CASE WHEN ? != '' THEN ? ELSE source END,
    evaluation_job_id = CASE WHEN ? != '' THEN ? ELSE evaluation_job_id END,
    detail = CASE WHEN ? != '' THEN ? ELSE detail END,
    trace_id = COALESCE(NULLIF(?, ''), trace_id)
WHERE detection_id = ?`,
			nowStr, strings.ToUpper(newSeverity), confidence,
			in.detectionStatusFromEvidence(status), eventCount,
			in.RuleVersion, in.RuleVersion,
			in.Source, in.Source,
			in.EvaluationJobID, in.EvaluationJobID,
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
  rule_version, source, evaluation_job_id, title, detail, remediation, attributes_json,
  first_seen_at, last_seen_at, event_count
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		detectionID, in.AgentID, nullStr(in.AgentName), nullStr(in.SessionID), nullStr(in.TraceID),
		in.DetectionType, in.Category, strings.ToUpper(in.Severity), in.Confidence, in.RuleID,
		in.detectionStatusFromEvidence(RuntimeDetectionStatusOpen), in.RuleVersion, in.Source, in.EvaluationJobID,
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
		DetectionID:     detectionID,
		AgentID:         in.AgentID,
		AgentName:       in.AgentName,
		SessionID:       in.SessionID,
		TraceID:         in.TraceID,
		DetectionType:   in.DetectionType,
		Category:        in.Category,
		Severity:        strings.ToUpper(in.Severity),
		Confidence:      in.Confidence,
		RuleID:          in.RuleID,
		RuleVersion:     in.RuleVersion,
		Source:          in.Source,
		EvaluationJobID: in.EvaluationJobID,
		Status:          in.detectionStatusFromEvidence(RuntimeDetectionStatusOpen),
		Title:           in.Title,
		Detail:          in.Detail,
		Remediation:     in.Remediation,
		Attributes:      in.Attributes,
		FirstSeenAt:     in.SeenAt,
		LastSeenAt:      in.SeenAt,
		EventCount:      len(in.Evidence),
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
	Source        string
	Keyword       string
	StartTime     time.Time
	EndTime       time.Time
	Offset        int
	Sort          string
	Limit         int
}

func runtimeDetectionWhereClause(f RuntimeDetectionFilter) (string, []any) {
	conds := []string{`"delete" = 0`}
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
	if values := runtimeDetectionFilterValues(f.DetectionType, strings.ToLower); len(values) > 0 {
		conds = append(conds, "LOWER(detection_type) IN ("+runtimeDetectionPlaceholders(len(values))+")")
		for _, value := range values {
			args = append(args, value)
		}
	}
	if values := runtimeDetectionFilterValues(f.Category, strings.ToLower); len(values) > 0 {
		conds = append(conds, "LOWER(category) IN ("+runtimeDetectionPlaceholders(len(values))+")")
		for _, value := range values {
			args = append(args, value)
		}
	}
	if values := runtimeDetectionFilterValues(f.Severity, strings.ToUpper); len(values) > 0 {
		conds = append(conds, "UPPER(severity) IN ("+runtimeDetectionPlaceholders(len(values))+")")
		for _, value := range values {
			args = append(args, value)
		}
	}
	if values := runtimeDetectionFilterValues(f.Status, strings.ToLower); len(values) > 0 {
		conds = append(conds, "LOWER(status) IN ("+runtimeDetectionPlaceholders(len(values))+")")
		for _, value := range values {
			args = append(args, value)
		}
	}
	if values := runtimeDetectionFilterValues(f.Source, strings.ToLower); len(values) > 0 {
		// New rows persist source directly. The JSON fallback keeps filters
		// useful for rows written before the source column was introduced.
		placeholders := runtimeDetectionPlaceholders(len(values))
		correlationFallback := "(COALESCE(source, '') = '' AND (event_count > 1 OR LOWER(detection_type) LIKE '%exfiltration%' OR LOWER(detection_type) LIKE '%exploit%') AND 'correlation_engine' IN (" + placeholders + "))"
		runtimeFallback := "(COALESCE(source, '') = '' AND event_count <= 1 AND 'runtime_detection' IN (" + placeholders + "))"
		conds = append(conds, "(LOWER(COALESCE(source, '')) IN ("+placeholders+") OR "+correlationFallback+" OR "+runtimeFallback+")")
		for _, value := range values {
			args = append(args, value)
		}
		for _, value := range values {
			args = append(args, value)
		}
		for _, value := range values {
			args = append(args, value)
		}
	}
	if keyword := strings.ToLower(strings.TrimSpace(f.Keyword)); keyword != "" {
		like := "%" + keyword + "%"
		conds = append(conds, `(
LOWER(detection_id) LIKE ? OR LOWER(agent_id) LIKE ? OR LOWER(COALESCE(agent_name, '')) LIKE ?
OR LOWER(COALESCE(session_id, '')) LIKE ? OR LOWER(COALESCE(trace_id, '')) LIKE ?
OR LOWER(detection_type) LIKE ? OR LOWER(category) LIKE ? OR LOWER(rule_id) LIKE ?
OR LOWER(COALESCE(rule_version, '')) LIKE ?
OR LOWER(title) LIKE ? OR LOWER(COALESCE(detail, '')) LIKE ? OR LOWER(COALESCE(remediation, '')) LIKE ?
)`)
		for i := 0; i < 12; i++ {
			args = append(args, like)
		}
	}
	if !f.StartTime.IsZero() {
		conds = append(conds, "last_seen_at >= ?")
		args = append(args, f.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !f.EndTime.IsZero() {
		conds = append(conds, "first_seen_at <= ?")
		args = append(args, f.EndTime.UTC().Format(time.RFC3339Nano))
	}
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func runtimeDetectionFilterValues(raw string, normalize func(string) string) []string {
	if strings.TrimSpace(raw) == "" || strings.EqualFold(strings.TrimSpace(raw), "all") {
		return nil
	}
	seen := map[string]bool{}
	var values []string
	for _, part := range strings.Split(raw, ",") {
		value := normalize(strings.TrimSpace(part))
		if value == "" || strings.EqualFold(value, "all") || seen[value] {
			continue
		}
		seen[value] = true
		values = append(values, value)
	}
	return values
}

func runtimeDetectionPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func runtimeDetectionOrderBy(sortValue string) string {
	switch strings.ToLower(strings.TrimSpace(sortValue)) {
	case "oldest", "last_seen_at:asc", "created_at:asc", "first_seen_at:asc":
		return "last_seen_at ASC, detection_id ASC"
	case "severity", "severity:desc", "severity_desc":
		return "CASE UPPER(severity) WHEN 'CRITICAL' THEN 5 WHEN 'HIGH' THEN 4 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 2 ELSE 1 END DESC, last_seen_at DESC"
	case "agent", "agent:asc":
		return "LOWER(COALESCE(agent_name, agent_id)), last_seen_at DESC"
	case "type", "type:asc":
		return "LOWER(detection_type), last_seen_at DESC"
	default:
		return "last_seen_at DESC, detection_id DESC"
	}
}

// CountRuntimeDetections returns the total number of detections that match
// the non-pagination fields in the filter.
func (s *Store) CountRuntimeDetections(f RuntimeDetectionFilter) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	where, args := runtimeDetectionWhereClause(f)
	var total int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM runtime_detections `+where, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// ListRuntimeDetections returns detections newest-first.
func (s *Store) ListRuntimeDetections(f RuntimeDetectionFilter) ([]RuntimeDetection, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	where, args := runtimeDetectionWhereClause(f)
	args = append(args, f.Limit, f.Offset)
	rows, err := s.queryDB(context.Background(), "runtime_detections_list", `
SELECT detection_id, agent_id, COALESCE(agent_name, ''), COALESCE(session_id, ''),
       COALESCE(trace_id, ''), detection_type, category, severity, confidence,
       rule_id, COALESCE(rule_version, ''), COALESCE(source, ''), COALESCE(evaluation_job_id, ''), status, title, COALESCE(detail, ''), COALESCE(remediation, ''),
       COALESCE(attributes_json, ''), first_seen_at, last_seen_at, event_count
FROM runtime_detections
`+where+`
ORDER BY `+runtimeDetectionOrderBy(f.Sort)+`
LIMIT ? OFFSET ?`, args...)
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
			&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID, &d.RuleVersion, &d.Source, &d.EvaluationJobID,
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

// RuntimeSecuritySummary is the aggregate card model for the runtime security
// page. Counts are detection-backed, not raw behavior event counts.
type RuntimeSecuritySummary struct {
	TotalDetections    int    `json:"total_detections"`
	SecurityDetections int    `json:"security_detections"`
	AttackDetections   int    `json:"attack_detections"`
	Blocked            int    `json:"blocked"`
	HighOrAbove        int    `json:"high_or_above"`
	CoveredAgents      int    `json:"covered_agents"`
	LatestAt           string `json:"latest_at,omitempty"`
	WindowStart        string `json:"window_start,omitempty"`
	WindowEnd          string `json:"window_end,omitempty"`
}

// RuntimeSecuritySummary aggregates runtime_detections for the global page or
// one selected agent when AgentID is present in the filter.
func (s *Store) RuntimeSecuritySummary(f RuntimeDetectionFilter) (RuntimeSecuritySummary, error) {
	if s == nil || s.db == nil {
		return RuntimeSecuritySummary{}, nil
	}
	where, args := runtimeDetectionWhereClause(f)
	var summary RuntimeSecuritySummary
	if err := s.db.QueryRowContext(context.Background(), `
SELECT COUNT(*),
       COALESCE(SUM(CASE WHEN LOWER(category) = 'attack' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN LOWER(status) IN ('blocked', 'mitigated') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN UPPER(severity) IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END), 0),
       COUNT(DISTINCT NULLIF(agent_id, '')),
       COALESCE(MIN(first_seen_at), ''),
       COALESCE(MAX(last_seen_at), '')
FROM runtime_detections `+where, args...).Scan(
		&summary.TotalDetections,
		&summary.AttackDetections,
		&summary.Blocked,
		&summary.HighOrAbove,
		&summary.CoveredAgents,
		&summary.WindowStart,
		&summary.WindowEnd,
	); err != nil {
		return RuntimeSecuritySummary{}, err
	}
	summary.SecurityDetections = summary.TotalDetections - summary.AttackDetections
	summary.LatestAt = summary.WindowEnd
	return summary, nil
}

// RuntimeSecurityAgent summarizes detections per canonical agent for the page
// left rail.
type RuntimeSecurityAgent struct {
	AgentID          string `json:"agent_id"`
	AgentName        string `json:"agent_name"`
	AgentType        string `json:"agent_type"`
	DetectionCount   int    `json:"detection_count"`
	AttackCount      int    `json:"attack_count"`
	BlockedCount     int    `json:"blocked_count"`
	HighOrAboveCount int    `json:"high_or_above_count"`
	LatestAt         string `json:"latest_at,omitempty"`
	RuntimeStatus    string `json:"runtime_status"`
}

// ListRuntimeSecurityAgents returns agent rows backed by runtime_detections.
func (s *Store) ListRuntimeSecurityAgents(limit int) ([]RuntimeSecurityAgent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 200
	}
	rows, err := s.queryDB(context.Background(), "runtime_security_agents", `
SELECT d.agent_id,
       COALESCE(NULLIF(MAX(d.agent_name), ''), NULLIF(MAX(a.display_name), ''), d.agent_id),
       COALESCE(NULLIF(MAX(a.kind), ''), 'Agent'),
       COUNT(*),
       COALESCE(SUM(CASE WHEN LOWER(d.category) = 'attack' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN LOWER(d.status) IN ('blocked', 'mitigated') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN UPPER(d.severity) IN ('CRITICAL', 'HIGH') THEN 1 ELSE 0 END), 0),
       COALESCE(MAX(d.last_seen_at), ''),
       COALESCE(NULLIF(MAX(a.runtime_status), ''), 'unknown')
FROM runtime_detections d
LEFT JOIN agents a ON a.id = d.agent_id
WHERE d.agent_id != '' AND d."delete" = 0
GROUP BY d.agent_id
ORDER BY MAX(d.last_seen_at) DESC, LOWER(COALESCE(NULLIF(MAX(d.agent_name), ''), NULLIF(MAX(a.display_name), ''), d.agent_id))
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuntimeSecurityAgent
	for rows.Next() {
		var agent RuntimeSecurityAgent
		if err := rows.Scan(
			&agent.AgentID,
			&agent.AgentName,
			&agent.AgentType,
			&agent.DetectionCount,
			&agent.AttackCount,
			&agent.BlockedCount,
			&agent.HighOrAboveCount,
			&agent.LatestAt,
			&agent.RuntimeStatus,
		); err != nil {
			return nil, err
		}
		out = append(out, agent)
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
       rule_id, COALESCE(rule_version, ''), COALESCE(source, ''), COALESCE(evaluation_job_id, ''), status, title, COALESCE(detail, ''), COALESCE(remediation, ''),
       COALESCE(attributes_json, ''), first_seen_at, last_seen_at, event_count
FROM runtime_detections WHERE detection_id = ? AND "delete" = 0`, detectionID,
	).Scan(
		&d.DetectionID, &d.AgentID, &d.AgentName, &d.SessionID, &d.TraceID,
		&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID, &d.RuleVersion, &d.Source, &d.EvaluationJobID,
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
       b.agent_pid, COALESCE(b.agent_executable, ''), COALESCE(b.actor_pid, 0),
       COALESCE(b.actor_executable, ''), COALESCE(b.path, ''), COALESCE(b.action, ''),
       COALESCE(b.ppid, 0),
       COALESCE(b.operation, ''), COALESCE(b.target, ''), COALESCE(b.tool_name, ''), COALESCE(b.mcp_server, ''),
       COALESCE(b.severity, ''), COALESCE(b.confidence, 0), b.outcome, b.detail,
       COALESCE(b.agent_name, ''), COALESCE(b.canonical_agent_id, ''), COALESCE(b.agent_instance_id, ''),
       COALESCE(b.session_id, ''), COALESCE(b.trace_id, ''), COALESCE(b.attributes_json, '')
FROM runtime_detection_events l
JOIN behavior_events b ON b.id = l.event_id
WHERE l.detection_id = ? AND l."delete" = 0 AND b."delete" = 0
ORDER BY l.sequence ASC, b.timestamp ASC`, detectionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DetectionEvidence
	for rows.Next() {
		var (
			link       DetectionEvidenceLink
			linkedAt   string
			e          BehaviorEvent
			ts         string
			actorPID   int64
			ppid       int64
			confidence float64
			attrs      string
		)
		if err := rows.Scan(
			&link.DetectionID, &link.EventID, &link.Role, &link.Sequence, &linkedAt,
			&e.ID, &ts, &e.EventType, &e.Source,
			&e.EventSource, &e.EventCategory, &e.EventID, &e.SpanID, &e.ParentSpanID,
			&e.AgentPID, &e.AgentExecutable, &actorPID, &e.ActorExecutable, &e.Path, &e.Action,
			&ppid, &e.Operation, &e.Target, &e.ToolName, &e.MCPServer,
			&e.Severity, &confidence, &e.Outcome, &e.Detail,
			&e.AgentName, &e.CanonicalAgentID, &e.AgentInstanceID, &e.SessionID, &e.TraceID, &attrs,
		); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.Timestamp = t
		}
		e.ActorPID = uint32(actorPID)
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
       d.rule_id, COALESCE(d.rule_version, ''), COALESCE(d.source, ''), COALESCE(d.evaluation_job_id, ''), d.status, d.title, COALESCE(d.detail, ''), COALESCE(d.remediation, ''),
       '' AS attributes, d.first_seen_at, d.last_seen_at, d.event_count
FROM runtime_detection_events l
JOIN runtime_detections d ON d.detection_id = l.detection_id
WHERE l."delete" = 0 AND d."delete" = 0 AND l.event_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			eventID    int64
			d          RuntimeDetection
			firstSeen  string
			lastSeen   string
			confidence float64
			eventCount int64
		)
		if err := rows.Scan(
			&eventID,
			&d.DetectionID, &d.AgentID, &d.AgentName, &d.SessionID, &d.TraceID,
			&d.DetectionType, &d.Category, &d.Severity, &confidence, &d.RuleID, &d.RuleVersion, &d.Source, &d.EvaluationJobID,
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
UPDATE runtime_detections SET status = ? WHERE detection_id = ? AND "delete" = 0`, status, detectionID)
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
