// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// Compile-time check: Store implements scanner.ScanPersistence.
var _ scanner.ScanPersistence = (*Store)(nil)

// InsertScanSummary persists a v7 scan_results row (scan_id == id).
func (s *Store) InsertScanSummary(p scanner.ScanSummaryParams) error {
	runID := p.RunID
	if runID == "" {
		runID = currentRunID()
	}
	ts := p.Timestamp.UTC().Format(time.RFC3339Nano)
	observed := p.Timestamp
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	agent, err := s.EnsureAgent(AgentIdentityInput{
		AgentID:          p.AgentID,
		AgentName:        p.AgentName,
		Target:           p.Target,
		Scanner:          p.Scanner,
		Source:           "scan_results",
		Status:           "observed",
		ObservedAt:       observed,
		LastStaticScanAt: observed,
	})
	if err != nil {
		return err
	}
	agentName := firstNonEmpty(p.AgentName, agent.DisplayName)
	if agent.DisplayName != "" {
		agentName = agent.DisplayName
	}
	canonicalAgentID := agent.ID
	staticResourceID := ""
	if p.StaticResourceID != "" {
		// Rule-driven resource scan: the watcher already resolved the
		// static_resources row during enumeration; trust it verbatim
		// rather than re-deriving via scanner/target classification.
		staticResourceID = p.StaticResourceID
	} else if IsStaticResourceScan(p.Scanner, p.Target) && canonicalAgentID != "" {
		staticResourceID, err = s.EnsureStaticResource(StaticResourceInput{
			CanonicalAgentID: canonicalAgentID,
			ResourceType:     StaticResourceType("", p.Scanner, p.Target),
			Target:           p.Target,
			Scanner:          p.Scanner,
			ScanID:           p.ScanID,
			ObservedAt:       observed,
			MaxSeverity:      p.MaxSeverity,
			FindingCount:     p.FindingCount,
			ContentHash:      p.ContentHash,
			Source:           "scan_results",
		})
		if err != nil {
			return err
		}
	}

	_, err = s.execDB(context.Background(), "scan_summary_insert", `
INSERT INTO scan_results (
  id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json, run_id,
  verdict, exit_code, error,
  schema_version, content_hash, generation, binary_version,
  agent_id, agent_name, agent_instance_id, sidecar_instance_id, session_id, request_id, trace_id,
  evaluation_id, canonical_agent_id, static_resource_id, scan_profile_id, resource_rule_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		p.ScanID,
		p.Scanner,
		p.Target,
		ts,
		p.DurationMs,
		p.FindingCount,
		p.MaxSeverity,
		p.RawJSON,
		nullStr(runID),
		nullStr(p.Verdict),
		p.ExitCode,
		nullStr(p.ScanError),
		nullInt(p.SchemaVersion),
		nullStr(p.ContentHash),
		nullUint64(p.Generation),
		nullStr(p.BinaryVersion),
		nullStr(p.AgentID),
		nullStr(agentName),
		nullStr(p.AgentInstanceID),
		nullStr(p.SidecarInstanceID),
		nullStr(p.SessionID),
		nullStr(p.RequestID),
		nullStr(p.TraceID),
		nullStr(p.EvaluationID),
		nullStr(canonicalAgentID),
		nullStr(staticResourceID),
		nullInt64Value(p.ScanProfileID),
		nullInt64Value(p.ResourceRuleID),
	)
	if err != nil {
		return fmt.Errorf("audit: insert scan summary: %w", err)
	}
	return nil
}

// InsertScanFindings writes one row per finding into scan_findings.
func (s *Store) InsertScanFindings(scanID, target string, findings []scanner.Finding, meta scanner.ScanFindingMeta) error {
	if len(findings) == 0 {
		return nil
	}
	ts := meta.Timestamp.UTC().Format(time.RFC3339Nano)
	if meta.Timestamp.IsZero() {
		ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	observed := meta.Timestamp
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	scannerName := ""
	if len(findings) > 0 {
		scannerName = findings[0].Scanner
	}
	agent, err := s.EnsureAgent(AgentIdentityInput{
		AgentID:          meta.AgentID,
		AgentName:        meta.AgentName,
		Target:           target,
		Scanner:          scannerName,
		Source:           "scan_findings",
		Status:           "observed",
		ObservedAt:       observed,
		LastStaticScanAt: observed,
	})
	if err != nil {
		return err
	}
	agentName := firstNonEmpty(meta.AgentName, agent.DisplayName)
	if agent.DisplayName != "" {
		agentName = agent.DisplayName
	}
	canonicalAgentID := agent.ID
	staticResourceID := strings.TrimSpace(meta.StaticResourceID)
	if staticResourceID == "" && len(findings) > 0 && IsStaticResourceScan(findings[0].Scanner, target) && canonicalAgentID != "" {
		staticResourceType := StaticResourceType("", findings[0].Scanner, target)
		staticResourceID, err = s.EnsureStaticResource(StaticResourceInput{
			CanonicalAgentID: canonicalAgentID,
			ResourceType:     staticResourceType,
			Target:           target,
			Scanner:          findings[0].Scanner,
			ScanID:           scanID,
			ObservedAt:       observed,
			MaxSeverity:      string(findings[0].Severity),
			FindingCount:     len(findings),
			Source:           "scan_findings",
		})
		if err != nil {
			return err
		}
	}

	for i := range findings {
		f := &findings[i]
		tagsJSON, _ := json.Marshal(f.Tags)
		safeDescription := redaction.ForSinkString(f.Description)
		safeLocation := redaction.ForSinkString(f.Location)
		safeRemediation := redaction.ForSinkString(f.Remediation)

		var line interface{}
		if f.LineNumber != nil {
			line = *f.LineNumber
		}

		var dataAxis interface{}
		if len(f.DataAxis) > 0 {
			b, _ := json.Marshal(f.DataAxis)
			dataAxis = string(b)
		}

		var turnID interface{}
		if f.TurnID != nil {
			turnID = *f.TurnID
		}

		var decisionPath interface{}
		if len(f.DecisionPath) > 0 {
			decisionPath = string(f.DecisionPath)
		}

		var confidence interface{}
		if f.Confidence > 0 {
			confidence = f.Confidence
		}

		id := uuid.New().String()
		_, err := s.execDB(context.Background(), "scan_finding_insert", `
INSERT INTO scan_findings (
  id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number,
  remediation, tags, timestamp,
  run_id, request_id, session_id, agent_id, agent_name, agent_instance_id, sidecar_instance_id, trace_id,
  schema_version, content_hash, generation, binary_version,
  data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, decision_path,
  confidence, evaluation_id, canonical_agent_id, static_resource_id
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id,
			scanID,
			f.Scanner,
			target,
			nullStr(f.RuleID),
			nullStr(f.Category),
			string(f.Severity),
			f.Title,
			safeDescription,
			safeLocation,
			line,
			safeRemediation,
			string(tagsJSON),
			ts,
			nullStr(meta.RunID),
			nullStr(meta.RequestID),
			nullStr(meta.SessionID),
			nullStr(meta.AgentID),
			nullStr(agentName),
			nullStr(meta.AgentInstanceID),
			nullStr(meta.SidecarInstanceID),
			nullStr(meta.TraceID),
			nullInt(meta.SchemaVersion),
			nullStr(meta.ContentHash),
			nullUint64(meta.Generation),
			nullStr(meta.BinaryVersion),
			dataAxis,
			nullStr(f.ToolCapabilityClass),
			nullStr(f.ContentFingerprint),
			nullStr(f.ExternalEndpoint),
			turnID,
			decisionPath,
			confidence,
			nullStr(meta.EvaluationID),
			nullStr(canonicalAgentID),
			nullStr(staticResourceID),
		)
		if err != nil {
			return fmt.Errorf("audit: insert scan finding: %w", err)
		}
	}
	return nil
}

// ScanFindingRow is a scan_findings table projection for tests and APIs.
type ScanFindingRow struct {
	ID          string
	ScanID      string
	Scanner     string
	Target      string
	RuleID      sql.NullString
	Category    sql.NullString
	Severity    string
	Title       sql.NullString
	Description sql.NullString
	Location    sql.NullString
	LineNumber  sql.NullInt64
	Remediation sql.NullString
	Tags        sql.NullString
	// Confidence is the per-finding model/heuristic score (0.0-1.0).
	// Populated for runtime detections (hooks, inspect, proxy
	// guardrail, mid-stream); zero for classic scanner CLIs that
	// don't emit a confidence channel.
	Confidence float64
	// EvaluationID is the join key back to the upstream runtime
	// evaluation (hook handler, /api/v1/inspect/*, proxy guardrail,
	// rescan). Empty for classic scanner-CLI invocations.
	EvaluationID string
}

// StaticScanResultRow is the latest scan_results projection used by API
// inventory views. It intentionally keeps only read-model fields; writers stay
// on InsertScanSummary / InsertScanFindings.
type StaticScanResultRow struct {
	ID               string
	Scanner          string
	Target           string
	Timestamp        string
	FindingCount     int
	MaxSeverity      string
	RawJSON          string
	TargetType       string
	ContentHash      string
	CapturedAt       string
	AgentID          string
	AgentName        string
	AgentInstanceID  string
	SessionID        string
	TraceID          string
	CanonicalAgentID string
	StaticResourceID string
	AgentDisplayName string
	AgentKind        string
	AgentRuntime     string
	AgentVendor      string
}

// RuntimeScanFindingRow is a recent scan_findings projection for runtime event
// views. Static inventory scanners are filtered by the caller-facing query.
type RuntimeScanFindingRow struct {
	ID               string
	ScanID           string
	Scanner          string
	Target           string
	RuleID           string
	Category         string
	Severity         string
	Title            string
	Description      string
	Location         string
	Remediation      string
	Timestamp        string
	SessionID        string
	AgentID          string
	AgentName        string
	AgentInstanceID  string
	TraceID          string
	EvaluationID     string
	CanonicalAgentID string
	StaticResourceID string
}

// ListLatestStaticScans returns one latest static-resource scan per target.
func (s *Store) ListLatestStaticScans(limit int) ([]StaticScanResultRow, error) {
	if limit <= 0 {
		limit = 600
	}
	rows, err := s.db.Query(`
SELECT sr.id,
       sr.scanner,
       sr.target,
       sr.timestamp,
       COALESCE(sr.finding_count, 0),
       COALESCE(sr.max_severity, 'INFO'),
       COALESCE(sr.raw_json, ''),
       COALESCE(ts.target_type, ''),
       COALESCE(ts.content_hash, ''),
       COALESCE(ts.captured_at, ''),
       COALESCE(sr.agent_id, ''),
       COALESCE(sr.agent_name, ''),
       COALESCE(sr.agent_instance_id, ''),
       COALESCE(sr.session_id, ''),
       COALESCE(sr.trace_id, ''),
       COALESCE(sr.canonical_agent_id, res.canonical_agent_id, ''),
       COALESCE(sr.static_resource_id, res.id, ''),
       COALESCE(ag.display_name, ''),
       COALESCE(ag.kind, ''),
       COALESCE(ag.runtime, ''),
       COALESCE(ag.vendor, '')
FROM scan_results sr
LEFT JOIN target_snapshots ts ON ts.scan_id = sr.id
LEFT JOIN static_resources res ON res.id = sr.static_resource_id
LEFT JOIN agents ag ON ag.id = COALESCE(sr.canonical_agent_id, res.canonical_agent_id)
JOIN (
    SELECT COALESCE(canonical_agent_id, '') AS agent_key, target, MAX(timestamp) AS latest_timestamp
    FROM scan_results
    WHERE lower(scanner) LIKE '%static-resource%'
       OR lower(scanner) LIKE '%skill%'
       OR lower(scanner) LIKE '%plugin%'
       OR lower(scanner) LIKE '%mcp%'
    GROUP BY COALESCE(canonical_agent_id, ''), target
) latest ON latest.agent_key = COALESCE(sr.canonical_agent_id, '') AND latest.target = sr.target AND latest.latest_timestamp = sr.timestamp
WHERE lower(sr.scanner) LIKE '%static-resource%'
   OR lower(sr.scanner) LIKE '%skill%'
   OR lower(sr.scanner) LIKE '%plugin%'
   OR lower(sr.scanner) LIKE '%mcp%'
ORDER BY sr.timestamp DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list latest static scans: %w", err)
	}
	defer rows.Close()

	var out []StaticScanResultRow
	for rows.Next() {
		var r StaticScanResultRow
		if err := rows.Scan(
			&r.ID, &r.Scanner, &r.Target, &r.Timestamp, &r.FindingCount,
			&r.MaxSeverity, &r.RawJSON, &r.TargetType, &r.ContentHash, &r.CapturedAt,
			&r.AgentID, &r.AgentName, &r.AgentInstanceID, &r.SessionID, &r.TraceID,
			&r.CanonicalAgentID, &r.StaticResourceID, &r.AgentDisplayName, &r.AgentKind,
			&r.AgentRuntime, &r.AgentVendor,
		); err != nil {
			return nil, fmt.Errorf("audit: scan latest static row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRecentRuntimeFindings returns recent non-static findings for event views.
func (s *Store) ListRecentRuntimeFindings(limit int) ([]RuntimeScanFindingRow, error) {
	if limit <= 0 {
		limit = 300
	}
	rows, err := s.db.Query(`
SELECT id,
       scan_id,
       scanner,
       target,
       COALESCE(rule_id, ''),
       COALESCE(category, ''),
       COALESCE(severity, 'INFO'),
       COALESCE(title, ''),
       COALESCE(description, ''),
       COALESCE(location, ''),
       COALESCE(remediation, ''),
       timestamp,
       COALESCE(session_id, ''),
       COALESCE(agent_id, ''),
       COALESCE(agent_name, ''),
       COALESCE(agent_instance_id, ''),
       COALESCE(trace_id, ''),
       COALESCE(evaluation_id, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(static_resource_id, '')
FROM scan_findings
WHERE lower(scanner) NOT LIKE '%skill-scanner%'
  AND lower(scanner) NOT LIKE '%plugin-scanner%'
  AND lower(scanner) NOT LIKE '%mcp-scanner%'
  AND lower(scanner) NOT LIKE '%static-resource%'
ORDER BY timestamp DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list recent runtime findings: %w", err)
	}
	defer rows.Close()

	var out []RuntimeScanFindingRow
	for rows.Next() {
		var r RuntimeScanFindingRow
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.Scanner, &r.Target, &r.RuleID, &r.Category,
			&r.Severity, &r.Title, &r.Description, &r.Location, &r.Remediation,
			&r.Timestamp, &r.SessionID, &r.AgentID, &r.AgentName, &r.AgentInstanceID,
			&r.TraceID, &r.EvaluationID, &r.CanonicalAgentID, &r.StaticResourceID,
		); err != nil {
			return nil, fmt.Errorf("audit: scan runtime finding row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListScanFindings returns persisted findings for a scan_id.
func (s *Store) ListScanFindings(scanID string) ([]ScanFindingRow, error) {
	rows, err := s.db.Query(`
SELECT id, scan_id, scanner, target, rule_id, category, severity, title, description, location, line_number,
       remediation, tags, confidence, evaluation_id
FROM scan_findings WHERE scan_id = ? ORDER BY severity`, scanID)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan findings: %w", err)
	}
	defer rows.Close()

	var out []ScanFindingRow
	for rows.Next() {
		var r ScanFindingRow
		var confidence sql.NullFloat64
		var evaluationID sql.NullString
		if err := rows.Scan(
			&r.ID, &r.ScanID, &r.Scanner, &r.Target, &r.RuleID, &r.Category,
			&r.Severity, &r.Title, &r.Description, &r.Location, &r.LineNumber, &r.Remediation, &r.Tags,
			&confidence, &evaluationID,
		); err != nil {
			return nil, fmt.Errorf("audit: scan finding row: %w", err)
		}
		if confidence.Valid {
			r.Confidence = confidence.Float64
		}
		if evaluationID.Valid {
			r.EvaluationID = evaluationID.String
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CorrelationFindingRow is the projection the sliding-window correlator
// reads — severity + rule_id + category + the enrichment columns that
// drive pattern matching.
type CorrelationFindingRow struct {
	ID                  string
	RuleID              sql.NullString
	Category            sql.NullString
	Severity            string
	DataAxis            sql.NullString
	ToolCapabilityClass sql.NullString
	ContentFingerprint  sql.NullString
	ExternalEndpoint    sql.NullString
	TurnID              sql.NullInt64
	Timestamp           string
}

// ListRecentFindingsInSession returns up to `limit` most-recent findings
// for a given (session_id, agent_instance_id) pair, newest first. The
// correlator calls this on every new finding insert to evaluate its
// pattern library against a sliding event window.
func (s *Store) ListRecentFindingsInSession(sessionID, agentInstanceID string, limit int) ([]CorrelationFindingRow, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.Query(`
SELECT id, rule_id, category, severity,
       data_axis, tool_capability_class, content_fingerprint, external_endpoint, turn_id, timestamp
FROM scan_findings
WHERE session_id = ? AND agent_instance_id = ?
ORDER BY timestamp DESC
LIMIT ?`, sessionID, agentInstanceID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list recent findings in session: %w", err)
	}
	defer rows.Close()

	var out []CorrelationFindingRow
	for rows.Next() {
		var r CorrelationFindingRow
		if err := rows.Scan(
			&r.ID, &r.RuleID, &r.Category, &r.Severity,
			&r.DataAxis, &r.ToolCapabilityClass, &r.ContentFingerprint,
			&r.ExternalEndpoint, &r.TurnID, &r.Timestamp,
		); err != nil {
			return nil, fmt.Errorf("audit: correlation finding row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
