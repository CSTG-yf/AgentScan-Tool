package audit

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

const UnlinkedAgentID = "__unlinked__"

type RuntimeEventSummary struct {
	TotalEvents      int `json:"total_events"`
	ActiveAgentCount int `json:"active_agent_count"`
	ToolEventCount   int `json:"tool_event_count"`
	FileEventCount   int `json:"file_event_count"`
}
type EventAgentSummary struct {
	AgentID          string `json:"agent_id"`
	AgentName        string `json:"agent_name"`
	AgentType        string `json:"agent_type"`
	EventCount       int    `json:"event_count"`
	HighOrAboveCount int    `json:"high_or_above_count,omitempty"`
	LatestEventAt    string `json:"latest_event_at"`
}
type RuntimeEventFacets struct {
	EventTypes      []string `json:"event_types"`
	EventCategories []string `json:"event_categories"`
	Sources         []string `json:"sources"`
	Severities      []string `json:"severities"`
	Outcomes        []string `json:"outcomes"`
}

func (s *Store) RuntimeEventSummary(f RuntimeEventFilter) (RuntimeEventSummary, error) {
	where, args := runtimeEventWhereClause(f)
	var out RuntimeEventSummary
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*), COUNT(DISTINCT a.id), COALESCE(SUM(CASE WHEN b.event_category='tool' THEN 1 ELSE 0 END),0), COALESCE(SUM(CASE WHEN b.event_category='file' THEN 1 ELSE 0 END),0) FROM (SELECT * FROM behavior_events `+where+`) b LEFT JOIN agents a ON a.id=b.canonical_agent_id AND a."delete"=0`, args...).Scan(&out.TotalEvents, &out.ActiveAgentCount, &out.ToolEventCount, &out.FileEventCount)
	return out, err
}

func (s *Store) RuntimeEventAgents(f RuntimeEventFilter) ([]EventAgentSummary, error) {
	f.AgentID = ""
	where, args := runtimeEventWhereClause(f)
	query := `WITH filtered AS (
  SELECT * FROM behavior_events ` + where + `
), event_counts AS (
  SELECT canonical_agent_id, MAX(NULLIF(agent_name,'')) AS event_agent_name,
         COUNT(*) AS event_count, MAX(timestamp) AS latest_event_at
  FROM filtered
  WHERE COALESCE(canonical_agent_id,'')<>''
  GROUP BY canonical_agent_id
)
SELECT agent_id, agent_name, agent_type, event_count, high_or_above_count, latest_event_at
FROM (
  SELECT a.id AS agent_id,
         COALESCE(NULLIF(a.display_name,''), ec.event_agent_name, a.id) AS agent_name,
         COALESCE(NULLIF(at.name,''), a.kind, '') AS agent_type,
         COALESCE(ec.event_count,0) AS event_count,
         0 AS high_or_above_count,
         COALESCE(ec.latest_event_at,'') AS latest_event_at
  FROM agents a
  LEFT JOIN agent_types at ON at.id=a.agent_type_id AND COALESCE(at."delete",0)=0
  LEFT JOIN event_counts ec ON ec.canonical_agent_id=a.id
  WHERE COALESCE(a."delete",0)=0
  UNION ALL
  SELECT ? AS agent_id,
         COALESCE(MAX(NULLIF(f.agent_name,'')),'未关联 Agent') AS agent_name,
         '' AS agent_type,
         COUNT(*) AS event_count,
         0 AS high_or_above_count,
         COALESCE(MAX(f.timestamp),'') AS latest_event_at
  FROM filtered f
  LEFT JOIN agents linked ON linked.id=f.canonical_agent_id AND COALESCE(linked."delete",0)=0
  WHERE COALESCE(f.canonical_agent_id,'')='' OR linked.id IS NULL
  HAVING COUNT(*)>0
)
ORDER BY CASE WHEN event_count>0 THEN 0 ELSE 1 END,
         latest_event_at DESC, LOWER(agent_name), LOWER(agent_id)`
	rows, err := s.db.QueryContext(context.Background(), query, append(args, UnlinkedAgentID)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventAgentSummary{}
	for rows.Next() {
		var x EventAgentSummary
		if err := rows.Scan(&x.AgentID, &x.AgentName, &x.AgentType, &x.EventCount, &x.HighOrAboveCount, &x.LatestEventAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

func distinctStrings(db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) RuntimeEventFacetValues(f RuntimeEventFilter) (RuntimeEventFacets, error) {
	where, args := runtimeEventWhereClause(f)
	col := func(expr string) ([]string, error) {
		return distinctStrings(s.db, `SELECT DISTINCT `+expr+` FROM behavior_events `+where+` AND `+expr+`<>'' ORDER BY 1`, args...)
	}
	var out RuntimeEventFacets
	var err error
	if out.EventTypes, err = col("event_type"); err != nil {
		return out, err
	}
	if out.EventCategories, err = col("COALESCE(event_category,'')"); err != nil {
		return out, err
	}
	if out.Sources, err = col("COALESCE(NULLIF(event_source,''),source,'')"); err != nil {
		return out, err
	}
	if out.Severities, err = col("COALESCE(severity,'')"); err != nil {
		return out, err
	}
	out.Outcomes, err = col("outcome")
	return out, err
}

type AuditEventFilter struct {
	AgentID, Action, Severity, Connector, Actor, ToolName, PolicyID, RequestID, SessionID, TraceID, Keyword, Sort string
	Enforced                                                                                                      *bool
	Since, Until                                                                                                  time.Time
	Limit, Offset                                                                                                 int
}

func auditEventWhere(f AuditEventFilter) (string, []any) {
	cond := []string{`ae."delete"=0`}
	args := []any{}
	add := func(sql, v string) {
		if strings.TrimSpace(v) != "" {
			cond = append(cond, sql)
			args = append(args, strings.TrimSpace(v))
		}
	}
	if f.AgentID == UnlinkedAgentID {
		cond = append(cond, "(COALESCE(ae.canonical_agent_id,'')='' OR a.id IS NULL)")
	} else {
		add("ae.canonical_agent_id=?", f.AgentID)
	}
	add("ae.action=?", f.Action)
	add("UPPER(COALESCE(ae.severity,''))=UPPER(?)", f.Severity)
	add("ae.connector=?", f.Connector)
	add("ae.actor=?", f.Actor)
	add("ae.tool_name=?", f.ToolName)
	add("ae.policy_id=?", f.PolicyID)
	add("ae.request_id=?", f.RequestID)
	add("ae.session_id=?", f.SessionID)
	add("ae.trace_id=?", f.TraceID)
	if f.Enforced != nil {
		cond = append(cond, "ae.enforced=?")
		args = append(args, *f.Enforced)
	}
	if !f.Since.IsZero() {
		cond = append(cond, "ae.timestamp>=?")
		args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		cond = append(cond, "ae.timestamp<=?")
		args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if k := strings.ToLower(strings.TrimSpace(f.Keyword)); k != "" {
		like := "%" + k + "%"
		cond = append(cond, `(LOWER(ae.action) LIKE ? OR LOWER(COALESCE(ae.target,'')) LIKE ? OR LOWER(ae.actor) LIKE ? OR LOWER(COALESCE(ae.details,'')) LIKE ? OR LOWER(COALESCE(ae.agent_name,'')) LIKE ? OR LOWER(COALESCE(ae.connector,'')) LIKE ? OR LOWER(COALESCE(ae.tool_name,'')) LIKE ? OR LOWER(COALESCE(ae.request_id,'')) LIKE ? OR LOWER(COALESCE(ae.session_id,'')) LIKE ? OR LOWER(COALESCE(ae.trace_id,'')) LIKE ?)`)
		for i := 0; i < 10; i++ {
			args = append(args, like)
		}
	}
	return "WHERE " + strings.Join(cond, " AND "), args
}

func auditSelect() string {
	return `SELECT ae.id,ae.timestamp,ae.action,ae.target,ae.actor,ae.details,ae.structured_json,ae.severity,ae.run_id,ae.trace_id,ae.request_id,ae.session_id,ae.agent_name,ae.agent_instance_id,ae.policy_id,ae.destination_app,ae.tool_name,ae.tool_id,ae.schema_version,ae.content_hash,ae.generation,ae.binary_version,ae.agent_id,ae.canonical_agent_id,ae.sidecar_instance_id,ae.connector,ae.step_idx,ae.enforced,ae.rule_pack_dir FROM audit_events ae LEFT JOIN agents a ON a.id=ae.canonical_agent_id AND a."delete"=0 `
}
func (s *Store) QueryAuditEvents(f AuditEventFilter) ([]Event, int, error) {
	where, args := auditEventWhere(f)
	var total int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events ae LEFT JOIN agents a ON a.id=ae.canonical_agent_id AND a."delete"=0 `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	order := "DESC"
	if f.Sort == "timestamp_asc" {
		order = "ASC"
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	qargs := append(append([]any{}, args...), limit, f.Offset)
	rows, err := s.queryDB(context.Background(), "audit_events_page", auditSelect()+where+` ORDER BY ae.timestamp `+order+`, ae.id `+order+` LIMIT ? OFFSET ?`, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		x, err := scanAuditEventRow(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, x)
	}
	return out, total, rows.Err()
}
func (s *Store) GetAuditEvent(id string) (Event, bool, error) {
	rows, err := s.queryDB(context.Background(), "audit_event_get", auditSelect()+`WHERE ae.id=? AND ae."delete"=0`, id)
	if err != nil {
		return Event{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Event{}, false, nil
	}
	x, err := scanAuditEventRow(rows)
	return x, true, err
}

type AuditEventSummary struct {
	TotalEvents       int `json:"total_events"`
	RelatedAgentCount int `json:"related_agent_count"`
	HighOrAboveCount  int `json:"high_or_above_count"`
	EnforcedCount     int `json:"enforced_count"`
}

func (s *Store) AuditEventSummary(f AuditEventFilter) (AuditEventSummary, error) {
	where, args := auditEventWhere(f)
	var x AuditEventSummary
	err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*),COUNT(DISTINCT CASE WHEN COALESCE(ae.canonical_agent_id,'')<>'' AND a.id IS NOT NULL THEN ae.canonical_agent_id END),COALESCE(SUM(CASE WHEN UPPER(COALESCE(ae.severity,'')) IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN ae.enforced=1 THEN 1 ELSE 0 END),0) FROM audit_events ae LEFT JOIN agents a ON a.id=ae.canonical_agent_id AND a."delete"=0 `+where, args...).Scan(&x.TotalEvents, &x.RelatedAgentCount, &x.HighOrAboveCount, &x.EnforcedCount)
	return x, err
}
func (s *Store) AuditEventAgents(f AuditEventFilter) ([]EventAgentSummary, error) {
	f.AgentID = ""
	where, args := auditEventWhere(f)
	query := `WITH filtered AS (
  SELECT ae.*
  FROM audit_events ae
  LEFT JOIN agents a ON a.id=ae.canonical_agent_id AND COALESCE(a."delete",0)=0
  ` + where + `
), event_counts AS (
  SELECT canonical_agent_id, MAX(NULLIF(agent_name,'')) AS event_agent_name,
         COUNT(*) AS event_count,
         SUM(CASE WHEN UPPER(COALESCE(severity,'')) IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS high_or_above_count,
         MAX(timestamp) AS latest_event_at
  FROM filtered
  WHERE COALESCE(canonical_agent_id,'')<>''
  GROUP BY canonical_agent_id
)
SELECT agent_id, agent_name, agent_type, event_count, high_or_above_count, latest_event_at
FROM (
  SELECT a.id AS agent_id,
         COALESCE(NULLIF(a.display_name,''), ec.event_agent_name, a.id) AS agent_name,
         COALESCE(NULLIF(at.name,''), a.kind, '') AS agent_type,
         COALESCE(ec.event_count,0) AS event_count,
         COALESCE(ec.high_or_above_count,0) AS high_or_above_count,
         COALESCE(ec.latest_event_at,'') AS latest_event_at
  FROM agents a
  LEFT JOIN agent_types at ON at.id=a.agent_type_id AND COALESCE(at."delete",0)=0
  LEFT JOIN event_counts ec ON ec.canonical_agent_id=a.id
  WHERE COALESCE(a."delete",0)=0
  UNION ALL
  SELECT ? AS agent_id,
         COALESCE(MAX(NULLIF(f.agent_name,'')),'未关联 Agent') AS agent_name,
         '' AS agent_type,
         COUNT(*) AS event_count,
         COALESCE(SUM(CASE WHEN UPPER(COALESCE(f.severity,'')) IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END),0) AS high_or_above_count,
         COALESCE(MAX(f.timestamp),'') AS latest_event_at
  FROM filtered f
  LEFT JOIN agents linked ON linked.id=f.canonical_agent_id AND COALESCE(linked."delete",0)=0
  WHERE COALESCE(f.canonical_agent_id,'')='' OR linked.id IS NULL
  HAVING COUNT(*)>0
)
ORDER BY CASE WHEN event_count>0 THEN 0 ELSE 1 END,
         latest_event_at DESC, LOWER(agent_name), LOWER(agent_id)`
	rows, err := s.db.QueryContext(context.Background(), query, append(args, UnlinkedAgentID)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []EventAgentSummary{}
	for rows.Next() {
		var x EventAgentSummary
		if err := rows.Scan(&x.AgentID, &x.AgentName, &x.AgentType, &x.EventCount, &x.HighOrAboveCount, &x.LatestEventAt); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

type AuditEventFacets struct {
	Actions    []string `json:"actions"`
	Severities []string `json:"severities"`
	Connectors []string `json:"connectors"`
	Actors     []string `json:"actors"`
	Tools      []string `json:"tools"`
}

func (s *Store) AuditEventFacetValues(f AuditEventFilter) (AuditEventFacets, error) {
	where, args := auditEventWhere(f)
	col := func(expr string) ([]string, error) {
		return distinctStrings(s.db, `SELECT DISTINCT `+expr+` FROM audit_events ae LEFT JOIN agents a ON a.id=ae.canonical_agent_id AND a."delete"=0 `+where+` AND `+expr+`<>'' ORDER BY 1`, args...)
	}
	var x AuditEventFacets
	var err error
	if x.Actions, err = col("ae.action"); err != nil {
		return x, err
	}
	if x.Severities, err = col("COALESCE(ae.severity,'')"); err != nil {
		return x, err
	}
	if x.Connectors, err = col("COALESCE(ae.connector,'')"); err != nil {
		return x, err
	}
	if x.Actors, err = col("ae.actor"); err != nil {
		return x, err
	}
	x.Tools, err = col("COALESCE(ae.tool_name,'')")
	return x, err
}
