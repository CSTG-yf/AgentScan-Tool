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

// Decision vocabulary. Phase 3 separates "应该怎么处理" (decision) from
// "实际执行了什么" (response action). ALLOW/AUDIT are passive; ALERT
// notifies the operator; CONFIRM defers to the user; BLOCK enforces at
// the least-impactful enforcement point.
const (
	RuntimeDecisionAllow   = "ALLOW"
	RuntimeDecisionAudit   = "AUDIT"
	RuntimeDecisionAlert   = "ALERT"
	RuntimeDecisionConfirm = "CONFIRM"
	RuntimeDecisionBlock   = "BLOCK"
)

// Enforcement points, ordered from least to most impactful. The policy
// engine always picks the SMALLEST point that contains the risk — a
// proxy-level network block is preferred over killing an agent.
const (
	EnforcementPointGuardrail = "guardrail"  // prompt layer
	EnforcementPointAgentHook = "agent_hook" // PreToolUse tool layer
	EnforcementPointMCP       = "mcp"        // MCP server layer
	EnforcementPointProxy     = "proxy"      // network egress layer
	EnforcementPointFile      = "file"       // filesystem layer
	EnforcementPointProcess   = "process"    // OS process layer (last resort)
)

// Runtime Security Mode: observe records would-block decisions without
// enforcing (false-positive tuning); action executes responses.
const (
	RuntimeSecurityModeObserve = "observe"
	RuntimeSecurityModeAction  = "action"
)

// Response action status values.
const (
	ResponseStatusExecuted   = "executed"    // enforcement really ran
	ResponseStatusWouldBlock = "would_block" // observe mode: decision says block, nothing enforced
	ResponseStatusDispatched = "dispatched"  // handed to an existing enforcement module
	ResponseStatusPlanned    = "planned"     // operator preview; no side effect
	ResponseStatusExecuting  = "executing"   // executor has started and awaits confirmation
	ResponseStatusFailed     = "failed"
	ResponseStatusExpired    = "expired"
	ResponseStatusRolledBack = "rolled_back"
)

// RuntimeDecision is the unified verdict derived from one runtime
// detection by the policy engine. It answers "应该怎么处理？" and names
// the enforcement point where the response should land.
type RuntimeDecision struct {
	DecisionID       string    `json:"decision_id"`
	DetectionID      string    `json:"detection_id"`
	AgentID          string    `json:"agent_id"`
	AgentName        string    `json:"agent_name,omitempty"`
	SessionID        string    `json:"session_id,omitempty"`
	TraceID          string    `json:"trace_id,omitempty"`
	Decision         string    `json:"decision"`
	RiskScore        float64   `json:"risk_score"`
	Confidence       float64   `json:"confidence"`
	PolicyID         string    `json:"policy_id"`
	Reason           string    `json:"reason,omitempty"`
	EnforcementPoint string    `json:"enforcement_point,omitempty"`
	Mode             string    `json:"mode"`
	WouldBlock       bool      `json:"would_block"`
	IdempotencyKey   string    `json:"idempotency_key,omitempty"`
	Source           string    `json:"source,omitempty"`
	PolicyVersion    string    `json:"policy_version,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// RuntimeDecisionInput is the policy engine's write shape.
type RuntimeDecisionInput struct {
	DetectionID      string
	AgentID          string
	AgentName        string
	SessionID        string
	TraceID          string
	Decision         string
	RiskScore        float64
	Confidence       float64
	PolicyID         string
	Reason           string
	EnforcementPoint string
	Mode             string
	WouldBlock       bool
	IdempotencyKey   string
	Source           string
	PolicyVersion    string
	CreatedAt        time.Time
}

// decisionDedupWindow: re-firing the same rule reuses one detection
// row, and each re-fire must not spam a decision per event. A fresh
// decision is recorded only when the verdict changes (e.g. AUDIT →
// BLOCK after severity escalation) or the previous decision ages out.
const decisionDedupWindow = 15 * time.Minute

// RecordRuntimeDecision persists one decision with dedup semantics:
// identity is (detection_id) among decisions created within
// decisionDedupWindow with the SAME verdict — those are silently
// dropped; a changed verdict (escalation) always records a new row.
func (s *Store) RecordRuntimeDecision(in RuntimeDecisionInput) (RuntimeDecision, bool, error) {
	if s == nil || s.db == nil {
		return RuntimeDecision{}, false, nil
	}
	in.Decision = strings.ToUpper(strings.TrimSpace(in.Decision))
	if in.Decision == "" || strings.TrimSpace(in.DetectionID) == "" {
		return RuntimeDecision{}, false, nil
	}
	if in.Mode == "" {
		in.Mode = RuntimeSecurityModeObserve
	}
	if strings.TrimSpace(in.Source) == "" {
		in.Source = "automatic"
	}
	if strings.TrimSpace(in.PolicyVersion) == "" {
		in.PolicyVersion = in.PolicyID
	}
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	cutoff := in.CreatedAt.Add(-decisionDedupWindow).UTC().Format(time.RFC3339Nano)

	var existingID string
	if in.IdempotencyKey != "" {
		err := s.db.QueryRowContext(context.Background(), `
SELECT decision_id FROM runtime_decisions
WHERE idempotency_key = ? AND "delete" = 0 LIMIT 1`, in.IdempotencyKey).Scan(&existingID)
		if err == nil {
			return RuntimeDecision{DecisionID: existingID, Decision: in.Decision, IdempotencyKey: in.IdempotencyKey}, false, nil
		}
		if err != sql.ErrNoRows {
			return RuntimeDecision{}, false, err
		}
	}
	err := s.db.QueryRowContext(context.Background(), `
SELECT decision_id FROM runtime_decisions
WHERE detection_id = ? AND decision = ? AND created_at >= ? AND "delete" = 0
ORDER BY created_at DESC LIMIT 1`,
		in.DetectionID, in.Decision, cutoff,
	).Scan(&existingID)
	if err == nil {
		// Same verdict inside the dedup window: nothing new to audit.
		return RuntimeDecision{DecisionID: existingID, Decision: in.Decision}, false, nil
	}
	if err != sql.ErrNoRows {
		return RuntimeDecision{}, false, err
	}

	decisionID := "V" + uuid.NewString()[:8]
	nowStr := in.CreatedAt.UTC().Format(time.RFC3339Nano)
	wouldBlock := 0
	if in.WouldBlock || in.Decision == RuntimeDecisionBlock {
		wouldBlock = 1
	}
	if _, err := s.execDB(context.Background(), "runtime_decision_insert", `
INSERT INTO runtime_decisions (
  decision_id, detection_id, agent_id, session_id, trace_id,
  decision, risk_score, confidence, policy_id, reason,
  enforcement_point, mode, would_block, agent_name, idempotency_key, source, policy_version, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		decisionID, in.DetectionID, in.AgentID, nullStr(in.SessionID), nullStr(in.TraceID),
		in.Decision, in.RiskScore, in.Confidence, in.PolicyID, nullStr(in.Reason),
		in.EnforcementPoint, in.Mode, wouldBlock, nullStr(in.AgentName), in.IdempotencyKey, in.Source, in.PolicyVersion, nowStr,
	); err != nil {
		return RuntimeDecision{}, false, err
	}
	return RuntimeDecision{
		DecisionID: decisionID, DetectionID: in.DetectionID,
		AgentID: in.AgentID, AgentName: in.AgentName,
		SessionID: in.SessionID, TraceID: in.TraceID,
		Decision: in.Decision, RiskScore: in.RiskScore, Confidence: in.Confidence,
		PolicyID: in.PolicyID, Reason: in.Reason,
		EnforcementPoint: in.EnforcementPoint, Mode: in.Mode,
		IdempotencyKey: in.IdempotencyKey, Source: in.Source, PolicyVersion: in.PolicyVersion,
		WouldBlock: wouldBlock != 0, CreatedAt: in.CreatedAt,
	}, true, nil
}

// RuntimeDecisionFilter selects decisions for the page and API.
type RuntimeDecisionFilter struct {
	AgentID     string
	SessionID   string
	TraceID     string
	DetectionID string
	Decision    string
	Mode        string
	Limit       int
}

// ListRuntimeDecisions returns decisions newest-first, each joined
// with its detection so the API can render verdict + risk in one row.
func (s *Store) ListRuntimeDecisions(f RuntimeDecisionFilter) ([]RuntimeDecision, []RuntimeDetection, error) {
	if s == nil || s.db == nil {
		return nil, nil, nil
	}
	if f.Limit <= 0 {
		f.Limit = 200
	}
	var conds []string
	var args []any
	conds = append(conds, `v."delete" = 0`, `(d.detection_id IS NULL OR d."delete" = 0)`)
	if f.AgentID != "" {
		conds = append(conds, "v.agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.SessionID != "" {
		conds = append(conds, "v.session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.TraceID != "" {
		conds = append(conds, "v.trace_id = ?")
		args = append(args, f.TraceID)
	}
	if f.DetectionID != "" {
		conds = append(conds, "v.detection_id = ?")
		args = append(args, f.DetectionID)
	}
	if f.Decision != "" {
		conds = append(conds, "v.decision = ?")
		args = append(args, strings.ToUpper(f.Decision))
	}
	if f.Mode != "" {
		conds = append(conds, "v.mode = ?")
		args = append(args, strings.ToLower(f.Mode))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, f.Limit)
	rows, err := s.queryDB(context.Background(), "runtime_decisions_list", `
SELECT v.decision_id, v.detection_id, v.agent_id, COALESCE(v.agent_name, ''),
       COALESCE(v.session_id, ''), COALESCE(v.trace_id, ''), v.decision,
       v.risk_score, v.confidence, COALESCE(v.policy_id, ''), COALESCE(v.reason, ''),
       COALESCE(v.enforcement_point, ''), v.mode, v.would_block,
       COALESCE(v.idempotency_key, ''), COALESCE(v.source, ''), COALESCE(v.policy_version, ''), v.created_at,
       d.detection_type, COALESCE(d.category, ''), COALESCE(d.severity, ''),
       COALESCE(d.rule_id, ''), COALESCE(d.rule_version, ''),
       COALESCE(d.title, ''), COALESCE(d.status, ''), COALESCE(d.confidence, 0),
       COALESCE(d.event_count, 0), COALESCE(d.first_seen_at, ''), COALESCE(d.last_seen_at, '')
FROM runtime_decisions v
LEFT JOIN runtime_detections d ON d.detection_id = v.detection_id
`+where+`
ORDER BY v.created_at DESC
LIMIT ?`, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var out []RuntimeDecision
	var detections []RuntimeDetection
	for rows.Next() {
		var (
			v           RuntimeDecision
			d           RuntimeDetection
			createdAt   string
			wouldBlock  int
			confidence  float64
			riskScore   float64
			dConfidence float64
			eventCount  int64
			firstSeen   string
			lastSeen    string
		)
		if err := rows.Scan(
			&v.DecisionID, &v.DetectionID, &v.AgentID, &v.AgentName,
			&v.SessionID, &v.TraceID, &v.Decision,
			&riskScore, &confidence, &v.PolicyID, &v.Reason,
			&v.EnforcementPoint, &v.Mode, &wouldBlock, &v.IdempotencyKey, &v.Source, &v.PolicyVersion, &createdAt,
			&d.DetectionType, &d.Category, &d.Severity,
			&d.RuleID, &d.RuleVersion,
			&d.Title, &d.Status, &dConfidence, &eventCount, &firstSeen, &lastSeen,
		); err != nil {
			return nil, nil, err
		}
		v.RiskScore = riskScore
		v.Confidence = confidence
		v.WouldBlock = wouldBlock != 0
		v.CreatedAt = parseTimeOrDefault(createdAt, time.Time{})
		d.DetectionID = v.DetectionID
		d.AgentID = v.AgentID
		d.AgentName = v.AgentName
		d.SessionID = v.SessionID
		d.TraceID = v.TraceID
		d.Confidence = dConfidence
		d.EventCount = int(eventCount)
		d.FirstSeenAt = parseTimeOrDefault(firstSeen, time.Time{})
		d.LastSeenAt = parseTimeOrDefault(lastSeen, time.Time{})
		out = append(out, v)
		detections = append(detections, d)
	}
	return out, detections, rows.Err()
}

// GetRuntimeDecisionDetail returns one decision with the response
// actions executed for it.
func (s *Store) GetRuntimeDecisionDetail(decisionID string) (RuntimeDecision, []ResponseAction, error) {
	var (
		v          RuntimeDecision
		createdAt  string
		wouldBlock int
		confidence float64
		riskScore  float64
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT decision_id, detection_id, agent_id, COALESCE(agent_name, ''),
       COALESCE(session_id, ''), COALESCE(trace_id, ''), decision,
       risk_score, confidence, COALESCE(policy_id, ''), COALESCE(reason, ''),
       COALESCE(enforcement_point, ''), mode, would_block,
       COALESCE(idempotency_key, ''), COALESCE(source, ''), COALESCE(policy_version, ''), created_at
FROM runtime_decisions WHERE decision_id = ? AND "delete" = 0`, decisionID,
	).Scan(
		&v.DecisionID, &v.DetectionID, &v.AgentID, &v.AgentName,
		&v.SessionID, &v.TraceID, &v.Decision,
		&riskScore, &confidence, &v.PolicyID, &v.Reason,
		&v.EnforcementPoint, &v.Mode, &wouldBlock, &v.IdempotencyKey, &v.Source, &v.PolicyVersion, &createdAt,
	)
	if err == sql.ErrNoRows {
		return RuntimeDecision{}, nil, nil
	}
	if err != nil {
		return RuntimeDecision{}, nil, err
	}
	v.RiskScore = riskScore
	v.Confidence = confidence
	v.WouldBlock = wouldBlock != 0
	v.CreatedAt = parseTimeOrDefault(createdAt, time.Time{})

	actions, err := s.ListResponseActions(decisionID)
	return v, actions, err
}

// ResponseAction records what was ACTUALLY executed (or would have
// been executed in observe mode) for one decision.
type ResponseAction struct {
	ResponseID        string    `json:"response_id"`
	DecisionID        string    `json:"decision_id"`
	ActionType        string    `json:"action_type"`
	Executor          string    `json:"executor,omitempty"`
	Target            string    `json:"target,omitempty"`
	Status            string    `json:"status"`
	Result            string    `json:"result,omitempty"`
	RollbackSupported bool      `json:"rollback_supported"`
	ExecutedAt        time.Time `json:"executed_at"`
}

// ResponseActionInput is the dispatcher's write shape.
type ResponseActionInput struct {
	DecisionID        string
	ActionType        string
	Executor          string
	Target            string
	Status            string
	Result            string
	RollbackSupported bool
	ExecutedAt        time.Time
}

// RecordResponseAction appends one response action.
func (s *Store) RecordResponseAction(in ResponseActionInput) (ResponseAction, error) {
	if s == nil || s.db == nil || strings.TrimSpace(in.DecisionID) == "" || strings.TrimSpace(in.ActionType) == "" {
		return ResponseAction{}, nil
	}
	if in.Status == "" {
		in.Status = ResponseStatusDispatched
	}
	if in.ExecutedAt.IsZero() {
		in.ExecutedAt = time.Now().UTC()
	}
	responseID := "R" + uuid.NewString()[:8]
	if _, err := s.execDB(context.Background(), "runtime_response_insert", `
INSERT INTO runtime_response_actions (
  response_id, decision_id, action_type, executor, target, status, result, rollback_supported, executed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		responseID, in.DecisionID, in.ActionType, in.Executor,
		nullStr(in.Target), in.Status, nullStr(in.Result), boolToInt(in.RollbackSupported),
		in.ExecutedAt.UTC().Format(time.RFC3339Nano),
	); err != nil {
		return ResponseAction{}, err
	}
	return ResponseAction{
		ResponseID: responseID, DecisionID: in.DecisionID,
		ActionType: in.ActionType, Executor: in.Executor, Target: in.Target,
		Status: in.Status, Result: in.Result, RollbackSupported: in.RollbackSupported, ExecutedAt: in.ExecutedAt,
	}, nil
}

// ListResponseActions returns the actions executed for one decision,
// oldest first (execution order).
func (s *Store) ListResponseActions(decisionID string) ([]ResponseAction, error) {
	if s == nil || s.db == nil || strings.TrimSpace(decisionID) == "" {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "runtime_response_list", `
SELECT response_id, decision_id, action_type, COALESCE(executor, ''),
       COALESCE(target, ''), status, COALESCE(result, ''), rollback_supported, executed_at
FROM runtime_response_actions
WHERE decision_id = ? AND "delete" = 0
ORDER BY executed_at ASC`, decisionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ResponseAction
	for rows.Next() {
		var (
			a                 ResponseAction
			executedAt        string
			rollbackSupported int
		)
		if err := rows.Scan(
			&a.ResponseID, &a.DecisionID, &a.ActionType, &a.Executor,
			&a.Target, &a.Status, &a.Result, &rollbackSupported, &executedAt,
		); err != nil {
			return nil, err
		}
		a.RollbackSupported = rollbackSupported != 0
		a.ExecutedAt = parseTimeOrDefault(executedAt, time.Time{})
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListResponseActionsAll returns persisted response actions newest first.
// The enforcement inventory must include non-network actions instead of
// reconstructing state from the in-memory proxy blocklist.
func (s *Store) ListResponseActionsAll(limit, offset int) ([]ResponseAction, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.queryDB(context.Background(), "runtime_response_list_all", `
SELECT response_id, decision_id, action_type, COALESCE(executor, ''),
       COALESCE(target, ''), status, COALESCE(result, ''), rollback_supported, executed_at
FROM runtime_response_actions
WHERE "delete" = 0
ORDER BY executed_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResponseAction
	for rows.Next() {
		var a ResponseAction
		var executedAt string
		var rollbackSupported int
		if err := rows.Scan(&a.ResponseID, &a.DecisionID, &a.ActionType, &a.Executor, &a.Target, &a.Status, &a.Result, &rollbackSupported, &executedAt); err != nil {
			return nil, err
		}
		a.RollbackSupported = rollbackSupported != 0
		a.ExecutedAt = parseTimeOrDefault(executedAt, time.Time{})
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountResponseActions returns all non-deleted response actions.
func (s *Store) CountResponseActions() (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	var total int
	if err := s.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM runtime_response_actions WHERE "delete" = 0`).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// UpdateResponseActionStatus records a terminal transition (for example
// active -> rolled_back) without deleting the audit row.
func (s *Store) UpdateResponseActionStatus(responseID, status, result string) error {
	if s == nil || s.db == nil || strings.TrimSpace(responseID) == "" {
		return nil
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return nil
	}
	_, err := s.execDB(context.Background(), "runtime_response_status", `
UPDATE runtime_response_actions SET status = ?, result = ?
WHERE response_id = ? AND "delete" = 0`, status, nullStringOrNil(result), strings.TrimSpace(responseID))
	return err
}

// RuntimeAttackChain is the backend security object for a correlated
// attack: the event sequence, its detection, and the decision that
// responded to it. This table is the authoritative record; page handlers
// must not reconstruct security meaning from display strings.
type RuntimeAttackChain struct {
	AttackChainID   string    `json:"attack_chain_id"`
	AgentID         string    `json:"agent_id"`
	AgentName       string    `json:"agent_name,omitempty"`
	SessionID       string    `json:"session_id,omitempty"`
	TraceID         string    `json:"trace_id,omitempty"`
	AttackType      string    `json:"attack_type"`
	Severity        string    `json:"severity"`
	Status          string    `json:"status"` // active | contained
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	DetectionID     string    `json:"detection_id,omitempty"`
	DecisionID      string    `json:"decision_id,omitempty"`
	BuilderVersion  string    `json:"builder_version,omitempty"`
	PolicyVersion   string    `json:"policy_version,omitempty"`
	EvaluationJobID string    `json:"evaluation_job_id,omitempty"`
}

// AttackChainEvent links one behavior event into a chain with its
// sequence and relation (e.g. "initial access", "credential access",
// "exfiltration", "block").
type AttackChainEvent struct {
	AttackChainID string        `json:"attack_chain_id"`
	EventID       int64         `json:"event_id"`
	Sequence      int           `json:"sequence"`
	Relation      string        `json:"relation,omitempty"`
	Event         BehaviorEvent `json:"event"`
}

// Attack chain status values.
const (
	AttackChainStatusActive    = "active"
	AttackChainStatusContained = "contained"
)

// UpsertRuntimeAttackChain creates or refreshes the attack chain for
// one detection (identity: detection_id). Evidence events are linked
// in chain order; re-fires append new events without duplicating.
func (s *Store) UpsertRuntimeAttackChain(in RuntimeAttackChain, events []AttackChainEventLink) (RuntimeAttackChain, error) {
	if s == nil || s.db == nil {
		return RuntimeAttackChain{}, nil
	}
	var (
		existingID string
		startTime  string
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT attack_chain_id, start_time FROM runtime_attack_chains
WHERE detection_id = ? AND "delete" = 0 ORDER BY start_time DESC LIMIT 1`, in.DetectionID,
	).Scan(&existingID, &startTime)
	if err == nil {
		// Refresh: bump end_time/severity/status and append events.
		if _, err := s.execDB(context.Background(), "runtime_attack_chain_update", `
UPDATE runtime_attack_chains
SET end_time = ?, severity = ?, status = ?, decision_id = ?,
    trace_id = COALESCE(NULLIF(?, ''), trace_id),
    builder_version = CASE WHEN ? != '' THEN ? ELSE builder_version END,
    policy_version = CASE WHEN ? != '' THEN ? ELSE policy_version END,
    evaluation_job_id = CASE WHEN ? != '' THEN ? ELSE evaluation_job_id END
WHERE attack_chain_id = ? AND "delete" = 0`,
			in.EndTime.UTC().Format(time.RFC3339Nano),
			strings.ToUpper(in.Severity), in.Status, in.DecisionID,
			in.TraceID,
			in.BuilderVersion, in.BuilderVersion,
			in.PolicyVersion, in.PolicyVersion,
			in.EvaluationJobID, in.EvaluationJobID,
			existingID,
		); err != nil {
			return RuntimeAttackChain{}, err
		}
		s.linkAttackChainEvents(existingID, events)
		in.AttackChainID = existingID
		in.StartTime = parseTimeOrDefault(startTime, in.StartTime)
		return in, nil
	}
	if err != sql.ErrNoRows {
		return RuntimeAttackChain{}, err
	}

	in.AttackChainID = "AC" + uuid.NewString()[:8]
	if _, err := s.execDB(context.Background(), "runtime_attack_chain_insert", `
INSERT INTO runtime_attack_chains (
  attack_chain_id, agent_id, session_id, trace_id, attack_type,
  severity, status, start_time, end_time, detection_id, decision_id, agent_name,
  builder_version, policy_version, evaluation_job_id
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.AttackChainID, in.AgentID, nullStr(in.SessionID), nullStr(in.TraceID),
		in.AttackType, strings.ToUpper(in.Severity), in.Status,
		in.StartTime.UTC().Format(time.RFC3339Nano),
		in.EndTime.UTC().Format(time.RFC3339Nano),
		in.DetectionID, in.DecisionID, nullStr(in.AgentName),
		in.BuilderVersion, in.PolicyVersion, in.EvaluationJobID,
	); err != nil {
		return RuntimeAttackChain{}, err
	}
	s.linkAttackChainEvents(in.AttackChainID, events)
	return in, nil
}

// AttackChainEventLink names one event in a chain.
type AttackChainEventLink struct {
	EventID  int64
	Sequence int
	Relation string
}

func (s *Store) linkAttackChainEvents(chainID string, events []AttackChainEventLink) {
	for _, ev := range events {
		if ev.EventID <= 0 {
			continue
		}
		_, _ = s.execDB(context.Background(), "runtime_attack_chain_event_link", `
INSERT INTO runtime_attack_chain_events (attack_chain_id, event_id, sequence, relation)
VALUES (?, ?, ?, ?)
ON CONFLICT(attack_chain_id, event_id) DO UPDATE SET
  sequence = excluded.sequence, relation = excluded.relation, "delete" = 0`,
			chainID, ev.EventID, ev.Sequence, ev.Relation)
	}
}

// AttackChainFilter selects chains for the API.
type AttackChainFilter struct {
	AgentID    string
	SessionID  string
	TraceID    string
	AttackType string
	Severity   string
	Status     string
	StartTime  time.Time
	EndTime    time.Time
	Offset     int
	Limit      int
}

func runtimeAttackChainWhereClause(f AttackChainFilter) (string, []any) {
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
	if f.AttackType != "" {
		conds = append(conds, "attack_type = ?")
		args = append(args, f.AttackType)
	}
	if f.Severity != "" {
		conds = append(conds, "severity = ?")
		args = append(args, strings.ToUpper(f.Severity))
	}
	if f.Status != "" {
		conds = append(conds, "status = ?")
		args = append(args, strings.ToLower(f.Status))
	}
	if !f.StartTime.IsZero() {
		conds = append(conds, "end_time >= ?")
		args = append(args, f.StartTime.UTC().Format(time.RFC3339Nano))
	}
	if !f.EndTime.IsZero() {
		conds = append(conds, "start_time <= ?")
		args = append(args, f.EndTime.UTC().Format(time.RFC3339Nano))
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// ListRuntimeAttackChains returns chains newest-first.
func (s *Store) ListRuntimeAttackChains(f AttackChainFilter) ([]RuntimeAttackChain, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if f.Limit <= 0 {
		f.Limit = 100
	}
	where, args := runtimeAttackChainWhereClause(f)
	if f.Offset < 0 {
		f.Offset = 0
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := s.queryDB(context.Background(), "runtime_attack_chains_list", `
SELECT attack_chain_id, agent_id, COALESCE(agent_name, ''),
       COALESCE(session_id, ''), COALESCE(trace_id, ''),
       attack_type, severity, status, start_time, end_time,
       COALESCE(detection_id, ''), COALESCE(decision_id, ''),
       COALESCE(builder_version, ''), COALESCE(policy_version, ''), COALESCE(evaluation_job_id, '')
FROM runtime_attack_chains
`+where+`
ORDER BY start_time DESC
LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []RuntimeAttackChain
	for rows.Next() {
		var (
			c         RuntimeAttackChain
			startTime string
			endTime   string
		)
		if err := rows.Scan(
			&c.AttackChainID, &c.AgentID, &c.AgentName,
			&c.SessionID, &c.TraceID, &c.AttackType, &c.Severity,
			&c.Status, &startTime, &endTime, &c.DetectionID, &c.DecisionID,
			&c.BuilderVersion, &c.PolicyVersion, &c.EvaluationJobID,
		); err != nil {
			return nil, err
		}
		c.StartTime = parseTimeOrDefault(startTime, time.Time{})
		c.EndTime = parseTimeOrDefault(endTime, time.Time{})
		out = append(out, c)
	}
	return out, rows.Err()
}

// CountRuntimeAttackChains returns the total number of non-deleted chains
// matching the same filters as ListRuntimeAttackChains.
func (s *Store) CountRuntimeAttackChains(f AttackChainFilter) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	where, args := runtimeAttackChainWhereClause(f)
	var total int
	if err := s.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM runtime_attack_chains `+where, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// GetRuntimeAttackChainDetail returns one chain with its event
// sequence (joined with behavior_events) in chain order.
func (s *Store) GetRuntimeAttackChainDetail(chainID string) (RuntimeAttackChain, []AttackChainEvent, error) {
	var (
		c         RuntimeAttackChain
		startTime string
		endTime   string
	)
	err := s.db.QueryRowContext(context.Background(), `
SELECT attack_chain_id, agent_id, COALESCE(agent_name, ''),
       COALESCE(session_id, ''), COALESCE(trace_id, ''),
       attack_type, severity, status, start_time, end_time,
       COALESCE(detection_id, ''), COALESCE(decision_id, ''),
       COALESCE(builder_version, ''), COALESCE(policy_version, ''), COALESCE(evaluation_job_id, '')
FROM runtime_attack_chains WHERE attack_chain_id = ? AND "delete" = 0`, chainID,
	).Scan(
		&c.AttackChainID, &c.AgentID, &c.AgentName,
		&c.SessionID, &c.TraceID, &c.AttackType, &c.Severity,
		&c.Status, &startTime, &endTime, &c.DetectionID, &c.DecisionID,
		&c.BuilderVersion, &c.PolicyVersion, &c.EvaluationJobID,
	)
	if err == sql.ErrNoRows {
		return RuntimeAttackChain{}, nil, nil
	}
	if err != nil {
		return RuntimeAttackChain{}, nil, err
	}
	c.StartTime = parseTimeOrDefault(startTime, time.Time{})
	c.EndTime = parseTimeOrDefault(endTime, time.Time{})

	rows, err := s.queryDB(context.Background(), "runtime_attack_chain_events", `
SELECT l.attack_chain_id, l.event_id, l.sequence, COALESCE(l.relation, ''),
       b.id, b.timestamp, b.event_type, b.source,
       COALESCE(b.event_source, ''), COALESCE(b.event_category, ''),
       COALESCE(b.event_id, ''), COALESCE(b.span_id, ''), COALESCE(b.parent_span_id, ''),
       b.agent_pid, COALESCE(b.agent_executable, ''), COALESCE(b.actor_pid, 0),
       COALESCE(b.actor_executable, ''), COALESCE(b.path, ''), COALESCE(b.action, ''),
       COALESCE(b.ppid, 0),
       COALESCE(b.operation, ''), COALESCE(b.target, ''), COALESCE(b.tool_name, ''), COALESCE(b.mcp_server, ''),
       COALESCE(b.severity, ''), COALESCE(b.confidence, 0), b.outcome, b.detail,
       COALESCE(b.agent_name, ''), COALESCE(b.canonical_agent_id, ''),
       COALESCE(b.session_id, ''), COALESCE(b.trace_id, ''), COALESCE(b.attributes_json, '')
FROM runtime_attack_chain_events l
JOIN behavior_events b ON b.id = l.event_id
WHERE l.attack_chain_id = ? AND l."delete" = 0 AND b."delete" = 0
ORDER BY l.sequence ASC, b.timestamp ASC`, chainID)
	if err != nil {
		return RuntimeAttackChain{}, nil, err
	}
	defer rows.Close()

	var events []AttackChainEvent
	for rows.Next() {
		var (
			link       AttackChainEvent
			e          BehaviorEvent
			ts         string
			agentPID   int64
			actorPID   int64
			ppid       int64
			confidence float64
			attrs      string
		)
		if err := rows.Scan(
			&link.AttackChainID, &link.EventID, &link.Sequence, &link.Relation,
			&e.ID, &ts, &e.EventType, &e.Source,
			&e.EventSource, &e.EventCategory, &e.EventID, &e.SpanID, &e.ParentSpanID,
			&agentPID, &e.AgentExecutable, &actorPID, &e.ActorExecutable, &e.Path, &e.Action,
			&ppid, &e.Operation, &e.Target, &e.ToolName, &e.MCPServer,
			&e.Severity, &confidence, &e.Outcome, &e.Detail,
			&e.AgentName, &e.CanonicalAgentID, &e.SessionID, &e.TraceID, &attrs,
		); err != nil {
			return RuntimeAttackChain{}, nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.Timestamp = t
		}
		e.AgentPID = uint32(agentPID)
		e.ActorPID = uint32(actorPID)
		e.PPID = uint32(ppid)
		e.Confidence = confidence
		if attrs != "" {
			_ = json.Unmarshal([]byte(attrs), &e.Attributes)
		}
		link.Event = e
		events = append(events, link)
	}
	return c, events, rows.Err()
}

// MaliciousStaticResource is a static_resources row flagged malicious
// by the scanner — the bridge from static scanning into runtime
// detection (Phase 3: Static Finding + Runtime Event → Detection).
type MaliciousStaticResource struct {
	ResourceID   string `json:"resource_id"`
	AgentID      string `json:"agent_id"`
	ResourceType string `json:"resource_type"`
	Name         string `json:"name"`
	Target       string `json:"target"`
	RiskLevel    string `json:"risk_level"`
}

// ListMaliciousStaticResources returns every active static resource
// flagged malicious. The detection engine caches this list and matches
// runtime tool/MCP invocations against it.
func (s *Store) ListMaliciousStaticResources() ([]MaliciousStaticResource, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resources_malicious", `
SELECT id, COALESCE(canonical_agent_id, ''), COALESCE(resource_type, ''),
       COALESCE(name, ''), COALESCE(target, ''), COALESCE(risk_level, 'high')
FROM static_resources
WHERE COALESCE(malicious, 0) = 1
  AND COALESCE(status, '') <> 'missing'
  AND COALESCE("delete", 0) = 0`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MaliciousStaticResource
	for rows.Next() {
		var r MaliciousStaticResource
		if err := rows.Scan(&r.ResourceID, &r.AgentID, &r.ResourceType, &r.Name, &r.Target, &r.RiskLevel); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
