// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// AgentIdentityInput is the backend-wide input shape used to bind any
// scanner, audit, or runtime signal to one canonical Agent row.
type AgentIdentityInput struct {
	AgentID          string
	AgentTypeID      int64
	DiscoveryRuleID  int64
	AgentName        string
	Connector        string
	Target           string
	Scanner          string
	Vendor           string
	Kind             string
	Runtime          string
	Source           string
	Status           string
	RuntimeStatus    string
	Confidence       int
	PIDs             []uint32
	ObservedAt       time.Time
	LastStaticScanAt time.Time
	Metadata         map[string]any
}

// CanonicalAgent is the durable Agent Inventory record returned from agents.
type CanonicalAgent struct {
	ID                    string `json:"id"`
	AgentTypeID           int64  `json:"agentTypeId,omitempty"`
	AgentTypeKey          string `json:"agentType,omitempty"`
	MatchedRuleID         int64  `json:"matchedRuleId,omitempty"`
	DisplayName           string `json:"displayName"`
	Vendor                string `json:"vendor"`
	Kind                  string `json:"kind"`
	Runtime               string `json:"runtime"`
	TypeDescription       string `json:"typeDescription,omitempty"`
	Source                string `json:"source"`
	Status                string `json:"status"`
	RuntimeStatus         string `json:"runtimeStatus"`
	Confidence            int    `json:"confidence,omitempty"`
	PIDs                  []uint32
	FirstSeenAt           string `json:"firstSeenAt"`
	LastSeenAt            string `json:"lastSeenAt"`
	LastStaticScanAt      string `json:"lastStaticScanAt,omitempty"`
	MetadataJSON          string `json:"metadataJson,omitempty"`
	StaticResourceCount   int    `json:"staticResourceCount"`
	RiskResourceCount     int    `json:"riskResourceCount"`
	CriticalResourceCount int    `json:"criticalResourceCount"`
}

// CanonicalAgentProfile is the built-in product profile for known agent
// families. It is intentionally small and stable; discovery can still override
// unknown products by passing explicit AgentName/Vendor/Kind/Runtime fields.
type CanonicalAgentProfile struct {
	ID          string
	DisplayName string
	Vendor      string
	Kind        string
	Runtime     string
	Source      string
}

// AgentType is the product identity catalog. It answers "what Agent family is
// this?" independently from how the local machine discovered an instance.
type AgentType struct {
	ID          int64  `json:"id"`
	TypeKey     string `json:"typeKey"`
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Kind        string `json:"kind"`
	Runtime     string `json:"runtime"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// AgentDiscoveryRule stores one scoring rule for discovering a concrete
// AgentType on the local host.
type AgentDiscoveryRule struct {
	ID         int64                     `json:"id"`
	AgentType  AgentType                 `json:"agentType"`
	RuleName   string                    `json:"ruleName"`
	Threshold  int                       `json:"threshold"`
	Enabled    bool                      `json:"enabled"`
	Conditions []AgentDiscoveryCondition `json:"conditions"`
}

// AgentDiscoveryCondition is one executable predicate inside a discovery rule:
// CLI exists, directory exists, file exists, process signal contains text, etc.
type AgentDiscoveryCondition struct {
	ID       int64  `json:"id"`
	RuleID   int64  `json:"ruleId"`
	Type     string `json:"type"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
	Weight   int    `json:"weight"`
	Required bool   `json:"required"`
	Enabled  bool   `json:"enabled"`
}

// StaticResourceInput is the normalized resource inventory shape written when
// a static scanner reports a target.
type StaticResourceInput struct {
	CanonicalAgentID string
	ResourceType     string
	Name             string
	Target           string
	Scanner          string
	TargetType       string
	ScanID           string
	ObservedAt       time.Time
	MaxSeverity      string
	FindingCount     int
	ContentHash      string
	Source           string
	// ResourceRuleID / ScanProfileID carry the agent_resource_rules lineage
	// when the resource was produced by rule-driven enumeration.
	ResourceRuleID int64
	ScanProfileID  int64
}

func CanonicalizeAgentIdentity(in AgentIdentityInput) CanonicalAgent {
	observed := in.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}

	id := canonicalAgentIDFromInput(in)
	if id == "" {
		return CanonicalAgent{}
	}
	if id == "unclassified-agent" && !IsStaticResourceScan(in.Scanner, in.Target) {
		return CanonicalAgent{}
	}

	profile, known := CanonicalAgentProfileForID(id)
	display := firstNonEmpty(profile.DisplayName, in.AgentName, in.AgentID, in.Connector, id)
	vendor := firstNonEmpty(in.Vendor, profile.Vendor)
	kind := firstNonEmpty(in.Kind, profile.Kind, "agent")
	runtime := firstNonEmpty(in.Runtime, profile.Runtime, runtimeLabel(kind))
	source := firstNonEmpty(in.Source, profile.Source, in.Scanner, in.Connector, "gateway")
	status := firstNonEmpty(in.Status, "observed")
	runtimeStatus := normalizeAgentRuntimeStatus(firstNonEmpty(in.RuntimeStatus, runtimeStatusFromAgentStatus(status)))
	if runtimeStatus == "" {
		runtimeStatus = "unknown"
	}
	if id == "unclassified-agent" && !known {
		display = "Unclassified Agent"
		vendor = firstNonEmpty(vendor, "Unknown")
		kind = firstNonEmpty(in.Kind, "unknown")
		runtime = firstNonEmpty(in.Runtime, "Backend Static Scanner")
	}

	ts := observed.UTC().Format(time.RFC3339Nano)
	agent := CanonicalAgent{
		ID:            id,
		DisplayName:   display,
		Vendor:        vendor,
		Kind:          kind,
		Runtime:       runtime,
		Source:        source,
		Status:        status,
		RuntimeStatus: runtimeStatus,
		FirstSeenAt:   ts,
		LastSeenAt:    ts,
	}
	if !in.LastStaticScanAt.IsZero() {
		agent.LastStaticScanAt = in.LastStaticScanAt.UTC().Format(time.RFC3339Nano)
	}
	if len(in.Metadata) > 0 {
		if b, err := json.Marshal(in.Metadata); err == nil {
			agent.MetadataJSON = string(b)
		}
	}
	agent.AgentTypeID = in.AgentTypeID
	agent.MatchedRuleID = in.DiscoveryRuleID
	agent.Confidence = in.Confidence
	agent.PIDs = normalizeAgentPIDs(in.PIDs)
	if agent.Confidence < 0 {
		agent.Confidence = 0
	}
	if agent.Confidence > 100 {
		agent.Confidence = 100
	}
	if agent.MetadataJSON == "" {
		agent.MetadataJSON = "{}"
	}
	return agent
}

func runtimeStatusFromAgentStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return "running"
	case "installed", "stopped", "missing":
		return "stopped"
	default:
		return ""
	}
}

func normalizeAgentRuntimeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running":
		return "running"
	case "stopped", "installed", "missing":
		return "stopped"
	case "unknown":
		return "unknown"
	default:
		return ""
	}
}

func normalizeAgentPIDs(pids []uint32) []uint32 {
	if len(pids) == 0 {
		return nil
	}
	seen := map[uint32]bool{}
	out := make([]uint32, 0, len(pids))
	for _, pid := range pids {
		if pid == 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		out = append(out, pid)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func agentPIDsJSON(pids []uint32) string {
	pids = normalizeAgentPIDs(pids)
	if len(pids) == 0 {
		return "[]"
	}
	b, err := json.Marshal(pids)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func agentPIDsFromJSON(raw string) []uint32 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var pids []uint32
	if err := json.Unmarshal([]byte(raw), &pids); err == nil {
		return normalizeAgentPIDs(pids)
	}
	return nil
}

// EnsureAgent upserts the canonical Agent row and all observed aliases. It is
// the write-side choke point that keeps audit_events, scan_results, and
// scan_findings attached to the same logical Agent.
func (s *Store) EnsureAgent(in AgentIdentityInput) (CanonicalAgent, error) {
	if s == nil || s.db == nil {
		return CanonicalAgent{}, nil
	}

	if canonicalAgentIDFromExplicitIdentity(in) == "" && knownAgentIDFromHints(in.Target) == "" {
		if existing, err := s.lookupAgentIDByAliases(in); err == nil && existing != "" {
			in.AgentID = existing
		} else if err != nil {
			return CanonicalAgent{}, err
		}
	}

	agent := CanonicalizeAgentIdentity(in)
	if agent.ID == "" {
		return CanonicalAgent{}, nil
	}

	err := retryBusy(context.Background(), "agent_inventory_upsert", func() error {
		tx, err := s.db.BeginTx(context.Background(), nil)
		if err != nil {
			return err
		}
		defer tx.Rollback() //nolint:errcheck
		if _, err := tx.ExecContext(context.Background(), `
INSERT INTO agents (
  id, agent_type_id, matched_rule_id, display_name, vendor, kind, runtime, source, status,
  runtime_status, pids_json, confidence, first_seen_at, last_seen_at, last_static_scan_at, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  agent_type_id = CASE WHEN excluded.agent_type_id IS NOT NULL THEN excluded.agent_type_id ELSE agents.agent_type_id END,
  matched_rule_id = CASE WHEN excluded.matched_rule_id IS NOT NULL THEN excluded.matched_rule_id ELSE agents.matched_rule_id END,
  display_name = excluded.display_name,
  vendor = CASE WHEN excluded.vendor <> '' THEN excluded.vendor ELSE agents.vendor END,
  kind = CASE WHEN excluded.kind <> '' THEN excluded.kind ELSE agents.kind END,
  runtime = CASE WHEN excluded.runtime <> '' THEN excluded.runtime ELSE agents.runtime END,
  source = CASE
    WHEN excluded.source = '' THEN agents.source
    WHEN agents.source = '' THEN excluded.source
    WHEN instr(',' || replace(agents.source, ', ', ',') || ',', ',' || excluded.source || ',') > 0 THEN agents.source
    ELSE agents.source || ', ' || excluded.source
  END,
  status = CASE WHEN excluded.status <> '' THEN excluded.status ELSE agents.status END,
  runtime_status = CASE
    WHEN excluded.runtime_status IN ('running', 'stopped') THEN excluded.runtime_status
    WHEN COALESCE(agents.runtime_status, '') = '' THEN excluded.runtime_status
    ELSE agents.runtime_status
  END,
  pids_json = CASE
    WHEN excluded.runtime_status IN ('running', 'stopped') THEN excluded.pids_json
    ELSE agents.pids_json
  END,
  confidence = CASE WHEN excluded.confidence > 0 THEN excluded.confidence ELSE agents.confidence END,
  last_seen_at = excluded.last_seen_at,
  last_static_scan_at = COALESCE(excluded.last_static_scan_at, agents.last_static_scan_at),
  metadata_json = CASE WHEN excluded.metadata_json <> '{}' THEN excluded.metadata_json ELSE agents.metadata_json END`,
			agent.ID,
			nullInt64Value(agent.AgentTypeID),
			nullInt64Value(agent.MatchedRuleID),
			agent.DisplayName,
			agent.Vendor,
			agent.Kind,
			agent.Runtime,
			agent.Source,
			agent.Status,
			agent.RuntimeStatus,
			agentPIDsJSON(agent.PIDs),
			agent.Confidence,
			agent.FirstSeenAt,
			agent.LastSeenAt,
			anyString(agent.LastStaticScanAt),
			agent.MetadataJSON,
		); err != nil {
			return fmt.Errorf("audit: upsert agent %q: %w", agent.ID, err)
		}

		for _, alias := range canonicalAgentAliases(agent.ID, in) {
			if _, err := tx.ExecContext(context.Background(), `
INSERT INTO agent_aliases (alias, agent_id, raw_alias, alias_type, source, created_at, last_seen_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(alias) DO UPDATE SET
  agent_id = excluded.agent_id,
  raw_alias = excluded.raw_alias,
  alias_type = excluded.alias_type,
  source = excluded.source,
  last_seen_at = excluded.last_seen_at`,
				alias.key,
				agent.ID,
				alias.raw,
				alias.kind,
				firstNonEmpty(in.Source, in.Scanner, in.Connector, "gateway"),
				agent.LastSeenAt,
				agent.LastSeenAt,
			); err != nil {
				return fmt.Errorf("audit: upsert agent alias %q: %w", alias.key, err)
			}
		}
		return tx.Commit()
	})
	if err != nil {
		return CanonicalAgent{}, err
	}

	return agent, nil
}

// EnsureStaticResource upserts the resource inventory row for a static scan
// and returns the stable static_resource_id.
func (s *Store) EnsureStaticResource(in StaticResourceInput) (string, error) {
	if s == nil || s.db == nil || strings.TrimSpace(in.Target) == "" || strings.TrimSpace(in.CanonicalAgentID) == "" {
		return "", nil
	}
	observed := in.ObservedAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	// Store and hash the canonical target: the Windows extended-length
	// prefix ("\\?\C:\...") is an API artifact of the producer, not part
	// of the resource identity.
	target := TrimExtendedPathPrefix(strings.TrimSpace(in.Target))
	rtype := CanonicalResourceType(firstNonEmpty(in.ResourceType, StaticResourceType(in.TargetType, in.Scanner, in.Target), "Config"))
	id := StaticResourceID(in.CanonicalAgentID, target, rtype)
	name := firstNonEmpty(in.Name, staticResourceName(target, rtype))
	status := staticResourceStatus(in.MaxSeverity)

	if _, err := s.execDB(context.Background(), "static_resource_upsert", `
INSERT INTO static_resources (
  id, canonical_agent_id, resource_type, name, target, scanner, target_type,
  last_scan_id, last_seen_at, max_severity, finding_count, content_hash, status, source,
  resource_rule_id, scan_profile_id, risk_level, malicious
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET
  canonical_agent_id = excluded.canonical_agent_id,
  resource_type = excluded.resource_type,
  name = excluded.name,
  target = excluded.target,
  scanner = excluded.scanner,
  target_type = excluded.target_type,
  last_scan_id = COALESCE(excluded.last_scan_id, static_resources.last_scan_id),
  last_seen_at = excluded.last_seen_at,
  max_severity = CASE WHEN excluded.last_scan_id IS NOT NULL THEN excluded.max_severity ELSE static_resources.max_severity END,
  finding_count = CASE WHEN excluded.last_scan_id IS NOT NULL THEN excluded.finding_count ELSE static_resources.finding_count END,
  content_hash = COALESCE(excluded.content_hash, static_resources.content_hash),
  status = CASE
    WHEN excluded.last_scan_id IS NOT NULL THEN excluded.status
    WHEN static_resources.status = 'missing' THEN 'discovered'
    ELSE static_resources.status END,
  source = CASE WHEN excluded.source <> '' THEN excluded.source ELSE static_resources.source END,
  resource_rule_id = COALESCE(excluded.resource_rule_id, static_resources.resource_rule_id),
  scan_profile_id = COALESCE(excluded.scan_profile_id, static_resources.scan_profile_id),
  risk_level = CASE WHEN excluded.last_scan_id IS NOT NULL THEN excluded.risk_level ELSE static_resources.risk_level END,
  malicious = CASE WHEN excluded.last_scan_id IS NOT NULL THEN excluded.malicious ELSE static_resources.malicious END`,
		id,
		in.CanonicalAgentID,
		rtype,
		name,
		target,
		firstNonEmpty(in.Scanner, "static-resource-scanner"),
		in.TargetType,
		anyString(in.ScanID),
		observed.UTC().Format(time.RFC3339Nano),
		firstNonEmpty(in.MaxSeverity, "INFO"),
		in.FindingCount,
		anyString(in.ContentHash),
		status,
		firstNonEmpty(in.Source, in.Scanner, "backend-static"),
		nullInt64Value(in.ResourceRuleID),
		nullInt64Value(in.ScanProfileID),
		ResourceRiskLevel(firstNonEmpty(in.MaxSeverity, "INFO")),
		0,
	); err != nil {
		return "", fmt.Errorf("audit: upsert static resource %q: %w", id, err)
	}
	return id, nil
}

func (s *Store) ListAgents(limit int) ([]CanonicalAgent, error) {
	if limit <= 0 {
		limit = 600
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_list", `
SELECT a.id,
       COALESCE(a.agent_type_id, 0),
       COALESCE(t.type_key, ''),
       COALESCE(a.matched_rule_id, 0),
       COALESCE(t.name, a.display_name),
       COALESCE(t.vendor, a.vendor, ''),
       COALESCE(t.kind, a.kind, ''),
       COALESCE(t.runtime, a.runtime, ''),
       COALESCE(t.description, ''),
       COALESCE(a.source, ''),
       COALESCE(a.status, ''),
       COALESCE(a.runtime_status, ''),
       COALESCE(a.pids_json, '[]'),
       COALESCE(a.confidence, 0),
       COALESCE(a.first_seen_at, ''),
       COALESCE(a.last_seen_at, ''),
       COALESCE(a.last_static_scan_at, ''),
       COALESCE(a.metadata_json, '{}'),
       COUNT(sr.id),
       COALESCE(SUM(CASE WHEN lower(sr.max_severity) IN ('high', 'critical', 'error') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN lower(sr.max_severity) = 'critical' THEN 1 ELSE 0 END), 0)
FROM agents a
LEFT JOIN agent_types t ON t.id = a.agent_type_id AND COALESCE(t."delete", 0) = 0
LEFT JOIN static_resources sr ON sr.canonical_agent_id = a.id AND COALESCE(sr."delete", 0) = 0
WHERE COALESCE(a."delete", 0) = 0
GROUP BY a.id
ORDER BY lower(COALESCE(t.name, a.display_name)), lower(a.id)
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list agents: %w", err)
	}
	defer rows.Close()

	var out []CanonicalAgent
	for rows.Next() {
		var a CanonicalAgent
		var pidsJSON string
		if err := rows.Scan(
			&a.ID, &a.AgentTypeID, &a.AgentTypeKey, &a.MatchedRuleID,
			&a.DisplayName, &a.Vendor, &a.Kind, &a.Runtime, &a.TypeDescription,
			&a.Source, &a.Status, &a.RuntimeStatus, &pidsJSON, &a.Confidence,
			&a.FirstSeenAt, &a.LastSeenAt, &a.LastStaticScanAt, &a.MetadataJSON,
			&a.StaticResourceCount, &a.RiskResourceCount, &a.CriticalResourceCount,
		); err != nil {
			return nil, fmt.Errorf("audit: scan agent row: %w", err)
		}
		a.RuntimeStatus = normalizeAgentRuntimeStatus(firstNonEmpty(a.RuntimeStatus, runtimeStatusFromAgentStatus(a.Status), "unknown"))
		a.PIDs = agentPIDsFromJSON(pidsJSON)
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ListEnabledAgentDiscoveryRules() ([]AgentDiscoveryRule, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "agent_discovery_rule_list", `
SELECT r.id,
       COALESCE(r.rule_name, ''),
       COALESCE(r.threshold, 60),
       COALESCE(r.enabled, 0),
       t.id,
       COALESCE(t.type_key, ''),
       COALESCE(t.name, ''),
       COALESCE(t.vendor, ''),
       COALESCE(t.kind, ''),
       COALESCE(t.runtime, ''),
       COALESCE(t.description, ''),
       COALESCE(t.enabled, 0)
FROM agent_discovery_rules r
JOIN agent_types t ON t.id = r.agent_type_id
WHERE COALESCE(r.enabled, 0) = 1
  AND COALESCE(r."delete", 0) = 0
  AND COALESCE(t.enabled, 0) = 1
  AND COALESCE(t."delete", 0) = 0
ORDER BY lower(t.name), r.id`)
	if err != nil {
		return nil, fmt.Errorf("audit: list agent discovery rules: %w", err)
	}
	defer rows.Close()

	rules := []AgentDiscoveryRule{}
	ruleIndex := map[int64]int{}
	for rows.Next() {
		var rule AgentDiscoveryRule
		var ruleEnabled, typeEnabled int
		if err := rows.Scan(
			&rule.ID, &rule.RuleName, &rule.Threshold, &ruleEnabled,
			&rule.AgentType.ID, &rule.AgentType.TypeKey, &rule.AgentType.Name, &rule.AgentType.Vendor,
			&rule.AgentType.Kind, &rule.AgentType.Runtime, &rule.AgentType.Description, &typeEnabled,
		); err != nil {
			return nil, fmt.Errorf("audit: scan agent discovery rule: %w", err)
		}
		rule.Enabled = ruleEnabled != 0
		rule.AgentType.Enabled = typeEnabled != 0
		if rule.Threshold <= 0 {
			rule.Threshold = 60
		}
		ruleIndex[rule.ID] = len(rules)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return rules, nil
	}

	ids := make([]string, 0, len(rules))
	args := make([]any, 0, len(rules))
	for _, rule := range rules {
		ids = append(ids, "?")
		args = append(args, rule.ID)
	}
	condRows, err := s.queryDB(context.Background(), "agent_discovery_condition_list", `
SELECT id,
       rule_id,
       COALESCE(condition_type, ''),
       COALESCE(field, ''),
       COALESCE(operator, ''),
       COALESCE(value, ''),
       COALESCE(weight, 0),
       COALESCE(required, 0),
       COALESCE(enabled, 0)
FROM agent_discovery_conditions
WHERE COALESCE(enabled, 0) = 1
  AND COALESCE("delete", 0) = 0
  AND rule_id IN (`+strings.Join(ids, ",")+`)
ORDER BY rule_id, required DESC, weight DESC, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list agent discovery conditions: %w", err)
	}
	defer condRows.Close()
	for condRows.Next() {
		var c AgentDiscoveryCondition
		var required, enabled int
		if err := condRows.Scan(&c.ID, &c.RuleID, &c.Type, &c.Field, &c.Operator, &c.Value, &c.Weight, &required, &enabled); err != nil {
			return nil, fmt.Errorf("audit: scan agent discovery condition: %w", err)
		}
		c.Required = required != 0
		c.Enabled = enabled != 0
		if idx, ok := ruleIndex[c.RuleID]; ok {
			rules[idx].Conditions = append(rules[idx].Conditions, c)
		}
	}
	return rules, condRows.Err()
}

func (s *Store) MarkMissingAgentDiscoveries(activeIDs []string, observedAt time.Time) error {
	if s == nil || s.db == nil {
		return nil
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	seen := map[string]bool{}
	args := []any{"missing"}
	predicates := []string{}
	for _, id := range activeIDs {
		id = CanonicalAgentID(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		predicates = append(predicates, "?")
		args = append(args, id)
	}
	query := `
UPDATE agents
SET status = ?, runtime_status = 'stopped', pids_json = '[]'
WHERE status <> 'missing'
  AND COALESCE("delete", 0) = 0
  AND (matched_rule_id IS NOT NULL OR source LIKE '%agent-scanner%')`
	if len(predicates) > 0 {
		query += ` AND id NOT IN (` + strings.Join(predicates, ",") + `)`
	}
	if _, err := s.execDB(context.Background(), "agent_discovery_mark_missing", query, args...); err != nil {
		return fmt.Errorf("audit: mark missing agent discoveries: %w", err)
	}
	return nil
}

func (s *Store) backfillAgentInventory() error {
	if s == nil || s.db == nil {
		return nil
	}
	present, err := tableExists(s.db, "agents")
	if err != nil || !present {
		return err
	}
	if err := s.backfillAuditEventAgents(); err != nil {
		return err
	}
	if err := s.backfillScanResultAgents(); err != nil {
		return err
	}
	if err := s.backfillScanFindingAgents(); err != nil {
		return err
	}
	if err := s.backfillNetworkEgressAgents(); err != nil {
		return err
	}
	if err := s.backfillActivityEventAgents(); err != nil {
		return err
	}
	if err := s.backfillJudgeResponseAgents(); err != nil {
		return err
	}
	return nil
}

type auditEventAgentBackfillRow struct {
	ID        string
	Timestamp string
	AgentID   string
	AgentName string
	Connector string
	Target    string
	Canonical string
}

func (s *Store) backfillAuditEventAgents() error {
	present, err := tableExists(s.db, "audit_events")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_audit_select", `
SELECT id,
       COALESCE(timestamp, ''),
       COALESCE(agent_id, ''),
       COALESCE(agent_name, ''),
       COALESCE(connector, ''),
       COALESCE(target, ''),
       COALESCE(canonical_agent_id, '')
FROM audit_events
WHERE COALESCE(canonical_agent_id, '') = ''
  AND (COALESCE(agent_id, '') <> ''
    OR COALESCE(agent_name, '') <> ''
    OR COALESCE(connector, '') <> '')`)
	if err != nil {
		return fmt.Errorf("audit: select audit event agents for backfill: %w", err)
	}
	var items []auditEventAgentBackfillRow
	for rows.Next() {
		var row auditEventAgentBackfillRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.AgentID, &row.AgentName, &row.Connector, &row.Target, &row.Canonical); err != nil {
			rows.Close()
			return fmt.Errorf("audit: scan audit event agent backfill row: %w", err)
		}
		items = append(items, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:    firstNonEmpty(row.Canonical, row.AgentID),
			AgentName:  row.AgentName,
			Connector:  row.Connector,
			Target:     row.Target,
			Source:     "audit_events",
			Status:     "observed",
			ObservedAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_audit_update",
			`UPDATE audit_events SET canonical_agent_id = ?, agent_name = ? WHERE id = ?`,
			agent.ID, agent.DisplayName, row.ID,
		); err != nil {
			return fmt.Errorf("audit: update audit event agent backfill: %w", err)
		}
	}
	return nil
}

type scanAgentBackfillRow struct {
	ID               string
	ScanID           string
	Scanner          string
	Target           string
	Timestamp        string
	AgentID          string
	AgentName        string
	CanonicalAgentID string
	StaticResourceID string
	MaxSeverity      string
	FindingCount     int
	ContentHash      string
}

func (s *Store) backfillScanResultAgents() error {
	present, err := tableExists(s.db, "scan_results")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_scan_results_select", `
SELECT id,
       id,
       COALESCE(scanner, ''),
       COALESCE(target, ''),
       COALESCE(timestamp, ''),
       COALESCE(agent_id, ''),
       COALESCE(agent_name, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(static_resource_id, ''),
       COALESCE(max_severity, 'INFO'),
       COALESCE(finding_count, 0),
       COALESCE(content_hash, '')
FROM scan_results
WHERE COALESCE(agent_id, '') <> ''
   OR COALESCE(agent_name, '') <> ''
   OR COALESCE(canonical_agent_id, '') <> ''
   OR lower(COALESCE(scanner, '')) LIKE '%static-resource%'
   OR lower(COALESCE(scanner, '')) LIKE '%skill%'
   OR lower(COALESCE(scanner, '')) LIKE '%plugin%'
   OR lower(COALESCE(scanner, '')) LIKE '%mcp%'`)
	if err != nil {
		return fmt.Errorf("audit: select scan result agents for backfill: %w", err)
	}
	items, err := scanAgentBackfillRows(rows)
	if err != nil {
		return err
	}
	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:          firstNonEmpty(row.CanonicalAgentID, row.AgentID),
			AgentName:        row.AgentName,
			Target:           row.Target,
			Scanner:          row.Scanner,
			Source:           "scan_results",
			Status:           "observed",
			ObservedAt:       parseInventoryTime(row.Timestamp),
			LastStaticScanAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		staticResourceID, err := s.ensureBackfilledStaticResource(agent.ID, row)
		if err != nil {
			return err
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_scan_results_update",
			`UPDATE scan_results SET canonical_agent_id = ?, agent_name = ?, static_resource_id = ? WHERE id = ?`,
			agent.ID, agent.DisplayName, nullStrValue(staticResourceID), row.ID,
		); err != nil {
			return fmt.Errorf("audit: update scan result agent backfill: %w", err)
		}
	}
	return nil
}

func (s *Store) backfillScanFindingAgents() error {
	present, err := tableExists(s.db, "scan_findings")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_scan_findings_select", `
SELECT id,
       COALESCE(scan_id, ''),
       COALESCE(scanner, ''),
       COALESCE(target, ''),
       COALESCE(timestamp, ''),
       COALESCE(agent_id, ''),
       COALESCE(agent_name, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(static_resource_id, ''),
       COALESCE(severity, 'INFO'),
       1,
       ''
FROM scan_findings
WHERE COALESCE(agent_id, '') <> ''
   OR COALESCE(agent_name, '') <> ''
   OR COALESCE(canonical_agent_id, '') <> ''
   OR lower(COALESCE(scanner, '')) LIKE '%static-resource%'
   OR lower(COALESCE(scanner, '')) LIKE '%skill%'
   OR lower(COALESCE(scanner, '')) LIKE '%plugin%'
   OR lower(COALESCE(scanner, '')) LIKE '%mcp%'`)
	if err != nil {
		return fmt.Errorf("audit: select scan finding agents for backfill: %w", err)
	}
	items, err := scanAgentBackfillRows(rows)
	if err != nil {
		return err
	}
	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:          firstNonEmpty(row.CanonicalAgentID, row.AgentID),
			AgentName:        row.AgentName,
			Target:           row.Target,
			Scanner:          row.Scanner,
			Source:           "scan_findings",
			Status:           "observed",
			ObservedAt:       parseInventoryTime(row.Timestamp),
			LastStaticScanAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		staticResourceID, err := s.ensureBackfilledStaticResource(agent.ID, row)
		if err != nil {
			return err
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_scan_findings_update",
			`UPDATE scan_findings SET canonical_agent_id = ?, agent_name = ?, static_resource_id = ? WHERE id = ?`,
			agent.ID, agent.DisplayName, nullStrValue(staticResourceID), row.ID,
		); err != nil {
			return fmt.Errorf("audit: update scan finding agent backfill: %w", err)
		}
	}
	return nil
}

func scanAgentBackfillRows(rows *sql.Rows) ([]scanAgentBackfillRow, error) {
	defer rows.Close()
	var items []scanAgentBackfillRow
	for rows.Next() {
		var row scanAgentBackfillRow
		if err := rows.Scan(
			&row.ID,
			&row.ScanID,
			&row.Scanner,
			&row.Target,
			&row.Timestamp,
			&row.AgentID,
			&row.AgentName,
			&row.CanonicalAgentID,
			&row.StaticResourceID,
			&row.MaxSeverity,
			&row.FindingCount,
			&row.ContentHash,
		); err != nil {
			return nil, fmt.Errorf("audit: scan agent inventory backfill row: %w", err)
		}
		items = append(items, row)
	}
	return items, rows.Err()
}

func (s *Store) ensureBackfilledStaticResource(agentID string, row scanAgentBackfillRow) (string, error) {
	if agentID == "" || !IsStaticResourceScan(row.Scanner, row.Target) {
		return "", nil
	}
	resourceID, err := s.EnsureStaticResource(StaticResourceInput{
		CanonicalAgentID: agentID,
		ResourceType:     StaticResourceType("", row.Scanner, row.Target),
		Target:           row.Target,
		Scanner:          row.Scanner,
		ScanID:           firstNonEmpty(row.ScanID, row.ID),
		ObservedAt:       parseInventoryTime(row.Timestamp),
		MaxSeverity:      row.MaxSeverity,
		FindingCount:     row.FindingCount,
		ContentHash:      row.ContentHash,
		Source:           "backfill",
	})
	if err != nil {
		return "", err
	}
	return firstNonEmpty(resourceID, row.StaticResourceID), nil
}

type networkEgressAgentBackfillRow struct {
	ID               string
	Timestamp        string
	Connector        string
	AgentID          string
	CanonicalAgentID string
	RootAgentID      string
	ParentAgentID    string
	Hostname         string
}

func (s *Store) backfillNetworkEgressAgents() error {
	present, err := tableExists(s.db, "network_egress_events")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_network_egress_select", `
SELECT id,
       COALESCE(timestamp, ''),
       COALESCE(connector, ''),
       COALESCE(agent_id, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(root_agent_id, ''),
       COALESCE(parent_agent_id, ''),
       COALESCE(hostname, '')
FROM network_egress_events
WHERE COALESCE(agent_id, '') <> ''
   OR COALESCE(canonical_agent_id, '') <> ''
   OR COALESCE(connector, '') <> ''
   OR COALESCE(root_agent_id, '') <> ''
   OR COALESCE(parent_agent_id, '') <> ''`)
	if err != nil {
		return fmt.Errorf("audit: select network egress agents for backfill: %w", err)
	}
	defer rows.Close()

	var items []networkEgressAgentBackfillRow
	for rows.Next() {
		var row networkEgressAgentBackfillRow
		if err := rows.Scan(
			&row.ID,
			&row.Timestamp,
			&row.Connector,
			&row.AgentID,
			&row.CanonicalAgentID,
			&row.RootAgentID,
			&row.ParentAgentID,
			&row.Hostname,
		); err != nil {
			return fmt.Errorf("audit: scan network egress agent backfill row: %w", err)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:    firstNonEmpty(row.CanonicalAgentID, row.AgentID, row.RootAgentID, row.ParentAgentID),
			AgentName:  firstNonEmpty(row.Connector, row.AgentID, row.RootAgentID, row.ParentAgentID),
			Connector:  row.Connector,
			Target:     row.Hostname,
			Source:     "network_egress_events",
			Status:     "observed",
			ObservedAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_network_egress_update",
			`UPDATE network_egress_events SET canonical_agent_id = ? WHERE id = ?`,
			agent.ID, row.ID,
		); err != nil {
			return fmt.Errorf("audit: update network egress agent backfill: %w", err)
		}
	}
	return nil
}

type activityEventAgentBackfillRow struct {
	ID               string
	Timestamp        string
	AgentID          string
	CanonicalAgentID string
	TargetID         string
}

func (s *Store) backfillActivityEventAgents() error {
	present, err := tableExists(s.db, "activity_events")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_activity_select", `
SELECT id,
       COALESCE(timestamp, ''),
       COALESCE(agent_id, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(target_id, '')
FROM activity_events
WHERE COALESCE(agent_id, '') <> ''
   OR COALESCE(canonical_agent_id, '') <> ''`)
	if err != nil {
		return fmt.Errorf("audit: select activity event agents for backfill: %w", err)
	}
	defer rows.Close()

	var items []activityEventAgentBackfillRow
	for rows.Next() {
		var row activityEventAgentBackfillRow
		if err := rows.Scan(&row.ID, &row.Timestamp, &row.AgentID, &row.CanonicalAgentID, &row.TargetID); err != nil {
			return fmt.Errorf("audit: scan activity event agent backfill row: %w", err)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:    firstNonEmpty(row.CanonicalAgentID, row.AgentID),
			AgentName:  row.AgentID,
			Target:     row.TargetID,
			Source:     "activity_events",
			Status:     "observed",
			ObservedAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_activity_update",
			`UPDATE activity_events SET canonical_agent_id = ? WHERE id = ?`,
			agent.ID, row.ID,
		); err != nil {
			return fmt.Errorf("audit: update activity event agent backfill: %w", err)
		}
	}
	return nil
}

type judgeResponseAgentBackfillRow struct {
	ID               string
	Timestamp        string
	AgentID          string
	CanonicalAgentID string
	ToolName         string
	DestinationApp   string
	Model            string
}

func (s *Store) backfillJudgeResponseAgents() error {
	present, err := tableExists(s.db, "judge_responses")
	if err != nil || !present {
		return err
	}
	rows, err := s.queryDB(context.Background(), "agent_inventory_backfill_judge_select", `
SELECT id,
       COALESCE(timestamp, ''),
       COALESCE(agent_id, ''),
       COALESCE(canonical_agent_id, ''),
       COALESCE(tool_name, ''),
       COALESCE(destination_app, ''),
       COALESCE(model, '')
FROM judge_responses
WHERE COALESCE(agent_id, '') <> ''
   OR COALESCE(canonical_agent_id, '') <> ''`)
	if err != nil {
		return fmt.Errorf("audit: select judge response agents for backfill: %w", err)
	}
	defer rows.Close()

	var items []judgeResponseAgentBackfillRow
	for rows.Next() {
		var row judgeResponseAgentBackfillRow
		if err := rows.Scan(
			&row.ID,
			&row.Timestamp,
			&row.AgentID,
			&row.CanonicalAgentID,
			&row.ToolName,
			&row.DestinationApp,
			&row.Model,
		); err != nil {
			return fmt.Errorf("audit: scan judge response agent backfill row: %w", err)
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, row := range items {
		agent, err := s.EnsureAgent(AgentIdentityInput{
			AgentID:    firstNonEmpty(row.CanonicalAgentID, row.AgentID),
			AgentName:  row.AgentID,
			Target:     firstNonEmpty(row.ToolName, row.DestinationApp, row.Model),
			Source:     "judge_responses",
			Status:     "observed",
			ObservedAt: parseInventoryTime(row.Timestamp),
		})
		if err != nil {
			return err
		}
		if agent.ID == "" {
			continue
		}
		if _, err := s.execDB(context.Background(), "agent_inventory_backfill_judge_update",
			`UPDATE judge_responses SET canonical_agent_id = ? WHERE id = ?`,
			agent.ID, row.ID,
		); err != nil {
			return fmt.Errorf("audit: update judge response agent backfill: %w", err)
		}
	}
	return nil
}

func parseInventoryTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Now().UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC()
		}
	}
	return time.Now().UTC()
}

func nullStrValue(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

func nullInt64Value(value int64) any {
	if value <= 0 {
		return nil
	}
	return value
}

func (s *Store) lookupAgentIDByAliases(in AgentIdentityInput) (string, error) {
	aliases := canonicalAgentAliases("", in)
	for _, alias := range aliases {
		var id string
		err := s.scanRow(context.Background(), "agent_alias_lookup",
			s.db.QueryRowContext(context.Background(), `SELECT agent_id FROM agent_aliases WHERE alias = ?`, alias.key),
			&id,
		)
		if err == nil && strings.TrimSpace(id) != "" {
			return id, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("audit: lookup agent alias %q: %w", alias.key, err)
		}
	}
	return "", nil
}

func CanonicalAgentIDFromHints(values ...string) string {
	if id := knownAgentIDFromHints(values...); id != "" {
		return id
	}
	for _, value := range values {
		id := CanonicalAgentID(value)
		if id != "" {
			return id
		}
	}
	return ""
}

func canonicalAgentIDFromInput(in AgentIdentityInput) string {
	if id := canonicalAgentIDFromExplicitIdentity(in); id != "" {
		return id
	}
	if id := knownAgentIDFromHints(in.Target); id != "" {
		return id
	}
	if IsStaticResourceScan(in.Scanner, in.Target) {
		return "unclassified-agent"
	}
	return ""
}

func canonicalAgentIDFromExplicitIdentity(in AgentIdentityInput) string {
	if id := knownAgentIDFromHints(in.AgentName, in.Connector, in.AgentID); id != "" {
		return id
	}
	for _, value := range []string{in.AgentID, in.AgentName, in.Connector} {
		if id := CanonicalAgentID(value); id != "" {
			return id
		}
	}
	return ""
}

func CanonicalAgentID(value string) string {
	id := stableID(value)
	switch id {
	case "", "unknown", "unknown-agent", "gateway", "backend", "audit", "scanner", "gateway-runtime", "tracebastion-gateway":
		return ""
	case "agentrange", "agent-range", "agentrange-player", "ops-pilot", "opspilot", "agentrange-opspilot":
		return "agentrange-opspilot"
	case "claude", "claudecode", "claude-code", "anthropic-claude", "anthropic-claude-code":
		return "claude-code"
	case "gemini", "geminicli", "gemini-cli", "google-gemini":
		return "gemini-cli"
	case "cherry", "cherrystudio", "cherry-studio", "cherry-studio-app":
		return "cherry-studio"
	case "openai-codex", "codex-cli":
		return "codex"
	default:
		return id
	}
}

func CanonicalAgentProfileForID(id string) (CanonicalAgentProfile, bool) {
	id = CanonicalAgentID(id)
	profile, ok := canonicalAgentProfiles()[id]
	return profile, ok
}

func IsStaticResourceScan(scannerName, target string) bool {
	combined := strings.ToLower(scannerName + " " + target)
	for _, marker := range []string{
		"static-resource", "skill-scanner", "plugin-scanner", "mcp-scanner",
		"credential-scanner", "prompt-scanner", "environment-scanner",
	} {
		if strings.Contains(combined, marker) {
			return true
		}
	}
	return false
}

func StaticResourceType(sourceType, scannerName, target string) string {
	combined := strings.ToLower(sourceType + " " + scannerName + " " + target)
	switch {
	case strings.Contains(combined, "credential") || strings.Contains(combined, "secret") ||
		strings.Contains(combined, "token") || strings.Contains(combined, "api_key") ||
		strings.Contains(combined, "apikey") || strings.Contains(combined, ".env"):
		return "Credential"
	case strings.Contains(combined, "environment") || strings.Contains(combined, "env://") ||
		strings.Contains(combined, "environment://"):
		return "Environment"
	case strings.Contains(combined, "mcp"):
		return "MCP"
	case strings.Contains(combined, "plugin"):
		return "Plugin"
	case strings.Contains(combined, "skill"):
		return "Skills"
	case strings.Contains(combined, "prompt") || strings.Contains(combined, "claude.md") ||
		strings.Contains(combined, "agents.md") || strings.Contains(combined, "rules.md"):
		return "Prompt"
	default:
		return "Config"
	}
}

func StaticResourceID(agentID, target, resourceType string) string {
	return "sr-" + stableHash(strings.Join([]string{
		CanonicalAgentID(agentID),
		CanonicalResourceType(resourceType),
		pathKey(target),
	}, "\x00"))[:24]
}

// CanonicalResourceType maps every historical resource-type spelling
// ("Skills", "MCP", "credential", "Configs" ...) onto the canonical
// singular lowercase form the rule-driven inventory writes ("skill",
// "mcp", ...). Older rows and the backfill path used capitalized or
// plural spellings; normalizing keeps one stable identity per resource.
func CanonicalResourceType(resourceType string) string {
	switch strings.ToLower(strings.TrimSpace(resourceType)) {
	case "skill", "skills":
		return "skill"
	case "mcp":
		return "mcp"
	case "plugin", "plugins":
		return "plugin"
	case "prompt", "prompts":
		return "prompt"
	case "credential", "credentials":
		return "credential"
	case "environment", "environments":
		return "environment"
	case "config", "configs":
		return "config"
	case "":
		return "config"
	default:
		return strings.ToLower(strings.TrimSpace(resourceType))
	}
}

func knownAgentIDFromHints(values ...string) string {
	combined := strings.ToLower(strings.Join(values, " "))
	checks := []struct {
		id      string
		markers []string
	}{
		{"agentrange-opspilot", []string{"agentrange-player", "agentrange", "ops-pilot", "opspilot"}},
		{"claude-code", []string{".claude", "claudecode", "claude-code", "anthropic claude", "anthropic-claude"}},
		{"codex", []string{".codex", "openai codex", "openai-codex", "codex"}},
		{"gemini-cli", []string{".gemini", "gemini-cli", "geminicli", "google gemini", "google-gemini"}},
		{"qoder", []string{"qoder"}},
		{"trae", []string{"trae"}},
		{"cherry-studio", []string{"cherrystudio", "cherry-studio", "cherry studio"}},
		{"cursor", []string{".cursor", "cursor"}},
		{"cline", []string{"cline", "claude-dev"}},
		{"roo-code", []string{"roo-code", "roo code", "roo-cline", "rooveterinaryinc"}},
		{"opencode", []string{"opencode", "open-code"}},
		{"aider", []string{"aider"}},
		{"openclaw", []string{"openclaw"}},
		{"system-environment", []string{"environment://", "env://", "system environment"}},
	}
	for _, check := range checks {
		for _, marker := range check.markers {
			if strings.Contains(combined, marker) {
				return check.id
			}
		}
	}
	return ""
}

func canonicalAgentProfiles() map[string]CanonicalAgentProfile {
	return map[string]CanonicalAgentProfile{
		"agentrange-opspilot": {ID: "agentrange-opspilot", DisplayName: "AgentRange / OpsPilot", Vendor: "TraceBastion Lab", Kind: "agent-platform", Runtime: "Agent Platform", Source: "agentrange"},
		"openclaw":            {ID: "openclaw", DisplayName: "OpenClaw", Vendor: "DefenseClaw", Kind: "agent-platform", Runtime: "Agent Platform", Source: "filesystem"},
		"claude-code":         {ID: "claude-code", DisplayName: "Claude Code", Vendor: "Anthropic", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "filesystem"},
		"codex":               {ID: "codex", DisplayName: "OpenAI Codex", Vendor: "OpenAI", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "filesystem"},
		"gemini-cli":          {ID: "gemini-cli", DisplayName: "Gemini CLI", Vendor: "Google", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "filesystem"},
		"aider":               {ID: "aider", DisplayName: "Aider", Vendor: "Aider", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "filesystem"},
		"opencode":            {ID: "opencode", DisplayName: "OpenCode", Vendor: "OpenCode", Kind: "terminal-agent", Runtime: "CLI Agent", Source: "filesystem"},
		"cursor":              {ID: "cursor", DisplayName: "Cursor", Vendor: "Anysphere", Kind: "editor-agent", Runtime: "IDE Agent", Source: "filesystem"},
		"cline":               {ID: "cline", DisplayName: "Cline", Vendor: "Cline", Kind: "editor-agent", Runtime: "IDE Agent", Source: "filesystem"},
		"roo-code":            {ID: "roo-code", DisplayName: "Roo Code", Vendor: "Roo Code", Kind: "editor-agent", Runtime: "IDE Agent", Source: "filesystem"},
		"qoder":               {ID: "qoder", DisplayName: "Qoder", Vendor: "Qoder", Kind: "ide-agent", Runtime: "IDE Agent", Source: "filesystem"},
		"trae":                {ID: "trae", DisplayName: "Trae", Vendor: "ByteDance", Kind: "desktop-agent", Runtime: "Desktop Agent", Source: "filesystem"},
		"cherry-studio":       {ID: "cherry-studio", DisplayName: "Cherry Studio", Vendor: "Cherry Studio", Kind: "desktop-agent", Runtime: "Desktop Agent", Source: "filesystem"},
		"system-environment":  {ID: "system-environment", DisplayName: "System Environment", Vendor: "Windows", Kind: "runtime", Runtime: "Windows Runtime", Source: "process environment"},
	}
}

type agentAlias struct {
	key  string
	raw  string
	kind string
}

func canonicalAgentAliases(agentID string, in AgentIdentityInput) []agentAlias {
	raw := []struct {
		kind, value string
	}{
		{"agent_id", in.AgentID},
		{"agent_name", in.AgentName},
		{"connector", in.Connector},
		{"scanner", in.Scanner},
		{"target", in.Target},
	}
	if agentID != "" {
		raw = append(raw, struct {
			kind, value string
		}{"canonical_agent_id", agentID})
	}
	seen := map[string]bool{}
	out := []agentAlias{}
	for _, item := range raw {
		value := strings.TrimSpace(item.value)
		if value == "" {
			continue
		}
		key := aliasKey(item.kind, value)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, agentAlias{key: key, raw: value, kind: item.kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key < out[j].key })
	return out
}

func aliasKey(kind, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch kind {
	case "target":
		return "target:" + stableHash(pathKey(value))[:24]
	default:
		id := CanonicalAgentID(value)
		if id == "" {
			id = stableID(value)
		}
		if id == "" {
			return ""
		}
		return kind + ":" + id
	}
}

func stableID(value string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.TrimSpace(value) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			dash = false
		} else if !dash {
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(strings.ToLower(b.String()), "-")
}

func stableHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func pathKey(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.Contains(path, "://") {
		return strings.ToLower(path)
	}
	path = TrimExtendedPathPrefix(path)
	if abs, err := filepath.Abs(path); err == nil {
		return strings.ToLower(filepath.Clean(abs))
	}
	return strings.ToLower(filepath.Clean(path))
}

// TrimExtendedPathPrefix strips the Windows extended-length path prefix so
// the same on-disk location yields one identity regardless of which code
// path produced the path ("\\?\C:\a\b" → "C:\a\b",
// "\\?\UNC\server\share" → "\\server\share").
func TrimExtendedPathPrefix(path string) string {
	if strings.HasPrefix(path, `\\?\UNC\`) {
		return `\\` + strings.TrimPrefix(path, `\\?\UNC\`)
	}
	if strings.HasPrefix(path, `\\?\`) {
		return strings.TrimPrefix(path, `\\?\`)
	}
	return path
}

func staticResourceName(target, resourceType string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return firstNonEmpty(resourceType, "static resource")
	}
	if strings.Contains(target, "://") {
		parts := strings.FieldsFunc(target, func(r rune) bool { return r == '/' || r == '#' || r == ':' })
		for i := len(parts) - 1; i >= 0; i-- {
			if strings.TrimSpace(parts[i]) != "" {
				return parts[i]
			}
		}
		return target
	}
	if base := filepath.Base(target); base != "" && base != "." {
		return base
	}
	return target
}

func staticResourceStatus(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "high", "error":
		return "needs_review"
	case "medium", "warning", "warn":
		return "review"
	default:
		return "discovered"
	}
}

func runtimeLabel(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "terminal-agent", "cli-agent":
		return "CLI Agent"
	case "editor-agent", "ide-agent":
		return "IDE Agent"
	case "desktop-agent":
		return "Desktop Agent"
	case "agent-platform":
		return "Agent Platform"
	case "":
		return "Agent"
	default:
		return kind
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
