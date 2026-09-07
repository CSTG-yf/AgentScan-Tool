// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"sort"
	"strings"
)

// RuntimeDetectionAgentTypeSummary is the per-AgentType aggregate used by
// the runtime anomaly-detection page. TotalEvents counts persisted detection
// rows, while RiskCounts is built from the severity values actually stored in
// runtime_detections. A missing severity is represented by the explicit
// "unknown" bucket so the risk counts still add up to TotalEvents.
type RuntimeDetectionAgentTypeSummary struct {
	AgentTypeID   int64          `json:"agent_type_id"`
	AgentType     string         `json:"agent_type"`
	AgentTypeKey  string         `json:"agent_type_key,omitempty"`
	AgentTypeName string         `json:"agent_type_name,omitempty"`
	TotalEvents   int            `json:"total_events"`
	AttackEvents  int            `json:"attack_events"`
	RiskCounts    map[string]int `json:"risk_counts"`
	BlockedEvents int            `json:"blocked_events,omitempty"`
	OpenEvents    int            `json:"open_events,omitempty"`
	LatestAt      string         `json:"latest_at,omitempty"`
}

// RuntimeAttackChainAgentTypeSummary is the per-AgentType aggregate used by
// the attack-chain page. StatusCounts and SeverityCounts are dynamic maps so
// new backend status/severity values remain visible without a frontend enum.
// RuntimeAttackChainAgentSummary counts matching chains for one persisted identity.
// It is independent of list pagination and keeps same-name instances separate.
type RuntimeAttackChainAgentSummary struct {
	AgentID     string `json:"agent_id"`
	TotalChains int    `json:"total_chains"`
	HighOrAbove int    `json:"high_or_above"`
}

type RuntimeAttackChainAgentTypeSummary struct {
	CoveredAgents   int                              `json:"covered_agents"`
	Agents          []RuntimeAttackChainAgentSummary `json:"agents"`
	AgentTypeID     int64                            `json:"agent_type_id"`
	AgentType       string                           `json:"agent_type"`
	AgentTypeKey    string                           `json:"agent_type_key,omitempty"`
	AgentTypeName   string                           `json:"agent_type_name,omitempty"`
	TotalChains     int                              `json:"total_chains"`
	StatusCounts    map[string]int                   `json:"status_counts"`
	SeverityCounts  map[string]int                   `json:"severity_counts"`
	ActiveChains    int                              `json:"active_chains,omitempty"`
	ContainedChains int                              `json:"contained_chains,omitempty"`
	LatestAt        string                           `json:"latest_at,omitempty"`
}

type runtimeAgentTypeSummaryKey struct {
	ID   int64
	Type string
	Key  string
	Name string
}

// ListRuntimeDetectionAgentTypeSummaries returns one row per AgentType that
// has at least one detection matching f. All non-pagination fields in f are
// applied in SQL, including the existing AgentTypeID, keyword and time
// filters. Limit and Offset are intentionally ignored because this endpoint
// returns the complete set of type buckets.
func (s *Store) ListRuntimeDetectionAgentTypeSummaries(f RuntimeDetectionFilter) ([]RuntimeDetectionAgentTypeSummary, error) {
	if s == nil || s.db == nil {
		return []RuntimeDetectionAgentTypeSummary{}, nil
	}
	where, args := runtimeDetectionWhereClause(f)
	rows, err := s.queryDB(context.Background(), "runtime_detection_agent_type_summary", `
SELECT
       COALESCE(a.agent_type_id, 0),
       COALESCE(NULLIF(TRIM(t.type_key), ''), NULLIF(TRIM(t.name), ''), NULLIF(TRIM(a.kind), ''), 'unknown'),
       COALESCE(TRIM(t.type_key), ''),
       COALESCE(TRIM(t.name), ''),
       COALESCE(NULLIF(LOWER(TRIM(d.severity)), ''), 'unknown'),
       COUNT(*),
       COALESCE(SUM(CASE WHEN LOWER(TRIM(COALESCE(d.category, ''))) = 'attack' THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN LOWER(TRIM(COALESCE(d.status, ''))) IN ('blocked', 'mitigated') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN LOWER(TRIM(COALESCE(d.status, ''))) = 'open' THEN 1 ELSE 0 END), 0),
       COALESCE(MAX(d.last_seen_at), '')
FROM (
       SELECT agent_id, category, severity, status, last_seen_at
       FROM runtime_detections
       `+where+`
) d
LEFT JOIN agents a
       ON a.id = d.agent_id AND COALESCE(a."delete", 0) = 0
LEFT JOIN agent_types t
       ON t.id = a.agent_type_id AND COALESCE(t."delete", 0) = 0
GROUP BY
       COALESCE(a.agent_type_id, 0),
       COALESCE(NULLIF(TRIM(t.type_key), ''), NULLIF(TRIM(t.name), ''), NULLIF(TRIM(a.kind), ''), 'unknown'),
       COALESCE(TRIM(t.type_key), ''),
       COALESCE(TRIM(t.name), ''),
       COALESCE(NULLIF(LOWER(TRIM(d.severity)), ''), 'unknown')
ORDER BY 2 ASC, 1 ASC, 5 ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[runtimeAgentTypeSummaryKey]*RuntimeDetectionAgentTypeSummary)
	for rows.Next() {
		var (
			key                          runtimeAgentTypeSummaryKey
			risk                         string
			count, attack, blocked, open int
			latest                       string
		)
		if err := rows.Scan(
			&key.ID, &key.Type, &key.Key, &key.Name, &risk,
			&count, &attack, &blocked, &open, &latest,
		); err != nil {
			return nil, err
		}
		key.Type = summaryAgentTypeValue(key.Type)
		risk = summaryBucketValue(risk)
		item := byType[key]
		if item == nil {
			item = &RuntimeDetectionAgentTypeSummary{
				AgentTypeID:   key.ID,
				AgentType:     key.Type,
				AgentTypeKey:  strings.TrimSpace(key.Key),
				AgentTypeName: strings.TrimSpace(key.Name),
				RiskCounts:    map[string]int{},
			}
			byType[key] = item
		}
		// COUNT(*) is repeated for each risk-level row. Add the per-risk
		// count instead of adding the repeated total.
		item.TotalEvents += count
		item.AttackEvents += attack
		item.RiskCounts[risk] += count
		item.BlockedEvents += blocked
		item.OpenEvents += open
		if latest > item.LatestAt {
			item.LatestAt = latest
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RuntimeDetectionAgentTypeSummary, 0, len(byType))
	for _, item := range byType {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalEvents != out[j].TotalEvents {
			return out[i].TotalEvents > out[j].TotalEvents
		}
		if strings.ToLower(out[i].AgentType) != strings.ToLower(out[j].AgentType) {
			return strings.ToLower(out[i].AgentType) < strings.ToLower(out[j].AgentType)
		}
		return out[i].AgentTypeID < out[j].AgentTypeID
	})
	return out, nil
}

// ListRuntimeAttackChainAgentTypeSummaries returns one row per AgentType that
// has at least one attack chain matching f. The query is fully database-backed
// and ignores only pagination fields, which have no meaning for type buckets.
func (s *Store) ListRuntimeAttackChainAgentTypeSummaries(f AttackChainFilter) ([]RuntimeAttackChainAgentTypeSummary, error) {
	if s == nil || s.db == nil {
		return []RuntimeAttackChainAgentTypeSummary{}, nil
	}
	where, args := runtimeAttackChainWhereClause(f)
	rows, err := s.queryDB(context.Background(), "runtime_attack_chain_agent_type_summary", `
SELECT
       COALESCE(a.agent_type_id, 0),
       COALESCE(NULLIF(TRIM(t.type_key), ''), NULLIF(TRIM(t.name), ''), NULLIF(TRIM(a.kind), ''), 'unknown'),
       COALESCE(TRIM(t.type_key), ''),
       COALESCE(TRIM(t.name), ''),
       COALESCE(NULLIF(LOWER(TRIM(d.status)), ''), 'unknown'),
       COALESCE(NULLIF(LOWER(TRIM(d.severity)), ''), 'unknown'),
       COUNT(*),
       COALESCE(MAX(d.end_time), ''),
       COALESCE(d.agent_id, '')
FROM (
       SELECT agent_id, status, severity, end_time
       FROM runtime_attack_chains
       `+where+`
) d
LEFT JOIN agents a
       ON a.id = d.agent_id AND COALESCE(a."delete", 0) = 0
LEFT JOIN agent_types t
       ON t.id = a.agent_type_id AND COALESCE(t."delete", 0) = 0
GROUP BY
       COALESCE(a.agent_type_id, 0),
       COALESCE(NULLIF(TRIM(t.type_key), ''), NULLIF(TRIM(t.name), ''), NULLIF(TRIM(a.kind), ''), 'unknown'),
       COALESCE(TRIM(t.type_key), ''),
       COALESCE(TRIM(t.name), ''),
       COALESCE(NULLIF(LOWER(TRIM(d.status)), ''), 'unknown'),
       COALESCE(NULLIF(LOWER(TRIM(d.severity)), ''), 'unknown'),
       COALESCE(d.agent_id, '')
ORDER BY 2 ASC, 1 ASC, 5 ASC, 6 ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byType := make(map[runtimeAgentTypeSummaryKey]*RuntimeAttackChainAgentTypeSummary)
	byAgent := make(map[runtimeAgentTypeSummaryKey]map[string]*RuntimeAttackChainAgentSummary)
	for rows.Next() {
		var (
			key             runtimeAgentTypeSummaryKey
			status, risk    string
			count           int
			latest, agentID string
		)
		if err := rows.Scan(
			&key.ID, &key.Type, &key.Key, &key.Name,
			&status, &risk, &count, &latest, &agentID,
		); err != nil {
			return nil, err
		}
		key.Type = summaryAgentTypeValue(key.Type)
		status = summaryBucketValue(status)
		risk = summaryBucketValue(risk)
		item := byType[key]
		if item == nil {
			item = &RuntimeAttackChainAgentTypeSummary{
				AgentTypeID:    key.ID,
				AgentType:      key.Type,
				AgentTypeKey:   strings.TrimSpace(key.Key),
				AgentTypeName:  strings.TrimSpace(key.Name),
				StatusCounts:   map[string]int{},
				SeverityCounts: map[string]int{},
			}
			byType[key] = item
			byAgent[key] = make(map[string]*RuntimeAttackChainAgentSummary)
		}
		if strings.TrimSpace(agentID) != "" {
			agent := byAgent[key][agentID]
			if agent == nil {
				agent = &RuntimeAttackChainAgentSummary{AgentID: agentID}
				byAgent[key][agentID] = agent
			}
			agent.TotalChains += count
			if risk == "high" || risk == "critical" {
				agent.HighOrAbove += count
			}
		}
		item.TotalChains += count
		item.StatusCounts[status] += count
		item.SeverityCounts[risk] += count
		switch status {
		case AttackChainStatusActive:
			item.ActiveChains += count
		case AttackChainStatusContained:
			item.ContainedChains += count
		}
		if latest > item.LatestAt {
			item.LatestAt = latest
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]RuntimeAttackChainAgentTypeSummary, 0, len(byType))
	for key, item := range byType {
		item.Agents = make([]RuntimeAttackChainAgentSummary, 0, len(byAgent[key]))
		for _, agent := range byAgent[key] {
			item.Agents = append(item.Agents, *agent)
		}
		sort.Slice(item.Agents, func(i, j int) bool { return item.Agents[i].AgentID < item.Agents[j].AgentID })
		item.CoveredAgents = len(item.Agents)
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TotalChains != out[j].TotalChains {
			return out[i].TotalChains > out[j].TotalChains
		}
		if strings.ToLower(out[i].AgentType) != strings.ToLower(out[j].AgentType) {
			return strings.ToLower(out[i].AgentType) < strings.ToLower(out[j].AgentType)
		}
		return out[i].AgentTypeID < out[j].AgentTypeID
	})
	return out, nil
}

func summaryAgentTypeValue(value string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return "unknown"
}

func summaryBucketValue(value string) string {
	if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
		return value
	}
	return "unknown"
}
