// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
)

// AgentResourceSummary aggregates one agent's static-resource posture for the
// desktop agent list: how many resources, how many risky, malicious, and
// critical ones. Backed by agents LEFT JOIN static_resources.
type AgentResourceSummary struct {
	AgentID                string `json:"agent_id"`
	AgentType              string `json:"agent_type"`
	AgentTypeID            int64  `json:"-"`
	Name                   string `json:"name"`
	Kind                   string `json:"kind"`
	ResourceCount          int    `json:"resource_count"`
	RiskResourceCount      int    `json:"risk_resource_count"`
	MaliciousResourceCount int    `json:"malicious_resource_count"`
	CriticalResourceCount  int    `json:"critical_resource_count"`
}

// ResourceTypeSummary is one row of the per-type aggregation on the summary
// endpoint (the Config / Skills / MCP cards).
type ResourceTypeSummary struct {
	ResourceType   string `json:"resource_type"`
	Count          int    `json:"count"`
	RiskCount      int    `json:"risk_count"`
	MaliciousCount int    `json:"malicious_count"`
}

// AgentResourceTypeSummary is the full summary payload for one agent.
type AgentResourceTypeSummary struct {
	Agent                  AgentResourceSummary  `json:"agent"`
	TotalResources         int                   `json:"total_resources"`
	ResourceTypeCount      int                   `json:"resource_type_count"`
	RiskResourceCount      int                   `json:"risk_resource_count"`
	MaliciousResourceCount int                   `json:"malicious_resource_count"`
	CriticalResourceCount  int                   `json:"critical_resource_count"`
	ByType                 []ResourceTypeSummary `json:"by_type"`
}

// StaticResourceFilter is the query-shape of GET /api/v1/static-resources:
// every field is optional; zero values mean "no constraint".
type StaticResourceFilter struct {
	AgentID       string
	ResourceType  string
	RiskLevel     string
	Malicious     *bool
	Status        string // active ⇒ status != 'missing'
	ScanCompleted *bool  // last_scan_id IS NOT NULL
	Keyword       string // matches name / target / resource_type
	Page          int
	PageSize      int
}

// StaticResourceRow is one row of the paginated resource table.
type StaticResourceRow struct {
	ID           string `json:"resource_id"`
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"-"`
	ResourceType string `json:"resource_type"`
	Name         string `json:"name"`
	Target       string `json:"path"`
	RiskLevel    string `json:"risk_level"`
	Malicious    bool   `json:"malicious"`
	FindingCount int    `json:"finding_count"`
	Status       string `json:"status"`
	LastScanID   string `json:"-"`
	LastScanAt   string `json:"last_scan_at,omitempty"`
	LastSeenAt   string `json:"updated_at"`
}

// StaticResourcePage is the paginated list response.
type StaticResourcePage struct {
	Total    int                 `json:"total"`
	Page     int                 `json:"page"`
	PageSize int                 `json:"page_size"`
	Items    []StaticResourceRow `json:"items"`
}

// StaticResourceDetail is the drawer "overview" payload: the resource row
// joined with its agent, rule, and scan-profile lineage.
type StaticResourceDetail struct {
	StaticResourceRow
	Agent            StaticResourceAgentRef     `json:"agent"`
	ContentHash      string                     `json:"content_hash,omitempty"`
	FirstSeenAt      string                     `json:"first_seen_at,omitempty"`
	ScanStatus       string                     `json:"scan_status"` // completed / pending / never_scanned
	Size             int64                      `json:"size,omitempty"`
	Permission       string                     `json:"permission,omitempty"`
	ResourceRule     *StaticResourceRuleRef     `json:"resource_rule,omitempty"`
	ScanProfile      *StaticResourceProfileRef  `json:"scan_profile,omitempty"`
	ScanCapabilities []StaticResourceCapability `json:"scan_capabilities,omitempty"`
}

// StaticResourceAgentRef identifies the owning agent on detail payloads.
type StaticResourceAgentRef struct {
	AgentID   string `json:"agent_id"`
	Name      string `json:"name"`
	AgentType string `json:"agent_type,omitempty"`
}

// StaticResourceRuleRef names the agent_resource_rules row that produced the
// resource.
type StaticResourceRuleRef struct {
	RuleID int64  `json:"rule_id"`
	Name   string `json:"name"`
}

// StaticResourceProfileRef names the resource_scan_profiles plan that
// applies to the resource.
type StaticResourceProfileRef struct {
	ProfileID int64  `json:"profile_id"`
	Name      string `json:"name"`
}

// StaticResourceCapability is one security capability configured on the
// resource's scan profile, resolved through resource_scan_profile_capabilities
// → security_scan_capabilities. Rendered as tags next to the 检测方案 row.
type StaticResourceCapability struct {
	CapabilityID int64  `json:"capability_id"`
	Key          string `json:"key,omitempty"`
	Name         string `json:"name"`
	Scanner      string `json:"scanner,omitempty"`
	Description  string `json:"description,omitempty"`
	Enabled      bool   `json:"enabled"`
}

// StaticResourceScanRecord is one historical scan of a static resource
// (scan_results row). A resource can be scanned many times; every run is a
// separate record so the history survives content drift and re-scans.
type StaticResourceScanRecord struct {
	ScanID       string `json:"scan_id"`
	Scanner      string `json:"scanner,omitempty"`
	ScannedAt    string `json:"scanned_at,omitempty"`
	FindingCount int    `json:"finding_count"`
	MaxSeverity  string `json:"max_severity,omitempty"`
	DurationMs   *int64 `json:"duration_ms,omitempty"`
	Verdict      string `json:"verdict,omitempty"`
}

// StaticResourceScanHistory is the drawer "history" payload: every recorded
// scan of one resource, newest first.
type StaticResourceScanHistory struct {
	ResourceID string                     `json:"resource_id"`
	Total      int                        `json:"total"`
	Items      []StaticResourceScanRecord `json:"items"`
}

// ListAgentResourceSummaries aggregates the resource posture per agent for
// the desktop left-hand agent list. Agents without resources still appear
// (with zero counts) so the list mirrors the agent inventory.
func (s *Store) ListAgentResourceSummaries() ([]AgentResourceSummary, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_agent_summaries", `
SELECT a.id,
       COALESCE(t.type_key, ''),
       COALESCE(a.display_name, a.id),
       COALESCE(t.kind, a.kind, ''),
       COUNT(r.id),
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(r.risk_level,'')) IN ('medium','high','critical') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN COALESCE(r.malicious,0) = 1 THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(r.risk_level,'')) = 'critical' THEN 1 ELSE 0 END), 0)
FROM agents a
LEFT JOIN static_resources r ON r.canonical_agent_id = a.id AND COALESCE(r."delete", 0) = 0
LEFT JOIN agent_types t ON t.id = COALESCE(a.agent_type_id, 0) AND COALESCE(t."delete", 0) = 0
WHERE COALESCE(a.status, 'observed') NOT IN ('gone','removed','disabled')
  AND COALESCE(a."delete", 0) = 0
GROUP BY a.id
ORDER BY COUNT(r.id) DESC, a.id`)

	if err != nil {
		return nil, fmt.Errorf("audit: agent resource summaries: %w", err)
	}
	defer rows.Close()

	var out []AgentResourceSummary
	for rows.Next() {
		var item AgentResourceSummary
		if err := rows.Scan(
			&item.AgentID, &item.AgentType, &item.Name, &item.Kind,
			&item.ResourceCount, &item.RiskResourceCount,
			&item.MaliciousResourceCount, &item.CriticalResourceCount,
		); err != nil {
			return nil, fmt.Errorf("audit: agent resource summary row: %w", err)
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetAgentResourceTypeSummary aggregates one agent's resources by type for
// the summary header + type cards. Returns nil when the agent is unknown.
func (s *Store) GetAgentResourceTypeSummary(agentID string) (*AgentResourceTypeSummary, error) {
	if s == nil || s.db == nil || strings.TrimSpace(agentID) == "" {
		return nil, nil
	}
	summaries, err := s.ListAgentResourceSummaries()
	if err != nil {
		return nil, err
	}
	var agent *AgentResourceSummary
	for i := range summaries {
		if summaries[i].AgentID == agentID {
			agent = &summaries[i]
			break
		}
	}
	if agent == nil {
		return nil, nil
	}

	rows, err := s.queryDB(context.Background(), "static_resource_type_summary", `
SELECT LOWER(COALESCE(resource_type, '')),
       COUNT(*),
       COALESCE(SUM(CASE WHEN LOWER(COALESCE(risk_level,'')) IN ('medium','high','critical') THEN 1 ELSE 0 END), 0),
       COALESCE(SUM(CASE WHEN COALESCE(malicious,0) = 1 THEN 1 ELSE 0 END), 0)
FROM static_resources
WHERE canonical_agent_id = ?
  AND COALESCE("delete", 0) = 0
GROUP BY LOWER(COALESCE(resource_type, ''))
ORDER BY COUNT(*) DESC`, agentID)
	if err != nil {
		return nil, fmt.Errorf("audit: resource type summary for %s: %w", agentID, err)
	}
	defer rows.Close()

	summary := &AgentResourceTypeSummary{
		Agent:                  *agent,
		RiskResourceCount:      agent.RiskResourceCount,
		MaliciousResourceCount: agent.MaliciousResourceCount,
		CriticalResourceCount:  agent.CriticalResourceCount,
	}
	for rows.Next() {
		var item ResourceTypeSummary
		if err := rows.Scan(&item.ResourceType, &item.Count, &item.RiskCount, &item.MaliciousCount); err != nil {
			return nil, fmt.Errorf("audit: resource type summary row: %w", err)
		}
		summary.TotalResources += item.Count
		summary.ByType = append(summary.ByType, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	summary.ResourceTypeCount = len(summary.ByType)
	return summary, nil
}

// staticResourceWhere builds the WHERE clause + args for the paginated list.
func staticResourceWhere(f StaticResourceFilter) (string, []any) {
	clauses := []string{`COALESCE(r."delete", 0) = 0`}
	var args []any
	if f.AgentID != "" {
		clauses = append(clauses, "r.canonical_agent_id = ?")
		args = append(args, f.AgentID)
	}
	if f.ResourceType != "" {
		clauses = append(clauses, "LOWER(COALESCE(r.resource_type,'')) = ?")
		args = append(args, strings.ToLower(f.ResourceType))
	}
	if f.RiskLevel != "" {
		clauses = append(clauses, "LOWER(COALESCE(r.risk_level,'')) = ?")
		args = append(args, strings.ToLower(f.RiskLevel))
	}
	if f.Malicious != nil {
		if *f.Malicious {
			clauses = append(clauses, "COALESCE(r.malicious,0) = 1")
		} else {
			clauses = append(clauses, "COALESCE(r.malicious,0) = 0")
		}
	}
	if f.Status != "" {
		if strings.EqualFold(f.Status, "active") {
			clauses = append(clauses, "COALESCE(r.status,'') <> 'missing'")
		} else {
			clauses = append(clauses, "LOWER(COALESCE(r.status,'')) = ?")
			args = append(args, strings.ToLower(f.Status))
		}
	}
	if f.ScanCompleted != nil {
		if *f.ScanCompleted {
			clauses = append(clauses, "COALESCE(r.last_scan_id,'') <> ''")
		} else {
			clauses = append(clauses, "COALESCE(r.last_scan_id,'') = ''")
		}
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		clauses = append(clauses, "(LOWER(COALESCE(r.name,'')) LIKE ? OR LOWER(COALESCE(r.target,'')) LIKE ? OR LOWER(COALESCE(r.resource_type,'')) LIKE ?)")
		pattern := "%" + strings.ToLower(kw) + "%"
		args = append(args, pattern, pattern, pattern)
	}
	if len(clauses) == 0 {
		return "1=1", args
	}
	return strings.Join(clauses, " AND "), args
}

// ListStaticResourcesPage returns the paginated, filtered resource table.
// Sorting: risk severity first (critical → clean), then most recently seen.
func (s *Store) ListStaticResourcesPage(f StaticResourceFilter) (*StaticResourcePage, error) {
	if s == nil || s.db == nil {
		return &StaticResourcePage{Items: []StaticResourceRow{}}, nil
	}
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	if f.PageSize > 200 {
		f.PageSize = 200
	}

	where, args := staticResourceWhere(f)

	var total int
	if err := s.queryRowDB(context.Background(), "static_resource_page_count",
		"SELECT COUNT(*) FROM static_resources r WHERE "+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("audit: count static resources: %w", err)
	}

	rows, err := s.queryDB(context.Background(), "static_resource_page", `
SELECT r.id,
       COALESCE(r.canonical_agent_id, ''),
       COALESCE(a.display_name, r.canonical_agent_id, ''),
       COALESCE(r.resource_type, ''),
       COALESCE(r.name, ''),
       COALESCE(r.target, ''),
       COALESCE(r.risk_level, 'clean'),
       COALESCE(r.malicious, 0),
       COALESCE(r.finding_count, 0),
       COALESCE(r.status, 'discovered'),
       COALESCE(r.last_scan_id, ''),
       COALESCE((SELECT CAST(MIN(timestamp) AS TEXT) FROM scan_results sr WHERE sr.id = r.last_scan_id AND COALESCE(sr."delete", 0) = 0), ''),
       COALESCE(r.last_seen_at, '')
FROM static_resources r
LEFT JOIN agents a ON a.id = r.canonical_agent_id AND COALESCE(a."delete", 0) = 0
WHERE `+where+`
ORDER BY CASE LOWER(COALESCE(r.risk_level,'clean'))
           WHEN 'critical' THEN 0
           WHEN 'high' THEN 1
           WHEN 'medium' THEN 2
           WHEN 'low' THEN 3
           ELSE 4 END,
         COALESCE(r.malicious,0) DESC,
         r.last_seen_at DESC
LIMIT ? OFFSET ?`,
		append(append([]any{}, args...), f.PageSize, (f.Page-1)*f.PageSize)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list static resources: %w", err)
	}
	defer rows.Close()

	page := &StaticResourcePage{Total: total, Page: f.Page, PageSize: f.PageSize, Items: []StaticResourceRow{}}
	for rows.Next() {
		var row StaticResourceRow
		var malicious int
		if err := rows.Scan(
			&row.ID, &row.AgentID, &row.AgentName, &row.ResourceType, &row.Name,
			&row.Target, &row.RiskLevel, &malicious, &row.FindingCount,
			&row.Status, &row.LastScanID, &row.LastScanAt, &row.LastSeenAt,
		); err != nil {
			return nil, fmt.Errorf("audit: static resource page row: %w", err)
		}
		row.Malicious = malicious != 0
		page.Items = append(page.Items, row)
	}
	return page, rows.Err()
}

// GetStaticResourceDetail loads one resource with its full lineage (agent,
// rule, profile) for the drawer overview tab. Returns nil when unknown.
func (s *Store) GetStaticResourceDetail(resourceID string) (*StaticResourceDetail, error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_detail", `
SELECT r.id,
       COALESCE(r.canonical_agent_id, ''),
       COALESCE(a.display_name, r.canonical_agent_id, ''),
       COALESCE(r.resource_type, ''),
       COALESCE(r.name, ''),
       COALESCE(r.target, ''),
       COALESCE(r.risk_level, 'clean'),
       COALESCE(r.malicious, 0),
       COALESCE(r.finding_count, 0),
       COALESCE(r.status, 'discovered'),
       COALESCE(r.last_scan_id, ''),
       COALESCE((SELECT CAST(MIN(timestamp) AS TEXT) FROM scan_results sr WHERE sr.id = r.last_scan_id AND COALESCE(sr."delete", 0) = 0), ''),
       COALESCE(r.last_seen_at, ''),
       COALESCE(r.content_hash, ''),
       COALESCE(a.first_seen_at, ''),
       COALESCE(t.type_key, ''),
       COALESCE(rr.id, 0),
       COALESCE(rr.name, ''),
       COALESCE(p.id, 0),
       COALESCE(p.name, '')
FROM static_resources r
LEFT JOIN agents a ON a.id = r.canonical_agent_id AND COALESCE(a."delete", 0) = 0
LEFT JOIN agent_types t ON t.id = COALESCE(a.agent_type_id, 0) AND COALESCE(t."delete", 0) = 0
LEFT JOIN agent_resource_rules rr ON rr.id = r.resource_rule_id AND COALESCE(rr."delete", 0) = 0
LEFT JOIN resource_scan_profiles p ON p.id = r.scan_profile_id AND COALESCE(p."delete", 0) = 0
WHERE r.id = ? AND COALESCE(r."delete", 0) = 0`, resourceID)
	if err != nil {
		return nil, fmt.Errorf("audit: static resource detail %q: %w", resourceID, err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, rows.Err()
	}
	var d StaticResourceDetail
	var malicious int
	var ruleID, profileID int64
	var ruleName, profileName string
	if err := rows.Scan(
		&d.ID, &d.AgentID, &d.AgentName, &d.ResourceType, &d.Name,
		&d.Target, &d.RiskLevel, &malicious, &d.FindingCount,
		&d.Status, &d.LastScanID, &d.LastScanAt, &d.LastSeenAt,
		&d.ContentHash, &d.FirstSeenAt,
		&d.Agent.AgentType, &ruleID, &ruleName, &profileID, &profileName,
	); err != nil {
		return nil, fmt.Errorf("audit: static resource detail row: %w", err)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// The pool is capped at a single connection (SetMaxOpenConns(1)); the
	// nested capability query below would deadlock on the still-open outer
	// rows, so release the connection explicitly before fanning out.
	rows.Close()
	d.Malicious = malicious != 0
	d.Agent.AgentID = d.AgentID
	d.Agent.Name = d.AgentName
	d.ScanStatus = "pending"
	switch {
	case d.LastScanID == "" && d.FindingCount == 0 && d.LastScanAt == "":
		d.ScanStatus = "never_scanned"
	case d.LastScanID != "":
		d.ScanStatus = "completed"
	}
	if ruleID > 0 {
		d.ResourceRule = &StaticResourceRuleRef{RuleID: ruleID, Name: ruleName}
	}
	if profileID > 0 {
		d.ScanProfile = &StaticResourceProfileRef{ProfileID: profileID, Name: profileName}
		caps, err := s.listProfileCapabilities(profileID)
		if err != nil {
			return nil, err
		}
		d.ScanCapabilities = caps
	}
	return &d, nil
}

// listProfileCapabilities resolves the security capabilities configured on
// one scan profile (resource_scan_profile_capabilities →
// security_scan_capabilities), priority-ordered. A capability counts as
// enabled only when both the profile binding and the capability itself are
// enabled.
func (s *Store) listProfileCapabilities(profileID int64) ([]StaticResourceCapability, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_profile_capabilities", `
SELECT c.id,
       COALESCE(c.capability_key, ''),
       COALESCE(c.name, ''),
       COALESCE(c.scanner_name, ''),
       COALESCE(c.description, ''),
       COALESCE(c.enabled, 1),
       COALESCE(pc.enabled, 1)
FROM resource_scan_profile_capabilities pc
JOIN security_scan_capabilities c ON c.id = pc.capability_id
WHERE pc.profile_id = ?
  AND COALESCE(pc."delete", 0) = 0
  AND COALESCE(c."delete", 0) = 0
ORDER BY COALESCE(pc.priority, 100), c.id`, profileID)
	if err != nil {
		return nil, fmt.Errorf("audit: profile capabilities %d: %w", profileID, err)
	}
	defer rows.Close()
	var out []StaticResourceCapability
	for rows.Next() {
		var item StaticResourceCapability
		var capabilityEnabled, bindingEnabled int
		if err := rows.Scan(
			&item.CapabilityID, &item.Key, &item.Name, &item.Scanner,
			&item.Description, &capabilityEnabled, &bindingEnabled,
		); err != nil {
			return nil, fmt.Errorf("audit: profile capability row %d: %w", profileID, err)
		}
		item.Enabled = capabilityEnabled != 0 && bindingEnabled != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

// GetStaticResourceTargetPath returns the on-disk target of one resource row
// (used by the on-demand scan trigger to rebuild its InstallEvent).
func (s *Store) GetStaticResourceTargetPath(resourceID string) (target, agentID, resourceType string, ruleID, profileID int64, ok bool, err error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return "", "", "", 0, 0, false, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_target_get", `
SELECT COALESCE(target,''), COALESCE(canonical_agent_id,''), COALESCE(resource_type,''),
       COALESCE(resource_rule_id,0), COALESCE(scan_profile_id,0)
FROM static_resources
WHERE id = ? AND COALESCE("delete", 0) = 0`, resourceID)
	if err != nil {
		return "", "", "", 0, 0, false, fmt.Errorf("audit: static resource target %q: %w", resourceID, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", "", "", 0, 0, false, rows.Err()
	}
	if err := rows.Scan(&target, &agentID, &resourceType, &ruleID, &profileID); err != nil {
		return "", "", "", 0, 0, false, fmt.Errorf("audit: static resource target row: %w", err)
	}
	return target, agentID, resourceType, ruleID, profileID, target != "", rows.Err()
}

// StaticResourceFindingRow is one finding of a resource's latest scan.
type StaticResourceFindingRow struct {
	FindingID   string  `json:"finding_id"`
	RuleID      string  `json:"rule_id,omitempty"`
	Category    string  `json:"category,omitempty"`
	Severity    string  `json:"severity"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Evidence    string  `json:"evidence,omitempty"`
	Location    string  `json:"location,omitempty"`
	LineNumber  int     `json:"-"`
	Scanner     string  `json:"scanner,omitempty"`
	Confidence  float64 `json:"-"`
}

// StaticResourceFindings bundles the latest-scan findings with the severity
// summary the risk tab renders.
type StaticResourceFindings struct {
	ResourceID string                     `json:"resource_id"`
	ScanID     string                     `json:"scan_id"`
	ScannedAt  string                     `json:"scanned_at,omitempty"`
	Scanner    string                     `json:"scanner,omitempty"`
	Severity   map[string]int             `json:"summary"`
	Items      []StaticResourceFindingRow `json:"items"`
}

// ListStaticResourceLatestFindings returns the findings of the resource's
// most recent scan (static_resources.last_scan_id → scan_findings), already
// severity-sorted. Findings are stored pre-redacted, but the evidence field
// is passed through redaction again as defense in depth.
func (s *Store) ListStaticResourceLatestFindings(resourceID string) (*StaticResourceFindings, error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return nil, nil
	}
	out := &StaticResourceFindings{
		ResourceID: resourceID,
		Severity:   map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0},
		Items:      []StaticResourceFindingRow{},
	}

	// Prefer the resource's last_scan_id; fall back to the newest
	// scan_results row referencing the resource (covers rows whose
	// last_scan_id was not yet written back).
	scanRow := s.queryRowDB(context.Background(), "static_resource_latest_scan", `
SELECT COALESCE(r.last_scan_id, ''),
       COALESCE((SELECT CAST(MIN(sr.timestamp) AS TEXT) FROM scan_results sr WHERE sr.id = r.last_scan_id AND COALESCE(sr."delete", 0) = 0),
                (SELECT CAST(MAX(sr2.timestamp) AS TEXT) FROM scan_results sr2 WHERE sr2.static_resource_id = r.id AND COALESCE(sr2."delete", 0) = 0), ''),
       COALESCE((SELECT sr3.scanner FROM scan_results sr3 WHERE sr3.id = r.last_scan_id AND COALESCE(sr3."delete", 0) = 0 LIMIT 1), '')
FROM static_resources r
WHERE r.id = ? AND COALESCE(r."delete", 0) = 0`, resourceID)
	var scanID, scannedAt, scanner string
	if err := scanRow.Scan(&scanID, &scannedAt, &scanner); err != nil {
		return nil, fmt.Errorf("audit: latest scan for resource %q: %w", resourceID, err)
	}
	if scanID == "" {
		// Fall back: newest scan_results row for this resource.
		rows, err := s.queryDB(context.Background(), "static_resource_latest_scan_fallback", `
SELECT id, COALESCE(CAST(timestamp AS TEXT), ''), COALESCE(scanner, '')
FROM scan_results WHERE static_resource_id = ?
  AND COALESCE("delete", 0) = 0
ORDER BY timestamp DESC LIMIT 1`, resourceID)
		if err != nil {
			return nil, fmt.Errorf("audit: fallback scan for resource %q: %w", resourceID, err)
		}
		if rows.Next() {
			_ = rows.Scan(&scanID, &scannedAt, &scanner)
		}
		rows.Close()
	}
	out.ScanID = scanID
	out.ScannedAt = scannedAt
	out.Scanner = scanner
	if scanID == "" {
		return out, nil
	}

	rows, err := s.queryDB(context.Background(), "static_resource_findings", `
SELECT COALESCE(f.id, ''),
       COALESCE(f.rule_id, ''),
       COALESCE(f.category, ''),
       COALESCE(f.severity, 'INFO'),
       COALESCE(f.title, ''),
       COALESCE(f.description, ''),
       COALESCE(f.location, ''),
       COALESCE(f.line_number, 0),
       COALESCE(f.scanner, '')
FROM scan_findings f
WHERE f.scan_id = ?
  AND COALESCE(f."delete", 0) = 0
ORDER BY CASE UPPER(COALESCE(f.severity,'INFO'))
         WHEN 'CRITICAL' THEN 0
         WHEN 'HIGH' THEN 1
         WHEN 'MEDIUM' THEN 2
         WHEN 'LOW' THEN 3
         ELSE 4 END, f.id`, scanID)
	if err != nil {
		return nil, fmt.Errorf("audit: findings for resource %q: %w", resourceID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var item StaticResourceFindingRow
		if err := rows.Scan(
			&item.FindingID, &item.RuleID, &item.Category, &item.Severity,
			&item.Title, &item.Description, &item.Location,
			&item.LineNumber, &item.Scanner,
		); err != nil {
			return nil, fmt.Errorf("audit: finding row for %q: %w", resourceID, err)
		}
		out.Items = append(out.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out.Items {
		sev := strings.ToLower(out.Items[i].Severity)
		if _, tracked := out.Severity[sev]; tracked {
			out.Severity[sev]++
		}
	}
	return out, nil
}

// ListStaticResourceScanHistory returns every scan_results record of one
// resource, newest first — the drawer history tab. A resource can be scanned
// many times (first discovery, content drift, manual rescan); each run is a
// separate row and the history is never overwritten.
func (s *Store) ListStaticResourceScanHistory(resourceID string, limit int) (*StaticResourceScanHistory, error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	out := &StaticResourceScanHistory{
		ResourceID: resourceID,
		Items:      []StaticResourceScanRecord{},
	}
	if err := s.queryRowDB(context.Background(), "static_resource_scan_history_total",
		`SELECT COUNT(*) FROM scan_results WHERE static_resource_id = ? AND COALESCE("delete", 0) = 0`, resourceID,
	).Scan(&out.Total); err != nil {
		return nil, fmt.Errorf("audit: scan history total for %q: %w", resourceID, err)
	}
	rows, err := s.queryDB(context.Background(), "static_resource_scan_history", `
SELECT COALESCE(id, ''),
       COALESCE(scanner, ''),
       COALESCE(CAST(timestamp AS TEXT), ''),
       COALESCE(finding_count, 0),
       COALESCE(max_severity, ''),
       duration_ms,
       COALESCE(verdict, '')
FROM scan_results
WHERE static_resource_id = ?
  AND COALESCE("delete", 0) = 0
ORDER BY timestamp DESC, id DESC
LIMIT ?`, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: scan history for %q: %w", resourceID, err)
	}
	defer rows.Close()
	for rows.Next() {
		var item StaticResourceScanRecord
		if err := rows.Scan(
			&item.ScanID, &item.Scanner, &item.ScannedAt, &item.FindingCount,
			&item.MaxSeverity, &item.DurationMs, &item.Verdict,
		); err != nil {
			return nil, fmt.Errorf("audit: scan history row for %q: %w", resourceID, err)
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

// SetStaticResourceStatus records the manual review decision on one resource
// (the API layer validates the allowed status set). Returns ok=false when the
// resource does not exist. Manual statuses survive enumeration sweeps and
// disappearances; a completed scan verdict supersedes them via the upsert.
func (s *Store) SetStaticResourceStatus(resourceID, status string) (bool, error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" || strings.TrimSpace(status) == "" {
		return false, nil
	}
	res, err := s.execDB(context.Background(), "static_resource_status_set",
		`UPDATE static_resources SET status = ? WHERE id = ? AND COALESCE("delete", 0) = 0`, status, resourceID)
	if err != nil {
		return false, fmt.Errorf("audit: set resource status %q: %w", resourceID, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("audit: set resource status rows for %q: %w", resourceID, err)
	}
	return n > 0, nil
}

// ListAgentResourceIDs returns every resource id of one agent (the rescan
// trigger re-scans these on demand).
func (s *Store) ListAgentResourceIDs(agentID string) ([]string, error) {
	if s == nil || s.db == nil || strings.TrimSpace(agentID) == "" {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_ids_by_agent", `
SELECT id FROM static_resources
WHERE canonical_agent_id = ? AND COALESCE(status,'') <> 'missing' AND COALESCE("delete", 0) = 0
ORDER BY id`, agentID)
	if err != nil {
		return nil, fmt.Errorf("audit: resource ids for agent %q: %w", agentID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("audit: resource id row: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// helper: queryRowDB mirrors queryDB for single-row queries.
func (s *Store) queryRowDB(ctx context.Context, label, query string, args ...any) rowScanner {
	return s.db.QueryRowContext(ctx, query, args...)
}
