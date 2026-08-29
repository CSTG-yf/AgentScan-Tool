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
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AgentResourceRule answers "for this agent type, where do we look for
// which resources?" — one row of agent_resource_rules.
type AgentResourceRule struct {
	ID              int64  `json:"id"`
	AgentTypeID     int64  `json:"agentTypeId"`
	Name            string `json:"name"`
	ResourceType    string `json:"resourceType"`    // skill / mcp / plugin / config / prompt / credential / environment
	PathPattern     string `json:"pathPattern"`     // e.g. ${WORKSPACE_ROOT}/skills
	EnumerationMode string `json:"enumerationMode"` // exact / children / glob / recursive
	ScanProfileID   int64  `json:"scanProfileId,omitempty"`
	Enabled         bool   `json:"enabled"`
	Priority        int    `json:"priority"`
}

// ResourceScanProfile answers "once a resource is found, which security
// detection plan applies?" — one row of resource_scan_profiles.
type ResourceScanProfile struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	ResourceType string `json:"resourceType"`
	Enabled      bool   `json:"enabled"`
	Description  string `json:"description,omitempty"`
}

// SecurityScanCapability is one registered security detection capability
// (capability_key → concrete scanner) in security_scan_capabilities.
type SecurityScanCapability struct {
	ID            int64  `json:"id"`
	CapabilityKey string `json:"capabilityKey"`
	Name          string `json:"name"`
	ScannerName   string `json:"scannerName"`
	Enabled       bool   `json:"enabled"`
	Description   string `json:"description,omitempty"`
}

// ProfileCapability is a joined resource_scan_profile_capabilities row:
// one capability bound to one profile, with its per-binding priority.
type ProfileCapability struct {
	ProfileID     int64  `json:"profileId"`
	CapabilityID  int64  `json:"capabilityId"`
	CapabilityKey string `json:"capabilityKey"`
	ScannerName   string `json:"scannerName"`
	Priority      int    `json:"priority"`
	Enabled       bool   `json:"enabled"`
	ConfigJSON    string `json:"configJson,omitempty"`
}

// AgentResourceRecord is the agents-table projection used by the watcher's
// rule-driven resource enumeration: identity + agent type binding + the root
// paths (parsed from agents.metadata_json) that expand the
// ${INSTALL_ROOT} / ${CONFIG_ROOT} / ${WORKSPACE_ROOT} placeholders inside
// agent_resource_rules.path_pattern.
type AgentResourceRecord struct {
	ID          string `json:"id"`
	AgentTypeID int64  `json:"agentTypeId"`
	TypeKey     string `json:"typeKey,omitempty"`
	DisplayName string `json:"displayName"`
	Status      string `json:"status"`
	// InstallRoot is the first discovered install path (metadata_json.install_paths).
	InstallRoot string `json:"installRoot,omitempty"`
	// ConfigRoot is the first discovered config path (metadata_json.config_paths).
	ConfigRoot string `json:"configRoot,omitempty"`
	// WorkspaceRoot is the agent's workspace root when recorded; the watcher
	// falls back to its own connector workspace for AgentRange-style agents.
	WorkspaceRoot string `json:"workspaceRoot,omitempty"`
}

// ResourceRiskUpdate is the post-scan risk payload written back onto a
// static_resources row.
type ResourceRiskUpdate struct {
	RiskLevel    string // clean / low / medium / high / critical
	Malicious    bool   // category-driven, independent of severity
	MaxSeverity  string // mirrored for legacy views
	FindingCount int
	LastScanID   string // empty keeps the previous scan reference
	LastSeenAt   time.Time
}

// ListActiveAgents returns discovered agents eligible for rule-driven
// resource enumeration (status not gone/removed/disabled), with the root
// paths (install/config) decoded from agents.metadata_json so callers can
// expand agent_resource_rules.path_pattern placeholders.
func (s *Store) ListActiveAgents() ([]AgentResourceRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "agent_active_list", `
SELECT a.id,
       COALESCE(a.agent_type_id, 0),
       COALESCE(t.type_key, ''),
       COALESCE(a.display_name, a.id),
       COALESCE(a.status, ''),
       COALESCE(a.metadata_json, '{}')
FROM agents a
LEFT JOIN agent_types t ON t.id = a.agent_type_id
WHERE COALESCE(a.status, 'observed') NOT IN ('gone', 'removed', 'disabled', 'retired')
  AND COALESCE(a."delete", 0) = 0
  AND COALESCE(t."delete", 0) = 0
ORDER BY a.id`)
	if err != nil {
		return nil, fmt.Errorf("audit: list active agents: %w", err)
	}
	defer rows.Close()

	var out []AgentResourceRecord
	for rows.Next() {
		var rec AgentResourceRecord
		var metadataJSON string
		if err := rows.Scan(&rec.ID, &rec.AgentTypeID, &rec.TypeKey, &rec.DisplayName, &rec.Status, &metadataJSON); err != nil {
			return nil, fmt.Errorf("audit: scan active agent row: %w", err)
		}
		decodeAgentResourceRoots(&rec, metadataJSON)
		out = append(out, rec)
	}
	return out, rows.Err()
}

// agentResourceRootsMetadata mirrors the install_paths / config_paths /
// workspace_root keys the agent-discovery pipeline writes into
// agents.metadata_json.
type agentResourceRootsMetadata struct {
	InstallPaths  []string `json:"install_paths,omitempty"`
	ConfigPaths   []string `json:"config_paths,omitempty"`
	WorkspaceRoot string   `json:"workspace_root,omitempty"`
}

// decodeAgentResourceRoots fills the InstallRoot / ConfigRoot /
// WorkspaceRoot fields of rec from a metadata_json blob. Unknown or
// malformed metadata leaves the roots empty — path-pattern expansion then
// simply skips rules whose placeholders cannot resolve for this agent.
func decodeAgentResourceRoots(rec *AgentResourceRecord, metadataJSON string) {
	if rec == nil || strings.TrimSpace(metadataJSON) == "" {
		return
	}
	var meta agentResourceRootsMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &meta); err != nil {
		return
	}
	if len(meta.InstallPaths) > 0 {
		rec.InstallRoot = strings.TrimSpace(meta.InstallPaths[0])
	}
	if len(meta.ConfigPaths) > 0 {
		rec.ConfigRoot = strings.TrimSpace(meta.ConfigPaths[0])
	}
	rec.WorkspaceRoot = strings.TrimSpace(meta.WorkspaceRoot)
}

// ListResourceRulesByAgentType returns the enabled agent_resource_rules for
// one agent type, ordered by priority then id.
func (s *Store) ListResourceRulesByAgentType(agentTypeID int64) ([]AgentResourceRule, error) {
	if s == nil || s.db == nil || agentTypeID <= 0 {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "agent_resource_rules_list", `
SELECT id, agent_type_id, name, resource_type, path_pattern,
       COALESCE(enumeration_mode, 'children'),
       COALESCE(scan_profile_id, 0),
       COALESCE(enabled, 0),
       COALESCE(priority, 100)
FROM agent_resource_rules
WHERE agent_type_id = ? AND COALESCE(enabled, 0) = 1 AND COALESCE("delete", 0) = 0
ORDER BY COALESCE(priority, 100), id`, agentTypeID)
	if err != nil {
		return nil, fmt.Errorf("audit: list resource rules for type %d: %w", agentTypeID, err)
	}
	defer rows.Close()

	var out []AgentResourceRule
	for rows.Next() {
		var rule AgentResourceRule
		var enabled int
		if err := rows.Scan(
			&rule.ID, &rule.AgentTypeID, &rule.Name, &rule.ResourceType, &rule.PathPattern,
			&rule.EnumerationMode, &rule.ScanProfileID, &enabled, &rule.Priority,
		); err != nil {
			return nil, fmt.Errorf("audit: scan resource rule row: %w", err)
		}
		rule.Enabled = enabled != 0
		out = append(out, rule)
	}
	return out, rows.Err()
}

// ListScanCapabilities returns the enabled capabilities bound to a scan
// profile, ordered by binding priority. Empty profile ID yields nil.
func (s *Store) ListScanCapabilities(profileID int64) ([]ProfileCapability, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return nil, nil
	}
	rows, err := s.queryDB(context.Background(), "profile_capabilities_list", `
SELECT pc.profile_id,
       pc.capability_id,
       COALESCE(c.capability_key, ''),
       COALESCE(c.scanner_name, ''),
       COALESCE(pc.priority, 100),
       COALESCE(pc.enabled, 0),
       COALESCE(pc.config_json, '')
FROM resource_scan_profile_capabilities pc
JOIN security_scan_capabilities c ON c.id = pc.capability_id
JOIN resource_scan_profiles p ON p.id = pc.profile_id
WHERE pc.profile_id = ?
  AND COALESCE(pc.enabled, 0) = 1
  AND COALESCE(pc."delete", 0) = 0
  AND COALESCE(c.enabled, 0) = 1
  AND COALESCE(c."delete", 0) = 0
  AND COALESCE(p.enabled, 0) = 1
  AND COALESCE(p."delete", 0) = 0
ORDER BY COALESCE(pc.priority, 100), pc.capability_id`, profileID)
	if err != nil {
		return nil, fmt.Errorf("audit: list capabilities for profile %d: %w", profileID, err)
	}
	defer rows.Close()

	var out []ProfileCapability
	for rows.Next() {
		var pc ProfileCapability
		var enabled int
		if err := rows.Scan(
			&pc.ProfileID, &pc.CapabilityID, &pc.CapabilityKey, &pc.ScannerName,
			&pc.Priority, &enabled, &pc.ConfigJSON,
		); err != nil {
			return nil, fmt.Errorf("audit: scan profile capability row: %w", err)
		}
		pc.Enabled = enabled != 0
		out = append(out, pc)
	}
	return out, rows.Err()
}

// UpdateStaticResourceRisk writes the post-scan risk verdict onto one
// static_resources row: risk bucket, malicious flag, scan reference, and
// the mirrored legacy severity columns. Empty lastScanID keeps the
// previously recorded scan reference.
func (s *Store) UpdateStaticResourceRisk(resourceID string, u ResourceRiskUpdate) error {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return nil
	}
	observed := u.LastSeenAt
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	maxSeverity := firstNonEmpty(u.MaxSeverity, "INFO")
	risk := firstNonEmpty(u.RiskLevel, ResourceRiskLevel(maxSeverity))
	malicious := 0
	if u.Malicious {
		malicious = 1
	}

	if _, err := s.execDB(context.Background(), "static_resource_risk_update", `
UPDATE static_resources SET
  risk_level = ?,
  malicious = ?,
  max_severity = ?,
  finding_count = ?,
  status = ?,
  last_scan_id = COALESCE(?, last_scan_id),
  last_seen_at = ?
WHERE id = ? AND COALESCE("delete", 0) = 0`,
		risk,
		malicious,
		maxSeverity,
		u.FindingCount,
		staticResourceStatus(maxSeverity),
		anyString(u.LastScanID),
		observed.UTC().Format(time.RFC3339Nano),
		resourceID,
	); err != nil {
		return fmt.Errorf("audit: update static resource risk %q: %w", resourceID, err)
	}
	return nil
}

// ResourceRiskLevel maps a max severity onto the resource risk bucket:
// no findings → clean, LOW → low, MEDIUM → medium, HIGH → high,
// CRITICAL → critical.
func ResourceRiskLevel(maxSeverity string) string {
	switch strings.ToUpper(strings.TrimSpace(maxSeverity)) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "clean"
	}
}

// MarkMissingResources flags the rule-produced resources of one agent that
// were not re-observed during the enumeration started at observedAt:
// last_seen_at < observedAt ⇒ status = 'missing'. Rows are never deleted —
// the active/missing history stays intact for drift analysis and incident
// investigation. Only resource_rule_id-bearing rows participate: legacy and
// auxiliary resources are enumerated through other paths and must not be
// marked missing by a rule-driven sweep. Rows the operator manually marked
// 'ignored' keep their review decision and are skipped. Returns the number
// of rows that transitioned to missing.
func (s *Store) MarkMissingResources(agentID string, observedAt time.Time) (int, error) {
	if s == nil || s.db == nil || strings.TrimSpace(agentID) == "" || observedAt.IsZero() {
		return 0, nil
	}
	res, err := s.execDB(context.Background(), "static_resource_missing_mark", `
UPDATE static_resources SET status = 'missing'
WHERE canonical_agent_id = ?
  AND resource_rule_id IS NOT NULL
  AND status <> 'missing'
  AND COALESCE(status, '') <> 'ignored'
  AND COALESCE("delete", 0) = 0
  AND julianday(last_seen_at) < julianday(?)`,
		agentID,
		observedAt.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, fmt.Errorf("audit: mark missing resources for %q: %w", agentID, err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// MarkResourceMissingByPath flags one agent's resource at a specific target
// path as missing (fsnotify Remove on a rule-produced resource). Precise,
// timestamp-independent counterpart to the enumeration-wide
// MarkMissingResources sweep. Manually 'ignored' rows keep their review
// decision.
func (s *Store) MarkResourceMissingByPath(agentID, target string) error {
	if s == nil || s.db == nil || strings.TrimSpace(agentID) == "" || strings.TrimSpace(target) == "" {
		return nil
	}
	if _, err := s.execDB(context.Background(), "static_resource_missing_by_path", `
UPDATE static_resources SET status = 'missing'
WHERE canonical_agent_id = ? AND target = ? AND status <> 'missing'
  AND COALESCE(status, '') <> 'ignored'
  AND COALESCE("delete", 0) = 0`,
		agentID, target,
	); err != nil {
		return fmt.Errorf("audit: mark resource missing %q/%q: %w", agentID, target, err)
	}
	return nil
}

// StaticResourceStatus returns the lifecycle status of one static_resources
// row (discovered / review / needs_review / missing), or "" when the row
// does not exist. Used by tests and diagnostics.
func (s *Store) StaticResourceStatus(resourceID string) (string, error) {
	if s == nil || s.db == nil || strings.TrimSpace(resourceID) == "" {
		return "", nil
	}
	rows, err := s.queryDB(context.Background(), "static_resource_status_get", `
SELECT COALESCE(status, '') FROM static_resources WHERE id = ? AND COALESCE("delete", 0) = 0`, resourceID)
	if err != nil {
		return "", fmt.Errorf("audit: get static resource status %q: %w", resourceID, err)
	}
	defer rows.Close()
	if !rows.Next() {
		return "", nil
	}
	var status string
	if err := rows.Scan(&status); err != nil {
		return "", fmt.Errorf("audit: scan static resource status %q: %w", resourceID, err)
	}
	return status, rows.Err()
}

// ScanProfileFingerprint returns a canonical string over everything about a
// scan profile that determines scanner behavior: the profile row itself and
// every enabled bound capability (key, priority, config_json, binding
// updated_at), sorted by capability key. The watcher folds this into its
// scanner fingerprint so an admin editing the profile — adding Malware to a
// Skill profile, tweaking a capability's config — invalidates baselines and
// forces a re-scan even though the resource bytes are unchanged.
func (s *Store) ScanProfileFingerprint(profileID int64) (string, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return "", nil
	}
	rows, err := s.queryDB(context.Background(), "scan_profile_fingerprint", `
SELECT p.id,
       COALESCE(p.name, ''),
       COALESCE(p.enabled, 0),
       COALESCE(p.updated_at, ''),
       COALESCE(c.capability_key, ''),
       COALESCE(pc.priority, 100),
       COALESCE(pc.config_json, ''),
       COALESCE(pc.updated_at, '')
FROM resource_scan_profiles p
LEFT JOIN resource_scan_profile_capabilities pc
       ON pc.profile_id = p.id AND COALESCE(pc.enabled, 0) = 1 AND COALESCE(pc."delete", 0) = 0
LEFT JOIN security_scan_capabilities c
       ON c.id = pc.capability_id AND COALESCE(c.enabled, 0) = 1 AND COALESCE(c."delete", 0) = 0
WHERE p.id = ? AND COALESCE(p."delete", 0) = 0
ORDER BY c.capability_key`, profileID)
	if err != nil {
		return "", fmt.Errorf("audit: profile fingerprint %d: %w", profileID, err)
	}
	defer rows.Close()

	var b strings.Builder
	first := true
	for rows.Next() {
		var id int64
		var name string
		var enabled int
		var profileUpdated string
		var capabilityKey string
		var priority int
		var configJSON string
		var bindingUpdated string
		if err := rows.Scan(&id, &name, &enabled, &profileUpdated,
			&capabilityKey, &priority, &configJSON, &bindingUpdated); err != nil {
			return "", fmt.Errorf("audit: scan profile fingerprint row: %w", err)
		}
		if first {
			fmt.Fprintf(&b, "id=%d:name=%s:enabled=%d:v=%s", id, name, enabled, profileUpdated)
			first = false
		}
		if capabilityKey != "" {
			fmt.Fprintf(&b, ";cap=%s:pri=%d:cfg=%s:v=%s", capabilityKey, priority, configJSON, bindingUpdated)
		}
	}
	if first {
		return "", nil // no such profile
	}
	return b.String(), rows.Err()
}
