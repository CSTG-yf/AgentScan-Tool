// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
)

// PreScanProfileFingerprint returns a stable representation of a pre-scan
// profile and all of its active rules. Rescan baselines must include this
// value because changing a decision from allow/skip to scan changes scanner
// behavior even when the resource bytes do not change.
func (s *Store) PreScanProfileFingerprint(profileID int64) (string, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return "", nil
	}
	rows, err := s.queryDB(context.Background(), "pre_scan_profile_fingerprint", `
SELECT p.id, COALESCE(p.profile_key, ''), COALESCE(p.name, ''),
       COALESCE(p.description, ''), COALESCE(p.enabled, 0),
       COALESCE(p.is_default, 0), COALESCE(p.updated_at, ''),
       COALESCE(r.id, 0), COALESCE(r.rule_name, ''), COALESCE(r.priority, 100),
       COALESCE(r.agent_type_id, 0), COALESCE(r.resource_type, ''),
       COALESCE(r.path_pattern, ''), COALESCE(r.source_trust, ''),
       COALESCE(r.decision, ''), COALESCE(r.install_action, ''),
       COALESCE(r.file_action, ''), COALESCE(r.runtime_action, ''),
       COALESCE(r.enabled, 0), COALESCE(r.updated_at, '')
FROM resource_pre_scan_profiles p
LEFT JOIN resource_pre_scan_rules r
       ON r.profile_id = p.id AND COALESCE(r."delete", 0) = 0
WHERE p.id = ? AND COALESCE(p."delete", 0) = 0
ORDER BY r.priority, r.id`, profileID)
	if err != nil {
		return "", fmt.Errorf("audit: pre-scan profile fingerprint %d: %w", profileID, err)
	}
	defer rows.Close()

	var b strings.Builder
	first := true
	for rows.Next() {
		var (
			profileIDValue int64
			profileKey     string
			name           string
			description    string
			profileEnabled int
			isDefault      int
			profileUpdated string
			ruleID         int64
			ruleName       string
			priority       int
			agentTypeID    int64
			resourceType   string
			pathPattern    string
			sourceTrust    string
			decision       string
			installAction  string
			fileAction     string
			runtimeAction string
			ruleEnabled    int
			ruleUpdated    string
		)
		if err := rows.Scan(
			&profileIDValue, &profileKey, &name, &description, &profileEnabled,
			&isDefault, &profileUpdated, &ruleID, &ruleName, &priority,
			&agentTypeID, &resourceType, &pathPattern, &sourceTrust, &decision,
			&installAction, &fileAction, &runtimeAction, &ruleEnabled, &ruleUpdated,
		); err != nil {
			return "", fmt.Errorf("audit: scan pre-scan profile fingerprint row: %w", err)
		}
		if first {
			fmt.Fprintf(&b, "profile=%d:key=%s:name=%s:description=%s:enabled=%d:default=%d:v=%s",
				profileIDValue, profileKey, name, description, profileEnabled, isDefault, profileUpdated)
			first = false
		}
		if ruleID != 0 {
			fmt.Fprintf(&b, ";rule=%d:name=%s:priority=%d:agent_type=%d:type=%s:path=%s:trust=%s:decision=%s:install=%s:file=%s:runtime=%s:enabled=%d:v=%s",
				ruleID, ruleName, priority, agentTypeID, resourceType, pathPattern, sourceTrust,
				decision, installAction, fileAction, runtimeAction, ruleEnabled, ruleUpdated)
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if first {
		return "", nil
	}
	return b.String(), nil
}

// PostScanProfileFingerprint returns a stable representation of a post-scan
// profile and all of its active rules for rescan invalidation.
func (s *Store) PostScanProfileFingerprint(profileID int64) (string, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return "", nil
	}
	rows, err := s.queryDB(context.Background(), "post_scan_profile_fingerprint", `
SELECT p.id, COALESCE(p.profile_key, ''), COALESCE(p.name, ''),
       COALESCE(p.description, ''), COALESCE(p.enabled, 0),
       COALESCE(p.is_default, 0), COALESCE(p.updated_at, ''),
       COALESCE(r.id, 0), COALESCE(r.rule_name, ''), COALESCE(r.priority, 100),
       COALESCE(r.resource_type, ''), COALESCE(r.severity, ''),
       COALESCE(r.risk_level, ''), COALESCE(r.malicious, 0),
       COALESCE(r.finding_category, ''), COALESCE(r.scanner, ''),
       COALESCE(r.decision, ''), COALESCE(r.install_action, ''),
       COALESCE(r.file_action, ''), COALESCE(r.runtime_action, ''),
       COALESCE(r.enabled, 0), COALESCE(r.updated_at, '')
FROM resource_post_scan_profiles p
LEFT JOIN resource_post_scan_rules r
       ON r.profile_id = p.id AND COALESCE(r."delete", 0) = 0
WHERE p.id = ? AND COALESCE(p."delete", 0) = 0
ORDER BY r.priority, r.id`, profileID)
	if err != nil {
		return "", fmt.Errorf("audit: post-scan profile fingerprint %d: %w", profileID, err)
	}
	defer rows.Close()

	var b strings.Builder
	first := true
	for rows.Next() {
		var (
			profileIDValue int64
			profileKey     string
			name           string
			description    string
			profileEnabled int
			isDefault      int
			profileUpdated string
			ruleID         int64
			ruleName       string
			priority       int
			resourceType   string
			severity       string
			riskLevel      string
			malicious      int
			findingCat     string
			scanner        string
			decision        string
			installAction  string
			fileAction     string
			runtimeAction string
			ruleEnabled    int
			ruleUpdated    string
		)
		if err := rows.Scan(
			&profileIDValue, &profileKey, &name, &description, &profileEnabled,
			&isDefault, &profileUpdated, &ruleID, &ruleName, &priority,
			&resourceType, &severity, &riskLevel, &malicious, &findingCat,
			&scanner, &decision, &installAction, &fileAction, &runtimeAction,
			&ruleEnabled, &ruleUpdated,
		); err != nil {
			return "", fmt.Errorf("audit: scan post-scan profile fingerprint row: %w", err)
		}
		if first {
			fmt.Fprintf(&b, "profile=%d:key=%s:name=%s:description=%s:enabled=%d:default=%d:v=%s",
				profileIDValue, profileKey, name, description, profileEnabled, isDefault, profileUpdated)
			first = false
		}
		if ruleID != 0 {
			fmt.Fprintf(&b, ";rule=%d:name=%s:priority=%d:type=%s:severity=%s:risk=%s:malicious=%d:category=%s:scanner=%s:decision=%s:install=%s:file=%s:runtime=%s:enabled=%d:v=%s",
				ruleID, ruleName, priority, resourceType, severity, riskLevel, malicious,
				findingCat, scanner, decision, installAction, fileAction, runtimeAction,
				ruleEnabled, ruleUpdated)
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if first {
		return "", nil
	}
	return b.String(), nil
}
