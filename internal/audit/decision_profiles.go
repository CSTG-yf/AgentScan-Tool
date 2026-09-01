// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
	"path"
	"strings"
	"time"
)

const (
	defaultPreScanProfileKey  = "default-pre-scan"
	defaultPostScanProfileKey = "default-post-scan"
)

type GovernancePreScanProfilePage struct {
	Total    int                           `json:"total"`
	Page     int                           `json:"page"`
	PageSize int                           `json:"page_size"`
	Items    []GovernancePreScanProfileRow `json:"items"`
}

type GovernancePreScanProfileRow struct {
	ID                int64  `json:"id"`
	ProfileKey        string `json:"profile_key"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Enabled           bool   `json:"enabled"`
	IsDefault         bool   `json:"is_default"`
	RuleCount         int    `json:"rule_count"`
	ResourceRuleCount int    `json:"resource_rule_count"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type GovernancePreScanProfileInput struct {
	ProfileKey  string                       `json:"profile_key"`
	Name        string                       `json:"name"`
	Description string                       `json:"description"`
	Enabled     bool                         `json:"enabled"`
	IsDefault   bool                         `json:"is_default"`
	Rules       []GovernancePreScanRuleInput `json:"rules,omitempty"`
}

type GovernancePreScanProfilePatch struct {
	ProfileKey  *string `json:"profile_key,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

type GovernancePreScanRulePage struct {
	Total    int                        `json:"total"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"page_size"`
	Items    []GovernancePreScanRuleRow `json:"items"`
}

type GovernancePreScanRuleRow struct {
	ID            int64  `json:"id"`
	ProfileID     int64  `json:"profile_id"`
	RuleName      string `json:"rule_name"`
	Priority      int    `json:"priority"`
	AgentTypeID   int64  `json:"agent_type_id,omitempty"`
	AgentTypeKey  string `json:"agent_type_key,omitempty"`
	AgentTypeName string `json:"agent_type_name,omitempty"`
	ResourceType  string `json:"resource_type"`
	PathPattern   string `json:"path_pattern"`
	SourceTrust   string `json:"source_trust"`
	Decision      string `json:"decision"`
	InstallAction string `json:"install_action"`
	FileAction    string `json:"file_action"`
	RuntimeAction string `json:"runtime_action"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type GovernancePreScanRuleInput struct {
	RuleName      string `json:"rule_name"`
	Priority      int    `json:"priority"`
	AgentTypeID   int64  `json:"agent_type_id,omitempty"`
	ResourceType  string `json:"resource_type"`
	PathPattern   string `json:"path_pattern"`
	SourceTrust   string `json:"source_trust"`
	Decision      string `json:"decision"`
	InstallAction string `json:"install_action"`
	FileAction    string `json:"file_action"`
	RuntimeAction string `json:"runtime_action"`
	Enabled       bool   `json:"enabled"`
}

type GovernancePreScanRulePatch struct {
	RuleName      *string `json:"rule_name,omitempty"`
	Priority      *int    `json:"priority,omitempty"`
	AgentTypeID   *int64  `json:"agent_type_id,omitempty"`
	ResourceType  *string `json:"resource_type,omitempty"`
	PathPattern   *string `json:"path_pattern,omitempty"`
	SourceTrust   *string `json:"source_trust,omitempty"`
	Decision      *string `json:"decision,omitempty"`
	InstallAction *string `json:"install_action,omitempty"`
	FileAction    *string `json:"file_action,omitempty"`
	RuntimeAction *string `json:"runtime_action,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

type GovernancePostScanProfilePage struct {
	Total    int                            `json:"total"`
	Page     int                            `json:"page"`
	PageSize int                            `json:"page_size"`
	Items    []GovernancePostScanProfileRow `json:"items"`
}

type GovernancePostScanProfileRow struct {
	ID                int64  `json:"id"`
	ProfileKey        string `json:"profile_key"`
	Name              string `json:"name"`
	Description       string `json:"description"`
	Enabled           bool   `json:"enabled"`
	IsDefault         bool   `json:"is_default"`
	RuleCount         int    `json:"rule_count"`
	ResourceRuleCount int    `json:"resource_rule_count"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type GovernancePostScanProfileInput struct {
	ProfileKey  string                        `json:"profile_key"`
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	Enabled     bool                          `json:"enabled"`
	IsDefault   bool                          `json:"is_default"`
	Rules       []GovernancePostScanRuleInput `json:"rules,omitempty"`
}

type GovernancePostScanProfilePatch struct {
	ProfileKey  *string `json:"profile_key,omitempty"`
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
	IsDefault   *bool   `json:"is_default,omitempty"`
}

type GovernancePostScanRulePage struct {
	Total    int                         `json:"total"`
	Page     int                         `json:"page"`
	PageSize int                         `json:"page_size"`
	Items    []GovernancePostScanRuleRow `json:"items"`
}

type GovernancePostScanRuleRow struct {
	ID              int64  `json:"id"`
	ProfileID       int64  `json:"profile_id"`
	RuleName        string `json:"rule_name"`
	Priority        int    `json:"priority"`
	ResourceType    string `json:"resource_type"`
	Severity        string `json:"severity"`
	RiskLevel       string `json:"risk_level"`
	Malicious       bool   `json:"malicious"`
	FindingCategory string `json:"finding_category"`
	Scanner         string `json:"scanner"`
	Decision        string `json:"decision"`
	InstallAction   string `json:"install_action"`
	FileAction      string `json:"file_action"`
	RuntimeAction   string `json:"runtime_action"`
	Enabled         bool   `json:"enabled"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type GovernancePostScanRuleInput struct {
	RuleName        string `json:"rule_name"`
	Priority        int    `json:"priority"`
	ResourceType    string `json:"resource_type"`
	Severity        string `json:"severity"`
	RiskLevel       string `json:"risk_level"`
	Malicious       bool   `json:"malicious"`
	FindingCategory string `json:"finding_category"`
	Scanner         string `json:"scanner"`
	Decision        string `json:"decision"`
	InstallAction   string `json:"install_action"`
	FileAction      string `json:"file_action"`
	RuntimeAction   string `json:"runtime_action"`
	Enabled         bool   `json:"enabled"`
}

type GovernancePostScanRulePatch struct {
	RuleName        *string `json:"rule_name,omitempty"`
	Priority        *int    `json:"priority,omitempty"`
	ResourceType    *string `json:"resource_type,omitempty"`
	Severity        *string `json:"severity,omitempty"`
	RiskLevel       *string `json:"risk_level,omitempty"`
	Malicious       *bool   `json:"malicious,omitempty"`
	FindingCategory *string `json:"finding_category,omitempty"`
	Scanner         *string `json:"scanner,omitempty"`
	Decision        *string `json:"decision,omitempty"`
	InstallAction   *string `json:"install_action,omitempty"`
	FileAction      *string `json:"file_action,omitempty"`
	RuntimeAction   *string `json:"runtime_action,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

type ResourcePreScanDecisionInput struct {
	AgentTypeID    int64
	ResourceRuleID int64
	ResourceType   string
	Path           string
	SourceTrust    string
}

type ResourcePostScanDecisionInput struct {
	ResourceType      string
	MaxSeverity       string
	RiskLevel         string
	Malicious         bool
	FindingCategories []string
	Scanner           string
	FindingScanners   []string
}

type ResourceDecisionResult struct {
	Matched       bool
	Phase         string
	ProfileID     int64
	RuleID        int64
	RuleName      string
	Decision      string
	InstallAction string
	FileAction    string
	RuntimeAction string
	Reason        string
}

func (s *Store) ListGovernancePreScanProfiles(f GovernancePageFilter) (*GovernancePreScanProfilePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE("delete",0) = 0`}
	var args []any
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(profile_key) LIKE ? OR LOWER(name) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_pre_scan_profile_count", "SELECT COUNT(*) FROM resource_pre_scan_profiles WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_pre_scan_profile_list", `
SELECT id, COALESCE(profile_key,''), COALESCE(name,''), COALESCE(description,''),
       COALESCE(enabled,0), COALESCE(is_default,0),
       (SELECT COUNT(*) FROM resource_pre_scan_rules r WHERE r.profile_id = p.id AND COALESCE(r."delete",0) = 0),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.pre_scan_profile_id,0) = p.id AND COALESCE(rr."delete",0) = 0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_pre_scan_profiles p
WHERE `+clause+`
ORDER BY COALESCE(is_default,0) DESC, COALESCE(enabled,0) DESC, LOWER(name), id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list pre-scan profiles: %w", err)
	}
	defer rows.Close()
	out := &GovernancePreScanProfilePage{Total: total, Page: page, PageSize: size, Items: []GovernancePreScanProfileRow{}}
	for rows.Next() {
		item, err := scanGovernancePreScanProfile(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernancePreScanProfile(in GovernancePreScanProfileInput) (GovernancePreScanProfileRow, error) {
	if err := validateDecisionProfileInput(in.ProfileKey, in.Name); err != nil {
		return GovernancePreScanProfileRow{}, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GovernancePreScanProfileRow{}, fmt.Errorf("audit: begin pre-scan profile create: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	key := normalizeDecisionProfileKey(in.ProfileKey)
	if in.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE resource_pre_scan_profiles SET is_default = 0, updated_at = ? WHERE COALESCE("delete",0) = 0`, now); err != nil {
			return GovernancePreScanProfileRow{}, fmt.Errorf("audit: clear pre-scan default profile: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO resource_pre_scan_profiles (profile_key, name, description, enabled, is_default, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(profile_key) DO UPDATE SET
  name = excluded.name,
  description = excluded.description,
  enabled = excluded.enabled,
  is_default = excluded.is_default,
  updated_at = excluded.updated_at,
  "delete" = 0`,
		key, strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), boolInt(in.Enabled), boolInt(in.IsDefault), now, now); err != nil {
		return GovernancePreScanProfileRow{}, fmt.Errorf("audit: create pre-scan profile: %w", err)
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM resource_pre_scan_profiles WHERE profile_key = ?`, key).Scan(&id); err != nil {
		return GovernancePreScanProfileRow{}, fmt.Errorf("audit: lookup pre-scan profile: %w", err)
	}
	for _, rule := range in.Rules {
		if _, err := insertPreScanRule(ctx, tx, id, rule, now); err != nil {
			return GovernancePreScanProfileRow{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return GovernancePreScanProfileRow{}, fmt.Errorf("audit: commit pre-scan profile create: %w", err)
	}
	row, ok, err := s.GetGovernancePreScanProfile(id)
	if err != nil {
		return GovernancePreScanProfileRow{}, err
	}
	if !ok {
		return GovernancePreScanProfileRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernancePreScanProfile(id int64, patch GovernancePreScanProfilePatch) (GovernancePreScanProfileRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.ProfileKey != nil {
		key := normalizeDecisionProfileKey(*patch.ProfileKey)
		if key == "" {
			return GovernancePreScanProfileRow{}, false, fmt.Errorf("audit: profile_key is required")
		}
		sets = append(sets, "profile_key = ?")
		args = append(args, key)
	}
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return GovernancePreScanProfileRow{}, false, fmt.Errorf("audit: name is required")
		}
		sets = append(sets, "name = ?")
		args = append(args, name)
	}
	if patch.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, strings.TrimSpace(*patch.Description))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if patch.IsDefault != nil {
		if *patch.IsDefault {
			if err := s.setPreScanDefaultProfile(id); err != nil {
				return GovernancePreScanProfileRow{}, false, err
			}
		} else {
			sets = append(sets, "is_default = ?")
			args = append(args, 0)
		}
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernancePreScanProfile(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_pre_scan_profile_update",
		"UPDATE resource_pre_scan_profiles SET "+strings.Join(sets, ", ")+" WHERE id = ? AND COALESCE(\"delete\",0) = 0", args...)
	if err != nil {
		return GovernancePreScanProfileRow{}, false, fmt.Errorf("audit: update pre-scan profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernancePreScanProfileRow{}, false, nil
	}
	row, ok, err := s.GetGovernancePreScanProfile(id)
	return row, ok, err
}

func (s *Store) DeleteGovernancePreScanProfile(id int64) (bool, error) {
	row, ok, err := s.GetGovernancePreScanProfile(id)
	if err != nil || !ok {
		return ok, err
	}
	if row.IsDefault {
		return false, fmt.Errorf("audit: default pre-scan profile cannot be deleted")
	}
	res, err := s.execDB(context.Background(), "governance_pre_scan_profile_delete",
		`UPDATE resource_pre_scan_profiles SET "delete" = 1, updated_at = ? WHERE id = ? AND COALESCE("delete",0) = 0`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("audit: delete pre-scan profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernancePreScanProfile(id int64) (GovernancePreScanProfileRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_pre_scan_profile_get", `
SELECT id, COALESCE(profile_key,''), COALESCE(name,''), COALESCE(description,''),
       COALESCE(enabled,0), COALESCE(is_default,0),
       (SELECT COUNT(*) FROM resource_pre_scan_rules r WHERE r.profile_id = p.id AND COALESCE(r."delete",0) = 0),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.pre_scan_profile_id,0) = p.id AND COALESCE(rr."delete",0) = 0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_pre_scan_profiles p
WHERE id = ? AND COALESCE("delete",0) = 0`, id)
	if err != nil {
		return GovernancePreScanProfileRow{}, false, fmt.Errorf("audit: get pre-scan profile: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernancePreScanProfileRow{}, false, rows.Err()
	}
	item, err := scanGovernancePreScanProfile(rows)
	return item, err == nil, err
}

func (s *Store) ListGovernancePreScanRules(profileID int64, f GovernancePageFilter) (*GovernancePreScanRulePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`r.profile_id = ?`, `COALESCE(r."delete",0) = 0`}
	args := []any{profileID}
	if f.Enabled != nil {
		where = append(where, "COALESCE(r.enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.ResourceType = strings.TrimSpace(f.ResourceType); f.ResourceType != "" {
		where = append(where, "LOWER(COALESCE(r.resource_type,'')) = ?")
		args = append(args, strings.ToLower(f.ResourceType))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(r.rule_name) LIKE ? OR LOWER(COALESCE(r.path_pattern,'')) LIKE ? OR LOWER(COALESCE(r.source_trust,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_pre_scan_rule_count", "SELECT COUNT(*) FROM resource_pre_scan_rules r WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_pre_scan_rule_list", `
SELECT r.id, r.profile_id, COALESCE(r.rule_name,''), COALESCE(r.priority,100),
       COALESCE(r.agent_type_id,0), COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(r.resource_type,'all'), COALESCE(r.path_pattern,''), COALESCE(r.source_trust,''),
       COALESCE(r.decision,'scan'), COALESCE(r.install_action,'none'),
       COALESCE(r.file_action,'none'), COALESCE(r.runtime_action,'allow'),
       COALESCE(r.enabled,0), COALESCE(CAST(r.created_at AS TEXT), ''), COALESCE(CAST(r.updated_at AS TEXT), '')
FROM resource_pre_scan_rules r
LEFT JOIN agent_types t ON t.id = r.agent_type_id AND COALESCE(t."delete",0) = 0
WHERE `+clause+`
ORDER BY COALESCE(r.enabled,0) DESC, COALESCE(r.priority,100), r.id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list pre-scan rules: %w", err)
	}
	defer rows.Close()
	out := &GovernancePreScanRulePage{Total: total, Page: page, PageSize: size, Items: []GovernancePreScanRuleRow{}}
	for rows.Next() {
		item, err := scanGovernancePreScanRule(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernancePreScanRule(profileID int64, in GovernancePreScanRuleInput) (GovernancePreScanRuleRow, error) {
	if _, ok, err := s.GetGovernancePreScanProfile(profileID); err != nil || !ok {
		if err != nil {
			return GovernancePreScanRuleRow{}, err
		}
		return GovernancePreScanRuleRow{}, sql.ErrNoRows
	}
	if err := validatePreScanRuleInput(profileID, in); err != nil {
		return GovernancePreScanRuleRow{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.execDB(context.Background(), "governance_pre_scan_rule_create", `
INSERT INTO resource_pre_scan_rules (
  profile_id, rule_name, priority, agent_type_id, resource_type, path_pattern, source_trust,
  decision, install_action, file_action, runtime_action, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profileID, strings.TrimSpace(in.RuleName), normalizePriority(in.Priority), nullInt64Value(in.AgentTypeID),
		normalizeDecisionResourceType(in.ResourceType), strings.TrimSpace(in.PathPattern), strings.TrimSpace(in.SourceTrust),
		normalizePreScanDecision(in.Decision), normalizeInstallAction(in.InstallAction), normalizeFileAction(in.FileAction),
		normalizeRuntimeAction(in.RuntimeAction), boolInt(in.Enabled), now, now)
	if err != nil {
		return GovernancePreScanRuleRow{}, fmt.Errorf("audit: create pre-scan rule: %w", err)
	}
	id, _ := res.LastInsertId()
	row, ok, err := s.GetGovernancePreScanRule(id)
	if err != nil {
		return GovernancePreScanRuleRow{}, err
	}
	if !ok {
		return GovernancePreScanRuleRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernancePreScanRule(id int64, patch GovernancePreScanRulePatch) (GovernancePreScanRuleRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.RuleName != nil {
		name := strings.TrimSpace(*patch.RuleName)
		if name == "" {
			return GovernancePreScanRuleRow{}, false, fmt.Errorf("audit: rule_name is required")
		}
		sets = append(sets, "rule_name = ?")
		args = append(args, name)
	}
	if patch.Priority != nil {
		sets = append(sets, "priority = ?")
		args = append(args, normalizePriority(*patch.Priority))
	}
	if patch.AgentTypeID != nil {
		sets = append(sets, "agent_type_id = ?")
		args = append(args, nullInt64Value(*patch.AgentTypeID))
	}
	if patch.ResourceType != nil {
		rtype := normalizeDecisionResourceType(*patch.ResourceType)
		if !validDecisionResourceType(rtype) {
			return GovernancePreScanRuleRow{}, false, fmt.Errorf("audit: unsupported resource_type %q", *patch.ResourceType)
		}
		sets = append(sets, "resource_type = ?")
		args = append(args, rtype)
	}
	if patch.PathPattern != nil {
		sets = append(sets, "path_pattern = ?")
		args = append(args, strings.TrimSpace(*patch.PathPattern))
	}
	if patch.SourceTrust != nil {
		sets = append(sets, "source_trust = ?")
		args = append(args, strings.TrimSpace(*patch.SourceTrust))
	}
	if patch.Decision != nil {
		decision := normalizePreScanDecision(*patch.Decision)
		if !validPreScanDecision(decision) {
			return GovernancePreScanRuleRow{}, false, fmt.Errorf("audit: unsupported pre-scan decision %q", *patch.Decision)
		}
		sets = append(sets, "decision = ?")
		args = append(args, decision)
	}
	if patch.InstallAction != nil {
		sets = append(sets, "install_action = ?")
		args = append(args, normalizeInstallAction(*patch.InstallAction))
	}
	if patch.FileAction != nil {
		sets = append(sets, "file_action = ?")
		args = append(args, normalizeFileAction(*patch.FileAction))
	}
	if patch.RuntimeAction != nil {
		sets = append(sets, "runtime_action = ?")
		args = append(args, normalizeRuntimeAction(*patch.RuntimeAction))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernancePreScanRule(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_pre_scan_rule_update",
		"UPDATE resource_pre_scan_rules SET "+strings.Join(sets, ", ")+" WHERE id = ? AND COALESCE(\"delete\",0) = 0", args...)
	if err != nil {
		return GovernancePreScanRuleRow{}, false, fmt.Errorf("audit: update pre-scan rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernancePreScanRuleRow{}, false, nil
	}
	row, ok, err := s.GetGovernancePreScanRule(id)
	return row, ok, err
}

func (s *Store) DeleteGovernancePreScanRule(id int64) (bool, error) {
	res, err := s.execDB(context.Background(), "governance_pre_scan_rule_delete",
		`UPDATE resource_pre_scan_rules SET "delete" = 1, updated_at = ? WHERE id = ? AND COALESCE("delete",0) = 0`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("audit: delete pre-scan rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernancePreScanRule(id int64) (GovernancePreScanRuleRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_pre_scan_rule_get", `
SELECT r.id, r.profile_id, COALESCE(r.rule_name,''), COALESCE(r.priority,100),
       COALESCE(r.agent_type_id,0), COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(r.resource_type,'all'), COALESCE(r.path_pattern,''), COALESCE(r.source_trust,''),
       COALESCE(r.decision,'scan'), COALESCE(r.install_action,'none'),
       COALESCE(r.file_action,'none'), COALESCE(r.runtime_action,'allow'),
       COALESCE(r.enabled,0), COALESCE(CAST(r.created_at AS TEXT), ''), COALESCE(CAST(r.updated_at AS TEXT), '')
FROM resource_pre_scan_rules r
LEFT JOIN agent_types t ON t.id = r.agent_type_id AND COALESCE(t."delete",0) = 0
WHERE r.id = ? AND COALESCE(r."delete",0) = 0`, id)
	if err != nil {
		return GovernancePreScanRuleRow{}, false, fmt.Errorf("audit: get pre-scan rule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernancePreScanRuleRow{}, false, rows.Err()
	}
	item, err := scanGovernancePreScanRule(rows)
	return item, err == nil, err
}

func (s *Store) ListGovernancePostScanProfiles(f GovernancePageFilter) (*GovernancePostScanProfilePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE("delete",0) = 0`}
	var args []any
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(profile_key) LIKE ? OR LOWER(name) LIKE ? OR LOWER(COALESCE(description,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_post_scan_profile_count", "SELECT COUNT(*) FROM resource_post_scan_profiles WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_post_scan_profile_list", `
SELECT id, COALESCE(profile_key,''), COALESCE(name,''), COALESCE(description,''),
       COALESCE(enabled,0), COALESCE(is_default,0),
       (SELECT COUNT(*) FROM resource_post_scan_rules r WHERE r.profile_id = p.id AND COALESCE(r."delete",0) = 0),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.post_scan_profile_id,0) = p.id AND COALESCE(rr."delete",0) = 0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_post_scan_profiles p
WHERE `+clause+`
ORDER BY COALESCE(is_default,0) DESC, COALESCE(enabled,0) DESC, LOWER(name), id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list post-scan profiles: %w", err)
	}
	defer rows.Close()
	out := &GovernancePostScanProfilePage{Total: total, Page: page, PageSize: size, Items: []GovernancePostScanProfileRow{}}
	for rows.Next() {
		item, err := scanGovernancePostScanProfile(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernancePostScanProfile(in GovernancePostScanProfileInput) (GovernancePostScanProfileRow, error) {
	if err := validateDecisionProfileInput(in.ProfileKey, in.Name); err != nil {
		return GovernancePostScanProfileRow{}, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GovernancePostScanProfileRow{}, fmt.Errorf("audit: begin post-scan profile create: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	key := normalizeDecisionProfileKey(in.ProfileKey)
	if in.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE resource_post_scan_profiles SET is_default = 0, updated_at = ? WHERE COALESCE("delete",0) = 0`, now); err != nil {
			return GovernancePostScanProfileRow{}, fmt.Errorf("audit: clear post-scan default profile: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO resource_post_scan_profiles (profile_key, name, description, enabled, is_default, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(profile_key) DO UPDATE SET
  name = excluded.name,
  description = excluded.description,
  enabled = excluded.enabled,
  is_default = excluded.is_default,
  updated_at = excluded.updated_at,
  "delete" = 0`,
		key, strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), boolInt(in.Enabled), boolInt(in.IsDefault), now, now); err != nil {
		return GovernancePostScanProfileRow{}, fmt.Errorf("audit: create post-scan profile: %w", err)
	}
	var id int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM resource_post_scan_profiles WHERE profile_key = ?`, key).Scan(&id); err != nil {
		return GovernancePostScanProfileRow{}, fmt.Errorf("audit: lookup post-scan profile: %w", err)
	}
	for _, rule := range in.Rules {
		if _, err := insertPostScanRule(ctx, tx, id, rule, now); err != nil {
			return GovernancePostScanProfileRow{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return GovernancePostScanProfileRow{}, fmt.Errorf("audit: commit post-scan profile create: %w", err)
	}
	row, ok, err := s.GetGovernancePostScanProfile(id)
	if err != nil {
		return GovernancePostScanProfileRow{}, err
	}
	if !ok {
		return GovernancePostScanProfileRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernancePostScanProfile(id int64, patch GovernancePostScanProfilePatch) (GovernancePostScanProfileRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.ProfileKey != nil {
		key := normalizeDecisionProfileKey(*patch.ProfileKey)
		if key == "" {
			return GovernancePostScanProfileRow{}, false, fmt.Errorf("audit: profile_key is required")
		}
		sets = append(sets, "profile_key = ?")
		args = append(args, key)
	}
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return GovernancePostScanProfileRow{}, false, fmt.Errorf("audit: name is required")
		}
		sets = append(sets, "name = ?")
		args = append(args, name)
	}
	if patch.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, strings.TrimSpace(*patch.Description))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if patch.IsDefault != nil {
		if *patch.IsDefault {
			if err := s.setPostScanDefaultProfile(id); err != nil {
				return GovernancePostScanProfileRow{}, false, err
			}
		} else {
			sets = append(sets, "is_default = ?")
			args = append(args, 0)
		}
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernancePostScanProfile(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_post_scan_profile_update",
		"UPDATE resource_post_scan_profiles SET "+strings.Join(sets, ", ")+" WHERE id = ? AND COALESCE(\"delete\",0) = 0", args...)
	if err != nil {
		return GovernancePostScanProfileRow{}, false, fmt.Errorf("audit: update post-scan profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernancePostScanProfileRow{}, false, nil
	}
	row, ok, err := s.GetGovernancePostScanProfile(id)
	return row, ok, err
}

func (s *Store) DeleteGovernancePostScanProfile(id int64) (bool, error) {
	row, ok, err := s.GetGovernancePostScanProfile(id)
	if err != nil || !ok {
		return ok, err
	}
	if row.IsDefault {
		return false, fmt.Errorf("audit: default post-scan profile cannot be deleted")
	}
	res, err := s.execDB(context.Background(), "governance_post_scan_profile_delete",
		`UPDATE resource_post_scan_profiles SET "delete" = 1, updated_at = ? WHERE id = ? AND COALESCE("delete",0) = 0`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("audit: delete post-scan profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernancePostScanProfile(id int64) (GovernancePostScanProfileRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_post_scan_profile_get", `
SELECT id, COALESCE(profile_key,''), COALESCE(name,''), COALESCE(description,''),
       COALESCE(enabled,0), COALESCE(is_default,0),
       (SELECT COUNT(*) FROM resource_post_scan_rules r WHERE r.profile_id = p.id AND COALESCE(r."delete",0) = 0),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.post_scan_profile_id,0) = p.id AND COALESCE(rr."delete",0) = 0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_post_scan_profiles p
WHERE id = ? AND COALESCE("delete",0) = 0`, id)
	if err != nil {
		return GovernancePostScanProfileRow{}, false, fmt.Errorf("audit: get post-scan profile: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernancePostScanProfileRow{}, false, rows.Err()
	}
	item, err := scanGovernancePostScanProfile(rows)
	return item, err == nil, err
}

func (s *Store) ListGovernancePostScanRules(profileID int64, f GovernancePageFilter) (*GovernancePostScanRulePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`profile_id = ?`, `COALESCE("delete",0) = 0`}
	args := []any{profileID}
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.ResourceType = strings.TrimSpace(f.ResourceType); f.ResourceType != "" {
		where = append(where, "LOWER(COALESCE(resource_type,'')) = ?")
		args = append(args, strings.ToLower(f.ResourceType))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(rule_name) LIKE ? OR LOWER(COALESCE(finding_category,'')) LIKE ? OR LOWER(COALESCE(scanner,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_post_scan_rule_count", "SELECT COUNT(*) FROM resource_post_scan_rules WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_post_scan_rule_list", `
SELECT id, profile_id, COALESCE(rule_name,''), COALESCE(priority,100),
       COALESCE(resource_type,'all'), COALESCE(severity,'INFO'), COALESCE(risk_level,'clean'),
       COALESCE(malicious,0), COALESCE(finding_category,''), COALESCE(scanner,''),
       COALESCE(decision,'alert'), COALESCE(install_action,'none'), COALESCE(file_action,'none'),
       COALESCE(runtime_action,'allow'), COALESCE(enabled,0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_post_scan_rules
WHERE `+clause+`
ORDER BY COALESCE(enabled,0) DESC, COALESCE(priority,100), id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list post-scan rules: %w", err)
	}
	defer rows.Close()
	out := &GovernancePostScanRulePage{Total: total, Page: page, PageSize: size, Items: []GovernancePostScanRuleRow{}}
	for rows.Next() {
		item, err := scanGovernancePostScanRule(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernancePostScanRule(profileID int64, in GovernancePostScanRuleInput) (GovernancePostScanRuleRow, error) {
	if _, ok, err := s.GetGovernancePostScanProfile(profileID); err != nil || !ok {
		if err != nil {
			return GovernancePostScanRuleRow{}, err
		}
		return GovernancePostScanRuleRow{}, sql.ErrNoRows
	}
	if err := validatePostScanRuleInput(profileID, in); err != nil {
		return GovernancePostScanRuleRow{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.execDB(context.Background(), "governance_post_scan_rule_create", `
INSERT INTO resource_post_scan_rules (
  profile_id, rule_name, priority, resource_type, severity, risk_level, malicious, finding_category, scanner,
  decision, install_action, file_action, runtime_action, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		profileID, strings.TrimSpace(in.RuleName), normalizePriority(in.Priority), normalizeDecisionResourceType(in.ResourceType),
		normalizePostScanSeverity(in.Severity), normalizePostScanRiskLevel(in.RiskLevel), boolInt(in.Malicious),
		strings.TrimSpace(in.FindingCategory), strings.TrimSpace(in.Scanner), normalizePostScanDecision(in.Decision),
		normalizeInstallAction(in.InstallAction), normalizeFileAction(in.FileAction), normalizeRuntimeAction(in.RuntimeAction),
		boolInt(in.Enabled), now, now)
	if err != nil {
		return GovernancePostScanRuleRow{}, fmt.Errorf("audit: create post-scan rule: %w", err)
	}
	id, _ := res.LastInsertId()
	row, ok, err := s.GetGovernancePostScanRule(id)
	if err != nil {
		return GovernancePostScanRuleRow{}, err
	}
	if !ok {
		return GovernancePostScanRuleRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernancePostScanRule(id int64, patch GovernancePostScanRulePatch) (GovernancePostScanRuleRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.RuleName != nil {
		name := strings.TrimSpace(*patch.RuleName)
		if name == "" {
			return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: rule_name is required")
		}
		sets = append(sets, "rule_name = ?")
		args = append(args, name)
	}
	if patch.Priority != nil {
		sets = append(sets, "priority = ?")
		args = append(args, normalizePriority(*patch.Priority))
	}
	if patch.ResourceType != nil {
		rtype := normalizeDecisionResourceType(*patch.ResourceType)
		if !validDecisionResourceType(rtype) {
			return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: unsupported resource_type %q", *patch.ResourceType)
		}
		sets = append(sets, "resource_type = ?")
		args = append(args, rtype)
	}
	if patch.Severity != nil {
		severity := normalizePostScanSeverity(*patch.Severity)
		if !validPostScanSeverity(severity) {
			return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: unsupported severity %q", *patch.Severity)
		}
		sets = append(sets, "severity = ?")
		args = append(args, severity)
	}
	if patch.RiskLevel != nil {
		risk := normalizePostScanRiskLevel(*patch.RiskLevel)
		if !validPostScanRiskLevel(risk) {
			return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: unsupported risk_level %q", *patch.RiskLevel)
		}
		sets = append(sets, "risk_level = ?")
		args = append(args, risk)
	}
	if patch.Malicious != nil {
		sets = append(sets, "malicious = ?")
		args = append(args, boolInt(*patch.Malicious))
	}
	if patch.FindingCategory != nil {
		sets = append(sets, "finding_category = ?")
		args = append(args, strings.TrimSpace(*patch.FindingCategory))
	}
	if patch.Scanner != nil {
		sets = append(sets, "scanner = ?")
		args = append(args, strings.TrimSpace(*patch.Scanner))
	}
	if patch.Decision != nil {
		decision := normalizePostScanDecision(*patch.Decision)
		if !validPostScanDecision(decision) {
			return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: unsupported post-scan decision %q", *patch.Decision)
		}
		sets = append(sets, "decision = ?")
		args = append(args, decision)
	}
	if patch.InstallAction != nil {
		sets = append(sets, "install_action = ?")
		args = append(args, normalizeInstallAction(*patch.InstallAction))
	}
	if patch.FileAction != nil {
		sets = append(sets, "file_action = ?")
		args = append(args, normalizeFileAction(*patch.FileAction))
	}
	if patch.RuntimeAction != nil {
		sets = append(sets, "runtime_action = ?")
		args = append(args, normalizeRuntimeAction(*patch.RuntimeAction))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernancePostScanRule(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_post_scan_rule_update",
		"UPDATE resource_post_scan_rules SET "+strings.Join(sets, ", ")+" WHERE id = ? AND COALESCE(\"delete\",0) = 0", args...)
	if err != nil {
		return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: update post-scan rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernancePostScanRuleRow{}, false, nil
	}
	row, ok, err := s.GetGovernancePostScanRule(id)
	return row, ok, err
}

func (s *Store) DeleteGovernancePostScanRule(id int64) (bool, error) {
	res, err := s.execDB(context.Background(), "governance_post_scan_rule_delete",
		`UPDATE resource_post_scan_rules SET "delete" = 1, updated_at = ? WHERE id = ? AND COALESCE("delete",0) = 0`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return false, fmt.Errorf("audit: delete post-scan rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernancePostScanRule(id int64) (GovernancePostScanRuleRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_post_scan_rule_get", `
SELECT id, profile_id, COALESCE(rule_name,''), COALESCE(priority,100),
       COALESCE(resource_type,'all'), COALESCE(severity,'INFO'), COALESCE(risk_level,'clean'),
       COALESCE(malicious,0), COALESCE(finding_category,''), COALESCE(scanner,''),
       COALESCE(decision,'alert'), COALESCE(install_action,'none'), COALESCE(file_action,'none'),
       COALESCE(runtime_action,'allow'), COALESCE(enabled,0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM resource_post_scan_rules
WHERE id = ? AND COALESCE("delete",0) = 0`, id)
	if err != nil {
		return GovernancePostScanRuleRow{}, false, fmt.Errorf("audit: get post-scan rule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernancePostScanRuleRow{}, false, rows.Err()
	}
	item, err := scanGovernancePostScanRule(rows)
	return item, err == nil, err
}

func (s *Store) EvaluateResourcePreScan(profileID int64, in ResourcePreScanDecisionInput) (ResourceDecisionResult, bool, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return ResourceDecisionResult{}, false, nil
	}
	resourceType := normalizeDecisionResourceType(in.ResourceType)
	rows, err := s.queryDB(context.Background(), "resource_pre_scan_evaluate", `
SELECT r.id,
       COALESCE(r.rule_name,''),
       COALESCE(r.path_pattern,''),
       COALESCE(r.source_trust,''),
       COALESCE(r.decision,'scan'),
       COALESCE(r.install_action,'none'),
       COALESCE(r.file_action,'none'),
       COALESCE(r.runtime_action,'allow')
FROM resource_pre_scan_rules r
JOIN resource_pre_scan_profiles p ON p.id = r.profile_id
WHERE r.profile_id = ?
  AND COALESCE(p.enabled,0) = 1
  AND COALESCE(p."delete",0) = 0
  AND COALESCE(r.enabled,0) = 1
  AND COALESCE(r."delete",0) = 0
  AND (LOWER(COALESCE(r.resource_type,'all')) = 'all' OR LOWER(COALESCE(r.resource_type,'')) = ?)
  AND (COALESCE(r.agent_type_id,0) = 0 OR COALESCE(r.agent_type_id,0) = ?)
ORDER BY COALESCE(r.priority,100), r.id`, profileID, resourceType, in.AgentTypeID)
	if err != nil {
		return ResourceDecisionResult{}, false, fmt.Errorf("audit: evaluate pre-scan profile %d: %w", profileID, err)
	}
	defer rows.Close()

	for rows.Next() {
		var ruleID int64
		var name, pattern, trust, decision, installAction, fileAction, runtimeAction string
		if err := rows.Scan(&ruleID, &name, &pattern, &trust, &decision, &installAction, &fileAction, &runtimeAction); err != nil {
			return ResourceDecisionResult{}, false, fmt.Errorf("audit: scan pre-scan evaluation row: %w", err)
		}
		if !decisionPathMatches(pattern, in.Path) || !decisionTokenMatches(trust, in.SourceTrust) {
			continue
		}
		decision = normalizePreScanDecision(decision)
		return ResourceDecisionResult{
			Matched:       true,
			Phase:         "pre_scan",
			ProfileID:     profileID,
			RuleID:        ruleID,
			RuleName:      name,
			Decision:      decision,
			InstallAction: normalizeInstallAction(installAction),
			FileAction:    normalizeFileAction(fileAction),
			RuntimeAction: normalizeRuntimeAction(runtimeAction),
			Reason:        fmt.Sprintf("pre-scan rule %q matched resource type %s", name, resourceType),
		}, true, nil
	}
	if err := rows.Err(); err != nil {
		return ResourceDecisionResult{}, false, err
	}
	return ResourceDecisionResult{}, false, nil
}

func (s *Store) EvaluateResourcePostScan(profileID int64, in ResourcePostScanDecisionInput) (ResourceDecisionResult, bool, error) {
	if s == nil || s.db == nil || profileID <= 0 {
		return ResourceDecisionResult{}, false, nil
	}
	resourceType := normalizeDecisionResourceType(in.ResourceType)
	rows, err := s.queryDB(context.Background(), "resource_post_scan_evaluate", `
SELECT r.id,
       COALESCE(r.rule_name,''),
       COALESCE(r.severity,'all'),
       COALESCE(r.risk_level,'all'),
       COALESCE(r.malicious,0),
       COALESCE(r.finding_category,''),
       COALESCE(r.scanner,''),
       COALESCE(r.decision,'alert'),
       COALESCE(r.install_action,'none'),
       COALESCE(r.file_action,'none'),
       COALESCE(r.runtime_action,'allow')
FROM resource_post_scan_rules r
JOIN resource_post_scan_profiles p ON p.id = r.profile_id
WHERE r.profile_id = ?
  AND COALESCE(p.enabled,0) = 1
  AND COALESCE(p."delete",0) = 0
  AND COALESCE(r.enabled,0) = 1
  AND COALESCE(r."delete",0) = 0
  AND (LOWER(COALESCE(r.resource_type,'all')) = 'all' OR LOWER(COALESCE(r.resource_type,'')) = ?)
ORDER BY COALESCE(r.priority,100), r.id`, profileID, resourceType)
	if err != nil {
		return ResourceDecisionResult{}, false, fmt.Errorf("audit: evaluate post-scan profile %d: %w", profileID, err)
	}
	defer rows.Close()

	categories := decisionTokenSet(in.FindingCategories...)
	scanners := decisionTokenSet(append(in.FindingScanners, in.Scanner)...)
	for rows.Next() {
		var ruleID int64
		var maliciousRule int
		var name, severity, risk, category, scannerName, decision, installAction, fileAction, runtimeAction string
		if err := rows.Scan(&ruleID, &name, &severity, &risk, &maliciousRule, &category, &scannerName, &decision, &installAction, &fileAction, &runtimeAction); err != nil {
			return ResourceDecisionResult{}, false, fmt.Errorf("audit: scan post-scan evaluation row: %w", err)
		}
		if !decisionSeverityMatches(severity, in.MaxSeverity) {
			continue
		}
		if !decisionRiskMatches(risk, in.RiskLevel) {
			continue
		}
		if maliciousRule != 0 && !in.Malicious {
			continue
		}
		if !decisionSetMatches(category, categories) {
			continue
		}
		if !decisionSetMatches(scannerName, scanners) {
			continue
		}
		decision = normalizePostScanDecision(decision)
		return ResourceDecisionResult{
			Matched:       true,
			Phase:         "post_scan",
			ProfileID:     profileID,
			RuleID:        ruleID,
			RuleName:      name,
			Decision:      decision,
			InstallAction: normalizeInstallAction(installAction),
			FileAction:    normalizeFileAction(fileAction),
			RuntimeAction: normalizeRuntimeAction(runtimeAction),
			Reason:        fmt.Sprintf("post-scan rule %q matched severity %s risk %s", name, normalizeSeverity(in.MaxSeverity), normalizeRiskLevel(in.RiskLevel)),
		}, true, nil
	}
	if err := rows.Err(); err != nil {
		return ResourceDecisionResult{}, false, err
	}
	return ResourceDecisionResult{}, false, nil
}

func (s *Store) DefaultPreScanProfileID() int64 {
	return s.defaultDecisionProfileID("resource_pre_scan_profiles")
}

func (s *Store) DefaultPostScanProfileID() int64 {
	return s.defaultDecisionProfileID("resource_post_scan_profiles")
}

func (s *Store) defaultDecisionProfileID(table string) int64 {
	if s == nil || s.db == nil {
		return 0
	}
	var id int64
	query := fmt.Sprintf(`SELECT id FROM %s WHERE COALESCE(is_default,0) = 1 AND COALESCE("delete",0) = 0 ORDER BY id LIMIT 1`, table)
	_ = s.scanRow(context.Background(), "governance_default_decision_profile", s.db.QueryRowContext(context.Background(), query), &id)
	return id
}

func (s *Store) setPreScanDefaultProfile(id int64) error {
	return s.setDefaultDecisionProfile("resource_pre_scan_profiles", id)
}

func (s *Store) setPostScanDefaultProfile(id int64) error {
	return s.setDefaultDecisionProfile("resource_post_scan_profiles", id)
}

func (s *Store) setDefaultDecisionProfile(table string, id int64) error {
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("audit: begin default decision profile update: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	query := fmt.Sprintf(`UPDATE %s SET is_default = CASE WHEN id = ? THEN 1 ELSE 0 END, updated_at = ? WHERE COALESCE("delete",0) = 0`, table)
	res, err := tx.ExecContext(ctx, query, id, now)
	if err != nil {
		return fmt.Errorf("audit: set default decision profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	check := fmt.Sprintf(`SELECT COUNT(*) FROM %s WHERE id = ? AND is_default = 1 AND COALESCE("delete",0) = 0`, table)
	var count int
	if err := tx.QueryRowContext(ctx, check, id).Scan(&count); err != nil {
		return fmt.Errorf("audit: verify default decision profile: %w", err)
	}
	if count == 0 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: commit default decision profile update: %w", err)
	}
	return nil
}

func scanGovernancePreScanProfile(rows *sql.Rows) (GovernancePreScanProfileRow, error) {
	var item GovernancePreScanProfileRow
	var enabled, isDefault int
	if err := rows.Scan(&item.ID, &item.ProfileKey, &item.Name, &item.Description,
		&enabled, &isDefault, &item.RuleCount, &item.ResourceRuleCount,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan pre-scan profile row: %w", err)
	}
	item.Enabled = enabled != 0
	item.IsDefault = isDefault != 0
	return item, nil
}

func scanGovernancePreScanRule(rows *sql.Rows) (GovernancePreScanRuleRow, error) {
	var item GovernancePreScanRuleRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.ProfileID, &item.RuleName, &item.Priority,
		&item.AgentTypeID, &item.AgentTypeKey, &item.AgentTypeName, &item.ResourceType,
		&item.PathPattern, &item.SourceTrust, &item.Decision, &item.InstallAction,
		&item.FileAction, &item.RuntimeAction, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan pre-scan rule row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernancePostScanProfile(rows *sql.Rows) (GovernancePostScanProfileRow, error) {
	var item GovernancePostScanProfileRow
	var enabled, isDefault int
	if err := rows.Scan(&item.ID, &item.ProfileKey, &item.Name, &item.Description,
		&enabled, &isDefault, &item.RuleCount, &item.ResourceRuleCount,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan post-scan profile row: %w", err)
	}
	item.Enabled = enabled != 0
	item.IsDefault = isDefault != 0
	return item, nil
}

func scanGovernancePostScanRule(rows *sql.Rows) (GovernancePostScanRuleRow, error) {
	var item GovernancePostScanRuleRow
	var enabled, malicious int
	if err := rows.Scan(&item.ID, &item.ProfileID, &item.RuleName, &item.Priority,
		&item.ResourceType, &item.Severity, &item.RiskLevel, &malicious,
		&item.FindingCategory, &item.Scanner, &item.Decision, &item.InstallAction,
		&item.FileAction, &item.RuntimeAction, &enabled, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan post-scan rule row: %w", err)
	}
	item.Enabled = enabled != 0
	item.Malicious = malicious != 0
	return item, nil
}

type sqlContextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertPreScanRule(ctx context.Context, ex sqlContextExecer, profileID int64, in GovernancePreScanRuleInput, now string) (sql.Result, error) {
	if err := validatePreScanRuleInput(profileID, in); err != nil {
		return nil, err
	}
	return ex.ExecContext(ctx, `
INSERT INTO resource_pre_scan_rules (
  profile_id, rule_name, priority, agent_type_id, resource_type, path_pattern, source_trust,
  decision, install_action, file_action, runtime_action, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(profile_id, rule_name) DO UPDATE SET
  priority = excluded.priority,
  agent_type_id = excluded.agent_type_id,
  resource_type = excluded.resource_type,
  path_pattern = excluded.path_pattern,
  source_trust = excluded.source_trust,
  decision = excluded.decision,
  install_action = excluded.install_action,
  file_action = excluded.file_action,
  runtime_action = excluded.runtime_action,
  enabled = excluded.enabled,
  updated_at = excluded.updated_at,
  "delete" = 0`,
		profileID, strings.TrimSpace(in.RuleName), normalizePriority(in.Priority),
		nullInt64Value(in.AgentTypeID), normalizeDecisionResourceType(in.ResourceType),
		strings.TrimSpace(in.PathPattern), strings.TrimSpace(in.SourceTrust),
		normalizePreScanDecision(in.Decision), normalizeInstallAction(in.InstallAction),
		normalizeFileAction(in.FileAction), normalizeRuntimeAction(in.RuntimeAction),
		boolInt(in.Enabled), now, now)
}

func insertPostScanRule(ctx context.Context, ex sqlContextExecer, profileID int64, in GovernancePostScanRuleInput, now string) (sql.Result, error) {
	if err := validatePostScanRuleInput(profileID, in); err != nil {
		return nil, err
	}
	return ex.ExecContext(ctx, `
INSERT INTO resource_post_scan_rules (
  profile_id, rule_name, priority, resource_type, severity, risk_level, malicious, finding_category, scanner,
  decision, install_action, file_action, runtime_action, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(profile_id, rule_name) DO UPDATE SET
  priority = excluded.priority,
  resource_type = excluded.resource_type,
  severity = excluded.severity,
  risk_level = excluded.risk_level,
  malicious = excluded.malicious,
  finding_category = excluded.finding_category,
  scanner = excluded.scanner,
  decision = excluded.decision,
  install_action = excluded.install_action,
  file_action = excluded.file_action,
  runtime_action = excluded.runtime_action,
  enabled = excluded.enabled,
  updated_at = excluded.updated_at,
  "delete" = 0`,
		profileID, strings.TrimSpace(in.RuleName), normalizePriority(in.Priority),
		normalizeDecisionResourceType(in.ResourceType), normalizePostScanSeverity(in.Severity),
		normalizePostScanRiskLevel(in.RiskLevel), boolInt(in.Malicious), strings.TrimSpace(in.FindingCategory),
		strings.TrimSpace(in.Scanner), normalizePostScanDecision(in.Decision),
		normalizeInstallAction(in.InstallAction), normalizeFileAction(in.FileAction),
		normalizeRuntimeAction(in.RuntimeAction), boolInt(in.Enabled), now, now)
}

func validateDecisionProfileInput(profileKey, name string) error {
	if normalizeDecisionProfileKey(profileKey) == "" {
		return fmt.Errorf("audit: profile_key is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("audit: name is required")
	}
	return nil
}

func validatePreScanRuleInput(profileID int64, in GovernancePreScanRuleInput) error {
	if profileID <= 0 {
		return fmt.Errorf("audit: profile_id is required")
	}
	if strings.TrimSpace(in.RuleName) == "" {
		return fmt.Errorf("audit: rule_name is required")
	}
	if !validDecisionResourceType(normalizeDecisionResourceType(in.ResourceType)) {
		return fmt.Errorf("audit: unsupported resource_type %q", in.ResourceType)
	}
	if !validPreScanDecision(normalizePreScanDecision(in.Decision)) {
		return fmt.Errorf("audit: unsupported pre-scan decision %q", in.Decision)
	}
	return validateDecisionActions(in.InstallAction, in.FileAction, in.RuntimeAction)
}

func validatePostScanRuleInput(profileID int64, in GovernancePostScanRuleInput) error {
	if profileID <= 0 {
		return fmt.Errorf("audit: profile_id is required")
	}
	if strings.TrimSpace(in.RuleName) == "" {
		return fmt.Errorf("audit: rule_name is required")
	}
	if !validDecisionResourceType(normalizeDecisionResourceType(in.ResourceType)) {
		return fmt.Errorf("audit: unsupported resource_type %q", in.ResourceType)
	}
	if !validPostScanSeverity(normalizePostScanSeverity(in.Severity)) {
		return fmt.Errorf("audit: unsupported severity %q", in.Severity)
	}
	if !validPostScanRiskLevel(normalizePostScanRiskLevel(in.RiskLevel)) {
		return fmt.Errorf("audit: unsupported risk_level %q", in.RiskLevel)
	}
	if !validPostScanDecision(normalizePostScanDecision(in.Decision)) {
		return fmt.Errorf("audit: unsupported post-scan decision %q", in.Decision)
	}
	return validateDecisionActions(in.InstallAction, in.FileAction, in.RuntimeAction)
}

func validateDecisionActions(install, file, runtime string) error {
	if !validInstallAction(normalizeInstallAction(install)) {
		return fmt.Errorf("audit: unsupported install_action %q", install)
	}
	if !validFileAction(normalizeFileAction(file)) {
		return fmt.Errorf("audit: unsupported file_action %q", file)
	}
	if !validRuntimeAction(normalizeRuntimeAction(runtime)) {
		return fmt.Errorf("audit: unsupported runtime_action %q", runtime)
	}
	return nil
}

func normalizeDecisionProfileKey(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeDecisionResourceType(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "all"
	}
	return v
}

func validDecisionResourceType(v string) bool {
	if normalizeDecisionResourceType(v) == "all" {
		return true
	}
	return validResourceType(v)
}

func normalizePreScanDecision(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "scan"
	}
	return v
}

func validPreScanDecision(v string) bool {
	switch normalizePreScanDecision(v) {
	case "scan", "skip", "block", "allow", "review", "alert", "reject", "rejected":
		return true
	default:
		return false
	}
}

func normalizePostScanDecision(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "alert"
	}
	return v
}

func validPostScanDecision(v string) bool {
	switch normalizePostScanDecision(v) {
	case "alert", "block", "allow", "review", "reject", "rejected", "clean", "ignore":
		return true
	default:
		return false
	}
}

func normalizePostScanSeverity(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "all") || v == "*" {
		return "all"
	}
	return normalizeSeverity(v)
}

func validPostScanSeverity(v string) bool {
	if normalizePostScanSeverity(v) == "all" {
		return true
	}
	return validSeverity(v)
}

func normalizePostScanRiskLevel(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "all") || v == "*" {
		return "all"
	}
	return normalizeRiskLevel(v)
}

func validPostScanRiskLevel(v string) bool {
	if normalizePostScanRiskLevel(v) == "all" {
		return true
	}
	return validRiskLevel(v)
}

func normalizeInstallAction(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "none"
	}
	return v
}

func validInstallAction(v string) bool {
	switch normalizeInstallAction(v) {
	case "none", "allow", "block":
		return true
	default:
		return false
	}
}

func normalizeFileAction(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "none"
	}
	return v
}

func validFileAction(v string) bool {
	switch normalizeFileAction(v) {
	case "none", "quarantine":
		return true
	default:
		return false
	}
}

func normalizeRuntimeAction(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "allow"
	}
	return v
}

func validRuntimeAction(v string) bool {
	switch normalizeRuntimeAction(v) {
	case "none", "allow", "block", "disable", "enable":
		return true
	default:
		return false
	}
}

func normalizeSeverity(v string) string {
	v = strings.ToUpper(strings.TrimSpace(v))
	if v == "" {
		return "INFO"
	}
	return v
}

func validSeverity(v string) bool {
	switch normalizeSeverity(v) {
	case "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func normalizeRiskLevel(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "clean"
	}
	return v
}

func validRiskLevel(v string) bool {
	switch normalizeRiskLevel(v) {
	case "clean", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

func decisionPathMatches(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if decisionIsWildcard(pattern) {
		return true
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	p := decisionNormalizePath(pattern)
	v := decisionNormalizePath(value)
	if ok, _ := path.Match(p, v); ok {
		return true
	}
	if ok, _ := path.Match(p, path.Base(v)); ok {
		return true
	}
	return strings.Contains(v, p)
}

func decisionTokenMatches(ruleValue, inputValue string) bool {
	if decisionIsWildcard(ruleValue) {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(ruleValue), strings.TrimSpace(inputValue))
}

func decisionSeverityMatches(ruleValue, current string) bool {
	if decisionIsWildcard(ruleValue) {
		return true
	}
	return normalizeSeverity(ruleValue) == normalizeSeverity(current)
}

func decisionRiskMatches(ruleValue, current string) bool {
	if decisionIsWildcard(ruleValue) {
		return true
	}
	return normalizeRiskLevel(ruleValue) == normalizeRiskLevel(current)
}

func decisionSetMatches(ruleValue string, candidates map[string]bool) bool {
	if decisionIsWildcard(ruleValue) {
		return true
	}
	for _, token := range splitDecisionTokens(ruleValue) {
		if candidates[token] {
			return true
		}
	}
	return false
}

func decisionTokenSet(values ...string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		for _, token := range splitDecisionTokens(value) {
			out[token] = true
		}
	}
	return out
}

func splitDecisionTokens(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == ';' || r == '|'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToLower(strings.TrimSpace(part))
		if part != "" && part != "all" && part != "*" {
			out = append(out, part)
		}
	}
	return out
}

func decisionIsWildcard(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "" || value == "all" || value == "*"
}

func decisionNormalizePath(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\\", "/")
	for strings.Contains(value, "//") {
		value = strings.ReplaceAll(value, "//", "/")
	}
	return strings.ToLower(value)
}

func seedResourceDecisionProfiles(ex dbExecer) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	preID, err := seedDefaultPreScanProfile(ex, now)
	if err != nil {
		return err
	}
	postID, err := seedDefaultPostScanProfile(ex, now)
	if err != nil {
		return err
	}
	for _, rule := range defaultPreScanRules() {
		if _, err := insertPreScanRule(context.Background(), dbContextAdapter{ex}, preID, rule, now); err != nil {
			return fmt.Errorf("seed pre-scan rule %q: %w", rule.RuleName, err)
		}
	}
	for _, rule := range defaultPostScanRules() {
		if _, err := insertPostScanRule(context.Background(), dbContextAdapter{ex}, postID, rule, now); err != nil {
			return fmt.Errorf("seed post-scan rule %q: %w", rule.RuleName, err)
		}
	}
	if _, err := ex.Exec(`UPDATE agent_resource_rules SET pre_scan_profile_id = ? WHERE pre_scan_profile_id IS NULL OR pre_scan_profile_id <= 0`, preID); err != nil {
		return fmt.Errorf("backfill agent_resource_rules.pre_scan_profile_id: %w", err)
	}
	if _, err := ex.Exec(`UPDATE agent_resource_rules SET post_scan_profile_id = ? WHERE post_scan_profile_id IS NULL OR post_scan_profile_id <= 0`, postID); err != nil {
		return fmt.Errorf("backfill agent_resource_rules.post_scan_profile_id: %w", err)
	}
	return nil
}

type dbContextAdapter struct {
	ex dbExecer
}

func (a dbContextAdapter) ExecContext(_ context.Context, query string, args ...any) (sql.Result, error) {
	return a.ex.Exec(query, args...)
}

func seedDefaultPreScanProfile(ex dbExecer, now string) (int64, error) {
	if _, err := ex.Exec(`
UPDATE resource_pre_scan_profiles
SET is_default = 0, updated_at = ?
WHERE profile_key <> ? AND COALESCE(is_default,0) = 1 AND COALESCE("delete",0) = 0`,
		now, defaultPreScanProfileKey); err != nil {
		return 0, fmt.Errorf("clear default pre-scan profile: %w", err)
	}
	if _, err := ex.Exec(`
INSERT INTO resource_pre_scan_profiles (profile_key, name, description, enabled, is_default, created_at, updated_at)
VALUES (?, '默认 Pre-scan 方案', '资源发现后、扫描前的默认准入决策方案。', 1, 1, ?, ?)
ON CONFLICT(profile_key) DO UPDATE SET
  is_default = 1,
  "delete" = 0`,
		defaultPreScanProfileKey, now, now); err != nil {
		return 0, fmt.Errorf("seed default pre-scan profile: %w", err)
	}
	var id int64
	if err := ex.QueryRow(`SELECT id FROM resource_pre_scan_profiles WHERE profile_key = ? AND COALESCE("delete",0) = 0`, defaultPreScanProfileKey).Scan(&id); err != nil {
		return 0, fmt.Errorf("lookup default pre-scan profile: %w", err)
	}
	return id, nil
}

func seedDefaultPostScanProfile(ex dbExecer, now string) (int64, error) {
	if _, err := ex.Exec(`
UPDATE resource_post_scan_profiles
SET is_default = 0, updated_at = ?
WHERE profile_key <> ? AND COALESCE(is_default,0) = 1 AND COALESCE("delete",0) = 0`,
		now, defaultPostScanProfileKey); err != nil {
		return 0, fmt.Errorf("clear default post-scan profile: %w", err)
	}
	if _, err := ex.Exec(`
INSERT INTO resource_post_scan_profiles (profile_key, name, description, enabled, is_default, created_at, updated_at)
VALUES (?, '默认 Post-scan 方案', '扫描完成后按严重级别和风险结论执行默认处置。', 1, 1, ?, ?)
ON CONFLICT(profile_key) DO UPDATE SET
  is_default = 1,
  "delete" = 0`,
		defaultPostScanProfileKey, now, now); err != nil {
		return 0, fmt.Errorf("seed default post-scan profile: %w", err)
	}
	var id int64
	if err := ex.QueryRow(`SELECT id FROM resource_post_scan_profiles WHERE profile_key = ? AND COALESCE("delete",0) = 0`, defaultPostScanProfileKey).Scan(&id); err != nil {
		return 0, fmt.Errorf("lookup default post-scan profile: %w", err)
	}
	return id, nil
}

func defaultPreScanRules() []GovernancePreScanRuleInput {
	return []GovernancePreScanRuleInput{
		{
			RuleName:      "默认扫描",
			Priority:      100,
			ResourceType:  "all",
			Decision:      "scan",
			InstallAction: "none",
			FileAction:    "none",
			RuntimeAction: "allow",
			Enabled:       true,
		},
	}
}

func defaultPostScanRules() []GovernancePostScanRuleInput {
	return []GovernancePostScanRuleInput{
		{RuleName: "严重风险阻断", Priority: 10, ResourceType: "all", Severity: "CRITICAL", RiskLevel: "critical", Decision: "block", InstallAction: "block", FileAction: "quarantine", RuntimeAction: "block", Enabled: true},
		{RuleName: "高风险阻断", Priority: 20, ResourceType: "all", Severity: "HIGH", RiskLevel: "high", Decision: "block", InstallAction: "block", FileAction: "quarantine", RuntimeAction: "block", Enabled: true},
		{RuleName: "中风险告警", Priority: 30, ResourceType: "all", Severity: "MEDIUM", RiskLevel: "medium", Decision: "alert", InstallAction: "none", FileAction: "none", RuntimeAction: "allow", Enabled: true},
		{RuleName: "低风险告警", Priority: 40, ResourceType: "all", Severity: "LOW", RiskLevel: "low", Decision: "alert", InstallAction: "none", FileAction: "none", RuntimeAction: "allow", Enabled: true},
		{RuleName: "无风险放行", Priority: 50, ResourceType: "all", Severity: "INFO", RiskLevel: "clean", Decision: "allow", InstallAction: "none", FileAction: "none", RuntimeAction: "allow", Enabled: true},
	}
}
