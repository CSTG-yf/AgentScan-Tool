// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrGovernanceConflict = errors.New("audit: governance conflict")

type GovernancePageFilter struct {
	Keyword       string
	Enabled       *bool
	Page          int
	PageSize      int
	Kind          string
	Runtime       string
	AgentTypeID   int64
	TypeKey       string
	ResourceType  string
	ScanProfileID int64
	TargetType    string
	TargetName    string
	Connector     string
	ActionField   string
	ActionValue   string
}

type GovernanceAgentTypePage struct {
	Total    int                      `json:"total"`
	Page     int                      `json:"page"`
	PageSize int                      `json:"page_size"`
	Items    []GovernanceAgentTypeRow `json:"items"`
}

type GovernanceAgentTypeRow struct {
	ID                 int64  `json:"id"`
	TypeKey            string `json:"type_key"`
	Name               string `json:"name"`
	Vendor             string `json:"vendor"`
	Kind               string `json:"kind"`
	Runtime            string `json:"runtime"`
	Description        string `json:"description"`
	Enabled            bool   `json:"enabled"`
	Deleted            bool   `json:"deleted"`
	CreatedAt          string `json:"created_at"`
	UpdatedAt          string `json:"updated_at"`
	AgentCount         int    `json:"agent_count"`
	DiscoveryRuleCount int    `json:"discovery_rule_count"`
	ResourceRuleCount  int    `json:"resource_rule_count"`
}

type GovernanceAgentTypeInput struct {
	TypeKey     string `json:"type_key"`
	Name        string `json:"name"`
	Vendor      string `json:"vendor"`
	Kind        string `json:"kind"`
	Runtime     string `json:"runtime"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

type GovernanceAgentTypePatch struct {
	TypeKey     *string `json:"type_key,omitempty"`
	Name        *string `json:"name,omitempty"`
	Vendor      *string `json:"vendor,omitempty"`
	Kind        *string `json:"kind,omitempty"`
	Runtime     *string `json:"runtime,omitempty"`
	Description *string `json:"description,omitempty"`
	Enabled     *bool   `json:"enabled,omitempty"`
}

type GovernanceDiscoveryRulePage struct {
	Total    int                          `json:"total"`
	Page     int                          `json:"page"`
	PageSize int                          `json:"page_size"`
	Items    []GovernanceDiscoveryRuleRow `json:"items"`
}

type GovernanceDiscoveryRuleRow struct {
	ID             int64                             `json:"id"`
	AgentTypeID    int64                             `json:"agent_type_id"`
	AgentTypeKey   string                            `json:"agent_type_key"`
	AgentTypeName  string                            `json:"agent_type_name"`
	RuleName       string                            `json:"rule_name"`
	Threshold      int                               `json:"threshold"`
	Enabled        bool                              `json:"enabled"`
	ConditionCount int                               `json:"condition_count"`
	Conditions     []GovernanceDiscoveryConditionRow `json:"conditions,omitempty"`
	CreatedAt      string                            `json:"created_at"`
	UpdatedAt      string                            `json:"updated_at"`
}

type GovernanceDiscoveryConditionRow struct {
	ID            int64  `json:"id"`
	RuleID        int64  `json:"rule_id"`
	ConditionType string `json:"condition_type"`
	Field         string `json:"field"`
	Operator      string `json:"operator"`
	Value         string `json:"value"`
	Weight        int    `json:"weight"`
	Required      bool   `json:"required"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type GovernanceDiscoveryRuleInput struct {
	AgentTypeID int64                               `json:"agent_type_id"`
	RuleName    string                              `json:"rule_name"`
	Threshold   int                                 `json:"threshold"`
	Enabled     bool                                `json:"enabled"`
	Conditions  []GovernanceDiscoveryConditionInput `json:"conditions,omitempty"`
}

type GovernanceDiscoveryRulePatch struct {
	RuleName  *string `json:"rule_name,omitempty"`
	Threshold *int    `json:"threshold,omitempty"`
	Enabled   *bool   `json:"enabled,omitempty"`
}

type GovernanceDiscoveryConditionInput struct {
	RuleID        int64  `json:"rule_id,omitempty"`
	ConditionType string `json:"condition_type"`
	Field         string `json:"field"`
	Operator      string `json:"operator"`
	Value         string `json:"value"`
	Weight        int    `json:"weight"`
	Required      bool   `json:"required"`
	Enabled       bool   `json:"enabled"`
}

type GovernanceDiscoveryConditionPatch struct {
	ConditionType *string `json:"condition_type,omitempty"`
	Field         *string `json:"field,omitempty"`
	Operator      *string `json:"operator,omitempty"`
	Value         *string `json:"value,omitempty"`
	Weight        *int    `json:"weight,omitempty"`
	Required      *bool   `json:"required,omitempty"`
	Enabled       *bool   `json:"enabled,omitempty"`
}

type GovernanceResourceRulePage struct {
	Total    int                         `json:"total"`
	Page     int                         `json:"page"`
	PageSize int                         `json:"page_size"`
	Items    []GovernanceResourceRuleRow `json:"items"`
}

type GovernanceResourceRuleRow struct {
	ID              int64  `json:"id"`
	AgentTypeID     int64  `json:"agent_type_id"`
	AgentTypeKey    string `json:"agent_type_key"`
	AgentTypeName   string `json:"agent_type_name"`
	Name            string `json:"name"`
	ResourceType    string `json:"resource_type"`
	PathPattern     string `json:"path_pattern"`
	EnumerationMode string `json:"enumeration_mode"`
	ScanProfileID   int64  `json:"scan_profile_id,omitempty"`
	ScanProfileName string `json:"scan_profile_name,omitempty"`
	Enabled         bool   `json:"enabled"`
	Priority        int    `json:"priority"`
	ResourceCount   int    `json:"resource_count"`
	CreatedAt       string `json:"created_at"`
	UpdatedAt       string `json:"updated_at"`
}

type GovernanceResourceRuleInput struct {
	AgentTypeID     int64  `json:"agent_type_id"`
	Name            string `json:"name"`
	ResourceType    string `json:"resource_type"`
	PathPattern     string `json:"path_pattern"`
	EnumerationMode string `json:"enumeration_mode"`
	ScanProfileID   int64  `json:"scan_profile_id,omitempty"`
	Enabled         bool   `json:"enabled"`
	Priority        int    `json:"priority"`
}

type GovernanceResourceRulePatch struct {
	AgentTypeID     *int64  `json:"agent_type_id,omitempty"`
	Name            *string `json:"name,omitempty"`
	ResourceType    *string `json:"resource_type,omitempty"`
	PathPattern     *string `json:"path_pattern,omitempty"`
	EnumerationMode *string `json:"enumeration_mode,omitempty"`
	ScanProfileID   *int64  `json:"scan_profile_id,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
	Priority        *int    `json:"priority,omitempty"`
}

type GovernanceScanProfilePage struct {
	Total    int                        `json:"total"`
	Page     int                        `json:"page"`
	PageSize int                        `json:"page_size"`
	Items    []GovernanceScanProfileRow `json:"items"`
}

type GovernanceScanProfileRow struct {
	ID              int                              `json:"id"`
	Name            string                           `json:"name"`
	ResourceType    string                           `json:"resource_type"`
	Enabled         bool                             `json:"enabled"`
	Description     string                           `json:"description"`
	CapabilityCount int                              `json:"capability_count"`
	RuleCount       int                              `json:"rule_count"`
	ResourceCount   int                              `json:"resource_count"`
	Capabilities    []GovernanceProfileCapabilityRow `json:"capabilities,omitempty"`
	CreatedAt       string                           `json:"created_at"`
	UpdatedAt       string                           `json:"updated_at"`
}

type GovernanceScanCapabilityRow struct {
	ID            int64  `json:"id"`
	CapabilityKey string `json:"capability_key"`
	Name          string `json:"name"`
	ScannerName   string `json:"scanner_name"`
	Enabled       bool   `json:"enabled"`
	Description   string `json:"description"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

type GovernanceProfileCapabilityRow struct {
	ProfileID     int64  `json:"profile_id"`
	CapabilityID  int64  `json:"capability_id"`
	CapabilityKey string `json:"capability_key"`
	Name          string `json:"name"`
	ScannerName   string `json:"scanner_name"`
	Priority      int    `json:"priority"`
	Enabled       bool   `json:"enabled"`
	ConfigJSON    string `json:"config_json"`
	Description   string `json:"description"`
}

type GovernanceScanProfileInput struct {
	Name         string                             `json:"name"`
	ResourceType string                             `json:"resource_type"`
	Description  string                             `json:"description"`
	Enabled      bool                               `json:"enabled"`
	Capabilities []GovernanceProfileCapabilityInput `json:"capabilities,omitempty"`
}

type GovernanceScanProfilePatch struct {
	Name         *string `json:"name,omitempty"`
	ResourceType *string `json:"resource_type,omitempty"`
	Description  *string `json:"description,omitempty"`
	Enabled      *bool   `json:"enabled,omitempty"`
}

type GovernanceProfileCapabilityInput struct {
	CapabilityID  int64  `json:"capability_id,omitempty"`
	CapabilityKey string `json:"capability_key,omitempty"`
	Priority      int    `json:"priority"`
	Enabled       bool   `json:"enabled"`
	ConfigJSON    string `json:"config_json,omitempty"`
}

type GovernanceResourceActionPage struct {
	Total    int                           `json:"total"`
	Page     int                           `json:"page"`
	PageSize int                           `json:"page_size"`
	Items    []GovernanceResourceActionRow `json:"items"`
}

type GovernanceResourceActionRow struct {
	ID         string      `json:"id"`
	TargetType string      `json:"target_type"`
	TargetName string      `json:"target_name"`
	Connector  string      `json:"connector"`
	SourcePath string      `json:"source_path"`
	Actions    ActionState `json:"actions"`
	Reason     string      `json:"reason"`
	UpdatedAt  string      `json:"updated_at"`
}

type GovernanceResourceActionInput struct {
	TargetType string      `json:"target_type"`
	TargetName string      `json:"target_name"`
	Connector  string      `json:"connector"`
	SourcePath string      `json:"source_path"`
	Actions    ActionState `json:"actions"`
	Reason     string      `json:"reason"`
}

type GovernanceActionStatePatch struct {
	File    *string `json:"file,omitempty"`
	Runtime *string `json:"runtime,omitempty"`
	Install *string `json:"install,omitempty"`
}

type GovernanceResourceActionPatch struct {
	SourcePath *string                     `json:"source_path,omitempty"`
	Actions    *GovernanceActionStatePatch `json:"actions,omitempty"`
	Reason     *string                     `json:"reason,omitempty"`
}

func (s *Store) ListGovernanceAgentTypes(f GovernancePageFilter) (*GovernanceAgentTypePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE(t."delete",0) = 0`}
	var args []any
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(t.type_key) LIKE ? OR LOWER(t.name) LIKE ? OR LOWER(t.vendor) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	if f.Enabled != nil {
		where = append(where, "COALESCE(t.enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Kind = strings.TrimSpace(f.Kind); f.Kind != "" {
		where = append(where, "LOWER(COALESCE(t.kind,'')) = ?")
		args = append(args, strings.ToLower(f.Kind))
	}
	if f.Runtime = strings.TrimSpace(f.Runtime); f.Runtime != "" {
		where = append(where, "LOWER(COALESCE(t.runtime,'')) = ?")
		args = append(args, strings.ToLower(f.Runtime))
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_agent_type_count", "SELECT COUNT(*) FROM agent_types t WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_agent_type_list", `
SELECT t.id, COALESCE(t.type_key,''), COALESCE(t.name,''), COALESCE(t.vendor,''),
       COALESCE(t.kind,''), COALESCE(t.runtime,''), COALESCE(t.description,''),
       COALESCE(t.enabled,0), COALESCE(t."delete",0), COALESCE(CAST(t.created_at AS TEXT), ''),
       COALESCE(CAST(t.updated_at AS TEXT), ''),
       (SELECT COUNT(*) FROM agents a WHERE COALESCE(a.agent_type_id,0) = t.id),
       (SELECT COUNT(*) FROM agent_discovery_rules r WHERE r.agent_type_id = t.id),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE rr.agent_type_id = t.id)
FROM agent_types t
WHERE `+clause+`
ORDER BY COALESCE(t.enabled,0) DESC, LOWER(t.name), t.id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list governance agent types: %w", err)
	}
	defer rows.Close()
	out := &GovernanceAgentTypePage{Total: total, Page: page, PageSize: size, Items: []GovernanceAgentTypeRow{}}
	for rows.Next() {
		item, err := scanGovernanceAgentType(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernanceAgentType(in GovernanceAgentTypeInput) (GovernanceAgentTypeRow, error) {
	if err := validateAgentTypeInput(in.TypeKey, in.Name); err != nil {
		return GovernanceAgentTypeRow{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.execDB(context.Background(), "governance_agent_type_create", `
INSERT INTO agent_types (type_key, name, vendor, kind, runtime, description, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		normalizeKey(in.TypeKey), strings.TrimSpace(in.Name), strings.TrimSpace(in.Vendor),
		strings.TrimSpace(in.Kind), strings.TrimSpace(in.Runtime), strings.TrimSpace(in.Description),
		boolInt(in.Enabled), now, now)
	if err != nil {
		return GovernanceAgentTypeRow{}, fmt.Errorf("audit: create agent type: %w", err)
	}
	id, _ := res.LastInsertId()
	row, ok, err := s.GetGovernanceAgentType(id)
	if err != nil {
		return GovernanceAgentTypeRow{}, err
	}
	if !ok {
		return GovernanceAgentTypeRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceAgentType(id int64, patch GovernanceAgentTypePatch) (GovernanceAgentTypeRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.TypeKey != nil {
		if err := validateAgentTypeInput(*patch.TypeKey, "placeholder"); err != nil {
			return GovernanceAgentTypeRow{}, false, err
		}
		sets = append(sets, "type_key = ?")
		args = append(args, normalizeKey(*patch.TypeKey))
	}
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return GovernanceAgentTypeRow{}, false, fmt.Errorf("audit: name is required")
		}
		sets = append(sets, "name = ?")
		args = append(args, name)
	}
	if patch.Vendor != nil {
		sets = append(sets, "vendor = ?")
		args = append(args, strings.TrimSpace(*patch.Vendor))
	}
	if patch.Kind != nil {
		sets = append(sets, "kind = ?")
		args = append(args, strings.TrimSpace(*patch.Kind))
	}
	if patch.Runtime != nil {
		sets = append(sets, "runtime = ?")
		args = append(args, strings.TrimSpace(*patch.Runtime))
	}
	if patch.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, strings.TrimSpace(*patch.Description))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernanceAgentType(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_agent_type_update",
		"UPDATE agent_types SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return GovernanceAgentTypeRow{}, false, fmt.Errorf("audit: update agent type: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernanceAgentTypeRow{}, false, nil
	}
	row, ok, err := s.GetGovernanceAgentType(id)
	return row, ok, err
}

func (s *Store) DisableGovernanceAgentType(id int64) (GovernanceAgentTypeRow, bool, error) {
	return s.UpdateGovernanceAgentType(id, GovernanceAgentTypePatch{Enabled: ptrBool(false)})
}

func (s *Store) DeleteGovernanceAgentType(id int64) (GovernanceAgentTypeRow, bool, error) {
	res, err := s.execDB(context.Background(), "governance_agent_type_delete",
		`UPDATE agent_types SET "delete" = 1, updated_at = ? WHERE id = ? AND COALESCE("delete",0) = 0`,
		time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return GovernanceAgentTypeRow{}, false, fmt.Errorf("audit: delete agent type: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		row, ok, err := s.GetGovernanceAgentType(id)
		if err != nil {
			return GovernanceAgentTypeRow{}, false, err
		}
		return row, ok, nil
	}
	row, ok, err := s.GetGovernanceAgentType(id)
	return row, ok, err
}

func (s *Store) GetGovernanceAgentType(id int64) (GovernanceAgentTypeRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_agent_type_get", `
SELECT t.id, COALESCE(t.type_key,''), COALESCE(t.name,''), COALESCE(t.vendor,''),
       COALESCE(t.kind,''), COALESCE(t.runtime,''), COALESCE(t.description,''),
       COALESCE(t.enabled,0), COALESCE(t."delete",0), COALESCE(CAST(t.created_at AS TEXT), ''),
       COALESCE(CAST(t.updated_at AS TEXT), ''),
       (SELECT COUNT(*) FROM agents a WHERE COALESCE(a.agent_type_id,0) = t.id),
       (SELECT COUNT(*) FROM agent_discovery_rules r WHERE r.agent_type_id = t.id),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE rr.agent_type_id = t.id)
FROM agent_types t
WHERE t.id = ?`, id)
	if err != nil {
		return GovernanceAgentTypeRow{}, false, fmt.Errorf("audit: get agent type: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernanceAgentTypeRow{}, false, rows.Err()
	}
	item, err := scanGovernanceAgentType(rows)
	if err != nil {
		return GovernanceAgentTypeRow{}, false, err
	}
	return item, true, rows.Err()
}

func (s *Store) ListGovernanceDiscoveryRules(f GovernancePageFilter) (*GovernanceDiscoveryRulePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE(t."delete",0) = 0`}
	var args []any
	if f.AgentTypeID > 0 {
		where = append(where, "r.agent_type_id = ?")
		args = append(args, f.AgentTypeID)
	}
	if f.TypeKey = strings.TrimSpace(f.TypeKey); f.TypeKey != "" {
		where = append(where, "LOWER(COALESCE(t.type_key,'')) = ?")
		args = append(args, strings.ToLower(f.TypeKey))
	}
	if f.Enabled != nil {
		where = append(where, "COALESCE(r.enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(r.rule_name) LIKE ? OR LOWER(COALESCE(t.name,'')) LIKE ? OR LOWER(COALESCE(t.type_key,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_discovery_rule_count", `
SELECT COUNT(*)
FROM agent_discovery_rules r
JOIN agent_types t ON t.id = r.agent_type_id
WHERE `+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_discovery_rule_list", `
SELECT r.id, r.agent_type_id, COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(r.rule_name,''), COALESCE(r.threshold,60), COALESCE(r.enabled,0),
       (SELECT COUNT(*) FROM agent_discovery_conditions c WHERE c.rule_id = r.id),
       COALESCE(CAST(r.created_at AS TEXT), ''), COALESCE(CAST(r.updated_at AS TEXT), '')
FROM agent_discovery_rules r
JOIN agent_types t ON t.id = r.agent_type_id
WHERE `+clause+`
ORDER BY COALESCE(r.enabled,0) DESC, COALESCE(t.type_key,''), r.id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list discovery rules: %w", err)
	}
	defer rows.Close()
	out := &GovernanceDiscoveryRulePage{Total: total, Page: page, PageSize: size, Items: []GovernanceDiscoveryRuleRow{}}
	for rows.Next() {
		item, err := scanGovernanceDiscoveryRule(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernanceDiscoveryRule(in GovernanceDiscoveryRuleInput) (GovernanceDiscoveryRuleRow, error) {
	if err := validateDiscoveryRuleInput(in); err != nil {
		return GovernanceDiscoveryRuleRow{}, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, fmt.Errorf("audit: begin discovery rule create: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
INSERT INTO agent_discovery_rules (agent_type_id, rule_name, threshold, enabled, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		in.AgentTypeID, strings.TrimSpace(in.RuleName), normalizeThreshold(in.Threshold), boolInt(in.Enabled), now, now)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, fmt.Errorf("audit: create discovery rule: %w", err)
	}
	id, _ := res.LastInsertId()
	for _, cond := range in.Conditions {
		cond.RuleID = id
		if _, err := insertDiscoveryCondition(ctx, tx, cond, now); err != nil {
			return GovernanceDiscoveryRuleRow{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return GovernanceDiscoveryRuleRow{}, fmt.Errorf("audit: commit discovery rule create: %w", err)
	}
	row, ok, err := s.GetGovernanceDiscoveryRule(id)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, err
	}
	if !ok {
		return GovernanceDiscoveryRuleRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceDiscoveryRule(id int64, patch GovernanceDiscoveryRulePatch) (GovernanceDiscoveryRuleRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.RuleName != nil {
		name := strings.TrimSpace(*patch.RuleName)
		if name == "" {
			return GovernanceDiscoveryRuleRow{}, false, fmt.Errorf("audit: rule_name is required")
		}
		sets = append(sets, "rule_name = ?")
		args = append(args, name)
	}
	if patch.Threshold != nil {
		sets = append(sets, "threshold = ?")
		args = append(args, normalizeThreshold(*patch.Threshold))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernanceDiscoveryRule(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_discovery_rule_update",
		"UPDATE agent_discovery_rules SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, false, fmt.Errorf("audit: update discovery rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernanceDiscoveryRuleRow{}, false, nil
	}
	row, ok, err := s.GetGovernanceDiscoveryRule(id)
	return row, ok, err
}

func (s *Store) DisableGovernanceDiscoveryRule(id int64) (GovernanceDiscoveryRuleRow, bool, error) {
	return s.UpdateGovernanceDiscoveryRule(id, GovernanceDiscoveryRulePatch{Enabled: ptrBool(false)})
}

func (s *Store) GetGovernanceDiscoveryRule(id int64) (GovernanceDiscoveryRuleRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_discovery_rule_get", `
SELECT r.id, r.agent_type_id, COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(r.rule_name,''), COALESCE(r.threshold,60), COALESCE(r.enabled,0),
       (SELECT COUNT(*) FROM agent_discovery_conditions c WHERE c.rule_id = r.id),
       COALESCE(CAST(r.created_at AS TEXT), ''), COALESCE(CAST(r.updated_at AS TEXT), '')
FROM agent_discovery_rules r
JOIN agent_types t ON t.id = r.agent_type_id
WHERE r.id = ?`, id)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, false, fmt.Errorf("audit: get discovery rule: %w", err)
	}
	if !rows.Next() {
		closeErr := rows.Close()
		if closeErr != nil {
			return GovernanceDiscoveryRuleRow{}, false, closeErr
		}
		return GovernanceDiscoveryRuleRow{}, false, rows.Err()
	}
	item, err := scanGovernanceDiscoveryRule(rows)
	if err != nil {
		_ = rows.Close()
		return GovernanceDiscoveryRuleRow{}, false, err
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return GovernanceDiscoveryRuleRow{}, false, err
	}
	if err := rows.Close(); err != nil {
		return GovernanceDiscoveryRuleRow{}, false, err
	}
	conditions, err := s.ListGovernanceDiscoveryConditions(id)
	if err != nil {
		return GovernanceDiscoveryRuleRow{}, false, err
	}
	item.Conditions = conditions
	return item, true, nil
}

func (s *Store) ListGovernanceDiscoveryConditions(ruleID int64) ([]GovernanceDiscoveryConditionRow, error) {
	rows, err := s.queryDB(context.Background(), "governance_discovery_condition_list", `
SELECT id, rule_id, COALESCE(condition_type,''), COALESCE(field,''), COALESCE(operator,''),
       COALESCE(value,''), COALESCE(weight,0), COALESCE(required,0), COALESCE(enabled,0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM agent_discovery_conditions
WHERE rule_id = ?
ORDER BY COALESCE(required,0) DESC, COALESCE(weight,0) DESC, id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("audit: list discovery conditions: %w", err)
	}
	defer rows.Close()
	var out []GovernanceDiscoveryConditionRow
	for rows.Next() {
		item, err := scanGovernanceDiscoveryCondition(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if out == nil {
		out = []GovernanceDiscoveryConditionRow{}
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernanceDiscoveryCondition(ruleID int64, in GovernanceDiscoveryConditionInput) (GovernanceDiscoveryConditionRow, error) {
	if ruleID <= 0 {
		return GovernanceDiscoveryConditionRow{}, fmt.Errorf("audit: rule_id is required")
	}
	in.RuleID = ruleID
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := insertDiscoveryCondition(context.Background(), s.db, in, now)
	if err != nil {
		return GovernanceDiscoveryConditionRow{}, err
	}
	id, _ := res.LastInsertId()
	row, ok, err := s.GetGovernanceDiscoveryCondition(id)
	if err != nil {
		return GovernanceDiscoveryConditionRow{}, err
	}
	if !ok {
		return GovernanceDiscoveryConditionRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceDiscoveryCondition(id int64, patch GovernanceDiscoveryConditionPatch) (GovernanceDiscoveryConditionRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.ConditionType != nil {
		value := strings.TrimSpace(*patch.ConditionType)
		if value == "" {
			return GovernanceDiscoveryConditionRow{}, false, fmt.Errorf("audit: condition_type is required")
		}
		sets = append(sets, "condition_type = ?")
		args = append(args, value)
	}
	if patch.Field != nil {
		sets = append(sets, "field = ?")
		args = append(args, strings.TrimSpace(*patch.Field))
	}
	if patch.Operator != nil {
		value := strings.TrimSpace(*patch.Operator)
		if value == "" {
			return GovernanceDiscoveryConditionRow{}, false, fmt.Errorf("audit: operator is required")
		}
		sets = append(sets, "operator = ?")
		args = append(args, value)
	}
	if patch.Value != nil {
		value := strings.TrimSpace(*patch.Value)
		if value == "" {
			return GovernanceDiscoveryConditionRow{}, false, fmt.Errorf("audit: value is required")
		}
		sets = append(sets, "value = ?")
		args = append(args, value)
	}
	if patch.Weight != nil {
		sets = append(sets, "weight = ?")
		args = append(args, *patch.Weight)
	}
	if patch.Required != nil {
		sets = append(sets, "required = ?")
		args = append(args, boolInt(*patch.Required))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernanceDiscoveryCondition(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_discovery_condition_update",
		"UPDATE agent_discovery_conditions SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return GovernanceDiscoveryConditionRow{}, false, fmt.Errorf("audit: update discovery condition: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernanceDiscoveryConditionRow{}, false, nil
	}
	row, ok, err := s.GetGovernanceDiscoveryCondition(id)
	return row, ok, err
}

func (s *Store) DeleteGovernanceDiscoveryCondition(id int64) (bool, error) {
	res, err := s.execDB(context.Background(), "governance_discovery_condition_delete",
		"DELETE FROM agent_discovery_conditions WHERE id = ?", id)
	if err != nil {
		return false, fmt.Errorf("audit: delete discovery condition: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernanceDiscoveryCondition(id int64) (GovernanceDiscoveryConditionRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_discovery_condition_get", `
SELECT id, rule_id, COALESCE(condition_type,''), COALESCE(field,''), COALESCE(operator,''),
       COALESCE(value,''), COALESCE(weight,0), COALESCE(required,0), COALESCE(enabled,0),
       COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '')
FROM agent_discovery_conditions
WHERE id = ?`, id)
	if err != nil {
		return GovernanceDiscoveryConditionRow{}, false, fmt.Errorf("audit: get discovery condition: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernanceDiscoveryConditionRow{}, false, rows.Err()
	}
	item, err := scanGovernanceDiscoveryCondition(rows)
	return item, err == nil, err
}

func (s *Store) ListGovernanceResourceRules(f GovernancePageFilter) (*GovernanceResourceRulePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{`COALESCE(t."delete",0) = 0`}
	var args []any
	if f.AgentTypeID > 0 {
		where = append(where, "rr.agent_type_id = ?")
		args = append(args, f.AgentTypeID)
	}
	if f.TypeKey = strings.TrimSpace(f.TypeKey); f.TypeKey != "" {
		where = append(where, "LOWER(COALESCE(t.type_key,'')) = ?")
		args = append(args, strings.ToLower(f.TypeKey))
	}
	if f.ResourceType = strings.TrimSpace(f.ResourceType); f.ResourceType != "" {
		where = append(where, "LOWER(COALESCE(rr.resource_type,'')) = ?")
		args = append(args, strings.ToLower(f.ResourceType))
	}
	if f.ScanProfileID > 0 {
		where = append(where, "COALESCE(rr.scan_profile_id,0) = ?")
		args = append(args, f.ScanProfileID)
	}
	if f.Enabled != nil {
		where = append(where, "COALESCE(rr.enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(rr.name) LIKE ? OR LOWER(rr.path_pattern) LIKE ? OR LOWER(COALESCE(t.type_key,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_resource_rule_count", `
SELECT COUNT(*)
FROM agent_resource_rules rr
JOIN agent_types t ON t.id = rr.agent_type_id
LEFT JOIN resource_scan_profiles p ON p.id = rr.scan_profile_id
WHERE `+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_resource_rule_list", `
SELECT rr.id, rr.agent_type_id, COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(rr.name,''), COALESCE(rr.resource_type,''), COALESCE(rr.path_pattern,''),
       COALESCE(rr.enumeration_mode,'children'), COALESCE(rr.scan_profile_id,0),
       COALESCE(p.name,''), COALESCE(rr.enabled,0), COALESCE(rr.priority,100),
       (SELECT COUNT(*) FROM static_resources sr WHERE COALESCE(sr.resource_rule_id,0) = rr.id),
       COALESCE(CAST(rr.created_at AS TEXT), ''), COALESCE(CAST(rr.updated_at AS TEXT), '')
FROM agent_resource_rules rr
JOIN agent_types t ON t.id = rr.agent_type_id
LEFT JOIN resource_scan_profiles p ON p.id = rr.scan_profile_id
WHERE `+clause+`
ORDER BY COALESCE(rr.enabled,0) DESC, COALESCE(t.type_key,''), COALESCE(rr.priority,100), rr.id
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list resource rules: %w", err)
	}
	defer rows.Close()
	out := &GovernanceResourceRulePage{Total: total, Page: page, PageSize: size, Items: []GovernanceResourceRuleRow{}}
	for rows.Next() {
		item, err := scanGovernanceResourceRule(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) CreateGovernanceResourceRule(in GovernanceResourceRuleInput) (GovernanceResourceRuleRow, error) {
	if err := validateResourceRuleInput(in.AgentTypeID, in.Name, in.ResourceType, in.PathPattern, in.EnumerationMode); err != nil {
		return GovernanceResourceRuleRow{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.execDB(context.Background(), "governance_resource_rule_create", `
INSERT INTO agent_resource_rules (
  agent_type_id, name, resource_type, path_pattern, enumeration_mode,
  scan_profile_id, enabled, priority, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.AgentTypeID, strings.TrimSpace(in.Name), normalizeResourceType(in.ResourceType),
		strings.TrimSpace(in.PathPattern), normalizeEnumerationMode(in.EnumerationMode),
		nullInt64Value(in.ScanProfileID), boolInt(in.Enabled), normalizePriority(in.Priority), now, now)
	if err != nil {
		return GovernanceResourceRuleRow{}, fmt.Errorf("audit: create resource rule: %w", err)
	}
	id, _ := res.LastInsertId()
	row, ok, err := s.GetGovernanceResourceRule(id)
	if err != nil {
		return GovernanceResourceRuleRow{}, err
	}
	if !ok {
		return GovernanceResourceRuleRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceResourceRule(id int64, patch GovernanceResourceRulePatch) (GovernanceResourceRuleRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.AgentTypeID != nil {
		if *patch.AgentTypeID <= 0 {
			return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: agent_type_id is required")
		}
		sets = append(sets, "agent_type_id = ?")
		args = append(args, *patch.AgentTypeID)
	}
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: name is required")
		}
		sets = append(sets, "name = ?")
		args = append(args, name)
	}
	if patch.ResourceType != nil {
		rtype := normalizeResourceType(*patch.ResourceType)
		if !validResourceType(rtype) {
			return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: unsupported resource_type %q", *patch.ResourceType)
		}
		sets = append(sets, "resource_type = ?")
		args = append(args, rtype)
	}
	if patch.PathPattern != nil {
		pattern := strings.TrimSpace(*patch.PathPattern)
		if pattern == "" {
			return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: path_pattern is required")
		}
		sets = append(sets, "path_pattern = ?")
		args = append(args, pattern)
	}
	if patch.EnumerationMode != nil {
		mode := normalizeEnumerationMode(*patch.EnumerationMode)
		if !validEnumerationMode(mode) {
			return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: unsupported enumeration_mode %q", *patch.EnumerationMode)
		}
		sets = append(sets, "enumeration_mode = ?")
		args = append(args, mode)
	}
	if patch.ScanProfileID != nil {
		sets = append(sets, "scan_profile_id = ?")
		args = append(args, nullInt64Value(*patch.ScanProfileID))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if patch.Priority != nil {
		sets = append(sets, "priority = ?")
		args = append(args, normalizePriority(*patch.Priority))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernanceResourceRule(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_resource_rule_update",
		"UPDATE agent_resource_rules SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: update resource rule: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernanceResourceRuleRow{}, false, nil
	}
	row, ok, err := s.GetGovernanceResourceRule(id)
	return row, ok, err
}

func (s *Store) DisableGovernanceResourceRule(id int64) (GovernanceResourceRuleRow, bool, error) {
	return s.UpdateGovernanceResourceRule(id, GovernanceResourceRulePatch{Enabled: ptrBool(false)})
}

func (s *Store) GetGovernanceResourceRule(id int64) (GovernanceResourceRuleRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_resource_rule_get", `
SELECT rr.id, rr.agent_type_id, COALESCE(t.type_key,''), COALESCE(t.name,''),
       COALESCE(rr.name,''), COALESCE(rr.resource_type,''), COALESCE(rr.path_pattern,''),
       COALESCE(rr.enumeration_mode,'children'), COALESCE(rr.scan_profile_id,0),
       COALESCE(p.name,''), COALESCE(rr.enabled,0), COALESCE(rr.priority,100),
       (SELECT COUNT(*) FROM static_resources sr WHERE COALESCE(sr.resource_rule_id,0) = rr.id),
       COALESCE(CAST(rr.created_at AS TEXT), ''), COALESCE(CAST(rr.updated_at AS TEXT), '')
FROM agent_resource_rules rr
JOIN agent_types t ON t.id = rr.agent_type_id
LEFT JOIN resource_scan_profiles p ON p.id = rr.scan_profile_id
WHERE rr.id = ?`, id)
	if err != nil {
		return GovernanceResourceRuleRow{}, false, fmt.Errorf("audit: get resource rule: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernanceResourceRuleRow{}, false, rows.Err()
	}
	item, err := scanGovernanceResourceRule(rows)
	return item, err == nil, err
}

func (s *Store) ListGovernanceScanProfiles(f GovernancePageFilter) (*GovernanceScanProfilePage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{"1=1"}
	var args []any
	if f.ResourceType = strings.TrimSpace(f.ResourceType); f.ResourceType != "" {
		where = append(where, "LOWER(COALESCE(p.resource_type,'')) = ?")
		args = append(args, strings.ToLower(f.ResourceType))
	}
	if f.Enabled != nil {
		where = append(where, "COALESCE(p.enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(p.name) LIKE ? OR LOWER(COALESCE(p.description,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_scan_profile_count", "SELECT COUNT(*) FROM resource_scan_profiles p WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_scan_profile_list", `
SELECT p.id, COALESCE(p.name,''), COALESCE(p.resource_type,''), COALESCE(p.enabled,0),
       COALESCE(p.description,''),
       (SELECT COUNT(*) FROM resource_scan_profile_capabilities pc WHERE pc.profile_id = p.id),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.scan_profile_id,0) = p.id),
       (SELECT COUNT(*) FROM static_resources sr WHERE COALESCE(sr.scan_profile_id,0) = p.id),
       COALESCE(CAST(p.created_at AS TEXT), ''), COALESCE(CAST(p.updated_at AS TEXT), '')
FROM resource_scan_profiles p
WHERE `+clause+`
ORDER BY COALESCE(p.enabled,0) DESC, COALESCE(p.resource_type,''), LOWER(p.name)
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan profiles: %w", err)
	}
	out := &GovernanceScanProfilePage{Total: total, Page: page, PageSize: size, Items: []GovernanceScanProfileRow{}}
	for rows.Next() {
		item, err := scanGovernanceScanProfile(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range out.Items {
		caps, err := s.ListGovernanceProfileCapabilities(int64(out.Items[i].ID))
		if err != nil {
			return nil, err
		}
		out.Items[i].Capabilities = caps
	}
	return out, nil
}

func (s *Store) CreateGovernanceScanProfile(in GovernanceScanProfileInput) (GovernanceScanProfileRow, error) {
	if err := validateScanProfileInput(in.Name, in.ResourceType); err != nil {
		return GovernanceScanProfileRow{}, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GovernanceScanProfileRow{}, fmt.Errorf("audit: begin scan profile create: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := tx.ExecContext(ctx, `
INSERT INTO resource_scan_profiles (name, resource_type, enabled, description, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)`,
		strings.TrimSpace(in.Name), normalizeResourceType(in.ResourceType), boolInt(in.Enabled),
		strings.TrimSpace(in.Description), now, now)
	if err != nil {
		return GovernanceScanProfileRow{}, fmt.Errorf("audit: create scan profile: %w", err)
	}
	id, _ := res.LastInsertId()
	if err := replaceProfileCapabilities(ctx, tx, id, in.Capabilities, now); err != nil {
		return GovernanceScanProfileRow{}, err
	}
	if err := tx.Commit(); err != nil {
		return GovernanceScanProfileRow{}, fmt.Errorf("audit: commit scan profile create: %w", err)
	}
	row, ok, err := s.GetGovernanceScanProfile(id)
	if err != nil {
		return GovernanceScanProfileRow{}, err
	}
	if !ok {
		return GovernanceScanProfileRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceScanProfile(id int64, patch GovernanceScanProfilePatch) (GovernanceScanProfileRow, bool, error) {
	sets := []string{}
	var args []any
	if patch.Name != nil {
		name := strings.TrimSpace(*patch.Name)
		if name == "" {
			return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: name is required")
		}
		sets = append(sets, "name = ?")
		args = append(args, name)
	}
	if patch.ResourceType != nil {
		rtype := normalizeResourceType(*patch.ResourceType)
		if !validResourceType(rtype) {
			return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: unsupported resource_type %q", *patch.ResourceType)
		}
		sets = append(sets, "resource_type = ?")
		args = append(args, rtype)
	}
	if patch.Description != nil {
		sets = append(sets, "description = ?")
		args = append(args, strings.TrimSpace(*patch.Description))
	}
	if patch.Enabled != nil {
		sets = append(sets, "enabled = ?")
		args = append(args, boolInt(*patch.Enabled))
	}
	if len(sets) == 0 {
		row, ok, err := s.GetGovernanceScanProfile(id)
		return row, ok, err
	}
	sets = append(sets, "updated_at = ?")
	args = append(args, time.Now().UTC().Format(time.RFC3339Nano), id)
	res, err := s.execDB(context.Background(), "governance_scan_profile_update",
		"UPDATE resource_scan_profiles SET "+strings.Join(sets, ", ")+" WHERE id = ?", args...)
	if err != nil {
		return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: update scan profile: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return GovernanceScanProfileRow{}, false, nil
	}
	row, ok, err := s.GetGovernanceScanProfile(id)
	return row, ok, err
}

func (s *Store) DisableGovernanceScanProfile(id int64) (GovernanceScanProfileRow, bool, error) {
	return s.UpdateGovernanceScanProfile(id, GovernanceScanProfilePatch{Enabled: ptrBool(false)})
}

func (s *Store) ReplaceGovernanceScanProfileCapabilities(id int64, caps []GovernanceProfileCapabilityInput) (GovernanceScanProfileRow, bool, error) {
	if _, ok, err := s.GetGovernanceScanProfile(id); err != nil || !ok {
		return GovernanceScanProfileRow{}, ok, err
	}
	ctx := context.Background()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: begin replace profile capabilities: %w", err)
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := replaceProfileCapabilities(ctx, tx, id, caps, now); err != nil {
		return GovernanceScanProfileRow{}, false, err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE resource_scan_profiles SET updated_at = ? WHERE id = ?", now, id); err != nil {
		return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: touch scan profile: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: commit replace profile capabilities: %w", err)
	}
	row, ok, err := s.GetGovernanceScanProfile(id)
	return row, ok, err
}

func (s *Store) GetGovernanceScanProfile(id int64) (GovernanceScanProfileRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_scan_profile_get", `
SELECT p.id, COALESCE(p.name,''), COALESCE(p.resource_type,''), COALESCE(p.enabled,0),
       COALESCE(p.description,''),
       (SELECT COUNT(*) FROM resource_scan_profile_capabilities pc WHERE pc.profile_id = p.id),
       (SELECT COUNT(*) FROM agent_resource_rules rr WHERE COALESCE(rr.scan_profile_id,0) = p.id),
       (SELECT COUNT(*) FROM static_resources sr WHERE COALESCE(sr.scan_profile_id,0) = p.id),
       COALESCE(CAST(p.created_at AS TEXT), ''), COALESCE(CAST(p.updated_at AS TEXT), '')
FROM resource_scan_profiles p
WHERE p.id = ?`, id)
	if err != nil {
		return GovernanceScanProfileRow{}, false, fmt.Errorf("audit: get scan profile: %w", err)
	}
	if !rows.Next() {
		closeErr := rows.Close()
		if closeErr != nil {
			return GovernanceScanProfileRow{}, false, closeErr
		}
		return GovernanceScanProfileRow{}, false, rows.Err()
	}
	item, err := scanGovernanceScanProfile(rows)
	if err != nil {
		_ = rows.Close()
		return GovernanceScanProfileRow{}, false, err
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return GovernanceScanProfileRow{}, false, err
	}
	if err := rows.Close(); err != nil {
		return GovernanceScanProfileRow{}, false, err
	}
	caps, err := s.ListGovernanceProfileCapabilities(id)
	if err != nil {
		return GovernanceScanProfileRow{}, false, err
	}
	item.Capabilities = caps
	return item, true, nil
}

func (s *Store) ListGovernanceScanCapabilities(f GovernancePageFilter) ([]GovernanceScanCapabilityRow, error) {
	where := []string{"1=1"}
	var args []any
	if f.Enabled != nil {
		where = append(where, "COALESCE(enabled,0) = ?")
		args = append(args, boolInt(*f.Enabled))
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(capability_key) LIKE ? OR LOWER(name) LIKE ? OR LOWER(scanner_name) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	rows, err := s.queryDB(context.Background(), "governance_scan_capability_list", `
SELECT id, COALESCE(capability_key,''), COALESCE(name,''), COALESCE(scanner_name,''),
       COALESCE(enabled,0), COALESCE(description,''), COALESCE(CAST(created_at AS TEXT), ''),
       COALESCE(CAST(updated_at AS TEXT), '')
FROM security_scan_capabilities
WHERE `+strings.Join(where, " AND ")+`
ORDER BY COALESCE(enabled,0) DESC, capability_key`, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: list scan capabilities: %w", err)
	}
	defer rows.Close()
	var out []GovernanceScanCapabilityRow
	for rows.Next() {
		var item GovernanceScanCapabilityRow
		var enabled int
		if err := rows.Scan(&item.ID, &item.CapabilityKey, &item.Name, &item.ScannerName,
			&enabled, &item.Description, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan scan capability row: %w", err)
		}
		item.Enabled = enabled != 0
		out = append(out, item)
	}
	if out == nil {
		out = []GovernanceScanCapabilityRow{}
	}
	return out, rows.Err()
}

func (s *Store) ListGovernanceProfileCapabilities(profileID int64) ([]GovernanceProfileCapabilityRow, error) {
	rows, err := s.queryDB(context.Background(), "governance_profile_capability_list", `
SELECT pc.profile_id, pc.capability_id, COALESCE(c.capability_key,''), COALESCE(c.name,''),
       COALESCE(c.scanner_name,''), COALESCE(pc.priority,100), COALESCE(pc.enabled,0),
       COALESCE(pc.config_json,''), COALESCE(c.description,'')
FROM resource_scan_profile_capabilities pc
JOIN security_scan_capabilities c ON c.id = pc.capability_id
WHERE pc.profile_id = ?
ORDER BY COALESCE(pc.priority,100), pc.capability_id`, profileID)
	if err != nil {
		return nil, fmt.Errorf("audit: list profile capabilities: %w", err)
	}
	defer rows.Close()
	var out []GovernanceProfileCapabilityRow
	for rows.Next() {
		var item GovernanceProfileCapabilityRow
		var enabled int
		if err := rows.Scan(&item.ProfileID, &item.CapabilityID, &item.CapabilityKey,
			&item.Name, &item.ScannerName, &item.Priority, &enabled, &item.ConfigJSON,
			&item.Description); err != nil {
			return nil, fmt.Errorf("audit: scan profile capability row: %w", err)
		}
		item.Enabled = enabled != 0
		out = append(out, item)
	}
	if out == nil {
		out = []GovernanceProfileCapabilityRow{}
	}
	return out, rows.Err()
}

func (s *Store) ListGovernanceResourceActions(f GovernancePageFilter) (*GovernanceResourceActionPage, error) {
	page, size := normalizeGovernancePage(f.Page, f.PageSize)
	where := []string{"1=1"}
	var args []any
	if f.TargetType = strings.TrimSpace(f.TargetType); f.TargetType != "" {
		where = append(where, "LOWER(target_type) = ?")
		args = append(args, strings.ToLower(f.TargetType))
	}
	if f.TargetName = strings.TrimSpace(f.TargetName); f.TargetName != "" {
		where = append(where, "LOWER(target_name) LIKE ?")
		args = append(args, "%"+strings.ToLower(f.TargetName)+"%")
	}
	if f.Connector = strings.TrimSpace(f.Connector); f.Connector != "" {
		where = append(where, "connector = ?")
		args = append(args, f.Connector)
	}
	if f.ActionField = strings.TrimSpace(f.ActionField); f.ActionField != "" {
		if err := validateActionFieldAndValue(f.ActionField, ""); err != nil {
			return nil, err
		}
		if f.ActionValue = strings.TrimSpace(f.ActionValue); f.ActionValue != "" {
			if err := validateActionFieldAndValue(f.ActionField, f.ActionValue); err != nil {
				return nil, err
			}
			where = append(where, fmt.Sprintf("json_extract(actions_json, '$.%s') = ?", f.ActionField))
			args = append(args, f.ActionValue)
		} else {
			where = append(where, fmt.Sprintf("COALESCE(json_extract(actions_json, '$.%s'), '') <> ''", f.ActionField))
		}
	}
	if f.Keyword = strings.TrimSpace(f.Keyword); f.Keyword != "" {
		where = append(where, "(LOWER(target_name) LIKE ? OR LOWER(COALESCE(source_path,'')) LIKE ? OR LOWER(COALESCE(reason,'')) LIKE ?)")
		p := "%" + strings.ToLower(f.Keyword) + "%"
		args = append(args, p, p, p)
	}
	clause := strings.Join(where, " AND ")
	total, err := s.countRows("governance_action_count", "SELECT COUNT(*) FROM actions WHERE "+clause, args...)
	if err != nil {
		return nil, err
	}
	rows, err := s.queryDB(context.Background(), "governance_action_list", `
SELECT id, target_type, target_name, COALESCE(connector,''), COALESCE(source_path,''),
       COALESCE(actions_json,'{}'), COALESCE(reason,''), COALESCE(CAST(updated_at AS TEXT), '')
FROM actions
WHERE `+clause+`
ORDER BY updated_at DESC
LIMIT ? OFFSET ?`, append(append([]any{}, args...), size, (page-1)*size)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list governance actions: %w", err)
	}
	defer rows.Close()
	out := &GovernanceResourceActionPage{Total: total, Page: page, PageSize: size, Items: []GovernanceResourceActionRow{}}
	for rows.Next() {
		item, err := scanGovernanceResourceAction(rows)
		if err != nil {
			return nil, err
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}

func (s *Store) UpsertGovernanceResourceAction(in GovernanceResourceActionInput) (GovernanceResourceActionRow, error) {
	if err := validateResourceActionInput(in); err != nil {
		return GovernanceResourceActionRow{}, err
	}
	if err := s.SetActionForConnector(
		strings.TrimSpace(in.TargetType),
		strings.TrimSpace(in.TargetName),
		strings.TrimSpace(in.Connector),
		strings.TrimSpace(in.SourcePath),
		in.Actions,
		strings.TrimSpace(in.Reason),
	); err != nil {
		return GovernanceResourceActionRow{}, err
	}
	row, ok, err := s.GetGovernanceResourceActionByTarget(in.TargetType, in.TargetName, in.Connector)
	if err != nil {
		return GovernanceResourceActionRow{}, err
	}
	if !ok {
		return GovernanceResourceActionRow{}, sql.ErrNoRows
	}
	return row, nil
}

func (s *Store) UpdateGovernanceResourceAction(id string, patch GovernanceResourceActionPatch) (GovernanceResourceActionRow, bool, error) {
	current, ok, err := s.GetGovernanceResourceActionByID(id)
	if err != nil || !ok {
		return GovernanceResourceActionRow{}, ok, err
	}
	state := current.Actions
	if patch.Actions != nil {
		if patch.Actions.Install != nil {
			if err := validateActionFieldAndValue("install", *patch.Actions.Install); err != nil {
				return GovernanceResourceActionRow{}, false, err
			}
			state.Install = strings.TrimSpace(*patch.Actions.Install)
		}
		if patch.Actions.File != nil {
			if err := validateActionFieldAndValue("file", *patch.Actions.File); err != nil {
				return GovernanceResourceActionRow{}, false, err
			}
			state.File = strings.TrimSpace(*patch.Actions.File)
		}
		if patch.Actions.Runtime != nil {
			if err := validateActionFieldAndValue("runtime", *patch.Actions.Runtime); err != nil {
				return GovernanceResourceActionRow{}, false, err
			}
			state.Runtime = strings.TrimSpace(*patch.Actions.Runtime)
		}
	}
	sourcePath := current.SourcePath
	if patch.SourcePath != nil {
		sourcePath = strings.TrimSpace(*patch.SourcePath)
	}
	reason := current.Reason
	if patch.Reason != nil {
		reason = strings.TrimSpace(*patch.Reason)
	}
	if err := s.SetActionForConnector(current.TargetType, current.TargetName, current.Connector, sourcePath, state, reason); err != nil {
		return GovernanceResourceActionRow{}, false, err
	}
	row, ok, err := s.GetGovernanceResourceActionByID(id)
	return row, ok, err
}

func (s *Store) DeleteGovernanceResourceAction(id string) (bool, error) {
	res, err := s.execDB(context.Background(), "governance_action_delete", "DELETE FROM actions WHERE id = ?", strings.TrimSpace(id))
	if err != nil {
		return false, fmt.Errorf("audit: delete action: %w", err)
	}
	affected, _ := res.RowsAffected()
	return affected > 0, nil
}

func (s *Store) GetGovernanceResourceActionByTarget(targetType, targetName, connector string) (GovernanceResourceActionRow, bool, error) {
	return s.getGovernanceResourceAction("target_type = ? AND target_name = ? AND connector = ?",
		strings.TrimSpace(targetType), strings.TrimSpace(targetName), strings.TrimSpace(connector))
}

func (s *Store) GetGovernanceResourceActionByID(id string) (GovernanceResourceActionRow, bool, error) {
	return s.getGovernanceResourceAction("id = ?", strings.TrimSpace(id))
}

func (s *Store) getGovernanceResourceAction(where string, args ...any) (GovernanceResourceActionRow, bool, error) {
	rows, err := s.queryDB(context.Background(), "governance_action_get", `
SELECT id, target_type, target_name, COALESCE(connector,''), COALESCE(source_path,''),
       COALESCE(actions_json,'{}'), COALESCE(reason,''), COALESCE(CAST(updated_at AS TEXT), '')
FROM actions
WHERE `+where+`
LIMIT 1`, args...)
	if err != nil {
		return GovernanceResourceActionRow{}, false, fmt.Errorf("audit: get action: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return GovernanceResourceActionRow{}, false, rows.Err()
	}
	item, err := scanGovernanceResourceAction(rows)
	return item, err == nil, err
}

func (s *Store) GetGovernanceAgentResourceContext(agentID string, agentTypeID int64) (AgentResourceRecord, bool, error) {
	where := `COALESCE(a.status, 'observed') NOT IN ('gone', 'removed', 'disabled', 'retired') AND COALESCE(t."delete",0) = 0`
	var args []any
	if strings.TrimSpace(agentID) != "" {
		where += " AND a.id = ?"
		args = append(args, strings.TrimSpace(agentID))
	} else if agentTypeID > 0 {
		where += " AND COALESCE(a.agent_type_id,0) = ?"
		args = append(args, agentTypeID)
	} else {
		return AgentResourceRecord{}, false, fmt.Errorf("audit: agent_id or agent_type_id is required")
	}
	rows, err := s.queryDB(context.Background(), "governance_agent_resource_context", `
SELECT a.id, COALESCE(a.agent_type_id, 0), COALESCE(t.type_key, ''),
       COALESCE(a.display_name, a.id), COALESCE(a.status, ''), COALESCE(a.metadata_json, '{}')
FROM agents a
LEFT JOIN agent_types t ON t.id = a.agent_type_id
WHERE `+where+`
ORDER BY a.last_seen_at DESC
LIMIT 1`, args...)
	if err != nil {
		return AgentResourceRecord{}, false, fmt.Errorf("audit: get agent resource context: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return AgentResourceRecord{}, false, rows.Err()
	}
	var rec AgentResourceRecord
	var metadataJSON string
	if err := rows.Scan(&rec.ID, &rec.AgentTypeID, &rec.TypeKey, &rec.DisplayName, &rec.Status, &metadataJSON); err != nil {
		return AgentResourceRecord{}, false, fmt.Errorf("audit: scan agent resource context: %w", err)
	}
	decodeAgentResourceRoots(&rec, metadataJSON)
	return rec, true, rows.Err()
}

func (s *Store) countRows(op, query string, args ...any) (int, error) {
	var total int
	if err := s.scanRow(context.Background(), op, s.db.QueryRowContext(context.Background(), query, args...), &total); err != nil {
		return 0, fmt.Errorf("audit: count rows: %w", err)
	}
	return total, nil
}

func scanGovernanceAgentType(rows *sql.Rows) (GovernanceAgentTypeRow, error) {
	var item GovernanceAgentTypeRow
	var enabled, deleted int
	if err := rows.Scan(&item.ID, &item.TypeKey, &item.Name, &item.Vendor, &item.Kind,
		&item.Runtime, &item.Description, &enabled, &deleted, &item.CreatedAt, &item.UpdatedAt,
		&item.AgentCount, &item.DiscoveryRuleCount, &item.ResourceRuleCount); err != nil {
		return item, fmt.Errorf("audit: scan agent type row: %w", err)
	}
	item.Enabled = enabled != 0
	item.Deleted = deleted != 0
	return item, nil
}

func scanGovernanceDiscoveryRule(rows *sql.Rows) (GovernanceDiscoveryRuleRow, error) {
	var item GovernanceDiscoveryRuleRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.AgentTypeID, &item.AgentTypeKey, &item.AgentTypeName,
		&item.RuleName, &item.Threshold, &enabled, &item.ConditionCount,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan discovery rule row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceDiscoveryCondition(rows *sql.Rows) (GovernanceDiscoveryConditionRow, error) {
	var item GovernanceDiscoveryConditionRow
	var required, enabled int
	if err := rows.Scan(&item.ID, &item.RuleID, &item.ConditionType, &item.Field,
		&item.Operator, &item.Value, &item.Weight, &required, &enabled,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan discovery condition row: %w", err)
	}
	item.Required = required != 0
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceResourceRule(rows *sql.Rows) (GovernanceResourceRuleRow, error) {
	var item GovernanceResourceRuleRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.AgentTypeID, &item.AgentTypeKey, &item.AgentTypeName,
		&item.Name, &item.ResourceType, &item.PathPattern, &item.EnumerationMode,
		&item.ScanProfileID, &item.ScanProfileName, &enabled, &item.Priority,
		&item.ResourceCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan resource rule row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceScanProfile(rows *sql.Rows) (GovernanceScanProfileRow, error) {
	var item GovernanceScanProfileRow
	var enabled int
	if err := rows.Scan(&item.ID, &item.Name, &item.ResourceType, &enabled,
		&item.Description, &item.CapabilityCount, &item.RuleCount, &item.ResourceCount,
		&item.CreatedAt, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan scan profile row: %w", err)
	}
	item.Enabled = enabled != 0
	return item, nil
}

func scanGovernanceResourceAction(rows *sql.Rows) (GovernanceResourceActionRow, error) {
	var item GovernanceResourceActionRow
	var raw string
	if err := rows.Scan(&item.ID, &item.TargetType, &item.TargetName, &item.Connector,
		&item.SourcePath, &raw, &item.Reason, &item.UpdatedAt); err != nil {
		return item, fmt.Errorf("audit: scan action row: %w", err)
	}
	if strings.TrimSpace(raw) != "" {
		_ = json.Unmarshal([]byte(raw), &item.Actions)
	}
	return item, nil
}

type discoveryConditionInserter interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertDiscoveryCondition(ctx context.Context, ex discoveryConditionInserter, in GovernanceDiscoveryConditionInput, now string) (sql.Result, error) {
	if in.RuleID <= 0 {
		return nil, fmt.Errorf("audit: rule_id is required")
	}
	if strings.TrimSpace(in.ConditionType) == "" || strings.TrimSpace(in.Operator) == "" || strings.TrimSpace(in.Value) == "" {
		return nil, fmt.Errorf("audit: condition_type, operator, and value are required")
	}
	return ex.ExecContext(ctx, `
INSERT INTO agent_discovery_conditions (
  rule_id, condition_type, field, operator, value, weight, required, enabled, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.RuleID, strings.TrimSpace(in.ConditionType), strings.TrimSpace(in.Field),
		strings.TrimSpace(in.Operator), strings.TrimSpace(in.Value), in.Weight,
		boolInt(in.Required), boolInt(in.Enabled), now, now)
}

func replaceProfileCapabilities(ctx context.Context, tx *sql.Tx, profileID int64, caps []GovernanceProfileCapabilityInput, now string) error {
	if _, err := tx.ExecContext(ctx, "DELETE FROM resource_scan_profile_capabilities WHERE profile_id = ?", profileID); err != nil {
		return fmt.Errorf("audit: clear profile capabilities: %w", err)
	}
	for i, cap := range caps {
		id := cap.CapabilityID
		if id <= 0 && strings.TrimSpace(cap.CapabilityKey) != "" {
			if err := tx.QueryRowContext(ctx,
				"SELECT id FROM security_scan_capabilities WHERE capability_key = ?",
				strings.TrimSpace(cap.CapabilityKey),
			).Scan(&id); err != nil {
				return fmt.Errorf("audit: lookup capability %q: %w", cap.CapabilityKey, err)
			}
		}
		if id <= 0 {
			return fmt.Errorf("audit: capabilities[%d].capability_id is required", i)
		}
		if strings.TrimSpace(cap.ConfigJSON) != "" && !json.Valid([]byte(cap.ConfigJSON)) {
			return fmt.Errorf("audit: capabilities[%d].config_json is not valid JSON", i)
		}
		priority := normalizePriority(cap.Priority)
		if _, err := tx.ExecContext(ctx, `
INSERT INTO resource_scan_profile_capabilities (
  profile_id, capability_id, priority, enabled, config_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			profileID, id, priority, boolInt(cap.Enabled), strings.TrimSpace(cap.ConfigJSON), now, now); err != nil {
			return fmt.Errorf("audit: insert profile capability: %w", err)
		}
	}
	return nil
}

func normalizeGovernancePage(page, size int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	return page, size
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ptrBool(v bool) *bool { return &v }

func normalizeKey(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func validateAgentTypeInput(typeKey, name string) error {
	if normalizeKey(typeKey) == "" {
		return fmt.Errorf("audit: type_key is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("audit: name is required")
	}
	return nil
}

func validateDiscoveryRuleInput(in GovernanceDiscoveryRuleInput) error {
	if in.AgentTypeID <= 0 {
		return fmt.Errorf("audit: agent_type_id is required")
	}
	if strings.TrimSpace(in.RuleName) == "" {
		return fmt.Errorf("audit: rule_name is required")
	}
	return nil
}

func normalizeThreshold(v int) int {
	if v <= 0 {
		return 60
	}
	if v > 100 {
		return 100
	}
	return v
}

func validateResourceRuleInput(agentTypeID int64, name, resourceType, pathPattern, mode string) error {
	if agentTypeID <= 0 {
		return fmt.Errorf("audit: agent_type_id is required")
	}
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("audit: name is required")
	}
	if !validResourceType(normalizeResourceType(resourceType)) {
		return fmt.Errorf("audit: unsupported resource_type %q", resourceType)
	}
	if strings.TrimSpace(pathPattern) == "" {
		return fmt.Errorf("audit: path_pattern is required")
	}
	if !validEnumerationMode(normalizeEnumerationMode(mode)) {
		return fmt.Errorf("audit: unsupported enumeration_mode %q", mode)
	}
	return nil
}

func validateScanProfileInput(name, resourceType string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("audit: name is required")
	}
	if !validResourceType(normalizeResourceType(resourceType)) {
		return fmt.Errorf("audit: unsupported resource_type %q", resourceType)
	}
	return nil
}

func validateResourceActionInput(in GovernanceResourceActionInput) error {
	if strings.TrimSpace(in.TargetType) == "" || strings.TrimSpace(in.TargetName) == "" {
		return fmt.Errorf("audit: target_type and target_name are required")
	}
	if err := validateActionFieldAndValue("install", strings.TrimSpace(in.Actions.Install)); err != nil {
		return err
	}
	if err := validateActionFieldAndValue("file", strings.TrimSpace(in.Actions.File)); err != nil {
		return err
	}
	if err := validateActionFieldAndValue("runtime", strings.TrimSpace(in.Actions.Runtime)); err != nil {
		return err
	}
	return nil
}

func normalizeResourceType(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func validResourceType(v string) bool {
	switch normalizeResourceType(v) {
	case "config", "skill", "mcp", "plugin", "prompt", "credential", "environment":
		return true
	default:
		return false
	}
}

func normalizeEnumerationMode(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "children"
	}
	return v
}

func validEnumerationMode(v string) bool {
	switch normalizeEnumerationMode(v) {
	case "exact", "children", "glob", "recursive":
		return true
	default:
		return false
	}
}

func normalizePriority(v int) int {
	if v <= 0 {
		return 100
	}
	return v
}
