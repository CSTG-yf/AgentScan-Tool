// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type runtimeSettingsReader interface {
	Query(string, ...any) (*sql.Rows, error)
	QueryRow(string, ...any) *sql.Row
}

func (s *Store) RuntimeSettingsRevision() uint64 { return s.runtimeSettingsRevision.Load() }

// All operator changes, their audit evidence and cursor updates commit
// together. A failed mutation never reports a successful configuration save.
func (s *Store) mutateRuntimeSettings(target string, fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = fn(tx); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return fmt.Errorf("%w: rule or policy identity already exists", ErrRuntimeSettingsConflict)
		}
		return err
	}
	_, err = tx.Exec(`INSERT INTO audit_events(id,timestamp,action,target,actor,details) VALUES(?,?,?,?,?,?)`, uuid.NewString(), time.Now().UTC().Format(time.RFC3339Nano), string(ActionConfigUpdate), target, "runtime-detection-settings", "runtime detection configuration changed; historical events are not replayed automatically")
	if err != nil {
		return err
	}
	if err = tx.Commit(); err == nil {
		s.runtimeSettingsRevision.Add(1)
	}
	return err
}

func requireRuntimeAgentType(q runtimeSettingsReader, id int64) error {
	var found int64
	if id <= 0 {
		return ErrRuntimeSettingsNotFound
	}
	err := q.QueryRow(`SELECT id FROM agent_types WHERE id=? AND "delete"=0`, id).Scan(&found)
	if err == sql.ErrNoRows {
		return ErrRuntimeSettingsNotFound
	}
	return err
}

// Agent type is resolved from persisted inventory, never from a caller's
// untrusted event attributes or the displayed agent name.
func (s *Store) RuntimeAgentTypeID(agentID string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT COALESCE(a.agent_type_id,0) FROM agents a JOIN agent_types t ON t.id=a.agent_type_id AND t."delete"=0 WHERE a.id=? AND a."delete"=0`, agentID).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

const runtimeRuleColumns = `id,rule_id,rule_name,source,scope,agent_type_id,detection_type,category,severity,confidence,matcher_json,detail,remediation,priority,enabled,system,version,override_severity,override_confidence,created_at,updated_at`

func runtimeRules(q runtimeSettingsReader, scope string, typeID int64) ([]RuntimeDetectionRule, error) {
	rows, err := q.Query(`SELECT `+runtimeRuleColumns+` FROM runtime_detection_rules WHERE scope=? AND COALESCE(agent_type_id,0)=? AND "delete"=0 ORDER BY priority,id`, scope, typeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []RuntimeDetectionRule{}
	for rows.Next() {
		var r RuntimeDetectionRule
		var matcher string
		if err = rows.Scan(&r.ID, &r.RuleID, &r.RuleName, &r.Source, &r.Scope, &r.AgentTypeID, &r.DetectionType, &r.Category, &r.Severity, &r.Confidence, &matcher, &r.Detail, &r.Remediation, &r.Priority, &r.Enabled, &r.System, &r.Version, &r.OverrideSeverity, &r.OverrideConfidence, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(matcher), &r.Matcher); err != nil {
			return nil, fmt.Errorf("rule %d matcher: %w", r.ID, err)
		}
		items = append(items, r)
	}
	return items, rows.Err()
}

func (s *Store) ListRuntimeDetectionRules(typeID int64) ([]RuntimeDetectionRule, error) {
	if typeID < 0 {
		return nil, ErrRuntimeSettingsNotFound
	}
	scope := "global"
	if typeID > 0 {
		if err := requireRuntimeAgentType(s.db, typeID); err != nil {
			return nil, err
		}
		scope = "agent_type"
	}
	return runtimeRules(s.db, scope, typeID)
}

func (s *Store) GetRuntimeDetectionRule(typeID, id int64) (RuntimeDetectionRule, error) {
	items, err := s.ListRuntimeDetectionRules(typeID)
	if err != nil {
		return RuntimeDetectionRule{}, err
	}
	for _, r := range items {
		if r.ID == id {
			return r, nil
		}
	}
	return RuntimeDetectionRule{}, ErrRuntimeSettingsNotFound
}

func insertRuntimeRule(tx *sql.Tx, r *RuntimeDetectionRule) error {
	matcher, err := json.Marshal(r.Matcher)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := tx.Exec(`INSERT INTO runtime_detection_rules(rule_id,rule_name,source,scope,agent_type_id,detection_type,category,severity,confidence,matcher_json,detail,remediation,priority,enabled,system,version,override_severity,override_confidence,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)`, r.RuleID, r.RuleName, r.Source, r.Scope, r.AgentTypeID, r.DetectionType, r.Category, r.Severity, r.Confidence, string(matcher), r.Detail, r.Remediation, r.Priority, r.Enabled, r.System, r.OverrideSeverity, r.OverrideConfidence, now, now)
	if err != nil {
		return err
	}
	r.ID, err = result.LastInsertId()
	r.Version = 1
	r.CreatedAt = now
	r.UpdatedAt = now
	return err
}

// Seeding never overwrites a user's disabled or edited builtin rule. Removed
// builtin rules stay disabled because DELETE preserves the builtin row.
func (s *Store) EnsureRuntimeBuiltinRules(rules []RuntimeDetectionRule) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	changed := false
	for _, r := range rules {
		if r.Source != "builtin" || !r.System {
			return fmt.Errorf("builtin seed requires a system rule")
		}
		if err = ValidateRuntimeDetectionRule(&r); err != nil {
			return err
		}
		var count int
		if err = tx.QueryRow(`SELECT COUNT(*) FROM runtime_detection_rules WHERE scope='global' AND rule_id=?`, r.RuleID).Scan(&count); err != nil {
			return err
		}
		if count > 0 {
			continue
		}
		if err = insertRuntimeRule(tx, &r); err != nil {
			return err
		}
		changed = true
	}
	if err = tx.Commit(); err == nil && changed {
		s.runtimeSettingsRevision.Add(1)
	}
	return err
}

func (s *Store) SaveRuntimeDetectionRule(r RuntimeDetectionRule) (RuntimeDetectionRule, error) {
	if err := ValidateRuntimeDetectionRule(&r); err != nil {
		return r, err
	}
	if r.ID == 0 && r.Source != "custom" {
		return r, fmt.Errorf("only custom rules can be created")
	}
	err := s.mutateRuntimeSettings("runtime-detection-settings/rules", func(tx *sql.Tx) error {
		if r.AgentTypeID != nil {
			if err := requireRuntimeAgentType(tx, *r.AgentTypeID); err != nil {
				return err
			}
		}
		if r.ID == 0 {
			return insertRuntimeRule(tx, &r)
		}
		typeID := int64(0)
		if r.AgentTypeID != nil {
			typeID = *r.AgentTypeID
		}
		items, err := runtimeRules(tx, r.Scope, typeID)
		if err != nil {
			return err
		}
		var old *RuntimeDetectionRule
		for i := range items {
			if items[i].ID == r.ID {
				old = &items[i]
				break
			}
		}
		if old == nil {
			return ErrRuntimeSettingsNotFound
		}
		if old.Version != r.Version {
			return ErrRuntimeSettingsConflict
		}
		if old.Source != r.Source || old.System != r.System {
			return fmt.Errorf("%w: rule source is immutable", ErrRuntimeSettingsConflict)
		}
		if r.System {
			oldMatcher, _ := json.Marshal(old.Matcher)
			newMatcher, _ := json.Marshal(r.Matcher)
			if old.RuleID != r.RuleID || old.RuleName != r.RuleName || old.DetectionType != r.DetectionType || old.Category != r.Category || string(oldMatcher) != string(newMatcher) {
				return fmt.Errorf("%w: builtin identity and matcher are immutable", ErrRuntimeSettingsConflict)
			}
			r.OverrideSeverity = old.OverrideSeverity || old.Severity != r.Severity || r.OverrideSeverity
			r.OverrideConfidence = old.OverrideConfidence || old.Confidence != r.Confidence || r.OverrideConfidence
		}
		matcher, err := json.Marshal(r.Matcher)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := tx.Exec(`UPDATE runtime_detection_rules SET rule_id=?,rule_name=?,detection_type=?,category=?,severity=?,confidence=?,matcher_json=?,detail=?,remediation=?,priority=?,enabled=?,override_severity=?,override_confidence=?,version=version+1,updated_at=? WHERE id=? AND version=? AND "delete"=0`, r.RuleID, r.RuleName, r.DetectionType, r.Category, r.Severity, r.Confidence, string(matcher), r.Detail, r.Remediation, r.Priority, r.Enabled, r.OverrideSeverity, r.OverrideConfidence, now, r.ID, r.Version)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrRuntimeSettingsConflict
		}
		r.Version++
		r.UpdatedAt = now
		r.CreatedAt = old.CreatedAt
		return nil
	})
	return r, err
}

func (s *Store) DeleteRuntimeDetectionRule(typeID, id int64) error {
	r, err := s.GetRuntimeDetectionRule(typeID, id)
	if err != nil {
		return err
	}
	return s.mutateRuntimeSettings(fmt.Sprintf("runtime-detection-settings/rules/%d", id), func(tx *sql.Tx) error {
		deleted := !r.System
		result, err := tx.Exec(`UPDATE runtime_detection_rules SET enabled=0,"delete"=?,version=version+1,updated_at=? WHERE id=? AND version=? AND "delete"=0`, deleted, time.Now().UTC().Format(time.RFC3339Nano), id, r.Version)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrRuntimeSettingsConflict
		}
		return nil
	})
}

func runtimeTypeSettings(q runtimeSettingsReader, typeID int64) (RuntimeDetectionAgentTypeSettings, error) {
	r := RuntimeDetectionAgentTypeSettings{AgentTypeID: typeID, Enabled: true, InheritGlobalRules: true, UseGlobalRiskPolicy: true}
	if typeID == 0 {
		return r, nil
	}
	if err := requireRuntimeAgentType(q, typeID); err != nil {
		return r, err
	}
	err := q.QueryRow(`SELECT enabled,inherit_global_rules,use_global_risk_policy,custom_risk_policy_id,created_at,updated_at FROM runtime_detection_agent_type_settings WHERE agent_type_id=? AND "delete"=0`, typeID).Scan(&r.Enabled, &r.InheritGlobalRules, &r.UseGlobalRiskPolicy, &r.CustomRiskPolicyID, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return r, nil
	}
	return r, err
}

func (s *Store) GetRuntimeDetectionAgentTypeSettings(typeID int64) (RuntimeDetectionAgentTypeSettings, error) {
	return runtimeTypeSettings(s.db, typeID)
}

func writeRuntimeTypeSettings(tx *sql.Tx, r *RuntimeDetectionAgentTypeSettings) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(`INSERT INTO runtime_detection_agent_type_settings(agent_type_id,enabled,inherit_global_rules,use_global_risk_policy,custom_risk_policy_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(agent_type_id) DO UPDATE SET enabled=excluded.enabled,inherit_global_rules=excluded.inherit_global_rules,use_global_risk_policy=excluded.use_global_risk_policy,custom_risk_policy_id=excluded.custom_risk_policy_id,updated_at=excluded.updated_at,"delete"=0`, r.AgentTypeID, r.Enabled, r.InheritGlobalRules, r.UseGlobalRiskPolicy, r.CustomRiskPolicyID, now, now)
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	r.UpdatedAt = now
	return err
}

func (s *Store) SaveRuntimeDetectionAgentTypeSettings(r RuntimeDetectionAgentTypeSettings) (RuntimeDetectionAgentTypeSettings, error) {
	err := s.mutateRuntimeSettings(fmt.Sprintf("runtime-detection-settings/agent-types/%d/settings", r.AgentTypeID), func(tx *sql.Tx) error {
		if err := requireRuntimeAgentType(tx, r.AgentTypeID); err != nil {
			return err
		}
		old, err := runtimeTypeSettings(tx, r.AgentTypeID)
		if err != nil {
			return err
		}
		r.CustomRiskPolicyID = old.CustomRiskPolicyID
		r.CreatedAt = old.CreatedAt
		if !r.UseGlobalRiskPolicy && r.CustomRiskPolicyID == nil {
			p, err := writeRuntimeRiskPolicy(tx, r.AgentTypeID, "Custom Runtime Risk Policy", DefaultRuntimeRiskPolicyRules())
			if err != nil {
				return err
			}
			r.CustomRiskPolicyID = &p.PolicyID
		}
		return writeRuntimeTypeSettings(tx, &r)
	})
	return r, err
}

func runtimeBlacklist(q runtimeSettingsReader, typeID int64) ([]RuntimeDetectionBlacklistItem, error) {
	items := []RuntimeDetectionBlacklistItem{}
	if typeID == 0 {
		return items, nil
	}
	rows, err := q.Query(`SELECT id,agent_type_id,target_type,match_type,value,detection_type,category,severity,confidence,reason,priority,enabled,version,created_at,updated_at FROM runtime_detection_blacklist_items WHERE agent_type_id=? AND "delete"=0 ORDER BY priority,id`, typeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r RuntimeDetectionBlacklistItem
		if err = rows.Scan(&r.ID, &r.AgentTypeID, &r.TargetType, &r.MatchType, &r.Value, &r.DetectionType, &r.Category, &r.Severity, &r.Confidence, &r.Reason, &r.Priority, &r.Enabled, &r.Version, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, r)
	}
	return items, rows.Err()
}

func (s *Store) ListRuntimeBlacklist(typeID int64) ([]RuntimeDetectionBlacklistItem, error) {
	if err := requireRuntimeAgentType(s.db, typeID); err != nil {
		return nil, err
	}
	return runtimeBlacklist(s.db, typeID)
}

func (s *Store) GetRuntimeBlacklistItem(typeID, id int64) (RuntimeDetectionBlacklistItem, error) {
	items, err := s.ListRuntimeBlacklist(typeID)
	if err != nil {
		return RuntimeDetectionBlacklistItem{}, err
	}
	for _, r := range items {
		if r.ID == id {
			return r, nil
		}
	}
	return RuntimeDetectionBlacklistItem{}, ErrRuntimeSettingsNotFound
}

func (s *Store) SaveRuntimeBlacklist(r RuntimeDetectionBlacklistItem) (RuntimeDetectionBlacklistItem, error) {
	if err := ValidateRuntimeBlacklist(&r); err != nil {
		return r, err
	}
	err := s.mutateRuntimeSettings(fmt.Sprintf("runtime-detection-settings/agent-types/%d/blacklist", r.AgentTypeID), func(tx *sql.Tx) error {
		if err := requireRuntimeAgentType(tx, r.AgentTypeID); err != nil {
			return err
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if r.ID == 0 {
			res, err := tx.Exec(`INSERT INTO runtime_detection_blacklist_items(agent_type_id,target_type,match_type,value,detection_type,category,severity,confidence,reason,priority,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, r.AgentTypeID, r.TargetType, r.MatchType, r.Value, r.DetectionType, r.Category, r.Severity, r.Confidence, r.Reason, r.Priority, r.Enabled, now, now)
			if err != nil {
				return err
			}
			r.ID, err = res.LastInsertId()
			r.Version = 1
			r.CreatedAt = now
			r.UpdatedAt = now
			return err
		}
		res, err := tx.Exec(`UPDATE runtime_detection_blacklist_items SET target_type=?,match_type=?,value=?,detection_type=?,category=?,severity=?,confidence=?,reason=?,priority=?,enabled=?,version=version+1,updated_at=? WHERE id=? AND agent_type_id=? AND version=? AND "delete"=0`, r.TargetType, r.MatchType, r.Value, r.DetectionType, r.Category, r.Severity, r.Confidence, r.Reason, r.Priority, r.Enabled, now, r.ID, r.AgentTypeID, r.Version)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrRuntimeSettingsConflict
		}
		r.Version++
		r.UpdatedAt = now
		return nil
	})
	return r, err
}

func (s *Store) DeleteRuntimeBlacklist(typeID, id int64) error {
	return s.mutateRuntimeSettings(fmt.Sprintf("runtime-detection-settings/agent-types/%d/blacklist/%d", typeID, id), func(tx *sql.Tx) error {
		res, err := tx.Exec(`UPDATE runtime_detection_blacklist_items SET enabled=0,"delete"=1,version=version+1,updated_at=? WHERE id=? AND agent_type_id=? AND "delete"=0`, time.Now().UTC().Format(time.RFC3339Nano), id, typeID)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrRuntimeSettingsNotFound
		}
		return nil
	})
}

func runtimeRiskPolicy(q runtimeSettingsReader, typeID int64) (RuntimeRiskPolicy, error) {
	p := RuntimeRiskPolicy{Rules: []RuntimeRiskPolicyRule{}}
	err := q.QueryRow(`SELECT id,policy_key,name,scope,agent_type_id,version,updated_at FROM runtime_risk_policies WHERE COALESCE(agent_type_id,0)=? AND enabled=1 AND "delete"=0`, typeID).Scan(&p.PolicyID, &p.PolicyKey, &p.Name, &p.Scope, &p.AgentTypeID, &p.Version, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return p, ErrRuntimeSettingsNotFound
	}
	if err != nil {
		return p, err
	}
	p.Editable = typeID > 0
	rows, err := q.Query(`SELECT risk_level,min_score,max_score,decision,priority,enabled FROM runtime_risk_policy_rules WHERE policy_id=? AND "delete"=0 ORDER BY min_score,id`, p.PolicyID)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var r RuntimeRiskPolicyRule
		if err = rows.Scan(&r.RiskLevel, &r.MinScore, &r.MaxScore, &r.Decision, &r.Priority, &r.Enabled); err != nil {
			return p, err
		}
		r.DisplayDecision = r.Decision
		if r.Decision == RuntimeDecisionConfirm {
			r.DisplayDecision = "ASK"
		}
		p.Rules = append(p.Rules, r)
	}
	if err := rows.Err(); err != nil {
		return p, err
	}
	return p, ValidateRuntimeRiskPolicy(p.Rules)
}

func (s *Store) GetRuntimeRiskPolicy(typeID int64) (RuntimeRiskPolicy, error) {
	return runtimeRiskPolicy(s.db, typeID)
}

func writeRuntimeRiskPolicy(tx *sql.Tx, typeID int64, name string, rules []RuntimeRiskPolicyRule) (RuntimeRiskPolicy, error) {
	p := RuntimeRiskPolicy{}
	if err := requireRuntimeAgentType(tx, typeID); err != nil {
		return p, err
	}
	if err := ValidateRuntimeRiskPolicy(rules); err != nil {
		return p, err
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 256 {
		return p, fmt.Errorf("policy name required (maximum 256 bytes)")
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	key := fmt.Sprintf("runtime-risk-policy-agent-type-%d", typeID)
	_, err := tx.Exec(`INSERT INTO runtime_risk_policies(policy_key,name,scope,agent_type_id,created_at,updated_at) VALUES(?,?,'agent_type',?,?,?) ON CONFLICT(policy_key) DO UPDATE SET name=excluded.name,version=version+1,updated_at=excluded.updated_at`, key, name, typeID, now, now)
	if err != nil {
		return p, err
	}
	if err = tx.QueryRow(`SELECT id FROM runtime_risk_policies WHERE policy_key=?`, key).Scan(&p.PolicyID); err != nil {
		return p, err
	}
	if _, err = tx.Exec(`UPDATE runtime_risk_policy_rules SET "delete"=1,updated_at=? WHERE policy_id=? AND "delete"=0`, now, p.PolicyID); err != nil {
		return p, err
	}
	for _, r := range rules {
		if _, err = tx.Exec(`INSERT INTO runtime_risk_policy_rules(policy_id,risk_level,min_score,max_score,decision,priority,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, p.PolicyID, r.RiskLevel, r.MinScore, r.MaxScore, r.Decision, r.Priority, r.Enabled, now, now); err != nil {
			return p, err
		}
	}
	return runtimeRiskPolicy(tx, typeID)
}

// The risk-policy update and the inheritance toggle are one transaction.
func (s *Store) SaveRuntimeRiskPolicy(typeID int64, useGlobal bool, name string, rules []RuntimeRiskPolicyRule) error {
	return s.mutateRuntimeSettings(fmt.Sprintf("runtime-detection-settings/agent-types/%d/risk-policy", typeID), func(tx *sql.Tx) error {
		settings, err := runtimeTypeSettings(tx, typeID)
		if err != nil {
			return err
		}
		if typeID <= 0 {
			return fmt.Errorf("global risk policy is read-only")
		}
		if !useGlobal {
			p, err := writeRuntimeRiskPolicy(tx, typeID, name, rules)
			if err != nil {
				return err
			}
			settings.CustomRiskPolicyID = &p.PolicyID
		}
		settings.UseGlobalRiskPolicy = useGlobal
		return writeRuntimeTypeSettings(tx, &settings)
	})
}

// A read transaction prevents a configuration assembled across two policy
// versions. Unknown/unclassified events (type 0) inherit global rules.
func (s *Store) EffectiveRuntimeDetectionConfig(typeID int64) (EffectiveRuntimeDetectionConfig, error) {
	config := EffectiveRuntimeDetectionConfig{AgentTypeID: typeID, Rules: []RuntimeDetectionRule{}, Blacklist: []RuntimeDetectionBlacklistItem{}}
	tx, err := s.db.Begin()
	if err != nil {
		return config, err
	}
	defer tx.Rollback()
	settings, err := runtimeTypeSettings(tx, typeID)
	if err != nil {
		return config, err
	}
	config.Enabled = settings.Enabled
	config.InheritGlobalRules = settings.InheritGlobalRules
	config.UseGlobalRiskPolicy = settings.UseGlobalRiskPolicy
	policyType := typeID
	if settings.UseGlobalRiskPolicy {
		policyType = 0
	}
	config.RiskPolicy, err = runtimeRiskPolicy(tx, policyType)
	if err != nil {
		return config, err
	}
	if settings.Enabled {
		if settings.InheritGlobalRules {
			rules, err := runtimeRules(tx, "global", 0)
			if err != nil {
				return config, err
			}
			for _, r := range rules {
				if r.Enabled {
					config.Rules = append(config.Rules, r)
				}
			}
		}
		if typeID > 0 {
			rules, err := runtimeRules(tx, "agent_type", typeID)
			if err != nil {
				return config, err
			}
			for _, r := range rules {
				if r.Enabled {
					config.Rules = append(config.Rules, r)
				}
			}
		}
		items, err := runtimeBlacklist(tx, typeID)
		if err != nil {
			return config, err
		}
		for _, r := range items {
			if r.Enabled {
				config.Blacklist = append(config.Blacklist, r)
			}
		}
	}
	return config, tx.Commit()
}
