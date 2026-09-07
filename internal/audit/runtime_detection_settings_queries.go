// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

type RuntimeDetectionAgentTypeRow struct {
	AgentTypeID            int64  `json:"agent_type_id"`
	AgentTypeKey           string `json:"agent_type_key"`
	AgentTypeName          string `json:"agent_type_name"`
	Vendor                 string `json:"vendor"`
	Runtime                string `json:"runtime"`
	Enabled                bool   `json:"enabled"`
	InheritGlobalRules     bool   `json:"inherit_global_rules"`
	SpecificRuleCount      int    `json:"specific_rule_count"`
	BlacklistCount         int    `json:"blacklist_count"`
	RiskPolicyMode         string `json:"risk_policy_mode"`
	UseGlobalRiskPolicy    bool   `json:"use_global_risk_policy"`
	Status                 string `json:"status"`
	UpdatedAt              string `json:"updated_at"`
	HasCustomConfiguration bool   `json:"-"`
	CustomRiskPolicyCount  int    `json:"-"`
}

// Administrative configuration rows are projected together, without loading
// every matcher or issuing a detail query per AgentType. API filters and
// pagination apply to this complete configuration inventory.
func (s *Store) ListRuntimeDetectionAgentTypes() ([]RuntimeDetectionAgentTypeRow, error) {
	rows, err := s.db.Query(`SELECT t.id,t.type_key,t.name,t.vendor,t.runtime,
 COALESCE(c.enabled,1),COALESCE(c.inherit_global_rules,1),COALESCE(c.use_global_risk_policy,1),
 COALESCE(r.n,0),COALESCE(b.n,0),COALESCE(p.n,0),c.agent_type_id IS NOT NULL,
 MAX(t.updated_at,COALESCE(c.updated_at,''),COALESCE(r.updated_at,''),COALESCE(b.updated_at,''),COALESCE(p.updated_at,''))
FROM agent_types t
LEFT JOIN runtime_detection_agent_type_settings c ON c.agent_type_id=t.id AND c."delete"=0
LEFT JOIN (SELECT agent_type_id,COUNT(*) n,MAX(updated_at) updated_at FROM runtime_detection_rules WHERE scope='agent_type' AND "delete"=0 GROUP BY agent_type_id) r ON r.agent_type_id=t.id
LEFT JOIN (SELECT agent_type_id,COUNT(*) n,MAX(updated_at) updated_at FROM runtime_detection_blacklist_items WHERE "delete"=0 GROUP BY agent_type_id) b ON b.agent_type_id=t.id
LEFT JOIN (SELECT agent_type_id,COUNT(*) n,MAX(updated_at) updated_at FROM runtime_risk_policies WHERE scope='agent_type' AND "delete"=0 GROUP BY agent_type_id) p ON p.agent_type_id=t.id
WHERE t."delete"=0 ORDER BY t.name,t.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimeDetectionAgentTypeRow{}
	for rows.Next() {
		var r RuntimeDetectionAgentTypeRow
		if err = rows.Scan(&r.AgentTypeID, &r.AgentTypeKey, &r.AgentTypeName, &r.Vendor, &r.Runtime, &r.Enabled, &r.InheritGlobalRules, &r.UseGlobalRiskPolicy, &r.SpecificRuleCount, &r.BlacklistCount, &r.CustomRiskPolicyCount, &r.HasCustomConfiguration, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.RiskPolicyMode = "global"
		if !r.UseGlobalRiskPolicy {
			r.RiskPolicyMode = "custom"
		}
		r.Status = "enabled"
		if !r.Enabled {
			r.Status = "disabled"
		}
		r.HasCustomConfiguration = r.HasCustomConfiguration || r.SpecificRuleCount > 0 || r.BlacklistCount > 0 || r.CustomRiskPolicyCount > 0
		out = append(out, r)
	}
	return out, rows.Err()
}
