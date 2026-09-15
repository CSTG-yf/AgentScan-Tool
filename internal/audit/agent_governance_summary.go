package audit

import "context"

// GovernanceSummary contains unfiltered counts for the governance header.
// Disabled entries are included; deleted entries and rules whose AgentType
// has been deleted are excluded, matching the governance list APIs.
type GovernanceSummary struct {
	AgentTypeCount         int `json:"agent_type_count"`
	DiscoveryRuleCount     int `json:"discovery_rule_count"`
	ResourceRuleCount      int `json:"resource_rule_count"`
	ScanProfileCount       int `json:"scan_profile_count"`
	DecisionProfileCount   int `json:"decision_profile_count"`
	RiskRuleCount          int `json:"risk_rule_count"`
	RuntimeRuleCount       int `json:"runtime_rule_count"`
	RuntimeBlacklistCount  int `json:"runtime_blacklist_count"`
	RuntimeRiskPolicyCount int `json:"runtime_risk_policy_count"`
	ScanScheduleCount      int `json:"scan_schedule_count"`
	PageRefreshPolicyCount int `json:"page_refresh_policy_count"`
}

func (s *Store) GetGovernanceSummary(ctx context.Context) (GovernanceSummary, error) {
	var result GovernanceSummary
	err := s.queryRowDB(ctx, "governance_summary", `SELECT
  (SELECT COUNT(*) FROM agent_types WHERE COALESCE("delete",0) = 0),
  (SELECT COUNT(*) FROM agent_discovery_rules r JOIN agent_types t ON t.id = r.agent_type_id
   WHERE COALESCE(r."delete",0) = 0 AND COALESCE(t."delete",0) = 0),
  (SELECT COUNT(*) FROM agent_resource_rules r JOIN agent_types t ON t.id = r.agent_type_id
   WHERE COALESCE(r."delete",0) = 0 AND COALESCE(t."delete",0) = 0),
  (SELECT COUNT(*) FROM resource_scan_profiles WHERE COALESCE("delete",0) = 0),
  ((SELECT COUNT(*) FROM resource_pre_scan_profiles WHERE COALESCE("delete",0) = 0) +
   (SELECT COUNT(*) FROM resource_post_scan_profiles WHERE COALESCE("delete",0) = 0)),
  ((SELECT COUNT(*) FROM risk_severity_mappings WHERE COALESCE("delete",0) = 0) +
   (SELECT COUNT(*) FROM risk_rule_prefix_matches WHERE COALESCE("delete",0) = 0) +
   (SELECT COUNT(*) FROM risk_category_matches WHERE COALESCE("delete",0) = 0)),
  (SELECT COUNT(*) FROM runtime_detection_rules r WHERE COALESCE(r."delete",0) = 0
   AND (r.scope = 'global' OR EXISTS (SELECT 1 FROM agent_types t WHERE t.id = r.agent_type_id AND COALESCE(t."delete",0) = 0))),
  (SELECT COUNT(*) FROM runtime_detection_blacklist_items r JOIN agent_types t ON t.id = r.agent_type_id
   WHERE COALESCE(r."delete",0) = 0 AND COALESCE(t."delete",0) = 0),
  (SELECT COUNT(*) FROM runtime_risk_policies r WHERE COALESCE(r."delete",0) = 0
   AND (r.scope = 'global' OR EXISTS (SELECT 1 FROM agent_types t WHERE t.id = r.agent_type_id AND COALESCE(t."delete",0) = 0))),
  (SELECT COUNT(*) FROM scan_schedules)
`).Scan(&result.AgentTypeCount, &result.DiscoveryRuleCount, &result.ResourceRuleCount, &result.ScanProfileCount,
		&result.DecisionProfileCount, &result.RiskRuleCount, &result.RuntimeRuleCount,
		&result.RuntimeBlacklistCount, &result.RuntimeRiskPolicyCount, &result.ScanScheduleCount)
	return result, err
}
