export type RuntimeRiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type RuntimeRiskDecision = "ALLOW" | "ALERT" | "CONFIRM" | "BLOCK";
export type RuntimeMatchType = "exact" | "contains" | "prefix" | "glob" | "regex";
export interface RuntimePattern { match_type: RuntimeMatchType; value: string }
export interface RuntimeMatcher {
  kind: "builtin" | "event_match";
  builtin_rule_id?: string;
  event_type?: string;
  event_category?: string;
  event_source?: string;
  target?: RuntimePattern;
  tool_name?: RuntimePattern;
  mcp_server?: RuntimePattern;
  detail?: RuntimePattern;
  path?: RuntimePattern;
  operation?: RuntimePattern;
}
export interface RuntimeRule {
  id: number;
  rule_id: string;
  rule_name: string;
  source: "builtin" | "custom";
  scope: "global" | "agent_type";
  agent_type_id: number | null;
  detection_type: string;
  category: "attack" | "suspicious" | "hygiene";
  severity: RuntimeRiskLevel;
  confidence: number;
  matcher: RuntimeMatcher;
  detail: string;
  remediation: string;
  priority: number;
  enabled: boolean;
  system: boolean;
  version: number;
  override_severity: boolean;
  override_confidence: boolean;
  created_at: string;
  updated_at: string;
}
export interface RuntimeBlacklist {
  id: number;
  agent_type_id: number;
  target_type: "command" | "path" | "tool" | "mcp" | "domain" | "url" | "process";
  match_type: RuntimeMatchType;
  value: string;
  detection_type: string;
  category: RuntimeRule["category"];
  severity: RuntimeRiskLevel;
  confidence: number;
  reason: string;
  priority: number;
  enabled: boolean;
  version: number;
  created_at: string;
  updated_at: string;
}
export interface RuntimeRiskPolicyRule {
  risk_level: RuntimeRiskLevel;
  min_score: number;
  max_score: number;
  decision: RuntimeRiskDecision;
  display_decision: string;
  priority: number;
  enabled: boolean;
}
export interface RuntimeRiskPolicy {
  policy_id: number;
  policy_key: string;
  name: string;
  scope: "global" | "agent_type";
  agent_type_id: number | null;
  editable: boolean;
  version: number;
  rules: RuntimeRiskPolicyRule[];
  updated_at: string;
}
export interface RuntimeTypeSettings {
  agent_type_id: number;
  enabled: boolean;
  inherit_global_rules: boolean;
  use_global_risk_policy: boolean;
  custom_risk_policy_id: number | null;
  updated_at: string;
}
export interface RuntimeTypeRow {
  agent_type_id: number;
  agent_type_key: string;
  agent_type_name: string;
  vendor: string;
  runtime: string;
  enabled: boolean;
  inherit_global_rules: boolean;
  specific_rule_count: number;
  blacklist_count: number;
  risk_policy_mode: "global" | "custom";
  use_global_risk_policy: boolean;
  status: string;
  updated_at: string;
}
export interface RuntimeRiskData {
  mode: "global" | "custom";
  use_global_risk_policy: boolean;
  policy: RuntimeRiskPolicy | null;
  custom_policy?: RuntimeRiskPolicy | null;
  effective_policy: RuntimeRiskPolicy;
}
export interface RuntimeTypeDetail {
  agent_type: Pick<RuntimeTypeRow, "agent_type_id" | "agent_type_key" | "agent_type_name">;
  settings: RuntimeTypeSettings;
  specific_rules: RuntimeRule[];
  blacklist: RuntimeBlacklist[];
  risk_policy: RuntimeRiskData;
  effective_summary: { global_rule_count: number; specific_rule_count: number; blacklist_count: number; effective_rule_count: number };
}
export interface RuntimeSettingsOverview {
  global_rule_count: number;
  enabled_global_rule_count: number;
  agent_type_count: number;
  custom_agent_type_count: number;
  blacklist_count: number;
  custom_risk_policy_count: number;
  updated_at: string;
}
export interface RuntimeSettingsPage<T> { items: T[]; total: number; page: number; page_size: number }
export interface RuntimeSettingsQuery {
  page?: number;
  page_size?: number;
  keyword?: string;
  enabled?: "all" | "true" | "false";
  source?: "builtin" | "custom";
  inherit_global_rules?: "all" | "true" | "false";
  risk_policy?: "all" | "global" | "custom";
  target_type?: string;
}
export interface RuntimeEvaluation {
  matched: boolean;
  matched_rules: { rule_id: string; rule_version: string; source: string; severity: RuntimeRiskLevel; confidence: number; detection_type: string; detail: string }[];
  risk_score: number;
  risk_level: string;
  decision: RuntimeRiskDecision;
}
