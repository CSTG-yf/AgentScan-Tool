use super::events::{path_with_query, push_query};
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainSnapshot {
    captured_at: String,
    source: String,
    chains: Vec<AttackChain>,
    #[serde(default)]
    total: Option<usize>,
    #[serde(default)]
    page: Option<usize>,
    #[serde(default, alias = "page_size")]
    page_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainAgentSummary {
    #[serde(alias = "agent_id")]
    agent_id: String,
    #[serde(alias = "total_chains")]
    total_chains: usize,
    #[serde(alias = "high_or_above")]
    high_or_above: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainAgentTypeSummary {
    #[serde(default, alias = "covered_agents")]
    pub(crate) covered_agents: usize,
    #[serde(default)]
    pub(crate) agents: Vec<AttackChainAgentSummary>,
    #[serde(default, alias = "agent_type_id")]
    pub(crate) agent_type_id: i64,
    #[serde(default, alias = "agent_type")]
    pub(crate) agent_type: String,
    #[serde(default, alias = "agent_type_key")]
    pub(crate) agent_type_key: String,
    #[serde(default, alias = "agent_type_name")]
    pub(crate) agent_type_name: String,
    #[serde(default, alias = "total_chains")]
    pub(crate) total_chains: usize,
    #[serde(default, alias = "status_counts")]
    pub(crate) status_counts: BTreeMap<String, usize>,
    #[serde(default, alias = "severity_counts")]
    pub(crate) severity_counts: BTreeMap<String, usize>,
    #[serde(default, alias = "active_chains")]
    pub(crate) active_chains: usize,
    #[serde(default, alias = "contained_chains")]
    pub(crate) contained_chains: usize,
    #[serde(default, alias = "latest_at")]
    pub(crate) latest_at: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainAgentTypeSummaryResponse {
    #[serde(default)]
    pub(crate) items: Vec<AttackChainAgentTypeSummary>,
    #[serde(default)]
    pub(crate) list: Vec<AttackChainAgentTypeSummary>,
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) count: usize,
    #[serde(default, alias = "captured_at")]
    pub(crate) captured_at: String,
    #[serde(default)]
    pub(crate) source: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackChain {
    #[serde(default)]
    agent_id: String,
    #[serde(default)]
    agent_type_id: i64,
    #[serde(default)]
    agent_type_name: String,
    #[serde(default)]
    raw_status: String,
    #[serde(default)]
    raw_severity: String,
    id: String,
    trace_id: String,
    session_id: String,
    agent: String,
    runtime: String,
    category: String,
    risk: String,
    status: String,
    started_at: String,
    ended_at: String,
    summary: String,
    step_count: usize,
    evidence_count: usize,
    sources: Vec<String>,
    steps: Vec<AttackChainStep>,
    evidence: Vec<AttackChainEvidenceRow>,
    // Phase 3: links to the structured detection and the policy
    // decision behind this persisted chain (empty for legacy
    // page-correlated chains).
    #[serde(default)]
    detection_id: String,
    #[serde(default)]
    decision_id: String,
    #[serde(default)]
    builder_version: String,
    #[serde(default)]
    policy_version: String,
    #[serde(default)]
    evaluation_job_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackChainStep {
    id: String,
    order: usize,
    occurred_at: String,
    title: String,
    stage: String,
    kind: String,
    severity: String,
    actor: String,
    prompt: String,
    tool: String,
    resource: String,
    evidence: String,
    decision: String,
    stack: Vec<String>,
    source_event_id: String,
    source: String,
    trace_id: String,
    session_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AttackChainEvidenceRow {
    key: String,
    index: usize,
    occurred_at: String,
    stage: String,
    agent: String,
    tool: String,
    resource: String,
    decision: String,
    evidence: String,
    source_event_id: String,
    source: String,
}

/// Non-pagination filters shared by the table and full summary.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainFilters {
    agent_id: Option<String>,
    agent_type_id: Option<i64>,
    session_id: Option<String>,
    trace_id: Option<String>,
    attack_type: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    keyword: Option<String>,
}

impl AttackChainFilters {
    fn query(&self) -> Vec<String> {
        let mut q = Vec::new();
        for (key, value) in [
            ("agent_id", &self.agent_id),
            ("session_id", &self.session_id),
            ("trace_id", &self.trace_id),
            ("attack_type", &self.attack_type),
            ("start_time", &self.start_time),
            ("end_time", &self.end_time),
            ("keyword", &self.keyword),
        ] {
            push_query(&mut q, key, value.as_deref());
        }
        if let Some(id) = self.agent_type_id {
            q.push(format!("AgenttypeId={id}"));
        }
        if let Some(value) = &self.severity {
            push_query(&mut q, "severity", Some(&value.to_uppercase()));
        }
        if let Some(value) = &self.status {
            let value = value.trim().to_lowercase();
            push_query(
                &mut q,
                "status",
                Some(if value == "blocked" || value == "mitigated" {
                    "contained"
                } else {
                    &value
                }),
            );
        }
        q
    }
}

#[tauri::command]
pub fn get_attack_chains(
    app: tauri::AppHandle,
    limit: Option<usize>,
    filters: Option<AttackChainFilters>,
    page: Option<usize>,
    page_size: Option<usize>,
    sort: Option<String>,
) -> Result<AttackChainSnapshot, String> {
    let mut q = filters.unwrap_or_default().query();
    q.push(format!("page={}", page.unwrap_or(1).max(1)));
    q.push(format!(
        "page_size={}",
        page_size.or(limit).unwrap_or(20).clamp(1, 200)
    ));
    push_query(&mut q, "sort", sort.as_deref());
    crate::commands::gateway_api::get_json::<AttackChainSnapshot>(
        &app,
        &path_with_query("/api/v1/attack-chains", &q),
    )
    .map_err(|error| format!("读取攻击链失败：{error}"))
}

#[tauri::command]
pub fn get_attack_chain_agent_type_summaries(
    app: tauri::AppHandle,
    filters: Option<AttackChainFilters>,
) -> Result<AttackChainAgentTypeSummaryResponse, String> {
    let q = filters.unwrap_or_default().query();
    crate::commands::gateway_api::get_json::<AttackChainAgentTypeSummaryResponse>(
        &app,
        &path_with_query("/api/v1/attack-chains/summary/agent-types", &q),
    )
    .map_err(|error| format!("获取 AgentType 攻击链汇总失败：{error}"))
}

#[tauri::command]
pub fn get_attack_chain_detail(
    app: tauri::AppHandle,
    chain_id: String,
) -> Result<serde_json::Value, String> {
    let id = chain_id.trim();
    if id.is_empty()
        || id.len() > 256
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
    {
        return Err("攻击链 ID 无效".into());
    }
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!("/api/v1/attack-chains/{id}"),
    )
}

#[cfg(test)]
mod chain_filter_tests {
    use super::*;
    #[test]
    fn filters_preserve_identity_and_dynamic_values_without_paging() {
        let filters: AttackChainFilters = serde_json::from_value(serde_json::json!({
            "agentId":"agent/a & b", "agentTypeId":14, "sessionId":"s+1", "traceId":"t?2",
            "attackType":"vendor/type", "severity":"vendor-risk", "status":"mitigated",
            "startTime":"2026-09-01T00:00:00Z", "endTime":"2026-09-02T00:00:00Z",
            "keyword":"a&severity=LOW", "page":99, "pageSize":1, "sort":"oldest"
        }))
        .unwrap();
        let q = filters.query();
        assert_eq!(q.len(), 10);
        for expected in [
            "agent_id=agent%2Fa%20%26%20b",
            "AgenttypeId=14",
            "session_id=s%2B1",
            "trace_id=t%3F2",
            "severity=VENDOR-RISK",
            "status=contained",
            "keyword=a%26severity%3DLOW",
        ] {
            assert!(q.iter().any(|v| v == expected), "missing {expected}: {q:?}");
        }
        assert!(!q
            .iter()
            .any(|v| v.starts_with("page") || v.starts_with("sort")));
    }
    #[test]
    fn instance_summary_survives_ipc_serialization() {
        let row: AttackChainAgentTypeSummary = serde_json::from_value(serde_json::json!({
            "agent_type_id":14,"total_chains":3,"covered_agents":2,
            "status_counts":{"vendor-status":3},"severity_counts":{"vendor-risk":3},
            "agents":[{"agent_id":"one","total_chains":2,"high_or_above":1}]
        }))
        .unwrap();
        let value = serde_json::to_value(row).unwrap();
        assert_eq!(value["coveredAgents"], 2);
        assert_eq!(value["agents"][0]["agentId"], "one");
        assert_eq!(value["severityCounts"]["vendor-risk"], 3);
    }
}
