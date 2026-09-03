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
pub struct AttackChainAgentTypeSummary {
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

#[tauri::command]
pub fn get_attack_chains(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<AttackChainSnapshot, String> {
    let limit = limit.unwrap_or(500).clamp(100, 1_000);
    crate::commands::gateway_api::get_json::<AttackChainSnapshot>(
        &app,
        &format!("/api/v1/attack-chains?limit={limit}"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，攻击链重建只能由 Go 后端提供：{error}"))
}

#[tauri::command]
pub fn get_attack_chain_agent_type_summaries(
    app: tauri::AppHandle,
) -> Result<AttackChainAgentTypeSummaryResponse, String> {
    crate::commands::gateway_api::get_json::<AttackChainAgentTypeSummaryResponse>(
        &app,
        "/api/v1/attack-chains/summary/agent-types",
    )
    .map_err(|error| format!("获取 AgentType 攻击链汇总失败：{error}"))
}
