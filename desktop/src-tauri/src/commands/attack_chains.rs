use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttackChainSnapshot {
    captured_at: String,
    source: String,
    chains: Vec<AttackChain>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
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
