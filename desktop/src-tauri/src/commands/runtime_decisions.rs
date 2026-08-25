use serde::{Deserialize, Serialize};

use crate::commands::events::RuntimeDetection;

/// Phase-3 unified policy decision (runtime_decisions row). The Go
/// gateway sends snake_case keys; aliases accept those while the
/// frontend receives camelCase.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDecision {
    #[serde(alias = "decision_id")]
    pub(crate) decision_id: String,
    #[serde(default, alias = "detection_id")]
    pub(crate) detection_id: String,
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: String,
    #[serde(default, alias = "agent_name")]
    pub(crate) agent_name: String,
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: String,
    #[serde(default, alias = "trace_id")]
    pub(crate) trace_id: String,
    #[serde(default)]
    pub(crate) decision: String,
    #[serde(default, alias = "risk_score")]
    pub(crate) risk_score: f64,
    #[serde(default)]
    pub(crate) confidence: f64,
    #[serde(default, alias = "policy_id")]
    pub(crate) policy_id: String,
    #[serde(default)]
    pub(crate) reason: String,
    #[serde(default, alias = "enforcement_point")]
    pub(crate) enforcement_point: String,
    #[serde(default)]
    pub(crate) mode: String,
    #[serde(default, alias = "would_block")]
    pub(crate) would_block: bool,
    #[serde(default, alias = "created_at")]
    pub(crate) created_at: String,
}

/// One decision row from the list endpoint: the decision paired with
/// its originating detection for one-row rendering.
#[derive(Clone, Default, Deserialize, Serialize)]
pub struct RuntimeDecisionRow {
    #[serde(flatten)]
    pub(crate) decision: RuntimeDecision,
    #[serde(default)]
    pub(crate) detection: RuntimeDetection,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDecisionSummary {
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) block: usize,
    #[serde(default)]
    pub(crate) confirm: usize,
    #[serde(default)]
    pub(crate) alert: usize,
    #[serde(default)]
    pub(crate) audit: usize,
    #[serde(default)]
    pub(crate) allow: usize,
    #[serde(default)]
    pub(crate) would_block: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct RuntimeDecisionListResponse {
    #[serde(default)]
    pub(crate) decisions: Vec<RuntimeDecisionRow>,
    #[serde(default)]
    pub(crate) summary: RuntimeDecisionSummary,
    #[serde(default)]
    pub(crate) count: usize,
}

/// Phase-3 response action (runtime_response_actions row): what was
/// actually executed for a decision, at which enforcement point.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeResponseAction {
    #[serde(alias = "response_id")]
    pub(crate) response_id: String,
    #[serde(default, alias = "decision_id")]
    pub(crate) decision_id: String,
    #[serde(default, alias = "action_type")]
    pub(crate) action_type: String,
    #[serde(default)]
    pub(crate) executor: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) result: String,
    #[serde(default, alias = "executed_at")]
    pub(crate) executed_at: String,
}

/// The behavior_events row behind one evidence link — only the fields
/// the decision drawer renders.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceBehaviorEvent {
    #[serde(default)]
    pub(crate) id: i64,
    #[serde(default)]
    pub(crate) timestamp: String,
    #[serde(default, alias = "event_type")]
    pub(crate) event_type: String,
    #[serde(default, alias = "event_source")]
    pub(crate) event_source: String,
    #[serde(default, alias = "agent_name")]
    pub(crate) agent_name: String,
    #[serde(default, alias = "tool_name")]
    pub(crate) tool_name: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) outcome: String,
    #[serde(default)]
    pub(crate) detail: String,
}

/// One evidence event supporting a decision's detection: the link
/// (role/sequence) joined with its behavior_events row under "event".
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionEvidenceEvent {
    #[serde(default, alias = "event_id")]
    pub(crate) event_id: i64,
    #[serde(default)]
    pub(crate) role: String,
    #[serde(default)]
    pub(crate) sequence: usize,
    #[serde(default)]
    pub(crate) event: EvidenceBehaviorEvent,
}

#[derive(Clone, Default, Deserialize, Serialize)]
pub struct RuntimeDecisionDetail {
    #[serde(default)]
    pub(crate) decision: RuntimeDecision,
    #[serde(default)]
    pub(crate) responses: Vec<RuntimeResponseAction>,
    #[serde(default)]
    pub(crate) detection: RuntimeDetection,
    #[serde(default)]
    pub(crate) evidence: Vec<DecisionEvidenceEvent>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct SecurityModeResponse {
    mode: String,
}

#[tauri::command]
pub fn get_runtime_decisions(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<RuntimeDecisionListResponse, String> {
    let limit = limit.unwrap_or(200).clamp(10, 1_000);
    crate::commands::gateway_api::get_json::<RuntimeDecisionListResponse>(
        &app,
        &format!("/api/v1/runtime-decisions?limit={limit}"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，运行时决策只能由 Go 后端提供：{error}"))
}

#[tauri::command]
pub fn get_runtime_decision_detail(
    app: tauri::AppHandle,
    decision_id: String,
) -> Result<RuntimeDecisionDetail, String> {
    if decision_id.trim().is_empty() {
        return Err("decision_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::get_json::<RuntimeDecisionDetail>(
        &app,
        &format!("/api/v1/runtime-decisions/{}", decision_id.trim()),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，运行时决策只能由 Go 后端提供：{error}"))
}

#[tauri::command]
pub fn get_runtime_security_mode(app: tauri::AppHandle) -> Result<String, String> {
    crate::commands::gateway_api::get_json::<SecurityModeResponse>(
        &app,
        "/api/v1/runtime-security-mode",
    )
    .map(|response| response.mode)
    .map_err(|error| format!("Go Gateway 暂不可用，安全模式只能由 Go 后端提供：{error}"))
}

#[tauri::command]
pub fn set_runtime_security_mode(app: tauri::AppHandle, mode: String) -> Result<String, String> {
    let mode = mode.trim().to_ascii_lowercase();
    if mode != "observe" && mode != "action" {
        return Err("mode 必须是 observe 或 action".to_owned());
    }
    crate::commands::gateway_api::put_json::<SecurityModeResponse, _>(
        &app,
        "/api/v1/runtime-security-mode",
        &serde_json::json!({ "mode": mode }),
    )
    .map(|response| response.mode)
    .map_err(|error| format!("Go Gateway 暂不可用，安全模式只能由 Go 后端切换：{error}"))
}
