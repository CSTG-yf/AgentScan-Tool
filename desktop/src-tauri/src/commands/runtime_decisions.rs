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
    #[serde(default, alias = "idempotency_key")]
    pub(crate) idempotency_key: String,
    #[serde(default)]
    pub(crate) source: String,
    #[serde(default, alias = "policy_version")]
    pub(crate) policy_version: String,
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
    #[serde(default, alias = "would_block")]
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
    #[serde(default, alias = "rollback_supported")]
    pub(crate) rollback_supported: bool,
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

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[tauri::command]
pub fn get_runtime_decisions(
    app: tauri::AppHandle,
    limit: Option<usize>,
    detection_id: Option<String>,
) -> Result<RuntimeDecisionListResponse, String> {
    let limit = limit.unwrap_or(200).clamp(10, 1_000);
    let mut path = format!("/api/v1/runtime-decisions?limit={limit}");
    if let Some(id) = detection_id.filter(|id| !id.trim().is_empty()) {
        path.push_str(&format!("&detection_id={}", urlencode(id.trim())));
    }
    crate::commands::gateway_api::get_json::<RuntimeDecisionListResponse>(&app, &path)
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
        "/api/v1/runtime-security/mode",
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
        "/api/v1/runtime-security/mode",
        &serde_json::json!({ "mode": mode }),
    )
    .map(|response| response.mode)
    .map_err(|error| format!("Go Gateway 暂不可用，安全模式只能由 Go 后端切换：{error}"))
}

#[tauri::command]
pub fn block_runtime_detection(
    app: tauri::AppHandle,
    detection_id: String,
    action_type: Option<String>,
    reason: Option<String>,
    preview: Option<bool>,
    idempotency_key: Option<String>,
) -> Result<serde_json::Value, String> {
    let detection_id = detection_id.trim();
    if detection_id.is_empty() {
        return Err("detection_id 不能为空".to_owned());
    }
    let mut body = serde_json::json!({
        "reason": reason.unwrap_or_else(|| "manual_operator_action".to_owned()),
    });
    if let Some(action_type) = action_type.filter(|value| !value.trim().is_empty()) {
        body["action_type"] = serde_json::Value::String(action_type);
    }
    if preview.unwrap_or(false) {
        body["preview"] = serde_json::Value::Bool(true);
    }
    if let Some(key) = idempotency_key.filter(|value| !value.trim().is_empty()) {
        body["idempotency_key"] = serde_json::Value::String(key);
    }
    crate::commands::gateway_api::post_json::<serde_json::Value, _>(
        &app,
        &format!(
            "/api/v1/runtime-detections/{}/actions/block",
            urlencode(detection_id)
        ),
        &body,
    )
    .map_err(|error| format!("执行运行时检测阻断失败：{error}"))
}

#[tauri::command]
pub fn enforce_runtime_decision(
    app: tauri::AppHandle,
    decision_id: String,
    preview: Option<bool>,
    idempotency_key: Option<String>,
) -> Result<serde_json::Value, String> {
    let decision_id = decision_id.trim();
    if decision_id.is_empty() {
        return Err("decision_id 不能为空".to_owned());
    }
    let mut body = serde_json::json!({});
    if preview.unwrap_or(false) {
        body["preview"] = serde_json::Value::Bool(true);
    }
    if let Some(key) = idempotency_key.filter(|value| !value.trim().is_empty()) {
        body["idempotency_key"] = serde_json::Value::String(key);
    }
    crate::commands::gateway_api::post_json::<serde_json::Value, _>(
        &app,
        &format!(
            "/api/v1/runtime-decisions/{}/enforce",
            urlencode(decision_id)
        ),
        &body,
    )
    .map_err(|error| format!("执行运行时决策失败：{error}"))
}

#[tauri::command]
pub fn rollback_runtime_enforcement(
    app: tauri::AppHandle,
    enforcement_id: String,
) -> Result<serde_json::Value, String> {
    let enforcement_id = enforcement_id.trim();
    if enforcement_id.is_empty() {
        return Err("enforcement_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::post_json::<serde_json::Value, _>(
        &app,
        &format!(
            "/api/v1/enforcements/{}/rollback",
            urlencode(enforcement_id)
        ),
        &serde_json::json!({}),
    )
    .map_err(|error| format!("回滚运行时阻断失败：{error}"))
}

#[tauri::command]
pub fn get_runtime_enforcements(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(&app, "/api/v1/enforcements")
        .map_err(|error| format!("获取运行时阻断列表失败：{error}"))
}

#[tauri::command]
pub fn get_runtime_enforcement(
    app: tauri::AppHandle,
    enforcement_id: String,
) -> Result<serde_json::Value, String> {
    let enforcement_id = enforcement_id.trim();
    if enforcement_id.is_empty() {
        return Err("enforcement_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!("/api/v1/enforcements/{}", urlencode(enforcement_id)),
    )
    .map_err(|error| format!("获取运行时阻断详情失败：{error}"))
}

#[tauri::command]
pub fn delete_runtime_enforcement(
    app: tauri::AppHandle,
    enforcement_id: String,
) -> Result<serde_json::Value, String> {
    let enforcement_id = enforcement_id.trim();
    if enforcement_id.is_empty() {
        return Err("enforcement_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::delete_json::<serde_json::Value>(
        &app,
        &format!("/api/v1/enforcements/{}", urlencode(enforcement_id)),
    )
    .map_err(|error| format!("删除运行时阻断失败：{error}"))
}
