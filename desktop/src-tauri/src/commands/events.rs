use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDetectionSnapshot {
    pub(crate) captured_at: String,
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) summary: EventDetectionSummary,
    #[serde(default)]
    pub(crate) source_breakdown: Vec<EventBreakdown>,
    #[serde(default)]
    pub(crate) agent_breakdown: Vec<EventAgentBreakdown>,
    #[serde(default)]
    pub(crate) timeline: Vec<EventTimelineBucket>,
    pub(crate) events: Vec<DetectedEvent>,
    // Phase-2 structured detections (runtime_detections): what is
    // actually risky per the agent-agnostic rules — the page prefers
    // these over string-matching heuristics.
    #[serde(default)]
    pub(crate) detections: Vec<RuntimeDetection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) warning: Option<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventDetectionSummary {
    pub(crate) total: usize,
    pub(crate) security: usize,
    pub(crate) attack: usize,
    pub(crate) blocked: usize,
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) correlated: usize,
    pub(crate) agents: usize,
    pub(crate) sources: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) window_start: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) window_end: String,
    // Phase-2 detection-backed counters.
    #[serde(default)]
    pub(crate) detections: usize,
    #[serde(default)]
    pub(crate) attack_detections: usize,
    #[serde(default)]
    pub(crate) open_detections: usize,
}

/// Phase-2 structured runtime detection (runtime_detections row).
/// The Go gateway sends snake_case keys (audit.RuntimeDetection JSON
/// tags); aliases accept those while the frontend receives camelCase.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetection {
    #[serde(alias = "detection_id")]
    pub(crate) detection_id: String,
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: String,
    #[serde(default, alias = "agent_name")]
    pub(crate) agent_name: String,
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: String,
    #[serde(default, alias = "trace_id")]
    pub(crate) trace_id: String,
    #[serde(default, alias = "detection_type")]
    pub(crate) detection_type: String,
    #[serde(default)]
    pub(crate) category: String,
    #[serde(default)]
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) confidence: f64,
    #[serde(default, alias = "rule_id")]
    pub(crate) rule_id: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) detail: String,
    #[serde(default)]
    pub(crate) remediation: String,
    #[serde(default, alias = "first_seen_at")]
    pub(crate) first_seen_at: String,
    #[serde(default, alias = "last_seen_at")]
    pub(crate) last_seen_at: String,
    #[serde(default, alias = "event_count")]
    pub(crate) event_count: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventBreakdown {
    pub(crate) name: String,
    pub(crate) count: usize,
    pub(crate) attack: usize,
    pub(crate) blocked: usize,
    pub(crate) max_severity: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventAgentBreakdown {
    pub(crate) agent: String,
    pub(crate) runtime: String,
    pub(crate) count: usize,
    pub(crate) attack: usize,
    pub(crate) blocked: usize,
    pub(crate) max_severity: String,
    pub(crate) last_seen: String,
    pub(crate) sources: Vec<String>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventTimelineBucket {
    pub(crate) bucket: String,
    pub(crate) total: usize,
    pub(crate) attack: usize,
    pub(crate) blocked: usize,
    pub(crate) high_risk: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DetectedEvent {
    pub(crate) id: String,
    pub(crate) occurred_at: String,
    #[serde(rename = "kind")]
    pub(crate) event_kind: String,
    pub(crate) agent: String,
    pub(crate) runtime: String,
    pub(crate) category: String,
    pub(crate) subtype: String,
    pub(crate) title: String,
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) risk_score: u8,
    pub(crate) status: String,
    pub(crate) evidence: String,
    pub(crate) action: String,
    pub(crate) trace_id: String,
    pub(crate) session_id: String,
    #[serde(default)]
    pub(crate) correlation_key: String,
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) raw_action: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) actor: String,
    #[serde(default)]
    pub(crate) connector: String,
    #[serde(default)]
    pub(crate) destination_app: String,
    #[serde(default)]
    pub(crate) tool_name: String,
    #[serde(default)]
    pub(crate) model: String,
    #[serde(default)]
    pub(crate) mcp_server: String,
    #[serde(default)]
    pub(crate) decision: String,
    #[serde(default)]
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) remediation: String,
    // Phase-2 structured detection backing: when this event is
    // evidence of a runtime detection, kind/severity come from the
    // detection instead of string matching.
    #[serde(default)]
    pub(crate) detection_id: String,
    #[serde(default)]
    pub(crate) detection_type: String,
    #[serde(default)]
    pub(crate) detection_severity: String,
}

#[tauri::command]
pub fn get_event_detections(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<EventDetectionSnapshot, String> {
    let limit = limit.unwrap_or(300).clamp(50, 1_000);
    crate::commands::gateway_api::get_json::<EventDetectionSnapshot>(
        &app,
        &format!("/api/v1/event-detections?limit={limit}"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，事件检测只能由 Go 后端提供：{error}"))
}
