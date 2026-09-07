use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    #[serde(default, rename = "type")]
    pub(crate) detection_kind: String,
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
    #[serde(default, alias = "rule_version")]
    pub(crate) rule_version: String,
    #[serde(default)]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) detail: String,
    #[serde(default)]
    pub(crate) remediation: String,
    #[serde(default)]
    pub(crate) source: String,
    #[serde(default, alias = "created_at")]
    pub(crate) created_at: String,
    #[serde(default, alias = "first_seen_at")]
    pub(crate) first_seen_at: String,
    #[serde(default, alias = "last_seen_at")]
    pub(crate) last_seen_at: String,
    #[serde(default, alias = "event_count")]
    pub(crate) event_count: usize,
    #[serde(default)]
    pub(crate) attributes: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSecuritySummary {
    #[serde(default, alias = "total_detections")]
    pub(crate) total_detections: usize,
    #[serde(default, alias = "security_detections")]
    pub(crate) security_detections: usize,
    #[serde(default, alias = "attack_detections")]
    pub(crate) attack_detections: usize,
    #[serde(default)]
    pub(crate) blocked: usize,
    #[serde(default, alias = "high_or_above")]
    pub(crate) high_or_above: usize,
    #[serde(default, alias = "covered_agents")]
    pub(crate) covered_agents: usize,
    #[serde(default, alias = "latest_at")]
    pub(crate) latest_at: String,
    #[serde(default, alias = "window_start")]
    pub(crate) window_start: String,
    #[serde(default, alias = "window_end")]
    pub(crate) window_end: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSecurityAgent {
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: String,
    #[serde(default, alias = "agent_name")]
    pub(crate) agent_name: String,
    #[serde(default, alias = "agent_type")]
    pub(crate) agent_type: String,
    #[serde(default, alias = "detection_count")]
    pub(crate) detection_count: usize,
    #[serde(default, alias = "attack_count")]
    pub(crate) attack_count: usize,
    #[serde(default, alias = "blocked_count")]
    pub(crate) blocked_count: usize,
    #[serde(default, alias = "high_or_above_count")]
    pub(crate) high_or_above_count: usize,
    #[serde(default, alias = "latest_at")]
    pub(crate) latest_at: String,
    #[serde(default, alias = "runtime_status")]
    pub(crate) runtime_status: String,
}

/// AgentType-level anomaly totals returned by the Go gateway. The backend
/// keeps risk buckets data-driven, so the map deliberately has no enum.
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionAgentTypeSummary {
    #[serde(default, alias = "agent_type_id")]
    pub(crate) agent_type_id: i64,
    #[serde(default, alias = "agent_type")]
    pub(crate) agent_type: String,
    #[serde(default, alias = "agent_type_key")]
    pub(crate) agent_type_key: String,
    #[serde(default, alias = "agent_type_name")]
    pub(crate) agent_type_name: String,
    #[serde(default, alias = "total_events")]
    pub(crate) total_events: usize,
    #[serde(default, alias = "attack_events")]
    pub(crate) attack_events: usize,
    #[serde(default, alias = "risk_counts")]
    pub(crate) risk_counts: BTreeMap<String, usize>,
    #[serde(default, alias = "blocked_events")]
    pub(crate) blocked_events: usize,
    #[serde(default, alias = "open_events")]
    pub(crate) open_events: usize,
    #[serde(default, alias = "latest_at")]
    pub(crate) latest_at: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionAgentTypeSummaryResponse {
    #[serde(default)]
    pub(crate) items: Vec<RuntimeDetectionAgentTypeSummary>,
    #[serde(default)]
    pub(crate) list: Vec<RuntimeDetectionAgentTypeSummary>,
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) count: usize,
    #[serde(default, alias = "captured_at")]
    pub(crate) captured_at: String,
    #[serde(default)]
    pub(crate) source: String,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeAgentListResponse {
    #[serde(default)]
    agents: Vec<RuntimeUnifiedAgent>,
    #[serde(default)]
    items: Vec<RuntimeUnifiedAgent>,
}

#[derive(Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeUnifiedAgent {
    id: String,
    #[serde(default, alias = "name")]
    product: String,
    #[serde(default)]
    kind: String,
    #[serde(default, alias = "runtimeStatus")]
    status: String,
    #[serde(default)]
    runtime_detection_count: usize,
    #[serde(default)]
    runtime_attack_count: usize,
    #[serde(default)]
    runtime_blocked_count: usize,
    #[serde(default)]
    runtime_high_or_above_count: usize,
    #[serde(default)]
    runtime_latest_at: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionListSummary {
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) attack: usize,
    #[serde(default)]
    pub(crate) blocked: usize,
    #[serde(default)]
    pub(crate) critical: usize,
    #[serde(default)]
    pub(crate) high: usize,
    #[serde(default)]
    pub(crate) open: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionListResponse {
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) items: Vec<RuntimeDetection>,
    #[serde(default)]
    pub(crate) list: Vec<RuntimeDetection>,
    #[serde(default)]
    pub(crate) detections: Vec<RuntimeDetection>,
    #[serde(default)]
    pub(crate) summary: RuntimeDetectionListSummary,
    #[serde(default)]
    pub(crate) count: usize,
    #[serde(default)]
    pub(crate) limit: usize,
    #[serde(default)]
    pub(crate) offset: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionAgentContext {
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: String,
    #[serde(default)]
    pub(crate) name: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionSessionContext {
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: String,
    #[serde(default, alias = "trace_id")]
    pub(crate) trace_id: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionEvidenceEvent {
    #[serde(default, alias = "detection_id")]
    pub(crate) detection_id: String,
    #[serde(default, alias = "event_id")]
    pub(crate) event_id: i64,
    #[serde(default, alias = "event_type")]
    pub(crate) event_type: String,
    #[serde(default, alias = "event_source")]
    pub(crate) event_source: String,
    #[serde(default, alias = "event_category")]
    pub(crate) event_category: String,
    #[serde(default)]
    pub(crate) timestamp: String,
    #[serde(default)]
    pub(crate) sequence: usize,
    #[serde(default)]
    pub(crate) role: String,
    #[serde(default, alias = "agent_id")]
    pub(crate) agent_id: String,
    #[serde(default, alias = "agent_name")]
    pub(crate) agent_name: String,
    #[serde(default, alias = "session_id")]
    pub(crate) session_id: String,
    #[serde(default, alias = "trace_id")]
    pub(crate) trace_id: String,
    #[serde(default, alias = "tool_name")]
    pub(crate) tool_name: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) operation: String,
    #[serde(default)]
    pub(crate) outcome: String,
    #[serde(default)]
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) detail: String,
    #[serde(default)]
    pub(crate) attributes: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionDetail {
    #[serde(default)]
    pub(crate) detection: RuntimeDetection,
    #[serde(default)]
    pub(crate) evidence: Vec<RuntimeDetectionEvidenceEvent>,
    #[serde(default)]
    pub(crate) agent: RuntimeDetectionAgentContext,
    #[serde(default, alias = "runtime_session")]
    pub(crate) runtime_session: RuntimeDetectionSessionContext,
    #[serde(default)]
    pub(crate) trace: RuntimeDetectionSessionContext,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEventsTimelineBucket {
    #[serde(default)]
    pub(crate) time: String,
    #[serde(default)]
    pub(crate) bucket: String,
    #[serde(default)]
    pub(crate) total: usize,
    #[serde(default)]
    pub(crate) prompt: usize,
    #[serde(default)]
    pub(crate) tool: usize,
    #[serde(default)]
    pub(crate) process: usize,
    #[serde(default)]
    pub(crate) file: usize,
    #[serde(default)]
    pub(crate) network: usize,
    #[serde(default)]
    pub(crate) content: usize,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeEventsTimelineResponse {
    #[serde(default)]
    pub(crate) buckets: Vec<RuntimeEventsTimelineBucket>,
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

pub(super) fn push_query(query: &mut Vec<String>, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        query.push(format!("{key}={}", urlencode(value)));
    }
}

pub(super) fn path_with_query(path: &str, query: &[String]) -> String {
    if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{}", query.join("&"))
    }
}

#[tauri::command]
pub fn get_runtime_security_summary(
    app: tauri::AppHandle,
    agent_id: Option<String>,
) -> Result<RuntimeSecuritySummary, String> {
    let mut query = Vec::new();
    push_query(&mut query, "agent_id", agent_id.as_deref());
    crate::commands::gateway_api::get_json::<RuntimeSecuritySummary>(
        &app,
        &path_with_query("/api/v1/runtime-security/summary", &query),
    )
    .map_err(|error| format!("获取运行态检测总览失败：{error}"))
}

/// Shared by the paginated list and the full AgentType summary. Pagination
/// intentionally lives outside this structure so totals cannot become page totals.
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeDetectionFilters {
    agent_id: Option<String>,
    agent_type_id: Option<i64>,
    agent_type: Option<String>,
    category: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    source: Option<String>,
    keyword: Option<String>,
    trace_id: Option<String>,
    session_id: Option<String>,
    detection_type: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
}

impl RuntimeDetectionFilters {
    fn query(&self) -> Vec<String> {
        let mut query = Vec::new();
        for (key, value) in [
            ("agent_id", &self.agent_id),
            ("agent_type", &self.agent_type),
            ("category", &self.category),
            ("severity", &self.severity),
            ("status", &self.status),
            ("source", &self.source),
            ("keyword", &self.keyword),
            ("trace_id", &self.trace_id),
            ("session_id", &self.session_id),
            ("detection_type", &self.detection_type),
            ("start_time", &self.start_time),
            ("end_time", &self.end_time),
        ] {
            push_query(&mut query, key, value.as_deref());
        }
        if let Some(id) = self.agent_type_id {
            query.push(format!("AgenttypeId={id}"));
        }
        query
    }
}

#[cfg(test)]
mod detection_filter_tests {
    use super::*;

    #[test]
    fn current_agent_inventory_names_and_status_parse() {
        let response: RuntimeAgentListResponse = serde_json::from_value(serde_json::json!({
            "agents": [{ "id":"instance-1", "name":"Codex", "runtimeStatus":"running", "kind":"agent", "runtimeDetectionCount":24, "runtimeHighOrAboveCount":16 }]
        })).unwrap();
        let agent = &response.agents[0];
        assert_eq!(agent.product, "Codex");
        assert_eq!(agent.status, "running");
        assert_eq!(agent.runtime_detection_count, 24);
        assert_eq!(agent.runtime_high_or_above_count, 16);
        let legacy: RuntimeUnifiedAgent = serde_json::from_value(serde_json::json!({"id":"legacy", "product":"Legacy", "status":"stopped", "kind":"agent"})).unwrap();
        assert_eq!(legacy.product, "Legacy");
        assert_eq!(legacy.status, "stopped");
    }

    #[test]
    fn desktop_filters_preserve_instance_type_time_and_multivalue_risks() {
        let filters: RuntimeDetectionFilters = serde_json::from_value(serde_json::json!({
            "agentId": "instance/a", "agentTypeId": 42, "agentType": "类型 A",
            "severity": "CRITICAL,HIGH", "status": "open,resolved",
            "category": "attack", "source": "hook", "keyword": "key&value",
            "sessionId": "session 1", "traceId": "trace?2", "detectionType": "rule_a,rule_b",
            "startTime": "2026-09-05T00:00:00+08:00", "endTime": "2026-09-06T00:00:00Z",
            "page": 7, "pageSize": 20, "limit": 1, "offset": 100
        }))
        .unwrap();
        let query = filters.query();
        assert_eq!(query.len(), 13);
        for expected in [
            "agent_id=instance%2Fa",
            "AgenttypeId=42",
            "severity=CRITICAL%2CHIGH",
            "keyword=key%26value",
            "detection_type=rule_a%2Crule_b",
            "start_time=2026-09-05T00%3A00%3A00%2B08%3A00",
        ] {
            assert!(
                query.iter().any(|value| value == expected),
                "missing {expected}: {query:?}"
            );
        }
        assert!(!query
            .iter()
            .any(|value| ["page=", "page_size=", "limit=", "offset="]
                .iter()
                .any(|prefix| value.starts_with(prefix))));
        assert!(RuntimeDetectionFilters::default().query().is_empty());
    }
}

#[tauri::command]
pub fn get_runtime_detection_agent_type_summaries(
    app: tauri::AppHandle,
    filters: Option<RuntimeDetectionFilters>,
) -> Result<RuntimeDetectionAgentTypeSummaryResponse, String> {
    let query = filters.unwrap_or_default().query();
    crate::commands::gateway_api::get_json::<RuntimeDetectionAgentTypeSummaryResponse>(
        &app,
        &path_with_query("/api/v1/runtime-detections/summary/agent-types", &query),
    )
    .map_err(|error| format!("获取 AgentType 异常事件汇总失败：{error}"))
}

#[tauri::command]
pub fn get_runtime_security_agents(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<Vec<RuntimeSecurityAgent>, String> {
    let limit = limit.unwrap_or(200).clamp(10, 1_000);
    let response = crate::commands::gateway_api::get_json::<RuntimeAgentListResponse>(
        &app,
        &format!("/api/v1/agents?page_size={limit}"),
    )
    .map_err(|error| format!("获取运行态 Agent 检测汇总失败：{error}"))?;
    let agents = if response.agents.is_empty() {
        response.items
    } else {
        response.agents
    };
    Ok(agents
        .into_iter()
        .map(|agent| RuntimeSecurityAgent {
            agent_id: agent.id,
            agent_name: agent.product,
            agent_type: agent.kind,
            detection_count: agent.runtime_detection_count,
            attack_count: agent.runtime_attack_count,
            blocked_count: agent.runtime_blocked_count,
            high_or_above_count: agent.runtime_high_or_above_count,
            latest_at: agent.runtime_latest_at,
            runtime_status: agent.status,
        })
        .collect())
}

#[tauri::command]
pub fn get_runtime_detections(
    app: tauri::AppHandle,
    agent_id: Option<String>,
    agent_type_id: Option<i64>,
    agent_type: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
    category: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    source: Option<String>,
    keyword: Option<String>,
    trace_id: Option<String>,
    session_id: Option<String>,
    detection_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    sort: Option<String>,
) -> Result<RuntimeDetectionListResponse, String> {
    let mut query = RuntimeDetectionFilters {
        agent_id,
        agent_type_id,
        agent_type,
        start_time,
        end_time,
        category,
        severity,
        status,
        source,
        keyword,
        trace_id,
        session_id,
        detection_type,
    }
    .query();
    push_query(&mut query, "sort", sort.as_deref());
    if page.is_some() || page_size.is_some() {
        query.push(format!("page={}", page.unwrap_or(1).max(1)));
        query.push(format!(
            "page_size={}",
            page_size.unwrap_or(20).clamp(1, 1_000)
        ));
    } else {
        query.push(format!("limit={}", limit.unwrap_or(20).clamp(1, 1_000)));
        query.push(format!("offset={}", offset.unwrap_or(0)));
    }

    let mut response = crate::commands::gateway_api::get_json::<RuntimeDetectionListResponse>(
        &app,
        &path_with_query("/api/v1/runtime-detections", &query),
    )
    .map_err(|error| format!("获取运行态检测列表失败：{error}"))?;

    if response.items.is_empty() {
        response.items = if response.list.is_empty() {
            response.detections.clone()
        } else {
            response.list.clone()
        };
    }
    if response.detections.is_empty() {
        response.detections = response.items.clone();
    }
    if response.count == 0 {
        response.count = response.items.len();
    }
    if response.total == 0 {
        response.total = response.count;
    }
    Ok(response)
}

#[tauri::command]
pub fn get_runtime_detection_detail(
    app: tauri::AppHandle,
    detection_id: String,
) -> Result<RuntimeDetectionDetail, String> {
    let detection_id = detection_id.trim();
    if detection_id.is_empty() {
        return Err("detection_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::get_json::<RuntimeDetectionDetail>(
        &app,
        &format!("/api/v1/runtime-detections/{}", urlencode(detection_id)),
    )
    .map_err(|error| format!("获取运行态检测详情失败：{error}"))
}

#[tauri::command]
pub fn get_runtime_detection_events(
    app: tauri::AppHandle,
    detection_id: String,
) -> Result<Vec<RuntimeDetectionEvidenceEvent>, String> {
    let detection_id = detection_id.trim();
    if detection_id.is_empty() {
        return Err("detection_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::get_json::<Vec<RuntimeDetectionEvidenceEvent>>(
        &app,
        &format!(
            "/api/v1/runtime-detections/{}/events",
            urlencode(detection_id)
        ),
    )
    .map_err(|error| format!("获取运行态检测证据事件失败：{error}"))
}

#[tauri::command]
pub fn get_runtime_events_timeline(
    app: tauri::AppHandle,
    agent_id: Option<String>,
    bucket: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
) -> Result<RuntimeEventsTimelineResponse, String> {
    let mut query = Vec::new();
    push_query(&mut query, "agent_id", agent_id.as_deref());
    push_query(&mut query, "bucket", bucket.as_deref());
    push_query(&mut query, "start_time", start_time.as_deref());
    push_query(&mut query, "end_time", end_time.as_deref());
    push_query(&mut query, "session_id", session_id.as_deref());
    push_query(&mut query, "trace_id", trace_id.as_deref());
    crate::commands::gateway_api::get_json::<RuntimeEventsTimelineResponse>(
        &app,
        &path_with_query("/api/v1/runtime-events/timeline", &query),
    )
    .map_err(|error| format!("获取运行态事件时间线失败：{error}"))
}
