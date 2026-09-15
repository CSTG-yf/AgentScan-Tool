use crate::models::{GatewayAuditSnapshot, GuardAuditSnapshot};
use serde::Deserialize;

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEventPageQuery {
    agent_id: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    action: Option<String>,
    severity: Option<String>,
    connector: Option<String>,
    enforced: Option<bool>,
    actor: Option<String>,
    tool_name: Option<String>,
    policy_id: Option<String>,
    request_id: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
    keyword: Option<String>,
    sort: Option<String>,
    page: Option<usize>,
    page_size: Option<usize>,
}
impl AuditEventPageQuery {
    fn query(&self, paginate: bool) -> Vec<String> {
        let mut q = Vec::new();
        for (key, value) in [
            ("agent_id", &self.agent_id),
            ("start_time", &self.start_time),
            ("end_time", &self.end_time),
            ("action", &self.action),
            ("severity", &self.severity),
            ("connector", &self.connector),
            ("actor", &self.actor),
            ("tool_name", &self.tool_name),
            ("policy_id", &self.policy_id),
            ("request_id", &self.request_id),
            ("session_id", &self.session_id),
            ("trace_id", &self.trace_id),
            ("keyword", &self.keyword),
            ("sort", &self.sort),
        ] {
            super::events::push_query(&mut q, key, value.as_deref())
        }
        if let Some(v) = self.enforced {
            q.push(format!("enforced={v}"))
        }
        if paginate {
            q.push(format!("page={}", self.page.unwrap_or(1).max(1)));
            q.push(format!(
                "page_size={}",
                self.page_size.unwrap_or(20).clamp(1, 200)
            ))
        }
        q
    }
}
#[tauri::command]
pub fn get_audit_events(
    app: tauri::AppHandle,
    query: Option<AuditEventPageQuery>,
) -> Result<serde_json::Value, String> {
    let q = query.unwrap_or_default();
    super::gateway_api::get_json(
        &app,
        &super::events::path_with_query("/api/v1/audit-events", &q.query(true)),
    )
    .map_err(|e| format!("获取审计事件失败：{e}"))
}
#[tauri::command]
pub fn get_audit_event_detail(
    app: tauri::AppHandle,
    event_id: String,
) -> Result<serde_json::Value, String> {
    let id = event_id.trim();
    if id.is_empty() {
        return Err("event_id 不能为空".into());
    }
    super::gateway_api::get_json(
        &app,
        &format!("/api/v1/audit-events/{}", super::events::urlencode(id)),
    )
    .map_err(|e| format!("获取审计事件详情失败：{e}"))
}
#[tauri::command]
pub fn get_audit_event_summary(
    app: tauri::AppHandle,
    query: Option<AuditEventPageQuery>,
) -> Result<serde_json::Value, String> {
    let q = query.unwrap_or_default();
    super::gateway_api::get_json(
        &app,
        &super::events::path_with_query("/api/v1/audit-events/summary", &q.query(false)),
    )
    .map_err(|e| format!("获取审计总览失败：{e}"))
}
#[tauri::command]
pub fn get_audit_event_agents(
    app: tauri::AppHandle,
    query: Option<AuditEventPageQuery>,
) -> Result<serde_json::Value, String> {
    let q = query.unwrap_or_default();
    super::gateway_api::get_json(
        &app,
        &super::events::path_with_query("/api/v1/audit-events/agents", &q.query(false)),
    )
    .map_err(|e| format!("获取审计 Agent 汇总失败：{e}"))
}
#[tauri::command]
pub fn get_audit_event_facets(
    app: tauri::AppHandle,
    query: Option<AuditEventPageQuery>,
) -> Result<serde_json::Value, String> {
    let q = query.unwrap_or_default();
    super::gateway_api::get_json(
        &app,
        &super::events::path_with_query("/api/v1/audit-events/facets", &q.query(false)),
    )
    .map_err(|e| format!("获取审计筛选项失败：{e}"))
}

#[tauri::command]
pub fn get_gateway_audit(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<GatewayAuditSnapshot, String> {
    let limit_value = limit.unwrap_or(200).clamp(1, 500);
    crate::commands::gateway_api::get_json::<GatewayAuditSnapshot>(
        &app,
        &format!("/api/v1/gateway-audit?limit={limit_value}&connector=agentrange"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，网关审计由 Go 后端 audit.db 提供：{error}"))
}

#[tauri::command]
pub fn get_process_guard_audit(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<GuardAuditSnapshot, String> {
    let limit_value = limit.unwrap_or(200).clamp(1, 500);
    crate::commands::gateway_api::get_json::<GuardAuditSnapshot>(
        &app,
        &format!("/api/v1/process-guard-audit?limit={limit_value}"),
    )
    .map_err(|error| {
        format!("Go Gateway 暂不可用，进程守护审计由 Go 后端 behavior_events 提供：{error}")
    })
}
