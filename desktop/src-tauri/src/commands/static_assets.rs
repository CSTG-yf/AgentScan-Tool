use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticAssetSnapshot {
    captured_at: String,
    source: String,
    last_scan_at: Option<String>,
    agents: Vec<StaticAgentInventory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticAgentInventory {
    id: String,
    name: String,
    runtime: String,
    source: String,
    description: String,
    resources: Vec<StaticResource>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticResource {
    id: String,
    name: String,
    #[serde(rename = "type")]
    resource_type: String,
    kind: String,
    path: String,
    risk: String,
    status: String,
    updated_at: String,
    size: String,
    permissions: String,
    hash: String,
    description: String,
    content_preview: String,
    findings: Vec<StaticResourceFinding>,
    relations: Vec<StaticResourceRelation>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticResourceFinding {
    id: String,
    title: String,
    severity: String,
    description: String,
    location: String,
    evidence: String,
    recommendation: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaticResourceRelation {
    id: String,
    name: String,
    #[serde(rename = "type")]
    resource_type: String,
    relation: String,
    risk: String,
}

#[tauri::command]
pub fn get_static_asset_inventory(
    app: tauri::AppHandle,
    limit: Option<i64>,
) -> Result<StaticAssetSnapshot, String> {
    let limit_value = limit.unwrap_or(600).clamp(50, 2_000);
    crate::commands::gateway_api::get_json::<StaticAssetSnapshot>(
        &app,
        &format!("/api/v1/static-resource-inventory?limit={limit_value}"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，静态资源 Inventory 只能由 Go 后端提供：{error}"))
}

// ---------------------------------------------------------------------------
// Rule-driven static resource API (/api/v1/static-resources*). The payloads
// are forwarded as raw JSON: the Go backend owns the DTO shapes, the Rust
// layer only routes and URL-encodes.
// ---------------------------------------------------------------------------

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

/// GET /api/v1/static-resources/agents — left-hand agent list with counts.
#[tauri::command]
pub fn get_static_resource_agents(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        "/api/v1/static-resources/agents",
    )
    .map_err(|error| format!("获取 Agent 资源统计失败：{error}"))
}

/// GET /api/v1/static-resources/summary?agent_id= — header totals + by-type cards.
#[tauri::command]
pub fn get_static_resource_summary(
    app: tauri::AppHandle,
    agent_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/summary?agent_id={}",
            urlencode(&agent_id)
        ),
    )
    .map_err(|error| format!("获取 Agent 资源总览失败：{error}"))
}

/// GET /api/v1/static-resources — paginated / filtered resource table.
#[tauri::command]
pub fn get_static_resources(
    app: tauri::AppHandle,
    agent_id: Option<String>,
    resource_type: Option<String>,
    risk_level: Option<String>,
    malicious: Option<bool>,
    scan_status: Option<String>,
    status: Option<String>,
    keyword: Option<String>,
    page: Option<i64>,
    page_size: Option<i64>,
) -> Result<serde_json::Value, String> {
    let mut query: Vec<String> = Vec::new();
    if let Some(value) = agent_id.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("agent_id={}", urlencode(value)));
    }
    if let Some(value) = resource_type.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("resource_type={}", urlencode(value)));
    }
    if let Some(value) = risk_level.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("risk_level={}", urlencode(value)));
    }
    if let Some(value) = malicious {
        query.push(format!("malicious={value}"));
    }
    if let Some(value) = scan_status.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("scan_status={}", urlencode(value)));
    }
    if let Some(value) = status.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("status={}", urlencode(value)));
    }
    if let Some(value) = keyword.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("keyword={}", urlencode(value)));
    }
    let page = page.unwrap_or(1).clamp(1, 100_000);
    let page_size = page_size.unwrap_or(20).clamp(1, 200);
    query.push(format!("page={page}"));
    query.push(format!("page_size={page_size}"));

    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!("/api/v1/static-resources?{}", query.join("&")),
    )
    .map_err(|error| format!("获取静态资源列表失败：{error}"))
}

/// GET /api/v1/static-resources/{id} — drawer overview.
#[tauri::command]
pub fn get_static_resource_detail(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取资源详情失败：{error}"))
}

/// GET /api/v1/static-resources/{id}/findings — drawer risk tab.
#[tauri::command]
pub fn get_static_resource_findings(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/findings",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取资源风险发现失败：{error}"))
}

/// GET /api/v1/static-resources/{id}/content — drawer content tab.
#[tauri::command]
pub fn get_static_resource_content(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/content",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取资源内容失败：{error}"))
}

/// GET /api/v1/static-resources/{id}/relations — drawer relations tab.
#[tauri::command]
pub fn get_static_resource_relations(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::get_json::<serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/relations",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取关联资源失败：{error}"))
}

/// POST /api/v1/static-resources/{id}/scan — on-demand single-resource scan.
#[tauri::command]
pub fn trigger_static_resource_scan(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::post_json::<serde_json::Value, serde_json::Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/scan",
            urlencode(&resource_id)
        ),
        &serde_json::json!({}),
    )
    .map_err(|error| format!("触发资源扫描失败：{error}"))
}

/// POST /api/v1/static-resources/rescan — re-enumerate and re-scan one agent
/// (or every agent when agent_id is empty).
#[tauri::command]
pub fn trigger_static_resource_rescan(
    app: tauri::AppHandle,
    agent_id: Option<String>,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({ "agent_id": agent_id.unwrap_or_default() });
    crate::commands::gateway_api::post_json::<serde_json::Value, serde_json::Value>(
        &app,
        "/api/v1/static-resources/rescan",
        &body,
    )
    .map_err(|error| format!("触发重新扫描失败：{error}"))
}
