use serde_json::Value;

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
pub fn get_static_resource_agents(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(&app, "/api/v1/static-resources/agents")
        .map_err(|error| format!("获取 Agent 资源统计失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_summary(
    app: tauri::AppHandle,
    agent_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!(
            "/api/v1/agents/{}/static-resources/summary",
            urlencode(&agent_id)
        ),
    )
    .map_err(|error| format!("获取 Agent 资源总览失败：{error}"))
}

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
) -> Result<Value, String> {
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

    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!("/api/v1/static-resources?{}", query.join("&")),
    )
    .map_err(|error| format!("获取静态资源列表失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_detail(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!("/api/v1/static-resources/{}", urlencode(&resource_id)),
    )
    .map_err(|error| format!("获取资源详情失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_findings(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/findings",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取资源风险发现失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_content(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/content",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取资源内容失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_relations(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/relations",
            urlencode(&resource_id)
        ),
    )
    .map_err(|error| format!("获取关联资源失败：{error}"))
}

#[tauri::command]
pub fn trigger_static_resource_scan(
    app: tauri::AppHandle,
    resource_id: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, Value>(
        &app,
        &format!("/api/v1/static-resources/{}/scan", urlencode(&resource_id)),
        &serde_json::json!({}),
    )
    .map_err(|error| format!("触发资源扫描失败：{error}"))
}

#[tauri::command]
pub fn trigger_static_resource_rescan(
    app: tauri::AppHandle,
    agent_id: Option<String>,
) -> Result<Value, String> {
    let agent_id = agent_id
        .as_deref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "agent_id 不能为空".to_owned())?;
    crate::commands::gateway_api::post_json::<Value, Value>(
        &app,
        &format!(
            "/api/v1/agents/{}/static-resources/scan",
            urlencode(agent_id)
        ),
        &serde_json::json!({}),
    )
    .map_err(|error| format!("触发重新扫描失败：{error}"))
}
