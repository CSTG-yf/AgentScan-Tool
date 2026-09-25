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
    start_time: Option<String>,
    end_time: Option<String>,
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
    if let Some(value) = start_time.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("start_time={}", urlencode(value)));
    }
    if let Some(value) = end_time.as_deref().filter(|v| !v.trim().is_empty()) {
        query.push(format!("end_time={}", urlencode(value)));
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
    idempotency_key: Option<String>,
) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, Value>(
        &app,
        &format!("/api/v1/static-resources/{}/scan", urlencode(&resource_id)),
        &serde_json::json!({"idempotency_key": idempotency_key}),
    )
    .map_err(|error| format!("触发资源扫描失败：{error}"))
}

#[tauri::command]
pub fn trigger_static_resource_rescan(
    app: tauri::AppHandle,
    agent_id: Option<String>,
    idempotency_key: Option<String>,
) -> Result<Value, String> {
    let path = match agent_id
        .as_deref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        Some(agent_id) => format!(
            "/api/v1/agents/{}/static-resources/scan",
            urlencode(agent_id)
        ),
        None => "/api/v1/static-resources/rescan".to_owned(),
    };
    crate::commands::gateway_api::post_json::<Value, Value>(
        &app,
        &path,
        &serde_json::json!({"agent_id": agent_id, "idempotency_key": idempotency_key}),
    )
    .map_err(|error| format!("触发重新扫描失败：{error}"))
}

#[tauri::command]
pub fn get_scan_status(app: tauri::AppHandle, scan_id: String) -> Result<Value, String> {
    let scan_id = scan_id.trim();
    if scan_id.is_empty() {
        return Err("scan_id 不能为空".to_owned());
    }
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!("/api/v1/scans/{}", urlencode(scan_id)),
    )
    .map_err(|error| format!("获取扫描任务状态失败：{error}"))
}

#[tauri::command]
pub fn get_static_resource_scans(
    app: tauri::AppHandle,
    resource_id: String,
    limit: Option<i64>,
) -> Result<Value, String> {
    let limit = limit.unwrap_or(50).clamp(1, 200);
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/scans?limit={}",
            urlencode(&resource_id),
            limit
        ),
    )
    .map_err(|error| format!("获取扫描历史失败：{error}"))
}

#[tauri::command]
pub fn export_static_resource_text_report(
    content: String,
    default_file_name: Option<String>,
    directory: String,
) -> Result<String, String> {
    crate::commands::report_export::write_text_export(
        &directory,
        default_file_name
            .as_deref()
            .unwrap_or("static-resources-report.md"),
        &content,
        &["md", "txt"],
    )
}

#[tauri::command]
pub fn update_static_resource_status(
    app: tauri::AppHandle,
    resource_id: String,
    status: String,
) -> Result<Value, String> {
    crate::commands::gateway_api::put_json::<Value, Value>(
        &app,
        &format!(
            "/api/v1/static-resources/{}/status",
            urlencode(&resource_id)
        ),
        &serde_json::json!({ "status": status }),
    )
    .map_err(|error| format!("更新资源状态失败：{error}"))
}

#[tauri::command]
pub async fn reveal_static_resource_path(path: String) -> Result<(), String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("资源路径为空".to_string());
    }
    if trimmed.contains("://") {
        return Err("虚拟资源（运行时快照）没有对应的磁盘路径".to_string());
    }
    let path = trimmed.to_owned();
    tauri::async_runtime::spawn_blocking(move || reveal_in_file_explorer(&path))
        .await
        .map_err(|error| format!("打开文件管理器任务失败：{error}"))?
}

#[cfg(windows)]
fn reveal_in_file_explorer(path: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::path::Path;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut command = std::process::Command::new("explorer");
    command.creation_flags(CREATE_NO_WINDOW);
    if Path::new(path).is_dir() {
        command.arg(path);
    } else {
        command.raw_arg(format!("/select,\"{}\"", path));
    }
    command
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("打开文件资源管理器失败：{error}"))
}

#[cfg(target_os = "linux")]
fn reveal_in_file_explorer(path: &str) -> Result<(), String> {
    crate::resource_opener::reveal(path)
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn reveal_in_file_explorer(_path: &str) -> Result<(), String> {
    Err("当前平台不支持在文件资源管理器中定位文件".to_string())
}
