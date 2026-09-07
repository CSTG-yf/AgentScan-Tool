use serde_json::{json, Value};

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

/// Create the explicit historical runtime detection replay job. The Go
/// gateway owns filtering and execution; the desktop only forwards the
/// operator's scope and polls the returned scan_id.
#[tauri::command]
pub fn create_event_replay_job(
    app: tauri::AppHandle,
    agent_type_id: Option<i64>,
    agent_id: Option<String>,
    session_id: Option<String>,
    trace_id: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, _>(
        &app,
        "/api/v1/jobs",
        &json!({
            "kind": "event_replay",
            "scope": agent_type_id.map(|id| json!({"agent_type_id": id})).unwrap_or_else(|| json!({})),
            "agent_id": agent_id,
            "session_id": session_id,
            "trace_id": trace_id,
            "start_time": start_time,
            "end_time": end_time,
        }),
    )
    .map_err(|error| format!("创建历史事件重放任务失败：{error}"))
}

#[tauri::command]
pub fn create_attack_chain_rebuild_job(
    app: tauri::AppHandle,
    limit: Option<i64>,
) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, _>(
        &app,
        "/api/v1/jobs",
        &json!({"kind": "attack_chain_rebuild", "limit": limit.unwrap_or(5000)}),
    )
    .map_err(|error| format!("创建攻击链重建任务失败：{error}"))
}

#[tauri::command]
pub fn get_scan_schedules(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(&app, "/api/v1/scan-schedules")
        .map_err(|error| format!("获取后端扫描策略失败：{error}"))
}

#[tauri::command]
pub fn update_scan_schedule(
    app: tauri::AppHandle,
    task_type: String,
    enabled: bool,
    interval_sec: i64,
    mode: String,
    scope: Option<Value>,
) -> Result<Value, String> {
    let task_type = task_type.trim();
    if task_type.is_empty() {
        return Err("task_type 不能为空".to_owned());
    }
    crate::commands::gateway_api::put_json::<Value, _>(
        &app,
        &format!("/api/v1/scan-schedules/{}", urlencode(task_type)),
        &json!({
            "enabled": enabled,
            "interval_sec": interval_sec,
            "mode": mode,
            "scope": scope.unwrap_or_else(|| json!({})),
        }),
    )
    .map_err(|error| format!("保存后端扫描策略失败：{error}"))
}

#[tauri::command]
pub fn create_scan_job(
    app: tauri::AppHandle,
    task_type: String,
    mode: Option<String>,
    scope: Option<Value>,
    idempotency_key: Option<String>,
) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, _>(
        &app,
        "/api/v1/jobs",
        &json!({
            "task_type": task_type,
            "mode": mode,
            "trigger": "manual",
            "scope": scope.unwrap_or_else(|| json!({})),
            "idempotency_key": idempotency_key,
        }),
    )
    .map_err(|error| format!("创建扫描任务失败：{error}"))
}

#[tauri::command]
pub fn get_scan_jobs(
    app: tauri::AppHandle,
    task_type: Option<String>,
    status: Option<String>,
    trigger: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
) -> Result<Value, String> {
    let mut query = Vec::new();
    for (name, value) in [
        ("task_type", task_type),
        ("status", status),
        ("trigger", trigger),
    ] {
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            query.push(format!("{name}={}", urlencode(&value)));
        }
    }
    query.push(format!("limit={}", limit.unwrap_or(20).clamp(1, 500)));
    query.push(format!("offset={}", offset.unwrap_or(0).max(0)));
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!("/api/v1/jobs?{}", query.join("&")),
    )
    .map_err(|error| format!("获取扫描任务历史失败：{error}"))
}

#[tauri::command]
pub fn get_scan_job(app: tauri::AppHandle, job_id: String) -> Result<Value, String> {
    crate::commands::gateway_api::get_json::<Value>(
        &app,
        &format!("/api/v1/jobs/{}", urlencode(job_id.trim())),
    )
    .map_err(|error| format!("获取扫描任务详情失败：{error}"))
}

#[tauri::command]
pub fn cancel_scan_job(app: tauri::AppHandle, job_id: String) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, _>(
        &app,
        &format!("/api/v1/jobs/{}/cancel", urlencode(job_id.trim())),
        &json!({}),
    )
    .map_err(|error| format!("取消扫描任务失败：{error}"))
}

/// Poll the SQLite invalidation cursor before deciding which page read model
/// needs a refresh. This keeps automatic UI sync separate from scan jobs.
#[tauri::command]
pub fn get_changes(
    app: tauri::AppHandle,
    cursor: Option<i64>,
    domains: Option<String>,
) -> Result<Value, String> {
    let mut query = Vec::new();
    if let Some(cursor) = cursor.filter(|value| *value >= 0) {
        query.push(format!("cursor={cursor}"));
    }
    if let Some(domains) = domains.filter(|value| !value.trim().is_empty()) {
        query.push(format!("domains={}", urlencode(&domains)));
    }
    let path = if query.is_empty() {
        "/api/v1/changes".to_owned()
    } else {
        format!("/api/v1/changes?{}", query.join("&"))
    };
    crate::commands::gateway_api::get_json::<Value>(&app, &path)
        .map_err(|error| format!("获取数据变更游标失败：{error}"))
}
