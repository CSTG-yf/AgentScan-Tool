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
