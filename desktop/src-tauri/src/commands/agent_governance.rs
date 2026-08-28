use serde_json::Value;

fn governance_path(path: &str) -> Result<String, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Agent governance API path is required".to_string());
    }
    if trimmed.contains('\r') || trimmed.contains('\n') || trimmed.contains("://") {
        return Err("Agent governance API path is invalid".to_string());
    }
    let path = if trimmed.starts_with("/api/v1/agent-governance") {
        trimmed.to_owned()
    } else if trimmed.starts_with('/') {
        format!("/api/v1/agent-governance{trimmed}")
    } else {
        format!("/api/v1/agent-governance/{trimmed}")
    };
    if !path.starts_with("/api/v1/agent-governance") {
        return Err("Agent governance API path is out of scope".to_string());
    }
    Ok(path)
}

#[tauri::command]
pub fn agent_governance_get(app: tauri::AppHandle, path: String) -> Result<Value, String> {
    let path = governance_path(&path)?;
    crate::commands::gateway_api::get_json::<Value>(&app, &path)
        .map_err(|error| format!("Agent governance query failed: {error}"))
}

#[tauri::command]
pub fn agent_governance_post(
    app: tauri::AppHandle,
    path: String,
    body: Value,
) -> Result<Value, String> {
    let path = governance_path(&path)?;
    crate::commands::gateway_api::post_json::<Value, Value>(&app, &path, &body)
        .map_err(|error| format!("Agent governance create failed: {error}"))
}

#[tauri::command]
pub fn agent_governance_patch(
    app: tauri::AppHandle,
    path: String,
    body: Value,
) -> Result<Value, String> {
    let path = governance_path(&path)?;
    crate::commands::gateway_api::patch_json::<Value, Value>(&app, &path, &body)
        .map_err(|error| format!("Agent governance update failed: {error}"))
}

#[tauri::command]
pub fn agent_governance_put(
    app: tauri::AppHandle,
    path: String,
    body: Value,
) -> Result<Value, String> {
    let path = governance_path(&path)?;
    crate::commands::gateway_api::put_json::<Value, Value>(&app, &path, &body)
        .map_err(|error| format!("Agent governance replace failed: {error}"))
}

#[tauri::command]
pub fn agent_governance_delete(app: tauri::AppHandle, path: String) -> Result<Value, String> {
    let path = governance_path(&path)?;
    crate::commands::gateway_api::delete_json::<Value>(&app, &path)
        .map_err(|error| format!("Agent governance delete failed: {error}"))
}
