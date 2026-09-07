use serde_json::Value;

const PREFIX: &str = "/api/v1/runtime-detection-settings";

fn settings_path(input: &str) -> Result<String, String> {
    if input.len() > 8192
        || input
            .chars()
            .any(|c| c.is_control() || c == ' ' || c == '#')
    {
        return Err("异常检测设置路径无效".to_owned());
    }
    let relative = input.strip_prefix(PREFIX).unwrap_or(input);
    let (path, _) = relative.split_once('?').unwrap_or((relative, ""));
    let segments: Vec<&str> = path.strip_prefix('/').unwrap_or("").split('/').collect();
    if !matches!(
        segments.first(),
        Some(&"overview" | &"rules" | &"risk-policy" | &"agent-types")
    ) || segments.iter().any(|s| {
        s.is_empty()
            || !s
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    }) {
        return Err("异常检测设置路径超出允许范围".to_owned());
    }
    Ok(format!("{PREFIX}{relative}"))
}

/// The gateway owns validation, defaults, persistence and effective rules.
/// This command only restricts the transport to the configuration domain.
#[tauri::command]
pub fn runtime_detection_settings_request(
    app: tauri::AppHandle,
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<Value, String> {
    let path = settings_path(&path)?;
    let payload = body.unwrap_or(Value::Null);
    match method.as_str() {
        "GET" => crate::commands::gateway_api::get_json::<Value>(&app, &path),
        "POST" => crate::commands::gateway_api::post_json::<Value, _>(&app, &path, &payload),
        "PATCH" => crate::commands::gateway_api::patch_json::<Value, _>(&app, &path, &payload),
        "PUT" => crate::commands::gateway_api::put_json::<Value, _>(&app, &path, &payload),
        "DELETE" => crate::commands::gateway_api::delete_json::<Value>(&app, &path),
        _ => Err("不支持的异常检测设置请求方法".to_owned()),
    }
    .map_err(|error| format!("异常检测设置请求失败：{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_transport_stays_within_domain() {
        for path in [
            "/rules?page=2&keyword=%E8%A7%84%E5%88%99",
            "/agent-types/1/blacklist/2",
            "/api/v1/runtime-detection-settings/risk-policy/global",
        ] {
            assert!(settings_path(path).unwrap().starts_with(PREFIX));
        }
        for path in [
            "/api/v1/jobs",
            "/../jobs",
            "/rules/../../jobs",
            "/rules/%2e%2e/jobs",
            "/rules\\jobs",
            "/api/v1/runtime-detection-settings-escape",
            "/rules\r\nInjected: yes",
            "https://example.test/rules",
            "/rules#fragment",
        ] {
            assert!(settings_path(path).is_err(), "accepted {path}");
        }
    }
}
