use serde_json::Value;

fn evaluation_path(path: &str) -> Result<&str, String> {
    let route = path.split('?').next().unwrap_or("");
    if !(route == "/api/v1/evaluations" || route.starts_with("/api/v1/evaluations/"))
        || path.chars().any(|c| matches!(c, '\r' | '\n' | '\\' | '#'))
        || path.contains("..")
    {
        return Err("评测接口路径无效".into());
    }
    Ok(path)
}

#[tauri::command]
pub async fn evaluation_request(
    app: tauri::AppHandle,
    method: String,
    path: String,
    body: Option<Value>,
) -> Result<Value, String> {
    evaluation_path(&path)?;
    tauri::async_runtime::spawn_blocking(move || match method.as_str() {
        "GET" => crate::commands::gateway_api::get_json::<Value>(&app, &path),
        "POST" => crate::commands::gateway_api::post_json::<Value, _>(
            &app,
            &path,
            &body.unwrap_or(Value::Null),
        ),
        _ => Err("评测接口仅支持 GET 和 POST".into()),
    })
    .await
    .map_err(|error| error.to_string())?
}

#[cfg(test)]
mod tests {
    use super::evaluation_path;

    #[test]
    fn scopes_requests_to_evaluation_api() {
        assert!(evaluation_path("/api/v1/evaluations/a/instances?limit=50").is_ok());
        for path in [
            "/api/v1/evaluations-other",
            "/api/v1/jobs",
            "/api/v1/evaluations/../jobs",
            "/api/v1/evaluations\r\nX: y",
        ] {
            assert!(evaluation_path(path).is_err());
        }
    }
}
