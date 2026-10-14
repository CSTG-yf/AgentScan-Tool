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

fn evaluation_resource(app: &tauri::AppHandle, name: &str) -> Result<std::path::PathBuf, String> {
    use tauri::Manager;
    let directory = app.path().resource_dir().map_err(|e| e.to_string())?;
    [directory.join("resources").join(name), directory.join(name),
     std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources").join(name)]
        .into_iter().find(|p| p.is_file()).ok_or_else(|| format!("缺少内置资源：{name}"))
}

#[tauri::command]
pub async fn import_bundled_static_evaluation(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let home = crate::commands::lifecycle::desktop_defenseclaw_home(&app)?;
        for marker_name in [
            "evaluation-seed-static-v0.2.4.json",
            "evaluation-seed-v0.2.3.json",
        ] {
            if let Ok(id) = std::fs::read_to_string(home.join(marker_name)) {
                let path = format!("/api/v1/evaluations/{}", id.trim());
                if let Ok(saved) =
                    crate::commands::gateway_api::get_json::<Value>(&app, &path)
                {
                    return Ok(saved);
                }
            }
        }
        let source = evaluation_resource(&app, "evaluation-static-v0.2.4.json")?;
        let report: Value = serde_json::from_slice(
            &std::fs::read(source).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let saved = crate::commands::gateway_api::post_json::<Value, _>(
            &app,
            "/api/v1/evaluations",
            &report,
        )?;
        let id = saved
            .get("id")
            .and_then(Value::as_str)
            .ok_or("评测记录缺少 ID")?;
        std::fs::write(home.join("evaluation-seed-static-v0.2.4.json"), id)
            .map_err(|e| e.to_string())?;
        Ok(saved)
    }).await.map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn import_bundled_runtime_evaluations(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let home = crate::commands::lifecycle::desktop_defenseclaw_home(&app)?;
        let mut imported = Vec::new();
        let marker = home.join("evaluation-seed-runtime-action-20261009.json");
        if let Ok(id) = std::fs::read_to_string(&marker) {
            if crate::commands::gateway_api::get_json::<Value>(
                &app,
                &format!("/api/v1/evaluations/{}", id.trim()),
            )
            .is_ok()
            {
                return Ok(serde_json::json!({"imported": []}));
            }
        }
        let source = evaluation_resource(&app, "evaluation-runtime-action-v0.2.4.json")?;
        let report: Value = serde_json::from_slice(
            &std::fs::read(source).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let saved = crate::commands::gateway_api::post_json::<Value, _>(
            &app,
            "/api/v1/evaluations",
            &report,
        )?;
        let id = saved
            .get("id")
            .and_then(Value::as_str)
            .ok_or("评测记录缺少 ID")?;
        std::fs::write(marker, id).map_err(|e| e.to_string())?;
        imported.push(serde_json::json!({"mode": "action", "id": id}));
        Ok(serde_json::json!({"imported": imported}))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn scan_range_assets(app: tauri::AppHandle) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let root = crate::commands::range::configured_root(&app).ok_or("请先设置靶场文件夹")?;
        let folder = crate::commands::lifecycle::desktop_defenseclaw_home(&app)?.join("arena-scans").join(chrono::Utc::now().format("%Y%m%d-%H%M%S-%f").to_string());
        std::fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        let output = folder.join("static-scan.json");
        let binary = evaluation_resource(&app, if cfg!(windows) {"tracebastion-arena-scan.exe"} else {"tracebastion-arena-scan"})?;
        let result = std::process::Command::new(binary).arg("--range-root").arg(root).arg("--output").arg(&output).output().map_err(|e| e.to_string())?;
        if !result.status.success() {return Err(String::from_utf8_lossy(&result.stderr).into_owned());}
        let report: Value = serde_json::from_slice(&std::fs::read(&output).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({"path":output.to_string_lossy(),"report":report}))
    }).await.map_err(|e| e.to_string())?
}
