use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use tauri::Manager;

use crate::models::{ScanScheduleSettings, StaticResourceScanSettings};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StaticResourceScanSettingsResponse {
    settings: StaticResourceScanSettings,
}

#[tauri::command]
pub fn get_scan_schedule_settings(app: tauri::AppHandle) -> Result<ScanScheduleSettings, String> {
    crate::commands::gateway_api::get_json::<ScanScheduleSettings>(
        &app,
        "/api/v1/page-refresh-settings",
    )
    .map(|settings| settings.normalize())
    .map_err(|error| format!("Go Gateway 暂不可用，扫描任务设置由 Go 后端保存：{error}"))
}

#[tauri::command]
pub fn save_scan_schedule_settings(
    app: tauri::AppHandle,
    settings: ScanScheduleSettings,
) -> Result<ScanScheduleSettings, String> {
    let settings = settings.normalize();
    crate::commands::gateway_api::put_json::<ScanScheduleSettings, _>(
        &app,
        "/api/v1/page-refresh-settings",
        &settings,
    )
    .map(|settings| settings.normalize())
    .map_err(|error| format!("Go Gateway 暂不可用，无法保存扫描任务设置：{error}"))
}

#[tauri::command]
pub fn get_static_resource_scan_settings(
    app: tauri::AppHandle,
) -> Result<StaticResourceScanSettings, String> {
    crate::commands::gateway_api::get_json::<StaticResourceScanSettings>(
        &app,
        "/api/v1/static-resource-scan-settings",
    )
    .map(|settings| settings.normalize())
    .map_err(|error| format!("Go Gateway 暂不可用，静态资源扫描配置由 Go 后端保存：{error}"))
}

#[tauri::command]
pub fn save_static_resource_scan_settings(
    app: tauri::AppHandle,
    settings: StaticResourceScanSettings,
) -> Result<StaticResourceScanSettings, String> {
    let settings = settings.normalize();
    crate::commands::gateway_api::put_json::<StaticResourceScanSettingsResponse, _>(
        &app,
        "/api/v1/static-resource-scan-settings",
        &settings,
    )
    .map(|response| response.settings.normalize())
    .map_err(|error| format!("Go Gateway 暂不可用，无法保存后端静态资源扫描配置：{error}"))
}

#[tauri::command]
pub fn get_privacy_settings(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::get_json(&app, "/api/v1/settings/privacy")
        .map_err(|error| format!("获取隐私设置失败：{error}"))
}

#[tauri::command]
pub fn save_privacy_settings(app: tauri::AppHandle, settings: Value) -> Result<Value, String> {
    crate::commands::gateway_api::patch_json(&app, "/api/v1/settings/privacy", &settings)
        .map_err(|error| format!("保存隐私设置失败：{error}"))
}

#[tauri::command]
pub fn get_notification_settings(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::get_json(&app, "/api/v1/settings/notifications")
        .map_err(|error| format!("获取通知设置失败：{error}"))
}

#[tauri::command]
pub fn save_notification_settings(app: tauri::AppHandle, settings: Value) -> Result<Value, String> {
    crate::commands::gateway_api::patch_json(&app, "/api/v1/settings/notifications", &settings)
        .map_err(|error| format!("保存通知设置失败：{error}"))
}

#[tauri::command]
pub fn get_storage_settings(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::get_json(&app, "/api/v1/settings/storage")
        .map_err(|error| format!("获取存储状态失败：{error}"))
}

#[tauri::command]
pub fn get_version_settings(app: tauri::AppHandle) -> Result<Value, String> {
    let gateway = crate::commands::gateway_api::get_json::<Value>(
        &app,
        "/api/v1/settings/versions",
    );
    Ok(json!({
        "desktopVersion": app.package_info().version.to_string(),
        "gateway": gateway.as_ref().ok(),
        "gatewayError": gateway.err(),
    }))
}

#[tauri::command]
pub fn run_diagnostics(app: tauri::AppHandle) -> Result<Value, String> {
    crate::commands::gateway_api::post_json::<Value, _>(
        &app,
        "/api/v1/diagnostics/run",
        &json!({}),
    )
    .map_err(|error| format!("运行诊断失败：{error}"))
}

#[tauri::command]
pub fn export_diagnostics(app: tauri::AppHandle) -> Result<Value, String> {
    let report: Value = crate::commands::gateway_api::post_json(
        &app,
        "/api/v1/diagnostics/export",
        &json!({}),
    )
    .map_err(|error| format!("生成脱敏诊断报告失败：{error}"))?;
    let payload = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("序列化诊断报告失败：{error}"))?;
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|error| format!("定位应用数据目录失败：{error}"))?
        .join("diagnostics");
    fs::create_dir_all(&dir).map_err(|error| format!("创建诊断目录失败：{error}"))?;
    let name = format!(
        "tracebastion-diagnostics-{}.json",
        chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ")
    );
    let path = dir.join(name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&path)
        .map_err(|error| format!("创建诊断文件失败：{error}"))?;
    if let Err(error) = file.write_all(&payload).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(format!("写入诊断文件失败：{error}"));
    }
    Ok(json!({ "path": path.display().to_string(), "bytes": payload.len() }))
}
