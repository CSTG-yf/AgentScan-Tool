use serde::Deserialize;
use serde_json::Value;

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
