use serde::Deserialize;

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
        "/api/v1/desktop-scan-schedule",
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
        "/api/v1/desktop-scan-schedule",
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
