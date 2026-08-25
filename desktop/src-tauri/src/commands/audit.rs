use crate::models::{GatewayAuditSnapshot, GuardAuditSnapshot};

#[tauri::command]
pub fn get_gateway_audit(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<GatewayAuditSnapshot, String> {
    let limit_value = limit.unwrap_or(200).clamp(1, 500);
    crate::commands::gateway_api::get_json::<GatewayAuditSnapshot>(
        &app,
        &format!("/api/v1/gateway-audit?limit={limit_value}&connector=agentrange"),
    )
    .map_err(|error| format!("Go Gateway 暂不可用，网关审计由 Go 后端 audit.db 提供：{error}"))
}

#[tauri::command]
pub fn get_process_guard_audit(
    app: tauri::AppHandle,
    limit: Option<usize>,
) -> Result<GuardAuditSnapshot, String> {
    let limit_value = limit.unwrap_or(200).clamp(1, 500);
    crate::commands::gateway_api::get_json::<GuardAuditSnapshot>(
        &app,
        &format!("/api/v1/process-guard-audit?limit={limit_value}"),
    )
    .map_err(|error| {
        format!("Go Gateway 暂不可用，进程守护审计由 Go 后端 behavior_events 提供：{error}")
    })
}
