use chrono::Utc;

use crate::models::AgentSnapshot;

#[tauri::command]
pub fn get_agent_processes(app: tauri::AppHandle) -> AgentSnapshot {
    match crate::commands::gateway_api::get_json::<AgentSnapshot>(
        &app,
        "/api/v1/agent-inventory?limit=600",
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => AgentSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            agents: Vec::new(),
            processes: Vec::new(),
            warning: Some(format!(
                "Go Gateway 暂不可用，Agent Inventory 只能由 Go 后端提供：{error}"
            )),
        },
    }
}
