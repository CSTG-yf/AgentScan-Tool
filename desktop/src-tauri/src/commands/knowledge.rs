use crate::knowledge::{self, AgentRuntimeCatalog};

#[tauri::command]
pub fn get_agent_runtime_catalog() -> Result<AgentRuntimeCatalog, String> {
    knowledge::catalog().cloned()
}
