use crate::models::TraceSnapshot;

#[tauri::command]
pub fn get_agent_trace(limit: Option<usize>) -> Result<TraceSnapshot, String> {
    crate::trace_store::snapshot(limit.unwrap_or(300))
}
