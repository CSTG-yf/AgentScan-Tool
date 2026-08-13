use chrono::Utc;

use crate::models::TraceSnapshot;

#[tauri::command]
pub fn get_agent_trace(limit: Option<usize>) -> Result<TraceSnapshot, String> {
    let path = crate::trace_store::default_database_path();
    let events = crate::trace_store::query(&path, limit.unwrap_or(300))?;
    Ok(TraceSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        database_path: path.display().to_string(),
        warning: events
            .is_empty()
            .then(|| "Trace 库尚未记录 Agent 活动".to_owned()),
        events,
    })
}
