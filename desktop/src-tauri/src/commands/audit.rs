use std::fs;

use chrono::Utc;
use serde_json::Value;

use crate::models::{GuardAuditRecord, GuardAuditSnapshot};

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn optional_text(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn optional_pid(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
}

#[tauri::command]
pub fn get_process_guard_audit(limit: Option<usize>) -> Result<GuardAuditSnapshot, String> {
    let (_, path) = crate::process_guard_service::default_paths();
    if !path.is_file() {
        return Ok(GuardAuditSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            path: path.display().to_string(),
            events: Vec::new(),
            warning: Some("进程守护尚未生成本机审计记录".to_owned()),
        });
    }

    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("read process guard audit {}: {error}", path.display()))?;
    let mut malformed = 0usize;
    let mut events = raw
        .lines()
        .rev()
        .take(limit.unwrap_or(200).clamp(1, 500))
        .filter_map(|line| match serde_json::from_str::<Value>(line) {
            Ok(value) => Some(GuardAuditRecord {
                timestamp: text(&value, "timestamp"),
                event_type: text(&value, "eventType"),
                outcome: text(&value, "outcome"),
                detail: text(&value, "detail"),
                mode: optional_text(&value, "mode"),
                rule_id: optional_text(&value, "ruleId"),
                action: optional_text(&value, "action"),
                child_pid: optional_pid(&value, "childPid"),
                child_executable: optional_text(&value, "childExecutable"),
                agent_pid: optional_pid(&value, "agentPid"),
                agent_executable: optional_text(&value, "agentExecutable"),
            }),
            Err(_) => {
                malformed += 1;
                None
            }
        })
        .collect::<Vec<_>>();
    events.reverse();

    Ok(GuardAuditSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        path: path.display().to_string(),
        events,
        warning: (malformed > 0).then(|| format!("忽略了 {malformed} 条格式无效的审计记录")),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{optional_pid, optional_text, text};

    #[test]
    fn extracts_optional_audit_fields_without_coercion() {
        let value = json!({"outcome":"terminated","agentPid":42,"ruleId":"command.grep"});
        assert_eq!(text(&value, "outcome"), "terminated");
        assert_eq!(optional_pid(&value, "agentPid"), Some(42));
        assert_eq!(
            optional_text(&value, "ruleId").as_deref(),
            Some("command.grep")
        );
        assert_eq!(optional_text(&value, "missing"), None);
    }
}
