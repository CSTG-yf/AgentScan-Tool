use std::fs;
use std::process::Command;

use chrono::Utc;
use serde_json::Value;

use crate::models::{GatewayAuditRecord, GatewayAuditSnapshot, GuardAuditRecord, GuardAuditSnapshot};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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

fn optional_nested_text(value: &Value, key: &str) -> Option<String> {
    optional_text(value, key).or_else(|| {
        value
            .get("structured")
            .and_then(|structured| optional_text(structured, key))
    })
}

fn optional_nested_u64(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64).or_else(|| {
        value
            .get("structured")
            .and_then(|structured| structured.get(key))
            .and_then(Value::as_u64)
    })
}

fn optional_structured<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.get("structured").and_then(|structured| structured.get(key))
}

fn text_or_structured(value: &Value, key: &str) -> String {
    optional_nested_text(value, key).unwrap_or_default()
}

fn event_action(value: &Value) -> String {
    text(value, "action")
}

fn event_target(value: &Value) -> String {
    optional_text(value, "target").unwrap_or_default()
}

fn optional_pid(value: &Value, key: &str) -> Option<u32> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|pid| u32::try_from(pid).ok())
}

#[tauri::command]
pub fn get_gateway_audit(app: tauri::AppHandle, limit: Option<usize>) -> Result<GatewayAuditSnapshot, String> {
    let gateway = crate::commands::lifecycle::gateway_binary(&app)?;
    let home = crate::commands::lifecycle::desktop_defenseclaw_home(&app)?;
    let limit_text = limit.unwrap_or(200).clamp(1, 500).to_string();

    let mut command = Command::new(gateway);
    command.args(["audit", "export", "--limit", &limit_text, "--connector", "agentrange"]);
    command.env("DEFENSECLAW_HOME", &home);
    command.env("DEFENSECLAW_CONFIG", home.join("config.yaml"));
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let output = command
        .output()
        .map_err(|error| format!("run gateway audit export: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Ok(GatewayAuditSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            source: "defenseclaw-gateway audit export".to_owned(),
            events: Vec::new(),
            warning: Some(if stderr.is_empty() {
                "网关审计导出失败，可能尚未启动或尚未生成 audit.db".to_owned()
            } else {
                stderr
            }),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut malformed = 0usize;
    let events = stdout
        .lines()
        .filter_map(|line| match serde_json::from_str::<Value>(line) {
            Ok(value) => {
                let structured = value.get("structured").unwrap_or(&Value::Null);
                Some(GatewayAuditRecord {
                    timestamp: text(&value, "timestamp"),
                    action: event_action(&value),
                    target: event_target(&value),
                    actor: text(&value, "actor"),
                    details: optional_text(&value, "details").unwrap_or_default(),
                    severity: text(&value, "severity"),
                    trace_id: text_or_structured(&value, "trace_id"),
                    session_id: text_or_structured(&value, "session_id"),
                    agent_name: text_or_structured(&value, "agent_name"),
                    connector: text_or_structured(&value, "connector"),
                    destination_app: optional_nested_text(&value, "destination_app")
                        .or_else(|| optional_nested_text(&value, "destination"))
                        .unwrap_or_default(),
                    tool_name: text_or_structured(&value, "tool_name"),
                    stage: text_or_structured(&value, "stage"),
                    prompt: text_or_structured(&value, "prompt"),
                    model: text_or_structured(&value, "model"),
                    mcp_server: text_or_structured(&value, "mcp_server"),
                    decision: text_or_structured(&value, "decision"),
                    reason: text_or_structured(&value, "reason"),
                    latency_ms: optional_nested_u64(&value, "latency_ms").or_else(|| {
                        optional_structured(structured, "latency_ms").and_then(Value::as_u64)
                    }),
                })
            }
            Err(_) => {
                malformed += 1;
                None
            }
        })
        .collect::<Vec<_>>();

    Ok(GatewayAuditSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        source: "defenseclaw-gateway audit export --connector agentrange".to_owned(),
        events,
        warning: (malformed > 0).then(|| format!("忽略了 {malformed} 条格式无效的网关审计记录")),
    })
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
                trace_id: optional_nested_text(&value, "trace_id"),
                session_id: optional_nested_text(&value, "session_id"),
                agent_name: optional_nested_text(&value, "agent_name"),
                connector: optional_nested_text(&value, "connector"),
                stage: optional_nested_text(&value, "stage"),
                source: optional_nested_text(&value, "source"),
                destination_app: optional_nested_text(&value, "destination_app")
                    .or_else(|| optional_nested_text(&value, "destination")),
                tool_name: optional_nested_text(&value, "tool_name"),
                mcp_server: optional_nested_text(&value, "mcp_server"),
                prompt: optional_nested_text(&value, "prompt"),
                model: optional_nested_text(&value, "model"),
                decision: optional_nested_text(&value, "decision"),
                severity: optional_nested_text(&value, "severity"),
                reason: optional_nested_text(&value, "reason"),
                latency_ms: optional_nested_u64(&value, "latency_ms"),
                raw_ref: optional_nested_text(&value, "raw_ref"),
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
