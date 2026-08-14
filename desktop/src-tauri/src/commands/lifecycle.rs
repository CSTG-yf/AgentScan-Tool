use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use tauri::Manager;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleResult {
    pub(crate) action: &'static str,
    pub(crate) success: bool,
    pub(crate) message: String,
}

pub(crate) fn gateway_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("resolve desktop resource directory: {error}"))?;
    let mut candidates = vec![
        resource_dir
            .join("resources")
            .join("defenseclaw-gateway.exe"),
        resource_dir.join("defenseclaw-gateway.exe"),
    ];
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join("defenseclaw-gateway.exe"));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("defenseclaw-gateway.exe"),
    );
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "bundled defenseclaw-gateway.exe was not found".to_owned())
}

pub(crate) fn desktop_defenseclaw_home(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("defenseclaw-home"))
        .map_err(|error| format!("resolve DefenseClaw data directory: {error}"))
}

fn write_file_if_missing(path: &Path, contents: &str) -> Result<(), String> {
    if path.is_file() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(path, contents).map_err(|error| format!("write {}: {error}", path.display()))
}

pub(crate) fn ensure_gateway_home(app: &tauri::AppHandle, mode: &str) -> Result<PathBuf, String> {
    let home = desktop_defenseclaw_home(app)?;
    fs::create_dir_all(&home).map_err(|error| format!("create {}: {error}", home.display()))?;

    let token_path = home.join(".env");
    write_file_if_missing(
        &token_path,
        "DEFENSECLAW_GATEWAY_TOKEN=defenseclaw-desktop-agentrange-token\n",
    )?;

    let mode = if mode == "action" {
        "action"
    } else {
        "observe"
    };
    let config_path = home.join("config.yaml");
    let home_text = home.to_string_lossy().replace('\\', "\\\\");
    let contents = format!(
        r#"config_version: 7
data_dir: "{home}"
audit_db: "{home}\\audit.db"
judge_bodies_db: "{home}\\judge_bodies.db"
quarantine_dir: "{home}\\quarantine"
plugin_dir: ""
policy_dir: ""
environment: windows
claw:
  mode: ""
guardrail:
  enabled: true
  mode: {mode}
  scanner_mode: local
  host: 127.0.0.1
  port: 4000
  connector: ""
  block_message: "DefenseClaw blocked this AgentRange action."
  stream_buffer_bytes: 1024
  judge:
    enabled: false
    injection: true
    pii: true
    pii_prompt: true
    pii_completion: true
    tool_injection: true
    exfil: true
    timeout: 30.0
  hilt:
    enabled: false
    min_severity: HIGH
gateway:
  host: 127.0.0.1
  port: 18789
  api_bind: 0.0.0.0
  token_env: DEFENSECLAW_GATEWAY_TOKEN
  device_key_file: "{home}\\device.key"
  auto_approve_safe: false
  reconnect_ms: 800
  max_reconnect_ms: 15000
  approval_timeout_s: 30
  api_port: 18970
  fleet_mode: disabled
  watcher:
    enabled: false
    skill:
      enabled: false
      take_action: false
      dirs: []
    plugin:
      enabled: false
      take_action: false
      dirs: []
    mcp:
      take_action: false
  watchdog:
    enabled: false
    interval: 30
    debounce: 2
"#,
        home = home_text,
        mode = mode
    );
    fs::write(&config_path, contents)
        .map_err(|error| format!("write {}: {error}", config_path.display()))?;
    Ok(home)
}

pub(crate) fn run_gateway_action_for_mode(
    app: &tauri::AppHandle,
    action: &'static str,
    mode: &str,
) -> Result<LifecycleResult, String> {
    if !matches!(action, "start" | "stop" | "status" | "restart") {
        return Err("unsupported gateway lifecycle action".to_owned());
    }
    let home = ensure_gateway_home(app, mode)?;
    let mut command = Command::new(gateway_binary(app)?);
    command.arg(action);
    command.env("DEFENSECLAW_HOME", &home);
    command.env("DEFENSECLAW_CONFIG", home.join("config.yaml"));
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command
        .output()
        .map_err(|error| format!("run gateway {action}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let message = if !stdout.is_empty() {
        stdout
    } else if !stderr.is_empty() {
        stderr
    } else {
        format!("gateway {action} completed")
    };
    Ok(LifecycleResult {
        action,
        success: output.status.success(),
        message,
    })
}

pub(crate) fn run_gateway_action(
    app: &tauri::AppHandle,
    action: &'static str,
) -> Result<LifecycleResult, String> {
    run_gateway_action_for_mode(app, action, "observe")
}

#[tauri::command]
pub fn start_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    run_gateway_action(&app, "start")
}

#[tauri::command]
pub fn stop_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    run_gateway_action(&app, "stop")
}
