use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::models::StaticResourceScanSettings;

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

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct DesktopSettings {
    agentrange_root: String,
}

fn desktop_settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("desktop-settings.json"))
        .map_err(|error| format!("resolve desktop settings path: {error}"))
}

fn read_desktop_settings(app: &tauri::AppHandle) -> DesktopSettings {
    let Ok(path) = desktop_settings_path(app) else {
        return DesktopSettings::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return DesktopSettings::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn looks_like_agentrange_root(path: &Path) -> bool {
    path.join("docker-compose.yml").is_file()
        && (path.join("skills").is_dir() || path.join("mcp").is_dir())
}

fn normalize_agentrange_root(path: PathBuf) -> Option<PathBuf> {
    if path.as_os_str().is_empty() || !looks_like_agentrange_root(&path) {
        return None;
    }
    Some(path.canonicalize().unwrap_or(path))
}

fn default_development_agentrange_root() -> Option<PathBuf> {
    normalize_agentrange_root(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("task")
            .join("AgentRange-player"),
    )
}

fn configured_agentrange_root(app: &tauri::AppHandle) -> Option<PathBuf> {
    let settings = read_desktop_settings(app);
    let configured = settings.agentrange_root.trim();
    if !configured.is_empty() {
        if let Some(root) = normalize_agentrange_root(PathBuf::from(configured)) {
            return Some(root);
        }
    }

    if let Some(root) = std::env::var_os("DEFENSECLAW_AGENTRANGE_ROOT")
        .and_then(|value| normalize_agentrange_root(PathBuf::from(value)))
    {
        return Some(root);
    }

    default_development_agentrange_root()
}

fn yaml_quoted_path(path: &Path) -> String {
    let value = path
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    format!("\"{value}\"")
}

fn render_claw_block(agentrange_root: Option<&Path>) -> String {
    let Some(root) = agentrange_root else {
        return "claw:\n  mode: \"\"".to_owned();
    };
    let root = yaml_quoted_path(root);
    format!("claw:\n  mode: \"\"\n  home_dir: {root}\n  workspace_dir: {root}")
}

fn render_yaml_path_list(paths: &[PathBuf], item_indent: usize) -> String {
    if paths.is_empty() {
        return "[]".to_owned();
    }
    let indent = " ".repeat(item_indent);
    let items = paths
        .iter()
        .map(|path| format!("{indent}- {}", yaml_quoted_path(path)))
        .collect::<Vec<_>>()
        .join("\n");
    format!("\n{items}")
}

fn read_static_resource_scan_settings_from_path(path: &Path) -> StaticResourceScanSettings {
    let Ok(raw) = fs::read_to_string(path) else {
        return StaticResourceScanSettings::default();
    };
    parse_static_resource_scan_settings(&raw).normalize()
}

fn parse_static_resource_scan_settings(raw: &str) -> StaticResourceScanSettings {
    let mut settings = StaticResourceScanSettings::default();
    let mut in_watch = false;

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_watch = trimmed == "watch:";
            continue;
        }
        if !in_watch {
            continue;
        }

        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = clean_yaml_scalar(value);
        match key {
            "realtime_enabled" => {
                settings.realtime_enabled = parse_yaml_bool(value, settings.realtime_enabled)
            }
            "rescan_enabled" => {
                settings.rescan_enabled = parse_yaml_bool(value, settings.rescan_enabled)
            }
            "debounce_ms" => settings.debounce_ms = parse_yaml_u64(value, settings.debounce_ms),
            "rescan_skill_interval_min" => {
                settings.skill_interval_min = parse_yaml_u64(value, settings.skill_interval_min)
            }
            "rescan_plugin_interval_min" => {
                settings.plugin_interval_min = parse_yaml_u64(value, settings.plugin_interval_min)
            }
            "rescan_mcp_interval_min" => {
                settings.mcp_interval_min = parse_yaml_u64(value, settings.mcp_interval_min)
            }
            "rescan_prompt_interval_min" => {
                settings.prompt_interval_min = parse_yaml_u64(value, settings.prompt_interval_min)
            }
            "rescan_credential_interval_min" => {
                settings.credential_interval_min =
                    parse_yaml_u64(value, settings.credential_interval_min)
            }
            "rescan_environment_interval_min" => {
                settings.environment_interval_min =
                    parse_yaml_u64(value, settings.environment_interval_min)
            }
            _ => {}
        }
    }

    settings
}

fn clean_yaml_scalar(value: &str) -> &str {
    value
        .split('#')
        .next()
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
}

fn parse_yaml_bool(value: &str, fallback: bool) -> bool {
    match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => true,
        "false" | "no" | "off" | "0" => false,
        _ => fallback,
    }
}

fn parse_yaml_u64(value: &str, fallback: u64) -> u64 {
    value.parse::<u64>().unwrap_or(fallback)
}

fn render_watch_block(settings: StaticResourceScanSettings) -> String {
    let settings = settings.normalize();
    format!(
        "\
watch:
  debounce_ms: {debounce_ms}
  auto_block: true
  allow_list_bypass_scan: false
  realtime_enabled: {realtime_enabled}
  rescan_enabled: {rescan_enabled}
  rescan_interval_min: 60
  rescan_skill_interval_min: {skill_interval_min}
  rescan_plugin_interval_min: {plugin_interval_min}
  rescan_mcp_interval_min: {mcp_interval_min}
  rescan_prompt_interval_min: {prompt_interval_min}
  rescan_credential_interval_min: {credential_interval_min}
  rescan_environment_interval_min: {environment_interval_min}
  rescan_content_gated: true",
        debounce_ms = settings.debounce_ms,
        realtime_enabled = settings.realtime_enabled,
        rescan_enabled = settings.rescan_enabled,
        skill_interval_min = settings.skill_interval_min,
        plugin_interval_min = settings.plugin_interval_min,
        mcp_interval_min = settings.mcp_interval_min,
        prompt_interval_min = settings.prompt_interval_min,
        credential_interval_min = settings.credential_interval_min,
        environment_interval_min = settings.environment_interval_min,
    )
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
    let agentrange_root = configured_agentrange_root(app);
    let claw_block = render_claw_block(agentrange_root.as_deref());
    let skill_dirs = agentrange_root
        .as_ref()
        .map(|root| vec![root.join("skills")])
        .unwrap_or_default();
    let skill_dirs_yaml = render_yaml_path_list(&skill_dirs, 8);
    let static_scan_settings = read_static_resource_scan_settings_from_path(&config_path);
    let watch_block = render_watch_block(static_scan_settings);
    let watcher_enabled =
        static_scan_settings.realtime_enabled || static_scan_settings.rescan_enabled;
    let plugin_watcher_enabled = watcher_enabled && agentrange_root.is_none();
    let contents = format!(
        r#"config_version: 7
data_dir: "{home}"
audit_db: "{home}\\audit.db"
judge_bodies_db: "{home}\\judge_bodies.db"
quarantine_dir: "{home}\\quarantine"
plugin_dir: ""
policy_dir: ""
environment: windows
{claw_block}
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
{watch_block}
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
    enabled: {watcher_enabled}
    skill:
      enabled: {watcher_enabled}
      take_action: false
      dirs: {skill_dirs_yaml}
    plugin:
      enabled: {plugin_watcher_enabled}
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
        mode = mode,
        claw_block = claw_block,
        watch_block = watch_block,
        watcher_enabled = watcher_enabled,
        skill_dirs_yaml = skill_dirs_yaml,
        plugin_watcher_enabled = plugin_watcher_enabled
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
