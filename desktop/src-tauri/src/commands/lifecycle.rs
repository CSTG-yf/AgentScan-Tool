use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::gateway_ownership;
use crate::models::StaticResourceScanSettings;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Canonical API port the bundled Gateway binds (`gateway.api_port` in the
/// generated `config.yaml`).
///
/// This stays the *preferred* port — the desktop returns to it as soon as it
/// is free — but it is no longer a hard requirement. A second DefenseClaw home
/// (a CLI gateway started by hand, an AgentRange session, another desktop
/// profile) can legitimately hold it, and in that case the desktop must move
/// aside instead of leaving the user with an unusable control plane. See
/// [`pick_gateway_api_port`].
const DESKTOP_GATEWAY_API_PORT: u16 = 18970;

/// How many ports above the canonical one the desktop tries before giving up.
///
/// 21 candidates is far more than the realistic number of DefenseClaw
/// instances on one machine, and keeping the scan anchored to the canonical
/// port means the chosen port stays predictable in logs and messages.
const DESKTOP_GATEWAY_PORT_SCAN: u16 = 20;

/// How long the desktop waits for the helper's `stop` to finish while
/// shutting down. Slightly above the daemon's own 10s stop timeout
/// (`internal/daemon`: `defaultStopTimeout`) so a healthy stop wins the race
/// and records its outcome, while the exit path can never hang forever.
const EXIT_STOP_TIMEOUT: Duration = Duration::from_secs(12);

/// How long the exit path waits for the background stop thread before giving
/// up on joining it. Deliberately *above* [`EXIT_STOP_TIMEOUT`]: the outer
/// wait must not truncate the inner one, otherwise a slow-but-successful stop
/// would exit before writing `gateway-exit-state.json` and the next session
/// could not tell the user what happened.
pub(crate) const EXIT_JOIN_TIMEOUT: Duration = Duration::from_secs(13);

/// Records the outcome of the last exit teardown. By the time the gateway is
/// stopped the window is gone, so a file is the only honest way to tell the
/// next session whether the gateway really went down.
const GATEWAY_EXIT_STATE_FILE: &str = "gateway-exit-state.json";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleResult {
    pub(crate) action: &'static str,
    pub(crate) success: bool,
    pub(crate) message: String,
    /// Set when the desktop had to leave the canonical port because another
    /// DefenseClaw home already holds it. The UI surfaces it once, so a gateway
    /// on 18971 never looks like a bug.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) notice: Option<String>,
}

pub(crate) fn gateway_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("resolve desktop resource directory: {error}"))?;
    let binary_name = if cfg!(windows) {
        "defenseclaw-gateway.exe"
    } else {
        "defenseclaw-gateway"
    };
    let mut candidates = vec![
        resource_dir.join("resources").join(binary_name),
        resource_dir.join(binary_name),
    ];
    if let Ok(current) = std::env::current_exe() {
        if let Some(parent) = current.parent() {
            candidates.push(parent.join(binary_name));
        }
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join(binary_name),
    );
    let bundled = candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| format!("bundled {binary_name} was not found"))?;

    #[cfg(target_os = "linux")]
    {
        return install_linux_gateway(app, &bundled, binary_name);
    }

    #[cfg(not(target_os = "linux"))]
    Ok(bundled)
}

#[cfg(target_os = "linux")]
fn install_linux_gateway(
    app: &tauri::AppHandle,
    bundled: &Path,
    binary_name: &str,
) -> Result<PathBuf, String> {
    use std::os::unix::fs::PermissionsExt;

    // AppImage resources live below /tmp/.mount_* and disappear when the
    // AppImage is unmounted. The gateway is a detached daemon, so give each
    // application version a stable executable path outside that mount.
    let install_dir = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("resolve application data directory: {error}"))?
        .join("gateway")
        .join(app.package_info().version.to_string());
    fs::create_dir_all(&install_dir)
        .map_err(|error| format!("create {}: {error}", install_dir.display()))?;

    let installed = install_dir.join(binary_name);
    let needs_copy = match (fs::read(bundled), fs::read(&installed)) {
        (Ok(source), Ok(destination)) => source != destination,
        (Ok(_), Err(_)) => true,
        (Err(error), _) => {
            return Err(format!(
                "read bundled gateway {}: {error}",
                bundled.display()
            ))
        }
    };

    if needs_copy {
        let temporary = install_dir.join(format!(".{binary_name}.{}.tmp", std::process::id()));
        fs::copy(bundled, &temporary).map_err(|error| {
            format!(
                "copy bundled gateway {} to {}: {error}",
                bundled.display(),
                temporary.display()
            )
        })?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("set permissions on {}: {error}", temporary.display()))?;
        fs::rename(&temporary, &installed).map_err(|error| {
            format!(
                "install gateway {} as {}: {error}",
                temporary.display(),
                installed.display()
            )
        })?;
    } else {
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o755))
            .map_err(|error| format!("set permissions on {}: {error}", installed.display()))?;
    }

    Ok(installed)
}

pub(crate) fn desktop_defenseclaw_home(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("defenseclaw-home"))
        .map_err(|error| format!("resolve DefenseClaw data directory: {error}"))
}

/// Reads the top-level `api_port:` value out of a `config.yaml` body.
///
/// Same one-pass shape as `gateway_api.rs::gateway_port` (and the copies in
/// `trace_store.rs` / `process_guard_service.rs`) so every desktop component
/// agrees on which port the bundled gateway is supposed to serve.
fn parse_api_port(raw: &str) -> Option<u16> {
    raw.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "api_port" {
            return None;
        }
        value.trim().parse::<u16>().ok()
    })
}

fn read_api_port(config_path: &Path) -> Option<u16> {
    fs::read_to_string(config_path)
        .ok()
        .and_then(|raw| parse_api_port(&raw))
}

/// Port this desktop currently serves from; the canonical port on a fresh
/// install.
pub(crate) fn desktop_gateway_api_port(home: &Path) -> u16 {
    read_api_port(&home.join("config.yaml")).unwrap_or(DESKTOP_GATEWAY_API_PORT)
}

pub(crate) fn desktop_gateway_api_port_for_app(app: &tauri::AppHandle) -> Result<u16, String> {
    Ok(desktop_gateway_api_port(&desktop_defenseclaw_home(app)?))
}

/// Picks the port the desktop should run its own gateway on.
///
/// The canonical port wins whenever it is free or already held by *our* daemon,
/// so a desktop that had to move aside returns to 18970 as soon as the other
/// home releases it. Only a listener that is demonstrably not ours pushes the
/// choice upward — which is exactly what lets two independent DefenseClaw homes
/// coexist on one machine.
fn pick_gateway_api_port<F>(canonical: u16, listeners: F, owned_pid: Option<u32>) -> u16
where
    F: Fn(u16) -> Option<u32>,
{
    let mut port = canonical;
    for _ in 0..=DESKTOP_GATEWAY_PORT_SCAN {
        match listeners(port) {
            None => return port,
            Some(listener) if Some(listener) == owned_pid => return port,
            Some(_) => {}
        }
        match port.checked_add(1) {
            Some(next) => port = next,
            None => break,
        }
    }
    canonical
}

fn choose_gateway_api_port(home: &Path) -> u16 {
    pick_gateway_api_port(
        DESKTOP_GATEWAY_API_PORT,
        gateway_ownership::port_listener_pid,
        gateway_ownership::owned_daemon_pid(home),
    )
}

/// Points `<home>/config.yaml` at `port`, rewriting only that one line so the
/// rest of the file (mode, watcher tuning, claw root, judge settings) survives
/// untouched. Regenerates the whole file on a fresh install, where there is
/// nothing to preserve yet.
fn ensure_config_api_port(app: &tauri::AppHandle, home: &Path, port: u16) -> Result<(), String> {
    let config_path = home.join("config.yaml");
    if !config_path.is_file() {
        return ensure_gateway_home_with_port(app, "observe", Some(port)).map(|_| ());
    }
    if read_api_port(&config_path) == Some(port) {
        return Ok(());
    }
    let raw = fs::read_to_string(&config_path)
        .map_err(|error| format!("read {}: {error}", config_path.display()))?;
    let mut replaced = false;
    let mut rendered = String::with_capacity(raw.len() + 8);
    for line in raw.lines() {
        if !replaced {
            if let Some((key, _)) = line.split_once(':') {
                if key.trim() == "api_port" {
                    let trimmed = line.trim_start();
                    let indent = &line[..line.len() - trimmed.len()];
                    rendered.push_str(&format!("{indent}api_port: {port}\n"));
                    replaced = true;
                    continue;
                }
            }
        }
        rendered.push_str(line);
        rendered.push('\n');
    }
    if !replaced {
        return Err(format!(
            "{} 中没有 api_port 行，无法把内置网关切换到端口 {port}",
            config_path.display()
        ));
    }
    fs::write(&config_path, rendered)
        .map_err(|error| format!("write {}: {error}", config_path.display()))
}

/// Explains, inside lifecycle messages and the one-shot UI notice, why the
/// desktop is not on the canonical port: the user should never have to guess
/// why the UI mentions 18971.
fn port_switch_notice(port: u16) -> Option<String> {
    if port == DESKTOP_GATEWAY_API_PORT {
        return None;
    }
    Some(match gateway_ownership::port_listener_pid(DESKTOP_GATEWAY_API_PORT) {
        Some(pid) => format!(
            "端口 {DESKTOP_GATEWAY_API_PORT} 已被另一个 DefenseClaw 网关占用（PID {pid}），本桌面端已改用端口 {port}，两个实例互不影响"
        ),
        None => format!("本桌面端使用端口 {port}"),
    })
}

/// `；`-prefixed form for lifecycle `message` strings.
fn port_switch_note(port: u16) -> String {
    port_switch_notice(port)
        .map(|notice| format!("；{notice}"))
        .unwrap_or_default()
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
            .join("AgentRange-player-full"),
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
    ensure_gateway_home_with_port(app, mode, None)
}

/// Generates (or regenerates) the desktop home's `config.yaml`.
///
/// `port_override` is only set while switching to an alternative API port.
/// Passing `None` keeps whatever port the existing config already records, so a
/// `restart`/`stop` can never silently drag the desktop back onto the canonical
/// port and collide with the other home again.
fn ensure_gateway_home_with_port(
    app: &tauri::AppHandle,
    mode: &str,
    port_override: Option<u16>,
) -> Result<PathBuf, String> {
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
    let api_port = port_override.unwrap_or_else(|| desktop_gateway_api_port(&home));
    let home_path = yaml_quoted_path(&home);
    let audit_db = yaml_quoted_path(&home.join("audit.db"));
    let judge_bodies_db = yaml_quoted_path(&home.join("judge_bodies.db"));
    let quarantine_dir = yaml_quoted_path(&home.join("quarantine"));
    let device_key_file = yaml_quoted_path(&home.join("device.key"));
    let environment = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "darwin"
    };
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
data_dir: {home}
audit_db: {audit_db}
judge_bodies_db: {judge_bodies_db}
quarantine_dir: {quarantine_dir}
plugin_dir: ""
policy_dir: ""
environment: {environment}
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
  api_bind: 127.0.0.1
  token_env: DEFENSECLAW_GATEWAY_TOKEN
  device_key_file: {device_key_file}
  auto_approve_safe: false
  reconnect_ms: 800
  max_reconnect_ms: 15000
  approval_timeout_s: 30
  api_port: {api_port}
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
        home = home_path,
        audit_db = audit_db,
        judge_bodies_db = judge_bodies_db,
        quarantine_dir = quarantine_dir,
        device_key_file = device_key_file,
        environment = environment,
        mode = mode,
        claw_block = claw_block,
        watch_block = watch_block,
        watcher_enabled = watcher_enabled,
        skill_dirs_yaml = skill_dirs_yaml,
        plugin_watcher_enabled = plugin_watcher_enabled,
        api_port = api_port
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
    run_gateway_action_for_mode_bounded(app, action, mode, None)
}

/// Runs a gateway lifecycle action with an optional hard deadline.
///
/// The unbounded path is fine for UI-triggered actions, but the shutdown path
/// needs a bounded wait: if the helper process never exits the desktop would
/// hang on the way out, so a deadline turns "hang" into a reported failure.
///
/// stdio is detached for the bounded path because the helper *spawns the
/// detached daemon*: with inherited pipes a surviving grandchild would hold
/// the write ends open, and `wait_with_output` would block on EOF even after
/// the helper itself exited. The unbounded path keeps piping so the UI can
/// still show the CLI's message.
fn run_gateway_action_for_mode_bounded(
    app: &tauri::AppHandle,
    action: &'static str,
    mode: &str,
    deadline: Option<Duration>,
) -> Result<LifecycleResult, String> {
    if !matches!(action, "start" | "stop" | "status" | "restart") {
        return Err("unsupported gateway lifecycle action".to_owned());
    }
    let bounded = deadline.is_some();
    let home = ensure_gateway_home(app, mode)?;
    let mut command = Command::new(gateway_binary(app)?);
    command.arg(action);
    command.env("DEFENSECLAW_HOME", &home);
    command.env("DEFENSECLAW_CONFIG", home.join("config.yaml"));
    command.env(
        "DEFENSECLAW_FILE_GUARD_POLICY",
        app.path()
            .app_config_dir()
            .map_err(|error| format!("resolve file guard policy: {error}"))?
            .join("process-guard.json"),
    );
    command.stdin(Stdio::null());
    if bounded {
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
    } else {
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
    }
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);

    let mut child = command
        .spawn()
        .map_err(|error| format!("run gateway {action}: {error}"))?;

    if let Some(deadline) = deadline {
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => return Err(format!("run gateway {action}: {error}")),
            }
            if started.elapsed() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Ok(LifecycleResult {
                    action,
                    success: false,
                    message: format!(
                        "gateway {action} did not finish within {}s and was terminated",
                        deadline.as_secs()
                    ),
                    notice: None,
                });
            }
            thread::sleep(Duration::from_millis(50));
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|error| format!("run gateway {action}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let message = if !stdout.is_empty() {
        stdout
    } else if !stderr.is_empty() {
        stderr
    } else if bounded {
        // Output was detached, so success is described rather than quoted.
        format!("gateway {action} finished (exit status only; output detached)")
    } else {
        format!("gateway {action} completed")
    };
    Ok(LifecycleResult {
        action,
        success: output.status.success(),
        message,
        notice: None,
    })
}

pub(crate) fn run_gateway_action(
    app: &tauri::AppHandle,
    action: &'static str,
) -> Result<LifecycleResult, String> {
    run_gateway_action_for_mode(app, action, "observe")
}

fn wait_for_gateway(app: &tauri::AppHandle, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_error =
        match crate::commands::gateway_api::get_json::<serde_json::Value>(app, "/health") {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };
    while Instant::now() < deadline {
        thread::sleep(Duration::from_millis(150));
        match crate::commands::gateway_api::get_json::<serde_json::Value>(app, "/health") {
            Ok(_) => return Ok(()),
            Err(error) => last_error = error,
        }
    }
    Err(last_error)
}

fn ensure_gateway_ready_inner(app: &tauri::AppHandle) -> Result<LifecycleResult, String> {
    let home = desktop_defenseclaw_home(app)?;
    // Pick the port *before* probing: `gateway_api` resolves the port from
    // `config.yaml`, so the file has to describe the port we are about to use.
    // A foreign gateway on 18970 (a hand-started CLI daemon, an AgentRange
    // session, another desktop profile) costs us the canonical port — never the
    // control plane.
    let port = choose_gateway_api_port(&home);
    ensure_config_api_port(app, &home, port)?;
    let note = port_switch_note(port);
    let notice = port_switch_notice(port);

    let ready = wait_for_gateway(app, Duration::from_millis(50)).is_ok();
    let owned = gateway_ownership::recorded_daemon_is_owned(&home);

    // Reuse an already healthy daemon. This keeps desktop restarts quick and
    // avoids interrupting hooks that continue to use the bundled gateway —
    // but only when that daemon is demonstrably ours. A daemon from another
    // DefenseClaw home (for example one started by hand with the CLI) also
    // answers /health, and adopting it would report success while the
    // desktop's own home, config and database were never in play.
    if ready && owned {
        return Ok(LifecycleResult {
            action: "start",
            success: true,
            message: format!("内置 Go Gateway 已就绪{note}"),
            notice,
        });
    }
    if ready {
        // Reachable only when every candidate port is held by another home
        // (or a listener appeared between the scan and this probe): report the
        // conflict instead of joining someone else's database.
        return Ok(LifecycleResult {
            action: "start",
            success: false,
            message: foreign_gateway_message(&home, port),
            notice: None,
        });
    }

    // A daemon PID can remain valid even after its API subsystem has stopped.
    // `start` only checks that PID and would report "already running", leaving
    // the desktop unable to reach /health. Restart is safe when no daemon is
    // running and repairs this live-process/dead-API state when one is.
    let started = run_gateway_action(app, "restart")?;
    if !started.success {
        // Keep the port-switch context: a failure *after* moving aside must
        // still tell the user which port the desktop tried to start on.
        return Ok(LifecycleResult {
            action: started.action,
            success: false,
            message: format!("{}{note}", started.message),
            notice,
        });
    }
    match wait_for_gateway(app, Duration::from_secs(12)) {
        Ok(()) => Ok(LifecycleResult {
            action: "start",
            success: true,
            message: format!("内置 Go Gateway 已启动{note}"),
            notice,
        }),
        Err(error) => Ok(LifecycleResult {
            action: "start",
            success: false,
            message: format!(
                "内置 Go Gateway 启动后未就绪：{error}。请查看 {}",
                home.join("gateway.log").display()
            ),
            notice: None,
        }),
    }
}

/// Explains why a healthy daemon on the desktop API port is not adopted.
///
/// Reachable only after [`pick_gateway_api_port`] failed to find a free port
/// inside its scan range, so it is now the *last resort* rather than the normal
/// outcome of two homes coexisting: another home holds every candidate port and
/// the user has to release one.
fn foreign_gateway_message(home: &Path, port: u16) -> String {
    let listener = gateway_ownership::port_listener_pid(port);
    let listener = match listener {
        Some(pid) => format!("，占用端口 {port} 的进程 PID 为 {pid}"),
        None => String::new(),
    };
    let recorded = gateway_ownership::read_pid_info(home).map(|info| info.pid);
    let recorded = match recorded {
        Some(pid) => format!("（本桌面端 gateway.pid 记录为 {pid}）"),
        None => "（本桌面端没有 gateway.pid，或文件不可读）".to_owned(),
    };
    format!(
        "端口 {port} 上已有 Gateway 响应，但它无法被证明属于本桌面端数据目录 {home}{recorded}{listener}。\
         为避免在错误的 home、配置或数据库上操作，桌面端不会接管该进程；\
         端口 {first}–{last} 也都已被其它 DefenseClaw 网关占用，请先释放其中一个端口再重试。\
         若 {port} 上是本桌面端残留的进程，请在 PowerShell 中执行：\
         $env:DEFENSECLAW_HOME='{home}'; defenseclaw-gateway stop；\
         若它来自其它 home，请在其所属 home 下停止后重新启动桌面端网关。",
        port = port,
        first = DESKTOP_GATEWAY_API_PORT,
        last = DESKTOP_GATEWAY_API_PORT.saturating_add(DESKTOP_GATEWAY_PORT_SCAN),
        home = home.display(),
        recorded = recorded,
        listener = listener,
    )
}

/// Whether an exit request should tear the gateway down, or let the app quit.
///
/// Pure so the decision is testable without a running event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExitRequestDisposition {
    HandleExit,
    Ignore,
}

/// `exit_code` is `Some` only when the exit was requested programmatically
/// (for example the tray's "退出并停止网关" item, which already stopped the
/// gateway itself). A `None` code means the user closed the window or chose
/// Quit, which is exactly the case that used to leave the daemon running.
pub(crate) fn exit_request_disposition(exit_code: Option<i32>) -> ExitRequestDisposition {
    match exit_code {
        None => ExitRequestDisposition::HandleExit,
        Some(_) => ExitRequestDisposition::Ignore,
    }
}

/// Runs once per process: the exit hook must not stop the gateway twice, and
/// a programmatic exit after a tray shutdown must not repeat the work.
static EXIT_TEARDOWN_STARTED: AtomicBool = AtomicBool::new(false);

/// Outcome of the shutdown teardown, persisted for the next session.
///
/// The window is already gone when this is written, so the file is the only
/// channel that can carry "the gateway may still be running" to the user.
/// `get_gateway_exit_state` surfaces it on the next start.
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct GatewayExitState {
    pub stopped: bool,
    pub message: String,
    pub recorded_at: String,
}

impl Default for GatewayExitState {
    fn default() -> Self {
        Self {
            stopped: true,
            message: String::new(),
            recorded_at: String::new(),
        }
    }
}

fn gateway_exit_state_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(GATEWAY_EXIT_STATE_FILE))
        .map_err(|error| format!("resolve gateway exit state path: {error}"))
}

/// Last recorded exit teardown, or `None` when this desktop has never
/// written one (fresh install, or every previous exit was clean and has been
/// acknowledged).
#[tauri::command]
pub fn get_gateway_exit_state(app: tauri::AppHandle) -> Option<GatewayExitState> {
    let path = gateway_exit_state_path(&app).ok()?;
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

/// Removes the recorded state once the user has seen it, so a stale warning
/// does not reappear on every launch.
#[tauri::command]
pub fn clear_gateway_exit_state(app: tauri::AppHandle) -> Result<(), String> {
    let path = gateway_exit_state_path(&app)?;
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove {}: {error}", path.display())),
    }
}

/// Stops the desktop-managed gateway as part of application shutdown.
///
/// Returns `None` when there is nothing to wait for (nothing of ours was
/// running, the port belongs to someone else, or the teardown already ran).
/// Returns `Some(handle)` when a stop was started in the background: the
/// caller must [`finish_gateway_shutdown`] before letting the process die,
/// otherwise the helper never gets the chance to terminate the detached
/// daemon and the original bug comes back.
pub(crate) fn begin_gateway_shutdown(app: &tauri::AppHandle) -> Option<thread::JoinHandle<()>> {
    if EXIT_TEARDOWN_STARTED.swap(true, Ordering::SeqCst) {
        return None;
    }

    // Resolve everything that needs the app handle *before* moving to the
    // background thread: `AppHandle::path()` reads the process environment,
    // which is still intact here, whereas a failure inside the worker would
    // silently skip the stop.
    let Ok(home) = desktop_defenseclaw_home(app) else {
        record_gateway_exit_state(app, false, "无法解析桌面端数据目录，未执行 Gateway 停止");
        return None;
    };
    let owned_pid = gateway_ownership::owned_daemon_pid(&home);
    // Our daemon may live on an alternative port (another DefenseClaw home held
    // 18970 on startup), so the teardown has to look at the port this desktop is
    // actually configured for — not the canonical constant.
    let port = desktop_gateway_api_port(&home);
    if gateway_ownership::port_listener_pid(port).is_none() {
        // Nobody holds the API port: nothing to stop, whether or not a stale
        // PID file happens to be lying around.
        record_gateway_exit_state(app, true, "Gateway 未在运行");
        return None;
    }
    if owned_pid.is_none() {
        // A Gateway is listening but it is not ours (no PID file, unreadable
        // PID file, or a PID that no longer matches). Stopping "our" absent
        // daemon would be a no-op, and stopping theirs would be wrong.
        record_gateway_exit_state(
            app,
            false,
            &format!("端口 {port} 由不属于本桌面端的进程占用，桌面退出时未执行停止"),
        );
        return None;
    }

    let app_handle = app.clone();
    let worker_home = home;
    thread::Builder::new()
        .name("gateway-shutdown".to_owned())
        .spawn(move || {
            let outcome = run_gateway_action_for_mode_bounded(
                &app_handle,
                "stop",
                "observe",
                Some(EXIT_STOP_TIMEOUT),
            );
            let (stopped, message) = match outcome {
                Ok(result) => (result.success, result.message),
                Err(error) => (false, error),
            };
            // The helper exits 0 even when nothing was running, so confirm
            // against the recorded PID and the port: claiming "stopped" while
            // the daemon still listens is exactly the state this fix exists to
            // remove.
            let recorded_alive = gateway_ownership::read_pid_info(&worker_home)
                .map(|info| gateway_ownership::process_is_running(info.pid))
                .unwrap_or(false);
            let port_held = gateway_ownership::port_listener_pid(port).is_some();
            let (stopped, message) = if recorded_alive {
                (
                    false,
                    format!("{message}；Gateway 进程仍在运行，请手动停止"),
                )
            } else if port_held {
                (
                    false,
                    format!("{message}；端口 {port} 上仍有进程在监听，请确认它是否属于本桌面端"),
                )
            } else {
                (stopped, message)
            };
            record_gateway_exit_state(&app_handle, stopped, &message);
        })
        .map_err(|error| {
            record_gateway_exit_state(
                app,
                false,
                &format!("无法启动 Gateway 停止线程：{error}"),
            );
            error
        })
        .ok()
}

/// Waits (bounded) for the background shutdown started by
/// [`begin_gateway_shutdown`], then returns whether it completed in time.
///
/// `JoinHandle::is_finished` keeps this a plain bounded poll instead of an
/// unbounded `join`, so a wedged helper can only cost the timeout — never a
/// desktop that refuses to close.
pub(crate) fn finish_gateway_shutdown(
    handle: Option<thread::JoinHandle<()>>,
    timeout: Duration,
) -> bool {
    let Some(handle) = handle else {
        return true;
    };
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
    // Joining a finished handle only collects the result.
    let _ = handle.join();
    true
}

fn record_gateway_exit_state(app: &tauri::AppHandle, stopped: bool, message: &str) {
    let Ok(directory) = app.path().app_config_dir() else {
        return;
    };
    let state = GatewayExitState {
        stopped,
        message: message.to_owned(),
        recorded_at: chrono::Utc::now().to_rfc3339(),
    };
    if fs::create_dir_all(&directory).is_err() {
        return;
    }
    if let Ok(serialized) = serde_json::to_vec_pretty(&state) {
        let _ = fs::write(directory.join(GATEWAY_EXIT_STATE_FILE), serialized);
    }
}

#[tauri::command]
pub fn ensure_gateway_ready(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    ensure_gateway_ready_inner(&app)
}

#[tauri::command]
pub fn start_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    ensure_gateway_ready_inner(&app)
}

#[tauri::command]
pub fn stop_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    run_gateway_action(&app, "stop")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_initiated_exit_handles_the_gateway() {
        assert_eq!(
            exit_request_disposition(None),
            ExitRequestDisposition::HandleExit
        );
    }

    #[test]
    fn programmatic_exit_does_not_repeat_the_stop() {
        assert_eq!(
            exit_request_disposition(Some(0)),
            ExitRequestDisposition::Ignore
        );
        assert_eq!(
            exit_request_disposition(Some(1)),
            ExitRequestDisposition::Ignore
        );
    }

    #[test]
    fn foreign_gateway_message_names_the_home_and_port() {
        let home = Path::new("C:\\Users\\tester\\AppData\\Roaming\\dev.defenseclaw.desktop\\defenseclaw-home");
        let message = foreign_gateway_message(home, DESKTOP_GATEWAY_API_PORT);
        assert!(message.contains("18970"));
        assert!(message.contains("defenseclaw-home"));
        assert!(message.contains("不会接管"));
    }

    /// The canonical port must win whenever it is free, so a desktop that had
    /// to move aside returns to 18970 as soon as the other home lets go.
    #[test]
    fn canonical_port_is_preferred_when_free() {
        let chosen = pick_gateway_api_port(DESKTOP_GATEWAY_API_PORT, |_| None, None);
        assert_eq!(chosen, DESKTOP_GATEWAY_API_PORT);
    }

    /// Our own daemon keeps its port even though a listener is present,
    /// otherwise every desktop restart would drift to a new port.
    #[test]
    fn own_daemon_keeps_its_port() {
        let port = DESKTOP_GATEWAY_API_PORT;
        let chosen = pick_gateway_api_port(port, |p| (p == port).then_some(4242), Some(4242));
        assert_eq!(chosen, port);
    }

    /// A foreign gateway on the canonical port makes the desktop move aside
    /// instead of failing: 18970 taken, 18971 free -> 18971.
    #[test]
    fn foreign_listener_pushes_the_desktop_up_one_port() {
        let canonical = DESKTOP_GATEWAY_API_PORT;
        let taken = canonical;
        let chosen = pick_gateway_api_port(canonical, |p| (p == taken).then_some(9999), Some(4242));
        assert_eq!(chosen, canonical + 1);
    }

    /// Every candidate taken is the one case that still reports a conflict.
    #[test]
    fn full_scan_falls_back_to_the_canonical_port_for_reporting() {
        let canonical = DESKTOP_GATEWAY_API_PORT;
        let chosen = pick_gateway_api_port(canonical, |_| Some(9999), Some(4242));
        assert_eq!(chosen, canonical);
    }

    #[test]
    fn api_port_parsing_matches_the_other_desktop_readers() {
        let raw = "config_version: 7\ndata_dir: \"C:\\\\home\"\n  api_port: 18971\n";
        assert_eq!(parse_api_port(raw), Some(18971));
        assert_eq!(parse_api_port("data_dir: x"), None);
        assert_eq!(parse_api_port("  # api_port: 1234"), None);
    }

    #[test]
    fn port_switch_note_is_silent_on_the_canonical_port() {
        assert!(port_switch_note(DESKTOP_GATEWAY_API_PORT).is_empty());
        assert!(port_switch_note(DESKTOP_GATEWAY_API_PORT + 1).contains("18971"));
    }

    #[test]
    fn port_switch_notice_is_only_set_off_the_canonical_port() {
        assert!(port_switch_notice(DESKTOP_GATEWAY_API_PORT).is_none());
        let notice =
            port_switch_notice(DESKTOP_GATEWAY_API_PORT + 1).expect("notice off canonical");
        assert!(notice.contains("18971"));
    }

    #[test]
    fn exit_state_round_trips_as_camel_case() {
        let state = GatewayExitState {
            stopped: false,
            message: "Gateway 进程仍在运行".to_owned(),
            recorded_at: "2026-02-01T00:00:00Z".to_owned(),
        };
        let encoded = serde_json::to_string(&state).expect("serialize exit state");
        assert!(encoded.contains("recordedAt"));
        assert!(encoded.contains("\"stopped\":false"));
        let decoded: GatewayExitState = serde_json::from_str(&encoded).unwrap();
        assert!(!decoded.stopped);
        assert_eq!(decoded.recorded_at, state.recorded_at);
    }

    #[test]
    fn missing_exit_state_fields_default_to_stopped() {
        // A truncated or older file must not be reported as "may still be
        // running" noise; the safe default is "nothing to warn about".
        let decoded: GatewayExitState = serde_json::from_str("{}").unwrap();
        assert!(decoded.stopped);
    }
}
