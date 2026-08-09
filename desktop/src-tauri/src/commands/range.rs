use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use tauri::Manager;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DesktopSettings {
    agentrange_root: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeStatus {
    configured: bool,
    root: String,
    compose_file: String,
    docker_available: bool,
    running_services: Vec<String>,
    state: &'static str,
    detail: String,
}

fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("desktop-settings.json"))
        .map_err(|error| format!("resolve desktop settings path: {error}"))
}

fn read_settings(app: &tauri::AppHandle) -> DesktopSettings {
    let Ok(path) = settings_path(app) else {
        return DesktopSettings::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return DesktopSettings::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn default_development_root() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("task")
        .join("AgentRange-player");
    path.join("docker-compose.yml").is_file().then_some(path)
}

fn configured_root(app: &tauri::AppHandle) -> Option<PathBuf> {
    let settings = read_settings(app);
    if !settings.agentrange_root.trim().is_empty() {
        return Some(PathBuf::from(settings.agentrange_root));
    }
    std::env::var_os("DEFENSECLAW_AGENTRANGE_ROOT")
        .map(PathBuf::from)
        .or_else(default_development_root)
}

fn compose_path(root: &Path) -> Result<PathBuf, String> {
    let canonical = root
        .canonicalize()
        .map_err(|error| format!("open AgentRange root {}: {error}", root.display()))?;
    let compose = canonical.join("docker-compose.yml");
    if !compose.is_file() {
        return Err(format!(
            "AgentRange compose file not found: {}",
            compose.display()
        ));
    }
    Ok(compose)
}

fn run_docker(compose: &Path, arguments: &[&str]) -> Result<std::process::Output, String> {
    let mut command = Command::new("docker.exe");
    command
        .arg("compose")
        .arg("-f")
        .arg(compose)
        .args(arguments);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .output()
        .map_err(|error| format!("run Docker Compose: {error}"))
}

#[tauri::command]
pub fn get_range_status(app: tauri::AppHandle) -> RangeStatus {
    let Some(root) = configured_root(&app) else {
        return RangeStatus {
            configured: false,
            root: String::new(),
            compose_file: String::new(),
            docker_available: false,
            running_services: Vec::new(),
            state: "unconfigured",
            detail: "请选择 AgentRange-player 目录".to_owned(),
        };
    };
    let root_text = root.to_string_lossy().into_owned();
    let compose = match compose_path(&root) {
        Ok(path) => path,
        Err(detail) => {
            return RangeStatus {
                configured: false,
                root: root_text,
                compose_file: String::new(),
                docker_available: false,
                running_services: Vec::new(),
                state: "invalid",
                detail,
            }
        }
    };
    let output = run_docker(&compose, &["ps", "--services", "--status", "running"]);
    let Ok(output) = output else {
        return RangeStatus {
            configured: true,
            root: root_text,
            compose_file: compose.to_string_lossy().into_owned(),
            docker_available: false,
            running_services: Vec::new(),
            state: "dockerUnavailable",
            detail: "Docker Desktop 不可用".to_owned(),
        };
    };
    let services = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    RangeStatus {
        configured: true,
        root: root_text,
        compose_file: compose.to_string_lossy().into_owned(),
        docker_available: true,
        state: if services.is_empty() {
            "stopped"
        } else {
            "running"
        },
        detail: if output.status.success() {
            format!("{} 个服务运行中", services.len())
        } else {
            String::from_utf8_lossy(&output.stderr).trim().to_owned()
        },
        running_services: services,
    }
}

#[tauri::command]
pub fn set_range_root(app: tauri::AppHandle, root: String) -> Result<RangeStatus, String> {
    let root = PathBuf::from(root.trim());
    let compose = compose_path(&root)?;
    let canonical_root = compose
        .parent()
        .ok_or_else(|| "compose path has no parent".to_owned())?;
    let settings = DesktopSettings {
        agentrange_root: canonical_root.to_string_lossy().into_owned(),
    };
    let path = settings_path(&app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "settings path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("create settings directory: {error}"))?;
    fs::write(
        &path,
        serde_json::to_vec_pretty(&settings).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write desktop settings: {error}"))?;
    Ok(get_range_status(app))
}

fn change_range_state(app: &tauri::AppHandle, running: bool) -> Result<RangeStatus, String> {
    let root =
        configured_root(app).ok_or_else(|| "AgentRange root is not configured".to_owned())?;
    let compose = compose_path(&root)?;
    let arguments = if running {
        vec!["up", "-d"]
    } else {
        vec!["down"]
    };
    let output = run_docker(&compose, &arguments)?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(get_range_status(app.clone()))
}

#[tauri::command]
pub fn start_range(app: tauri::AppHandle) -> Result<RangeStatus, String> {
    change_range_state(&app, true)
}

#[tauri::command]
pub fn stop_range(app: tauri::AppHandle) -> Result<RangeStatus, String> {
    change_range_state(&app, false)
}
