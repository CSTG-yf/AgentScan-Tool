use std::path::PathBuf;
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
    action: &'static str,
    success: bool,
    message: String,
}

fn gateway_binary(app: &tauri::AppHandle) -> Result<PathBuf, String> {
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

fn run_gateway_action(
    app: &tauri::AppHandle,
    action: &'static str,
) -> Result<LifecycleResult, String> {
    if !matches!(action, "start" | "stop" | "status") {
        return Err("unsupported gateway lifecycle action".to_owned());
    }
    let mut command = Command::new(gateway_binary(app)?);
    command.arg(action);
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

#[tauri::command]
pub fn start_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    run_gateway_action(&app, "start")
}

#[tauri::command]
pub fn stop_gateway(app: tauri::AppHandle) -> Result<LifecycleResult, String> {
    run_gateway_action(&app, "stop")
}
