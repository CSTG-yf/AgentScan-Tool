use std::path::Path;

use tauri::Manager;

#[cfg(windows)]
fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn request_elevation(executable: &Path, arguments: &str) -> Result<(), String> {
    use std::ffi::c_void;

    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            window: *mut c_void,
            operation: *const u16,
            file: *const u16,
            parameters: *const u16,
            directory: *const u16,
            show_command: i32,
        ) -> isize;
    }

    let operation = wide("runas");
    let file = wide(&executable.to_string_lossy());
    let parameters = wide(arguments);
    // SAFETY: all UTF-16 buffers are NUL terminated and live through the call.
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            1,
        )
    };
    if result <= 32 {
        return Err(format!(
            "Windows elevation request failed with code {result}"
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn request_elevation(_executable: &Path, _arguments: &str) -> Result<(), String> {
    Err("process guard service is supported only on Windows".to_owned())
}

fn current_executable() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("resolve desktop executable: {error}"))
}

#[tauri::command]
pub fn install_process_guard() -> Result<(), String> {
    request_elevation(&current_executable()?, "--install-process-guard")
}

#[tauri::command]
pub fn apply_process_guard_policy(app: tauri::AppHandle) -> Result<(), String> {
    let policy_path = app
        .path()
        .app_config_dir()
        .map_err(|error| format!("resolve process guard policy path: {error}"))?
        .join("process-guard.json");
    if !policy_path.is_file() {
        return Err("save the process guard policy before applying it".to_owned());
    }
    let path_text = policy_path.to_string_lossy();
    if path_text.contains('"') {
        return Err("policy path contains an unsupported quote character".to_owned());
    }
    request_elevation(
        &current_executable()?,
        &format!("--apply-process-guard-policy \"{path_text}\""),
    )
}

#[tauri::command]
pub fn uninstall_process_guard() -> Result<(), String> {
    request_elevation(&current_executable()?, "--uninstall-process-guard")
}
