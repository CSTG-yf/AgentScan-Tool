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
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED,
    };
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS,
        SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    // Shell execution needs a COM apartment even on the blocking worker thread.
    let initialized = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    if initialized < 0 {
        return Err(format!(
            "初始化 Windows 提权接口失败：0x{:08x}",
            initialized as u32
        ));
    }
    struct ComApartment;
    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    let _apartment = ComApartment;

    let operation = wide("runas");
    let file = wide(&executable.to_string_lossy());
    let parameters = wide(arguments);
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = operation.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_HIDE;
    // Buffers and the execution structure remain alive until ShellExecuteExW returns.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(1223) {
            return Err("已取消管理员授权，操作未执行".to_owned());
        }
        return Err(format!("无法启动管理员操作：{error}"));
    }
    if info.hProcess.is_null() {
        return Err("Windows 未返回管理员进程句柄，无法确认操作结果".to_owned());
    }
    let result = (|| {
        match unsafe { WaitForSingleObject(info.hProcess, 120_000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(
                    "管理员操作尚未完成（等待超过 120 秒），请刷新检查状态后再操作".to_owned(),
                )
            }
            _ => {
                return Err(format!(
                    "等待管理员操作失败：{}",
                    std::io::Error::last_os_error()
                ))
            }
        }
        let mut code = 0;
        if unsafe { GetExitCodeProcess(info.hProcess, &mut code) } == 0 {
            return Err(format!(
                "读取管理员操作结果失败：{}",
                std::io::Error::last_os_error()
            ));
        }
        if code != 0 {
            return Err(format!(
                "管理员操作执行失败（退出码 {code}），请检查服务状态和策略路径；未确认操作成功"
            ));
        }
        Ok(())
    })();
    unsafe { CloseHandle(info.hProcess) };
    result
}

#[cfg(not(windows))]
fn request_elevation(_executable: &Path, _arguments: &str) -> Result<(), String> {
    Err("process guard service is supported only on Windows".to_owned())
}

fn current_executable() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("resolve desktop executable: {error}"))
}

#[tauri::command]
pub async fn install_process_guard() -> Result<(), String> {
    run_elevated("--install-process-guard".to_owned()).await
}

#[tauri::command]
pub async fn start_process_guard() -> Result<(), String> {
    run_elevated("--start-process-guard".to_owned()).await
}

#[tauri::command]
pub async fn apply_process_guard_policy(app: tauri::AppHandle) -> Result<(), String> {
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
    run_elevated(format!("--apply-process-guard-policy \"{path_text}\"")).await
}

#[tauri::command]
pub async fn uninstall_process_guard() -> Result<(), String> {
    run_elevated("--uninstall-process-guard".to_owned()).await
}

async fn run_elevated(arguments: String) -> Result<(), String> {
    let executable = current_executable()?;
    tauri::async_runtime::spawn_blocking(move || request_elevation(&executable, &arguments))
        .await
        .map_err(|error| format!("管理员操作任务失败：{error}"))?
}

#[cfg(all(test, windows))]
mod tests {
    #[test]
    #[ignore = "launches an elevated harmless cmd.exe fixture; run explicitly"]
    fn elevated_exit_code_is_checked() {
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32\\cmd.exe");
        assert!(super::request_elevation(&executable, "/d /c exit 0").is_ok());
        let error = super::request_elevation(&executable, "/d /c exit 7").unwrap_err();
        assert!(error.contains("退出码 7"), "{error}");
    }
}
