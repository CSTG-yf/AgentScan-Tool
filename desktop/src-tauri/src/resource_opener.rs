//! Linux/WSL folder opening. Kept independent of Tauri for platform tests.
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn resource_directory(path: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        format!(
            "无法访问资源 {}：{error}。文件可能已被删除、移动或隔离。",
            path.display()
        )
    })?;
    let directory = if metadata.is_dir() {
        path
    } else if metadata.is_file() {
        path.parent().unwrap_or_else(|| Path::new("."))
    } else {
        return Err(format!("资源不是普通文件或目录：{}", path.display()));
    };
    // Absolute paths also prevent names starting with '-' being treated as options.
    std::fs::canonicalize(directory)
        .map_err(|error| format!("无法解析资源目录 {}：{error}", directory.display()))
}

fn wsl_kernel(release: &str) -> bool {
    let release = release.to_ascii_lowercase();
    release.contains("microsoft") || release.contains("wsl")
}

fn is_wsl() -> bool {
    std::env::var_os("WSL_DISTRO_NAME").is_some()
        || std::env::var_os("WSL_INTEROP").is_some()
        || std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|release| wsl_kernel(&release))
            .unwrap_or(false)
}

fn converted_windows_path(bytes: &[u8]) -> Result<String, String> {
    let value = std::str::from_utf8(bytes)
        .map_err(|_| "wslpath 返回了无法识别的路径编码".to_owned())?
        .trim_end_matches(['\r', '\n']);
    let drive_path = value.as_bytes().get(1) == Some(&b':')
        && value.as_bytes().get(2) == Some(&b'\\')
        && value.as_bytes()[0].is_ascii_alphabetic();
    if value.is_empty()
        || value.contains(['\r', '\n', '\0'])
        || !(value.starts_with("\\\\") || drive_path)
    {
        return Err("wslpath 未返回有效的 Windows 绝对路径".to_owned());
    }
    Ok(value.to_owned())
}

fn launch(mut command: Command, explorer: bool) -> Result<(), String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("无法启动 {program}：{error}"))?;

    // Catch immediate failures (e.g. xdg-open installed but no file manager).
    // Some managers stay alive until their window is closed; do not wait for that.
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Explorer can return 1 after handing the request to its existing process.
                return if status.success() || (explorer && status.code() == Some(1)) {
                    Ok(())
                } else {
                    Err(format!("{program} 打开目录失败（{status}）"))
                };
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(25));
            }
            result => {
                // Reap long-lived launchers without blocking the desktop command.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                return result
                    .map(|_| ())
                    .map_err(|error| format!("检查 {program} 启动状态失败：{error}"));
            }
        }
    }
}

fn open_wsl_directory(directory: &Path) -> Result<(), String> {
    let output = Command::new("wslpath")
        .args(["-w", "-a"])
        .arg(directory)
        .output()
        .map_err(|error| format!("无法执行 wslpath：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "wslpath 无法转换目录 {}（{}）",
            directory.display(),
            output.status
        ));
    }
    let windows_path = converted_windows_path(&output.stdout)?;
    // Pass paths as a single argument, never through sh/cmd or string interpolation.
    let mut command = Command::new("explorer.exe");
    command.arg(windows_path);
    launch(command, true)
}

pub fn reveal(path: &str) -> Result<(), String> {
    let directory = resource_directory(Path::new(path))?;
    let wsl = is_wsl();
    let mut failures = Vec::new();
    if wsl {
        match open_wsl_directory(&directory) {
            Ok(()) => return Ok(()),
            Err(error) => failures.push(error),
        }
    }
    for program in ["xdg-open", "gio"] {
        let mut command = Command::new(program);
        if program == "gio" {
            command.arg("open");
        }
        command.arg(&directory);
        match launch(command, false) {
            Ok(()) => return Ok(()),
            Err(error) => failures.push(error),
        }
    }
    let hint = if wsl {
        "请确认 WSL 的 Windows 程序互操作已启用，且 PATH 中能找到 explorer.exe；或安装 Linux 文件管理器及 xdg-utils。"
    } else {
        "请确认正在图形桌面会话中运行，并已安装文件管理器及 xdg-utils。"
    };
    Err(format!(
        "无法打开资源目录 {}。{hint}\n{}",
        directory.display(),
        failures.join("；")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_wsl1_and_wsl2_kernels() {
        assert!(wsl_kernel("4.4.0-19041-Microsoft"));
        assert!(wsl_kernel("6.6.87.2-microsoft-standard-WSL2"));
        assert!(!wsl_kernel("6.8.0-ubuntu-generic"));
    }

    #[test]
    fn preserves_windows_paths_with_spaces_and_unicode() {
        for path in [
            r"\\wsl.localhost\Ubuntu-22.04\home\用户\some folder",
            r"C:\Users\用户\some folder",
        ] {
            assert_eq!(
                converted_windows_path(format!("{path}\r\n").as_bytes()).unwrap(),
                path
            );
        }
        for path in ["", "\n", "relative/path", "-option", "C:", "\\\\host\na"] {
            assert!(converted_windows_path(path.as_bytes()).is_err());
        }
        assert!(converted_windows_path(&[0xff]).is_err());
    }

    #[test]
    fn resolves_directories_files_and_missing_resources() {
        let root =
            std::env::temp_dir().join(format!("resource-opener-test-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let file = root.join("中文 spaces & dollar$.txt");
        std::fs::write(&file, "test").unwrap();
        let expected = root.canonicalize().unwrap();
        assert_eq!(resource_directory(&root).unwrap(), expected);
        assert_eq!(resource_directory(&file).unwrap(), expected);
        assert!(resource_directory(&root.join("missing"))
            .unwrap_err()
            .contains("无法访问资源"));
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detects_missing_launchers_and_nonzero_exit() {
        assert!(launch(Command::new("/defenseclaw-nonexistent-opener"), false).is_err());
        assert!(launch(Command::new("/bin/false"), false).is_err());
        assert!(launch(Command::new("/bin/true"), false).is_ok());
    }
}
