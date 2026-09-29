//! Reuse a Windows Chromium browser when WSL has no native PDF renderer.
//! Reports stay local: stage in Windows TEMP, then copy the PDF back to Linux.
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// No report contents or user-supplied paths are interpolated into this script.
const DISCOVER_WINDOWS_BROWSER: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$browser = $null
foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:LOCALAPPDATA)) {
  if (-not $base) { continue }
  foreach ($relative in @('Microsoft\Edge\Application\msedge.exe', 'Google\Chrome\Application\chrome.exe')) {
    $candidate = Join-Path $base $relative
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $browser = $candidate; break }
  }
  if ($browser) { break }
}
if (-not $browser) { exit 3 }
[Console]::WriteLine($browser)
[Console]::WriteLine([System.IO.Path]::GetTempPath())
"#;

fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    // Discovery produces only two paths. Read pipes concurrently so failures
    // cannot deadlock a child that writes more than a pipe buffer.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("启动 PDF 辅助程序失败：{error}"))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let read = |mut stream: Box<dyn Read + Send>| {
        thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = stream.read_to_end(&mut bytes);
            bytes
        })
    };
    let out = read(Box::new(stdout));
    let err = read(Box::new(stderr));
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return Ok(std::process::Output {
                    status,
                    stdout: out.join().unwrap_or_default(),
                    stderr: err.join().unwrap_or_default(),
                })
            }
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(100)),
            state => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match state {
                    Err(error) => format!("检查 PDF 辅助程序失败：{error}"),
                    _ => "PDF 辅助程序执行超时，请检查 WSL Windows 互操作是否可用".to_owned(),
                });
            }
        }
    }
}

fn translate_path(flag: &str, path: &Path) -> Result<PathBuf, String> {
    let mut command = Command::new("wslpath");
    command.args([flag, "-a"]).arg(path);
    let output = run_with_timeout(command, Duration::from_secs(10))?;
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| "wslpath 返回了无效的路径编码".to_owned())?
        .trim_end_matches(['\r', '\n']);
    if !output.status.success() || value.is_empty() || value.contains(['\0', '\r', '\n']) {
        return Err(format!("无法转换 PDF 临时路径：{}", path.display()));
    }
    Ok(PathBuf::from(value))
}

fn windows_file_url(path: &str) -> String {
    let raw = path.replace('\\', "/");
    let mut encoded = String::new();
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b':' | b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    if raw.starts_with("//") {
        format!("file:{encoded}")
    } else {
        format!("file:///{encoded}")
    }
}

fn complete_pdf(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut header = [0; 5];
    if file.read_exact(&mut header).is_err() || &header != b"%PDF-" {
        return false;
    }
    let len = file.metadata().map(|value| value.len()).unwrap_or(0);
    if file
        .seek(SeekFrom::Start(len.saturating_sub(1024)))
        .is_err()
    {
        return false;
    }
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).is_ok() && tail.windows(5).any(|value| value == b"%%EOF")
}

struct StagingDirectory(PathBuf);

impl StagingDirectory {
    fn new(parent: &Path) -> Result<Self, String> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = parent.join(format!(
            "defenseclaw-wsl-pdf-{}-{stamp}",
            std::process::id()
        ));
        // Atomic creation: never reuse or clean a pre-existing directory.
        fs::create_dir(&path)
            .map_err(|error| format!("创建 PDF 临时目录 {} 失败：{error}", path.display()))?;
        Ok(Self(path))
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        // Remove report content even if a browser temporarily holds profile files.
        let _ = fs::remove_file(self.0.join("report.html"));
        let _ = fs::remove_file(self.0.join("report.pdf"));
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wait_for_pdf(
    child: &mut std::process::Child,
    pdf: &Path,
    timeout: Duration,
    exit_grace: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut exited = None;
    let mut previous_pdf_size = None;
    loop {
        if complete_pdf(&pdf) {
            let size = fs::metadata(pdf).map(|value| value.len()).ok();
            if size.is_some() && size == previous_pdf_size {
                break Ok(());
            }
            previous_pdf_size = size;
        } else {
            previous_pdf_size = None;
        }
        if let Some((status, at)) = exited {
            if start.elapsed() >= timeout || Instant::now().duration_since(at) >= exit_grace {
                break Err(format!("Windows 浏览器退出后仍未生成完整 PDF（{status}）"));
            }
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    // The Windows launcher may finish before its renderer writes the PDF.
                    exited = Some((status, Instant::now()));
                } else {
                    break Err(format!("Windows 浏览器生成 PDF 失败（{status}）"));
                }
            }
            Ok(None) if start.elapsed() < timeout => thread::sleep(Duration::from_millis(100)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(match result {
                    Err(error) => format!("检查 PDF 浏览器进程失败：{error}"),
                    _ => "生成 PDF 超时（45 秒），请检查 Windows 浏览器是否可用".to_owned(),
                });
            }
        }
    }
}

pub fn print_html_to_pdf(html_path: &Path, output_path: &Path) -> Result<(), String> {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if std::env::var_os("WSL_DISTRO_NAME").is_none()
        && std::env::var_os("WSL_INTEROP").is_none()
        && !kernel.contains("microsoft")
    {
        return Err("Linux 中未找到 PDF 渲染浏览器。请安装 Google Chrome、Chromium 或 Microsoft Edge，并确保其命令在 PATH 中，然后重新启动桌面程序。".to_owned());
    }
    let mut discover = Command::new("powershell.exe");
    discover.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        DISCOVER_WINDOWS_BROWSER,
    ]);
    let output = run_with_timeout(discover, Duration::from_secs(15))
        .map_err(|error| format!("WSL 无法访问 Windows PDF 浏览器：{error}"))?;
    if !output.status.success() {
        return Err("Linux 中未找到 PDF 浏览器，且无法找到或访问 Windows Edge/Chrome。请确认 Windows 已安装浏览器且 WSL 互操作已启用，或在 Linux 中安装 Chromium/Chrome。".to_owned());
    }
    let text =
        std::str::from_utf8(&output.stdout).map_err(|_| "Windows 浏览器路径编码无效".to_owned())?;
    let paths: Vec<_> = text.lines().filter(|line| !line.is_empty()).collect();
    if paths.len() != 2 {
        return Err("无法解析 Windows 浏览器和临时目录路径".to_owned());
    }
    let browser = translate_path("-u", Path::new(paths[0]))?;
    let parent = translate_path("-u", Path::new(paths[1]))?;
    let staging = StagingDirectory::new(&parent)?;
    let html = staging.0.join("report.html");
    let pdf = staging.0.join("report.pdf");
    fs::copy(html_path, &html).map_err(|error| format!("准备 WSL PDF 报告失败：{error}"))?;
    let windows_dir = translate_path("-w", &staging.0)?
        .to_string_lossy()
        .into_owned();
    let source = windows_file_url(&format!("{windows_dir}\\report.html"));
    let browser_log = staging.0.join("browser.log");
    let log = fs::File::create(&browser_log)
        .map_err(|error| format!("创建 PDF 诊断日志失败：{error}"))?;
    let stdout_log = log
        .try_clone()
        .map_err(|error| format!("准备 PDF 诊断日志失败：{error}"))?;
    let mut command = Command::new(browser);
    command
        .args([
            "--headless=new",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--no-first-run",
            "--no-default-browser-check",
            "--run-all-compositor-stages-before-draw",
            "--virtual-time-budget=1000",
            "--no-pdf-header-footer",
        ])
        .arg(format!("--user-data-dir={windows_dir}\\profile"))
        .arg(format!("--print-to-pdf={windows_dir}\\report.pdf"))
        .arg(source)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(log));
    let mut child = command
        .spawn()
        .map_err(|error| format!("启动 Windows PDF 浏览器失败：{error}"))?;
    let render_result = wait_for_pdf(
        &mut child,
        &pdf,
        Duration::from_secs(45),
        Duration::from_secs(10),
    );
    if let Err(error) = render_result {
        let diagnostic = fs::read_to_string(&browser_log).unwrap_or_default();
        let diagnostic = diagnostic
            .chars()
            .rev()
            .take(2000)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        return Err(format!("{error}。浏览器诊断：{}", diagnostic.trim()));
    }
    let copied = fs::copy(&pdf, output_path).map_err(|error| {
        format!(
            "将 PDF 写回 Linux 路径 {} 失败：{error}",
            output_path.display()
        )
    });
    // Keep the private profile alive until the launcher finishes shutting down.
    thread::spawn(move || {
        let _ = child.wait();
        drop(staging);
    });
    copied?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_for_delayed_pdf_after_successful_launcher_exit() {
        let stage = StagingDirectory::new(&std::env::temp_dir()).unwrap();
        let pdf = stage.0.join("report.pdf");
        let target = pdf.clone();
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(250));
            fs::write(target, b"%PDF-1.7\nfixture\n%%EOF\n").unwrap();
        });
        let mut child = Command::new("/bin/true").spawn().unwrap();
        assert!(wait_for_pdf(
            &mut child,
            &pdf,
            Duration::from_secs(2),
            Duration::from_secs(1)
        )
        .is_ok());
        writer.join().unwrap();
    }

    #[test]
    fn exit_zero_without_a_pdf_is_still_an_error() {
        let stage = StagingDirectory::new(&std::env::temp_dir()).unwrap();
        let mut child = Command::new("/bin/true").spawn().unwrap();
        assert!(wait_for_pdf(
            &mut child,
            &stage.0.join("missing.pdf"),
            Duration::from_secs(1),
            Duration::from_millis(50)
        )
        .is_err());
    }

    #[test]
    fn file_urls_escape_spaces_unicode_and_url_delimiters() {
        assert_eq!(
            windows_file_url(r"C:\some folder\报告#1%.html"),
            "file:///C:/some%20folder/%E6%8A%A5%E5%91%8A%231%25.html"
        );
        assert_eq!(
            windows_file_url(r"\\host\share\report.html"),
            "file://host/share/report.html"
        );
    }

    #[test]
    fn staging_is_unique_and_cleaned_and_incomplete_pdf_rejected() {
        let first = StagingDirectory::new(&std::env::temp_dir()).unwrap();
        let second = StagingDirectory::new(&std::env::temp_dir()).unwrap();
        assert_ne!(first.0, second.0);
        let pdf = first.0.join("report.pdf");
        fs::write(&pdf, b"%PDF-1.7\nincomplete").unwrap();
        assert!(!complete_pdf(&pdf));
        fs::write(&pdf, b"%PDF-1.7\nfixture\n%%EOF\n").unwrap();
        assert!(complete_pdf(&pdf));
        let path = first.0.clone();
        drop(first);
        assert!(!path.exists());
    }

    #[test]
    #[ignore = "requires WSL interop and Windows Edge/Chrome; writes only into a temporary directory"]
    fn wsl_browser_renders_real_pdf() {
        let stage = StagingDirectory::new(&std::env::temp_dir()).unwrap();
        let html = stage.0.join("report.html");
        let pdf = stage.0.join("report.pdf");
        fs::write(&html, "<!doctype html><meta charset=utf-8><h1>Linux PDF 导出验证</h1><p>中文 / spaces / # &amp; %</p>").unwrap();
        print_html_to_pdf(&html, &pdf).unwrap();
        assert!(complete_pdf(&pdf));
    }
}
