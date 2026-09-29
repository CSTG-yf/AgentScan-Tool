use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[tauri::command]
pub fn select_export_directory(title: Option<String>) -> Result<Option<String>, String> {
    let title = title
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("选择导出文件夹");
    choose_directory(title)
        .map(|directory| directory.map(|path| path.to_string_lossy().into_owned()))
}

#[tauri::command]
pub fn export_text_file_to_directory(
    directory: String,
    content: String,
    default_file_name: Option<String>,
) -> Result<String, String> {
    write_text_export(
        &directory,
        default_file_name.as_deref().unwrap_or("export.txt"),
        &content,
        &["md", "txt", "json", "csv"],
    )
}

pub(crate) fn write_text_export(
    directory: &str,
    default_file_name: &str,
    content: &str,
    allowed_extensions: &[&str],
) -> Result<String, String> {
    // create_new makes the no-overwrite guarantee atomic even if another
    // process creates the same name after resolve_unique_export_path returns.
    for _ in 0..10_000 {
        let path = resolve_unique_export_path(
            directory,
            default_file_name,
            "export.txt",
            allowed_extensions,
        )?;
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if let Err(error) = file
                    .write_all(content.as_bytes())
                    .and_then(|_| file.sync_all())
                {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(format!("写入导出文件“{}”失败：{error}", path.display()));
                }
                return Ok(path.to_string_lossy().into_owned());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("创建导出文件“{}”失败：{error}", path.display())),
        }
    }
    Err(format!("导出目录“{directory}”中存在过多同名文件"))
}

pub(crate) fn copy_file_export(
    directory: &str,
    default_file_name: &str,
    source: &Path,
    allowed_extensions: &[&str],
) -> Result<String, String> {
    for _ in 0..10_000 {
        let path = resolve_unique_export_path(
            directory,
            default_file_name,
            "export.pdf",
            allowed_extensions,
        )?;
        let mut target = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("创建导出文件“{}”失败：{error}", path.display())),
        };
        let copy_result = fs::File::open(source)
            .and_then(|mut source_file| std::io::copy(&mut source_file, &mut target))
            .and_then(|_| target.sync_all());
        if let Err(error) = copy_result {
            drop(target);
            let _ = fs::remove_file(&path);
            return Err(format!("写入导出文件“{}”失败：{error}", path.display()));
        }
        return Ok(path.to_string_lossy().into_owned());
    }
    Err(format!("导出目录“{directory}”中存在过多同名文件"))
}

pub(crate) fn resolve_unique_export_path(
    directory: &str,
    default_file_name: &str,
    fallback_file_name: &str,
    allowed_extensions: &[&str],
) -> Result<PathBuf, String> {
    let directory = directory.trim();
    if directory.is_empty() {
        return Err("导出目录不能为空".to_owned());
    }

    let directory_path = PathBuf::from(directory);
    let metadata = fs::metadata(&directory_path)
        .map_err(|error| format!("导出目录“{}”不可用：{error}", directory_path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("导出路径“{}”不是文件夹", directory_path.display()));
    }

    let file_name = safe_file_name(default_file_name, fallback_file_name, allowed_extensions)?;
    let candidate = directory_path.join(&file_name);
    if !candidate.exists() {
        return Ok(candidate);
    }

    let file_path = Path::new(&file_name);
    let stem = file_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("export");
    let extension = file_path.extension().and_then(|value| value.to_str());
    for suffix in 1..10_000 {
        let next_name = match extension {
            Some(extension) => format!("{stem}-{suffix}.{extension}"),
            None => format!("{stem}-{suffix}"),
        };
        let next = directory_path.join(next_name);
        if !next.exists() {
            return Ok(next);
        }
    }
    Err(format!(
        "无法在导出目录“{}”中生成不重复的文件名",
        directory_path.display()
    ))
}

fn safe_file_name(
    input: &str,
    fallback_file_name: &str,
    allowed_extensions: &[&str],
) -> Result<String, String> {
    // Split on both separator styles so a filename supplied on one platform
    // cannot become a nested path on the other platform.
    let leaf = input.trim().rsplit(['/', '\\']).next().unwrap_or("").trim();
    let mut name = leaf
        .chars()
        .map(|character| match character {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            value if value.is_control() => '_',
            value => value,
        })
        .collect::<String>();
    name = name.trim().trim_matches(['.', ' ']).to_owned();
    if name.is_empty() || name == "." || name == ".." {
        name = fallback_file_name.to_owned();
    }

    let extension = Path::new(&name)
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    if !allowed_extensions.is_empty()
        && !extension
            .as_deref()
            .is_some_and(|value| allowed_extensions.iter().any(|allowed| value == *allowed))
    {
        return Err(format!(
            "不支持导出文件扩展名，仅允许：{}",
            allowed_extensions.join("、")
        ));
    }

    let stem = Path::new(&name)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_uppercase();
    let windows_reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    if windows_reserved {
        name.insert(0, '_');
    }

    if name.chars().count() > 180 {
        let path = Path::new(&name);
        let extension = path
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let stem = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("export");
        let shortened = stem.chars().take(160).collect::<String>();
        name = if extension.is_empty() {
            shortened
        } else {
            format!("{shortened}.{extension}")
        };
    }
    Ok(name)
}

#[cfg(windows)]
fn choose_directory(title: &str) -> Result<Option<PathBuf>, String> {
    let title = title.replace('\'', "''");
    let script = format!(
        r#"
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.FolderBrowserDialog
$dialog.Description = '{title}'
$dialog.ShowNewFolderButton = $true
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{
  Write-Output $dialog.SelectedPath
}}
"#
    );
    let output = quiet_command("powershell.exe")
        .args([
            "-NoProfile",
            "-STA",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .map_err(|error| format!("打开文件夹选择窗口失败：{error}"))?;
    if !output.status.success() {
        return Err(format!(
            "文件夹选择窗口启动失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    selected_directory(&output.stdout)
}

#[cfg(target_os = "linux")]
fn choose_directory(title: &str) -> Result<Option<PathBuf>, String> {
    use gtk::prelude::*;

    let dialog = gtk::FileChooserNative::new(
        Some(title),
        None::<&gtk::Window>,
        gtk::FileChooserAction::SelectFolder,
        Some("选择"),
        Some("取消"),
    );
    let response = dialog.run();
    let selected = if response == gtk::ResponseType::Accept {
        dialog.filename()
    } else {
        None
    };
    dialog.destroy();
    match selected {
        Some(path) => validate_selected_directory(path).map(Some),
        None => Ok(None),
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn choose_directory(_title: &str) -> Result<Option<PathBuf>, String> {
    Err("当前平台暂不支持选择导出文件夹".to_owned())
}

#[cfg(windows)]
fn selected_directory(stdout: &[u8]) -> Result<Option<PathBuf>, String> {
    let selected = String::from_utf8_lossy(stdout).trim().to_owned();
    if selected.is_empty() {
        return Ok(None);
    }
    validate_selected_directory(PathBuf::from(selected)).map(Some)
}

fn validate_selected_directory(path: PathBuf) -> Result<PathBuf, String> {
    let metadata = fs::metadata(&path)
        .map_err(|error| format!("所选导出目录“{}”不可用：{error}", path.display()))?;
    if !metadata.is_dir() {
        return Err(format!("所选导出路径“{}”不是文件夹", path.display()));
    }
    Ok(path)
}

#[cfg(windows)]
fn quiet_command(program: &str) -> Command {
    let mut command = Command::new(program);
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_file_name_removes_paths_and_invalid_characters() {
        assert_eq!(
            safe_file_name("../folder\\bad:name?.json", "export.json", &["json"]).unwrap(),
            "bad_name_.json"
        );
    }

    #[test]
    fn safe_file_name_rejects_unexpected_extensions() {
        assert!(safe_file_name("report.exe", "report.pdf", &["pdf"]).is_err());
    }

    #[test]
    fn unique_path_adds_numeric_suffix() {
        let directory = std::env::temp_dir().join(format!(
            "defenseclaw-export-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("report.pdf"), b"existing").unwrap();
        let path = resolve_unique_export_path(
            directory.to_str().unwrap(),
            "report.pdf",
            "report.pdf",
            &["pdf"],
        )
        .unwrap();
        assert_eq!(
            path.file_name().and_then(|value| value.to_str()),
            Some("report-1.pdf")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn copy_file_export_never_overwrites_existing_file() {
        let directory = std::env::temp_dir().join(format!(
            "defenseclaw-export-copy-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("report.pdf"), b"keep").unwrap();
        let source = directory.join("source.tmp");
        fs::write(&source, b"new report").unwrap();

        let exported =
            copy_file_export(directory.to_str().unwrap(), "report.pdf", &source, &["pdf"]).unwrap();

        assert_eq!(fs::read(directory.join("report.pdf")).unwrap(), b"keep");
        assert_eq!(fs::read(exported).unwrap(), b"new report");
        fs::remove_dir_all(directory).unwrap();
    }
}
