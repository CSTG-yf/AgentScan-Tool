use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use crate::models::{AgentConfigRoot, AgentInventory, AgentProcess, AgentSnapshot};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentListQuery {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub query: Option<String>,
    pub runtime_status: Option<String>,
    pub sort: Option<String>,
}

#[tauri::command]
pub fn get_agents(app: tauri::AppHandle, query: Option<AgentListQuery>) -> AgentSnapshot {
    let path = agent_list_path(query.as_ref());
    match crate::commands::gateway_api::get_json::<AgentSnapshot>(&app, &path) {
        Ok(snapshot) => snapshot,
        Err(error) => AgentSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            agents: Vec::new(),
            processes: Vec::new(),
            warning: Some(format!(
                "Go Gateway 暂不可用，Agent Inventory 只能由 Go 后端提供：{error}"
            )),
        },
    }
}

#[tauri::command]
pub fn get_agent_detail(app: tauri::AppHandle, agent_id: String) -> Result<AgentInventory, String> {
    let agent_id = agent_id.trim();
    if agent_id.is_empty() {
        return Err("agent_id is required".to_string());
    }
    crate::commands::gateway_api::get_json::<AgentInventory>(
        &app,
        &format!("/api/v1/agents/{}", escape_path_segment(agent_id)),
    )
}

#[tauri::command]
pub fn export_agents_report_pdf(
    agents: Vec<AgentInventory>,
    default_file_name: Option<String>,
) -> Result<Option<String>, String> {
    let file_name = safe_pdf_file_name(default_file_name.as_deref().unwrap_or("agents-report.pdf"));
    let Some(output_path) = choose_pdf_output_path(&file_name)? else {
        return Ok(None);
    };

    let temp_dir = env::temp_dir().join(format!(
        "defenseclaw-agent-report-{}",
        Utc::now().timestamp_millis()
    ));
    fs::create_dir_all(&temp_dir).map_err(|err| format!("创建临时目录失败：{err}"))?;
    let html_path = temp_dir.join("report.html");
    fs::write(&html_path, build_agents_report_html(&agents))
        .map_err(|err| format!("写入临时报告失败：{err}"))?;

    let print_result = print_html_to_pdf(&html_path, &output_path);
    let _ = fs::remove_file(&html_path);
    let _ = fs::remove_dir_all(&temp_dir);
    print_result?;

    Ok(Some(output_path.to_string_lossy().to_string()))
}

fn agent_list_path(query: Option<&AgentListQuery>) -> String {
    let mut pairs = vec![("page_size".to_string(), "600".to_string())];
    if let Some(query) = query {
        if let Some(page) = query.page.filter(|value| *value > 0) {
            pairs.push(("page".to_string(), page.to_string()));
        }
        if let Some(page_size) = query.page_size.filter(|value| *value > 0) {
            pairs.retain(|(key, _)| key != "page_size");
            pairs.push(("page_size".to_string(), page_size.to_string()));
        }
        if let Some(value) = query
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            pairs.push(("query".to_string(), value.to_string()));
        }
        if let Some(value) = query
            .runtime_status
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "all")
        {
            pairs.push(("runtimeStatus".to_string(), value.to_string()));
        }
        if let Some(value) = query
            .sort
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            pairs.push(("sort".to_string(), value.to_string()));
        }
    }
    let query = pairs
        .into_iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                escape_query_component(&key),
                escape_query_component(&value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("/api/v1/agents?{query}")
}

fn choose_pdf_output_path(default_file_name: &str) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        let file_name = default_file_name.replace('\'', "''");
        let script = format!(
            r#"
$OutputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.SaveFileDialog
$dialog.Title = '导出 Agent PDF 报告'
$dialog.Filter = 'PDF 文件 (*.pdf)|*.pdf'
$dialog.DefaultExt = 'pdf'
$dialog.AddExtension = $true
$dialog.OverwritePrompt = $true
$dialog.FileName = '{file_name}'
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {{
  Write-Output $dialog.FileName
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
            .map_err(|err| format!("打开保存对话框失败：{err}"))?;
        if !output.status.success() {
            return Err(format!(
                "保存对话框失败：{}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let selected = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if selected.is_empty() {
            return Ok(None);
        }
        let mut path = PathBuf::from(selected);
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .is_empty()
        {
            path.set_extension("pdf");
        }
        return Ok(Some(path));
    }

    #[cfg(not(windows))]
    {
        let mut path = env::current_dir().map_err(|err| format!("读取当前目录失败：{err}"))?;
        path.push(default_file_name);
        Ok(Some(path))
    }
}

fn print_html_to_pdf(html_path: &Path, output_path: &Path) -> Result<(), String> {
    let browser = find_pdf_browser().ok_or_else(|| {
        "未找到 Microsoft Edge 或 Chrome，无法将 Agent 报告导出为 PDF".to_string()
    })?;
    let profile_dir = env::temp_dir().join(format!(
        "defenseclaw-agent-report-profile-{}",
        Utc::now().timestamp_millis()
    ));
    fs::create_dir_all(&profile_dir).map_err(|err| format!("创建浏览器临时目录失败：{err}"))?;
    let target = output_path.to_string_lossy().to_string();
    let source = file_url(html_path);

    let mut last_error = String::new();
    for headless_flag in ["--headless=new", "--headless"] {
        let output = quiet_command(&browser)
            .arg(headless_flag)
            .arg("--disable-gpu")
            .arg("--no-first-run")
            .arg(format!("--user-data-dir={}", profile_dir.to_string_lossy()))
            .arg(format!("--print-to-pdf={target}"))
            .arg(&source)
            .output()
            .map_err(|err| format!("调用浏览器导出 PDF 失败：{err}"))?;

        if output.status.success()
            && output_path.exists()
            && output_path
                .metadata()
                .map(|meta| meta.len() > 0)
                .unwrap_or(false)
        {
            let _ = fs::remove_dir_all(&profile_dir);
            return Ok(());
        }
        last_error = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }

    let _ = fs::remove_dir_all(&profile_dir);
    Err(format!(
        "浏览器生成 PDF 失败{}",
        if last_error.is_empty() {
            "".to_string()
        } else {
            format!("：{last_error}")
        }
    ))
}

fn find_pdf_browser() -> Option<String> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    for env_key in ["ProgramFiles", "ProgramFiles(x86)", "LocalAppData"] {
        if let Some(base) = env::var_os(env_key) {
            let base = PathBuf::from(base);
            candidates.push(base.join("Microsoft\\Edge\\Application\\msedge.exe"));
            candidates.push(base.join("Google\\Chrome\\Application\\chrome.exe"));
        }
    }
    for candidate in candidates {
        if candidate.exists() {
            return Some(candidate.to_string_lossy().to_string());
        }
    }
    for name in ["msedge.exe", "chrome.exe"] {
        if quiet_command("where.exe")
            .arg(name)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return Some(name.to_string());
        }
    }
    None
}

fn build_agents_report_html(agents: &[AgentInventory]) -> String {
    let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    let running = agents
        .iter()
        .filter(|agent| agent_runtime_status(agent) == "running")
        .count();
    let stopped = agents
        .iter()
        .filter(|agent| agent_runtime_status(agent) == "stopped")
        .count();
    let unknown = agents.len().saturating_sub(running + stopped);

    let mut html = String::from(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Agent 报告</title>
<style>
@page { size: A4; margin: 15mm 13mm; }
* { box-sizing: border-box; }
body { margin: 0; color: #172033; font: 13px/1.55 "Microsoft YaHei", "SimSun", Arial, sans-serif; background: #fff; }
h1 { margin: 0 0 6px; font-size: 24px; }
h2 { margin: 0 0 10px; font-size: 17px; break-after: avoid; }
.muted { color: #667085; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 16px 0 18px; }
.metric { padding: 10px 12px; border: 1px solid #dfe5ef; border-radius: 6px; background: #f8fafc; }
.metric strong { display: block; margin-top: 4px; font-size: 20px; }
.agent { break-inside: avoid; margin: 0 0 14px; padding: 14px; border: 1px solid #dfe5ef; border-radius: 7px; }
table { width: 100%; border-collapse: collapse; }
td { vertical-align: top; padding: 7px 8px; border-top: 1px solid #edf1f7; }
td:first-child { width: 26%; color: #475467; background: #fbfcfe; }
.code { font-family: "Cascadia Code", Consolas, monospace; word-break: break-all; }
.pill { display: inline-block; padding: 1px 7px; margin: 0 4px 4px 0; border-radius: 999px; background: #edf4ff; color: #164ea6; }
.block { margin-top: 10px; }
</style>
</head>
<body>
"#,
    );
    html.push_str("<h1>Agent 详情报告</h1>");
    html.push_str(&format!(
        r#"<div class="muted">生成时间：{} · Agent 数量：{}</div>"#,
        html_escape(&generated_at),
        agents.len()
    ));
    html.push_str(&format!(
        r#"<section class="summary"><div class="metric">总数<strong>{}</strong></div><div class="metric">运行中<strong>{}</strong></div><div class="metric">未运行<strong>{}</strong></div><div class="metric">未知<strong>{}</strong></div></section>"#,
        agents.len(),
        running,
        stopped,
        unknown
    ));

    for agent in agents {
        let name = agent_name(agent);
        html.push_str(r#"<section class="agent">"#);
        html.push_str(&format!("<h2>{}</h2>", html_escape(&name)));
        html.push_str("<table>");
        html_row(
            &mut html,
            "Agent 信息",
            &format!(
                "{} / {} / {}",
                name,
                value_or_dash(&agent.vendor),
                value_or_dash(&agent_primary_path(agent))
            ),
        );
        html_row(
            &mut html,
            "状态",
            &format!(
                "{} / PID {}",
                runtime_status_label(&agent_runtime_status(agent)),
                format_pids(agent)
            ),
        );
        html_row(&mut html, "类型", &value_or_dash(&agent.kind));
        html_row(&mut html, "版本", &value_or_dash(&agent.version));
        html_row(&mut html, "发现状态", &discovery_status_label(agent));
        html_row(
            &mut html,
            "首次发现",
            &value_or_dash(agent.first_seen_scan_at.as_deref().unwrap_or("")),
        );
        html_row(
            &mut html,
            "最近发现",
            &value_or_dash(agent.last_seen_scan_at.as_deref().unwrap_or("")),
        );
        html_row(
            &mut html,
            "静态资源",
            &format!(
                "{} 个资源 / {} 个风险 / {} 个严重",
                agent.static_resource_count,
                agent.risk_resource_count,
                agent.critical_resource_count
            ),
        );
        html_row(
            &mut html,
            "运行检测",
            &format!(
                "{} 个检测 / {} 个攻击 / {} 个阻断 / {} 个高危以上",
                agent.runtime_detection_count.unwrap_or(0),
                agent.runtime_attack_count.unwrap_or(0),
                agent.runtime_blocked_count.unwrap_or(0),
                agent.runtime_high_or_above_count.unwrap_or(0),
            ),
        );
        html_row(&mut html, "数据来源", &value_or_dash(&agent.source));
        html_row(&mut html, "说明", &value_or_dash(&agent.description));
        html.push_str("</table>");
        append_string_list(
            &mut html,
            "配置位置",
            agent.config_roots.iter().map(config_root_text).collect(),
        );
        append_string_list(&mut html, "安装位置", agent.install_paths.clone());
        append_string_list(&mut html, "可执行文件", agent.executable_names.clone());
        append_processes(&mut html, &agent.processes);
        html.push_str("</section>");
    }
    html.push_str("</body></html>");
    html
}

fn html_row(html: &mut String, label: &str, value: &str) {
    html.push_str("<tr><td>");
    html.push_str(&html_escape(label));
    html.push_str("</td><td>");
    html.push_str(&html_escape(value));
    html.push_str("</td></tr>");
}

fn append_string_list(html: &mut String, title: &str, values: Vec<String>) {
    let values: Vec<String> = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if values.is_empty() {
        return;
    }
    html.push_str(&format!(
        r#"<div class="block"><strong>{}</strong><div>"#,
        html_escape(title)
    ));
    for value in values {
        html.push_str(&format!(
            r#"<span class="pill code">{}</span>"#,
            html_escape(&value)
        ));
    }
    html.push_str("</div></div>");
}

fn append_processes(html: &mut String, processes: &[AgentProcess]) {
    if processes.is_empty() {
        return;
    }
    html.push_str(r#"<div class="block"><strong>进程</strong><table>"#);
    html.push_str("<tr><td>PID</td><td>名称</td><td>启动时间</td></tr>");
    for process in processes {
        html.push_str("<tr><td>");
        html.push_str(&process.pid.to_string());
        html.push_str("</td><td>");
        html.push_str(&html_escape(&process.name));
        html.push_str("</td><td>");
        html.push_str(&html_escape(process.started_at.as_deref().unwrap_or("-")));
        html.push_str("</td></tr>");
    }
    html.push_str("</table></div>");
}

fn config_root_text(root: &AgentConfigRoot) -> String {
    format!(
        "{}: {}{}",
        value_or_dash(&root.kind),
        value_or_dash(&root.path),
        if root.exists { "" } else { " (不存在)" }
    )
}

fn agent_name(agent: &AgentInventory) -> String {
    first_non_empty([agent.product.as_str(), agent.id.as_str()].as_slice())
        .unwrap_or("未知 Agent")
        .to_string()
}

fn agent_primary_path(agent: &AgentInventory) -> String {
    if !agent.primary_path.trim().is_empty() {
        return agent.primary_path.trim().to_string();
    }
    if let Some(root) = agent
        .config_roots
        .iter()
        .find(|root| !root.path.trim().is_empty())
    {
        return root.path.trim().to_string();
    }
    if let Some(path) = agent
        .install_paths
        .iter()
        .find(|path| !path.trim().is_empty())
    {
        return path.trim().to_string();
    }
    agent.source.trim().to_string()
}

fn agent_runtime_status(agent: &AgentInventory) -> String {
    let status = first_non_empty([agent.runtime_status.as_str(), agent.status.as_str()].as_slice())
        .unwrap_or("");
    match status.trim().to_ascii_lowercase().as_str() {
        "running" => "running".to_string(),
        "stopped" | "installed" | "missing" => "stopped".to_string(),
        "unknown" => "unknown".to_string(),
        _ if agent.running || !agent.pids.is_empty() => "running".to_string(),
        _ => "unknown".to_string(),
    }
}

fn runtime_status_label(status: &str) -> &'static str {
    match status {
        "running" => "运行中",
        "stopped" => "未运行",
        _ => "未知",
    }
}

fn discovery_status_label(agent: &AgentInventory) -> String {
    let value = first_non_empty(
        [
            agent.discovery_status.as_str(),
            agent.inventory_state.as_deref().unwrap_or(""),
        ]
        .as_slice(),
    )
    .unwrap_or("unknown");
    match value.trim().to_ascii_lowercase().as_str() {
        "running" => "已识别 / 运行中".to_string(),
        "installed" | "discovered" => "已识别".to_string(),
        "runtime_observed" => "运行时观测".to_string(),
        "missing" => "曾发现 / 当前缺失".to_string(),
        _ => value.to_string(),
    }
}

fn format_pids(agent: &AgentInventory) -> String {
    if agent.pids.is_empty() {
        "-".to_string()
    } else {
        agent
            .pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn value_or_dash(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "-".to_string()
    } else {
        value.to_string()
    }
}

fn first_non_empty<'a>(values: &[&'a str]) -> Option<&'a str> {
    values
        .iter()
        .copied()
        .find(|value| !value.trim().is_empty())
}

fn html_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn safe_pdf_file_name(input: &str) -> String {
    let mut name = input
        .chars()
        .map(|ch| match ch {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '-',
            ch if ch.is_control() => '-',
            ch => ch,
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_string();
    if name.is_empty() {
        name = "agents-report".to_string();
    }
    if !name.to_ascii_lowercase().ends_with(".pdf") {
        name.push_str(".pdf");
    }
    name
}

fn file_url(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    format!("file:///{}", raw.replace(' ', "%20"))
}

fn escape_path_segment(value: &str) -> String {
    escape_percent(value, false)
}

fn escape_query_component(value: &str) -> String {
    escape_percent(value, false)
}

fn escape_percent(value: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        let b = *byte;
        let keep = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && b == b'/');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn quiet_command(program: &str) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}
