use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
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
            total: 0,
            warning: Some(format!(
                "Go Gateway 暂不可用，Agent Inventory 只能由 Go 后端提供：{error}"
            )),
        },
    }
}

/// Start an explicit backend Agent discovery job. Reads stay side-effect
/// free; the returned scan_id is polled by the desktop before refreshing.
#[tauri::command]
pub fn trigger_agent_scan(
    app: tauri::AppHandle,
    mode: Option<String>,
    idempotency_key: Option<String>,
) -> Result<serde_json::Value, String> {
    crate::commands::gateway_api::post_json::<serde_json::Value, _>(
        &app,
        "/api/v1/scans/agents",
        &serde_json::json!({"mode": mode.unwrap_or_else(|| "full".to_owned()), "idempotency_key": idempotency_key}),
    )
    .map_err(|error| format!("触发 Agent 发现扫描失败：{error}"))
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
pub async fn export_agents_report_pdf(
    agents: Vec<AgentInventory>,
    default_file_name: Option<String>,
    directory: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        export_agents_report_pdf_impl(agents, default_file_name, directory)
    })
    .await
    .map_err(|error| format!("PDF 导出任务失败：{error}"))?
}

fn export_agents_report_pdf_impl(
    agents: Vec<AgentInventory>,
    default_file_name: Option<String>,
    directory: String,
) -> Result<String, String> {
    // Validate the selected directory and filename before generating the PDF.
    crate::commands::report_export::resolve_unique_export_path(
        &directory,
        default_file_name.as_deref().unwrap_or("agents-report.pdf"),
        "agents-report.pdf",
        &["pdf"],
    )?;

    let temp_dir = create_report_temp_dir("agent-report")?;
    let html_path = temp_dir.join("report.html");
    let pdf_path = temp_dir.join("report.pdf");
    fs::write(&html_path, build_agents_report_html(&agents))
        .map_err(|err| format!("写入临时报告失败：{err}"))?;

    let print_result = print_html_to_pdf(&html_path, &pdf_path)
        .map_err(|error| format!("无法生成导出到“{directory}”的 PDF：{error}"));
    let export_result = print_result.and_then(|_| {
        crate::commands::report_export::copy_file_export(
            &directory,
            default_file_name.as_deref().unwrap_or("agents-report.pdf"),
            &pdf_path,
            &["pdf"],
        )
    });
    let _ = fs::remove_dir_all(&temp_dir);
    export_result
}

/// Export a pre-rendered, self-contained report from a desktop page. The HTML
/// is produced by trusted application code and printed through the same local
/// Edge/Chrome pipeline used by the Agent report.
#[tauri::command]
pub async fn export_page_report_pdf(
    html: String,
    default_file_name: Option<String>,
    directory: String,
) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        export_page_report_pdf_impl(html, default_file_name, directory)
    })
    .await
    .map_err(|error| format!("PDF 导出任务失败：{error}"))?
}

fn export_page_report_pdf_impl(
    html: String,
    default_file_name: Option<String>,
    directory: String,
) -> Result<String, String> {
    if html.trim().is_empty() {
        return Err("导出内容不能为空".to_owned());
    }
    crate::commands::report_export::resolve_unique_export_path(
        &directory,
        default_file_name
            .as_deref()
            .unwrap_or("runtime-detections-report.pdf"),
        "runtime-detections-report.pdf",
        &["pdf"],
    )?;

    let temp_dir = create_report_temp_dir("page-report")?;
    let html_path = temp_dir.join("report.html");
    let pdf_path = temp_dir.join("report.pdf");
    fs::write(&html_path, html).map_err(|err| format!("写入临时报告失败：{err}"))?;

    let print_result = print_html_to_pdf(&html_path, &pdf_path)
        .map_err(|error| format!("无法生成导出到“{directory}”的 PDF：{error}"));
    let export_result = print_result.and_then(|_| {
        crate::commands::report_export::copy_file_export(
            &directory,
            default_file_name
                .as_deref()
                .unwrap_or("runtime-detections-report.pdf"),
            &pdf_path,
            &["pdf"],
        )
    });
    let _ = fs::remove_dir_all(&temp_dir);
    export_result
}

fn agent_list_path(query: Option<&AgentListQuery>) -> String {
    let mut pairs = vec![("page_size".to_string(), "5000".to_string())];
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

fn create_report_temp_dir(kind: &str) -> Result<PathBuf, String> {
    static NEXT_REPORT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let id = NEXT_REPORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = env::temp_dir().join(format!(
        "defenseclaw-{kind}-{}-{}-{id}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir(&path).map_err(|error| format!("创建报告临时目录失败：{error}"))?;
    Ok(path)
}

fn print_html_to_pdf(html_path: &Path, output_path: &Path) -> Result<(), String> {
    let browser = match find_pdf_browser() {
        Some(browser) => browser,
        None => {
            #[cfg(target_os = "linux")]
            return crate::wsl_pdf::print_html_to_pdf(html_path, output_path);
            #[cfg(not(target_os = "linux"))]
            return Err("未找到 Microsoft Edge、Chrome 或 Chromium，请安装浏览器后重试导出 PDF".to_owned());
        }
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("创建导出目录失败：{err}"))?;
    }
    let profile_dir = create_report_temp_dir("report-profile")?;
    let target = output_path.to_string_lossy().to_string();
    let source = file_url(html_path);

    let mut last_error = String::new();
    for headless_flag in ["--headless=new", "--headless"] {
        // The output lives in our private temporary directory, so a failed
        // Chromium attempt can be removed safely before retrying.
        let _ = fs::remove_file(output_path);
        let output = quiet_command(&browser)
            .arg(headless_flag)
            .arg("--disable-gpu")
            .arg("--disable-extensions")
            .arg("--disable-background-networking")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--run-all-compositor-stages-before-draw")
            .arg("--virtual-time-budget=1000")
            .arg("--no-pdf-header-footer")
            .arg(format!("--user-data-dir={}", profile_dir.to_string_lossy()))
            .arg(format!("--print-to-pdf={target}"))
            .arg(&source)
            .output()
            .map_err(|err| format!("调用浏览器导出 PDF 失败：{err}"))?;

        if output.status.success() && wait_for_non_empty_file(output_path, Duration::from_secs(8)) {
            let _ = fs::remove_dir_all(&profile_dir);
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        last_error = [stderr, stdout]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("；");
        if last_error.is_empty() {
            last_error = format!("浏览器退出码：{}", output.status);
        }
    }

    let _ = fs::remove_dir_all(&profile_dir);
    let _ = fs::remove_file(output_path);
    Err(format!(
        "浏览器生成 PDF“{}”失败{}",
        output_path.display(),
        if last_error.is_empty() {
            "".to_string()
        } else {
            format!("：{last_error}")
        }
    ))
}

fn wait_for_non_empty_file(path: &Path, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if path.metadata().map(|meta| meta.len() > 0).unwrap_or(false) {
            return true;
        }
        thread::sleep(Duration::from_millis(150));
    }
    false
}

fn find_pdf_browser() -> Option<String> {
    #[cfg(windows)]
    {
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
    }

    #[cfg(target_os = "linux")]
    {
        for name in [
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
            "microsoft-edge",
            "microsoft-edge-stable",
        ] {
            if Command::new(name)
                .arg("--version")
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
            {
                return Some(name.to_owned());
            }
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

#[cfg(test)]
mod pdf_tests {
    use super::*;

    #[test]
    fn agent_report_preserves_linux_paths_and_escapes_names() {
        let agent: AgentInventory = serde_json::from_value(serde_json::json!({
            "id": "pdf-test-agent",
            "product": "AgentRange / OpsPilot <测试>",
            "vendor": "TraceBastion Lab",
            "kind": "Agent Platform",
            "runtimeStatus": "running",
            "primaryPath": "/home/用户/AgentScan-Tool-linux/task/AgentRange-player",
            "staticResourceCount": 17,
            "riskResourceCount": 2,
            "description": "Linux / WSL PDF 导出验证（测试数据）"
        })).unwrap();
        let html = build_agents_report_html(&[agent]);
        assert!(html.contains("OpsPilot &lt;测试&gt;"));
        assert!(html.contains("/home/用户/AgentScan-Tool-linux/task/AgentRange-player"));
        // Optional artifact for manual rendering QA; normal test runs write nothing.
        if let Some(path) = env::var_os("DEFENSECLAW_TEST_REPORT_HTML") {
            fs::write(path, html).unwrap();
        }
    }
}
