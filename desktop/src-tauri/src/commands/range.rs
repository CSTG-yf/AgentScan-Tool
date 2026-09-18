use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::Manager;

use crate::commands::lifecycle::{
    desktop_defenseclaw_home, run_gateway_action, run_gateway_action_for_mode,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

const RANGE_REPLAY_LOG_LIMIT: usize = 160;
const RANGE_REPLAY_WRAPPER: &str = r##"
import importlib.util
import json
import os
import pathlib
import sys
import time
import traceback

CURRENT_SCENARIO = "all"
CURRENT_TOTAL = 0


def emit(completed, total, scenario, status, detail=""):
    completed = int(completed or 0)
    total = int(total or 0)
    print("DEFENSECLAW_PROGRESS " + json.dumps({
        "completed": completed,
        "total": total,
        "remaining": max(total - completed, 0),
        "scenario": scenario or "all",
        "status": status,
        "detail": detail,
    }, ensure_ascii=False), flush=True)


def request_with_retries(runner, client, method, url, scenario, total, detail, attempts=45, **kwargs):
    last_error = None
    for attempt in range(1, attempts + 1):
        try:
            response = client.request(method, url, **kwargs)
            if response.status_code >= 500:
                response.raise_for_status()
            response.raise_for_status()
            return response
        except runner.httpx.HTTPStatusError as exc:
            if exc.response.status_code < 500:
                raise
            last_error = exc
        except runner.httpx.RequestError as exc:
            last_error = exc

        if attempt == 1 or attempt % 5 == 0:
            emit(0, total, scenario, "waiting", f"{detail} not ready ({attempt}/{attempts}): {last_error}")
        time.sleep(1)
    raise last_error


def load_runner(path_text):
    path = pathlib.Path(path_text).resolve()
    spec = importlib.util.spec_from_file_location("agentrange_original_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load runner: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    global CURRENT_SCENARIO, CURRENT_TOTAL
    if len(sys.argv) < 2:
        raise SystemExit("usage: agentrange-runner-progress.py <runner.py> [scenario]")

    runner = load_runner(sys.argv[1])
    runner.OPSPILOT = os.getenv("OPSPILOT_BASE", "http://127.0.0.1:8100").rstrip("/")
    runner.LANGFLOW = os.getenv("LANGFLOW_BASE", "http://127.0.0.1:7860").rstrip("/")
    runner.LLM_STUB = os.getenv("LLM_STUB_BASE", "http://127.0.0.1:8000").rstrip("/")
    os.environ["NO_PROXY"] = "127.0.0.1,localhost,host.docker.internal"
    os.environ["no_proxy"] = "127.0.0.1,localhost,host.docker.internal"
    scenario = sys.argv[2] if len(sys.argv) > 2 else "all"
    CURRENT_SCENARIO = scenario
    only = None if scenario == "all" else scenario
    generated = runner.generate(1337, 5200, 80)
    selected = runner.select_events(generated, only)
    public_events = [runner.public_record(event) for event in selected]
    actions = runner.plan_actions(public_events)
    total = len(actions)
    CURRENT_TOTAL = total

    emit(0, total, scenario, "prepared", "actions prepared")
    with runner.httpx.Client(timeout=15, trust_env=False) as admin_client:
        request_with_retries(
            runner,
            admin_client,
            "POST",
            f"{runner.LLM_STUB}/admin/trajectories",
            scenario,
            total,
            "llm-stub trajectory admin",
            json={"trajectories": runner.trajectory_map(selected)},
        )
    try:
        with runner.httpx.Client(timeout=15, trust_env=False) as client:
            tokens = {}
            langflow_token = None
            for index, action in enumerate(actions, 1):
                if action["target"] == "langflow":
                    langflow_token = langflow_token or runner.fetch_langflow_token(client)
                    runner.fire_cat1(client, action, langflow_token)
                else:
                    runner.fire_opspilot(client, action, tokens)
                emit(index, total, scenario, "running", action.get("instance_id", ""))
    finally:
        with runner.httpx.Client(timeout=15, trust_env=False) as admin_client:
            request_with_retries(
                runner,
                admin_client,
                "DELETE",
                f"{runner.LLM_STUB}/admin/trajectories",
                scenario,
                total,
                "llm-stub trajectory cleanup",
                attempts=5,
            )

    emit(total, total, scenario, "completed", "done")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        emit(0, CURRENT_TOTAL, CURRENT_SCENARIO, "error", str(exc))
        traceback.print_exc()
        raise
"##;

#[derive(Default)]
struct ReplayStateInner {
    running: bool,
    command: String,
    scenario: String,
    started_at: String,
    finished_at: Option<String>,
    pid: Option<u32>,
    completed: u32,
    total: u32,
    remaining: u32,
    exit_code: Option<i32>,
    error: Option<String>,
    log: Vec<String>,
    child: Option<std::process::Child>,
}

static RANGE_REPLAY_STATE: Mutex<Option<Arc<Mutex<ReplayStateInner>>>> = Mutex::new(None);

#[derive(Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct DesktopSettings {
    agentrange_root: String,
    range_mode: RangeMode,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeStatus {
    configured: bool,
    root: String,
    compose_file: String,
    adapter_compose_file: String,
    mode: RangeMode,
    docker_available: bool,
    running_services: Vec<String>,
    state: &'static str,
    detail: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RangeReplayStatus {
    running: bool,
    command: String,
    scenario: String,
    started_at: String,
    finished_at: Option<String>,
    pid: Option<u32>,
    completed: u32,
    total: u32,
    remaining: u32,
    exit_code: Option<i32>,
    error: Option<String>,
    detail: String,
    log: Vec<String>,
}

#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RangeMode {
    #[default]
    Baseline,
    Observe,
    Action,
}

impl RangeMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::Observe => "observe",
            Self::Action => "action",
        }
    }

    fn requires_adapter(self) -> bool {
        !matches!(self, Self::Baseline)
    }
}

fn replay_state() -> Arc<Mutex<ReplayStateInner>> {
    let mut guard = RANGE_REPLAY_STATE
        .lock()
        .expect("range replay state poisoned");
    guard
        .get_or_insert_with(|| Arc::new(Mutex::new(ReplayStateInner::default())))
        .clone()
}

fn replay_status_from(inner: &ReplayStateInner) -> RangeReplayStatus {
    let detail = if inner.running {
        if inner.total > 0 {
            format!(
                "回放进行中：已完成 {} / {} 条事件",
                inner.completed, inner.total
            )
        } else {
            "回放进行中：正在等待 runner 输出进度".to_owned()
        }
    } else if let Some(error) = &inner.error {
        error.clone()
    } else if let Some(code) = inner.exit_code {
        if code == 0 {
            "回放已完成".to_owned()
        } else {
            format!("回放已退出，退出码 {code}")
        }
    } else {
        "尚未启动攻击回放".to_owned()
    };
    RangeReplayStatus {
        running: inner.running,
        command: inner.command.clone(),
        scenario: inner.scenario.clone(),
        started_at: inner.started_at.clone(),
        finished_at: inner.finished_at.clone(),
        pid: inner.pid,
        completed: inner.completed,
        total: inner.total,
        remaining: inner.remaining,
        exit_code: inner.exit_code,
        error: inner.error.clone(),
        detail,
        log: inner.log.clone(),
    }
}

fn push_replay_log(inner: &mut ReplayStateInner, line: String) {
    inner.log.push(line);
    if inner.log.len() > RANGE_REPLAY_LOG_LIMIT {
        let overflow = inner.log.len() - RANGE_REPLAY_LOG_LIMIT;
        inner.log.drain(0..overflow);
    }
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

pub(crate) fn configured_root(app: &tauri::AppHandle) -> Option<PathBuf> {
    let settings = read_settings(app);
    if !settings.agentrange_root.trim().is_empty() {
        return Some(PathBuf::from(settings.agentrange_root));
    }
    std::env::var_os("DEFENSECLAW_AGENTRANGE_ROOT")
        .map(PathBuf::from)
        .or_else(default_development_root)
}

fn configured_mode(app: &tauri::AppHandle) -> RangeMode {
    read_settings(app).range_mode
}

fn split_command_line(input: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for character in input.trim().chars() {
        match character {
            '"' | '\'' if quote == Some(character) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(character),
            ch if ch.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            ch => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err("攻击命令中的引号没有闭合".to_owned());
    }
    if !current.is_empty() {
        args.push(current);
    }
    Ok(args)
}

fn is_uv_token(token: &str) -> bool {
    let normalized = token
        .trim_matches('"')
        .trim_matches('\'')
        .replace('\\', "/");
    normalized.eq_ignore_ascii_case("uv")
        || normalized.eq_ignore_ascii_case("uv.exe")
        || normalized.to_ascii_lowercase().ends_with("/uv.exe")
}

fn is_allowed_scenario(value: &str) -> bool {
    matches!(
        value,
        "all" | "C1-A" | "C1-B" | "C2-A" | "C2-B" | "C2-C" | "C2-D" | "M-1"
    )
}

fn runner_path_from_root(root: &Path) -> Result<PathBuf, String> {
    let runner = root.join("scenario-runner").join("runner.py");
    if runner.is_file() {
        Ok(runner)
    } else {
        Err(format!("未找到靶场回放脚本：{}", runner.display()))
    }
}

fn write_replay_wrapper(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let home = desktop_defenseclaw_home(app)?;
    let runtime_dir = home.join("agentrange-runtime");
    fs::create_dir_all(&runtime_dir)
        .map_err(|error| format!("create {}: {error}", runtime_dir.display()))?;
    let wrapper = runtime_dir.join("agentrange-runner-progress.py");
    fs::write(&wrapper, RANGE_REPLAY_WRAPPER)
        .map_err(|error| format!("write {}: {error}", wrapper.display()))?;
    Ok(wrapper)
}

fn uv_program_from_token(token: &str) -> String {
    if token.contains('\\') || token.contains('/') {
        return token.to_owned();
    }
    "uv.exe".to_owned()
}

struct ReplayCommand {
    program: String,
    args: Vec<String>,
    cwd: PathBuf,
    command: String,
    scenario: String,
}

fn resolve_replay_command(app: &tauri::AppHandle, input: &str) -> Result<ReplayCommand, String> {
    let tokens = split_command_line(input)?;
    if tokens.is_empty() {
        return Err("请输入攻击回放命令".to_owned());
    }
    let root =
        configured_root(app).ok_or_else(|| "AgentRange root is not configured".to_owned())?;
    let runner = runner_path_from_root(&root)?;
    let wrapper = write_replay_wrapper(app)?;
    let mut scenario = "all".to_owned();

    if tokens.len() == 1 && is_allowed_scenario(&tokens[0]) {
        scenario = tokens[0].clone();
    } else {
        if !is_uv_token(&tokens[0]) {
            return Err(
                "只允许执行 uv run --with httpx python ...scenario-runner\\runner.py [场景]"
                    .to_owned(),
            );
        }
        let python_index = tokens
            .iter()
            .position(|token| token.eq_ignore_ascii_case("python"))
            .ok_or_else(|| "攻击命令必须包含 python runner.py".to_owned())?;
        let script = tokens
            .get(python_index + 1)
            .ok_or_else(|| "攻击命令缺少 scenario-runner\\runner.py".to_owned())?;
        if !script
            .replace('\\', "/")
            .to_ascii_lowercase()
            .ends_with("scenario-runner/runner.py")
        {
            return Err("只允许运行 AgentRange 的 scenario-runner\\runner.py".to_owned());
        }
        if let Some(value) = tokens.get(python_index + 2) {
            if !is_allowed_scenario(value) {
                return Err(format!(
                    "不支持的场景 {value}，可用：C1-A、C1-B、C2-A、C2-B、C2-C、C2-D、M-1、all"
                ));
            }
            scenario = value.clone();
        }
    }

    let mut args = vec![
        "run".to_owned(),
        "--with".to_owned(),
        "httpx".to_owned(),
        "python".to_owned(),
        wrapper.to_string_lossy().into_owned(),
        runner.to_string_lossy().into_owned(),
    ];
    if scenario != "all" {
        args.push(scenario.clone());
    }

    Ok(ReplayCommand {
        program: uv_program_from_token(&tokens[0]),
        args,
        cwd: root,
        command: if scenario == "all" {
            format!(
                "uv run --with httpx python \"{}\"",
                runner.to_string_lossy()
            )
        } else {
            format!(
                "uv run --with httpx python \"{}\" {}",
                runner.to_string_lossy(),
                scenario
            )
        },
        scenario,
    })
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

fn sidecar_resource_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let resource_dir = app
        .path()
        .resource_dir()
        .map_err(|error| format!("resolve desktop resource directory: {error}"))?;
    let candidates = [
        resource_dir
            .join("cli")
            .join("defenseclaw")
            .join("agentrange_sidecar.py"),
        resource_dir.join("agentrange_sidecar.py"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("cli")
            .join("defenseclaw")
            .join("agentrange_sidecar.py"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| "bundled agentrange_sidecar.py was not found".to_owned())
}

fn docker_mount_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn write_adapter_compose(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let home = desktop_defenseclaw_home(app)?;
    let runtime_dir = home.join("agentrange-adapter");
    fs::create_dir_all(&runtime_dir)
        .map_err(|error| format!("create {}: {error}", runtime_dir.display()))?;
    let sidecar = sidecar_resource_path(app)?;
    let env_file = home.join(".env");
    let compose = runtime_dir.join("docker-compose.defenseclaw.override.yml");
    let sidecar_mount = docker_mount_path(&sidecar);
    let env_mount = docker_mount_path(&env_file);
    let contents = format!(
        r#"services:
  opspilot-app:
    environment:
      DEFENSECLAW_CONNECTOR: agentrange
      DEFENSECLAW_ADAPTER: external-sidecar
      LLM_BASE: http://defenseclaw-llm-proxy:8000/v1
      LANGFLOW_BASE: http://defenseclaw-langflow-ingress:7860
      MCP_CUSTOMER_DB: http://defenseclaw-mcp-proxy:8000/mcp-customer-db/mcp
      MCP_GITLAB: http://defenseclaw-mcp-proxy:8000/mcp-gitlab/mcp
      MCP_KNOWLEDGE: http://defenseclaw-mcp-proxy:8000/mcp-knowledge/mcp
      MCP_MONITORING: http://defenseclaw-mcp-proxy:8000/mcp-monitoring/mcp
      MCP_NOTES_SYNC: http://defenseclaw-mcp-proxy:8000/mcp-notes-sync/mcp
      MCP_SANDBOX_EXEC: http://defenseclaw-mcp-proxy:8000/mcp-sandbox-exec/mcp
      MCP_SHELL_RUNNER: http://defenseclaw-mcp-proxy:8000/mcp-shell-runner/mcp
      MCP_THREAT_INTEL: http://defenseclaw-mcp-proxy:8000/mcp-threat-intel/mcp
    ports: !reset []
  defenseclaw-opspilot-ingress:
    image: python:3.12-slim
    command: python /opt/defenseclaw/agentrange_sidecar.py
    env_file:
    - "{env_file}"
    volumes:
    - "{sidecar}:/opt/defenseclaw/agentrange_sidecar.py:ro"
    extra_hosts:
    - host.docker.internal:host-gateway
    networks:
    - egress-net
    - opspilot-net
    environment:
      PYTHONUNBUFFERED: '1'
      DC_GATEWAY_BASE: http://host.docker.internal:18970
      DC_FAIL_MODE: open
      DC_INSPECT_TIMEOUT_MS: '250'
      DC_CONNECTOR: agentrange
      DC_PROXY_KIND: opspilot
      DC_TARGET_BASE: http://opspilot-app:8000
      DC_LISTEN_PORT: '8000'
    depends_on:
    - opspilot-app
    ports:
    - 8100:8000
  defenseclaw-llm-proxy:
    image: python:3.12-slim
    command: python /opt/defenseclaw/agentrange_sidecar.py
    env_file:
    - "{env_file}"
    volumes:
    - "{sidecar}:/opt/defenseclaw/agentrange_sidecar.py:ro"
    extra_hosts:
    - host.docker.internal:host-gateway
    networks:
    - egress-net
    - opspilot-net
    environment:
      PYTHONUNBUFFERED: '1'
      DC_GATEWAY_BASE: http://host.docker.internal:18970
      DC_FAIL_MODE: open
      DC_INSPECT_TIMEOUT_MS: '250'
      DC_CONNECTOR: agentrange
      DC_PROXY_KIND: llm
      DC_TARGET_BASE: http://llm-stub:8000
      DC_LISTEN_PORT: '8000'
    depends_on:
    - llm-stub
  defenseclaw-mcp-proxy:
    image: python:3.12-slim
    command: python /opt/defenseclaw/agentrange_sidecar.py
    env_file:
    - "{env_file}"
    volumes:
    - "{sidecar}:/opt/defenseclaw/agentrange_sidecar.py:ro"
    extra_hosts:
    - host.docker.internal:host-gateway
    networks:
    - egress-net
    - opspilot-net
    environment:
      PYTHONUNBUFFERED: '1'
      DC_GATEWAY_BASE: http://host.docker.internal:18970
      DC_FAIL_MODE: open
      DC_INSPECT_TIMEOUT_MS: '250'
      DC_CONNECTOR: agentrange
      DC_PROXY_KIND: mcp
      DC_MCP_TARGETS: '{{"mcp-customer-db": "http://mcp-customer-db:8000", "mcp-gitlab": "http://mcp-gitlab:8000", "mcp-knowledge": "http://mcp-knowledge:8000", "mcp-monitoring": "http://mcp-monitoring:8000", "mcp-notes-sync": "http://mcp-notes-sync:8000", "mcp-sandbox-exec": "http://mcp-sandbox-exec:8000", "mcp-shell-runner": "http://mcp-shell-runner:8000", "mcp-threat-intel": "http://mcp-threat-intel:8000"}}'
      DC_LISTEN_PORT: '8000'
    depends_on:
    - mcp-customer-db
    - mcp-gitlab
    - mcp-knowledge
    - mcp-monitoring
    - mcp-notes-sync
    - mcp-sandbox-exec
    - mcp-shell-runner
    - mcp-threat-intel
  langflow:
    environment:
      OPENAI_API_BASE: http://defenseclaw-llm-proxy:8000/v1
    ports: !reset []
  defenseclaw-langflow-ingress:
    image: python:3.12-slim
    command: python /opt/defenseclaw/agentrange_sidecar.py
    env_file:
    - "{env_file}"
    volumes:
    - "{sidecar}:/opt/defenseclaw/agentrange_sidecar.py:ro"
    extra_hosts:
    - host.docker.internal:host-gateway
    networks:
    - egress-net
    - opspilot-net
    environment:
      PYTHONUNBUFFERED: '1'
      DC_GATEWAY_BASE: http://host.docker.internal:18970
      DC_FAIL_MODE: open
      DC_INSPECT_TIMEOUT_MS: '250'
      DC_CONNECTOR: agentrange
      DC_PROXY_KIND: langflow
      DC_TARGET_BASE: http://langflow:7860
      DC_LISTEN_PORT: '7860'
    depends_on:
    - langflow
    ports:
    - 7860:7860
"#,
        env_file = env_mount,
        sidecar = sidecar_mount
    );
    fs::write(&compose, contents)
        .map_err(|error| format!("write {}: {error}", compose.display()))?;
    Ok(compose)
}

fn compose_files(
    app: &tauri::AppHandle,
    root: &Path,
    mode: RangeMode,
) -> Result<Vec<PathBuf>, String> {
    let mut files = vec![compose_path(root)?];
    if mode.requires_adapter() {
        files.push(write_adapter_compose(app)?);
    }
    Ok(files)
}

fn run_docker(
    compose_files: &[PathBuf],
    arguments: &[&str],
) -> Result<std::process::Output, String> {
    let mut command = Command::new(if cfg!(windows) {
        "docker.exe"
    } else {
        "docker"
    });
    command.arg("compose");
    for compose in compose_files {
        command.arg("-f").arg(compose);
    }
    command.args(arguments);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
        .output()
        .map_err(|error| format!("run Docker Compose: {error}"))
}

fn apply_progress_line(inner: &mut ReplayStateInner, line: &str) {
    let Some(raw) = line.strip_prefix("DEFENSECLAW_PROGRESS ") else {
        return;
    };
    let Ok(value) = serde_json::from_str::<Value>(raw) else {
        return;
    };
    if let Some(completed) = value
        .get("completed")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    {
        inner.completed = completed;
    }
    if let Some(total) = value
        .get("total")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    {
        inner.total = total;
    }
    inner.remaining = value
        .get("remaining")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or_else(|| inner.total.saturating_sub(inner.completed));
    if let Some(scenario) = value.get("scenario").and_then(Value::as_str) {
        inner.scenario = scenario.to_owned();
    }
}

fn read_replay_lines<R: std::io::Read + Send + 'static>(
    reader: R,
    state: Arc<Mutex<ReplayStateInner>>,
    stream: &'static str,
) {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            let Ok(line) = line else {
                break;
            };
            let mut inner = state.lock().expect("range replay state poisoned");
            apply_progress_line(&mut inner, &line);
            push_replay_log(&mut inner, format!("{stream}: {line}"));
        }
    });
}

fn monitor_replay_process(state: Arc<Mutex<ReplayStateInner>>) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(300));
        let mut inner = state.lock().expect("range replay state poisoned");
        let Some(child) = inner.child.as_mut() else {
            break;
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                let code = status.code();
                inner.running = false;
                inner.finished_at = Some(Utc::now().to_rfc3339());
                inner.exit_code = code;
                if code == Some(0) {
                    inner.error = None;
                    if inner.total > 0 {
                        inner.completed = inner.total;
                        inner.remaining = 0;
                    }
                    push_replay_log(&mut inner, "system: 攻击回放已完成".to_owned());
                } else if inner.error.is_none() {
                    inner.error = Some(format!("攻击回放异常退出，退出码 {}", code.unwrap_or(-1)));
                }
                inner.child = None;
                break;
            }
            Ok(None) => {}
            Err(error) => {
                inner.running = false;
                inner.finished_at = Some(Utc::now().to_rfc3339());
                inner.error = Some(format!("查询回放进程状态失败：{error}"));
                inner.child = None;
                break;
            }
        }
    });
}

#[tauri::command]
pub fn get_range_replay_status() -> RangeReplayStatus {
    let state = replay_state();
    let inner = state.lock().expect("range replay state poisoned");
    replay_status_from(&inner)
}

#[tauri::command]
pub fn start_range_replay(
    app: tauri::AppHandle,
    command: String,
) -> Result<RangeReplayStatus, String> {
    let replay = resolve_replay_command(&app, &command)?;
    let state = replay_state();
    {
        let inner = state.lock().expect("range replay state poisoned");
        if inner.running {
            return Err("已有攻击回放正在运行，请先停止当前任务".to_owned());
        }
    }

    let mut process = Command::new(&replay.program);
    process.args(&replay.args);
    process.current_dir(&replay.cwd);
    process.env("PYTHONUNBUFFERED", "1");
    process.env("LLM_STUB_BASE", "http://127.0.0.1:8000");
    process.env("OPSPILOT_BASE", "http://127.0.0.1:8100");
    process.env("LANGFLOW_BASE", "http://127.0.0.1:7860");
    process.env("NO_PROXY", "127.0.0.1,localhost,host.docker.internal");
    process.env("no_proxy", "127.0.0.1,localhost,host.docker.internal");
    process.stdout(Stdio::piped());
    process.stderr(Stdio::piped());
    #[cfg(windows)]
    process.creation_flags(CREATE_NO_WINDOW);
    let mut child = process
        .spawn()
        .map_err(|error| format!("启动攻击回放失败：{error}"))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let pid = child.id();

    {
        let mut inner = state.lock().expect("range replay state poisoned");
        *inner = ReplayStateInner {
            running: true,
            command: replay.command,
            scenario: replay.scenario,
            started_at: Utc::now().to_rfc3339(),
            finished_at: None,
            pid: Some(pid),
            completed: 0,
            total: 0,
            remaining: 0,
            exit_code: None,
            error: None,
            log: Vec::new(),
            child: Some(child),
        };
        push_replay_log(&mut inner, format!("system: 已启动攻击回放进程 PID {pid}"));
    }

    if let Some(stdout) = stdout {
        read_replay_lines(stdout, state.clone(), "stdout");
    }
    if let Some(stderr) = stderr {
        read_replay_lines(stderr, state.clone(), "stderr");
    }
    monitor_replay_process(state.clone());

    let inner = state.lock().expect("range replay state poisoned");
    Ok(replay_status_from(&inner))
}

#[tauri::command]
pub fn stop_range_replay() -> Result<RangeReplayStatus, String> {
    let state = replay_state();
    let mut inner = state.lock().expect("range replay state poisoned");
    if let Some(child) = inner.child.as_mut() {
        #[cfg(windows)]
        {
            let mut command = Command::new("taskkill.exe");
            command.args(["/PID", &child.id().to_string(), "/T", "/F"]);
            command.stdout(Stdio::null());
            command.stderr(Stdio::null());
            #[cfg(windows)]
            command.creation_flags(CREATE_NO_WINDOW);
            let _ = command.output();
        }
        #[cfg(not(windows))]
        {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
    inner.running = false;
    inner.finished_at = Some(Utc::now().to_rfc3339());
    inner.exit_code = None;
    inner.error = Some("攻击回放已停止".to_owned());
    inner.child = None;
    push_replay_log(&mut inner, "system: 攻击回放已停止".to_owned());
    Ok(replay_status_from(&inner))
}

#[tauri::command]
pub fn get_range_status(app: tauri::AppHandle) -> RangeStatus {
    let Some(root) = configured_root(&app) else {
        return RangeStatus {
            configured: false,
            root: String::new(),
            compose_file: String::new(),
            adapter_compose_file: String::new(),
            mode: configured_mode(&app),
            docker_available: false,
            running_services: Vec::new(),
            state: "unconfigured",
            detail: "请选择 AgentRange-player 目录".to_owned(),
        };
    };
    let mode = configured_mode(&app);
    let root_text = root.to_string_lossy().into_owned();
    let files = match compose_files(&app, &root, mode) {
        Ok(files) => files,
        Err(detail) => {
            return RangeStatus {
                configured: false,
                root: root_text,
                compose_file: String::new(),
                adapter_compose_file: String::new(),
                mode,
                docker_available: false,
                running_services: Vec::new(),
                state: "invalid",
                detail,
            }
        }
    };
    let output = run_docker(&files, &["ps", "--services", "--status", "running"]);
    let Ok(output) = output else {
        return RangeStatus {
            configured: true,
            root: root_text,
            compose_file: files[0].to_string_lossy().into_owned(),
            adapter_compose_file: files
                .get(1)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default(),
            mode,
            docker_available: false,
            running_services: Vec::new(),
            state: "dockerUnavailable",
            detail: "未检测到兼容的容器运行时；靶场为可选功能，不影响核心防护".to_owned(),
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
        compose_file: files[0].to_string_lossy().into_owned(),
        adapter_compose_file: files
            .get(1)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default(),
        mode,
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
    let mode = configured_mode(&app);
    let settings = DesktopSettings {
        agentrange_root: canonical_root.to_string_lossy().into_owned(),
        range_mode: mode,
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
    if mode.requires_adapter() {
        let lifecycle = run_gateway_action_for_mode(&app, "restart", mode.as_str())?;
        if !lifecycle.success {
            return Err(lifecycle.message);
        }
    }
    Ok(get_range_status(app))
}

#[tauri::command]
pub fn set_range_mode(app: tauri::AppHandle, mode: RangeMode) -> Result<RangeStatus, String> {
    let lifecycle = if mode.requires_adapter() {
        run_gateway_action_for_mode(&app, "restart", mode.as_str())?
    } else {
        run_gateway_action(&app, "stop")?
    };
    if !lifecycle.success {
        return Err(lifecycle.message);
    }
    let settings = DesktopSettings {
        agentrange_root: configured_root(&app)
            .map(|root| root.to_string_lossy().into_owned())
            .unwrap_or_default(),
        range_mode: mode,
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

fn change_range_state(
    app: &tauri::AppHandle,
    running: bool,
    mode: RangeMode,
) -> Result<RangeStatus, String> {
    let root =
        configured_root(app).ok_or_else(|| "AgentRange root is not configured".to_owned())?;
    let baseline_files = vec![compose_path(&root)?];
    let mode_files = compose_files(app, &root, mode)?;
    let output = if running {
        let _ = run_docker(&mode_files, &["down"]);
        let _ = run_docker(&baseline_files, &["down"]);
        if mode.requires_adapter() {
            let result = run_gateway_action_for_mode(app, "restart", mode.as_str())?;
            if !result.success {
                return Err(result.message);
            }
        }
        run_docker(&mode_files, &["up", "-d", "--no-build"])?
    } else {
        let _ = run_docker(&mode_files, &["down"]);
        run_docker(&baseline_files, &["down"])?
    };
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(get_range_status(app.clone()))
}

#[tauri::command]
pub fn start_range(app: tauri::AppHandle) -> Result<RangeStatus, String> {
    let mode = configured_mode(&app);
    change_range_state(&app, true, mode)
}

#[tauri::command]
pub fn stop_range(app: tauri::AppHandle) -> Result<RangeStatus, String> {
    let mode = configured_mode(&app);
    change_range_state(&app, false, mode)
}
