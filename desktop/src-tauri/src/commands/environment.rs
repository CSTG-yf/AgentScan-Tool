use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

use chrono::Utc;

use crate::models::{EnvironmentComponent, EnvironmentSnapshot};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn run_fixed(program: &str, args: &[&str]) -> Option<String> {
    let mut command = Command::new(program);
    command.args(args);
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

fn tcp_ready(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(350)).is_ok()
}

#[tauri::command]
pub fn get_environment_snapshot() -> EnvironmentSnapshot {
    let gateway_ready = tcp_ready(18_970);
    let docker_version = run_fixed(
        "docker.exe",
        &["version", "--format", "{{.Server.Version}}"],
    );
    let range_ready = tcp_ready(8_000) || tcp_ready(8_100) || tcp_ready(7_860);
    let guard_status = run_fixed("sc.exe", &["query", "DefenseClawProcessGuard"]);
    let guard_running = guard_status
        .as_deref()
        .is_some_and(|text| text.contains("RUNNING"));

    EnvironmentSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        components: vec![
            EnvironmentComponent {
                id: "gateway",
                label: "DefenseClaw Gateway",
                state: if gateway_ready { "ready" } else { "stopped" },
                detail: if gateway_ready {
                    "本机 127.0.0.1:18970 可连接"
                } else {
                    "网关端口未监听"
                }
                .to_owned(),
                version: None,
                requires_elevation: false,
            },
            EnvironmentComponent {
                id: "docker",
                label: "Docker Desktop",
                state: if docker_version.is_some() {
                    "ready"
                } else {
                    "missing"
                },
                detail: docker_version.as_ref().map_or_else(
                    || "Docker Engine 不可用".to_owned(),
                    |version| format!("Docker Engine {version}"),
                ),
                version: docker_version,
                requires_elevation: false,
            },
            EnvironmentComponent {
                id: "agentrange",
                label: "AgentRange 靶场",
                state: if range_ready { "ready" } else { "stopped" },
                detail: if range_ready {
                    "检测到靶场服务端口"
                } else {
                    "未检测到运行中的靶场服务"
                }
                .to_owned(),
                version: None,
                requires_elevation: false,
            },
            EnvironmentComponent {
                id: "processGuard",
                label: "Windows 进程守护",
                state: if guard_running {
                    "ready"
                } else if guard_status.is_some() {
                    "stopped"
                } else {
                    "missing"
                },
                detail: if guard_running {
                    "管理员监控服务正在运行"
                } else if guard_status.is_some() {
                    "服务已安装但未运行"
                } else {
                    "管理员监控服务尚未安装"
                }
                .to_owned(),
                version: None,
                requires_elevation: true,
            },
        ],
    }
}
