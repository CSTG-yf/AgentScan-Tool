use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use chrono::Utc;
use tauri::Manager;

use crate::models::{EnvironmentComponent, EnvironmentSnapshot};

fn tcp_ready(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(350)).is_ok()
}

fn sandbox_component(app: &tauri::AppHandle) -> EnvironmentComponent {
    let binary_name = if cfg!(windows) {
        "tracebastion-sandbox.exe"
    } else {
        "tracebastion-sandbox"
    };
    let mut candidates = Vec::new();
    if let Ok(resources) = app.path().resource_dir() {
        candidates.push(resources.join("resources").join(binary_name));
        candidates.push(resources.join(binary_name));
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join(binary_name),
    );
    let binary = candidates.into_iter().find(|path| path.is_file());
    let (state, detail, endpoint) = match binary {
        None => ("missing", "本安装包未包含本地沙箱工具".to_owned(), None),
        Some(path) => {
            let status = Command::new(&path).arg("status").output();
            let (state, detail) = match status {
                Ok(output) if output.status.success() => {
                    let report = String::from_utf8_lossy(&output.stdout);
                    ("ready", report.lines().take(2).collect::<Vec<_>>().join(" · "))
                }
                Ok(output) => (
                    "degraded",
                    String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                ),
                Err(error) => ("degraded", format!("沙箱探测失败: {error}")),
            };
            (state, detail, Some(path.display().to_string()))
        }
    };
    EnvironmentComponent {
        id: "sandbox",
        label: "本地命令沙箱",
        state,
        detail,
        endpoint,
        version: None,
        requires_elevation: false,
    }
}

#[tauri::command]
pub fn get_environment_snapshot(app: tauri::AppHandle) -> EnvironmentSnapshot {
    // Never probe a hardcoded 18970: the desktop moves to an alternative port
    // when another DefenseClaw home already holds the canonical one.
    let gateway_port =
        crate::commands::lifecycle::desktop_gateway_api_port_for_app(&app).unwrap_or(18_970);
    let gateway_ready = tcp_ready(gateway_port);
    let range_ready = tcp_ready(8_000) || tcp_ready(8_100) || tcp_ready(7_860);
    let (guard_installed, guard_running) = crate::process_guard_service::service_status();

    EnvironmentSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        components: vec![
            EnvironmentComponent {
                id: "gateway",
                label: "TraceBastion Gateway",
                state: if gateway_ready { "ready" } else { "stopped" },
                detail: if gateway_ready {
                    format!("本机 127.0.0.1:{gateway_port} 可连接")
                } else {
                    "网关端口未监听".to_owned()
                },
                endpoint: Some(format!("127.0.0.1:{gateway_port}")),
                version: None,
                requires_elevation: false,
            },
            EnvironmentComponent {
                id: "agentrange",
                label: "AgentRange 验证靶场（可选）",
                state: if range_ready { "ready" } else { "stopped" },
                detail: if range_ready {
                    "模拟攻击与正常业务流量的隔离验证环境正在运行"
                } else {
                    "仅用于安全能力测试与演示，未运行不影响日常防护"
                }
                .to_owned(),
                endpoint: None,
                version: None,
                requires_elevation: false,
            },
            EnvironmentComponent {
                id: "processGuard",
                label: if crate::platform::NAME == "Linux" {
                    "Linux 进程守护"
                } else {
                    "Windows 进程守护"
                },
                state: if guard_running {
                    "ready"
                } else if guard_installed {
                    "stopped"
                } else {
                    "missing"
                },
                detail: if guard_running {
                    "管理员监控服务正在运行"
                } else if guard_installed {
                    "服务已安装但未运行"
                } else {
                    if cfg!(target_os = "linux") {
                        "systemd 监控服务尚未安装"
                    } else {
                        "管理员监控服务尚未安装"
                    }
                }
                .to_owned(),
                endpoint: None,
                version: None,
                requires_elevation: true,
            },
            sandbox_component(&app),
        ],
    }
}
