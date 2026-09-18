use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use chrono::Utc;

use crate::models::{EnvironmentComponent, EnvironmentSnapshot};

fn tcp_ready(port: u16) -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&address, Duration::from_millis(350)).is_ok()
}

#[tauri::command]
pub fn get_environment_snapshot() -> EnvironmentSnapshot {
    let gateway_ready = tcp_ready(18_970);
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
                    "本机 127.0.0.1:18970 可连接"
                } else {
                    "网关端口未监听"
                }
                .to_owned(),
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
                version: None,
                requires_elevation: true,
            },
        ],
    }
}
