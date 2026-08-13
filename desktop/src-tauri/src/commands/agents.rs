use chrono::Utc;

use crate::knowledge;
use crate::models::{AgentProcess, AgentSnapshot};
use crate::windows_process;

#[tauri::command]
pub fn get_agent_processes() -> AgentSnapshot {
    let catalog = match knowledge::catalog() {
        Ok(catalog) => catalog,
        Err(error) => {
            return AgentSnapshot {
                captured_at: Utc::now().to_rfc3339(),
                processes: Vec::new(),
                warning: Some(error),
            };
        }
    };
    let (mut processes, warning) = match windows_process::snapshot() {
        Ok(snapshot) => {
            let agents = snapshot
                .into_iter()
                .filter_map(|process| {
                    let signature = knowledge::identify_agent_in(catalog, &process.name)?;
                    Some(AgentProcess {
                        pid: process.pid,
                        ppid: process.ppid,
                        name: process.name,
                        product: signature.product.clone(),
                        vendor: signature.vendor.clone(),
                        started_at: process.started_at,
                        uptime_sec: process.uptime_sec,
                        source: "native",
                    })
                })
                .collect::<Vec<_>>();
            (agents, None)
        }
        Err(error) => (Vec::new(), Some(error)),
    };
    processes.sort_by(|left, right| {
        left.product
            .cmp(&right.product)
            .then(left.pid.cmp(&right.pid))
    });
    AgentSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        processes,
        warning,
    }
}

#[cfg(test)]
mod tests {
    use crate::knowledge::{catalog, identify_agent_in};

    #[test]
    fn recognizes_windows_executable_names_from_catalog() {
        let signature = identify_agent_in(
            catalog().expect("valid embedded runtime catalog"),
            " Cursor.EXE ",
        )
        .expect("Cursor signature");
        assert_eq!(signature.product, "Cursor");
    }
}
