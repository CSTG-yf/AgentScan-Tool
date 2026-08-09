use chrono::Utc;

use crate::models::{AgentProcess, AgentSnapshot};
use crate::windows_process;

struct AgentSignature {
    names: &'static [&'static str],
    product: &'static str,
    vendor: &'static str,
}

const SIGNATURES: &[AgentSignature] = &[
    AgentSignature {
        names: &["codex", "codex.exe"],
        product: "OpenAI Codex",
        vendor: "OpenAI",
    },
    AgentSignature {
        names: &["claude", "claude.exe"],
        product: "Claude Code",
        vendor: "Anthropic",
    },
    AgentSignature {
        names: &["cursor", "cursor.exe", "cursor-agent", "cursor-agent.exe"],
        product: "Cursor",
        vendor: "Anysphere",
    },
    AgentSignature {
        names: &["windsurf", "windsurf.exe"],
        product: "Windsurf",
        vendor: "Cognition",
    },
    AgentSignature {
        names: &["codeium", "codeium.exe", "language_server_windows_x64.exe"],
        product: "Codeium",
        vendor: "Cognition",
    },
    AgentSignature {
        names: &["aider", "aider.exe"],
        product: "Aider",
        vendor: "Aider",
    },
    AgentSignature {
        names: &["opencode", "opencode.exe"],
        product: "OpenCode",
        vendor: "OpenCode",
    },
    AgentSignature {
        names: &["openhands", "openhands.exe"],
        product: "OpenHands",
        vendor: "All Hands AI",
    },
    AgentSignature {
        names: &["goose", "goose.exe"],
        product: "Goose",
        vendor: "Block",
    },
    AgentSignature {
        names: &["cline", "cline.exe"],
        product: "Cline",
        vendor: "Cline",
    },
];

fn normalize_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

#[tauri::command]
pub fn get_agent_processes() -> AgentSnapshot {
    let (mut processes, warning) = match windows_process::snapshot() {
        Ok(snapshot) => {
            let agents = snapshot
                .into_iter()
                .filter_map(|process| {
                    let normalized = normalize_name(&process.name);
                    let signature = SIGNATURES
                        .iter()
                        .find(|candidate| candidate.names.contains(&normalized.as_str()))?;
                    Some(AgentProcess {
                        pid: process.pid,
                        ppid: process.ppid,
                        name: process.name,
                        product: signature.product,
                        vendor: signature.vendor,
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
            .cmp(right.product)
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
    use super::normalize_name;

    #[test]
    fn normalizes_windows_executable_names() {
        assert_eq!(normalize_name(" Cursor.EXE "), "cursor.exe");
    }
}
