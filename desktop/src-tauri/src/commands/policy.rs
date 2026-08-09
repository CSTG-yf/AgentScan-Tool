use std::fs;
use std::path::PathBuf;

use tauri::Manager;

use crate::models::{GuardPolicy, GuardRule, TerminationPolicy};

fn default_policy() -> GuardPolicy {
    GuardPolicy {
        version: 1,
        enabled: false,
        mode: "observe".to_owned(),
        agent_names: vec![
            "codex.exe".to_owned(),
            "claude.exe".to_owned(),
            "cursor.exe".to_owned(),
            "cursor-agent.exe".to_owned(),
            "windsurf.exe".to_owned(),
            "codeium.exe".to_owned(),
            "language_server_windows_x64.exe".to_owned(),
            "aider.exe".to_owned(),
            "opencode.exe".to_owned(),
            "openhands.exe".to_owned(),
            "goose.exe".to_owned(),
            "cline.exe".to_owned(),
        ],
        rules: vec![
            GuardRule {
                id: "command.grep".to_owned(),
                enabled: false,
                executable: "grep.exe".to_owned(),
                action: "terminateAgentTree".to_owned(),
                description: "示例规则：Agent 创建 grep.exe 时记录并终止所属 Agent 进程树。"
                    .to_owned(),
            },
            GuardRule {
                id: "command.curl".to_owned(),
                enabled: false,
                executable: "curl.exe".to_owned(),
                action: "audit".to_owned(),
                description: "观察 Agent 发起的 curl 子进程，不执行终止。".to_owned(),
            },
            GuardRule {
                id: "command.powershell".to_owned(),
                enabled: false,
                executable: "powershell.exe".to_owned(),
                action: "audit".to_owned(),
                description: "观察传统 Windows PowerShell 子进程。".to_owned(),
            },
        ],
        termination: TerminationPolicy {
            grace_period_ms: 1_500,
            verify_process_identity: true,
            protected_process_behavior: "auditOnly".to_owned(),
        },
    }
}

fn policy_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("process-guard.json"))
        .map_err(|error| format!("resolve process guard policy path: {error}"))
}

fn validate(policy: &GuardPolicy) -> Result<(), String> {
    if policy.version != 1 {
        return Err("unsupported process guard policy version".to_owned());
    }
    if !matches!(policy.mode.as_str(), "observe" | "enforce") {
        return Err("mode must be observe or enforce".to_owned());
    }
    if policy.termination.grace_period_ms > 30_000 || !policy.termination.verify_process_identity {
        return Err("invalid termination safety settings".to_owned());
    }
    for rule in &policy.rules {
        let executable = rule.executable.trim();
        if executable.is_empty()
            || executable.contains(['/', '\\', '*', '?', ' ', '\t', '"', '\''])
            || !matches!(rule.action.as_str(), "audit" | "terminateAgentTree")
        {
            return Err(format!("invalid process guard rule: {}", rule.id));
        }
    }
    Ok(())
}

#[tauri::command]
pub fn get_guard_policy(app: tauri::AppHandle) -> Result<GuardPolicy, String> {
    let path = policy_path(&app)?;
    if !path.is_file() {
        return Ok(default_policy());
    }
    let raw =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let policy: GuardPolicy =
        serde_json::from_str(&raw).map_err(|error| format!("parse {}: {error}", path.display()))?;
    validate(&policy)?;
    Ok(policy)
}

#[tauri::command]
pub fn save_guard_policy(
    app: tauri::AppHandle,
    policy: GuardPolicy,
) -> Result<GuardPolicy, String> {
    validate(&policy)?;
    let path = policy_path(&app)?;
    let parent = path
        .parent()
        .ok_or_else(|| "process guard policy path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("create {}: {error}", parent.display()))?;
    let raw = serde_json::to_vec_pretty(&policy)
        .map_err(|error| format!("serialize process guard policy: {error}"))?;
    fs::write(&path, raw).map_err(|error| format!("write {}: {error}", path.display()))?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::{default_policy, validate};

    #[test]
    fn default_policy_is_valid_and_safe() {
        let policy = default_policy();
        assert!(!policy.enabled);
        assert_eq!(policy.mode, "observe");
        assert!(policy.rules.iter().all(|rule| !rule.enabled));
        assert!(policy.agent_names.iter().any(|name| name == "codeium.exe"));
        assert!(policy.agent_names.iter().any(|name| name == "cline.exe"));
        assert!(validate(&policy).is_ok());
    }

    #[test]
    fn rejects_paths_and_shell_syntax() {
        let mut policy = default_policy();
        policy.rules[0].executable = "C:\\Windows\\grep.exe".to_owned();
        assert!(validate(&policy).is_err());
    }
}
