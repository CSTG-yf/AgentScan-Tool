use std::fs;
use std::path::PathBuf;

use tauri::Manager;

use crate::models::GuardPolicy;
use crate::policy_defaults::default_policy;

fn policy_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join("process-guard.json"))
        .map_err(|error| format!("resolve process guard policy path: {error}"))
}

fn validate(policy: &GuardPolicy) -> Result<(), String> {
    crate::process_guard::validate_policy(policy)
}

#[tauri::command]
pub fn get_guard_policy(app: tauri::AppHandle) -> Result<GuardPolicy, String> {
    let path = policy_path(&app)?;
    if !path.is_file() {
        return default_policy();
    }
    let raw =
        fs::read_to_string(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let policy: GuardPolicy =
        serde_json::from_str(&raw).map_err(|error| format!("parse {}: {error}", path.display()))?;
    validate(&policy)?;
    Ok(policy.normalize())
}

#[tauri::command]
pub fn save_guard_policy(
    app: tauri::AppHandle,
    policy: GuardPolicy,
) -> Result<GuardPolicy, String> {
    let policy = policy.normalize();
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
        let policy = default_policy().expect("valid embedded policy and knowledge catalog");
        assert!(!policy.enabled);
        assert_eq!(policy.mode, "observe");
        assert!(policy.rules.iter().all(|rule| !rule.enabled));
        assert!(policy.agent_names.iter().any(|name| name == "codex.exe"));
        assert!(policy.agent_names.iter().any(|name| name == "cline.exe"));
        assert!(!policy.agent_names.iter().any(|name| name == "node.exe"));
        assert!(validate(&policy).is_ok());
    }

    #[test]
    fn rejects_paths_and_shell_syntax() {
        let mut policy = default_policy().expect("valid embedded policy and knowledge catalog");
        policy.rules[0].executable = "C:\\Windows\\grep.exe".to_owned();
        assert!(validate(&policy).is_err());
    }
}
