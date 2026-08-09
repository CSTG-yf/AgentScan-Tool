use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;
use serde::Serialize;

use crate::models::{GuardPolicy, GuardRule};
use crate::windows_process::{self, ProcessInfo};

const POLL_INTERVAL: Duration = Duration::from_millis(150);
const POLICY_RELOAD_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
struct GuardMatch {
    child: ProcessInfo,
    agent: ProcessInfo,
    rule_id: String,
    action: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditEvent<'a> {
    timestamp: String,
    event_type: &'static str,
    mode: &'a str,
    rule_id: &'a str,
    action: &'a str,
    child_pid: u32,
    child_ppid: u32,
    child_executable: &'a str,
    agent_pid: u32,
    agent_executable: &'a str,
    outcome: &'a str,
    detail: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ServiceAuditEvent<'a> {
    timestamp: String,
    event_type: &'static str,
    outcome: &'a str,
    detail: &'a str,
}

fn canonical_executable(name: &str) -> String {
    let normalized = name.trim().to_ascii_lowercase();
    normalized
        .strip_suffix(".exe")
        .unwrap_or(&normalized)
        .to_owned()
}

fn executable_matches(left: &str, right: &str) -> bool {
    canonical_executable(left) == canonical_executable(right)
}

fn is_new(process: &ProcessInfo, previous: &HashSet<(u32, u64)>) -> bool {
    !previous.contains(&(process.pid, process.creation_ticks))
}

fn find_agent_ancestor<'a>(
    child: &ProcessInfo,
    by_pid: &'a HashMap<u32, &'a ProcessInfo>,
    agent_names: &[String],
) -> Option<&'a ProcessInfo> {
    let mut pid = child.ppid;
    let mut visited = HashSet::new();
    for _ in 0..64 {
        if pid == 0 || !visited.insert(pid) {
            return None;
        }
        let process = *by_pid.get(&pid)?;
        if agent_names
            .iter()
            .any(|name| executable_matches(&process.name, name))
        {
            return Some(process);
        }
        pid = process.ppid;
    }
    None
}

fn evaluate(
    previous: &HashSet<(u32, u64)>,
    current: &[ProcessInfo],
    policy: &GuardPolicy,
) -> Vec<GuardMatch> {
    if !policy.enabled {
        return Vec::new();
    }
    let enabled_rules = policy
        .rules
        .iter()
        .filter(|rule| rule.enabled)
        .collect::<Vec<&GuardRule>>();
    if enabled_rules.is_empty() {
        return Vec::new();
    }
    let by_pid = current
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    current
        .iter()
        .filter(|process| is_new(process, previous))
        .filter_map(|child| {
            let rule = enabled_rules
                .iter()
                .find(|rule| executable_matches(&child.name, &rule.executable))?;
            let agent = find_agent_ancestor(child, &by_pid, &policy.agent_names)?;
            Some(GuardMatch {
                child: child.clone(),
                agent: agent.clone(),
                rule_id: rule.id.clone(),
                action: rule.action.clone(),
            })
        })
        .collect()
}

fn evaluate_start(
    child: &ProcessInfo,
    current: &[ProcessInfo],
    policy: &GuardPolicy,
) -> Option<GuardMatch> {
    if !policy.enabled {
        return None;
    }
    let rule = policy
        .rules
        .iter()
        .find(|rule| rule.enabled && executable_matches(&child.name, &rule.executable))?;
    let by_pid = current
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let agent = find_agent_ancestor(child, &by_pid, &policy.agent_names)?;
    Some(GuardMatch {
        child: child.clone(),
        agent: agent.clone(),
        rule_id: rule.id.clone(),
        action: rule.action.clone(),
    })
}

fn append_audit(path: &Path, event: &AuditEvent<'_>) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create audit directory {}: {error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open audit log {}: {error}", path.display()))?;
    serde_json::to_writer(&mut file, event)
        .map_err(|error| format!("serialize process guard audit: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("append audit log {}: {error}", path.display()))
}

pub fn audit_service_event(path: &Path, outcome: &str, detail: &str) -> Result<(), String> {
    let event = ServiceAuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        event_type: "process-guard-service",
        outcome,
        detail,
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create audit directory {}: {error}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("open audit log {}: {error}", path.display()))?;
    serde_json::to_writer(&mut file, &event)
        .map_err(|error| format!("serialize process guard service audit: {error}"))?;
    file.write_all(b"\n")
        .map_err(|error| format!("append audit log {}: {error}", path.display()))
}

fn depth_from_root(
    process: &ProcessInfo,
    root_pid: u32,
    by_pid: &HashMap<u32, &ProcessInfo>,
) -> Option<usize> {
    let mut pid = process.pid;
    for depth in 0..64 {
        if pid == root_pid {
            return Some(depth);
        }
        pid = by_pid.get(&pid)?.ppid;
    }
    None
}

fn terminate_agent_tree(agent: &ProcessInfo) -> Result<String, String> {
    let snapshot = windows_process::snapshot()?;
    let current_root = snapshot
        .iter()
        .find(|process| process.pid == agent.pid && process.creation_ticks == agent.creation_ticks)
        .ok_or_else(|| "Agent process already exited or its PID was reused".to_owned())?;
    let by_pid = snapshot
        .iter()
        .map(|process| (process.pid, process))
        .collect::<HashMap<_, _>>();
    let mut tree = snapshot
        .iter()
        .filter_map(|process| {
            depth_from_root(process, current_root.pid, &by_pid).map(|depth| (depth, process))
        })
        .collect::<Vec<_>>();
    tree.sort_by(|left, right| right.0.cmp(&left.0));

    let mut terminated = 0usize;
    let mut errors = Vec::new();
    for (_, process) in tree {
        match windows_process::terminate_verified(process.pid, process.creation_ticks) {
            Ok(()) => terminated += 1,
            Err(error) => errors.push(error),
        }
    }
    if errors.is_empty() {
        Ok(format!("terminated {terminated} process(es)"))
    } else {
        Err(format!(
            "terminated {terminated} process(es); {}",
            errors.join("; ")
        ))
    }
}

pub fn load_and_validate_policy(path: &Path) -> Result<GuardPolicy, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("read policy {}: {error}", path.display()))?;
    let policy: GuardPolicy = serde_json::from_str(&raw)
        .map_err(|error| format!("parse policy {}: {error}", path.display()))?;
    if policy.version != 1
        || !matches!(policy.mode.as_str(), "observe" | "enforce")
        || policy.termination.grace_period_ms > 30_000
        || !policy.termination.verify_process_identity
        || policy.termination.protected_process_behavior != "auditOnly"
    {
        return Err("unsupported or invalid process guard policy".to_owned());
    }
    let valid_name = |value: &str| {
        !value.trim().is_empty()
            && !value.contains(['/', '\\', '*', '?', ' ', '\t', '"', '\''])
            && value.len() <= 260
    };
    if !policy.agent_names.iter().all(|name| valid_name(name))
        || !policy.rules.iter().all(|rule| {
            valid_name(&rule.executable)
                && !rule.id.trim().is_empty()
                && matches!(rule.action.as_str(), "audit" | "terminateAgentTree")
        })
    {
        return Err("process guard policy contains an invalid executable or action".to_owned());
    }
    Ok(policy)
}

fn audit_match(
    path: &Path,
    policy: &GuardPolicy,
    matched: &GuardMatch,
    outcome: &str,
    detail: &str,
) -> Result<(), String> {
    let event = AuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        event_type: "agent-command-rule-matched",
        mode: &policy.mode,
        rule_id: &matched.rule_id,
        action: &matched.action,
        child_pid: matched.child.pid,
        child_ppid: matched.child.ppid,
        child_executable: &matched.child.name,
        agent_pid: matched.agent.pid,
        agent_executable: &matched.agent.name,
        outcome,
        detail,
    };
    append_audit(path, &event)
}

/// Run the process guard in the foreground. Windows Service lifecycle support
/// wraps this same loop in the next delivery phase; keeping the enforcement
/// core here makes console integration tests deterministic.
pub fn run_until<F>(policy_path: &Path, audit_path: &Path, should_stop: F) -> Result<(), String>
where
    F: Fn() -> bool,
{
    let mut policy = load_and_validate_policy(policy_path)?;
    let baseline = windows_process::snapshot()?;
    let mut previous = baseline
        .iter()
        .map(|process| (process.pid, process.creation_ticks))
        .collect::<HashSet<_>>();
    let mut last_reload = Instant::now();

    loop {
        if should_stop() {
            return Ok(());
        }
        thread::sleep(POLL_INTERVAL);
        if last_reload.elapsed() >= POLICY_RELOAD_INTERVAL {
            if let Ok(updated) = load_and_validate_policy(policy_path) {
                policy = updated;
            }
            last_reload = Instant::now();
        }
        let current = match windows_process::snapshot() {
            Ok(snapshot) => snapshot,
            Err(_) => continue,
        };
        let matches = evaluate(&previous, &current, &policy);
        previous = current
            .iter()
            .map(|process| (process.pid, process.creation_ticks))
            .collect();

        for matched in matches {
            if policy.mode != "enforce" || matched.action != "terminateAgentTree" {
                let _ = audit_match(
                    audit_path,
                    &policy,
                    &matched,
                    "observed",
                    "rule matched; no termination requested",
                );
                continue;
            }
            if audit_match(
                audit_path,
                &policy,
                &matched,
                "terminationPending",
                "identity captured; termination requested",
            )
            .is_err()
            {
                continue;
            }
            thread::sleep(Duration::from_millis(u64::from(
                policy.termination.grace_period_ms,
            )));
            match terminate_agent_tree(&matched.agent) {
                Ok(detail) => {
                    let _ = audit_match(audit_path, &policy, &matched, "terminated", &detail);
                }
                Err(detail) => {
                    let _ =
                        audit_match(audit_path, &policy, &matched, "terminationFailed", &detail);
                }
            }
        }
    }
}

pub fn run_console(policy_path: &Path, audit_path: &Path) -> Result<(), String> {
    run_until(policy_path, audit_path, || false)
}

/// Handle one native process-create event. The child may already have exited;
/// its event PID, PPID, and name are sufficient to trace the live Agent parent.
pub fn handle_process_start(
    policy_path: &Path,
    audit_path: &Path,
    child_pid: u32,
    child_ppid: u32,
    child_name: String,
) -> Result<bool, String> {
    let policy = load_and_validate_policy(policy_path)?;
    if !policy.enabled {
        return Ok(false);
    }
    let current = windows_process::snapshot()?;
    let child = ProcessInfo {
        pid: child_pid,
        ppid: child_ppid,
        name: child_name,
        creation_ticks: 0,
        started_at: None,
        uptime_sec: 0,
    };
    let Some(matched) = evaluate_start(&child, &current, &policy) else {
        return Ok(false);
    };
    if policy.mode != "enforce" || matched.action != "terminateAgentTree" {
        audit_match(
            audit_path,
            &policy,
            &matched,
            "observed",
            "process-create event matched; no termination requested",
        )?;
        return Ok(true);
    }
    audit_match(
        audit_path,
        &policy,
        &matched,
        "terminationPending",
        "process-create event matched; termination requested",
    )?;
    thread::sleep(Duration::from_millis(u64::from(
        policy.termination.grace_period_ms,
    )));
    match terminate_agent_tree(&matched.agent) {
        Ok(detail) => {
            let _ = audit_match(audit_path, &policy, &matched, "terminated", &detail);
        }
        Err(detail) => {
            let _ = audit_match(audit_path, &policy, &matched, "terminationFailed", &detail);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::models::{GuardPolicy, GuardRule, TerminationPolicy};
    use crate::windows_process::ProcessInfo;

    use super::{canonical_executable, evaluate, evaluate_start};

    fn process(pid: u32, ppid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            ppid,
            name: name.to_owned(),
            creation_ticks: u64::from(pid) * 10,
            started_at: None,
            uptime_sec: 0,
        }
    }

    fn policy() -> GuardPolicy {
        GuardPolicy {
            version: 1,
            enabled: true,
            mode: "enforce".to_owned(),
            agent_names: vec!["codex.exe".to_owned()],
            rules: vec![GuardRule {
                id: "command.grep".to_owned(),
                enabled: true,
                executable: "grep".to_owned(),
                action: "terminateAgentTree".to_owned(),
                description: String::new(),
            }],
            termination: TerminationPolicy {
                grace_period_ms: 0,
                verify_process_identity: true,
                protected_process_behavior: "auditOnly".to_owned(),
            },
        }
    }

    #[test]
    fn canonicalizes_optional_exe_suffix() {
        assert_eq!(canonical_executable(" Grep.EXE "), "grep");
        assert_eq!(canonical_executable("grep"), "grep");
    }

    #[test]
    fn matches_new_child_through_intermediate_process() {
        let current = vec![
            process(10, 1, "codex.exe"),
            process(11, 10, "cmd.exe"),
            process(12, 11, "grep.exe"),
        ];
        let previous = HashSet::from([(10, 100), (11, 110)]);
        let matches = evaluate(&previous, &current, &policy());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].agent.pid, 10);
        assert_eq!(matches[0].child.pid, 12);
    }

    #[test]
    fn disabled_policy_never_matches() {
        let mut disabled = policy();
        disabled.enabled = false;
        assert!(evaluate(
            &HashSet::new(),
            &[process(10, 1, "codex.exe"), process(12, 10, "grep.exe")],
            &disabled
        )
        .is_empty());
    }

    #[test]
    fn event_matches_after_short_lived_child_exits() {
        let current = vec![process(10, 1, "codex.exe")];
        let child_event = process(12, 10, "grep.exe");
        let matched = evaluate_start(&child_event, &current, &policy()).expect("event match");
        assert_eq!(matched.agent.pid, 10);
        assert_eq!(matched.child.pid, 12);
    }
}
