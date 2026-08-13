use std::collections::HashMap;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use quick_xml::escape::unescape;

use crate::models::{FileBlacklistRule, GuardPolicy};
use crate::trace_store::{self, NewTraceEvent};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const MAX_EVENTS_PER_POLL: usize = 512;

#[derive(Clone, Debug)]
struct SecurityFileEvent {
    record_id: u64,
    event_id: u16,
    process_id: u32,
    object_name: String,
    handle_id: String,
    access_mask: u32,
}

#[derive(Clone)]
struct PendingDelete {
    recorded_at: Instant,
    path: String,
    actor_name: String,
    agent_pid: u32,
    agent_name: String,
}

struct Attribution<'a> {
    actor_name: &'a str,
    agent_pid: u32,
    agent_name: &'a str,
}

fn xml_value(value: &str) -> String {
    unescape(value)
        .map(|text| text.into_owned())
        .unwrap_or_else(|_| value.to_owned())
}

fn between<'a>(value: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let offset = value.find(start)? + start.len();
    let tail = &value[offset..];
    Some(&tail[..tail.find(end)?])
}

fn data_value(event: &str, name: &str) -> Option<String> {
    let double = format!(r#"<Data Name="{name}">"#);
    let single = format!(r#"<Data Name='{name}'>"#);
    between(event, &double, "</Data>")
        .or_else(|| between(event, &single, "</Data>"))
        .map(xml_value)
}

fn parse_u64(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse().ok()
    }
}

fn parse_events(xml: &str) -> Vec<SecurityFileEvent> {
    xml.split("<Event ")
        .skip(1)
        .filter_map(|fragment| {
            let event = fragment.split_once("</Event>")?.0;
            let event_id = between(event, "<EventID", "</EventID>")?
                .rsplit_once('>')?
                .1
                .parse::<u16>()
                .ok()?;
            let record_id = between(event, "<EventRecordID>", "</EventRecordID>")?
                .parse::<u64>()
                .ok()?;
            let process_id = data_value(event, "ProcessId")
                .as_deref()
                .and_then(parse_u64)
                .and_then(|pid| u32::try_from(pid).ok())
                .unwrap_or(0);
            Some(SecurityFileEvent {
                record_id,
                event_id,
                process_id,
                object_name: data_value(event, "ObjectName").unwrap_or_default(),
                handle_id: data_value(event, "HandleId").unwrap_or_default(),
                access_mask: data_value(event, "AccessMask")
                    .as_deref()
                    .and_then(parse_u64)
                    .and_then(|mask| u32::try_from(mask).ok())
                    .unwrap_or(0),
            })
        })
        .collect()
}

fn query_events(after_record_id: Option<u64>) -> Result<Vec<SecurityFileEvent>, String> {
    let record_filter = after_record_id
        .map(|id| format!(" and (EventRecordID > {id})"))
        .unwrap_or_default();
    let query = format!("*[System[((EventID=4663) or (EventID=4660)){record_filter}]]");
    let count = if after_record_id.is_some() {
        MAX_EVENTS_PER_POLL
    } else {
        1
    };
    let output = Command::new("wevtutil.exe")
        .args([
            "qe",
            "Security",
            &format!("/q:{query}"),
            "/f:xml",
            if after_record_id.is_some() {
                "/rd:false"
            } else {
                "/rd:true"
            },
            &format!("/c:{count}"),
        ])
        .output()
        .map_err(|error| format!("launch wevtutil Security query: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "query Windows Security log failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(parse_events(&String::from_utf8_lossy(&output.stdout)))
}

fn normalized_path(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(['\\', '/'])
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn path_matches(path: &str, expected: &str, match_kind: &str) -> bool {
    let path = normalized_path(path);
    let expected = normalized_path(expected);
    path == expected
        || (match_kind == "subtree"
            && path
                .strip_prefix(&expected)
                .is_some_and(|tail| tail.starts_with('\\')))
}

fn classify_access(event: &SecurityFileEvent) -> &'static str {
    if event.event_id == 4660 {
        return "fileDelete";
    }
    let mask = event.access_mask;
    if mask & (0x0001_0000 | 0x0000_0040) != 0 {
        return "fileDeleteIntent";
    }
    if mask & (0x0000_0002 | 0x0000_0004) != 0 {
        if Path::new(&event.object_name)
            .metadata()
            .ok()
            .and_then(|metadata| metadata.created().ok())
            .and_then(|created| SystemTime::now().duration_since(created).ok())
            .is_some_and(|age| age <= Duration::from_secs(5))
        {
            return "fileCreate";
        }
        return "fileWrite";
    }
    "fileRead"
}

fn operation_name(event_type: &str) -> &str {
    match event_type {
        "fileRead" => "read",
        "fileWrite" => "write",
        "fileCreate" => "create",
        "fileDelete" | "fileDeleteIntent" => "delete",
        _ => "any",
    }
}

fn matching_blacklist<'a>(
    policy: &'a GuardPolicy,
    path: &str,
    event_type: &str,
) -> Option<&'a FileBlacklistRule> {
    let operation = operation_name(event_type);
    policy.file_guard.blacklist.iter().find(|rule| {
        rule.enabled
            && path_matches(path, &rule.path, &rule.match_kind)
            && rule
                .access
                .iter()
                .any(|access| access == "any" || access == operation)
    })
}

fn is_monitored(policy: &GuardPolicy, path: &str) -> bool {
    policy
        .file_guard
        .audit_roots
        .iter()
        .any(|root| path_matches(path, root, "subtree"))
        || policy
            .file_guard
            .blacklist
            .iter()
            .any(|rule| rule.enabled && path_matches(path, &rule.path, &rule.match_kind))
}

fn append_activity(
    event_type: &str,
    event: &SecurityFileEvent,
    attribution: &Attribution<'_>,
    action: Option<&str>,
    outcome: &str,
    detail: &str,
) -> Result<(), String> {
    trace_store::append(
        &trace_store::default_database_path(),
        &NewTraceEvent {
            event_type,
            source: "windows-security-audit",
            agent_pid: attribution.agent_pid,
            agent_executable: attribution.agent_name,
            actor_pid: event.process_id,
            actor_executable: attribution.actor_name,
            path: Some(&event.object_name),
            action,
            outcome,
            detail,
        },
    )
}

fn should_capture(policy: &GuardPolicy, event_type: &str) -> bool {
    policy.trace.enabled
        && match event_type {
            "fileRead" => policy.trace.capture_file_reads,
            "fileWrite" | "fileDeleteIntent" => policy.trace.capture_file_writes,
            "fileCreate" => policy.trace.capture_file_creates,
            "fileDelete" => policy.trace.capture_file_deletes,
            _ => false,
        }
}

pub fn run_until<F>(policy_path: &Path, audit_path: &Path, should_stop: F) -> Result<(), String>
where
    F: Fn() -> bool,
{
    let mut last_record_id = query_events(None)?
        .iter()
        .map(|event| event.record_id)
        .max()
        .unwrap_or(0);
    let mut pending_deletes = HashMap::<(u32, String), PendingDelete>::new();
    let mut last_retention = Instant::now();
    while !should_stop() {
        thread::sleep(POLL_INTERVAL);
        let policy = match crate::process_guard::load_and_validate_policy(policy_path) {
            Ok(policy) => policy,
            Err(_) => continue,
        };
        for event in query_events(Some(last_record_id))? {
            last_record_id = last_record_id.max(event.record_id);
            if event.event_id == 4660 {
                if let Some(pending) =
                    pending_deletes.remove(&(event.process_id, event.handle_id.clone()))
                {
                    let synthetic = SecurityFileEvent {
                        object_name: pending.path,
                        ..event
                    };
                    if should_capture(&policy, "fileDelete") {
                        let _ = append_activity(
                            "fileDelete",
                            &synthetic,
                            &Attribution {
                                actor_name: &pending.actor_name,
                                agent_pid: pending.agent_pid,
                                agent_name: &pending.agent_name,
                            },
                            None,
                            "observed",
                            "Windows event 4660 confirmed object deletion",
                        );
                    }
                }
                continue;
            }
            if event.process_id == 0
                || event.object_name.is_empty()
                || !is_monitored(&policy, &event.object_name)
            {
                continue;
            }
            let Some((actor, agent)) =
                crate::process_guard::attributed_process(event.process_id, &policy.agent_names)?
            else {
                continue;
            };
            let event_type = classify_access(&event);
            let attribution = Attribution {
                actor_name: &actor.name,
                agent_pid: agent.pid,
                agent_name: &agent.name,
            };
            if event_type == "fileDeleteIntent" && !event.handle_id.is_empty() {
                pending_deletes.insert(
                    (event.process_id, event.handle_id.clone()),
                    PendingDelete {
                        recorded_at: Instant::now(),
                        path: event.object_name.clone(),
                        actor_name: actor.name.clone(),
                        agent_pid: agent.pid,
                        agent_name: agent.name.clone(),
                    },
                );
            }
            let blacklist = policy
                .file_guard
                .enabled
                .then(|| matching_blacklist(&policy, &event.object_name, event_type))
                .flatten();
            if let Some(rule) = blacklist {
                append_activity(
                    "blacklistFileAccess",
                    &event,
                    &attribution,
                    Some("terminateAgentTree"),
                    "terminationPending",
                    &format!(
                        "blacklist rule {} matched {}",
                        rule.id,
                        operation_name(event_type)
                    ),
                )?;
                crate::process_guard::audit_service_event(
                    audit_path,
                    "fileTerminationPending",
                    &format!(
                        "rule={} agentPid={} actorPid={} path={}",
                        rule.id, agent.pid, actor.pid, event.object_name
                    ),
                )?;
                let result = if policy.mode == "enforce" {
                    crate::process_guard::terminate_agent_tree(&agent)
                } else {
                    Ok("observe mode; termination not executed".to_owned())
                };
                let (outcome, detail) = match result {
                    Ok(detail) if policy.mode == "enforce" => ("terminated", detail),
                    Ok(detail) => ("observed", detail),
                    Err(detail) => ("terminationFailed", detail),
                };
                let _ = append_activity(
                    "blacklistFileAccess",
                    &event,
                    &attribution,
                    Some("terminateAgentTree"),
                    outcome,
                    &detail,
                );
                let _ = crate::process_guard::audit_service_event(audit_path, outcome, &detail);
            } else if should_capture(&policy, event_type) {
                let _ = append_activity(
                    event_type,
                    &event,
                    &attribution,
                    None,
                    "observed",
                    &format!("accessMask=0x{:x}", event.access_mask),
                );
            }
        }
        pending_deletes
            .retain(|_, pending| pending.recorded_at.elapsed() < Duration::from_secs(30));
        if last_retention.elapsed() >= Duration::from_secs(3600) {
            let _ = trace_store::enforce_retention(
                &trace_store::default_database_path(),
                &policy.trace,
            );
            last_retention = Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{classify_access, parse_events, path_matches, SecurityFileEvent};

    #[test]
    fn parses_security_event_xml() {
        let xml = r#"<Events><Event xmlns='x'><System><EventID>4663</EventID><EventRecordID>42</EventRecordID></System><EventData><Data Name='ProcessId'>0x10</Data><Data Name='ProcessName'>C:\agent.exe</Data><Data Name='ObjectName'>C:\work\a.txt</Data><Data Name='HandleId'>0x20</Data><Data Name='AccessMask'>0x1</Data></EventData></Event></Events>"#;
        let events = parse_events(xml);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process_id, 16);
        assert_eq!(events[0].object_name, r"C:\work\a.txt");
    }

    #[test]
    fn subtree_match_respects_path_boundary() {
        assert!(path_matches(r"C:\work\a.txt", r"C:\work", "subtree"));
        assert!(!path_matches(r"C:\workspace\a.txt", r"C:\work", "subtree"));
    }

    #[test]
    fn access_mask_classifies_read_and_delete_intent() {
        let mut event = SecurityFileEvent {
            record_id: 1,
            event_id: 4663,
            process_id: 1,
            object_name: r"C:\missing".into(),
            handle_id: String::new(),
            access_mask: 1,
        };
        assert_eq!(classify_access(&event), "fileRead");
        event.access_mask = 0x10000;
        assert_eq!(classify_access(&event), "fileDeleteIntent");
    }
}
