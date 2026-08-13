use std::fs;
use std::path::{Path, PathBuf};

use chrono::{Duration, Utc};
use rusqlite::{params, Connection, OpenFlags};

use crate::models::{TraceEvent, TracePolicy};

pub struct NewTraceEvent<'a> {
    pub event_type: &'a str,
    pub source: &'a str,
    pub agent_pid: u32,
    pub agent_executable: &'a str,
    pub actor_pid: u32,
    pub actor_executable: &'a str,
    pub path: Option<&'a str>,
    pub action: Option<&'a str>,
    pub outcome: &'a str,
    pub detail: &'a str,
}

pub fn default_database_path() -> PathBuf {
    let (policy, _) = crate::process_guard_service::default_paths();
    policy
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\ProgramData\DefenseClaw"))
        .join("trace")
        .join("agent-trace.db")
}

fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create trace directory {}: {error}", parent.display()))?;
    }
    let connection = Connection::open(path)
        .map_err(|error| format!("open trace database {}: {error}", path.display()))?;
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             CREATE TABLE IF NOT EXISTS trace_events (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               timestamp TEXT NOT NULL,
               event_type TEXT NOT NULL,
               source TEXT NOT NULL,
               agent_pid INTEGER NOT NULL,
               agent_executable TEXT NOT NULL,
               actor_pid INTEGER NOT NULL,
               actor_executable TEXT NOT NULL,
               path TEXT,
               action TEXT,
               outcome TEXT NOT NULL,
               detail TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_trace_timestamp ON trace_events(timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_trace_agent ON trace_events(agent_pid, timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_trace_path ON trace_events(path, timestamp DESC);
             CREATE INDEX IF NOT EXISTS idx_trace_type ON trace_events(event_type, timestamp DESC);",
        )
        .map_err(|error| format!("initialize trace database {}: {error}", path.display()))?;
    Ok(connection)
}

pub fn append(path: &Path, event: &NewTraceEvent<'_>) -> Result<(), String> {
    let connection = open(path)?;
    connection
        .execute(
            "INSERT INTO trace_events
             (timestamp, event_type, source, agent_pid, agent_executable, actor_pid,
              actor_executable, path, action, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                Utc::now().to_rfc3339(),
                event.event_type,
                event.source,
                event.agent_pid,
                event.agent_executable,
                event.actor_pid,
                event.actor_executable,
                event.path,
                event.action,
                event.outcome,
                event.detail,
            ],
        )
        .map_err(|error| format!("append trace event: {error}"))?;
    Ok(())
}

pub fn query(path: &Path, limit: usize) -> Result<Vec<TraceEvent>, String> {
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| format!("open trace database read-only {}: {error}", path.display()))?;
    let mut statement = connection
        .prepare(
            "SELECT id, timestamp, event_type, source, agent_pid, agent_executable,
                    actor_pid, actor_executable, path, action, outcome, detail
             FROM trace_events ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|error| format!("prepare trace query: {error}"))?;
    let rows = statement
        .query_map([limit.clamp(1, 1000)], |row| {
            Ok(TraceEvent {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                event_type: row.get(2)?,
                source: row.get(3)?,
                agent_pid: row.get(4)?,
                agent_executable: row.get(5)?,
                actor_pid: row.get(6)?,
                actor_executable: row.get(7)?,
                path: row.get(8)?,
                action: row.get(9)?,
                outcome: row.get(10)?,
                detail: row.get(11)?,
            })
        })
        .map_err(|error| format!("query trace database: {error}"))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("read trace row: {error}"))
}

pub fn enforce_retention(path: &Path, policy: &TracePolicy) -> Result<(), String> {
    if !path.is_file() {
        return Ok(());
    }
    let connection = open(path)?;
    let cutoff = (Utc::now() - Duration::days(i64::from(policy.retention_days))).to_rfc3339();
    connection
        .execute("DELETE FROM trace_events WHERE timestamp < ?1", [cutoff])
        .map_err(|error| format!("prune expired trace events: {error}"))?;
    let max_bytes = u64::from(policy.max_database_mb) * 1024 * 1024;
    if fs::metadata(path).map(|meta| meta.len()).unwrap_or(0) > max_bytes {
        connection
            .execute(
                "DELETE FROM trace_events WHERE id IN
             (SELECT id FROM trace_events ORDER BY id ASC LIMIT
              MAX(1, (SELECT COUNT(*) FROM trace_events) / 10))",
                [],
            )
            .map_err(|error| format!("prune oversized trace database: {error}"))?;
        connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|error| format!("checkpoint trace database: {error}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{append, query, NewTraceEvent};

    #[test]
    fn stores_and_queries_trace_events() {
        let path = std::env::temp_dir().join(format!(
            "defenseclaw-trace-test-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        append(
            &path,
            &NewTraceEvent {
                event_type: "fileRead",
                source: "test",
                agent_pid: 10,
                agent_executable: "codex.exe",
                actor_pid: 11,
                actor_executable: "cmd.exe",
                path: Some(r"C:\secret.txt"),
                action: None,
                outcome: "observed",
                detail: "test",
            },
        )
        .expect("append");
        let events = query(&path, 10).expect("query");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path.as_deref(), Some(r"C:\secret.txt"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
}
