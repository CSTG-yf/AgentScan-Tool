use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentSnapshot {
    pub captured_at: String,
    pub components: Vec<EnvironmentComponent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentComponent {
    pub id: &'static str,
    pub label: &'static str,
    pub state: &'static str,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub requires_elevation: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSnapshot {
    pub captured_at: String,
    pub processes: Vec<AgentProcess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub product: String,
    pub vendor: String,
    pub started_at: Option<String>,
    pub uptime_sec: u64,
    pub source: &'static str,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardPolicy {
    pub version: u8,
    pub enabled: bool,
    pub mode: String,
    pub agent_names: Vec<String>,
    pub rules: Vec<GuardRule>,
    #[serde(default)]
    pub file_guard: FileGuardPolicy,
    #[serde(default)]
    pub trace: TracePolicy,
    pub termination: TerminationPolicy,
}

impl GuardPolicy {
    pub fn normalize(mut self) -> Self {
        self.version = 2;
        self
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardRule {
    pub id: String,
    pub enabled: bool,
    pub executable: String,
    pub action: String,
    pub description: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminationPolicy {
    pub grace_period_ms: u32,
    pub verify_process_identity: bool,
    pub protected_process_behavior: String,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileGuardPolicy {
    pub enabled: bool,
    pub audit_roots: Vec<String>,
    pub blacklist: Vec<FileBlacklistRule>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileBlacklistRule {
    pub id: String,
    pub enabled: bool,
    pub path: String,
    pub match_kind: String,
    pub access: Vec<String>,
    pub action: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracePolicy {
    pub enabled: bool,
    pub capture_processes: bool,
    pub capture_file_reads: bool,
    pub capture_file_writes: bool,
    pub capture_file_creates: bool,
    pub capture_file_deletes: bool,
    pub retention_days: u16,
    pub max_database_mb: u32,
}

impl Default for TracePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            capture_processes: true,
            capture_file_reads: true,
            capture_file_writes: true,
            capture_file_creates: true,
            capture_file_deletes: true,
            retention_days: 30,
            max_database_mb: 256,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceEvent {
    pub id: i64,
    pub timestamp: String,
    pub event_type: String,
    pub source: String,
    pub agent_pid: u32,
    pub agent_executable: String,
    pub actor_pid: u32,
    pub actor_executable: String,
    pub path: Option<String>,
    pub action: Option<String>,
    pub outcome: String,
    pub detail: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceSnapshot {
    pub captured_at: String,
    pub database_path: String,
    pub events: Vec<TraceEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardAuditSnapshot {
    pub captured_at: String,
    pub path: String,
    pub events: Vec<GuardAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardAuditRecord {
    pub timestamp: String,
    pub event_type: String,
    pub outcome: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_executable: Option<String>,
}
