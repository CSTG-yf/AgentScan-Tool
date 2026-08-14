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
    pub product: &'static str,
    pub vendor: &'static str,
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
    pub termination: TerminationPolicy,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connector: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_app: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAuditSnapshot {
    pub captured_at: String,
    pub source: String,
    pub events: Vec<GatewayAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAuditRecord {
    pub timestamp: String,
    pub action: String,
    pub target: String,
    pub actor: String,
    pub details: String,
    pub severity: String,
    pub trace_id: String,
    pub session_id: String,
    pub agent_name: String,
    pub connector: String,
    pub destination_app: String,
    pub tool_name: String,
    pub stage: String,
    pub prompt: String,
    pub model: String,
    pub mcp_server: String,
    pub decision: String,
    pub reason: String,
    pub latency_ms: Option<u64>,
}
