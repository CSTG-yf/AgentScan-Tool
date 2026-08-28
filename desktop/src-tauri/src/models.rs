use serde::{Deserialize, Serialize};

fn vec_or_default<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSnapshot {
    pub captured_at: String,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub agents: Vec<AgentInventory>,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub processes: Vec<AgentProcess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub product: String,
    pub vendor: String,
    pub started_at: Option<String>,
    pub uptime_sec: u64,
    pub source: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentConfigRoot {
    pub path: String,
    pub kind: String,
    pub exists: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentEvidence {
    #[serde(default)]
    pub r#type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub weight: i32,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentInventory {
    #[serde(default)]
    pub id: String,
    #[serde(default, alias = "name")]
    pub product: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inventory_state: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default, alias = "runtime_status")]
    pub runtime_status: String,
    #[serde(default, alias = "discovery_status")]
    pub discovery_status: String,
    #[serde(default, alias = "primary_path")]
    pub primary_path: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub running: bool,
    #[serde(default)]
    pub process_count: usize,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub pids: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_pid: Option<u32>,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub processes: Vec<AgentProcess>,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub executable_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uptime_sec: Option<u64>,
    #[serde(default)]
    pub source: String,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub install_paths: Vec<String>,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub config_roots: Vec<AgentConfigRoot>,
    #[serde(default, deserialize_with = "vec_or_default")]
    pub evidence: Vec<AgentEvidence>,
    #[serde(default)]
    pub static_resource_count: u64,
    #[serde(default)]
    pub risk_resource_count: u64,
    #[serde(default)]
    pub critical_resource_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_static_scan_at: Option<String>,
    #[serde(default, alias = "first_seen_at", alias = "first_seen_scan_at")]
    pub first_seen_scan_at: Option<String>,
    #[serde(default, alias = "last_seen_at", alias = "last_seen_scan_at")]
    pub last_seen_scan_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_detection_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_attack_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_blocked_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_high_or_above_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_latest_at: Option<String>,
    #[serde(default)]
    pub description: String,
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

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanTaskSchedule {
    pub enabled: bool,
    pub interval_sec: u64,
}

impl ScanTaskSchedule {
    pub fn new(enabled: bool, interval_sec: u64) -> Self {
        Self {
            enabled,
            interval_sec,
        }
    }

    fn normalize(self, default_interval_sec: u64) -> Self {
        let interval_sec = if self.interval_sec == 0 {
            default_interval_sec
        } else {
            self.interval_sec
        };

        Self {
            enabled: self.enabled,
            interval_sec: interval_sec.clamp(3, 3600),
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanScheduleSettings {
    #[serde(default = "ScanScheduleSettings::default_version")]
    pub version: u8,
    #[serde(default = "ScanScheduleSettings::default_environment")]
    pub environment: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_agent_discovery")]
    pub agent_discovery: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_static_assets")]
    pub static_assets: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_behavior_trace")]
    pub behavior_trace: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_event_detection")]
    pub event_detection: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_process_guard_audit")]
    pub process_guard_audit: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_gateway_audit")]
    pub gateway_audit: ScanTaskSchedule,
    #[serde(default = "ScanScheduleSettings::default_range_status")]
    pub range_status: ScanTaskSchedule,
}

impl ScanScheduleSettings {
    fn default_version() -> u8 {
        1
    }

    fn default_environment() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 30)
    }

    fn default_agent_discovery() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 15)
    }

    fn default_static_assets() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 300)
    }

    fn default_behavior_trace() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 5)
    }

    fn default_event_detection() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 15)
    }

    fn default_process_guard_audit() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 10)
    }

    fn default_gateway_audit() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 10)
    }

    fn default_range_status() -> ScanTaskSchedule {
        ScanTaskSchedule::new(true, 30)
    }

    pub fn normalize(mut self) -> Self {
        self.version = 1;
        self.environment = self.environment.normalize(30);
        self.agent_discovery = self.agent_discovery.normalize(15);
        self.static_assets = self.static_assets.normalize(300);
        self.behavior_trace = self.behavior_trace.normalize(5);
        self.event_detection = self.event_detection.normalize(15);
        self.process_guard_audit = self.process_guard_audit.normalize(10);
        self.gateway_audit = self.gateway_audit.normalize(10);
        self.range_status = self.range_status.normalize(30);
        self
    }
}

impl Default for ScanScheduleSettings {
    fn default() -> Self {
        Self {
            version: 1,
            environment: Self::default_environment(),
            agent_discovery: Self::default_agent_discovery(),
            static_assets: Self::default_static_assets(),
            behavior_trace: Self::default_behavior_trace(),
            event_detection: Self::default_event_detection(),
            process_guard_audit: Self::default_process_guard_audit(),
            gateway_audit: Self::default_gateway_audit(),
            range_status: Self::default_range_status(),
        }
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticResourceScanSettings {
    #[serde(default = "StaticResourceScanSettings::default_version")]
    pub version: u8,
    #[serde(default = "StaticResourceScanSettings::default_realtime_enabled")]
    pub realtime_enabled: bool,
    #[serde(default = "StaticResourceScanSettings::default_rescan_enabled")]
    pub rescan_enabled: bool,
    #[serde(default = "StaticResourceScanSettings::default_debounce_ms")]
    pub debounce_ms: u64,
    #[serde(default = "StaticResourceScanSettings::default_skill_interval_min")]
    pub skill_interval_min: u64,
    #[serde(default = "StaticResourceScanSettings::default_plugin_interval_min")]
    pub plugin_interval_min: u64,
    #[serde(default = "StaticResourceScanSettings::default_mcp_interval_min")]
    pub mcp_interval_min: u64,
    #[serde(default = "StaticResourceScanSettings::default_prompt_interval_min")]
    pub prompt_interval_min: u64,
    #[serde(default = "StaticResourceScanSettings::default_credential_interval_min")]
    pub credential_interval_min: u64,
    #[serde(default = "StaticResourceScanSettings::default_environment_interval_min")]
    pub environment_interval_min: u64,
}

impl StaticResourceScanSettings {
    fn default_version() -> u8 {
        1
    }

    fn default_realtime_enabled() -> bool {
        true
    }

    fn default_rescan_enabled() -> bool {
        true
    }

    fn default_debounce_ms() -> u64 {
        500
    }

    fn default_skill_interval_min() -> u64 {
        15
    }

    fn default_plugin_interval_min() -> u64 {
        30
    }

    fn default_mcp_interval_min() -> u64 {
        10
    }

    fn default_prompt_interval_min() -> u64 {
        15
    }

    fn default_credential_interval_min() -> u64 {
        5
    }

    fn default_environment_interval_min() -> u64 {
        30
    }

    pub fn normalize(mut self) -> Self {
        self.version = 1;
        self.debounce_ms = self.debounce_ms.clamp(100, 10_000);
        self.skill_interval_min = self.skill_interval_min.clamp(1, 1_440);
        self.plugin_interval_min = self.plugin_interval_min.clamp(1, 1_440);
        self.mcp_interval_min = self.mcp_interval_min.clamp(1, 1_440);
        self.prompt_interval_min = self.prompt_interval_min.clamp(1, 1_440);
        self.credential_interval_min = self.credential_interval_min.clamp(1, 1_440);
        self.environment_interval_min = self.environment_interval_min.clamp(1, 1_440);
        self
    }
}

impl Default for StaticResourceScanSettings {
    fn default() -> Self {
        Self {
            version: Self::default_version(),
            realtime_enabled: Self::default_realtime_enabled(),
            rescan_enabled: Self::default_rescan_enabled(),
            debounce_ms: Self::default_debounce_ms(),
            skill_interval_min: Self::default_skill_interval_min(),
            plugin_interval_min: Self::default_plugin_interval_min(),
            mcp_interval_min: Self::default_mcp_interval_min(),
            prompt_interval_min: Self::default_prompt_interval_min(),
            credential_interval_min: Self::default_credential_interval_min(),
            environment_interval_min: Self::default_environment_interval_min(),
        }
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TraceSnapshot {
    pub captured_at: String,
    pub database_path: String,
    pub events: Vec<TraceEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardAuditSnapshot {
    pub captured_at: String,
    pub path: String,
    pub events: Vec<GuardAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayAuditSnapshot {
    pub captured_at: String,
    pub source: String,
    pub events: Vec<GatewayAuditRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Deserialize, Serialize)]
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
