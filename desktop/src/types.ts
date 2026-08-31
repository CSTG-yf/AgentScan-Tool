export type ComponentState = "ready" | "degraded" | "stopped" | "missing" | "unknown";

export interface EnvironmentComponent {
  id: "gateway" | "docker" | "agentrange" | "processGuard";
  label: string;
  state: ComponentState;
  detail: string;
  version?: string;
  requiresElevation?: boolean;
}

export interface EnvironmentSnapshot {
  capturedAt: string;
  components: EnvironmentComponent[];
}

export interface AgentProcess {
  pid: number;
  ppid: number;
  name: string;
  product: string;
  vendor: string;
  startedAt?: string;
  uptimeSec: number;
  source: "native" | "gateway";
}

export interface AgentConfigRoot {
  path: string;
  kind: string;
  exists: boolean;
}

export type AgentStatus = "running" | "stopped" | "unknown";

export interface AgentEvidence {
  type: string;
  value: string;
  weight: number;
}

export interface AgentInventory {
  id: string;
  product: string;
  vendor: string;
  kind: string;
  inventoryState?: string;
  runtimeStatus: AgentStatus;
  discoveryStatus?: string;
  primaryPath?: string;
  version?: string;
  status: AgentStatus;
  running: boolean;
  processCount: number;
  pids: number[];
  primaryPid?: number;
  processes?: AgentProcess[];
  executableNames: string[];
  startedAt?: string;
  uptimeSec?: number;
  source: string;
  installPaths?: string[];
  configRoots: AgentConfigRoot[];
  evidence?: AgentEvidence[];
  staticResourceCount: number;
  riskResourceCount: number;
  criticalResourceCount: number;
  lastStaticScanAt?: string;
  firstSeenScanAt?: string;
  lastSeenScanAt?: string;
  runtimeDetectionCount?: number;
  runtimeAttackCount?: number;
  runtimeBlockedCount?: number;
  runtimeHighOrAboveCount?: number;
  runtimeLatestAt?: string;
  description: string;
}

export interface AgentSnapshot {
  capturedAt: string;
  agents: AgentInventory[];
  processes: AgentProcess[];
  total?: number;
  page?: number;
  pageSize?: number;
  warning?: string;
}

export interface CatalogSource {
  id: string;
  title: string;
  url: string;
}

export interface AgentKnowledge {
  id: string;
  product: string;
  vendor: string;
  kind: "terminal-agent" | "editor-agent" | "desktop-agent" | "agent-platform";
  launchCommands: string[];
  windowsProcessNames: string[];
  relatedProcessNames: string[];
  guardRootEligible: boolean;
  confidence: "high" | "medium" | "low";
  notes?: string;
  sourceRefs: string[];
}

export interface CommandKnowledge {
  id: string;
  category: "shell" | "search" | "version-control" | "network" | "runtime" | "package-manager" | "build" | "container-cloud" | "filesystem" | "system-control";
  commandNames: string[];
  windowsProcessNames: string[];
  processVisibility: "exact-image" | "host-process" | "mixed";
  riskLevel: "low" | "medium" | "high" | "critical";
  recommendedAction: "observe" | "review" | "restrict";
  commonUses: string[];
  notes?: string;
}

export interface AgentRuntimeCatalog {
  version: 1;
  updatedAt: string;
  sources: CatalogSource[];
  agents: AgentKnowledge[];
  commands: CommandKnowledge[];
}

export type GuardMode = "observe" | "enforce";
export type RangeMode = "baseline" | "observe" | "action";

export interface GuardRule {
  id: string;
  enabled: boolean;
  executable: string;
  action: "audit" | "terminateAgentTree";
  description?: string;
}

export interface GuardPolicy {
  version: 2;
  enabled: boolean;
  mode: GuardMode;
  agentNames: string[];
  rules: GuardRule[];
  fileGuard: {
    enabled: boolean;
    auditRoots: string[];
    blacklist: FileBlacklistRule[];
  };
  trace: TracePolicy;
  termination: {
    gracePeriodMs: number;
    verifyProcessIdentity: true;
    protectedProcessBehavior: "auditOnly";
  };
}

export interface FileBlacklistRule {
  id: string;
  enabled: boolean;
  path: string;
  matchKind: "exact" | "subtree";
  access: Array<"read" | "write" | "create" | "delete" | "any">;
  action: "terminateAgentTree";
  description?: string;
}

export interface TracePolicy {
  enabled: boolean;
  captureProcesses: boolean;
  captureFileReads: boolean;
  captureFileWrites: boolean;
  captureFileCreates: boolean;
  captureFileDeletes: boolean;
  retentionDays: number;
  maxDatabaseMb: number;
}

export interface AgentTraceEvent {
  id: number;
  timestamp: string;
  eventType: "agentProcessStart" | "agentCommandStart" | "fileRead" | "fileWrite" | "fileCreate" | "fileDelete" | "blacklistFileAccess" | string;
  source: string;
  agentPid: number;
  agentExecutable: string;
  actorPid: number;
  actorExecutable: string;
  path?: string;
  action?: string;
  outcome: string;
  detail: string;
}

export interface AgentTraceSnapshot {
  capturedAt: string;
  databasePath: string;
  events: AgentTraceEvent[];
  warning?: string;
}

export interface RangeStatus {
  configured: boolean;
  root: string;
  composeFile: string;
  adapterComposeFile: string;
  mode: RangeMode;
  dockerAvailable: boolean;
  runningServices: string[];
  state: "unconfigured" | "invalid" | "dockerUnavailable" | "stopped" | "running";
  detail: string;
}

export interface RangeReplayStatus {
  running: boolean;
  command: string;
  scenario: string;
  startedAt: string;
  finishedAt?: string;
  pid?: number;
  completed: number;
  total: number;
  remaining: number;
  exitCode?: number;
  error?: string;
  detail: string;
  log: string[];
}

export interface GuardAuditEvent {
  timestamp: string;
  eventType: "agent-command-rule-matched" | "process-guard-service" | string;
  outcome: string;
  detail: string;
  mode?: GuardMode;
  ruleId?: string;
  action?: string;
  childPid?: number;
  childExecutable?: string;
  agentPid?: number;
  agentExecutable?: string;
  traceId?: string;
  sessionId?: string;
  agentName?: string;
  connector?: string;
  stage?: string;
  source?: string;
  destinationApp?: string;
  toolName?: string;
  mcpServer?: string;
  prompt?: string;
  model?: string;
  decision?: string;
  severity?: string;
  reason?: string;
  latencyMs?: number;
  rawRef?: string;
}

export interface GuardAuditSnapshot {
  capturedAt: string;
  path: string;
  events: GuardAuditEvent[];
  warning?: string;
}

export interface GatewayAuditEvent {
  timestamp: string;
  action: string;
  target: string;
  actor: string;
  details: string;
  severity: string;
  traceId: string;
  sessionId: string;
  agentName: string;
  connector: string;
  destinationApp: string;
  toolName: string;
  stage: string;
  prompt: string;
  model: string;
  mcpServer: string;
  decision: string;
  reason: string;
  latencyMs?: number;
}

export interface GatewayAuditSnapshot {
  capturedAt: string;
  source: string;
  events: GatewayAuditEvent[];
  warning?: string;
}

export type EventKind = "security" | "attack";
export type EventStatus = "detected" | "audited" | "blocked" | "pending";
export type EventFilter = "all" | EventKind;

/** Phase-2 structured runtime detection (runtime_detections row). */
export interface RuntimeDetection {
  detectionId: string;
  agentId?: string;
  agentName?: string;
  sessionId?: string;
  traceId?: string;
  type?: string;
  detectionType: string;
  category: string;
  severity: string;
  confidence?: number;
  ruleId?: string;
  status: string;
  title: string;
  description?: string;
  detail?: string;
  remediation?: string;
  source?: string;
  createdAt?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
  eventCount?: number;
  attributes?: Record<string, unknown>;
}

export interface RuntimeSecuritySummary {
  totalDetections: number;
  securityDetections: number;
  attackDetections: number;
  blocked: number;
  highOrAbove: number;
  coveredAgents: number;
  latestAt?: string;
  windowStart?: string;
  windowEnd?: string;
}

export interface RuntimeSecurityAgent {
  agentId: string;
  agentName: string;
  agentType: string;
  detectionCount: number;
  attackCount: number;
  blockedCount: number;
  highOrAboveCount: number;
  latestAt?: string;
  runtimeStatus: string;
}

export interface RuntimeDetectionListSummary {
  total: number;
  attack: number;
  blocked: number;
  critical: number;
  high: number;
  open: number;
}

export interface RuntimeDetectionListResponse {
  total: number;
  items: RuntimeDetection[];
  detections?: RuntimeDetection[];
  summary?: RuntimeDetectionListSummary;
  count: number;
  limit: number;
  offset: number;
}

export interface RuntimeDetectionListQuery {
  agentId?: string;
  category?: string;
  severity?: string;
  status?: string;
  source?: string;
  keyword?: string;
  traceId?: string;
  sessionId?: string;
  detectionType?: string;
  limit?: number;
  offset?: number;
  sort?: string;
}

export interface RuntimeDetectionEvidenceEvent {
  detectionId?: string;
  eventId: number;
  eventType: string;
  eventSource?: string;
  eventCategory?: string;
  timestamp?: string;
  sequence?: number;
  role?: string;
  agentId?: string;
  agentName?: string;
  sessionId?: string;
  traceId?: string;
  toolName?: string;
  target?: string;
  operation?: string;
  outcome?: string;
  severity?: string;
  detail?: string;
  attributes?: Record<string, unknown>;
}

export interface RuntimeDetectionDetail {
  detection: RuntimeDetection;
  evidence?: RuntimeDetectionEvidenceEvent[];
  agent?: { agentId?: string; name?: string };
  runtimeSession?: { sessionId?: string; traceId?: string };
  trace?: { sessionId?: string; traceId?: string };
}

export interface RuntimeEventsTimelineBucket {
  time: string;
  bucket: string;
  total: number;
  prompt: number;
  tool: number;
  process: number;
  file: number;
  network: number;
  content: number;
}

export interface RuntimeEventsTimelineResponse {
  buckets: RuntimeEventsTimelineBucket[];
}

export interface RuntimeEventsTimelineQuery {
  agentId?: string;
  bucket?: string;
  startTime?: string;
  endTime?: string;
  sessionId?: string;
  traceId?: string;
}

export type ChainNodeKind = "entry" | "agent" | "llm" | "tool" | "mcp" | "data" | "network" | "defense";

export interface AttackChainStep {
  id: string;
  order: number;
  occurredAt: string;
  title: string;
  stage: string;
  kind: ChainNodeKind;
  severity: StaticRisk;
  actor: string;
  prompt: string;
  tool: string;
  resource: string;
  evidence: string;
  decision: string;
  stack: string[];
  sourceEventId: string;
  source: string;
  traceId: string;
  sessionId: string;
}

export interface ChainEvidenceRow {
  key: string;
  index: number;
  occurredAt: string;
  stage: string;
  agent: string;
  tool: string;
  resource: string;
  decision: string;
  evidence: string;
  sourceEventId: string;
  source: string;
}

export interface AttackChain {
  id: string;
  traceId: string;
  sessionId: string;
  agent: string;
  runtime: string;
  category: string;
  risk: StaticRisk;
  status: EventStatus;
  startedAt: string;
  endedAt: string;
  summary: string;
  stepCount: number;
  evidenceCount: number;
  sources: string[];
  steps: AttackChainStep[];
  evidence: ChainEvidenceRow[];
  /** Phase-3 links to the structured detection and policy decision. */
  detectionId?: string;
  decisionId?: string;
}

export interface AttackChainSnapshot {
  capturedAt: string;
  source: string;
  chains: AttackChain[];
  warning?: string;
}

/** Runtime Security Mode: observe records would-block, action enforces. */
export type RuntimeSecurityMode = "observe" | "action";

export type RuntimeDecisionVerdict = "ALLOW" | "AUDIT" | "ALERT" | "CONFIRM" | "BLOCK";

/** Phase-3 unified policy decision (runtime_decisions row). */
export interface RuntimeDecision {
  decisionId: string;
  detectionId?: string;
  agentId?: string;
  agentName?: string;
  sessionId?: string;
  traceId?: string;
  decision: string;
  riskScore?: number;
  confidence?: number;
  policyId?: string;
  reason?: string;
  enforcementPoint?: string;
  mode?: string;
  wouldBlock?: boolean;
  createdAt?: string;
}

/** One decision row paired with its originating detection. */
export interface RuntimeDecisionRow {
  decision: RuntimeDecision;
  detection?: RuntimeDetection;
}

export interface RuntimeDecisionSummary {
  total: number;
  block: number;
  confirm: number;
  alert: number;
  audit: number;
  allow: number;
  wouldBlock: number;
}

export interface RuntimeDecisionListResponse {
  decisions: RuntimeDecisionRow[];
  summary?: RuntimeDecisionSummary;
  count: number;
}

/** Phase-3 executed response (runtime_response_actions row). */
export interface RuntimeResponseAction {
  responseId: string;
  decisionId?: string;
  actionType: string;
  executor?: string;
  target?: string;
  status: string;
  result?: string;
  executedAt?: string;
}

/** The behavior event behind one evidence link. */
export interface EvidenceBehaviorEvent {
  id?: number;
  timestamp?: string;
  eventType?: string;
  eventSource?: string;
  agentName?: string;
  toolName?: string;
  target?: string;
  outcome?: string;
  detail?: string;
}

export interface DecisionEvidenceEvent {
  eventId?: number;
  role?: string;
  sequence?: number;
  event?: EvidenceBehaviorEvent;
}

export interface RuntimeDecisionDetail {
  decision: RuntimeDecision;
  responses?: RuntimeResponseAction[];
  detection?: RuntimeDetection;
  evidence?: DecisionEvidenceEvent[];
}

export interface RuntimeEnforcementRecord {
  id: string;
  kind?: string;
  target?: string;
  host?: string;
  status?: string;
  reason?: string;
  source?: string;
  decision_id?: string;
  response_id?: string;
  action_type?: string;
  executor?: string;
  result?: string;
  added_at?: string;
  expires_at?: string;
}

export interface RuntimeEnforcementListResponse {
  items: RuntimeEnforcementRecord[];
  total?: number;
  count?: number;
}

export interface RuntimeEnforcementResult {
  status?: string;
  id?: string;
  removed?: number;
  decision?: RuntimeDecision;
  response?: RuntimeResponseAction;
  responses?: RuntimeResponseAction[];
  items?: RuntimeEnforcementRecord[];
}

export interface ScanTaskSchedule {
  enabled: boolean;
  intervalSec: number;
}

export interface ScanScheduleSettings {
  version: 1;
  environment: ScanTaskSchedule;
  agentDiscovery: ScanTaskSchedule;
  staticAssets: ScanTaskSchedule;
  behaviorTrace: ScanTaskSchedule;
  eventDetection: ScanTaskSchedule;
  processGuardAudit: ScanTaskSchedule;
  gatewayAudit: ScanTaskSchedule;
  rangeStatus: ScanTaskSchedule;
}

export type ScanTaskKey = Exclude<keyof ScanScheduleSettings, "version">;

export interface StaticResourceScanSettings {
  version: 1;
  realtimeEnabled: boolean;
  rescanEnabled: boolean;
  debounceMs: number;
  skillIntervalMin: number;
  pluginIntervalMin: number;
  mcpIntervalMin: number;
  promptIntervalMin: number;
  credentialIntervalMin: number;
  environmentIntervalMin: number;
}

export type StaticRisk = "critical" | "high" | "medium" | "low" | "info";
export type StaticResourceType = "Config" | "Skills" | "MCP" | "Plugin" | "Prompt" | "Credential" | "Environment";
export type StaticResourceStatus = "discovered" | "reviewed" | "changed" | "ignored";

export interface StaticResourceFinding {
  id: string;
  title: string;
  severity: StaticRisk;
  description: string;
  location: string;
  evidence: string;
  recommendation: string;
}

export interface StaticResourceRelation {
  id: string;
  name: string;
  type: StaticResourceType;
  relation: string;
  risk: StaticRisk;
}

// ---------------------------------------------------------------------------
// Rule-driven static resource API (/api/v1/static-resources*). Field names
// mirror the Go backend's DTO json tags (snake_case); the backend owns the
// shapes so database changes never ripple into the frontend.
// ---------------------------------------------------------------------------

export interface StaticResourceAgentSummary {
  agent_id: string;
  agent_type: string;
  name: string;
  kind: string;
  resource_count: number;
  risk_resource_count: number;
  malicious_resource_count: number;
  critical_resource_count: number;
}

export interface StaticResourceAgentsResponse {
  items: StaticResourceAgentSummary[];
}

export interface StaticResourceTypeSummary {
  resource_type: string;
  count: number;
  risk_count: number;
  malicious_count: number;
}

export interface StaticResourceSummaryResponse {
  agent: {
    agent_id: string;
    name: string;
    agent_type?: string;
    kind?: string;
    resource_count?: number;
    risk_resource_count?: number;
    malicious_resource_count?: number;
    critical_resource_count?: number;
  };
  total_resources: number;
  resource_type_count: number;
  risk_resource_count: number;
  malicious_resource_count: number;
  critical_resource_count: number;
  by_type: StaticResourceTypeSummary[];
}

export interface StaticResourceListItem {
  resource_id: string;
  agent_id: string;
  resource_type: string;
  name: string;
  path: string;
  risk_level: string;
  malicious: boolean;
  finding_count: number;
  status: string;
  last_scan_at?: string;
  updated_at: string;
}

export interface StaticResourceListResponse {
  total: number;
  page: number;
  page_size: number;
  items: StaticResourceListItem[];
}

export interface StaticResourceDetailResponse {
  resource_id: string;
  agent_id: string;
  resource_type: string;
  name: string;
  path: string;
  risk_level: string;
  malicious: boolean;
  finding_count: number;
  status: string;
  last_scan_at?: string;
  updated_at: string;
  agent: { agent_id: string; name: string; agent_type?: string };
  content_hash?: string;
  first_seen_at?: string;
  scan_status: string;
  size?: number;
  permission?: string;
  resource_rule?: { rule_id: number; name: string };
  scan_profile?: { profile_id: number; name: string };
  scan_capabilities?: StaticResourceScanCapability[];
}

export interface StaticResourceScanCapability {
  capability_id: number;
  key?: string;
  name: string;
  scanner?: string;
  description?: string;
  enabled: boolean;
}

export interface StaticResourceScanHistoryItem {
  scan_id: string;
  scanner?: string;
  scanned_at?: string;
  finding_count: number;
  max_severity?: string;
  duration_ms?: number;
  verdict?: string;
}

export interface StaticResourceScanHistoryResponse {
  resource_id: string;
  total: number;
  items: StaticResourceScanHistoryItem[];
}

export interface StaticResourceStatusUpdateResponse {
  resource_id: string;
  status: string;
}

export interface StaticResourceFindingItem {
  finding_id: string;
  rule_id?: string;
  category?: string;
  severity: string;
  title: string;
  description?: string;
  evidence?: string;
  location?: string;
  line_number?: number;
  scanner?: string;
}

export interface StaticResourceFindingsResponse {
  resource_id: string;
  scan_id: string;
  scanned_at?: string;
  scanner?: string;
  summary: Record<string, number>;
  items: StaticResourceFindingItem[];
}

export interface StaticResourceContentFile {
  name: string;
  path: string;
  size: number;
  type: string;
}

export interface StaticResourceContentResponse {
  resource_id: string;
  type: "file" | "directory" | "virtual";
  content_type?: string;
  language?: string;
  truncated?: boolean;
  content?: string;
  redacted?: boolean;
  redaction_count?: number;
  files?: StaticResourceContentFile[];
}

export interface StaticResourceRelationItem {
  resource_id: string;
  name: string;
  resource_type: string;
  relation_type: string;
  risk_level: string;
  malicious: boolean;
}

export interface StaticResourceRelationsResponse {
  items: StaticResourceRelationItem[];
}

export interface StaticResourceScanAccepted {
  resource_id?: string;
  agent_id?: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Agent governance API (/api/v1/agent-governance*).
// ---------------------------------------------------------------------------

export interface GovernancePage<T> {
  total: number;
  page: number;
  page_size: number;
  items: T[];
}

export interface GovernanceAgentType {
  id: number;
  type_key: string;
  name: string;
  vendor: string;
  kind: string;
  runtime: string;
  description: string;
  enabled: boolean;
  deleted: boolean;
  created_at: string;
  updated_at: string;
  agent_count: number;
  discovery_rule_count: number;
  resource_rule_count: number;
}

export interface GovernanceAgentTypeInput {
  type_key?: string;
  name?: string;
  vendor?: string;
  kind?: string;
  runtime?: string;
  description?: string;
  enabled?: boolean;
}

export interface GovernanceDiscoveryCondition {
  id: number;
  rule_id: number;
  condition_type: string;
  field: string;
  operator: string;
  value: string;
  weight: number;
  required: boolean;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceDiscoveryConditionInput {
  condition_type?: string;
  field?: string;
  operator?: string;
  value?: string;
  weight?: number;
  required?: boolean;
  enabled?: boolean;
}

export interface GovernanceDiscoveryRule {
  id: number;
  agent_type_id: number;
  agent_type_key: string;
  agent_type_name: string;
  rule_name: string;
  threshold: number;
  enabled: boolean;
  condition_count: number;
  conditions?: GovernanceDiscoveryCondition[];
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceDiscoveryRuleInput {
  agent_type_id?: number;
  rule_name?: string;
  threshold?: number;
  enabled?: boolean;
  conditions?: GovernanceDiscoveryConditionInput[];
}

export interface GovernanceResourceRule {
  id: number;
  agent_type_id: number;
  agent_type_key: string;
  agent_type_name: string;
  name: string;
  resource_type: string;
  path_pattern: string;
  enumeration_mode: string;
  scan_profile_id?: number;
  scan_profile_name?: string;
  pre_scan_profile_id?: number;
  pre_scan_profile_name?: string;
  post_scan_profile_id?: number;
  post_scan_profile_name?: string;
  enabled: boolean;
  priority: number;
  resource_count: number;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceResourceRuleInput {
  agent_type_id?: number;
  name?: string;
  resource_type?: string;
  path_pattern?: string;
  enumeration_mode?: string;
  scan_profile_id?: number;
  pre_scan_profile_id?: number;
  post_scan_profile_id?: number;
  enabled?: boolean;
  priority?: number;
}

export interface GovernancePreScanRule {
  id: number;
  profile_id: number;
  rule_name: string;
  priority: number;
  agent_type_id?: number;
  agent_type_key?: string;
  agent_type_name?: string;
  resource_type: string;
  path_pattern: string;
  source_trust: string;
  decision: string;
  install_action: string;
  file_action: string;
  runtime_action: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernancePreScanRuleInput {
  rule_name?: string;
  priority?: number;
  agent_type_id?: number;
  resource_type?: string;
  path_pattern?: string;
  source_trust?: string;
  decision?: string;
  install_action?: string;
  file_action?: string;
  runtime_action?: string;
  enabled?: boolean;
}

export interface GovernancePreScanProfile {
  id: number;
  profile_key: string;
  name: string;
  description: string;
  enabled: boolean;
  is_default: boolean;
  rule_count: number;
  resource_rule_count: number;
  created_at?: string;
  updated_at?: string;
}

export interface GovernancePreScanProfileInput {
  profile_key?: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  is_default?: boolean;
  rules?: GovernancePreScanRuleInput[];
}

export interface GovernancePostScanRule {
  id: number;
  profile_id: number;
  rule_name: string;
  priority: number;
  resource_type: string;
  severity: string;
  risk_level: string;
  malicious: boolean;
  finding_category: string;
  scanner: string;
  decision: string;
  install_action: string;
  file_action: string;
  runtime_action: string;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernancePostScanRuleInput {
  rule_name?: string;
  priority?: number;
  resource_type?: string;
  severity?: string;
  risk_level?: string;
  malicious?: boolean;
  finding_category?: string;
  scanner?: string;
  decision?: string;
  install_action?: string;
  file_action?: string;
  runtime_action?: string;
  enabled?: boolean;
}

export interface GovernancePostScanProfile {
  id: number;
  profile_key: string;
  name: string;
  description: string;
  enabled: boolean;
  is_default: boolean;
  rule_count: number;
  resource_rule_count: number;
  created_at?: string;
  updated_at?: string;
}

export interface GovernancePostScanProfileInput {
  profile_key?: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  is_default?: boolean;
  rules?: GovernancePostScanRuleInput[];
}

export interface GovernanceProfileCapability {
  profile_id?: number;
  capability_id: number;
  capability_key: string;
  name?: string;
  scanner_name?: string;
  priority: number;
  enabled: boolean;
  config_json?: string;
  description?: string;
}

export interface GovernanceScanProfile {
  id: number;
  name: string;
  resource_type: string;
  enabled: boolean;
  description: string;
  capability_count: number;
  rule_count: number;
  resource_count: number;
  capabilities?: GovernanceProfileCapability[];
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceScanProfileInput {
  name?: string;
  resource_type?: string;
  description?: string;
  enabled?: boolean;
  capabilities?: Array<{
    capability_id?: number;
    capability_key?: string;
    priority?: number;
    enabled?: boolean;
    config_json?: string;
  }>;
}

export interface GovernanceScanCapability {
  id: number;
  capability_key: string;
  name: string;
  scanner_name: string;
  enabled: boolean;
  description: string;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceActionState {
  file?: string;
  runtime?: string;
  install?: string;
}

export interface GovernanceResourceAction {
  id: string;
  target_type: string;
  target_name: string;
  connector: string;
  source_path: string;
  actions: GovernanceActionState;
  reason: string;
  updated_at: string;
}

export interface GovernanceResourceActionInput {
  target_type?: string;
  target_name?: string;
  connector?: string;
  source_path?: string;
  actions?: GovernanceActionState;
  reason?: string;
}

export interface GovernanceAdmissionMatrixItem {
  resource_type: string;
  severity: string;
  verdict: string;
  install_action: string;
  file_action: string;
  runtime_action: string;
  phase: string;
  source: string;
}

export interface GovernanceAdmissionMatrixResponse {
  items: GovernanceAdmissionMatrixItem[];
}

export interface GovernanceAdmissionEvaluateInput {
  resource_type: string;
  target_name: string;
  path?: string;
  scan_result?: {
    max_severity: string;
    total_findings: number;
    scanner_name?: string;
    exit_code?: number;
    scan_error?: string;
  };
}

export interface GovernanceAdmissionEvaluateResponse {
  verdict: string;
  reason: string;
  file_action: string;
  install_action: string;
  runtime_action: string;
}

export interface GovernanceRiskModelResponse {
  severity_mapping: Array<{ severity: string; risk_level: string }>;
  malicious_indicators: Array<{ match_type: string; match_value: string }>;
}

export interface GovernanceRiskSeverityMapping {
  id: number;
  source_severity: string;
  risk_level: string;
  description: string;
  priority: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceRiskRulePrefixMatch {
  id: number;
  rule_id_prefix: string;
  risk_level: string;
  description: string;
  priority: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceRiskCategoryMatch {
  id: number;
  category: string;
  risk_level: string;
  description: string;
  priority: number;
  enabled: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface GovernanceRiskEvaluateInput {
  resource_type: string;
  severity: string;
  rule_id?: string;
  category?: string;
  tags?: string;
  title?: string;
}

export interface GovernanceRiskEvaluateResponse {
  risk_level: string;
  matched_type: string;
  matched_value: string;
  reason: string;
  precedence: string[];
}

export interface GovernanceResourcePreviewResponse {
  agent_id: string;
  agent_type_id: number;
  agent_type_key: string;
  expanded_paths: string[];
  targets: Array<{ name: string; target: string; exists: boolean; type: string }>;
}
