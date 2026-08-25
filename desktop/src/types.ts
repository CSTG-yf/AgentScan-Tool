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

export interface AgentInventory {
  id: string;
  product: string;
  vendor: string;
  kind: string;
  status: AgentStatus;
  running: boolean;
  processCount: number;
  pids: number[];
  primaryPid?: number;
  executableNames: string[];
  startedAt?: string;
  uptimeSec?: number;
  source: string;
  configRoots: AgentConfigRoot[];
  staticResourceCount: number;
  riskResourceCount: number;
  criticalResourceCount: number;
  lastStaticScanAt?: string;
  description: string;
}

export interface AgentSnapshot {
  capturedAt: string;
  agents: AgentInventory[];
  processes: AgentProcess[];
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

export interface EventDetectionSummary {
  total: number;
  security: number;
  attack: number;
  blocked: number;
  critical: number;
  high: number;
  correlated: number;
  agents: number;
  sources: number;
  windowStart?: string;
  windowEnd?: string;
  /** Phase-2 detection-backed counters. */
  detections?: number;
  attackDetections?: number;
  openDetections?: number;
}

export interface EventBreakdown {
  name: string;
  count: number;
  attack: number;
  blocked: number;
  maxSeverity: StaticRisk;
}

export interface EventAgentBreakdown {
  agent: string;
  runtime: string;
  count: number;
  attack: number;
  blocked: number;
  maxSeverity: StaticRisk;
  lastSeen: string;
  sources: string[];
}

export interface EventTimelineBucket {
  bucket: string;
  total: number;
  attack: number;
  blocked: number;
  highRisk: number;
}

export interface DetectedEvent {
  id: string;
  occurredAt: string;
  kind: EventKind;
  agent: string;
  runtime: string;
  category: string;
  subtype: string;
  title: string;
  severity: StaticRisk;
  riskScore?: number;
  status: EventStatus;
  evidence: string;
  action: string;
  traceId: string;
  sessionId: string;
  correlationKey?: string;
  source: string;
  rawAction?: string;
  target?: string;
  actor?: string;
  connector?: string;
  destinationApp?: string;
  toolName?: string;
  model?: string;
  mcpServer?: string;
  decision?: string;
  reason?: string;
  remediation?: string;
  /** Phase-2 structured detection backing. */
  detectionId?: string;
  detectionType?: string;
  detectionSeverity?: string;
}

/** Phase-2 structured runtime detection (runtime_detections row). */
export interface RuntimeDetection {
  detectionId: string;
  agentId?: string;
  agentName?: string;
  sessionId?: string;
  traceId?: string;
  detectionType: string;
  category: string;
  severity: string;
  confidence?: number;
  ruleId?: string;
  status: string;
  title: string;
  detail?: string;
  remediation?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
  eventCount?: number;
}

export interface EventDetectionSnapshot {
  capturedAt: string;
  source: string;
  summary?: EventDetectionSummary;
  sourceBreakdown?: EventBreakdown[];
  agentBreakdown?: EventAgentBreakdown[];
  timeline?: EventTimelineBucket[];
  events: DetectedEvent[];
  /** Phase-2 structured detections (runtime_detections). */
  detections?: RuntimeDetection[];
  warning?: string;
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

export interface StaticResource {
  id: string;
  name: string;
  type: StaticResourceType;
  kind: string;
  path: string;
  risk: StaticRisk;
  status: StaticResourceStatus;
  updatedAt: string;
  size: string;
  permissions: string;
  hash: string;
  description: string;
  contentPreview: string;
  findings: StaticResourceFinding[];
  relations: StaticResourceRelation[];
}

export interface StaticAgentInventory {
  id: string;
  name: string;
  runtime: string;
  source: string;
  description: string;
  resources: StaticResource[];
}

export interface StaticAssetSnapshot {
  capturedAt: string;
  source: string;
  lastScanAt?: string;
  agents: StaticAgentInventory[];
  warning?: string;
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
