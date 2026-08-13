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

export interface AgentSnapshot {
  capturedAt: string;
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
  dockerAvailable: boolean;
  runningServices: string[];
  state: "unconfigured" | "invalid" | "dockerUnavailable" | "stopped" | "running";
  detail: string;
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
}

export interface GuardAuditSnapshot {
  capturedAt: string;
  path: string;
  events: GuardAuditEvent[];
  warning?: string;
}
