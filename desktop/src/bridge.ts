import { invoke } from "@tauri-apps/api/core";
import type {
  AgentRuntimeCatalog,
  AgentInventory,
  AgentSnapshot,
  AgentTraceSnapshot,
  AttackChainSnapshot,
  EnvironmentSnapshot,
  GatewayAuditSnapshot,
  GovernanceAdmissionEvaluateInput,
  GovernanceAdmissionEvaluateResponse,
  GovernanceAdmissionMatrixResponse,
  GovernanceAgentType,
  GovernanceAgentTypeInput,
  GovernanceDiscoveryCondition,
  GovernanceDiscoveryConditionInput,
  GovernanceDiscoveryRule,
  GovernanceDiscoveryRuleInput,
  GovernancePage,
  GovernanceResourceAction,
  GovernanceResourceActionInput,
  GovernanceResourcePreviewResponse,
  GovernanceResourceRule,
  GovernanceResourceRuleInput,
  GovernanceRiskEvaluateInput,
  GovernanceRiskEvaluateResponse,
  GovernanceRiskModelResponse,
  GovernanceScanCapability,
  GovernanceScanProfile,
  GovernanceScanProfileInput,
  GuardAuditSnapshot,
  GuardPolicy,
  RangeMode,
  RangeReplayStatus,
  RangeStatus,
  RuntimeDecisionDetail,
  RuntimeDecisionListResponse,
  RuntimeDetectionDetail,
  RuntimeDetectionEvidenceEvent,
  RuntimeDetectionListQuery,
  RuntimeDetectionListResponse,
  RuntimeEnforcementListResponse,
  RuntimeEnforcementResult,
  RuntimeEventsTimelineQuery,
  RuntimeEventsTimelineResponse,
  RuntimeSecurityAgent,
  RuntimeSecurityMode,
  RuntimeSecuritySummary,
  ScanScheduleSettings,
  StaticResourceAgentsResponse,
  StaticResourceContentResponse,
  StaticResourceDetailResponse,
  StaticResourceFindingsResponse,
  StaticResourceListResponse,
  StaticResourceRelationsResponse,
  StaticResourceScanAccepted,
  StaticResourceScanHistoryResponse,
  StaticResourceScanSettings,
  StaticResourceStatusUpdateResponse,
  StaticResourceSummaryResponse,
} from "./types";

const inTauri = (): boolean => "__TAURI_INTERNALS__" in window;

const defaultScanScheduleSettings = (): ScanScheduleSettings => ({
  version: 1,
  environment: { enabled: true, intervalSec: 30 },
  agentDiscovery: { enabled: true, intervalSec: 15 },
  staticAssets: { enabled: true, intervalSec: 300 },
  behaviorTrace: { enabled: true, intervalSec: 5 },
  eventDetection: { enabled: true, intervalSec: 15 },
  processGuardAudit: { enabled: true, intervalSec: 10 },
  gatewayAudit: { enabled: true, intervalSec: 10 },
  rangeStatus: { enabled: true, intervalSec: 30 },
});

const defaultStaticResourceScanSettings = (): StaticResourceScanSettings => ({
  version: 1,
  realtimeEnabled: true,
  rescanEnabled: true,
  debounceMs: 500,
  skillIntervalMin: 15,
  pluginIntervalMin: 30,
  mcpIntervalMin: 10,
  promptIntervalMin: 15,
  credentialIntervalMin: 5,
  environmentIntervalMin: 30,
});

const defaultRuntimeSecuritySummary = (): RuntimeSecuritySummary => ({
  totalDetections: 0,
  securityDetections: 0,
  attackDetections: 0,
  blocked: 0,
  highOrAbove: 0,
  coveredAgents: 0,
});

const defaultRuntimeDetectionList = (): RuntimeDetectionListResponse => ({
  total: 0,
  items: [],
  detections: [],
  count: 0,
  limit: 200,
  offset: 0,
  summary: { total: 0, attack: 0, blocked: 0, critical: 0, high: 0, open: 0 },
});

const defaultRuntimeTimeline = (): RuntimeEventsTimelineResponse => ({ buckets: [] });

const defaultAttackChainSnapshot = (): AttackChainSnapshot => ({
  capturedAt: new Date().toISOString(),
  source: "desktop preview",
  chains: [],
  warning: "浏览器预览模式不会读取后端事件库；请在桌面应用中查看真实攻击链重建结果。",
});

export async function getScanScheduleSettings(): Promise<ScanScheduleSettings> {
  return inTauri() ? invoke<ScanScheduleSettings>("get_scan_schedule_settings") : defaultScanScheduleSettings();
}

export async function saveScanScheduleSettings(settings: ScanScheduleSettings): Promise<ScanScheduleSettings> {
  if (!inTauri()) return settings;
  return invoke<ScanScheduleSettings>("save_scan_schedule_settings", { settings });
}

export async function getStaticResourceScanSettings(): Promise<StaticResourceScanSettings> {
  return inTauri() ? invoke<StaticResourceScanSettings>("get_static_resource_scan_settings") : defaultStaticResourceScanSettings();
}

export async function saveStaticResourceScanSettings(settings: StaticResourceScanSettings): Promise<StaticResourceScanSettings> {
  if (!inTauri()) return settings;
  return invoke<StaticResourceScanSettings>("save_static_resource_scan_settings", { settings });
}

// ---------------------------------------------------------------------------
// Rule-driven static resource API. All calls go through the Tauri backend,
// which forwards them to the Go gateway; in browser preview mode they
// resolve to empty structures so the page still renders.
// ---------------------------------------------------------------------------

const emptyAgents = (): StaticResourceAgentsResponse => ({ items: [] });
const emptySummary = (agentId: string): StaticResourceSummaryResponse => ({
  agent: { agent_id: agentId, name: agentId },
  total_resources: 0,
  resource_type_count: 0,
  risk_resource_count: 0,
  malicious_resource_count: 0,
  critical_resource_count: 0,
  by_type: [],
});
const emptyList = (): StaticResourceListResponse => ({ total: 0, page: 1, page_size: 20, items: [] });

export async function getStaticResourceAgents(): Promise<StaticResourceAgentsResponse> {
  return inTauri() ? invoke<StaticResourceAgentsResponse>("get_static_resource_agents") : emptyAgents();
}

export async function getStaticResourceSummary(agentId: string): Promise<StaticResourceSummaryResponse> {
  return inTauri() ? invoke<StaticResourceSummaryResponse>("get_static_resource_summary", { agentId }) : emptySummary(agentId);
}

export interface StaticResourceListQuery {
  agentId?: string;
  resourceType?: string;
  riskLevel?: string;
  malicious?: boolean;
  scanStatus?: string;
  status?: string;
  keyword?: string;
  page?: number;
  pageSize?: number;
}

export async function getStaticResources(query: StaticResourceListQuery): Promise<StaticResourceListResponse> {
  if (!inTauri()) return emptyList();
  return invoke<StaticResourceListResponse>("get_static_resources", {
    agentId: query.agentId,
    resourceType: query.resourceType,
    riskLevel: query.riskLevel,
    malicious: query.malicious,
    scanStatus: query.scanStatus,
    status: query.status,
    keyword: query.keyword,
    page: query.page,
    pageSize: query.pageSize,
  });
}

export async function getStaticResourceDetail(resourceId: string): Promise<StaticResourceDetailResponse> {
  return invoke<StaticResourceDetailResponse>("get_static_resource_detail", { resourceId });
}

export async function getStaticResourceFindings(resourceId: string): Promise<StaticResourceFindingsResponse> {
  return invoke<StaticResourceFindingsResponse>("get_static_resource_findings", { resourceId });
}

export async function getStaticResourceContent(resourceId: string): Promise<StaticResourceContentResponse> {
  return invoke<StaticResourceContentResponse>("get_static_resource_content", { resourceId });
}

export async function getStaticResourceRelations(resourceId: string): Promise<StaticResourceRelationsResponse> {
  return invoke<StaticResourceRelationsResponse>("get_static_resource_relations", { resourceId });
}

export async function triggerStaticResourceScan(resourceId: string): Promise<StaticResourceScanAccepted> {
  return invoke<StaticResourceScanAccepted>("trigger_static_resource_scan", { resourceId });
}

export async function triggerStaticResourceRescan(agentId?: string): Promise<StaticResourceScanAccepted> {
  return invoke<StaticResourceScanAccepted>("trigger_static_resource_rescan", { agentId: agentId ?? null });
}

export async function getStaticResourceScans(resourceId: string, limit = 50): Promise<StaticResourceScanHistoryResponse> {
  if (!inTauri()) return { resource_id: resourceId, total: 0, items: [] };
  return invoke<StaticResourceScanHistoryResponse>("get_static_resource_scans", { resourceId, limit });
}

export async function updateStaticResourceStatus(resourceId: string, status: string): Promise<StaticResourceStatusUpdateResponse> {
  if (!inTauri()) throw new Error("仅桌面应用可以修改资源状态");
  return invoke<StaticResourceStatusUpdateResponse>("update_static_resource_status", { resourceId, status });
}

export async function revealStaticResourcePath(path: string): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以在资源管理器中定位文件");
  await invoke("reveal_static_resource_path", { path });
}

// ---------------------------------------------------------------------------
// Agent governance API.
// ---------------------------------------------------------------------------

export interface GovernanceListQuery {
  keyword?: string;
  enabled?: boolean;
  kind?: string;
  runtime?: string;
  agentTypeId?: number;
  typeKey?: string;
  resourceType?: string;
  scanProfileId?: number;
  targetType?: string;
  targetName?: string;
  connector?: string;
  actionField?: string;
  actionValue?: string;
  page?: number;
  pageSize?: number;
}

const emptyPage = <T>(): GovernancePage<T> => ({ total: 0, page: 1, page_size: 20, items: [] });

function governanceQuery(query: GovernanceListQuery = {}): string {
  const params = new URLSearchParams();
  if (query.keyword) params.set("keyword", query.keyword);
  if (query.enabled !== undefined) params.set("enabled", String(query.enabled));
  if (query.kind) params.set("kind", query.kind);
  if (query.runtime) params.set("runtime", query.runtime);
  if (query.agentTypeId) params.set("agent_type_id", String(query.agentTypeId));
  if (query.typeKey) params.set("type_key", query.typeKey);
  if (query.resourceType) params.set("resource_type", query.resourceType);
  if (query.scanProfileId) params.set("scan_profile_id", String(query.scanProfileId));
  if (query.targetType) params.set("target_type", query.targetType);
  if (query.targetName) params.set("target_name", query.targetName);
  if (query.connector) params.set("connector", query.connector);
  if (query.actionField) params.set("action_field", query.actionField);
  if (query.actionValue) params.set("action_value", query.actionValue);
  if (query.page) params.set("page", String(query.page));
  if (query.pageSize) params.set("page_size", String(query.pageSize));
  const text = params.toString();
  return text ? `?${text}` : "";
}

async function governanceGet<T>(path: string): Promise<T> {
  return invoke<T>("agent_governance_get", { path });
}

async function governancePost<T>(path: string, body: unknown): Promise<T> {
  return invoke<T>("agent_governance_post", { path, body });
}

async function governancePatch<T>(path: string, body: unknown): Promise<T> {
  return invoke<T>("agent_governance_patch", { path, body });
}

async function governancePut<T>(path: string, body: unknown): Promise<T> {
  return invoke<T>("agent_governance_put", { path, body });
}

async function governanceDelete<T>(path: string): Promise<T> {
  return invoke<T>("agent_governance_delete", { path });
}

export async function getGovernanceAgentTypes(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceAgentType>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/agent-types${governanceQuery(query)}`);
}

export async function createGovernanceAgentType(body: GovernanceAgentTypeInput): Promise<GovernanceAgentType> {
  return governancePost("/agent-types", body);
}

export async function updateGovernanceAgentType(id: number, body: GovernanceAgentTypeInput): Promise<GovernanceAgentType> {
  return governancePatch(`/agent-types/${id}`, body);
}

export async function deleteGovernanceAgentType(id: number): Promise<GovernanceAgentType> {
  return governanceDelete(`/agent-types/${id}`);
}

export async function getGovernanceDiscoveryRules(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceDiscoveryRule>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/discovery-rules${governanceQuery(query)}`);
}

export async function getGovernanceDiscoveryRule(id: number): Promise<GovernanceDiscoveryRule> {
  return governanceGet(`/discovery-rules/${id}`);
}

export async function createGovernanceDiscoveryRule(body: GovernanceDiscoveryRuleInput): Promise<GovernanceDiscoveryRule> {
  return governancePost("/discovery-rules", body);
}

export async function updateGovernanceDiscoveryRule(id: number, body: GovernanceDiscoveryRuleInput): Promise<GovernanceDiscoveryRule> {
  return governancePatch(`/discovery-rules/${id}`, body);
}

export async function deleteGovernanceDiscoveryRule(id: number): Promise<GovernanceDiscoveryRule> {
  return governanceDelete(`/discovery-rules/${id}`);
}

export async function createGovernanceDiscoveryCondition(ruleId: number, body: GovernanceDiscoveryConditionInput): Promise<GovernanceDiscoveryCondition> {
  return governancePost(`/discovery-rules/${ruleId}/conditions`, body);
}

export async function updateGovernanceDiscoveryCondition(id: number, body: GovernanceDiscoveryConditionInput): Promise<GovernanceDiscoveryCondition> {
  return governancePatch(`/discovery-conditions/${id}`, body);
}

export async function deleteGovernanceDiscoveryCondition(id: number): Promise<{ status: string }> {
  return governanceDelete(`/discovery-conditions/${id}`);
}

export async function getGovernanceResourceRules(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceResourceRule>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/resource-rules${governanceQuery(query)}`);
}

export async function createGovernanceResourceRule(body: GovernanceResourceRuleInput): Promise<GovernanceResourceRule> {
  return governancePost("/resource-rules", body);
}

export async function updateGovernanceResourceRule(id: number, body: GovernanceResourceRuleInput): Promise<GovernanceResourceRule> {
  return governancePatch(`/resource-rules/${id}`, body);
}

export async function deleteGovernanceResourceRule(id: number): Promise<GovernanceResourceRule> {
  return governanceDelete(`/resource-rules/${id}`);
}

export async function previewGovernanceResourceRule(body: {
  agent_id?: string;
  agent_type_id?: number;
  path_pattern: string;
  enumeration_mode: string;
}): Promise<GovernanceResourcePreviewResponse> {
  return governancePost("/resource-rules/preview", body);
}

export async function getGovernanceScanProfiles(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceScanProfile>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/scan-profiles${governanceQuery(query)}`);
}

export async function createGovernanceScanProfile(body: GovernanceScanProfileInput): Promise<GovernanceScanProfile> {
  return governancePost("/scan-profiles", body);
}

export async function updateGovernanceScanProfile(id: number, body: GovernanceScanProfileInput): Promise<GovernanceScanProfile> {
  return governancePatch(`/scan-profiles/${id}`, body);
}

export async function deleteGovernanceScanProfile(id: number): Promise<GovernanceScanProfile> {
  return governanceDelete(`/scan-profiles/${id}`);
}

export async function replaceGovernanceScanProfileCapabilities(id: number, capabilities: GovernanceScanProfileInput["capabilities"]): Promise<GovernanceScanProfile> {
  return governancePut(`/scan-profiles/${id}/capabilities`, { capabilities: capabilities ?? [] });
}

export async function getGovernanceScanCapabilities(query: GovernanceListQuery = {}): Promise<{ items: GovernanceScanCapability[] }> {
  if (!inTauri()) return { items: [] };
  return governanceGet(`/scan-capabilities${governanceQuery(query)}`);
}

export async function getGovernanceResourceActions(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceResourceAction>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/resource-actions${governanceQuery(query)}`);
}

export async function createGovernanceResourceAction(body: GovernanceResourceActionInput): Promise<GovernanceResourceAction> {
  return governancePost("/resource-actions", body);
}

export async function updateGovernanceResourceAction(id: string, body: GovernanceResourceActionInput): Promise<GovernanceResourceAction> {
  return governancePatch(`/resource-actions/${id}`, body);
}

export async function deleteGovernanceResourceAction(id: string): Promise<{ status: string }> {
  return governanceDelete(`/resource-actions/${id}`);
}

export async function getGovernanceAdmissionMatrix(): Promise<GovernanceAdmissionMatrixResponse> {
  if (!inTauri()) return { items: [] };
  return governanceGet("/admission-matrix");
}

export async function evaluateGovernanceAdmission(body: GovernanceAdmissionEvaluateInput): Promise<GovernanceAdmissionEvaluateResponse> {
  if (!inTauri()) {
    const max = body.scan_result?.max_severity ?? "INFO";
    const blocked = max === "HIGH" || max === "CRITICAL";
    return {
      verdict: blocked ? "rejected" : body.scan_result ? "warning" : "scan",
      reason: blocked ? "preview: high severity blocks" : "preview",
      file_action: blocked ? "quarantine" : "none",
      install_action: blocked ? "block" : "none",
      runtime_action: blocked ? "block" : "allow",
    };
  }
  return governancePost("/admission/evaluate", body);
}

export async function getGovernanceRiskModel(): Promise<GovernanceRiskModelResponse> {
  if (!inTauri()) {
    return {
      severity_mapping: [
        { severity: "CRITICAL", risk_level: "critical" },
        { severity: "HIGH", risk_level: "high" },
        { severity: "MEDIUM", risk_level: "medium" },
        { severity: "LOW", risk_level: "low" },
        { severity: "INFO", risk_level: "clean" },
      ],
      malicious_indicators: [{ match_type: "rule_id_prefix", match_value: "CS-MAL-" }],
    };
  }
  return governanceGet("/risk-model");
}

export async function evaluateGovernanceRisk(body: GovernanceRiskEvaluateInput): Promise<GovernanceRiskEvaluateResponse> {
  if (!inTauri()) {
    const rank: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    const max = body.findings.reduce((acc, finding) => {
      const severity = String(finding.severity ?? "INFO").toUpperCase();
      return (rank[severity] ?? 0) > (rank[acc] ?? 0) ? severity : acc;
    }, "INFO");
    const risk = max === "CRITICAL" ? "critical" : max === "HIGH" ? "high" : max === "MEDIUM" ? "medium" : max === "LOW" ? "low" : "clean";
    const malicious = body.findings.some((finding) => finding.rule_id?.startsWith("CS-MAL-") || finding.category === "prompt_injection");
    return { risk_level: risk, malicious, max_severity: max, finding_count: body.findings.length, matched_indicators: malicious ? [{ match_type: "rule_id_prefix", match_value: "CS-MAL-" }] : [] };
  }
  return governancePost("/risk/evaluate", body);
}

export async function getRuntimeSecuritySummary(agentId?: string): Promise<RuntimeSecuritySummary> {
  if (!inTauri()) return defaultRuntimeSecuritySummary();
  return invoke<RuntimeSecuritySummary>("get_runtime_security_summary", { agentId: agentId ?? null });
}

export async function getRuntimeSecurityAgents(limit = 200): Promise<RuntimeSecurityAgent[]> {
  if (!inTauri()) return [];
  return invoke<RuntimeSecurityAgent[]>("get_runtime_security_agents", { limit });
}

export async function getRuntimeDetections(query: RuntimeDetectionListQuery = {}): Promise<RuntimeDetectionListResponse> {
  if (!inTauri()) return defaultRuntimeDetectionList();
  return invoke<RuntimeDetectionListResponse>("get_runtime_detections", {
    agentId: query.agentId,
    category: query.category,
    severity: query.severity,
    status: query.status,
    source: query.source,
    keyword: query.keyword,
    traceId: query.traceId,
    sessionId: query.sessionId,
    detectionType: query.detectionType,
    limit: query.limit,
    offset: query.offset,
    sort: query.sort,
  });
}

export async function getRuntimeDetectionDetail(detectionId: string): Promise<RuntimeDetectionDetail> {
  if (!inTauri()) {
    return {
      detection: {
        detectionId,
        detectionType: "",
        category: "suspicious",
        severity: "info",
        status: "open",
        title: "浏览器预览模式无详情",
      },
      evidence: [],
    };
  }
  return invoke<RuntimeDetectionDetail>("get_runtime_detection_detail", { detectionId });
}

export async function getRuntimeDetectionEvents(detectionId: string): Promise<RuntimeDetectionEvidenceEvent[]> {
  if (!inTauri()) return [];
  return invoke<RuntimeDetectionEvidenceEvent[]>("get_runtime_detection_events", { detectionId });
}

export async function getRuntimeEventsTimeline(query: RuntimeEventsTimelineQuery = {}): Promise<RuntimeEventsTimelineResponse> {
  if (!inTauri()) return defaultRuntimeTimeline();
  return invoke<RuntimeEventsTimelineResponse>("get_runtime_events_timeline", {
    agentId: query.agentId,
    bucket: query.bucket,
    startTime: query.startTime,
    endTime: query.endTime,
    sessionId: query.sessionId,
    traceId: query.traceId,
  });
}

export async function getAttackChains(limit = 500): Promise<AttackChainSnapshot> {
  return inTauri() ? invoke<AttackChainSnapshot>("get_attack_chains", { limit }) : defaultAttackChainSnapshot();
}

/** Phase-3 runtime decisions: list, detail, and security mode. */
export async function getRuntimeDecisions(limit = 200): Promise<RuntimeDecisionListResponse> {
  if (!inTauri()) {
    return { decisions: [], summary: { total: 0, block: 0, confirm: 0, alert: 0, audit: 0, allow: 0, wouldBlock: 0 }, count: 0 };
  }
  return invoke<RuntimeDecisionListResponse>("get_runtime_decisions", { limit });
}

export async function getRuntimeDecisionDetail(decisionId: string): Promise<RuntimeDecisionDetail> {
  return invoke<RuntimeDecisionDetail>("get_runtime_decision_detail", { decisionId });
}

export async function getRuntimeSecurityMode(): Promise<RuntimeSecurityMode> {
  if (!inTauri()) return "observe";
  return invoke<RuntimeSecurityMode>("get_runtime_security_mode");
}

export async function setRuntimeSecurityMode(mode: RuntimeSecurityMode): Promise<RuntimeSecurityMode> {
  if (!inTauri()) return mode;
  return invoke<RuntimeSecurityMode>("set_runtime_security_mode", { mode });
}

export async function blockRuntimeDetection(detectionId: string, actionType = "BLOCK", reason = "manual_operator_action"): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview" };
  return invoke<RuntimeEnforcementResult>("block_runtime_detection", { detectionId, actionType, reason });
}

export async function enforceRuntimeDecision(decisionId: string): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview" };
  return invoke<RuntimeEnforcementResult>("enforce_runtime_decision", { decisionId });
}

export async function getRuntimeEnforcements(): Promise<RuntimeEnforcementListResponse> {
  if (!inTauri()) return { items: [], total: 0 };
  return invoke<RuntimeEnforcementListResponse>("get_runtime_enforcements");
}

export async function getRuntimeEnforcement(enforcementId: string): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview" };
  return invoke<RuntimeEnforcementResult>("get_runtime_enforcement", { enforcementId });
}

export async function deleteRuntimeEnforcement(enforcementId: string): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview", removed: 0 };
  return invoke<RuntimeEnforcementResult>("delete_runtime_enforcement", { enforcementId });
}

const browserEnvironment = (): EnvironmentSnapshot => ({
  capturedAt: new Date().toISOString(),
  components: [
    { id: "gateway", label: "TraceBastion Gateway", state: "unknown", detail: "桌面宿主未连接" },
    { id: "docker", label: "Docker Desktop", state: "unknown", detail: "桌面宿主未连接" },
    { id: "agentrange", label: "AgentRange 靶场", state: "unknown", detail: "桌面宿主未连接" },
    { id: "processGuard", label: "Windows 进程守护", state: "unknown", detail: "桌面宿主未连接", requiresElevation: true },
  ],
});

export async function getEnvironment(): Promise<EnvironmentSnapshot> {
  return inTauri() ? invoke<EnvironmentSnapshot>("get_environment_snapshot") : browserEnvironment();
}

export interface AgentListQuery {
  page?: number;
  pageSize?: number;
  query?: string;
  runtimeStatus?: string;
  sort?: string;
}

export async function getAgents(query: AgentListQuery = {}): Promise<AgentSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), agents: [], processes: [], warning: "浏览器预览模式不具备本机进程访问权限" };
  }
  return invoke<AgentSnapshot>("get_agents", { query });
}

export async function getAgentDetail(agentId: string): Promise<AgentInventory> {
  if (!inTauri()) throw new Error("仅桌面应用可以读取 Agent 详情");
  return invoke<AgentInventory>("get_agent_detail", { agentId });
}

export async function exportAgentsReportPdf(agents: AgentInventory[], defaultFileName?: string): Promise<string | null> {
  if (!inTauri()) throw new Error("仅桌面应用可以选择路径并导出 PDF 报告");
  return invoke<string | null>("export_agents_report_pdf", { agents, defaultFileName });
}

export async function getAgentRuntimeCatalog(): Promise<AgentRuntimeCatalog> {
  if (!inTauri()) throw new Error("Agent runtime catalog is available from the desktop host only");
  return invoke<AgentRuntimeCatalog>("get_agent_runtime_catalog");
}

export async function getGuardPolicy(): Promise<GuardPolicy> {
  if (!inTauri()) {
    return {
      version: 2,
      enabled: false,
      mode: "observe",
      agentNames: [],
      rules: [],
      fileGuard: { enabled: false, auditRoots: [], blacklist: [] },
      trace: { enabled: true, captureProcesses: true, captureFileReads: true, captureFileWrites: true, captureFileCreates: true, captureFileDeletes: true, retentionDays: 30, maxDatabaseMb: 256 },
      termination: { gracePeriodMs: 1500, verifyProcessIdentity: true, protectedProcessBehavior: "auditOnly" },
    };
  }
  return invoke<GuardPolicy>("get_guard_policy");
}

export async function getAgentTrace(limit = 300): Promise<AgentTraceSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), databasePath: "audit.db:behavior_events", events: [], warning: "浏览器预览模式不读取 Go 后端行为事件库" };
  }
  return invoke<AgentTraceSnapshot>("get_agent_trace", { limit });
}

export async function saveGuardPolicy(policy: GuardPolicy): Promise<GuardPolicy> {
  if (!inTauri()) return policy;
  return invoke<GuardPolicy>("save_guard_policy", { policy });
}

export async function installProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以安装 Windows 服务");
  await invoke("install_process_guard");
}

export async function applyProcessGuardPolicy(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以应用系统策略");
  await invoke("apply_process_guard_policy");
}

export async function uninstallProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以卸载 Windows 服务");
  await invoke("uninstall_process_guard");
}

export async function getProcessGuardAudit(limit = 200): Promise<GuardAuditSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), path: "本机受保护存储", events: [], warning: "浏览器预览模式不读取本机审计文件" };
  }
  return invoke<GuardAuditSnapshot>("get_process_guard_audit", { limit });
}

export async function getGatewayAudit(limit = 200): Promise<GatewayAuditSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), source: "defenseclaw-gateway audit export", events: [], warning: "浏览器预览模式不读取网关审计数据库" };
  }
  return invoke<GatewayAuditSnapshot>("get_gateway_audit", { limit });
}

export interface LifecycleResult {
  action: string;
  success: boolean;
  message: string;
}

export async function setGatewayRunning(running: boolean): Promise<LifecycleResult> {
  if (!inTauri()) throw new Error("仅桌面应用可以控制网关");
  return invoke<LifecycleResult>(running ? "start_gateway" : "stop_gateway");
}

export async function getRangeStatus(): Promise<RangeStatus> {
  if (!inTauri()) return { configured: false, root: "", composeFile: "", adapterComposeFile: "", mode: "baseline", dockerAvailable: false, runningServices: [], state: "unconfigured", detail: "Desktop host is not connected" };
  return invoke<RangeStatus>("get_range_status");
}

export async function saveRangeRoot(root: string): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can configure the range");
  return invoke<RangeStatus>("set_range_root", { root });
}

export async function saveDefenseMode(mode: RangeMode): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can configure the TraceBastion mode");
  return invoke<RangeStatus>("set_range_mode", { mode });
}

export const saveRangeMode = saveDefenseMode;

export async function setRangeRunning(running: boolean): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can control the range");
  return invoke<RangeStatus>(running ? "start_range" : "stop_range");
}

export async function getRangeReplayStatus(): Promise<RangeReplayStatus> {
  if (!inTauri()) return { running: false, command: "", scenario: "", startedAt: "", completed: 0, total: 0, remaining: 0, detail: "Desktop host is not connected", log: [] };
  return invoke<RangeReplayStatus>("get_range_replay_status");
}

export async function startRangeReplay(command: string): Promise<RangeReplayStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can run AgentRange replay");
  return invoke<RangeReplayStatus>("start_range_replay", { command });
}

export async function stopRangeReplay(): Promise<RangeReplayStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can stop AgentRange replay");
  return invoke<RangeReplayStatus>("stop_range_replay");
}
