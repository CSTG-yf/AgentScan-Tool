import type { RuntimeBlacklist, RuntimeEvaluation, RuntimeRiskData, RuntimeRiskPolicy, RuntimeRiskPolicyRule, RuntimeRule, RuntimeSettingsOverview, RuntimeSettingsPage, RuntimeSettingsQuery, RuntimeTypeDetail, RuntimeTypeRow, RuntimeTypeSettings } from "./types";
import { invoke } from "@tauri-apps/api/core";
import type {
  AgentRuntimeCatalog,
  AgentInventory,
  AgentSnapshot,
  AgentTraceEvent,
  AgentTraceSnapshot,
  AttackChainAgentTypeSummaryResponse,
  AttackChainSnapshot,
  AttackChainListQuery,
  AttackChainDetail,
  BackendScanSchedule,
  BackendScanSchedulesResponse,
  ChangeCursor,
  EnvironmentSnapshot,
  GatewayAuditSnapshot,
  GatewayDesktopSettings,
  GatewayExitState,
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
  GovernancePostScanProfile,
  GovernancePostScanProfileInput,
  GovernancePostScanRule,
  GovernancePostScanRuleInput,
  GovernancePreScanProfile,
  GovernancePreScanProfileInput,
  GovernancePreScanRule,
  GovernancePreScanRuleInput,
  GovernanceResourceAction,
  GovernanceResourceActionInput,
  GovernanceResourcePreviewResponse,
  GovernanceResourceRule,
  GovernanceResourceRuleInput,
  GovernanceRiskEvaluateInput,
  GovernanceRiskEvaluateResponse,
  GovernanceRiskCategoryMatch,
  GovernanceRiskModelResponse,
  GovernanceRiskRulePrefixMatch,
  GovernanceRiskSeverityMapping,
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
  RuntimeDetectionAgentTypeSummaryResponse,
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
  ScanJob,
  ScanJobsResponse,
  ScanTaskType,
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
export const isDesktopRuntime = (): boolean => inTauri();

export async function selectExportDirectory(title = "选择导出文件夹"): Promise<string | null> {
  if (!inTauri()) return null;
  return invoke<string | null>("select_export_directory", { title });
}

export async function exportTextFileToDirectory(directory: string, content: string, defaultFileName: string): Promise<string> {
  if (!inTauri()) throw new Error("仅桌面应用可以将文件写入所选目录");
  return invoke<string>("export_text_file_to_directory", { directory, content, defaultFileName });
}

const defaultScanScheduleSettings = (): ScanScheduleSettings => ({
  version: 1,
  environment: { enabled: true, intervalSec: 10 },
  agentDiscovery: { enabled: true, intervalSec: 15 },
  staticAssets: { enabled: true, intervalSec: 10 },
  behaviorTrace: { enabled: true, intervalSec: 15 },
  eventDetection: { enabled: true, intervalSec: 8 },
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
const emptyList = (): StaticResourceListResponse => ({ total: 0, page: 1, pageSize: 20, items: [] });

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
  startTime?: string;
  endTime?: string;
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
    startTime: query.startTime,
    endTime: query.endTime,
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

export async function triggerStaticResourceScan(resourceId: string, idempotencyKey?: string): Promise<StaticResourceScanAccepted> {
  return invoke<StaticResourceScanAccepted>("trigger_static_resource_scan", { resourceId, idempotencyKey });
}

export async function triggerStaticResourceRescan(agentId?: string, idempotencyKey?: string): Promise<StaticResourceScanAccepted> {
  return invoke<StaticResourceScanAccepted>("trigger_static_resource_rescan", { agentId: agentId ?? null, idempotencyKey });
}

export async function getScanStatus(scanId: string): Promise<StaticResourceScanAccepted> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后查询任务状态");
  const status = await invoke<StaticResourceScanAccepted>("get_scan_status", { scanId });
  return { ...status, scan_id: status.scan_id ?? status.job_id, job_id: status.job_id ?? status.scan_id, type: status.type ?? status.kind };
}

export interface RuntimeEventReplayScope {
  agentTypeId?: number;
  agentId?: string;
  sessionId?: string;
  traceId?: string;
  startTime?: string;
  endTime?: string;
}

export async function createRuntimeEventReplay(scope: RuntimeEventReplayScope = {}): Promise<StaticResourceScanAccepted> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后创建重放任务");
  const status = await invoke<StaticResourceScanAccepted>("create_event_replay_job", {
    agentTypeId: scope.agentTypeId,
    agentId: scope.agentId,
    sessionId: scope.sessionId,
    traceId: scope.traceId,
    startTime: scope.startTime,
    endTime: scope.endTime,
  });
  return { ...status, scan_id: status.scan_id ?? status.job_id, job_id: status.job_id ?? status.scan_id, type: status.type ?? status.kind };
}

export async function createAttackChainRebuildJob(limit = 5000): Promise<StaticResourceScanAccepted> {
  if (!inTauri()) throw new Error("攻击链重建需要连接桌面网关。");
  const status = await invoke<StaticResourceScanAccepted>("create_attack_chain_rebuild_job", { limit });
  return { ...status, scan_id: status.scan_id ?? status.job_id, job_id: status.job_id ?? status.scan_id, type: status.type ?? status.kind };
}

const defaultBackendScanSchedules = (): BackendScanSchedulesResponse => ({
  total: 6,
  source: "preview",
  items: [
    { task_type: "agent_discovery", enabled: true, interval_sec: 900, mode: "incremental", scope: {} },
    { task_type: "static_assets", enabled: false, interval_sec: 3600, mode: "incremental", scope: {} },
    { task_type: "runtime_detections", enabled: false, interval_sec: 3600, mode: "replay", scope: {} },
    { task_type: "attack_chains", enabled: false, interval_sec: 3600, mode: "rebuild", scope: {} },
    { task_type: "behavior_trace", enabled: false, interval_sec: 900, mode: "incremental", scope: {} },
    { task_type: "environment", enabled: false, interval_sec: 300, mode: "incremental", scope: {} },
  ],
});

export async function getBackendScanSchedules(): Promise<BackendScanSchedulesResponse> {
  return inTauri() ? invoke<BackendScanSchedulesResponse>("get_scan_schedules") : defaultBackendScanSchedules();
}

export async function updateBackendScanSchedule(schedule: BackendScanSchedule): Promise<BackendScanSchedule> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后保存扫描策略");
  return invoke<BackendScanSchedule>("update_scan_schedule", {
    taskType: schedule.task_type,
    enabled: schedule.enabled,
    intervalSec: schedule.interval_sec,
    mode: schedule.mode,
    scope: schedule.scope,
  });
}

export async function createScanJob(taskType: ScanTaskType, mode?: string, scope: Record<string, unknown> = {}): Promise<ScanJob> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后创建扫描任务");
  return invoke<ScanJob>("create_scan_job", {
    taskType,
    mode,
    scope,
    idempotencyKey: `manual:${taskType}:${Date.now()}`,
  });
}

export async function getScanJobs(query: { taskType?: ScanTaskType; status?: string; trigger?: string; limit?: number; offset?: number } = {}): Promise<ScanJobsResponse> {
  if (!inTauri()) return { items: [], jobs: [], count: 0, total: 0, limit: query.limit ?? 20, offset: query.offset ?? 0, next_offset: 0 };
  return invoke<ScanJobsResponse>("get_scan_jobs", {
    taskType: query.taskType,
    status: query.status,
    trigger: query.trigger,
    limit: query.limit,
    offset: query.offset,
  });
}

export async function getScanJob(jobId: string): Promise<ScanJob> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后查询扫描任务");
  return invoke<ScanJob>("get_scan_job", { jobId });
}

export async function cancelScanJob(jobId: string): Promise<ScanJob> {
  if (!inTauri()) throw new Error("请在桌面应用中连接网关后取消扫描任务");
  return invoke<ScanJob>("cancel_scan_job", { jobId });
}

export async function getChanges(cursor = 0, domains?: string[]): Promise<ChangeCursor> {
  if (!inTauri()) return { next_cursor: cursor, changed_domains: [], source: "preview" };
  return invoke<ChangeCursor>("get_changes", {
    cursor,
    domains: domains?.join(","),
  });
}

export async function getStaticResourceScans(resourceId: string, limit = 50): Promise<StaticResourceScanHistoryResponse> {
  if (!inTauri()) return { resource_id: resourceId, total: 0, items: [] };
  return invoke<StaticResourceScanHistoryResponse>("get_static_resource_scans", { resourceId, limit });
}

export async function exportStaticResourceTextReport(content: string, defaultFileName: string, directory: string): Promise<string> {
  if (!inTauri()) throw new Error("仅桌面应用可以将静态资源报告写入所选目录");
  return invoke<string>("export_static_resource_text_report", { content, defaultFileName, directory });
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
  riskLevel?: string;
  page?: number;
  pageSize?: number;
}

const emptyPage = <T>(): GovernancePage<T> => ({ total: 0, page: 1, page_size: 20, items: [] });

const mockPage = <T>(items: T[], query: GovernanceListQuery = {}): GovernancePage<T> => {
  const page = query.page ?? 1;
  const pageSize = query.pageSize ?? 20;
  const start = (page - 1) * pageSize;
  return { total: items.length, page, page_size: pageSize, items: items.slice(start, start + pageSize) };
};

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
  if (query.riskLevel) params.set("risk_level", query.riskLevel);
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

export interface GovernanceSummary {
  agent_type_count: number;
  discovery_rule_count: number;
  resource_rule_count: number;
  scan_profile_count: number;
  decision_profile_count: number;
  risk_rule_count: number;
  runtime_rule_count: number;
  runtime_blacklist_count: number;
  runtime_risk_policy_count: number;
  scan_schedule_count: number;
  page_refresh_policy_count: number;
}

export async function getGovernanceSummary(): Promise<GovernanceSummary> {
  if (!inTauri()) throw new Error("治理统计需要连接桌面网关");
  return governanceGet<GovernanceSummary>("/summary");
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

export async function getGovernancePreScanProfiles(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernancePreScanProfile>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/pre-scan-profiles${governanceQuery(query)}`);
}

export async function createGovernancePreScanProfile(body: GovernancePreScanProfileInput): Promise<GovernancePreScanProfile> {
  return governancePost("/pre-scan-profiles", body);
}

export async function updateGovernancePreScanProfile(id: number, body: GovernancePreScanProfileInput): Promise<GovernancePreScanProfile> {
  return governancePatch(`/pre-scan-profiles/${id}`, body);
}

export async function deleteGovernancePreScanProfile(id: number): Promise<{ status: string }> {
  return governanceDelete(`/pre-scan-profiles/${id}`);
}

export async function getGovernancePreScanRules(profileId: number, query: GovernanceListQuery = {}): Promise<GovernancePage<GovernancePreScanRule>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/pre-scan-profiles/${profileId}/rules${governanceQuery(query)}`);
}

export async function createGovernancePreScanRule(profileId: number, body: GovernancePreScanRuleInput): Promise<GovernancePreScanRule> {
  return governancePost(`/pre-scan-profiles/${profileId}/rules`, body);
}

export async function updateGovernancePreScanRule(id: number, body: GovernancePreScanRuleInput): Promise<GovernancePreScanRule> {
  return governancePatch(`/pre-scan-rules/${id}`, body);
}

export async function deleteGovernancePreScanRule(id: number): Promise<{ status: string }> {
  return governanceDelete(`/pre-scan-rules/${id}`);
}

export async function getGovernancePostScanProfiles(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernancePostScanProfile>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/post-scan-profiles${governanceQuery(query)}`);
}

export async function createGovernancePostScanProfile(body: GovernancePostScanProfileInput): Promise<GovernancePostScanProfile> {
  return governancePost("/post-scan-profiles", body);
}

export async function updateGovernancePostScanProfile(id: number, body: GovernancePostScanProfileInput): Promise<GovernancePostScanProfile> {
  return governancePatch(`/post-scan-profiles/${id}`, body);
}

export async function deleteGovernancePostScanProfile(id: number): Promise<{ status: string }> {
  return governanceDelete(`/post-scan-profiles/${id}`);
}

export async function getGovernancePostScanRules(profileId: number, query: GovernanceListQuery = {}): Promise<GovernancePage<GovernancePostScanRule>> {
  if (!inTauri()) return emptyPage();
  return governanceGet(`/post-scan-profiles/${profileId}/rules${governanceQuery(query)}`);
}

export async function createGovernancePostScanRule(profileId: number, body: GovernancePostScanRuleInput): Promise<GovernancePostScanRule> {
  return governancePost(`/post-scan-profiles/${profileId}/rules`, body);
}

export async function updateGovernancePostScanRule(id: number, body: GovernancePostScanRuleInput): Promise<GovernancePostScanRule> {
  return governancePatch(`/post-scan-rules/${id}`, body);
}

export async function deleteGovernancePostScanRule(id: number): Promise<{ status: string }> {
  return governanceDelete(`/post-scan-rules/${id}`);
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

export async function getGovernanceRiskSeverityMappings(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceRiskSeverityMapping>> {
  if (!inTauri()) {
    return mockPage([
      { id: 1, source_severity: "CRITICAL", risk_level: "critical", description: "Critical scanner finding maps to critical resource risk.", priority: 30, enabled: true },
      { id: 2, source_severity: "HIGH", risk_level: "high", description: "High scanner finding maps to high resource risk.", priority: 31, enabled: true },
      { id: 3, source_severity: "MEDIUM", risk_level: "medium", description: "Medium scanner finding maps to medium resource risk.", priority: 32, enabled: true },
      { id: 4, source_severity: "LOW", risk_level: "low", description: "Low scanner finding maps to low resource risk.", priority: 33, enabled: true },
      { id: 5, source_severity: "INFO", risk_level: "clean", description: "Informational scanner finding maps to clean resource risk.", priority: 34, enabled: true },
    ], query);
  }
  return governanceGet(`/risk-severity-mappings${governanceQuery(query)}`);
}

export async function getGovernanceRiskRulePrefixMatches(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceRiskRulePrefixMatch>> {
  if (!inTauri()) {
    return mockPage([
      { id: 1, rule_id_prefix: "CS-MAL-", risk_level: "critical", description: "ClawShield malware rule IDs are treated as critical before category or severity fallback.", priority: 10, enabled: true },
    ], query);
  }
  return governanceGet(`/risk-rule-prefix-matches${governanceQuery(query)}`);
}

export async function getGovernanceRiskCategoryMatches(query: GovernanceListQuery = {}): Promise<GovernancePage<GovernanceRiskCategoryMatch>> {
  if (!inTauri()) {
    return mockPage(["malware", "reverse_shell", "credential_harvest", "credential_exfiltration", "cryptominer", "c2", "command_execution"].map((category, index) => ({
      id: index + 1,
      category,
      risk_level: "critical",
      description: `Category ${category} is treated as critical resource risk.`,
      priority: 20,
      enabled: true,
    })), query);
  }
  return governanceGet(`/risk-category-matches${governanceQuery(query)}`);
}

export async function evaluateGovernanceRisk(body: GovernanceRiskEvaluateInput): Promise<GovernanceRiskEvaluateResponse> {
  if (!inTauri()) {
    const precedence = ["rule_id_prefix", "category", "severity", "default"];
    if (body.rule_id?.startsWith("CS-MAL-")) {
      return { risk_level: "critical", matched_type: "rule_id_prefix", matched_value: "CS-MAL-", reason: "Rule ID prefix matched CS-MAL-, mapped to critical.", precedence };
    }
    if (["malware", "reverse_shell", "credential_harvest", "credential_exfiltration", "cryptominer", "c2", "command_execution"].includes(String(body.category ?? "").toLowerCase())) {
      return { risk_level: "critical", matched_type: "category", matched_value: String(body.category), reason: `Category matched ${body.category}, mapped to critical.`, precedence };
    }
    const severity = String(body.severity ?? "INFO").toUpperCase();
    const risk = severity === "CRITICAL" ? "critical" : severity === "HIGH" ? "high" : severity === "MEDIUM" ? "medium" : severity === "LOW" ? "low" : "clean";
    return { risk_level: risk, matched_type: "severity", matched_value: severity, reason: `Severity matched ${severity}, mapped to ${risk}.`, precedence };
  }
  return governancePost("/risk-explain/evaluate", body);
}

export async function getRuntimeSecuritySummary(agentId?: string): Promise<RuntimeSecuritySummary> {
  if (!inTauri()) return defaultRuntimeSecuritySummary();
  return invoke<RuntimeSecuritySummary>("get_runtime_security_summary", { agentId: agentId ?? null });
}

export async function getRuntimeDetectionAgentTypeSummaries(query: RuntimeDetectionListQuery = {}): Promise<RuntimeDetectionAgentTypeSummaryResponse> {
  if (!inTauri()) throw new Error("异常事件汇总需要连接桌面网关。");
  const { page: _page, pageSize: _pageSize, limit: _limit, offset: _offset, sort: _sort, ...filters } = query;
  const response = await invoke<RuntimeDetectionAgentTypeSummaryResponse>("get_runtime_detection_agent_type_summaries", { filters });
  const items = response.items?.length ? response.items : response.list ?? [];
  return {
    ...response,
    items,
    list: response.list?.length ? response.list : items,
    total: response.total ?? items.length,
    count: response.count ?? items.length,
  };
}

export async function getRuntimeSecurityAgents(limit = 200): Promise<RuntimeSecurityAgent[]> {
  if (!inTauri()) return [];
  return invoke<RuntimeSecurityAgent[]>("get_runtime_security_agents", { limit });
}

export async function getRuntimeDetections(query: RuntimeDetectionListQuery = {}): Promise<RuntimeDetectionListResponse> {
  if (!inTauri()) throw new Error("异常事件列表需要连接桌面网关。");
  return invoke<RuntimeDetectionListResponse>("get_runtime_detections", {
    agentId: query.agentId,
    agentTypeId: query.agentTypeId,
    agentType: query.agentType,
    startTime: query.startTime,
    endTime: query.endTime,
    page: query.page,
    pageSize: query.pageSize,
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

export async function getAttackChains(query: AttackChainListQuery | number = {}): Promise<AttackChainSnapshot> {
  if (!inTauri()) throw new Error("攻击链需要连接桌面网关。");
  const { page = 1, pageSize = 20, sort, ...filters } = typeof query === "number" ? { pageSize: query } : query;
  return invoke<AttackChainSnapshot>("get_attack_chains", { filters, page, pageSize, sort });
}

export async function getAttackChainAgentTypeSummaries(query: AttackChainListQuery = {}): Promise<AttackChainAgentTypeSummaryResponse> {
  if (!inTauri()) throw new Error("攻击链汇总需要连接桌面网关。");
  const { page: _page, pageSize: _pageSize, sort: _sort, ...filters } = query;
  const response = await invoke<AttackChainAgentTypeSummaryResponse>("get_attack_chain_agent_type_summaries", { filters });
  const items = response.items?.length ? response.items : response.list ?? [];
  return { ...response, items, list: response.list?.length ? response.list : items };
}

export async function getAttackChainDetail(chainId: string): Promise<AttackChainDetail> {
  if (!inTauri()) throw new Error("攻击链详情需要连接桌面网关。");
  return invoke<AttackChainDetail>("get_attack_chain_detail", { chainId });
}

/** Phase-3 runtime decisions: list, detail, and security mode. */
export async function getRuntimeDecisions(limit = 200, detectionId?: string): Promise<RuntimeDecisionListResponse> {
  if (!inTauri()) {
    throw new Error("运行时决策需要连接桌面网关。");
  }
  const response = await invoke<RuntimeDecisionListResponse>("get_runtime_decisions", { limit, detectionId });
  // Rust's RuntimeDecisionRow uses serde(flatten), while the TS model keeps
  // the decision nested for page ergonomics. Normalize both shapes here so
  // older sidecars and the current Tauri command remain compatible.
  const rawRows = (response as unknown as { decisions?: Array<Record<string, unknown>> }).decisions ?? [];
  const decisions = rawRows.map((row) => {
    if (row.decision && typeof row.decision === "object") return row as unknown as RuntimeDecisionListResponse["decisions"][number];
    const { detection, ...decision } = row;
    return { decision, detection } as unknown as RuntimeDecisionListResponse["decisions"][number];
  });
  return { ...response, decisions };
}

export async function getRuntimeDecisionDetail(decisionId: string): Promise<RuntimeDecisionDetail> {
  return invoke<RuntimeDecisionDetail>("get_runtime_decision_detail", { decisionId });
}

export async function getRuntimeSecurityMode(): Promise<RuntimeSecurityMode> {
  if (!inTauri()) throw new Error("运行模式需要连接桌面网关。");
  return invoke<RuntimeSecurityMode>("get_runtime_security_mode");
}

export async function setRuntimeSecurityMode(mode: RuntimeSecurityMode): Promise<RuntimeSecurityMode> {
  if (!inTauri()) throw new Error("未连接桌面网关，运行模式未保存。");
  return invoke<RuntimeSecurityMode>("set_runtime_security_mode", { mode });
}

export interface RuntimeEnforcementOptions {
  preview?: boolean;
  idempotencyKey?: string;
}

export async function blockRuntimeDetection(detectionId: string, actionType?: string, reason = "manual_operator_action", options: RuntimeEnforcementOptions = {}): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) throw new Error("未连接桌面网关，无法预览或执行阻断。");
  return invoke<RuntimeEnforcementResult>("block_runtime_detection", { detectionId, actionType, reason, preview: options.preview, idempotencyKey: options.idempotencyKey });
}

export async function enforceRuntimeDecision(decisionId: string, options: RuntimeEnforcementOptions = {}): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview" };
  return invoke<RuntimeEnforcementResult>("enforce_runtime_decision", { decisionId, preview: options.preview, idempotencyKey: options.idempotencyKey });
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

export async function rollbackRuntimeEnforcement(enforcementId: string): Promise<RuntimeEnforcementResult> {
  if (!inTauri()) return { status: "preview", removed: 0 };
  return invoke<RuntimeEnforcementResult>("rollback_runtime_enforcement", { enforcementId });
}

export async function triggerAgentScan(mode = "full", idempotencyKey?: string): Promise<StaticResourceScanAccepted> {
  if (!inTauri()) return { status: "preview", progress: 0 };
  const status = await invoke<StaticResourceScanAccepted>("trigger_agent_scan", { mode, idempotencyKey });
  return { ...status, scan_id: status.scan_id ?? status.job_id, job_id: status.job_id ?? status.scan_id, type: status.type ?? status.kind };
}

export async function getAgentDetail(agentId: string): Promise<AgentInventory> {
  if (!inTauri()) throw new Error("仅桌面应用可以读取 Agent 详情");
  return invoke<AgentInventory>("get_agent_detail", { agentId });
}

export async function exportAgentsReportPdf(agents: AgentInventory[], defaultFileName: string, directory: string): Promise<string> {
  if (!inTauri()) throw new Error("仅桌面应用可以将 PDF 报告写入所选目录");
  return invoke<string>("export_agents_report_pdf", { agents, defaultFileName, directory });
}

export async function exportPageReportPdf(html: string, defaultFileName: string, directory: string): Promise<string> {
  if (!inTauri()) throw new Error("仅桌面应用可以将 PDF 报告写入所选目录");
  return invoke<string>("export_page_report_pdf", { html, defaultFileName, directory });
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

function camelizeEvent<T>(value: unknown, preserveKeys = false): T {
  if (Array.isArray(value)) return value.map(item => camelizeEvent(item)) as T;
  if (!value || typeof value !== "object") return value as T;
  if (preserveKeys) return value as T;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => {
    const mapped = key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
    return [mapped, camelizeEvent(item, mapped === "attributes" || mapped === "structured")];
  })) as T;
}

export async function getRuntimeEvents(query: import("./types").RuntimeEventQuery = {}): Promise<import("./types").RuntimeEventListResponse> {
  if (!inTauri()) return { items: [], total: 0, page: query.page ?? 1, pageSize: query.pageSize ?? 20 };
  return camelizeEvent(await invoke("get_runtime_events", { query }));
}
export async function getRuntimeEventDetail(eventId: number): Promise<AgentTraceEvent> { return camelizeEvent(await invoke("get_runtime_event_detail", { eventId })); }
export async function getRuntimeEventSummary(query: import("./types").RuntimeEventQuery = {}): Promise<import("./types").RuntimeEventSummary> { if (!inTauri()) return { totalEvents:0,activeAgentCount:0,toolEventCount:0,fileEventCount:0 }; return camelizeEvent(await invoke("get_runtime_event_summary", { query })); }
export async function getRuntimeEventAgents(query: import("./types").RuntimeEventQuery = {}): Promise<import("./types").EventAgentSummary[]> { if (!inTauri()) return []; const response=camelizeEvent<{items:import("./types").EventAgentSummary[]}>(await invoke("get_runtime_event_agents", { query })); return response.items ?? []; }
export async function getRuntimeEventFacets(query: import("./types").RuntimeEventQuery = {}): Promise<import("./types").RuntimeEventFacets> { if (!inTauri()) return {eventTypes:[],eventCategories:[],sources:[],severities:[],outcomes:[]}; return camelizeEvent(await invoke("get_runtime_event_facets", { query })); }

export async function getAuditEvents(query: import("./types").AuditEventQuery = {}): Promise<import("./types").AuditEventListResponse> { if (!inTauri()) return {items:[],total:0,page:query.page??1,pageSize:query.pageSize??20}; return camelizeEvent(await invoke("get_audit_events", { query })); }
export async function getAuditEventDetail(eventId:string):Promise<import("./types").AuditEventRecord>{return camelizeEvent(await invoke("get_audit_event_detail",{eventId}));}
export async function getAuditEventSummary(query:import("./types").AuditEventQuery={}):Promise<import("./types").AuditEventSummary>{if(!inTauri())return{totalEvents:0,relatedAgentCount:0,highOrAboveCount:0,enforcedCount:0};return camelizeEvent(await invoke("get_audit_event_summary",{query}));}
export async function getAuditEventAgents(query:import("./types").AuditEventQuery={}):Promise<import("./types").EventAgentSummary[]>{if(!inTauri())return[];const response=camelizeEvent<{items:import("./types").EventAgentSummary[]}>(await invoke("get_audit_event_agents",{query}));return response.items??[];}
export async function getAuditEventFacets(query:import("./types").AuditEventQuery={}):Promise<import("./types").AuditEventFacets>{if(!inTauri())return{actions:[],severities:[],connectors:[],actors:[],tools:[]};return camelizeEvent(await invoke("get_audit_event_facets",{query}));}

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
  /** Set when the desktop had to leave 18970 because another DefenseClaw home holds it. */
  notice?: string;
}

export async function startProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以启动 Windows 服务");
  await invoke("start_process_guard");
}

export async function stopProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以停止 Windows 服务");
  await invoke("stop_process_guard");
}

export async function ensureGatewayReady(): Promise<LifecycleResult> {
  if (!inTauri()) {
    return { action: "start", success: true, message: "浏览器预览不启动本地 Gateway" };
  }
  return invoke<LifecycleResult>("ensure_gateway_ready");
}

export async function setGatewayRunning(running: boolean): Promise<LifecycleResult> {
  if (!inTauri()) throw new Error("仅桌面应用可以控制网关");
  return invoke<LifecycleResult>(running ? "start_gateway" : "stop_gateway");
}

/**
 * Reads the desktop-level gateway preference. In browser preview the setting
 * is meaningless (there is no window to close and no managed gateway), so the
 * default "stop on close" is returned instead of throwing.
 */
export async function getGatewaySettings(): Promise<GatewayDesktopSettings> {
  if (!inTauri()) return { keepRunningOnClose: false };
  return invoke<GatewayDesktopSettings>("get_gateway_settings");
}

export async function saveGatewaySettings(
  settings: GatewayDesktopSettings,
): Promise<GatewayDesktopSettings> {
  if (!inTauri()) return settings;
  return invoke<GatewayDesktopSettings>("set_gateway_settings", { settings });
}

/**
 * Result of the gateway stop performed while the desktop was last closed.
 * `null` means the previous exit left nothing to report.
 */
export async function getGatewayExitState(): Promise<GatewayExitState | null> {
  if (!inTauri()) return null;
  return invoke<GatewayExitState | null>("get_gateway_exit_state");
}

export async function clearGatewayExitState(): Promise<void> {
  if (!inTauri()) return;
  await invoke("clear_gateway_exit_state");
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

// Runtime detection settings API.

async function requestRuntimeSettings<T>(method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
  if (!inTauri()) throw new Error("异常检测设置需要连接桌面网关。请在 TraceBastion 桌面应用中打开此页面。");
  return invoke<T>("runtime_detection_settings_request", { method, path, body: body ?? null });
}
function runtimeSettingsQueryPath(path: string, query: RuntimeSettingsQuery) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== "") params.set(key, String(value));
  return `${path}?${params}`;
}
const runtimeSettingsTypePath = (id: number) => `/agent-types/${id}`;
const runtimeSettingsRulesPath = (typeId?: number) => typeId === undefined ? "/rules" : `${runtimeSettingsTypePath(typeId)}/rules`;

export const getRuntimeSettingsOverview = () => requestRuntimeSettings<RuntimeSettingsOverview>("GET", "/overview");
export const getGlobalRuntimeRiskPolicy = () => requestRuntimeSettings<RuntimeRiskPolicy>("GET", "/risk-policy/global");
export const getRuntimeRules = (query: RuntimeSettingsQuery, typeId?: number) => requestRuntimeSettings<RuntimeSettingsPage<RuntimeRule>>("GET", runtimeSettingsQueryPath(runtimeSettingsRulesPath(typeId), query));
export const createRuntimeRule = (body: Partial<RuntimeRule>, typeId?: number) => requestRuntimeSettings<RuntimeRule>("POST", runtimeSettingsRulesPath(typeId), body);
export const patchRuntimeRule = (id: number, body: Partial<RuntimeRule>, typeId?: number) => requestRuntimeSettings<RuntimeRule>("PATCH", `${runtimeSettingsRulesPath(typeId)}/${id}`, body);
export const deleteRuntimeRule = (id: number, typeId?: number) => requestRuntimeSettings<{ deleted: boolean }>("DELETE", `${runtimeSettingsRulesPath(typeId)}/${id}`);
export const getRuntimeTypes = (query: RuntimeSettingsQuery) => requestRuntimeSettings<RuntimeSettingsPage<RuntimeTypeRow>>("GET", runtimeSettingsQueryPath("/agent-types", query));
export const getRuntimeTypeDetail = (id: number) => requestRuntimeSettings<RuntimeTypeDetail>("GET", runtimeSettingsTypePath(id));
export const patchRuntimeTypeSettings = (id: number, body: Pick<RuntimeTypeSettings, "enabled" | "inherit_global_rules" | "use_global_risk_policy">) => requestRuntimeSettings<RuntimeTypeSettings>("PATCH", `${runtimeSettingsTypePath(id)}/settings`, body);
export const getRuntimeBlacklist = (id: number, query: RuntimeSettingsQuery) => requestRuntimeSettings<RuntimeSettingsPage<RuntimeBlacklist>>("GET", runtimeSettingsQueryPath(`${runtimeSettingsTypePath(id)}/blacklist`, query));
export const createRuntimeBlacklist = (typeId: number, body: Partial<RuntimeBlacklist>) => requestRuntimeSettings<RuntimeBlacklist>("POST", `${runtimeSettingsTypePath(typeId)}/blacklist`, body);
export const patchRuntimeBlacklist = (typeId: number, id: number, body: Partial<RuntimeBlacklist>) => requestRuntimeSettings<RuntimeBlacklist>("PATCH", `${runtimeSettingsTypePath(typeId)}/blacklist/${id}`, body);
export const deleteRuntimeBlacklist = (typeId: number, id: number) => requestRuntimeSettings<{ deleted: boolean }>("DELETE", `${runtimeSettingsTypePath(typeId)}/blacklist/${id}`);
export const saveRuntimeRiskPolicy = (typeId: number, useGlobal: boolean, policy?: { name: string; rules: RuntimeRiskPolicyRule[] }) => requestRuntimeSettings<RuntimeRiskData>("PUT", `${runtimeSettingsTypePath(typeId)}/risk-policy`, { use_global_risk_policy: useGlobal, policy });
export const evaluateRuntimeEvent = (typeId: number, event: Record<string, unknown>) => requestRuntimeSettings<RuntimeEvaluation>("POST", `${runtimeSettingsTypePath(typeId)}/evaluate`, { event });
