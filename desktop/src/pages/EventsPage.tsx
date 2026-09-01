import { useCallback, useEffect, useMemo, useState } from "react";
import { FilterOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Descriptions, Drawer, Empty, Input, Modal, Segmented, Select, Space, Table, Tabs, Tag, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  getRuntimeDetectionDetail,
  getRuntimeDetectionEvents,
  getRuntimeDetections,
  getRuntimeDecisions,
  getRuntimeDecisionDetail,
  getRuntimeEventsTimeline,
  getRuntimeSecurityMode,
  getRuntimeSecurityAgents,
  getRuntimeSecuritySummary,
  blockRuntimeDetection,
  enforceRuntimeDecision,
  setRuntimeSecurityMode,
  createRuntimeEventReplay,
  getScanStatus,
  rollbackRuntimeEnforcement,
} from "../bridge";
import { formatClock, formatTimestamp, staticRiskTag } from "../app/display";
import { staticRiskMeta } from "../data/staticAssets";
import type {
  RuntimeDetection,
  RuntimeDetectionDetail,
  RuntimeDetectionEvidenceEvent,
  RuntimeDetectionListQuery,
  RuntimeDetectionListResponse,
  RuntimeDecisionRow,
  RuntimeDecisionDetail,
  RuntimeResponseAction,
  RuntimeEventsTimelineBucket,
  RuntimeSecurityMode,
  RuntimeSecurityAgent,
  RuntimeSecuritySummary,
  StaticRisk,
} from "../types";

const { Text, Title } = Typography;

interface EventsPageProps {
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
  refreshNonce?: number;
}

type SeverityFilter = StaticRisk | "all";
type DetectionStatusFilter = "open" | "blocked" | "resolved" | "all";
type DetectionGroupFilter = "all" | "security" | "attack" | "blocked" | "highRisk";

interface SourceBreakdown {
  name: string;
  count: number;
  attack: number;
  blocked: number;
}

async function waitForReplayCompletion(scanId?: string): Promise<void> {
  if (!scanId) return;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = await getScanStatus(scanId);
    if (status.status === "completed") return;
    if (status.status === "failed") throw new Error(status.error || "历史事件重放失败");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new Error("历史事件重放等待超时，请稍后刷新");
}

const emptySummary = (): RuntimeSecuritySummary => ({
  totalDetections: 0,
  securityDetections: 0,
  attackDetections: 0,
  blocked: 0,
  highOrAbove: 0,
  coveredAgents: 0,
});

const emptyDetectionList = (): RuntimeDetectionListResponse => ({
  total: 0,
  items: [],
  detections: [],
  count: 0,
  limit: 200,
  offset: 0,
  summary: { total: 0, attack: 0, blocked: 0, critical: 0, high: 0, open: 0 },
});

const severityOptions: Array<{ label: string; value: SeverityFilter }> = [
  { label: "全部风险", value: "all" },
  { label: "严重", value: "critical" },
  { label: "高风险", value: "high" },
  { label: "中风险", value: "medium" },
  { label: "低风险", value: "low" },
  { label: "信息", value: "info" },
];

const statusOptions: Array<{ label: string; value: DetectionStatusFilter }> = [
  { label: "全部状态", value: "all" },
  { label: "已检测", value: "open" },
  { label: "已阻断", value: "blocked" },
  { label: "已处理", value: "resolved" },
];

function normalizeRisk(value?: string): StaticRisk {
  const normalized = (value || "").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low" || normalized === "info") {
    return normalized;
  }
  return "info";
}

function riskRank(value?: string) {
  return staticRiskMeta[normalizeRisk(value)].rank;
}

function detectionSeverityTag(value?: string) {
  return staticRiskTag(normalizeRisk(value));
}

function isAttackDetection(detection: RuntimeDetection) {
  return (detection.category || "").toLowerCase() === "attack";
}

function isBlockedStatus(status?: string) {
  const normalized = (status || "").toLowerCase();
  return normalized === "blocked" || normalized === "mitigated";
}

function detectionTime(detection: RuntimeDetection) {
  return detection.lastSeenAt || detection.createdAt || detection.firstSeenAt || "";
}

function confidenceText(value?: number) {
  if (value === undefined || Number.isNaN(value)) return "-";
  return `${Math.round((value > 1 ? value / 100 : value) * 100)}%`;
}

function categoryTag(category?: string) {
  const normalized = (category || "").toLowerCase();
  if (normalized === "attack") return <Tag color="red">攻击检测</Tag>;
  if (normalized === "suspicious" || normalized === "security") return <Tag color="blue">安全检测</Tag>;
  return <Tag>{category || "检测"}</Tag>;
}

function statusTag(status?: string) {
  const normalized = (status || "").toLowerCase();
  if (normalized === "blocked" || normalized === "mitigated") return <Tag color="red">已阻断</Tag>;
  if (normalized === "resolved" || normalized === "audited") return <Tag color="green">已处理</Tag>;
  if (normalized === "pending") return <Tag color="default">待处置</Tag>;
  return <Tag color="gold">已检测</Tag>;
}

function sourceLabel(source?: string) {
  const normalized = (source || "").trim();
  const labels: Record<string, string> = {
    runtime_detection: "运行态规则",
    correlation_engine: "关联引擎",
    runtime_policy: "运行态策略",
    event_detection: "事件检测",
  };
  return labels[normalized] ?? (normalized || "runtime_detection");
}

function sourceBreakdownFromDetections(detections: RuntimeDetection[]): SourceBreakdown[] {
  const map = new Map<string, SourceBreakdown>();
  for (const detection of detections) {
    const name = detection.source || "runtime_detection";
    const item = map.get(name) ?? { name, count: 0, attack: 0, blocked: 0 };
    item.count += 1;
    if (isAttackDetection(detection)) item.attack += 1;
    if (isBlockedStatus(detection.status)) item.blocked += 1;
    map.set(name, item);
  }
  return [...map.values()].sort((left, right) => right.count - left.count || left.name.localeCompare(right.name));
}

function detectionMatchesGroup(group: DetectionGroupFilter): Partial<RuntimeDetectionListQuery> {
  if (group === "security") return { category: "suspicious,security" };
  if (group === "attack") return { category: "attack" };
  if (group === "blocked") return { status: "blocked" };
  if (group === "highRisk") return { severity: "critical,high" };
  return {};
}

function evidenceTitle(event: RuntimeDetectionEvidenceEvent) {
  return [event.eventType, event.eventSource ? sourceLabel(event.eventSource) : ""].filter(Boolean).join(" / ") || `Event #${event.eventId}`;
}

function evidenceSummary(event: RuntimeDetectionEvidenceEvent) {
  const action = [event.operation, event.target].filter(Boolean).join(" ");
  return event.detail || action || event.toolName || event.eventType || "-";
}

function attributesText(value?: Record<string, unknown>) {
  if (!value || Object.keys(value).length === 0) return "-";
  return JSON.stringify(value, null, 2);
}

export function EventsPage({ loading = false, onRefresh, refreshNonce = 0 }: EventsPageProps) {
  const [globalSummary, setGlobalSummary] = useState<RuntimeSecuritySummary>(emptySummary);
  const [selectedSummary, setSelectedSummary] = useState<RuntimeSecuritySummary>(emptySummary);
  const [agents, setAgents] = useState<RuntimeSecurityAgent[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>();
  const [detectionsResponse, setDetectionsResponse] = useState<RuntimeDetectionListResponse>(emptyDetectionList);
  const [timeline, setTimeline] = useState<RuntimeEventsTimelineBucket[]>([]);
  const [selectedGroup, setSelectedGroup] = useState<DetectionGroupFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [statusFilter, setStatusFilter] = useState<DetectionStatusFilter>("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [overviewLoading, setOverviewLoading] = useState(false);
  const [listLoading, setListLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [dataError, setDataError] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedDetectionId, setSelectedDetectionId] = useState<string>();
  const [detail, setDetail] = useState<RuntimeDetectionDetail>();
  const [detailEvents, setDetailEvents] = useState<RuntimeDetectionEvidenceEvent[]>([]);
  const [detailLoading, setDetailLoading] = useState(false);
  const [runtimeMode, setRuntimeMode] = useState<RuntimeSecurityMode>("observe");
  const [runtimeModeLoading, setRuntimeModeLoading] = useState(false);
  const [decisions, setDecisions] = useState<RuntimeDecisionRow[]>([]);
  const [decisionDetail, setDecisionDetail] = useState<RuntimeDecisionDetail>();
  const [actionLoading, setActionLoading] = useState(false);
  const [rollbackLoading, setRollbackLoading] = useState<string>();
  const [replayLoading, setReplayLoading] = useState(false);

  const detections = useMemo(
    () => [...(detectionsResponse.items?.length ? detectionsResponse.items : detectionsResponse.detections ?? [])],
    [detectionsResponse],
  );
  const selectedAgent = useMemo(() => agents.find((agent) => agent.agentId === selectedAgentId), [agents, selectedAgentId]);
  const activeSummary = selectedAgentId ? selectedSummary : globalSummary;
  const busy = loading || refreshing || overviewLoading;
  const normalizedQuery = query.trim();

  const listQuery = useMemo<RuntimeDetectionListQuery>(() => {
    const next: RuntimeDetectionListQuery = {
      ...detectionMatchesGroup(selectedGroup),
      agentId: selectedAgentId,
      limit: 300,
      offset: 0,
      sort: "latest",
    };
    if (severityFilter !== "all") next.severity = severityFilter;
    if (statusFilter !== "all") next.status = statusFilter;
    if (sourceFilter !== "all") next.source = sourceFilter;
    if (normalizedQuery) next.keyword = normalizedQuery;
    return next;
  }, [normalizedQuery, selectedAgentId, selectedGroup, severityFilter, sourceFilter, statusFilter]);

  const loadOverview = useCallback(async () => {
    setOverviewLoading(true);
    try {
      const [summary, agentRows, mode, decisionResponse] = await Promise.all([
        getRuntimeSecuritySummary(),
        getRuntimeSecurityAgents(200),
        getRuntimeSecurityMode(),
        getRuntimeDecisions(500),
      ]);
      setGlobalSummary(summary);
      setAgents(agentRows);
      setRuntimeMode(mode);
      setDecisions(decisionResponse.decisions ?? []);
      setSelectedAgentId((current) => current && agentRows.some((agent) => agent.agentId === current) ? current : undefined);
      setDataError("");
    } catch (error) {
      setDataError(`读取运行态检测总览失败：${String(error)}`);
      throw error;
    } finally {
      setOverviewLoading(false);
    }
  }, []);

  const loadSelectedData = useCallback(async () => {
    setListLoading(true);
    try {
      const [summary, list, timelineResponse] = await Promise.all([
        getRuntimeSecuritySummary(selectedAgentId),
        getRuntimeDetections(listQuery),
        getRuntimeEventsTimeline({ agentId: selectedAgentId, bucket: "5m" }),
      ]);
      setSelectedSummary(summary);
      setDetectionsResponse(list);
      setTimeline(timelineResponse.buckets ?? []);
      setDataError("");
    } catch (error) {
      setDataError(`读取运行态检测列表失败：${String(error)}`);
      throw error;
    } finally {
      setListLoading(false);
    }
  }, [listQuery, selectedAgentId]);

  useEffect(() => {
    void loadOverview().catch(() => undefined);
  }, [loadOverview]);

  useEffect(() => {
    void loadSelectedData().catch(() => undefined);
  }, [loadSelectedData]);

  useEffect(() => {
    if (refreshNonce <= 0) return;
    void Promise.all([loadOverview(), loadSelectedData()]).catch(() => undefined);
  }, [loadOverview, loadSelectedData, refreshNonce]);

  const sourceBreakdown = useMemo(() => sourceBreakdownFromDetections(detections), [detections]);
  const sourceOptions = useMemo(() => {
    const options = [{ label: "全部来源", value: "all" }, ...sourceBreakdown.map((source) => ({ label: sourceLabel(source.name), value: source.name }))];
    if (sourceFilter !== "all" && !sourceBreakdown.some((source) => source.name === sourceFilter)) {
      options.push({ label: sourceLabel(sourceFilter), value: sourceFilter });
    }
    return options;
  }, [sourceBreakdown, sourceFilter]);

  const groupSummaries = useMemo(() => [
    { key: "all" as const, title: "全部检测", count: activeSummary.totalDetections, detail: `${activeSummary.coveredAgents} 个 Agent` },
    { key: "security" as const, title: "安全检测", count: activeSummary.securityDetections, detail: "可疑行为与策略命中" },
    { key: "attack" as const, title: "攻击检测", count: activeSummary.attackDetections, detail: "注入、外联与链路攻击" },
    { key: "blocked" as const, title: "已阻断", count: activeSummary.blocked, detail: "后端已执行阻断或缓解" },
    { key: "highRisk" as const, title: "高危及以上", count: activeSummary.highOrAbove, detail: "严重与高风险检测" },
  ], [activeSummary]);

  const filteredAttackCount = detections.filter(isAttackDetection).length;
  const filteredBlockedCount = detections.filter((detection) => isBlockedStatus(detection.status)).length;
  const filteredHighCount = detections.filter((detection) => riskRank(detection.severity) >= 4).length;
  const timelineBuckets = timeline.slice(-24);
  const maxTimeline = Math.max(1, ...timelineBuckets.map((bucket) => bucket.total));

  const selectAgent = (agentId?: string) => {
    setSelectedAgentId(agentId);
    setSelectedGroup("all");
    setSeverityFilter("all");
    setStatusFilter("all");
    setSourceFilter("all");
    setSelectedDetectionId(undefined);
    setDrawerOpen(false);
  };

  const selectGroup = (group: DetectionGroupFilter) => {
    setSelectedGroup(group);
    setSeverityFilter("all");
    setStatusFilter("all");
    setSourceFilter("all");
    setSelectedDetectionId(undefined);
    setDrawerOpen(false);
  };

  const refreshEvents = async () => {
    setRefreshing(true);
    try {
      await onRefresh?.();
      await Promise.all([loadOverview(), loadSelectedData()]);
      message.success("已刷新运行态检测结果");
    } catch (error) {
      message.error(`刷新运行态检测结果失败：${String(error)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const openDetection = async (detection: RuntimeDetection) => {
    setSelectedDetectionId(detection.detectionId);
    setDrawerOpen(true);
    setDetail(undefined);
    setDetailEvents([]);
    setDecisionDetail(undefined);
    setDetailLoading(true);
    try {
      const linkedDecision = decisions.find((candidate) => candidate.decision.detectionId === detection.detectionId || candidate.detection?.detectionId === detection.detectionId)?.decision;
      const [nextDetail, events, nextDecisionDetail] = await Promise.all([
        getRuntimeDetectionDetail(detection.detectionId),
        getRuntimeDetectionEvents(detection.detectionId),
        linkedDecision?.decisionId ? getRuntimeDecisionDetail(linkedDecision.decisionId) : Promise.resolve(undefined),
      ]);
      setDetail(nextDetail);
      setDetailEvents(events.length ? events : nextDetail.evidence ?? []);
      setDecisionDetail(nextDecisionDetail);
    } catch (error) {
      message.error(`读取检测证据失败：${String(error)}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const replayHistoricalEvents = async () => {
    setReplayLoading(true);
    try {
      const accepted = await createRuntimeEventReplay({ agentId: selectedAgentId });
      await waitForReplayCompletion(accepted.scan_id);
      await Promise.all([loadOverview(), loadSelectedData()]);
      message.success("历史事件已重新检测");
    } catch (error) {
      message.error(`历史事件重放失败：${String(error)}`);
    } finally {
      setReplayLoading(false);
    }
  };

  const selectedDecision = useMemo(() => {
    const row = decisions.find((candidate) => candidate.decision.detectionId === selectedDetectionId || candidate.detection?.detectionId === selectedDetectionId);
    return row?.decision;
  }, [decisions, selectedDetectionId]);

  const changeRuntimeMode = async (value: string | number) => {
    const mode = String(value) as RuntimeSecurityMode;
    if (mode !== "observe" && mode !== "action") return;
    setRuntimeModeLoading(true);
    try {
      const next = await setRuntimeSecurityMode(mode);
      setRuntimeMode(next);
      message.success(next === "action" ? "运行态安全已切换为强制处置" : "运行态安全已切换为仅观察");
      await loadOverview();
    } catch (error) {
      message.error(`切换运行态安全模式失败：${String(error)}`);
    } finally {
      setRuntimeModeLoading(false);
    }
  };

  const blockSelectedDetection = async () => {
    if (!selectedDetectionId) return;
    setActionLoading(true);
    const idempotencyKey = globalThis.crypto?.randomUUID?.() ?? `manual-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    try {
      const preview = await blockRuntimeDetection(selectedDetectionId, undefined, "manual_operator_action", { preview: true, idempotencyKey });
      const plan = (preview as { plan?: { enforcement_point?: string; action_type?: string; target?: string } }).plan;
      Modal.confirm({
        title: "确认执行运行时阻断？",
        content: `执行点：${plan?.enforcement_point || "后端策略"}；动作：${plan?.action_type || "BLOCK"}；目标：${plan?.target || "由证据链确定"}。确认后会产生实际处置副作用。`,
        okText: "确认阻断",
        okButtonProps: { danger: true },
        cancelText: "取消",
        onCancel: () => setActionLoading(false),
        onOk: async () => {
          try {
            const result = await blockRuntimeDetection(selectedDetectionId, undefined, "manual_operator_action", { idempotencyKey });
            if (result.status === "blocked") message.success("阻断已执行");
            else if (result.status === "dispatched") message.info("处置已转交执行模块，检测保持待确认");
            else message.warning(`阻断未执行：${result.status || "unknown"}`);
            await Promise.all([loadOverview(), loadSelectedData()]);
            const decisionId = result.decision?.decisionId || selectedDecision?.decisionId;
            if (decisionId) {
              setDecisionDetail(await getRuntimeDecisionDetail(decisionId));
            }
          } finally {
            setActionLoading(false);
          }
        },
      });
    } catch (error) {
      message.error(`执行阻断失败：${String(error)}`);
      setActionLoading(false);
    }
  };

  const enforceSelectedDecision = async () => {
    if (!selectedDecision?.decisionId) return;
    setActionLoading(true);
    try {
      const result = await enforceRuntimeDecision(selectedDecision.decisionId);
      if (result.status === "blocked") {
        message.success("运行态决策已执行");
      } else if (result.status === "dispatched") {
        message.info("运行态决策已转交执行模块，检测保持待确认");
      } else {
        message.warning(`运行态决策未执行：${result.status || "unknown"}`);
      }
      await Promise.all([loadOverview(), loadSelectedData()]);
      setDecisionDetail(await getRuntimeDecisionDetail(selectedDecision.decisionId));
    } catch (error) {
      message.error(`执行运行态决策失败：${String(error)}`);
    } finally {
      setActionLoading(false);
    }
  };

  const rollbackResponse = async (response: RuntimeResponseAction) => {
    const enforcementId = response.responseId || response.decisionId || response.target;
    if (!enforcementId) return;
    setRollbackLoading(enforcementId);
    try {
      const result = await rollbackRuntimeEnforcement(enforcementId);
      if (result.status === "rolled_back") {
        message.success("处置已回滚");
      } else {
        message.warning(`处置未回滚：${result.status || "unknown"}`);
      }
      const decisionId = selectedDecision?.decisionId || response.decisionId;
      await Promise.all([loadOverview(), loadSelectedData()]);
      if (decisionId) setDecisionDetail(await getRuntimeDecisionDetail(decisionId));
    } catch (error) {
      message.error(`回滚处置失败：${String(error)}`);
    } finally {
      setRollbackLoading(undefined);
    }
  };

  const selectedDetection = detail?.detection?.detectionId
    ? detail.detection
    : detections.find((detection) => detection.detectionId === selectedDetectionId);
  const evidenceEvents = detailEvents.length ? detailEvents : detail?.evidence ?? [];

  const columns: ColumnsType<RuntimeDetection> = [
    {
      title: "时间",
      width: 176,
      sorter: (left, right) => new Date(detectionTime(left)).getTime() - new Date(detectionTime(right)).getTime(),
      render: (_, row) => <Text className="mono">{formatTimestamp(detectionTime(row))}</Text>,
    },
    { title: "类型", width: 112, render: (_, row) => categoryTag(row.category) },
    {
      title: "Runtime Detection",
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{row.title || row.detectionType || row.detectionId}</Text>
          <Text type="secondary">{row.detectionType || row.type || "runtime_detection"} / {row.ruleId || "rule"}</Text>
          <Text code className="event-evidence">{row.description || row.detail || row.remediation || "-"}</Text>
        </Space>
      ),
    },
    { title: "风险", dataIndex: "severity", width: 96, render: detectionSeverityTag },
    { title: "状态", dataIndex: "status", width: 104, render: statusTag },
    {
      title: "关联",
      width: 190,
      render: (_, row) => <Text code>{row.traceId || row.sessionId || row.detectionId}</Text>,
    },
    { title: "证据", dataIndex: "eventCount", width: 86, render: (value) => <Tag color="geekblue">{value || 0}</Tag> },
    { title: "来源", dataIndex: "source", width: 136, render: (value) => <Tag>{sourceLabel(value)}</Tag> },
  ];

  return (
    <section className="events-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">RUNTIME SECURITY</Text>
          <Title level={2}>事件检测</Title>
          <Text type="secondary">检测结果来自 Go 后端 runtime_detections；原始行为事件保留在检测详情的证据链中。</Text>
        </div>
        <Space wrap>
          <Tag color="blue">Agent {globalSummary.coveredAgents}</Tag>
          <Tag color="red">攻击 {globalSummary.attackDetections}</Tag>
          <Segmented
            disabled={runtimeModeLoading || busy}
            options={[{ label: "仅观察", value: "observe" }, { label: "强制处置", value: "action" }]}
            value={runtimeMode}
            onChange={(value) => void changeRuntimeMode(value)}
          />
          <Button icon={<ReloadOutlined />} loading={busy || listLoading} onClick={() => void refreshEvents()}>
            刷新数据
          </Button>
          <Button loading={replayLoading} onClick={() => void replayHistoricalEvents()}>
            重放历史检测
          </Button>
        </Space>
      </div>

      {dataError ? <Alert type="warning" showIcon message={dataError} /> : null}

      <div className="event-summary-grid">
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">检测结果</Text>
          <div className="event-metric-value">{globalSummary.totalDetections}</div>
          <Text>最近 {globalSummary.latestAt ? formatTimestamp(globalSummary.latestAt) : "-"}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">攻击检测</Text>
          <div className="event-metric-value attack">{globalSummary.attackDetections}</div>
          <Text>安全检测 {globalSummary.securityDetections}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">已阻断</Text>
          <div className="event-metric-value blocked">{globalSummary.blocked}</div>
          <Text>高危及以上 {globalSummary.highOrAbove}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">覆盖 Agent</Text>
          <div className="event-metric-value security">{globalSummary.coveredAgents}</div>
          <Text>窗口 {globalSummary.windowStart ? `${formatClock(globalSummary.windowStart)} - ${formatClock(globalSummary.windowEnd ?? "")}` : "-"}</Text>
        </Card>
      </div>

      <div className="event-workbench">
        <aside className="event-side-panel static-agent-panel">
          <div className="static-panel-heading">
            <Text type="secondary">Agents</Text>
            <Tag color="blue">{agents.length}</Tag>
          </div>
          <div className="static-agent-list">
            <button
              className={`static-agent-item ${selectedAgentId ? "" : "static-agent-item-active"}`}
              type="button"
              onClick={() => selectAgent(undefined)}
            >
              <span className="static-agent-name">全部 Agent</span>
              <span className="static-agent-source">runtime-security</span>
              <span className="static-agent-meta">
                <span>{globalSummary.totalDetections} Detections</span>
                <span className={globalSummary.attackDetections || globalSummary.blocked ? "static-agent-risk" : ""}>
                  {globalSummary.attackDetections} Attacks · {globalSummary.blocked} Blocked
                </span>
              </span>
            </button>
            {agents.length ? agents.map((agent) => (
              <button
                key={agent.agentId}
                className={`static-agent-item ${selectedAgentId === agent.agentId ? "static-agent-item-active" : ""}`}
                type="button"
                onClick={() => selectAgent(agent.agentId)}
              >
                <span className="static-agent-name">{agent.agentName || agent.agentId}</span>
                <span className="static-agent-source">{agent.agentType || agent.runtimeStatus || "Agent"}</span>
                <span className="static-agent-meta">
                  <span>{agent.detectionCount} Detections</span>
                  <span className={agent.attackCount || agent.blockedCount ? "static-agent-risk" : ""}>
                    {agent.attackCount} Attacks · {agent.blockedCount} Blocked
                  </span>
                </span>
              </button>
            )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent 检测" />}
          </div>

          <div className="event-panel-heading event-panel-section">
            <Text strong>检测来源</Text>
            <Tag>{sourceBreakdown.length}</Tag>
          </div>
          <div className="event-breakdown-list">
            {sourceBreakdown.length ? sourceBreakdown.map((source) => (
              <button
                key={source.name}
                className={`event-breakdown-item ${sourceFilter === source.name ? "event-breakdown-active" : ""}`}
                type="button"
                onClick={() => setSourceFilter(sourceFilter === source.name ? "all" : source.name)}
              >
                <span>{sourceLabel(source.name)}</span>
                <strong>{source.count}</strong>
                <em>攻击 {source.attack} · 阻断 {source.blocked}</em>
              </button>
            )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无来源" />}
          </div>
        </aside>

        <main className="event-main-panel">
          <div className="event-agent-context">
            <div>
              <Title level={3}>{selectedAgent ? selectedAgent.agentName || selectedAgent.agentId : "全部 Agent"}</Title>
              <Text type="secondary">
                {activeSummary.totalDetections} Detections · {activeSummary.attackDetections} Attacks · {activeSummary.blocked} Blocked
              </Text>
            </div>
            <Space direction="vertical" align="end" size={6}>
              <Text className="mono event-agent-path">{selectedAgent?.agentId || "runtime-security"}</Text>
              <Space wrap>
                <Tag color="blue">安全 {activeSummary.securityDetections}</Tag>
                <Tag color="red">攻击 {activeSummary.attackDetections}</Tag>
                <Tag>最近 {activeSummary.latestAt ? formatTimestamp(activeSummary.latestAt) : "-"}</Tag>
              </Space>
            </Space>
          </div>

          <div className="event-type-strip">
            {groupSummaries.map((group) => (
              <button
                key={group.key}
                className={`event-type-card ${selectedGroup === group.key ? "event-type-card-active" : ""}`}
                type="button"
                onClick={() => selectGroup(group.key)}
              >
                <strong>{group.title}</strong>
                <span>{group.count} Detections</span>
                <em>{group.detail}</em>
              </button>
            ))}
          </div>

          <Card bordered={false} className="event-filter-card">
            <div className="event-filter-bar">
              <Input
                allowClear
                prefix={<SearchOutlined />}
                placeholder="搜索检测、规则、Trace、Session、工具或目标"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
              <Select
                value={severityFilter}
                options={severityOptions}
                onChange={(value) => setSeverityFilter(value)}
              />
              <Select
                value={statusFilter}
                options={statusOptions}
                onChange={(value) => setStatusFilter(value)}
              />
              <Select value={sourceFilter} options={sourceOptions} onChange={(value) => setSourceFilter(value)} />
              <Button icon={<FilterOutlined />} onClick={() => void loadSelectedData()}>
                应用
              </Button>
            </div>
            <div className="event-filter-foot">
              <Text type="secondary">当前筛选 {detections.length} / {detectionsResponse.total}</Text>
              <Space wrap>
                <Tag color="red">攻击 {filteredAttackCount}</Tag>
                <Tag color="volcano">高危 {filteredHighCount}</Tag>
                <Tag color="gold">阻断 {filteredBlockedCount}</Tag>
              </Space>
            </div>
          </Card>

          <Card bordered={false} className="event-timeline-card">
            <div className="event-timeline-header">
              <Text strong>运行态事件时间线</Text>
              <Text type="secondary">5 分钟窗口</Text>
            </div>
            {timelineBuckets.length ? (
              <div className="event-timeline">
                {timelineBuckets.map((bucket) => (
                  <div key={bucket.bucket} className="event-timeline-bar" title={`${formatTimestamp(bucket.bucket)} · ${bucket.total}`}>
                    <span style={{ height: `${Math.max(8, Math.round((bucket.total / maxTimeline) * 78))}px` }} />
                    <em>{bucket.time || formatClock(bucket.bucket)}</em>
                    {bucket.network + bucket.process + bucket.file > 0 && <strong>{bucket.network + bucket.process + bucket.file}</strong>}
                  </div>
                ))}
              </div>
            ) : (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无时间线数据" />
            )}
          </Card>

          <Card bordered={false} className="event-table-card" title="Runtime Detection" extra={<Text type="secondary">{detectionsResponse.total} 项检测</Text>}>
            <Table
              rowKey="detectionId"
              loading={loading || refreshing || listLoading}
              columns={columns}
              dataSource={detections}
              pagination={{ pageSize: 12 }}
              locale={{ emptyText: "暂无运行态检测结果" }}
              scroll={{ x: 1180 }}
              rowClassName={(row) => row.detectionId === selectedDetectionId ? "event-table-row-active" : ""}
              onRow={(row) => ({ onClick: () => void openDetection(row) })}
            />
          </Card>
        </main>
      </div>

      <Drawer
        className="event-detail-drawer"
        title={selectedDetection ? (
          <Space direction="vertical" size={4}>
            <Space wrap>{categoryTag(selectedDetection.category)}{detectionSeverityTag(selectedDetection.severity)}{statusTag(selectedDetection.status)}</Space>
            <Text strong>{selectedDetection.title || selectedDetection.detectionId}</Text>
          </Space>
        ) : "检测详情"}
        open={drawerOpen}
        width={640}
        loading={detailLoading}
        onClose={() => {
          setDrawerOpen(false);
          setSelectedDetectionId(undefined);
          setDecisionDetail(undefined);
        }}
      >
        {selectedDetection ? (
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Card size="small" bordered={false}>
              <Space wrap>
                <Button danger loading={actionLoading} onClick={() => void blockSelectedDetection()}>
                  立即阻断
                </Button>
                {selectedDecision?.decision === "BLOCK" ? (
                  <Button loading={actionLoading} onClick={() => void enforceSelectedDecision()}>
                    执行已有决策
                  </Button>
                ) : null}
                <Tag color={runtimeMode === "action" ? "red" : "blue"}>
                  当前模式：{runtimeMode === "action" ? "强制处置" : "仅观察"}
                </Tag>
                {selectedDecision ? <Tag>决策：{selectedDecision.decision}</Tag> : <Tag>尚无策略决策</Tag>}
              </Space>
              <div style={{ marginTop: 8 }}>
                <Text type="secondary">
                  “立即阻断”会创建人工 BLOCK 决策；只有后端返回 executed 时，检测才会标记为已阻断。
                </Text>
              </div>
            </Card>
            <Card size="small" bordered={false} title={`处置执行记录 ${decisionDetail?.responses?.length ?? 0}`}>
              {decisionDetail?.responses?.length ? (
                <Space direction="vertical" size={10} style={{ width: "100%" }}>
                  {decisionDetail.responses.map((response) => {
                    const normalizedStatus = (response.status || "").toLowerCase();
                    const canRollback = (response.rollbackSupported || response.executor === "proxy") && normalizedStatus === "executed";
                    const responseKey = response.responseId || response.decisionId || response.target || normalizedStatus;
                    return (
                      <Card key={responseKey} size="small" type="inner">
                        <Space direction="vertical" size={4} style={{ width: "100%" }}>
                          <Space wrap>
                            <Tag color={normalizedStatus === "executed" ? "green" : normalizedStatus === "failed" ? "red" : "gold"}>{response.status || "unknown"}</Tag>
                            <Tag>{response.executor || "未指定执行器"}</Tag>
                            {response.actionType ? <Tag>{response.actionType}</Tag> : null}
                            {response.rollbackSupported || response.executor === "proxy" ? <Tag color="blue">可回滚</Tag> : <Tag>不可回滚</Tag>}
                          </Space>
                          <Text type="secondary">目标：{response.target || "-"}</Text>
                          <Text type="secondary">结果：{response.result || "-"}</Text>
                          {canRollback ? (
                            <Button size="small" danger loading={rollbackLoading === responseKey} onClick={() => void rollbackResponse(response)}>
                              回滚处置
                            </Button>
                          ) : null}
                        </Space>
                      </Card>
                    );
                  })}
                </Space>
              ) : <Text type="secondary">尚无后端执行记录；仅在决策落地或手动处置后显示。</Text>}
            </Card>
            <Tabs
            items={[
              {
                key: "overview",
                label: "概览",
                children: (
                  <Descriptions column={1} size="small" bordered>
                    <Descriptions.Item label="Detection ID"><Text code>{selectedDetection.detectionId}</Text></Descriptions.Item>
                    <Descriptions.Item label="Agent">{selectedDetection.agentName || detail?.agent?.name || selectedDetection.agentId || "-"}</Descriptions.Item>
                    <Descriptions.Item label="检测类型">{selectedDetection.detectionType || selectedDetection.type || "-"}</Descriptions.Item>
                    <Descriptions.Item label="规则">{selectedDetection.ruleId || "-"}</Descriptions.Item>
                    <Descriptions.Item label="来源">{sourceLabel(selectedDetection.source)}</Descriptions.Item>
                    <Descriptions.Item label="置信度">{confidenceText(selectedDetection.confidence)}</Descriptions.Item>
                    <Descriptions.Item label="首次发现">{formatTimestamp(selectedDetection.firstSeenAt || "")}</Descriptions.Item>
                    <Descriptions.Item label="最近发现">{formatTimestamp(detectionTime(selectedDetection))}</Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: "evidence",
                label: `证据链 ${evidenceEvents.length}`,
                children: evidenceEvents.length ? (
                  <Space direction="vertical" size={12} className="event-detail-stack">
                    {evidenceEvents.map((event, index) => (
                      <div className="event-detail-block" key={`${event.eventId}-${event.sequence ?? index}`}>
                        <Space wrap>
                          <Tag color="geekblue">#{event.sequence ?? index + 1}</Tag>
                          <Tag>{event.role || "evidence"}</Tag>
                          <Tag>{evidenceTitle(event)}</Tag>
                          {event.severity ? detectionSeverityTag(event.severity) : null}
                        </Space>
                        <pre>{evidenceSummary(event)}</pre>
                        <Descriptions column={1} size="small" bordered>
                          <Descriptions.Item label="Event ID"><Text code>{event.eventId || "-"}</Text></Descriptions.Item>
                          <Descriptions.Item label="时间">{formatTimestamp(event.timestamp || "")}</Descriptions.Item>
                          <Descriptions.Item label="Agent">{event.agentName || event.agentId || "-"}</Descriptions.Item>
                          <Descriptions.Item label="目标">{event.target || "-"}</Descriptions.Item>
                          <Descriptions.Item label="工具">{event.toolName || "-"}</Descriptions.Item>
                          <Descriptions.Item label="结果">{event.outcome || "-"}</Descriptions.Item>
                          <Descriptions.Item label="Trace"><Text code>{event.traceId || "-"}</Text></Descriptions.Item>
                          <Descriptions.Item label="Session"><Text code>{event.sessionId || "-"}</Text></Descriptions.Item>
                        </Descriptions>
                      </div>
                    ))}
                  </Space>
                ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无证据事件" />,
              },
              {
                key: "context",
                label: "上下文",
                children: (
                  <Space direction="vertical" size={12} className="event-detail-stack">
                    <Descriptions column={1} size="small" bordered>
                      <Descriptions.Item label="Trace"><Text code>{selectedDetection.traceId || detail?.trace?.traceId || "-"}</Text></Descriptions.Item>
                      <Descriptions.Item label="Session"><Text code>{selectedDetection.sessionId || detail?.runtimeSession?.sessionId || "-"}</Text></Descriptions.Item>
                      <Descriptions.Item label="事件数量">{selectedDetection.eventCount ?? evidenceEvents.length}</Descriptions.Item>
                      <Descriptions.Item label="说明">{selectedDetection.detail || selectedDetection.description || "-"}</Descriptions.Item>
                      <Descriptions.Item label="处置建议">{selectedDetection.remediation || "-"}</Descriptions.Item>
                    </Descriptions>
                    <div className="event-detail-block">
                      <Text type="secondary">结构化属性</Text>
                      <pre>{attributesText(selectedDetection.attributes)}</pre>
                    </div>
                  </Space>
                ),
              },
            ]}
            />
          </Space>
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
        )}
      </Drawer>
    </section>
  );
}
