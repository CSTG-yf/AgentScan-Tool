import { useEffect, useMemo, useState } from "react";
import { FilterOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tabs, Tag, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { eventKindTag, eventStatusTag, formatClock, formatTimestamp, staticRiskTag } from "../app/display";
import { eventKindMeta } from "../data/events";
import { staticRiskMeta } from "../data/staticAssets";
import type {
  DetectedEvent,
  EventAgentBreakdown,
  EventBreakdown,
  EventDetectionSnapshot,
  EventDetectionSummary,
  EventFilter,
  EventStatus,
  EventTimelineBucket,
  StaticRisk,
} from "../types";

const { Text, Title } = Typography;

interface EventsPageProps {
  snapshot?: EventDetectionSnapshot;
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
}

type SeverityFilter = StaticRisk | "all";
type StatusFilter = EventStatus | "all";
type EventGroupFilter = "all" | "security" | "attack" | "blocked" | "highRisk";

const severityOptions: Array<{ label: string; value: SeverityFilter }> = [
  { label: "全部风险", value: "all" },
  { label: "严重", value: "critical" },
  { label: "高风险", value: "high" },
  { label: "中风险", value: "medium" },
  { label: "低风险", value: "low" },
  { label: "信息", value: "info" },
];

const statusOptions: Array<{ label: string; value: StatusFilter }> = [
  { label: "全部状态", value: "all" },
  { label: "已阻断", value: "blocked" },
  { label: "已检测", value: "detected" },
  { label: "已审计", value: "audited" },
  { label: "待处置", value: "pending" },
];

function riskRank(risk: StaticRisk) {
  return staticRiskMeta[risk]?.rank ?? 0;
}

function agentKey(agent: Pick<EventAgentBreakdown, "agent" | "runtime">) {
  return `${agent.agent}::${agent.runtime}`;
}

function eventAgentKey(event: DetectedEvent) {
  return `${event.agent}::${event.runtime}`;
}

function correlationKey(event: DetectedEvent) {
  if (event.correlationKey) return event.correlationKey;
  if (event.traceId) return `trace:${event.traceId}`;
  if (event.sessionId) return `session:${event.sessionId}`;
  return `agent:${event.agent}:${Math.floor(new Date(event.occurredAt).getTime() / 300000)}`;
}

function computeSummary(events: DetectedEvent[]): EventDetectionSummary {
  const keys = new Set<string>();
  const agents = new Set<string>();
  const sources = new Set<string>();
  let windowStart = "";
  let windowEnd = "";
  const summary: EventDetectionSummary = {
    total: events.length,
    security: 0,
    attack: 0,
    blocked: 0,
    critical: 0,
    high: 0,
    correlated: 0,
    agents: 0,
    sources: 0,
  };

  for (const event of events) {
    if (!windowStart || event.occurredAt < windowStart) windowStart = event.occurredAt;
    if (!windowEnd || event.occurredAt > windowEnd) windowEnd = event.occurredAt;
    if (event.kind === "attack") summary.attack += 1;
    else summary.security += 1;
    if (event.status === "blocked") summary.blocked += 1;
    if (event.severity === "critical") summary.critical += 1;
    if (event.severity === "high") summary.high += 1;
    keys.add(correlationKey(event));
    agents.add(eventAgentKey(event));
    sources.add(event.source || "gateway");
  }

  summary.correlated = keys.size;
  summary.agents = agents.size;
  summary.sources = sources.size;
  summary.windowStart = windowStart;
  summary.windowEnd = windowEnd;
  return summary;
}

function buildSourceBreakdown(events: DetectedEvent[]): EventBreakdown[] {
  const map = new Map<string, EventBreakdown>();
  for (const event of events) {
    const name = event.source || "gateway";
    const item = map.get(name) ?? { name, count: 0, attack: 0, blocked: 0, maxSeverity: "info" };
    item.count += 1;
    if (event.kind === "attack") item.attack += 1;
    if (event.status === "blocked") item.blocked += 1;
    if (riskRank(event.severity) > riskRank(item.maxSeverity)) item.maxSeverity = event.severity;
    map.set(name, item);
  }
  return [...map.values()].sort((left, right) => right.count - left.count || left.name.localeCompare(right.name));
}

function buildAgentBreakdown(events: DetectedEvent[]): EventAgentBreakdown[] {
  const map = new Map<string, EventAgentBreakdown>();
  for (const event of events) {
    const key = eventAgentKey(event);
    const item = map.get(key) ?? {
      agent: event.agent,
      runtime: event.runtime,
      count: 0,
      attack: 0,
      blocked: 0,
      maxSeverity: "info",
      lastSeen: event.occurredAt,
      sources: [],
    };
    item.count += 1;
    if (event.kind === "attack") item.attack += 1;
    if (event.status === "blocked") item.blocked += 1;
    if (riskRank(event.severity) > riskRank(item.maxSeverity)) item.maxSeverity = event.severity;
    if (event.occurredAt > item.lastSeen) item.lastSeen = event.occurredAt;
    if (event.source && !item.sources.includes(event.source)) item.sources.push(event.source);
    map.set(key, item);
  }
  return [...map.values()].sort((left, right) => riskRank(right.maxSeverity) - riskRank(left.maxSeverity) || right.count - left.count || left.agent.localeCompare(right.agent));
}

function buildTimeline(events: DetectedEvent[]): EventTimelineBucket[] {
  const map = new Map<string, EventTimelineBucket>();
  for (const event of events) {
    const timestamp = new Date(event.occurredAt).getTime();
    if (Number.isNaN(timestamp)) continue;
    const bucket = new Date(Math.floor(timestamp / 300000) * 300000).toISOString();
    const item = map.get(bucket) ?? { bucket, total: 0, attack: 0, blocked: 0, highRisk: 0 };
    item.total += 1;
    if (event.kind === "attack") item.attack += 1;
    if (event.status === "blocked") item.blocked += 1;
    if (riskRank(event.severity) >= 4) item.highRisk += 1;
    map.set(bucket, item);
  }
  return [...map.values()].sort((left, right) => left.bucket.localeCompare(right.bucket)).slice(-24);
}

function eventMatches(event: DetectedEvent, query: string) {
  if (!query) return true;
  return [
    event.agent,
    event.runtime,
    event.category,
    event.subtype,
    event.title,
    event.evidence,
    event.action,
    event.traceId,
    event.sessionId,
    event.target,
    event.toolName,
    event.destinationApp,
    event.reason,
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

function groupMatches(event: DetectedEvent, group: EventGroupFilter) {
  if (group === "security") return event.kind === "security";
  if (group === "attack") return event.kind === "attack";
  if (group === "blocked") return event.status === "blocked";
  if (group === "highRisk") return riskRank(event.severity) >= 4;
  return true;
}

export function EventsPage({ snapshot, loading = false, onRefresh }: EventsPageProps) {
  const [selectedAgentKey, setSelectedAgentKey] = useState<string>();
  const [selectedEventGroup, setSelectedEventGroup] = useState<EventGroupFilter>("all");
  const [kindFilter, setKindFilter] = useState<EventFilter>("all");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [selectedEventId, setSelectedEventId] = useState<string>();
  const [eventDetailOpen, setEventDetailOpen] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const events = useMemo(
    () => [...(snapshot?.events ?? [])].sort((left, right) => new Date(right.occurredAt).getTime() - new Date(left.occurredAt).getTime()),
    [snapshot],
  );
  const globalSummary = snapshot?.summary ?? computeSummary(events);
  const globalAgentBreakdown = useMemo(
    () => (snapshot?.agentBreakdown?.length ? snapshot.agentBreakdown : buildAgentBreakdown(events)),
    [events, snapshot],
  );

  useEffect(() => {
    if (!globalAgentBreakdown.length) {
      setSelectedAgentKey(undefined);
      setSelectedEventId(undefined);
      setEventDetailOpen(false);
      return;
    }
    if (!selectedAgentKey || !globalAgentBreakdown.some((agent) => agentKey(agent) === selectedAgentKey)) {
      setSelectedAgentKey(agentKey(globalAgentBreakdown[0]));
      setSelectedEventGroup("all");
      setSourceFilter("all");
      setSelectedEventId(undefined);
      setEventDetailOpen(false);
    }
  }, [globalAgentBreakdown, selectedAgentKey]);

  const selectedAgent = useMemo(
    () => globalAgentBreakdown.find((agent) => agentKey(agent) === selectedAgentKey),
    [globalAgentBreakdown, selectedAgentKey],
  );
  const selectedAgentEvents = useMemo(
    () => selectedAgentKey ? events.filter((event) => eventAgentKey(event) === selectedAgentKey) : [],
    [events, selectedAgentKey],
  );
  const selectedSummary = useMemo(() => computeSummary(selectedAgentEvents), [selectedAgentEvents]);
  const selectedSourceBreakdown = useMemo(() => buildSourceBreakdown(selectedAgentEvents), [selectedAgentEvents]);
  const selectedTimeline = useMemo(() => buildTimeline(selectedAgentEvents), [selectedAgentEvents]);
  const normalizedQuery = query.trim().toLowerCase();

  useEffect(() => {
    if (sourceFilter !== "all" && !selectedSourceBreakdown.some((source) => source.name === sourceFilter)) {
      setSourceFilter("all");
    }
  }, [selectedSourceBreakdown, sourceFilter]);

  const eventGroupSummaries = useMemo(() => {
    const security = selectedAgentEvents.filter((event) => event.kind === "security");
    const attack = selectedAgentEvents.filter((event) => event.kind === "attack");
    const blocked = selectedAgentEvents.filter((event) => event.status === "blocked");
    const highRisk = selectedAgentEvents.filter((event) => riskRank(event.severity) >= 4);
    return [
      { key: "all" as const, title: "全部事件", count: selectedAgentEvents.length, detail: `${selectedSummary.sources} 来源 · ${selectedSummary.correlated} 关联组` },
      { key: "security" as const, title: "安全事件", count: security.length, detail: eventKindMeta.security.description },
      { key: "attack" as const, title: "攻击事件", count: attack.length, detail: eventKindMeta.attack.description },
      { key: "blocked" as const, title: "已阻断", count: blocked.length, detail: "后端防护已经执行阻断或拒绝动作" },
      { key: "highRisk" as const, title: "高风险及以上", count: highRisk.length, detail: "优先查看严重和高风险事件" },
    ];
  }, [selectedAgentEvents, selectedSummary]);

  const filteredEvents = useMemo(
    () =>
      selectedAgentEvents.filter((event) => {
        if (!groupMatches(event, selectedEventGroup)) return false;
        if (kindFilter !== "all" && event.kind !== kindFilter) return false;
        if (severityFilter !== "all" && event.severity !== severityFilter) return false;
        if (statusFilter !== "all" && event.status !== statusFilter) return false;
        if (sourceFilter !== "all" && event.source !== sourceFilter) return false;
        return eventMatches(event, normalizedQuery);
      }),
    [kindFilter, normalizedQuery, selectedAgentEvents, selectedEventGroup, severityFilter, sourceFilter, statusFilter],
  );

  useEffect(() => {
    if (!filteredEvents.length) {
      setSelectedEventId(undefined);
      setEventDetailOpen(false);
      return;
    }
    if (selectedEventId && !filteredEvents.some((event) => event.id === selectedEventId)) {
      setSelectedEventId(undefined);
      setEventDetailOpen(false);
    }
  }, [filteredEvents, selectedEventId]);

  const selectedEvent = filteredEvents.find((event) => event.id === selectedEventId);
  const sourceOptions = useMemo(
    () => [{ label: "全部来源", value: "all" }, ...selectedSourceBreakdown.map((source) => ({ label: source.name, value: source.name }))],
    [selectedSourceBreakdown],
  );

  const selectAgent = (key: string) => {
    setSelectedAgentKey(key);
    setSelectedEventGroup("all");
    setSourceFilter("all");
    setSelectedEventId(undefined);
    setEventDetailOpen(false);
  };

  const selectGroup = (group: EventGroupFilter) => {
    setSelectedEventGroup(group);
    setKindFilter("all");
    setSeverityFilter("all");
    setStatusFilter("all");
    setSelectedEventId(undefined);
    setEventDetailOpen(false);
  };

  const refreshEvents = async () => {
    if (!onRefresh) return;
    setRefreshing(true);
    try {
      await onRefresh();
      message.success("已刷新后端事件检测结果");
    } catch (error) {
      message.error(`刷新事件检测结果失败：${String(error)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const columns: ColumnsType<DetectedEvent> = [
    {
      title: "时间",
      dataIndex: "occurredAt",
      width: 176,
      sorter: (left, right) => new Date(left.occurredAt).getTime() - new Date(right.occurredAt).getTime(),
      render: (value) => <Text className="mono">{formatTimestamp(value)}</Text>,
    },
    { title: "类型", dataIndex: "kind", width: 104, render: eventKindTag },
    {
      title: "事件",
      dataIndex: "title",
      render: (value, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{value}</Text>
          <Text type="secondary">{row.category} / {row.subtype}</Text>
          <Text code className="event-evidence">{row.evidence}</Text>
        </Space>
      ),
    },
    { title: "风险", dataIndex: "severity", width: 96, render: staticRiskTag },
    { title: "状态", dataIndex: "status", width: 104, render: eventStatusTag },
    {
      title: "关联",
      width: 190,
      render: (_, row) => <Text code>{row.traceId || row.sessionId || row.correlationKey || "-"}</Text>,
    },
    { title: "来源", dataIndex: "source", width: 136, render: (value) => <Tag>{value}</Tag> },
  ];

  const maxTimeline = Math.max(1, ...selectedTimeline.map((bucket) => bucket.total));

  return (
    <section className="events-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">EVENT DETECTION</Text>
          <Title level={2}>事件检测</Title>
          <Text type="secondary">按 Agent 归并展示 Go 后端检测到的行为事件、审计事件、运行时发现和阻断结果。</Text>
        </div>
        <Space wrap>
          <Tag color="geekblue">来源 {globalSummary.sources}</Tag>
          <Tag color="purple">关联组 {globalSummary.correlated}</Tag>
          <Button icon={<ReloadOutlined />} loading={loading || refreshing} onClick={() => void refreshEvents()}>
            重新检测
          </Button>
        </Space>
      </div>

      {snapshot?.warning ? <Alert type="warning" showIcon message={snapshot.warning} /> : null}

      <div className="event-summary-grid">
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">全部事件</Text>
          <div className="event-metric-value">{globalSummary.total}</div>
          <Text>最近 {globalSummary.windowEnd ? formatTimestamp(globalSummary.windowEnd) : "-"}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">攻击事件</Text>
          <div className="event-metric-value attack">{globalSummary.attack}</div>
          <Text>{eventKindMeta.attack.description}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">已阻断</Text>
          <div className="event-metric-value blocked">{globalSummary.blocked}</div>
          <Text>严重 {globalSummary.critical} · 高风险 {globalSummary.high}</Text>
        </Card>
        <Card bordered={false} className="event-metric-card">
          <Text type="secondary">覆盖 Agent</Text>
          <div className="event-metric-value security">{globalSummary.agents}</div>
          <Text>窗口 {globalSummary.windowStart ? `${formatClock(globalSummary.windowStart)} - ${formatClock(globalSummary.windowEnd ?? "")}` : "-"}</Text>
        </Card>
      </div>

      <div className="event-workbench">
        <aside className="event-side-panel static-agent-panel">
          <div className="static-panel-heading">
            <Text type="secondary">Agents</Text>
            <Tag color="blue">{globalAgentBreakdown.length}</Tag>
          </div>
          <div className="static-agent-list">
            {globalAgentBreakdown.length ? globalAgentBreakdown.map((agent) => {
              const key = agentKey(agent);
              return (
                <button
                  key={key}
                  className={`static-agent-item ${selectedAgentKey === key ? "static-agent-item-active" : ""}`}
                  type="button"
                  onClick={() => selectAgent(key)}
                >
                  <span className="static-agent-name">{agent.agent}</span>
                  <span className="static-agent-source">{agent.runtime}</span>
                  <span className="static-agent-meta">
                    <span>{agent.count} Events</span>
                    <span className={agent.attack || agent.blocked ? "static-agent-risk" : ""}>
                      {agent.attack} Attacks · {agent.blocked} Blocked
                    </span>
                  </span>
                </button>
              );
            }) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent 事件" />}
          </div>

          <div className="event-panel-heading event-panel-section">
            <Text strong>当前来源</Text>
            <Tag>{selectedSourceBreakdown.length}</Tag>
          </div>
          <div className="event-breakdown-list">
            {selectedSourceBreakdown.length ? selectedSourceBreakdown.map((source) => (
              <button
                key={source.name}
                className={`event-breakdown-item ${sourceFilter === source.name ? "event-breakdown-active" : ""}`}
                type="button"
                onClick={() => setSourceFilter(sourceFilter === source.name ? "all" : source.name)}
              >
                <span>{source.name}</span>
                <strong>{source.count}</strong>
                <em>攻击 {source.attack} · 阻断 {source.blocked}</em>
              </button>
            )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无来源" />}
          </div>
        </aside>

        <main className="event-main-panel">
          {selectedAgent ? (
            <>
              <div className="event-agent-context">
                <div>
                  <Title level={3}>{selectedAgent.agent}</Title>
                  <Text type="secondary">
                    {selectedAgent.count} Events · {selectedAgent.attack} Attacks · {selectedAgent.blocked} Blocked
                  </Text>
                </div>
                <Space direction="vertical" align="end" size={6}>
                  <Text className="mono event-agent-path">{selectedAgent.runtime}</Text>
                  <Space wrap>
                    {staticRiskTag(selectedAgent.maxSeverity)}
                    <Tag color="blue">来源 {selectedAgent.sources.length || selectedSummary.sources}</Tag>
                    <Tag>最近 {formatTimestamp(selectedAgent.lastSeen)}</Tag>
                  </Space>
                </Space>
              </div>

              <div className="event-type-strip">
                {eventGroupSummaries.map((group) => (
                  <button
                    key={group.key}
                    className={`event-type-card ${selectedEventGroup === group.key ? "event-type-card-active" : ""}`}
                    type="button"
                    onClick={() => selectGroup(group.key)}
                  >
                    <strong>{group.title}</strong>
                    <span>{group.count} Events</span>
                    <em>{group.detail}</em>
                  </button>
                ))}
              </div>

              <Card bordered={false} className="event-filter-card">
                <div className="event-filter-bar">
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索事件、证据、Trace、Session、工具或目标"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  <Select
                    value={kindFilter}
                    options={[
                      { label: "全部事件", value: "all" },
                      { label: "安全事件", value: "security" },
                      { label: "攻击事件", value: "attack" },
                    ]}
                    onChange={(value) => {
                      setSelectedEventGroup("all");
                      setKindFilter(value);
                    }}
                  />
                  <Select
                    value={severityFilter}
                    options={severityOptions}
                    onChange={(value) => {
                      setSelectedEventGroup("all");
                      setSeverityFilter(value);
                    }}
                  />
                  <Select
                    value={statusFilter}
                    options={statusOptions}
                    onChange={(value) => {
                      setSelectedEventGroup("all");
                      setStatusFilter(value);
                    }}
                  />
                  <Select value={sourceFilter} options={sourceOptions} onChange={(value) => setSourceFilter(value)} />
                </div>
                <div className="event-filter-foot">
                  <Space wrap>
                    <FilterOutlined />
                    <Text type="secondary">当前筛选 {filteredEvents.length} / {selectedAgentEvents.length}</Text>
                  </Space>
                  <Space wrap>
                    <Tag color="blue">安全 {filteredEvents.filter((event) => event.kind === "security").length}</Tag>
                    <Tag color="red">攻击 {filteredEvents.filter((event) => event.kind === "attack").length}</Tag>
                    <Tag color="volcano">高危 {filteredEvents.filter((event) => riskRank(event.severity) >= 4).length}</Tag>
                  </Space>
                </div>
              </Card>

              <Card bordered={false} className="event-timeline-card">
                <div className="event-timeline-header">
                  <Text strong>当前 Agent 事件时间线</Text>
                  <Text type="secondary">5 分钟窗口</Text>
                </div>
                {selectedTimeline.length ? (
                  <div className="event-timeline">
                    {selectedTimeline.map((bucket) => (
                      <div key={bucket.bucket} className="event-timeline-bar" title={`${formatTimestamp(bucket.bucket)} · ${bucket.total}`}>
                        <span style={{ height: `${Math.max(8, Math.round((bucket.total / maxTimeline) * 78))}px` }} />
                        <em>{formatClock(bucket.bucket)}</em>
                        {bucket.attack > 0 && <strong>{bucket.attack}</strong>}
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无时间线数据" />
                )}
              </Card>

              <Card bordered={false} className="event-table-card" title="检测事件" extra={<Text type="secondary">{filteredEvents.length} 项事件</Text>}>
                <Table
                  rowKey="id"
                  loading={loading || refreshing}
                  columns={columns}
                  dataSource={filteredEvents}
                  pagination={{ pageSize: 12 }}
                  locale={{ emptyText: "暂无当前 Agent 的后端事件检测结果" }}
                  scroll={{ x: 1080 }}
                  rowClassName={(row) => row.id === selectedEventId ? "event-table-row-active" : ""}
                  onRow={(row) => ({
                    onClick: () => {
                      setSelectedEventId(row.id);
                      setEventDetailOpen(true);
                    },
                  })}
                />
              </Card>
            </>
          ) : (
            <Card bordered={false} className="event-table-card">
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无后端事件检测结果" />
            </Card>
          )}
        </main>
      </div>

      <Drawer
        className="event-detail-drawer"
        title={selectedEvent ? (
          <Space direction="vertical" size={4}>
            <Space wrap>{eventKindTag(selectedEvent.kind)}{staticRiskTag(selectedEvent.severity)}{eventStatusTag(selectedEvent.status)}</Space>
            <Text strong>{selectedEvent.title}</Text>
          </Space>
        ) : "事件详情"}
        open={eventDetailOpen && Boolean(selectedEvent)}
        width={560}
        onClose={() => {
          setEventDetailOpen(false);
          setSelectedEventId(undefined);
        }}
      >
        {selectedEvent ? (
          <Tabs
            items={[
              {
                key: "overview",
                label: "概览",
                children: (
                  <Descriptions column={1} size="small" bordered>
                    <Descriptions.Item label="Agent">{selectedEvent.agent}</Descriptions.Item>
                    <Descriptions.Item label="运行时">{selectedEvent.runtime}</Descriptions.Item>
                    <Descriptions.Item label="发生时间">{formatTimestamp(selectedEvent.occurredAt)}</Descriptions.Item>
                    <Descriptions.Item label="分类">{selectedEvent.category} / {selectedEvent.subtype}</Descriptions.Item>
                    <Descriptions.Item label="来源">{selectedEvent.source}</Descriptions.Item>
                    <Descriptions.Item label="关联键"><Text code>{selectedEvent.correlationKey || correlationKey(selectedEvent)}</Text></Descriptions.Item>
                  </Descriptions>
                ),
              },
              {
                key: "evidence",
                label: "证据",
                children: (
                  <Space direction="vertical" size={12} className="event-detail-stack">
                    <div className="event-detail-block">
                      <Text type="secondary">证据摘要</Text>
                      <pre>{selectedEvent.evidence || "-"}</pre>
                    </div>
                    <div className="event-detail-block">
                      <Text type="secondary">处置建议</Text>
                      <pre>{selectedEvent.remediation || selectedEvent.action || "-"}</pre>
                    </div>
                    {selectedEvent.reason ? (
                      <div className="event-detail-block">
                        <Text type="secondary">原因</Text>
                        <pre>{selectedEvent.reason}</pre>
                      </div>
                    ) : null}
                  </Space>
                ),
              },
              {
                key: "context",
                label: "上下文",
                children: (
                  <Descriptions column={1} size="small" bordered>
                    <Descriptions.Item label="Trace"><Text code>{selectedEvent.traceId || "-"}</Text></Descriptions.Item>
                    <Descriptions.Item label="Session"><Text code>{selectedEvent.sessionId || "-"}</Text></Descriptions.Item>
                    <Descriptions.Item label="原始动作">{selectedEvent.rawAction || "-"}</Descriptions.Item>
                    <Descriptions.Item label="目标">{selectedEvent.target || "-"}</Descriptions.Item>
                    <Descriptions.Item label="操作者">{selectedEvent.actor || "-"}</Descriptions.Item>
                    <Descriptions.Item label="Connector">{selectedEvent.connector || "-"}</Descriptions.Item>
                    <Descriptions.Item label="目标应用">{selectedEvent.destinationApp || "-"}</Descriptions.Item>
                    <Descriptions.Item label="工具">{selectedEvent.toolName || selectedEvent.mcpServer || "-"}</Descriptions.Item>
                    <Descriptions.Item label="模型">{selectedEvent.model || "-"}</Descriptions.Item>
                    <Descriptions.Item label="决策">{selectedEvent.decision || selectedEvent.action || "-"}</Descriptions.Item>
                  </Descriptions>
                ),
              },
            ]}
          />
        ) : (
          <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} />
        )}
      </Drawer>
    </section>
  );
}
