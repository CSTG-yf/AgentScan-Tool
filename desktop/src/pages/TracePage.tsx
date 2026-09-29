import { useCallback, useEffect, useMemo, useState } from "react";
import type { ComponentProps } from "react";
import { DownloadOutlined, EyeOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Card, ConfigProvider, DatePicker, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tag, Typography, message, theme } from "antd";
import type { ColumnsType } from "antd/es/table";
import { getRuntimeEventAgents, getRuntimeEventDetail, getRuntimeEventFacets, getRuntimeEvents, getRuntimeEventSummary } from "../bridge";
import type { AgentTraceEvent, EventAgentSummary, RuntimeEventFacets, RuntimeEventQuery, RuntimeEventSummary } from "../types";
import { chooseExportDirectory, collectAllPages, exportTablePdf } from "../app/reportExport";

const { Text, Title } = Typography;
const ALL = "__all__";
const EMPTY_FACETS: RuntimeEventFacets = { eventTypes: [], eventCategories: [], sources: [], severities: [], outcomes: [] };
const fmt = (value?: string) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
type RangeValue = Parameters<NonNullable<ComponentProps<typeof DatePicker.RangePicker>["onChange"]>>[0];

export function TracePage({ refreshNonce = 0, focusTraceId }: { refreshNonce?: number; focusTraceId?: string }) {
  const [summary, setSummary] = useState<RuntimeEventSummary>({ totalEvents: 0, activeAgentCount: 0, toolEventCount: 0, fileEventCount: 0 });
  const [agents, setAgents] = useState<EventAgentSummary[]>([]);
  const [facets, setFacets] = useState(EMPTY_FACETS);
  const [items, setItems] = useState<AgentTraceEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(ALL);
  const [agentSearch, setAgentSearch] = useState("");
  const [keyword, setKeyword] = useState("");
  const [debouncedKeyword, setDebouncedKeyword] = useState("");
  const [category, setCategory] = useState<string>();
  const [eventType, setEventType] = useState<string>();
  const [source, setSource] = useState<string>();
  const [outcome, setOutcome] = useState<string>();
  const [severity, setSeverity] = useState<string>();
  const [agentPid, setAgentPid] = useState("");
  const [actorPid, setActorPid] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [traceId, setTraceId] = useState("");
  const [times, setTimes] = useState<[string?, string?]>([]);
  const [dateRange, setDateRange] = useState<RangeValue>(null);
  const [includeDesktop, setIncludeDesktop] = useState(true);
  const [advanced, setAdvanced] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [detail, setDetail] = useState<AgentTraceEvent>();

  useEffect(() => { const id = setTimeout(() => setDebouncedKeyword(keyword.trim()), 300); return () => clearTimeout(id); }, [keyword]);
  useEffect(() => { if (focusTraceId) setTraceId(focusTraceId); }, [focusTraceId]);
  const globalQuery = useMemo<RuntimeEventQuery>(() => ({ startTime: times[0], endTime: times[1], includeDesktopBehavior: includeDesktop }), [times, includeDesktop]);
  const query = useMemo<RuntimeEventQuery>(() => ({ ...globalQuery, agentId: selectedAgent === ALL ? undefined : selectedAgent, eventCategory: category, eventType, source, outcome, severity, keyword: debouncedKeyword, agentPid: Number(agentPid) || undefined, actorPid: Number(actorPid) || undefined, sessionId: sessionId.trim() || undefined, traceId: traceId.trim() || undefined, page, pageSize, sort: "timestamp_desc" }), [globalQuery, selectedAgent, category, eventType, source, outcome, severity, debouncedKeyword, agentPid, actorPid, sessionId, traceId, page, pageSize]);
  const loadGlobals = useCallback(async () => { try { const [s, a, f] = await Promise.all([getRuntimeEventSummary(globalQuery), getRuntimeEventAgents(globalQuery), getRuntimeEventFacets(globalQuery)]); setSummary(s); setAgents(a); setFacets(f); } catch (error) { message.error(`读取行为总览失败：${String(error)}`); } }, [globalQuery]);
  const loadList = useCallback(async () => { setLoading(true); try { const response = await getRuntimeEvents(query); setItems(response.items ?? []); setTotal(response.total ?? 0); } catch (error) { message.error(`读取行为事件失败：${String(error)}`); setItems([]); setTotal(0); } finally { setLoading(false); } }, [query]);
  useEffect(() => { void loadGlobals(); }, [loadGlobals, refreshNonce]);
  useEffect(() => { void loadList(); }, [loadList, refreshNonce]);
  useEffect(() => setPage(1), [selectedAgent, category, eventType, source, outcome, severity, debouncedKeyword, agentPid, actorPid, sessionId, traceId, times, includeDesktop]);

  const visibleAgents = agents.filter(agent => `${agent.agentName} ${agent.agentType} ${agent.agentId}`.toLowerCase().includes(agentSearch.toLowerCase()));
  const exportFiltered = async () => {
    setExporting(true);
    try {
      const directory = await chooseExportDirectory("选择行为追踪报告导出文件夹");
      if (directory === null) { message.info("已取消导出"); return; }
      const base = { ...query, page: undefined, pageSize: undefined };
      const rows = await collectAllPages<AgentTraceEvent>((nextPage, nextSize) => getRuntimeEvents({ ...base, page: nextPage, pageSize: nextSize }));
      const path = await exportTablePdf({ directory, title: "Agent 行为追踪报告", fileName: `agent-trace-${new Date().toISOString().slice(0, 10)}.pdf`, filters: base, columns: ["时间", "Agent", "AgentType", "分类", "类型", "操作/工具", "目标", "结果", "来源", "Session", "Trace"], rows: rows.map(row => [fmt(row.timestamp), row.agentName || row.canonicalAgentId, agents.find(agent => agent.agentId === row.canonicalAgentId)?.agentType, row.eventCategory, row.eventType, row.operation || row.action || row.toolName, row.target || row.path, row.outcome, row.eventSource || row.source, row.sessionId, row.traceId]) });
      message.success(`PDF 已导出：${path}`);
    } catch (error) { message.error(`导出失败：${String(error)}`); } finally { setExporting(false); }
  };
  const reset = () => { setKeyword(""); setCategory(undefined); setEventType(undefined); setSource(undefined); setOutcome(undefined); setSeverity(undefined); setAgentPid(""); setActorPid(""); setSessionId(""); setTraceId(""); setTimes([]); setDateRange(null); setPage(1); };
  const columns: ColumnsType<AgentTraceEvent> = [
    { title: "时间", dataIndex: "timestamp", width: 170, render: fmt },
    { title: "Agent / 执行进程", width: 230, render: (_, row) => <Space direction="vertical" size={0}><Text strong>{row.agentName || row.agentExecutable || "未关联 Agent"}{row.agentPid ? ` · PID ${row.agentPid}` : ""}</Text><Text type="secondary" className="mono">{row.actorExecutable || "—"}{row.actorPid ? ` · PID ${row.actorPid}` : ""}</Text></Space> },
    { title: "分类 / 类型", width: 190, render: (_, row) => <Space direction="vertical" size={2}><Tag color="blue">{row.eventCategory || "未分类"}</Tag><Text>{row.eventType}</Text></Space> },
    { title: "操作 / 工具", width: 180, render: (_, row) => <><div>{row.operation || row.action || "—"}</div><Text type="secondary">{row.toolName || ""}</Text></> },
    { title: "目标", ellipsis: true, render: (_, row) => <Text className="mono">{row.target || row.path || "—"}</Text> },
    { title: "结果", dataIndex: "outcome", width: 110, render: value => <Tag color={value === "blocked" ? "red" : value === "allowed" ? "green" : "blue"}>{value || "未记录"}</Tag> },
    { title: "来源", width: 145, render: (_, row) => row.eventSource || row.source || "—" },
    { title: "操作", fixed: "right", width: 130, render: (_, row) => <Space size={4}><Button type="link" icon={<EyeOutlined />} onClick={() => void getRuntimeEventDetail(row.id).then(setDetail).catch(error => message.error(String(error)))}>详情</Button>{row.sessionId && <Button type="link" onClick={() => setSessionId(row.sessionId || "")}>同会话</Button>}</Space> },
  ];

  return <ConfigProvider theme={{ inherit: false, algorithm: theme.defaultAlgorithm }}><section className="workspace-page event-inventory-page">
    <div className="event-inventory-heading"><div><Text className="eyebrow">AGENT ACTIVITY TRACE</Text><Title level={2}>Agent 行为追踪</Title><Text type="secondary">记录 Agent 请求、工具调用、检查结果及进程和文件行为；请求提交不代表实际执行。</Text></div><Space><Button icon={<DownloadOutlined />} loading={exporting} disabled={!total} onClick={() => void exportFiltered()}>导出行为追踪检测报告</Button><Button icon={<ReloadOutlined />} loading={loading} onClick={() => { void loadGlobals(); void loadList(); }}>刷新数据</Button></Space></div>
    <div className="event-summary-grid">{[["行为事件总数", summary.totalEvents, "blue"], ["活跃 Agent 数", summary.activeAgentCount, "green"], ["工具调用事件数", summary.toolEventCount, "orange"], ["文件行为事件数", summary.fileEventCount, "purple"]].map(([label, value, tone]) => <Card key={String(label)} className={`event-summary-card ${tone}`}><Text type="secondary">{label}</Text><strong>{value}</strong><Text type="secondary">当前时间范围 · 全部 Agent</Text></Card>)}</div>
    <div className="event-inventory-layout"><Card className="event-agent-panel" title={<>Agents <Tag>{agents.length}</Tag></>}><Input allowClear prefix={<SearchOutlined />} placeholder="搜索 Agent" value={agentSearch} onChange={event => setAgentSearch(event.target.value)} /><div className="event-agent-list"><button className={selectedAgent === ALL ? "active" : ""} onClick={() => setSelectedAgent(ALL)}><strong>全部 Agent</strong><span>{summary.totalEvents} 条事件</span></button>{visibleAgents.map(agent => <button key={agent.agentId} className={selectedAgent === agent.agentId ? "active" : ""} onClick={() => setSelectedAgent(agent.agentId)}><strong>{agent.agentName || "未关联 Agent"}</strong><em>{agent.agentType || agent.agentId}</em><span>{agent.eventCount} 条 · {fmt(agent.latestEventAt)}</span></button>)}</div></Card>
      <div className="event-inventory-main"><Card><div className="event-context"><div><Text type="secondary">当前范围</Text><Title level={3}>{selectedAgent === ALL ? "全部 Agent" : agents.find(agent => agent.agentId === selectedAgent)?.agentName || "未关联 Agent"}</Title></div><strong>匹配 {total} 条</strong></div>
        <div className="event-filters"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索类型、Agent、工具、目标、详情" value={keyword} onChange={event => setKeyword(event.target.value)} /><Select allowClear placeholder="行为分类" value={category} onChange={setCategory} options={facets.eventCategories.map(value => ({ value, label: value }))} /><Select allowClear placeholder="行为类型" value={eventType} onChange={setEventType} options={facets.eventTypes.map(value => ({ value, label: value }))} /><Select allowClear placeholder="来源" value={source} onChange={setSource} options={facets.sources.map(value => ({ value, label: value }))} /><Select allowClear placeholder="行为结果" value={outcome} onChange={setOutcome} options={facets.outcomes.map(value => ({ value, label: value }))} /><DatePicker.RangePicker showTime value={dateRange} onChange={value => { setDateRange(value); setTimes(value ? [value[0]?.toISOString(), value[1]?.toISOString()] : []); }} /><Button onClick={() => setAdvanced(value => !value)}>{advanced ? "收起" : "高级筛选"}</Button><Button onClick={reset}>重置</Button></div>
        {advanced && <div className="event-filters advanced"><Select allowClear placeholder="严重级别" value={severity} onChange={setSeverity} options={facets.severities.map(value => ({ value, label: value }))} /><Input placeholder="Agent PID" value={agentPid} onChange={event => setAgentPid(event.target.value.replace(/\D/g, ""))} /><Input placeholder="Actor PID" value={actorPid} onChange={event => setActorPid(event.target.value.replace(/\D/g, ""))} /><Input placeholder="Session ID" value={sessionId} onChange={event => setSessionId(event.target.value)} /><Input placeholder="Trace ID" value={traceId} onChange={event => setTraceId(event.target.value)} /><Select value={includeDesktop} onChange={setIncludeDesktop} options={[{ value: true, label: "包含旧版桌面行为" }, { value: false, label: "仅统一运行时事件" }]} /></div>}
        <Table rowKey="id" loading={loading} columns={columns} dataSource={items} scroll={{ x: 1450 }} pagination={{ current: page, pageSize, total, showSizeChanger: true, onChange: (nextPage, nextSize) => { setPage(nextPage); setPageSize(nextSize); } }} locale={{ emptyText: <Empty description="暂无行为事件" /> }} />
      </Card></div></div>
    <Drawer rootClassName="event-detail-drawer" title="行为事件详情" width={760} open={!!detail} onClose={() => setDetail(undefined)}>{detail && <Space direction="vertical" size={16} className="event-full-width"><Descriptions bordered size="small" column={2} items={[{ key: "id", label: "数据库 ID", children: detail.id }, { key: "time", label: "时间", children: fmt(detail.timestamp) }, { key: "agent", label: "Agent", children: detail.agentName || detail.canonicalAgentId || "未关联" }, { key: "process", label: "进程", children: `Agent PID ${detail.agentPid || "—"} / Actor PID ${detail.actorPid || "—"}` }, { key: "type", label: "事件", children: `${detail.eventCategory || "—"} / ${detail.eventType}` }, { key: "source", label: "来源", children: detail.eventSource || detail.source }, { key: "event", label: "Event / Span", span: 2, children: <Text className="mono">{detail.eventId || "—"} / {detail.spanId || "—"} / {detail.parentSpanId || "—"}</Text> }, { key: "session", label: "Session ID", children: detail.sessionId || "—" }, { key: "trace", label: "Trace ID", children: detail.traceId || "—" }, { key: "target", label: "操作 / 目标", span: 2, children: `${detail.operation || detail.action || "—"} / ${detail.target || detail.path || "—"}` }, { key: "detail", label: "详细说明", span: 2, children: detail.detail || "—" }]}/><div><Text strong>脱敏属性</Text><pre className="event-json">{JSON.stringify(detail.attributes ?? {}, null, 2)}</pre></div></Space>}</Drawer>
  </section></ConfigProvider>;
}
