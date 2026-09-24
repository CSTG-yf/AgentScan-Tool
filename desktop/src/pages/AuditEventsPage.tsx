import { useCallback, useEffect, useMemo, useState } from "react";
import type { ComponentProps } from "react";
import { DownloadOutlined, EyeOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Card, ConfigProvider, DatePicker, Descriptions, Drawer, Empty, Input, Select, Space, Table, Tag, Typography, message, theme } from "antd";
import type { ColumnsType } from "antd/es/table";
import { getAuditEventAgents, getAuditEventDetail, getAuditEventFacets, getAuditEvents, getAuditEventSummary } from "../bridge";
import type { AuditEventFacets, AuditEventQuery, AuditEventRecord, AuditEventSummary, EventAgentSummary } from "../types";
import { chooseExportDirectory, collectAllPages, exportTablePdf } from "../app/reportExport";

const { Text, Title } = Typography;
const ALL = "__all__";
const EMPTY: AuditEventFacets = { actions: [], severities: [], connectors: [], actors: [], tools: [] };
const fmt = (value?: string) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const riskColor = (value?: string) => ({ CRITICAL: "red", HIGH: "volcano", MEDIUM: "orange", LOW: "blue", INFO: "cyan" }[String(value || "").toUpperCase()] || "default");
type RangeValue = Parameters<NonNullable<ComponentProps<typeof DatePicker.RangePicker>["onChange"]>>[0];

export function AuditEventsPage({ onOpenTrace, refreshNonce = 0 }: { onOpenTrace?: (traceId: string) => void; refreshNonce?: number }) {
  const [summary, setSummary] = useState<AuditEventSummary>({ totalEvents: 0, relatedAgentCount: 0, highOrAboveCount: 0, enforcedCount: 0 });
  const [agents, setAgents] = useState<EventAgentSummary[]>([]);
  const [facets, setFacets] = useState(EMPTY);
  const [items, setItems] = useState<AuditEventRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState(ALL);
  const [agentSearch, setAgentSearch] = useState("");
  const [keyword, setKeyword] = useState("");
  const [debounced, setDebounced] = useState("");
  const [action, setAction] = useState<string>();
  const [severity, setSeverity] = useState<string>();
  const [connector, setConnector] = useState<string>();
  const [enforced, setEnforced] = useState<boolean>();
  const [actor, setActor] = useState<string>();
  const [tool, setTool] = useState<string>();
  const [policyId, setPolicyId] = useState("");
  const [requestId, setRequestId] = useState("");
  const [sessionId, setSessionId] = useState("");
  const [traceId, setTraceId] = useState("");
  const [times, setTimes] = useState<[string?, string?]>([]);
  const [dateRange, setDateRange] = useState<RangeValue>(null);
  const [advanced, setAdvanced] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [detail, setDetail] = useState<AuditEventRecord>();

  useEffect(() => { const id = setTimeout(() => setDebounced(keyword.trim()), 300); return () => clearTimeout(id); }, [keyword]);
  const globalQuery = useMemo<AuditEventQuery>(() => ({ startTime: times[0], endTime: times[1] }), [times]);
  const query = useMemo<AuditEventQuery>(() => ({ ...globalQuery, agentId: selectedAgent === ALL ? undefined : selectedAgent, action, severity, connector, enforced, actor, toolName: tool, policyId: policyId.trim() || undefined, requestId: requestId.trim() || undefined, sessionId: sessionId.trim() || undefined, traceId: traceId.trim() || undefined, keyword: debounced, page, pageSize, sort: "timestamp_desc" }), [globalQuery, selectedAgent, action, severity, connector, enforced, actor, tool, policyId, requestId, sessionId, traceId, debounced, page, pageSize]);
  const loadGlobals = useCallback(async () => { try { const [s, a, f] = await Promise.all([getAuditEventSummary(globalQuery), getAuditEventAgents(globalQuery), getAuditEventFacets(globalQuery)]); setSummary(s); setAgents(a); setFacets(f); } catch (error) { message.error(`读取事件审计总览失败：${String(error)}`); } }, [globalQuery]);
  const loadList = useCallback(async () => { setLoading(true); try { const response = await getAuditEvents(query); setItems(response.items ?? []); setTotal(response.total ?? 0); } catch (error) { message.error(`读取事件审计失败：${String(error)}`); setItems([]); setTotal(0); } finally { setLoading(false); } }, [query]);
  useEffect(() => { void loadGlobals(); }, [loadGlobals, refreshNonce]);
  useEffect(() => { void loadList(); }, [loadList, refreshNonce]);
  useEffect(() => setPage(1), [selectedAgent, action, severity, connector, enforced, actor, tool, policyId, requestId, sessionId, traceId, debounced, times]);

  const visibleAgents = agents.filter(agent => `${agent.agentName} ${agent.agentType} ${agent.agentId}`.toLowerCase().includes(agentSearch.toLowerCase()));
  const exportFiltered = async () => {
    setExporting(true);
    try {
      const directory = await chooseExportDirectory("选择事件审计报告导出文件夹");
      if (directory === null) { message.info("已取消导出"); return; }
      const base = { ...query, page: undefined, pageSize: undefined };
      const rows = await collectAllPages<AuditEventRecord>((nextPage, nextSize) => getAuditEvents({ ...base, page: nextPage, pageSize: nextSize }));
      const path = await exportTablePdf({ directory, title: "事件审计报告", fileName: `audit-events-${new Date().toISOString().slice(0, 10)}.pdf`, filters: base, columns: ["时间", "Agent", "AgentType", "主体", "动作", "目标/工具", "风险", "状态", "Connector", "Session", "Trace"], rows: rows.map(row => [fmt(row.timestamp), row.agentName || row.canonicalAgentId, agents.find(agent => agent.agentId === (row.agentId || row.canonicalAgentId))?.agentType, row.actor, row.action, row.target || row.toolName, row.severity, row.enforced ? "已强制阻断" : "未强制阻断", row.connector, row.sessionId, row.traceId]) });
      message.success(`PDF 已导出：${path}`);
    } catch (error) { message.error(`导出失败：${String(error)}`); } finally { setExporting(false); }
  };
  const reset = () => { setKeyword(""); setAction(undefined); setSeverity(undefined); setConnector(undefined); setEnforced(undefined); setActor(undefined); setTool(undefined); setPolicyId(""); setRequestId(""); setSessionId(""); setTraceId(""); setTimes([]); setDateRange(null); setPage(1); };
  const columns: ColumnsType<AuditEventRecord> = [
    { title: "时间", dataIndex: "timestamp", width: 170, render: fmt },
    { title: "Agent / 审计主体", width: 210, render: (_, row) => <Space direction="vertical" size={0}><Text strong>{row.agentName || "系统 / 未关联"}</Text><Text type="secondary">{row.actor || "—"}</Text></Space> },
    { title: "审计动作", dataIndex: "action", width: 190 },
    { title: "目标 / 工具", width: 210, ellipsis: true, render: (_, row) => <><div className="mono">{row.target || "—"}</div><Text type="secondary">{row.toolName || ""}</Text></> },
    { title: "风险", dataIndex: "severity", width: 100, render: value => <Tag color={riskColor(value)}>{value || "未记录"}</Tag> },
    { title: "接入来源", dataIndex: "connector", width: 120, render: value => value || "未记录" },
    { title: "决策 / 强制阻断", width: 150, render: (_, row) => <Space direction="vertical" size={2}><Text>{String(row.structured?.decision || row.structured?.verdict || "未记录")}</Text>{row.enforced ? <Tag color="red">已强制阻断</Tag> : <Tag>未强制阻断</Tag>}</Space> },
    { title: "摘要", dataIndex: "details", ellipsis: true },
    { title: "操作", fixed: "right", width: 140, render: (_, row) => <Space size={4}><Button type="link" icon={<EyeOutlined />} onClick={() => void getAuditEventDetail(row.id).then(setDetail).catch(error => message.error(String(error)))}>详情</Button>{row.traceId && <Button type="link" onClick={() => onOpenTrace?.(row.traceId || "")}>关联追踪</Button>}</Space> },
  ];

  return <ConfigProvider theme={{ inherit: false, algorithm: theme.defaultAlgorithm }}><section className="workspace-page event-inventory-page">
    <div className="event-inventory-heading"><div><Text className="eyebrow">SECURITY EVENT AUDIT</Text><Title level={2}>事件审计</Title><Text type="secondary">审阅系统检查、策略判断、接入来源及实际强制阻断记录。</Text></div><Space><Button icon={<DownloadOutlined />} loading={exporting} disabled={!total} onClick={() => void exportFiltered()}>导出事件审计检测报告</Button><Button icon={<ReloadOutlined />} loading={loading} onClick={() => { void loadGlobals(); void loadList(); }}>刷新数据</Button></Space></div>
    <div className="event-summary-grid">{[["审计记录总数", summary.totalEvents, "blue"], ["涉及 Agent 数", summary.relatedAgentCount, "green"], ["高危及以上记录", summary.highOrAboveCount, "orange"], ["已强制阻断记录", summary.enforcedCount, "red"]].map(([label, value, tone]) => <Card key={String(label)} className={`event-summary-card ${tone}`}><Text type="secondary">{label}</Text><strong>{value}</strong><Text type="secondary">当前时间范围 · 全部 Agent</Text></Card>)}</div>
    <div className="event-inventory-layout"><Card className="event-agent-panel" title={<>Agents <Tag>{agents.length}</Tag></>}><Input allowClear prefix={<SearchOutlined />} placeholder="搜索 Agent" value={agentSearch} onChange={event => setAgentSearch(event.target.value)} /><div className="event-agent-list"><button className={selectedAgent === ALL ? "active" : ""} onClick={() => setSelectedAgent(ALL)}><strong>全部 Agent</strong><span>{summary.totalEvents} 条审计</span></button>{visibleAgents.map(agent => <button key={agent.agentId} className={selectedAgent === agent.agentId ? "active" : ""} onClick={() => setSelectedAgent(agent.agentId)}><strong>{agent.agentName || "未关联 Agent"}</strong><em>{agent.agentType || agent.agentId}</em><span>{agent.eventCount} 条 · 高危 {agent.highOrAboveCount ?? 0}</span><span>{fmt(agent.latestEventAt)}</span></button>)}</div></Card>
      <div className="event-inventory-main"><Card><div className="event-context"><div><Text type="secondary">当前范围</Text><Title level={3}>{selectedAgent === ALL ? "全部 Agent" : agents.find(agent => agent.agentId === selectedAgent)?.agentName || "未关联 Agent"}</Title></div><strong>匹配 {total} 条</strong></div>
        <div className="event-filters"><Input allowClear prefix={<SearchOutlined />} placeholder="搜索动作、目标、主体、详情、ID" value={keyword} onChange={event => setKeyword(event.target.value)} /><Select allowClear placeholder="审计动作" value={action} onChange={setAction} options={facets.actions.map(value => ({ value, label: value }))} /><Select allowClear placeholder="严重级别" value={severity} onChange={setSeverity} options={facets.severities.map(value => ({ value, label: value }))} /><Select allowClear placeholder="Connector" value={connector} onChange={setConnector} options={facets.connectors.map(value => ({ value, label: value }))} /><Select allowClear placeholder="强制阻断" value={enforced} onChange={setEnforced} options={[{ value: true, label: "已强制阻断" }, { value: false, label: "未强制阻断" }]} /><DatePicker.RangePicker showTime value={dateRange} onChange={value => { setDateRange(value); setTimes(value ? [value[0]?.toISOString(), value[1]?.toISOString()] : []); }} /><Button onClick={() => setAdvanced(value => !value)}>{advanced ? "收起" : "高级筛选"}</Button><Button onClick={reset}>重置</Button></div>
        {advanced && <div className="event-filters advanced"><Select showSearch allowClear placeholder="Actor" value={actor} onChange={setActor} options={facets.actors.map(value => ({ value, label: value }))} /><Select showSearch allowClear placeholder="工具" value={tool} onChange={setTool} options={facets.tools.map(value => ({ value, label: value }))} /><Input placeholder="Policy ID" value={policyId} onChange={event => setPolicyId(event.target.value)} /><Input placeholder="Request ID" value={requestId} onChange={event => setRequestId(event.target.value)} /><Input placeholder="Session ID" value={sessionId} onChange={event => setSessionId(event.target.value)} /><Input placeholder="Trace ID" value={traceId} onChange={event => setTraceId(event.target.value)} /></div>}
        <Table rowKey="id" loading={loading} columns={columns} dataSource={items} scroll={{ x: 1550 }} pagination={{ current: page, pageSize, total, showSizeChanger: true, onChange: (nextPage, nextSize) => { setPage(nextPage); setPageSize(nextSize); } }} locale={{ emptyText: <Empty description="暂无审计事件" /> }} />
      </Card></div></div>
    <Drawer rootClassName="event-detail-drawer" title="审计事件详情" width={760} open={!!detail} onClose={() => setDetail(undefined)}>{detail && <Space direction="vertical" size={16} className="event-full-width"><Descriptions bordered size="small" column={2} items={[{ key: "id", label: "审计 ID", span: 2, children: <Text className="mono">{detail.id}</Text> }, { key: "time", label: "时间", children: fmt(detail.timestamp) }, { key: "severity", label: "严重级别", children: <Tag color={riskColor(detail.severity)}>{detail.severity || "未记录"}</Tag> }, { key: "agent", label: "Agent", children: detail.agentName || detail.canonicalAgentId || "系统 / 未关联" }, { key: "actor", label: "审计主体", children: detail.actor }, { key: "action", label: "动作", children: detail.action }, { key: "connector", label: "Connector", children: detail.connector || "未记录" }, { key: "target", label: "目标 / 工具", span: 2, children: `${detail.target || "—"} / ${detail.toolName || "—"}` }, { key: "request", label: "Request ID", children: detail.requestId || "—" }, { key: "policy", label: "Policy ID", children: detail.policyId || "—" }, { key: "session", label: "Session ID", children: detail.sessionId || "—" }, { key: "trace", label: "Trace ID", children: detail.traceId || "—" }, { key: "enforced", label: "实际强制阻断", children: detail.enforced ? "是" : "未记录为阻断" }, { key: "detail", label: "摘要", span: 2, children: detail.details || "—" }]}/><div><Text strong>脱敏结构化信息</Text><pre className="event-json">{JSON.stringify(detail.structured ?? {}, null, 2)}</pre></div></Space>}</Drawer>
  </section></ConfigProvider>;
}
