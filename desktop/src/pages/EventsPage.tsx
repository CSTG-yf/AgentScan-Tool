import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Card, ConfigProvider, Descriptions, Drawer, Empty, Input, Modal, Segmented, Select, Space, Table, Tabs, Tag, Typography, message, theme } from "antd";
import { blockRuntimeDetection, createRuntimeEventReplay, getRuntimeDetectionAgentTypeSummaries, getRuntimeDetectionDetail, getRuntimeDetections, getRuntimeDecisions, getRuntimeDecisionDetail, getRuntimeSecurityAgents, getRuntimeSecurityMode, getRuntimeSecuritySummary, getScanStatus, setRuntimeSecurityMode } from "../bridge";
import type { RuntimeDetection, RuntimeDetectionAgentTypeSummary, RuntimeDetectionDetail, RuntimeDetectionListQuery, RuntimeDecisionDetail, RuntimeEnforcementResult, RuntimeSecurityAgent, RuntimeSecurityMode } from "../types";
import { formatTimestamp } from "../app/display";
import "./runtime-workbench.css";

const { Text, Title } = Typography;
const errorText = (e: unknown) => e instanceof Error ? e.message : String(e);
const riskColors: Record<string, string> = { critical: "red", high: "orange", medium: "gold", low: "green", info: "blue" };
const riskTag = (risk?: string) => <Tag color={riskColors[(risk || "").toLowerCase()]}>{(risk || "unknown").toUpperCase()}</Tag>;
const statusTag = (status?: string) => <Tag>{({ open: "未解决", mitigated: "已缓解", blocked: "已阻断", resolved: "已解决" } as Record<string, string>)[status || ""] || status || "unknown"}</Tag>;
const json = (value: unknown) => JSON.stringify(value, null, 2);
type Filters = Omit<RuntimeDetectionListQuery, "page" | "pageSize" | "limit" | "offset">;
type Preview = { id: string; key: string; plan: NonNullable<RuntimeEnforcementResult["plan"]> };
interface Props { loading?: boolean; onRefresh?: () => Promise<void> | void; refreshNonce?: number }

export function EventsPage({ refreshNonce = 0 }: Props) {
  const [filters, setFilters] = useState<Filters>({ sort: "latest" });
  const [paging, setPaging] = useState({ page: 1, pageSize: 20 });
  const [revision, setRevision] = useState(0);
  const [agents, setAgents] = useState<RuntimeSecurityAgent[]>([]);
  const [agentSearch, setAgentSearch] = useState("");
  const [types, setTypes] = useState<RuntimeDetectionAgentTypeSummary[]>([]);
  const [typeOptions, setTypeOptions] = useState<Record<number, string>>({});
  const [rows, setRows] = useState<RuntimeDetection[]>([]);
  const [total, setTotal] = useState(0);
  const [mode, setMode] = useState<RuntimeSecurityMode>();
  const [modeBusy, setModeBusy] = useState(false);
  const [replayBusy, setReplayBusy] = useState(false);
  const [listBusy, setListBusy] = useState(false);
  const [summaryBusy, setSummaryBusy] = useState(false);
  const [summaryReady, setSummaryReady] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [selectedId, setSelectedId] = useState<string>();
  const [detail, setDetail] = useState<RuntimeDetectionDetail>();
  const [decisions, setDecisions] = useState<RuntimeDecisionDetail[]>([]);
  const [detailTab, setDetailTab] = useState("overview");
  const [detailBusy, setDetailBusy] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [preview, setPreview] = useState<Preview>();
  const [actionBusy, setActionBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [dates, setDates] = useState({ start: "", end: "" });
  const request = useRef(0);
  const selected = useRef<string | undefined>(undefined);
  const setError = useCallback((key: string, error?: unknown) => setErrors(old => ({ ...old, [key]: error ? errorText(error) : "" })), []);
  const change = (patch: Partial<Filters>) => { setFilters(old => ({ ...old, ...patch })); setPaging(old => ({ ...old, page: 1 })); };
  const refresh = () => setRevision(value => value + 1);
  useEffect(() => {
    let active = true;
    void Promise.allSettled([getRuntimeSecurityAgents(1000), getRuntimeSecurityMode(), getRuntimeSecuritySummary()]).then(([a, m, g]) => {
      if (!active) return;
      if (a.status === "fulfilled") { setAgents(a.value); setError("agents"); } else setError("agents", a.reason);
      if (m.status === "fulfilled") { setMode(m.value); setError("mode"); } else setError("mode", m.reason);
      setError("global", g.status === "rejected" ? g.reason : undefined);
    });
    return () => { active = false; };
  }, [revision, refreshNonce, setError]);
  const { sort: _sort, ...summaryFilters } = filters;
  const summaryKey = json(summaryFilters);
  useEffect(() => {
    let active = true; setSummaryBusy(true); setSummaryReady(false);
    void getRuntimeDetectionAgentTypeSummaries(JSON.parse(summaryKey)).then(value => {
      if (active) {
        const items = value.items ?? value.list ?? [];
        setTypes(items);
        setTypeOptions(old => ({ ...old, ...Object.fromEntries(items.filter(item => item.agentTypeId > 0).map(item => [item.agentTypeId, item.agentTypeName || item.agentType])) }));
        setSummaryReady(true); setError("summary");
      }
    }).catch(e => { if (active) setError("summary", e); }).finally(() => { if (active) setSummaryBusy(false); });
    return () => { active = false; };
  }, [summaryKey, revision, refreshNonce, setError]);
  useEffect(() => {
    let active = true; setListBusy(true);
    void getRuntimeDetections({ ...filters, ...paging }).then(value => {
      if (active) { setRows(value.items ?? value.detections ?? []); setTotal(value.total); setError("list"); }
    }).catch(e => { if (active) setError("list", e); }).finally(() => { if (active) setListBusy(false); });
    return () => { active = false; };
  }, [filters, paging, revision, refreshNonce, setError]);
  const totals = useMemo(() => types.reduce((sum, type) => ({ total: sum.total + type.totalEvents, attack: sum.attack + (type.attackEvents ?? 0), open: sum.open + (type.openEvents ?? 0), high: sum.high + Object.entries(type.riskCounts).reduce((count, [risk, value]) => count + (["critical", "high"].includes(risk.toLowerCase()) ? value : 0), 0) }), { total: 0, attack: 0, high: 0, open: 0 }), [types]);
  const loadDetail = useCallback(async (id: string) => {
    const token = ++request.current; setDetailBusy(true); setDetailError("");
    const [record, linked] = await Promise.allSettled([getRuntimeDetectionDetail(id), getRuntimeDecisions(1000, id)]);
    if (token !== request.current) return;
    const failures: string[] = [];
    if (record.status === "fulfilled") setDetail(record.value); else failures.push(errorText(record.reason));
    if (linked.status === "fulfilled") {
      const results = await Promise.allSettled(linked.value.decisions.map(row => getRuntimeDecisionDetail(row.decision.decisionId)));
      if (token !== request.current) return;
      setDecisions(results.flatMap(result => result.status === "fulfilled" ? [result.value] : []));
      results.forEach(result => { if (result.status === "rejected") failures.push(errorText(result.reason)); });
    } else failures.push(errorText(linked.reason));
    setDetailError([...new Set(failures)].join("；")); setDetailBusy(false);
  }, []);
  const open = (id: string) => { setDetailTab("overview"); selected.current = id; setSelectedId(id); setDetail(undefined); setDecisions([]); setActionError(""); void loadDetail(id); };
  const close = () => { selected.current = undefined; request.current++; setSelectedId(undefined); setPreview(undefined); };
  useEffect(() => () => { request.current++; selected.current = undefined; }, []);
  const changeMode = async (value: string | number) => {
    setModeBusy(true); try { setMode(await setRuntimeSecurityMode(value as RuntimeSecurityMode)); setError("mode"); } catch (e) { setError("mode", e); } finally { setModeBusy(false); }
  };
  const rebuildDetections = async () => {
    setReplayBusy(true); setError("replay");
    try {
      const job = await createRuntimeEventReplay();
      if (!job.scan_id) throw new Error("网关未返回检测重建任务 ID");
      for (let attempt = 0; attempt < 120; attempt += 1) {
        const status = await getScanStatus(job.scan_id);
        if (status.status === "completed") { message.success("历史行为检测重建完成"); refresh(); return; }
        if (["failed", "cancelled", "canceled"].includes(status.status)) throw new Error(status.error || `检测重建任务：${status.status}`);
        await new Promise<void>(resolve => window.setTimeout(resolve, 1000));
      }
      throw new Error("检测重建等待超时，请稍后刷新查看");
    } catch (error) { setError("replay", error); }
    finally { setReplayBusy(false); }
  };
  const previewBlock = async () => {
    const id = selected.current; if (!id) return; setActionBusy(true); setActionError("");
    try { const key = crypto.randomUUID(); const result = await blockRuntimeDetection(id, undefined, "manual_operator_action", { preview: true, idempotencyKey: key }); if (!result.plan) throw new Error("后端未返回处置预览，无法确认执行。"); if (selected.current === id) setPreview({ id, key, plan: result.plan }); }
    catch (e) { if (selected.current === id) setActionError(errorText(e)); } finally { setActionBusy(false); }
  };
  const execute = async () => {
    if (!preview) return; const action = preview; setActionBusy(true); setActionError("");
    try { const result = await blockRuntimeDetection(action.id, undefined, "manual_operator_action", { idempotencyKey: action.key }); if (result.status === "blocked") message.success("后端确认阻断已执行"); else message.info(`处置状态：${result.status || "unknown"}，请查看执行记录。`); setPreview(undefined); refresh(); if (selected.current === action.id) await loadDetail(action.id); }
    catch (e) { setActionError(errorText(e)); } finally { setActionBusy(false); }
  };
  const multi = (key: "category" | "detectionType" | "severity" | "status" | "source", label: string, values: string[]) => <Select aria-label={label} mode="tags" allowClear placeholder={label} value={filters[key]?.split(",").filter(Boolean) ?? []} options={values.map(value => ({ value, label: value }))} onChange={value => change({ [key]: value.join(",") || undefined })} />;
  const setDate = (key: "start" | "end", value: string) => { setDates(old => ({ ...old, [key]: value })); const date = new Date(value); change({ [key === "start" ? "startTime" : "endTime"]: value && Number.isFinite(date.getTime()) ? date.toISOString() : undefined }); };
  const record = detail?.detection;
  const info = record ? { "Detection ID": record.detectionId, "Agent 实例": `${record.agentName || detail?.agent?.name || ""} · ${record.agentId || detail?.agent?.agentId || "unknown"}`, "检测类型": record.detectionType, "规则 / 版本": `${record.ruleId || "—"} / ${record.ruleVersion || "—"}`, "来源": record.source || "—", "首次发现": formatTimestamp(record.firstSeenAt || ""), "最近发现": formatTimestamp(record.lastSeenAt || ""), "Session": record.sessionId || detail?.runtimeSession?.sessionId || "—", "Trace": record.traceId || detail?.trace?.traceId || "—", "置信度": record.confidence === undefined ? "—" : `${Math.round(record.confidence * 100)}%`, "处置建议": record.remediation || "—" } : {};
  return <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorPrimary: "#1677ff", colorBgContainer: "#fff", colorText: "#16273e", borderRadius: 10 } }}><section className="runtime-workbench">
    <div className="runtime-workbench-heading"><div><Text className="eyebrow">ANOMALY DETECTION</Text><Title level={2}>异常事件检测</Title><Text type="secondary">追踪异常行为、核对证据与处置结果。</Text></div><Space wrap>{mode ? <Segmented value={mode} disabled={modeBusy} options={[{ value: "observe", label: "观察模式" }, { value: "action", label: "处置模式" }]} onChange={value => void changeMode(value)} /> : <Tag>运行模式不可用</Tag>}<Button loading={replayBusy} onClick={() => void rebuildDetections()}>重建检测结果</Button><Button icon={<ReloadOutlined />} loading={listBusy || summaryBusy} onClick={refresh}>刷新</Button></Space></div>
    {Object.entries(errors).filter(([, e]) => e).map(([key, e]) => <Alert key={key} type="error" showIcon title={e} action={<Button onClick={refresh}>重试</Button>} />)}
    <div className="runtime-workbench-metrics">{[["总异常事件", totals.total], ["攻击事件", totals.attack], ["高危及以上", totals.high], ["未解决事件", totals.open]].map(([label, value], index) => <Card key={label} className={`runtime-workbench-metric metric-${index}`}><Text type="secondary">{label}</Text><strong>{summaryReady ? value : "—"}</strong><Text type="secondary">当前筛选的完整汇总</Text></Card>)}</div>
    <Card title="Agent 类型风险分布" extra={<Button type="link" onClick={() => change({ agentTypeId: undefined })}>全部类型</Button>}><div className="runtime-type-cards">{types.map(type => <button type="button" key={`${type.agentTypeId}:${type.agentType}`} className={filters.agentTypeId === type.agentTypeId ? "selected" : ""} onClick={() => change({ agentTypeId: type.agentTypeId || undefined })}><strong>{type.agentTypeName || type.agentType || "unknown"}</strong><b>{type.totalEvents}</b><span>异常事件</span><div>{Object.entries(type.riskCounts).map(([risk, count]) => <Tag key={risk} color={riskColors[risk.toLowerCase()]}>{risk.toUpperCase()} {count}</Tag>)}</div></button>)}</div>{!types.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={summaryBusy ? "正在读取汇总" : "当前筛选无异常事件"} />}</Card>
    <div className="runtime-workbench-columns"><Card className="runtime-instance-list" title="Agents" extra={<Tag>{agents.length}</Tag>}><Input aria-label="搜索 Agent 实例" prefix={<SearchOutlined />} placeholder="搜索 Agent" value={agentSearch} onChange={e => setAgentSearch(e.target.value)} allowClear /><button type="button" className={!filters.agentId ? "selected" : ""} onClick={() => change({ agentId: undefined })}><strong>全部 Agent 实例</strong></button>{agents.filter(a => `${a.agentName} ${a.agentId} ${a.agentType}`.toLowerCase().includes(agentSearch.toLowerCase())).map(a => <button type="button" key={a.agentId} className={filters.agentId === a.agentId ? "selected" : ""} onClick={() => change({ agentId: a.agentId })}><strong>{a.agentName || a.agentId}</strong><span>{a.agentType}</span><code>{a.agentId}</code><span>{a.detectionCount} 个检测 · 高危 {a.highOrAboveCount}</span></button>)}{!agents.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent 实例" />}</Card>
    <Card className="runtime-result-card" title="异常事件列表" extra={<Space><Text type="secondary">{total} 条</Text><Button type="link" onClick={() => setAdvanced(value => !value)}>{advanced ? "收起筛选" : "更多筛选"}</Button></Space>}><div className="runtime-workbench-filters" data-expanded={advanced}>
      <Input aria-label="事件关键字" allowClear placeholder="搜索事件、规则、Agent" value={filters.keyword || ""} onChange={e => change({ keyword: e.target.value || undefined })} />
      {multi("category", "类别", ["attack", "suspicious", "hygiene"])}{multi("severity", "风险等级", ["critical", "high", "medium", "low", "info"])}{multi("status", "事件状态", ["open", "mitigated", "resolved", "blocked"])}{multi("detectionType", "检测类型", [...new Set(rows.map(r => r.detectionType).filter(Boolean))])}{multi("source", "检测来源", ["runtime_detection", "correlation_engine", "runtime_policy"])}
      <Select aria-label="Agent 类型" allowClear placeholder="全部 Agent 类型" value={filters.agentTypeId} options={Object.entries(typeOptions).map(([id, label]) => ({ value: Number(id), label }))} onChange={agentTypeId => change({ agentTypeId })} />
      <Input aria-label="Session ID" allowClear placeholder="Session ID" value={filters.sessionId || ""} onChange={e => change({ sessionId: e.target.value || undefined })} /><Input aria-label="Trace ID" allowClear placeholder="Trace ID" value={filters.traceId || ""} onChange={e => change({ traceId: e.target.value || undefined })} />
      <label>开始时间<Input aria-label="开始时间" type="datetime-local" value={dates.start} onChange={e => setDate("start", e.target.value)} /></label><label>结束时间<Input aria-label="结束时间" type="datetime-local" value={dates.end} onChange={e => setDate("end", e.target.value)} /></label>
      <Select aria-label="排序" value={filters.sort} options={[{ value: "latest", label: "最近发现优先" }, { value: "oldest", label: "最早发现优先" }, { value: "severity", label: "风险优先" }]} onChange={sort => change({ sort })} />
    </div><Table<RuntimeDetection> rowKey="detectionId" loading={listBusy} dataSource={rows} scroll={{ x: 1400 }} onRow={row => ({ onClick: () => open(row.detectionId) })} pagination={{ current: paging.page, pageSize: paging.pageSize, total, showSizeChanger: true, pageSizeOptions: [20, 50, 100], onChange: (page, pageSize) => setPaging({ page: pageSize === paging.pageSize ? page : 1, pageSize }) }} columns={[
      { title: "异常事件 / 检测类型", width: 260, render: (_, row) => <Space orientation="vertical" size={2}><Text strong>{row.title || row.detectionType}</Text><Text type="secondary">{row.detectionType} · {row.ruleId}</Text></Space> }, { title: "Agent", width: 150, render: (_, row) => <span title={row.agentId}>{row.agentName || row.agentId || "unknown"}</span> }, { title: "类别", dataIndex: "category", width: 100 }, { title: "风险", dataIndex: "severity", render: riskTag, width: 110 }, { title: "状态", dataIndex: "status", render: statusTag, width: 100 }, { title: "来源", dataIndex: "source", width: 150 }, { title: "最近发现", width: 180, render: (_, row) => formatTimestamp(row.lastSeenAt || row.createdAt || "") }, { title: "Session / Trace", width: 175, render: (_, row) => <Space orientation="vertical" size={0}><Text code>{row.sessionId || "—"}</Text><Text code>{row.traceId || "—"}</Text></Space> }, { title: "证据", dataIndex: "eventCount", width: 65, render: (count: number | undefined) => count ?? 0 }, { title: "操作", width: 85, render: (_, row) => <Button type="link" onClick={e => { e.stopPropagation(); open(row.detectionId); }}>详情</Button> },
    ]} locale={{ emptyText: "当前筛选无异常事件" }} /></Card></div>
    <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorBgContainer: "#ffffff", colorBgElevated: "#ffffff", colorText: "#14213a", colorTextSecondary: "#667085", colorBorderSecondary: "#e7ebf3" } }}>
      <Drawer className="runtime-evidence-drawer" title={record?.title || "异常事件详情"} open={!!selectedId} width="min(680px, 96vw)" onClose={close} loading={detailBusy} footer={<Space><Button danger disabled={!record} loading={actionBusy} onClick={() => void previewBlock()}>预览阻断方案</Button><Button onClick={() => selectedId && void loadDetail(selectedId)}>重新读取</Button></Space>}>
        {detailError && <Alert type="error" title={detailError} action={<Button onClick={() => selectedId && void loadDetail(selectedId)}>重试详情</Button>} />}{actionError && <Alert type="error" title={actionError} />}
        {record && <><Space>{riskTag(record.severity)}{statusTag(record.status)}<Tag>{record.category}</Tag></Space>
          <Tabs activeKey={detailTab} onChange={setDetailTab} items={[
            { key: "overview", label: "概览", children: <Space orientation="vertical" size={16} style={{width:"100%"}}><Text>{record.detail || record.description || "暂无补充说明"}</Text><Descriptions bordered size="small" column={1} items={Object.entries(info).map(([label, children]) => ({ key: label, label, children }))} /></Space> },
            { key: "evidence", label: `证据 (${detail?.evidence?.length ?? 0})`, children: <Card size="small" title={`证据事件 · ${detail?.evidence?.length ?? 0}`}>{detail?.evidence?.map((event, index) => <div className="runtime-evidence-event" key={`${event.eventId}:${index}`}><Space wrap><Tag>#{event.sequence ?? index + 1}</Tag><Text strong>{event.eventType}</Text><Tag>{event.outcome || "unknown"}</Tag></Space><p>{event.detail || event.target || event.toolName || "—"}</p><Text type="secondary">{formatTimestamp(event.timestamp || "")} · {event.eventSource} · Event {event.eventId}</Text><pre>{json(event)}</pre></div>)}{!detail?.evidence?.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无证据事件" />}</Card> },
            { key: "context", label: "上下文", children: <Space orientation="vertical" size={16} style={{width:"100%"}}><Descriptions bordered size="small" column={1} items={[{ key: "session", label: "Session", children: record.sessionId || detail?.runtimeSession?.sessionId || "—" }, { key: "trace", label: "Trace", children: record.traceId || detail?.trace?.traceId || "—" }]} /><Card size="small" title="结构化上下文"><pre>{json(record.attributes ?? {})}</pre></Card></Space> },
            { key: "actions", label: "处置", children: <Card size="small" title={`决策与执行结果 · ${decisions.length}`}>{decisions.map(item => <div className="runtime-evidence-event" key={item.decision.decisionId}><Space wrap><Tag>{item.decision.decision}</Tag><Tag>{item.decision.mode}</Tag>{item.decision.wouldBlock && <Tag>仅记录拟阻断</Tag>}</Space><p>{item.decision.reason}</p><Text type="secondary">{item.decision.decisionId} · {item.decision.policyVersion || item.decision.policyId}</Text>{item.responses?.map(response => <div className="runtime-response" key={response.responseId}><Space wrap><Tag color={response.status === "executed" ? "green" : response.status === "failed" ? "red" : "gold"}>{response.status}</Tag><Text>{response.actionType} · {response.executor}</Text></Space><p>目标：{response.target || "—"}</p><p>执行结果：{response.result || "—"}</p><Text type="secondary">{formatTimestamp(response.executedAt || "")}</Text></div>)}{!item.responses?.length && <p>尚无执行记录</p>}</div>)}{!decisions.length && <Text type="secondary">尚无决策记录。风险等级不代表已执行阻断。</Text>}</Card> },
          ]} />
        </>}
      </Drawer>
      <Modal title="确认阻断方案" open={!!preview} onCancel={() => !actionBusy && setPreview(undefined)} onOk={() => void execute()} confirmLoading={actionBusy} okText="确认执行阻断" okButtonProps={{ danger: true }} cancelText="取消">{actionError && <Alert type="error" title={actionError} />}<Descriptions column={1} items={[{ key: "point", label: "执行点", children: preview?.plan.enforcement_point }, { key: "action", label: "动作", children: preview?.plan.action_type }, { key: "target", label: "目标", children: preview?.plan.target }]} /></Modal>
    </ConfigProvider>
  </section></ConfigProvider>;
}
