import { useEffect, useMemo, useRef, useState } from "react";
import { DownloadOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Card, ConfigProvider, Drawer, Empty, Input, Select, Space, Table, Tabs, Tag, Typography, message, theme } from "antd";
import { createAttackChainRebuildJob, getAttackChainAgentTypeSummaries, getAttackChainDetail, getAttackChains, getRuntimeSecurityAgents, getScanStatus } from "../bridge";
import { formatTimestamp } from "../app/display";
import type { AttackChain, AttackChainAgentTypeSummary, AttackChainDetail, AttackChainListQuery, AttackChainSnapshot, GatewayAuditSnapshot, RangeMode, RuntimeSecurityAgent } from "../types";
import { attackChainDetailTabs } from "./AttackChainDetailContent";

const { Text, Title } = Typography;

type Filters = Omit<AttackChainListQuery, "page" | "pageSize">;
interface Props { defenseMode: RangeMode; gatewayAudit?: GatewayAuditSnapshot; snapshot?: AttackChainSnapshot; loading?: boolean; onRefresh?: () => Promise<void> | void }
const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
const rawText = (value: unknown) => value === undefined || value === null || value === "" ? "—" : String(value);
const riskColors: Record<string, string> = { critical: "red", high: "orange", medium: "gold", low: "green", info: "blue" };
const riskTag = (risk?: string) => <Tag color={riskColors[(risk || "").toLowerCase()]}>{(risk || "unknown").toUpperCase()}</Tag>;
const statusTag = (status?: string) => <Tag>{({ active: "活跃", contained: "已遏制" } as Record<string, string>)[status || ""] || status || "unknown"}</Tag>;
const json = (value: unknown) => JSON.stringify(value, null, 2);

function exportJSON(value: unknown, name: string) {
  const url = URL.createObjectURL(new Blob([json(value)], { type: "application/json" }));
  const a = document.createElement("a"); a.href = url; a.download = name; a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function AttackChainPage({ snapshot }: Props) {
  const [filters, setFilters] = useState<Filters>({ sort: "latest" });
  const [paging, setPaging] = useState({ page: 1, pageSize: 20 });
  const [revision, setRevision] = useState(0);
  const [agents, setAgents] = useState<RuntimeSecurityAgent[]>([]);
  const [search, setSearch] = useState("");
  const [types, setTypes] = useState<AttackChainAgentTypeSummary[]>([]);
  const [typeOptions, setTypeOptions] = useState<Record<number, string>>({});
  const [rows, setRows] = useState<AttackChain[]>([]);
  const [total, setTotal] = useState(0);
  const [listBusy, setListBusy] = useState(false);
  const [summaryReady, setSummaryReady] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [advanced, setAdvanced] = useState(false);
  const [dates, setDates] = useState({ start: "", end: "" });
  const [selectedId, setSelectedId] = useState<string>();
  const [detail, setDetail] = useState<AttackChainDetail>();
  const [detailBusy, setDetailBusy] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [detailTab, setDetailTab] = useState("overview");
  const [jobId, setJobId] = useState<string>();
  const [jobBusy, setJobBusy] = useState(false);
  const [jobStatus, setJobStatus] = useState("");
  const detailGeneration = useRef(0);
  const setError = (source: string, error: unknown) => setErrors(current => ({ ...current, [source]: error ? errorText(error) : "" }));
  const refreshNonce = snapshot?.capturedAt;
  const listKey = JSON.stringify({ ...filters, ...paging });
  const { sort: _sort, ...summaryFilters } = filters;
  const summaryKey = JSON.stringify(summaryFilters);

  useEffect(() => {
    let active = true;
    getRuntimeSecurityAgents(1000).then(value => { if (active) { setAgents(value); setError("agents", ""); } })
      .catch(error => { if (active) setError("agents", error); });
    return () => { active = false; };
  }, [revision, refreshNonce]);

  useEffect(() => {
    let active = true; setSummaryReady(false);
    getAttackChainAgentTypeSummaries(JSON.parse(summaryKey)).then(value => {
      if (!active) return;
      const items = value.items ?? value.list ?? [];
      setTypes(items); setSummaryReady(true); setError("summary", "");
      setTypeOptions(current => ({ ...current, ...Object.fromEntries(items.filter(item => item.agentTypeId > 0).map(item => [item.agentTypeId, item.agentTypeName || item.agentType])) }));
    }).catch(error => { if (active) setError("summary", error); });
    return () => { active = false; };
  }, [summaryKey, revision, refreshNonce]);

  useEffect(() => {
    let active = true; setListBusy(true);
    getAttackChains(JSON.parse(listKey)).then(value => {
      if (active) { setRows(value.chains ?? []); setTotal(value.total ?? 0); setError("list", ""); }
    }).catch(error => { if (active) setError("list", error); }).finally(() => { if (active) setListBusy(false); });
    return () => { active = false; };
  }, [listKey, revision, refreshNonce]);

  useEffect(() => {
    if (!jobId) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const result = await getScanStatus(jobId);
        if (!active) return;
        setJobStatus(result.status); setError("job", "");
        if (["completed", "failed", "cancelled", "canceled"].includes(result.status)) {
          setJobId(undefined); setJobBusy(false);
          if (result.status === "completed") { setRevision(value => value + 1); message.success("攻击链重建完成"); }
          else setError("job", result.error || `重建任务：${result.status}`);
          return;
        }
      } catch (error) { if (active) setError("job", error); }
      if (active) timer = setTimeout(poll, 1500);
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [jobId]);

  const totals = useMemo(() => types.reduce((result, item) => ({
    covered: result.covered + (item.coveredAgents ?? 0),
    chains: result.chains + item.totalChains,
    active: result.active + (item.statusCounts.active ?? 0),
    high: result.high + Object.entries(item.severityCounts).reduce((sum, [risk, count]) => sum + (["high", "critical"].includes(risk.toLowerCase()) ? count : 0), 0),
  }), { covered: 0, chains: 0, active: 0, high: 0 }), [types]);
  const instanceCounts = useMemo(() => new Map(types.flatMap(type => (type.agents ?? []).map(agent => [agent.agentId, agent] as const))), [types]);
  const instances = useMemo(() => {
    const map = new Map(agents.map(agent => [agent.agentId, { id: agent.agentId, name: agent.agentName || agent.agentId, type: agent.agentType }]));
    for (const type of types) for (const agent of type.agents ?? []) {
      if (!map.has(agent.agentId)) map.set(agent.agentId, { id: agent.agentId, name: agent.agentId, type: type.agentTypeName || type.agentType });
    }
    return [...map.values()].filter(agent => `${agent.name} ${agent.id} ${agent.type}`.toLowerCase().includes(search.toLowerCase()));
  }, [agents, types, search]);
  const change = (patch: Partial<Filters>) => { setFilters(current => ({ ...current, ...patch })); setPaging(current => ({ ...current, page: 1 })); };
  const clear = () => { setFilters({ sort: "latest" }); setPaging(current => ({ ...current, page: 1 })); setDates({ start: "", end: "" }); };
  const openDetail = async (id: string, reload = false) => {
    const generation = ++detailGeneration.current;
    setSelectedId(id); setDetailBusy(true); setDetailError("");
    if (!reload) { setDetail(undefined); setDetailTab("overview"); }
    try { const value = await getAttackChainDetail(id); if (generation === detailGeneration.current) setDetail(value); }
    catch (error) { if (generation === detailGeneration.current) setDetailError(errorText(error)); }
    finally { if (generation === detailGeneration.current) setDetailBusy(false); }
  };
  const rebuild = async () => {
    setJobBusy(true); setError("job", "");
    try {
      const job = await createAttackChainRebuildJob();
      if (!job.scan_id) throw new Error("网关未返回重建任务 ID");
      setJobId(job.scan_id); setJobStatus(job.status);
    } catch (error) { setError("job", error); setJobBusy(false); }
  };
  const raw = detail?.attack_chain;
  const responses = detail?.responses?.length ? detail.responses : detail?.response?.response_id ? [detail.response] : [];
  const riskOptions = [...new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", ...types.flatMap(type => Object.keys(type.severityCounts).map(value => value.toUpperCase()))])];
  const statusOptions = [...new Set(["active", "contained", ...types.flatMap(type => Object.keys(type.statusCounts))])];

  return <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorPrimary: "#1677ff", colorBgContainer: "#ffffff", colorText: "#16273e", borderRadius: 10 } }}>
    <div className="chain-page-workbench">
      <div className="chain-page-workbench-heading">
        <div><Text type="secondary">RUNTIME ATTACK CHAINS</Text><Title level={2}>攻击链</Title><Text type="secondary">按 Agent、类型与风险调查链路及关联证据</Text></div>
        <Space wrap>
          <Button icon={<DownloadOutlined />} disabled={!rows.length} onClick={() => exportJSON({ filters, ...paging, total, chains: rows }, "attack-chains-page.json")}>导出当前页</Button>
          <Button loading={jobBusy} onClick={() => void rebuild()}>重建攻击链</Button>
          <Button icon={<ReloadOutlined />} onClick={() => setRevision(value => value + 1)}>刷新结果</Button>
        </Space>
      </div>
      {Object.entries(errors).filter(([, value]) => value).map(([key, value]) => <Alert key={key} type="error" showIcon title={value} />)}
      {jobId && <Alert type="info" showIcon title={`重建任务 ${jobId} · ${jobStatus}`} />}
      <div className="chain-page-workbench-metrics">{[
        ["覆盖 Agent", totals.covered], ["攻击链总数", totals.chains], ["活跃攻击链", totals.active], ["高危及以上", totals.high],
      ].map(([label, value], index) => <Card key={label} className={`chain-page-workbench-metric metric-${index}`}><Text type="secondary">{label}</Text><strong>{summaryReady ? value : "—"}</strong><Text type="secondary">当前筛选完整统计</Text></Card>)}</div>
      <div className="chain-page-workbench-columns">
        <Card title="Agents" className="runtime-instance-list">
          <Input aria-label="搜索 Agent 实例" prefix={<SearchOutlined />} placeholder="搜索实例" value={search} onChange={event => setSearch(event.target.value)} />
          <button className={!filters.agentId ? "selected" : ""} onClick={() => change({ agentId: undefined })}><strong>全部 Agent</strong><span>{summaryReady ? totals.chains : "—"} Chains · {summaryReady ? totals.high : "—"} High+</span></button>
          {instances.map(agent => <button key={agent.id} className={filters.agentId === agent.id ? "selected" : ""} onClick={() => change({ agentId: agent.id })}>
            <strong>{agent.name}</strong><code>{agent.id}</code><span>{agent.type}</span><span>{summaryReady ? instanceCounts.get(agent.id)?.totalChains ?? 0 : "—"} Chains · {summaryReady ? instanceCounts.get(agent.id)?.highOrAbove ?? 0 : "—"} High+</span>
          </button>)}
          {!instances.length && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="没有匹配实例" />}
        </Card>
        <div style={{ display: "grid", gap: 18, minWidth: 0 }}>
          <Card size="small"><Title level={4} style={{ marginTop: 0 }}>{filters.agentId ? agents.find(agent => agent.agentId === filters.agentId)?.agentName || filters.agentId : "全部 Agent"} / 攻击链</Title>
            <Space wrap>{types.map(type => <Tag key={`${type.agentTypeId}:${type.agentType}`}>{type.agentTypeName || type.agentType || "unknown"} · {type.totalChains}</Tag>)}</Space>
            <div style={{ marginTop: 8 }}><Space wrap>{types.flatMap(type => Object.entries(type.statusCounts).map(([status, count]) => <Text type="secondary" key={`${type.agentTypeId}:${type.agentType}:${status}`}>{type.agentType} · {status}: {count}</Text>))}</Space></div>
          </Card>
          <Card className="runtime-result-card">
            <div className="chain-page-workbench-filters" data-expanded={advanced}>
              <Input aria-label="搜索攻击链" allowClear prefix={<SearchOutlined />} placeholder="链路 ID、Agent、会话、检测/决策 ID" value={filters.keyword} onChange={event => change({ keyword: event.target.value || undefined })} />
              <Select aria-label="攻击类型" mode="tags" maxCount={1} placeholder="全部攻击类型" value={filters.attackType ? [filters.attackType] : []} options={[...new Set(rows.map(row => row.category))].map(value => ({ value }))} onChange={value => change({ attackType: value[0] })} />
              <Select aria-label="风险等级" allowClear placeholder="全部风险" value={filters.severity} options={riskOptions.map(value => ({ value }))} onChange={severity => change({ severity })} />
              <Select aria-label="链路状态" allowClear placeholder="全部状态" value={filters.status} options={statusOptions.map(value => ({ value }))} onChange={status => change({ status })} />
              <Select aria-label="Agent 类型" allowClear placeholder="全部 Agent 类型" value={filters.agentTypeId} options={Object.entries(typeOptions).map(([value, label]) => ({ value: Number(value), label }))} onChange={agentTypeId => change({ agentTypeId })} />
              <Input aria-label="Session ID" placeholder="Session ID" value={filters.sessionId} onChange={event => change({ sessionId: event.target.value || undefined })} />
              <Input aria-label="Trace ID" placeholder="Trace ID" value={filters.traceId} onChange={event => change({ traceId: event.target.value || undefined })} />
              <label>开始时间<Input aria-label="开始时间" type="datetime-local" value={dates.start} onChange={event => { setDates(value => ({ ...value, start: event.target.value })); change({ startTime: event.target.value ? new Date(event.target.value).toISOString() : undefined }); }} /></label>
              <label>结束时间<Input aria-label="结束时间" type="datetime-local" value={dates.end} onChange={event => { setDates(value => ({ ...value, end: event.target.value })); change({ endTime: event.target.value ? new Date(event.target.value).toISOString() : undefined }); }} /></label>
            </div>
            <Space wrap style={{ marginBottom: 16 }}><Button size="small" onClick={() => setAdvanced(value => !value)}>{advanced ? "收起筛选" : "更多筛选"}</Button><Button size="small" onClick={clear}>重置筛选</Button>
              <Select aria-label="时间排序" value={filters.sort} options={[{ value: "latest", label: "时间倒序" }, { value: "oldest", label: "时间正序" }, { value: "severity", label: "风险优先" }]} onChange={sort => change({ sort })} />
              <Text type="secondary">共 {total} 条链路</Text>
            </Space>
            <Table<AttackChain> rowKey="id" size="small" dataSource={rows} loading={listBusy} scroll={{ x: 1100 }} onRow={row => ({ onClick: () => void openDetail(row.id) })}
              pagination={{ current: paging.page, pageSize: paging.pageSize, total, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: value => `共 ${value} 条`, onChange: (page, pageSize) => setPaging({ page, pageSize }) }}
              columns={[
                { title: "攻击链", key: "chain", width: 240, render: (_, row) => <><Text strong>{row.category}</Text><div><Text type="secondary">{row.id}</Text></div><Text type="secondary">{row.detectionId || row.decisionId}</Text></> },
                { title: "Agent", key: "agent", width: 190, render: (_, row) => <>{row.agent}<div><Text type="secondary">{row.agentId}</Text></div><Text type="secondary">{row.agentTypeName}</Text></> },
                { title: "攻击类型", dataIndex: "category", width: 150 },
                { title: "风险", key: "risk", width: 100, render: (_, row) => riskTag(row.rawSeverity || row.risk) },
                { title: "状态", key: "status", width: 100, render: (_, row) => statusTag(row.rawStatus || row.status) },
                { title: "步骤 / 证据", key: "counts", width: 110, render: (_, row) => `${row.stepCount} / ${row.evidenceCount}` },
                { title: "Trace / Session", key: "context", width: 180, render: (_, row) => <><Text>{row.traceId || "—"}</Text><div><Text type="secondary">{row.sessionId || "—"}</Text></div></> },
                { title: "结束时间", dataIndex: "endedAt", width: 180, render: formatTimestamp },
              ]} />
          </Card>
        </div>
      </div>
      <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorBgElevated: "#ffffff", colorBgContainer: "#ffffff", colorText: "#14213a", colorTextSecondary: "#667085", colorBorder: "#e7ebf3" } }}>
        <Drawer rootClassName="chain-page-workbench-drawer" width="min(720px, 96vw)" open={!!selectedId} title={detail?.detections?.[0]?.title ? String(detail.detections[0].title) : "攻击链详情"} onClose={() => { detailGeneration.current++; setSelectedId(undefined); }} loading={detailBusy}
          footer={<Space wrap><Button icon={<ReloadOutlined />} onClick={() => selectedId && void openDetail(selectedId, true)}>刷新详情</Button><Button disabled={!detail} icon={<DownloadOutlined />} onClick={() => detail && exportJSON(detail, `attack-chain-${selectedId}.json`)}>导出详情</Button></Space>}>
          {detailError && <Alert type="error" showIcon title={detailError} />}
          {detail && <><Title level={4}>{rawText(raw?.attack_type)}</Title><Text code>{rawText(raw?.attack_chain_id)}</Text><div style={{ margin: "16px 0" }}><Space>{riskTag(String(raw?.severity || "unknown"))}{statusTag(String(raw?.status || "unknown"))}<Tag>{responses.filter(response => response.status === "executed").length} 条已执行响应</Tag></Space></div>
            <Tabs activeKey={detailTab} onChange={setDetailTab} items={attackChainDetailTabs(detail)} />
          </>}
        </Drawer>
      </ConfigProvider>
    </div>
  </ConfigProvider>;
}
