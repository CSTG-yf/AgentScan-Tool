import { useEffect, useRef, useState } from "react";
import { Alert, Button, Card, ConfigProvider, Input, Popconfirm, Progress, Select, Space, Switch, Table, Tag, Typography, message, theme } from "antd";
import { PlusOutlined, ReloadOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { getScanStatus } from "../bridge";
import type { StaticResourceScanAccepted } from "../types";
import { deleteRuntimeRule, getGlobalRuntimeRiskPolicy, getRuntimeRules, getRuntimeSettingsOverview, getRuntimeTypes, patchRuntimeRule } from "./api";
import { RuleEditor, enabledOptions, errorText } from "./Editors";
import { RuntimeTypeDialog, riskTag } from "./TypeDialog";
import type { RuntimeRiskPolicy, RuntimeRule, RuntimeSettingsOverview, RuntimeSettingsPage, RuntimeSettingsQuery, RuntimeTypeRow } from "./types";
import "./settings.css";

const { Text, Title } = Typography;
export function RuntimeDetectionSettingsPage() {
  const [overview, setOverview] = useState<RuntimeSettingsOverview>();
  const [riskPolicy, setRiskPolicy] = useState<RuntimeRiskPolicy>();
  const [rules, setRules] = useState<RuntimeSettingsPage<RuntimeRule>>();
  const [types, setTypes] = useState<RuntimeSettingsPage<RuntimeTypeRow>>();
  const [ruleQuery, setRuleQuery] = useState<RuntimeSettingsQuery>({ page: 1, page_size: 5, enabled: "all" });
  const [typeQuery, setTypeQuery] = useState<RuntimeSettingsQuery>({ page: 1, page_size: 10, enabled: "all", risk_policy: "all" });
  const [tick, setTick] = useState(0);
  const [loadingRules, setLoadingRules] = useState(false);
  const [loadingTypes, setLoadingTypes] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [editor, setEditor] = useState<{ rule?: RuntimeRule }>();
  const [typeId, setTypeId] = useState<number>();
  const [mutating, setMutating] = useState<number>();
  const [job, setJob] = useState<StaticResourceScanAccepted>();
  const [jobError, setJobError] = useState("");
  const [pollRetry, setPollRetry] = useState(0);
  const ruleRequest = useRef(0), typeRequest = useRef(0);
  const reportError = (key: string, value: string) => setErrors(old => ({ ...old, [key]: value }));
  const refresh = () => setTick(old => old + 1);
  useEffect(() => {
    let current = true;
    void Promise.allSettled([getRuntimeSettingsOverview(), getGlobalRuntimeRiskPolicy()]).then(([summary, risk]) => {
      if (!current) return;
      if (summary.status === "fulfilled") { setOverview(summary.value); reportError("overview", ""); } else reportError("overview", errorText(summary.reason));
      if (risk.status === "fulfilled") { setRiskPolicy(risk.value); reportError("risk", ""); } else reportError("risk", errorText(risk.reason));
    });
    return () => { current = false; };
  }, [tick]);
  useEffect(() => {
    const id = ++ruleRequest.current; setLoadingRules(true);
    void getRuntimeRules(ruleQuery).then(value => { if (id === ruleRequest.current) { setRules(value); reportError("rules", ""); } }).catch(error => { if (id === ruleRequest.current) reportError("rules", errorText(error)); }).finally(() => { if (id === ruleRequest.current) setLoadingRules(false); });
    return () => { ruleRequest.current++; };
  }, [ruleQuery, tick]);
  useEffect(() => {
    const id = ++typeRequest.current; setLoadingTypes(true);
    void getRuntimeTypes(typeQuery).then(value => { if (id === typeRequest.current) { setTypes(value); reportError("types", ""); } }).catch(error => { if (id === typeRequest.current) reportError("types", errorText(error)); }).finally(() => { if (id === typeRequest.current) setLoadingTypes(false); });
    return () => { typeRequest.current++; };
  }, [typeQuery, tick]);
  const jobId = job?.job_id ?? job?.scan_id;
  const jobRunning = !!job && ["queued", "running"].includes(job.status);
  useEffect(() => {
    if (!jobId || !jobRunning) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const value = await getScanStatus(jobId);
        if (cancelled) return;
        setJob(value); setJobError("");
        if (["queued", "running"].includes(value.status)) timer = setTimeout(() => void poll(), 1500);
        else refresh();
      } catch (error) { if (!cancelled) setJobError(errorText(error)); }
    };
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [jobId, jobRunning, pollRetry]);
  const mutate = async (rule: RuntimeRule, operation: () => Promise<unknown>) => {
    setMutating(rule.id); reportError("mutation", "");
    try { await operation(); refresh(); message.success("规则已保存；新配置影响后续事件，历史数据需显式重放"); }
    catch (error) { reportError("mutation", errorText(error)); } finally { setMutating(undefined); }
  };
  const visibleErrors = [...new Set(Object.values(errors).filter(Boolean))];
  return <ConfigProvider theme={{ algorithm: theme.defaultAlgorithm, token: { colorPrimary: "#1677ff", colorInfo: "#1677ff", colorBgBase: "#ffffff", colorBgContainer: "#ffffff", colorText: "#14213a", colorTextSecondary: "#667085", borderRadius: 10 } }}><div className="runtime-settings">
    <div className="runtime-section-heading"><div><Text className="eyebrow">ANOMALY DETECTION SETTINGS</Text><Title level={3}>异常检测设置</Title><Text type="secondary">维护通用规则、只读风险策略，以及不同 AgentType 的专属规则与黑名单。</Text></div><Button icon={<ReloadOutlined />} onClick={refresh}>刷新配置</Button></div>
    {visibleErrors.length > 0 && <Alert type="error" showIcon title="部分配置读取或保存失败" description={visibleErrors.join("；")} action={<Button onClick={refresh}>重试</Button>} />}
    <div className="runtime-summary-grid">
      {([ ["通用规则", overview?.global_rule_count, "blue"], ["已启用规则", overview?.enabled_global_rule_count, "green"], ["AgentType 配置", overview?.agent_type_count, "orange"], ["自定义风险策略", overview?.custom_risk_policy_count, "red"] ] as const).map(([label, value, color]) => <div className={`runtime-summary-card runtime-${color}`} key={label}><span><SafetyCertificateOutlined /> {label}</span><strong>{value ?? "—"}</strong></div>)}
    </div>
    <Card className="runtime-main-card" title={<div><strong>通用异常检测配置</strong><p className="runtime-muted">管理通用规则；通用风险判定规则只读展示。</p></div>}>
      <div className="runtime-global-columns">
        <div className="runtime-rule-panel">
          <div className="runtime-toolbar"><strong>通用异常检测规则</strong><Button type="primary" icon={<PlusOutlined />} onClick={() => setEditor({})}>新增规则</Button></div>
          <Space wrap className="runtime-filters">
            <Input.Search allowClear placeholder="搜索规则 / 类型 / 分类" onSearch={keyword => setRuleQuery(old => ({ ...old, keyword, page: 1 }))} style={{ width: 240 }} />
            <Select aria-label="通用规则状态" value={ruleQuery.enabled} options={enabledOptions} onChange={enabled => setRuleQuery(old => ({ ...old, enabled, page: 1 }))} />
            <Select aria-label="规则来源" value={ruleQuery.source ?? "all"} options={[{ value: "all", label: "全部来源" }, { value: "builtin", label: "内置规则" }, { value: "custom", label: "自定义" }]} onChange={source => setRuleQuery(old => ({ ...old, source: source === "all" ? undefined : source as "builtin" | "custom", page: 1 }))} />
          </Space>
          <Table<RuntimeRule> rowKey="id" size="small" loading={loadingRules} dataSource={rules?.items ?? []} scroll={{ x: 760 }} pagination={{ current: ruleQuery.page, pageSize: ruleQuery.page_size, total: rules?.total ?? 0, showSizeChanger: true, pageSizeOptions: [5, 10, 20, 50], showTotal: total => `共 ${total} 条`, onChange: (page, page_size) => setRuleQuery(old => ({ ...old, page: page_size !== old.page_size ? 1 : page, page_size })) }} columns={[
            { title: "规则名称", dataIndex: "rule_name", width: 190, render: (value, r) => <div><strong>{value}</strong><div className="runtime-muted">{r.source === "builtin" ? "内置" : "自定义"} · v{r.version}</div></div> },
            { title: "检测类型", dataIndex: "detection_type", width: 180, render: value => <span className="runtime-wrap">{value}</span> },
            { title: "分类", dataIndex: "category", width: 96, render: value => <Tag>{value}</Tag> },
            { title: "严重级别", dataIndex: "severity", width: 112, render: riskTag },
            { title: "状态", width: 68, render: (_, r) => <Switch size="small" checked={r.enabled} loading={mutating === r.id} disabled={mutating !== undefined} onChange={enabled => void mutate(r, () => patchRuntimeRule(r.id, { enabled, version: r.version }))} /> },
            { title: "操作", width: 110, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setEditor({ rule: r })}>编辑</Button><Popconfirm title={r.system ? "禁用此内置规则？" : "删除此自定义规则？"} description={r.system ? "内置算法保留，可再次启用。" : undefined} onConfirm={() => mutate(r, () => deleteRuntimeRule(r.id))}><Button type="link" danger size="small" disabled={mutating !== undefined}>{r.system ? "禁用" : "删除"}</Button></Popconfirm></Space> },
          ]} />
        </div>
        <div className="runtime-risk-panel"><div className="runtime-toolbar"><strong>通用风险判定规则</strong><Tag>只读展示</Tag></div><p className="runtime-muted">默认分值区间与决策映射。</p>
          {riskPolicy?.rules.map(row => <div className="runtime-risk-row" key={row.risk_level}>{riskTag(row.risk_level)}<span>{row.min_score.toFixed(2)} – {row.max_score.toFixed(2)}</span><Tag color={row.decision === "BLOCK" ? "red" : row.decision === "CONFIRM" ? "orange" : "blue"}>{row.display_decision}</Tag></div>)}
          {!riskPolicy && <Text type="secondary">{errors.risk ? "风险策略暂不可用" : "正在读取风险策略…"}</Text>}
        </div>
      </div>
    </Card>
    <Card className="runtime-main-card" title={<div><strong>AgentType 专属配置列表</strong><p className="runtime-muted">为不同类型 Agent 配置专属规则、黑名单与风险判定方式。</p></div>} extra={<Button icon={<ReloadOutlined />} onClick={() => setTypeQuery(old => ({ ...old }))}>刷新列表</Button>}>
      <Space wrap className="runtime-filters">
        <Input.Search allowClear placeholder="搜索 AgentType / 厂商 / 运行时" style={{ width: 280 }} onSearch={keyword => setTypeQuery(old => ({ ...old, keyword, page: 1 }))} />
        <Select aria-label="AgentType 检测状态" value={typeQuery.enabled} options={enabledOptions} onChange={enabled => setTypeQuery(old => ({ ...old, enabled, page: 1 }))} />
        <Select aria-label="继承通用规则筛选" value={typeQuery.inherit_global_rules ?? "all"} options={[{ value: "all", label: "全部继承方式" }, { value: "true", label: "继承通用规则" }, { value: "false", label: "不继承" }]} onChange={inherit_global_rules => setTypeQuery(old => ({ ...old, inherit_global_rules, page: 1 }))} />
        <Select aria-label="风险策略筛选" value={typeQuery.risk_policy} options={[{ value: "all", label: "全部风险策略" }, { value: "global", label: "通用策略" }, { value: "custom", label: "自定义策略" }]} onChange={risk_policy => setTypeQuery(old => ({ ...old, risk_policy, page: 1 }))} />
      </Space>
      <Table<RuntimeTypeRow> rowKey="agent_type_id" loading={loadingTypes} dataSource={types?.items ?? []} scroll={{ x: 960 }} pagination={{ current: typeQuery.page, pageSize: typeQuery.page_size, total: types?.total ?? 0, showSizeChanger: true, showTotal: total => `共 ${total} 个类型`, onChange: (page, page_size) => setTypeQuery(old => ({ ...old, page: old.page_size !== page_size ? 1 : page, page_size })) }} columns={[
        { title: "AgentType", dataIndex: "agent_type_name", render: (value, row) => <div><strong>{value}</strong><div className="runtime-muted">{row.agent_type_key}</div></div> },
        { title: "继承通用检测", dataIndex: "inherit_global_rules", render: value => <Tag color={value ? "blue" : "default"}>{value ? "是" : "否"}</Tag> },
        { title: "专属规则数", dataIndex: "specific_rule_count" }, { title: "黑名单数", dataIndex: "blacklist_count" },
        { title: "风险判定方式", dataIndex: "risk_policy_mode", render: value => <Tag color={value === "custom" ? "orange" : "blue"}>{value === "custom" ? "自定义" : "通用"}</Tag> },
        { title: "状态", dataIndex: "enabled", render: value => <Tag color={value ? "green" : "default"}>{value ? "启用" : "停用"}</Tag> },
        { title: "操作", render: (_, row) => <Button type="primary" ghost onClick={() => setTypeId(row.agent_type_id)}>详情</Button> },
      ]} />
    </Card>
    {job && <Alert showIcon type={jobError || job.status === "failed" ? "error" : job.status === "completed" ? "success" : "info"} title={`历史重放 · ${{ queued: "排队中", running: "运行中", completed: "完成", failed: "失败", cancelled: "已取消" }[job.status] ?? job.status}`} description={<><Text>任务 {jobId}</Text><Progress percent={job.progress ?? 0} status={job.status === "failed" ? "exception" : undefined} /><div>{jobError || job.error || job.phase}</div></>} action={jobError ? <Button onClick={() => setPollRetry(old => old + 1)}>重新查询</Button> : undefined} />}
    <RuleEditor open={!!editor} rule={editor?.rule} onClose={() => setEditor(undefined)} onSaved={refresh} />
    {typeId !== undefined && <RuntimeTypeDialog key={typeId} typeId={typeId} onClose={() => setTypeId(undefined)} onChanged={refresh} onReplay={value => { setJob(value); setJobError(""); }} />}
  </div></ConfigProvider>;
}
