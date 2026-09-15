import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Input, Popconfirm, Progress, Select, Space, Switch, Table, Tag, Typography, message, theme, Form, InputNumber, Modal, Spin } from "antd";
import { PlusOutlined, ReloadOutlined, DeleteOutlined } from "@ant-design/icons";
import { deleteRuntimeRule, getGlobalRuntimeRiskPolicy, getRuntimeRules, getRuntimeTypes, getScanStatus, patchRuntimeRule, createRuntimeBlacklist, createRuntimeRule, patchRuntimeBlacklist, createRuntimeEventReplay, deleteRuntimeBlacklist, evaluateRuntimeEvent, getRuntimeTypeDetail, patchRuntimeTypeSettings, saveRuntimeRiskPolicy } from "../../bridge";
import type { RuntimeRiskPolicy, RuntimeRule, RuntimeSettingsPage, RuntimeSettingsQuery, RuntimeTypeRow, StaticResourceScanAccepted, RuntimeBlacklist, RuntimeMatcher, RuntimePattern, RuntimeEvaluation, RuntimeRiskPolicyRule, RuntimeTypeDetail, RuntimeTypeSettings } from "../../types";
const { Text, Title } = Typography;
export function RuntimeDetectionSettingsSubpage() {
    const [riskPolicy, setRiskPolicy] = useState<RuntimeRiskPolicy>();
    const [rules, setRules] = useState<RuntimeSettingsPage<RuntimeRule>>();
    const [types, setTypes] = useState<RuntimeSettingsPage<RuntimeTypeRow>>();
    const [ruleQuery, setRuleQuery] = useState<RuntimeSettingsQuery>({ page: 1, page_size: 5, enabled: "all" });
    const [typeQuery, setTypeQuery] = useState<RuntimeSettingsQuery>({ page: 1, page_size: 10, enabled: "all", risk_policy: "all" });
    const [tick, setTick] = useState(0);
    const [loadingRules, setLoadingRules] = useState(false);
    const [loadingTypes, setLoadingTypes] = useState(false);
    const [errors, setErrors] = useState<Record<string, string>>({});
    const [editor, setEditor] = useState<{
        rule?: RuntimeRule;
    }>();
    const [typeId, setTypeId] = useState<number>();
    const [mutating, setMutating] = useState<number>();
    const [job, setJob] = useState<StaticResourceScanAccepted>();
    const [jobError, setJobError] = useState("");
    const [pollRetry, setPollRetry] = useState(0);
    const ruleRequest = useRef(0), typeRequest = useRef(0);
    const reportError = useCallback((key: string, value: string) => setErrors(old => ({ ...old, [key]: value })), []);
    const refresh = useCallback(() => setTick(old => old + 1), []);
    useEffect(() => {
        let current = true;
        void Promise.allSettled([getGlobalRuntimeRiskPolicy()]).then(([risk]) => {
            if (!current)
                return;
            if (risk.status === "fulfilled") {
                setRiskPolicy(risk.value);
                reportError("risk", "");
            }
            else
                reportError("risk", errorText(risk.reason));
        });
        return () => { current = false; };
    }, [tick, reportError]);
    useEffect(() => {
        const id = ++ruleRequest.current;
        setLoadingRules(true);
        void getRuntimeRules(ruleQuery).then(value => { if (id === ruleRequest.current) {
            setRules(value);
            reportError("rules", "");
        } }).catch(error => { if (id === ruleRequest.current)
            reportError("rules", errorText(error)); }).finally(() => { if (id === ruleRequest.current)
            setLoadingRules(false); });
        return () => { ruleRequest.current++; };
    }, [ruleQuery, tick, reportError]);
    useEffect(() => {
        const id = ++typeRequest.current;
        setLoadingTypes(true);
        void getRuntimeTypes(typeQuery).then(value => { if (id === typeRequest.current) {
            setTypes(value);
            reportError("types", "");
        } }).catch(error => { if (id === typeRequest.current)
            reportError("types", errorText(error)); }).finally(() => { if (id === typeRequest.current)
            setLoadingTypes(false); });
        return () => { typeRequest.current++; };
    }, [typeQuery, tick, reportError]);
    const jobId = job?.job_id ?? job?.scan_id;
    const jobRunning = !!job && ["queued", "running"].includes(job.status);
    useEffect(() => {
        if (!jobId || !jobRunning)
            return;
        let cancelled = false;
        let timer: ReturnType<typeof setTimeout> | undefined;
        const poll = async () => {
            try {
                const value = await getScanStatus(jobId);
                if (cancelled)
                    return;
                setJob(value);
                setJobError("");
                if (["queued", "running"].includes(value.status))
                    timer = setTimeout(() => void poll(), 1500);
                else
                    refresh();
            }
            catch (error) {
                if (!cancelled)
                    setJobError(errorText(error));
            }
        };
        void poll();
        return () => { cancelled = true; clearTimeout(timer); };
    }, [jobId, jobRunning, pollRetry, refresh]);
    const mutate = async (rule: RuntimeRule, operation: () => Promise<unknown>) => {
        setMutating(rule.id);
        reportError("mutation", "");
        try {
            await operation();
            refresh();
            message.success("规则已保存；新配置影响后续事件，历史数据需显式重放");
        }
        catch (error) {
            reportError("mutation", errorText(error));
        }
        finally {
            setMutating(undefined);
        }
    };
    const visibleErrors = [...new Set(Object.values(errors).filter(Boolean))];
    return <div className="runtime-settings">
    <div className="runtime-section-heading"><div><Text className="eyebrow">ANOMALY DETECTION SETTINGS</Text><Title level={3}>异常检测设置</Title><Text type="secondary">维护通用规则、只读风险策略，以及不同 AgentType 的专属规则与黑名单。</Text></div><Button icon={<ReloadOutlined />} onClick={refresh}>刷新数据</Button></div>
    {visibleErrors.length > 0 && <Alert type="error" showIcon title="部分配置读取或保存失败" description={visibleErrors.join("；")} action={<Button onClick={refresh}>重试</Button>}/>}
    <Card className="runtime-main-card" title={<div><strong>通用异常检测配置</strong><p className="runtime-muted">管理通用规则；通用风险判定规则只读展示。</p></div>}>
      <div className="runtime-global-columns">
        <div className="runtime-rule-panel">
          <div className="runtime-toolbar"><strong>通用异常检测规则</strong><Button type="primary" icon={<PlusOutlined />} onClick={() => setEditor({})}>新增规则</Button></div>
          <Space wrap className="runtime-filters">
            <Input.Search allowClear placeholder="搜索规则 / 类型 / 分类" onSearch={keyword => setRuleQuery(old => ({ ...old, keyword, page: 1 }))} className="governance-search-compact"/>
            <Select aria-label="通用规则状态" value={ruleQuery.enabled} options={enabledOptions} onChange={enabled => setRuleQuery(old => ({ ...old, enabled, page: 1 }))}/>
            <Select aria-label="规则来源" value={ruleQuery.source ?? "all"} options={[{ value: "all", label: "全部来源" }, { value: "builtin", label: "内置规则" }, { value: "custom", label: "自定义" }]} onChange={source => setRuleQuery(old => ({ ...old, source: source === "all" ? undefined : source as "builtin" | "custom", page: 1 }))}/>
          </Space>
          <Table<RuntimeRule> rowKey="id" size="small" loading={loadingRules} dataSource={rules?.items ?? []} scroll={{ x: 760 }} pagination={{ current: ruleQuery.page, pageSize: ruleQuery.page_size, total: rules?.total ?? 0, showSizeChanger: true, pageSizeOptions: [5, 10, 20, 50], showTotal: total => `共 ${total} 条`, onChange: (page, page_size) => setRuleQuery(old => ({ ...old, page: page_size !== old.page_size ? 1 : page, page_size })) }} columns={[
            { title: "规则名称", dataIndex: "rule_name", width: 190, render: (value, r) => <div><strong>{value}</strong><div className="runtime-muted">{r.source === "builtin" ? "内置" : "自定义"} · v{r.version}</div></div> },
            { title: "检测类型", dataIndex: "detection_type", width: 180, render: value => <span className="runtime-wrap">{value}</span> },
            { title: "分类", dataIndex: "category", width: 96, render: value => <Tag>{value}</Tag> },
            { title: "严重级别", dataIndex: "severity", width: 112, render: riskTag },
            { title: "状态", width: 68, render: (_, r) => <Switch size="small" checked={r.enabled} loading={mutating === r.id} disabled={mutating !== undefined} onChange={enabled => void mutate(r, () => patchRuntimeRule(r.id, { enabled, version: r.version }))}/> },
            { title: "操作", width: 110, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setEditor({ rule: r })}>编辑</Button><Popconfirm title={r.system ? "禁用此内置规则？" : "删除此自定义规则？"} description={r.system ? "内置算法保留，可再次启用。" : undefined} onConfirm={() => mutate(r, () => deleteRuntimeRule(r.id))}><Button type="link" danger size="small" disabled={mutating !== undefined}>{r.system ? "禁用" : "删除"}</Button></Popconfirm></Space> },
        ]}/>
        </div>
        <div className="runtime-risk-panel"><div className="runtime-toolbar"><strong>通用风险判定规则</strong><Tag>只读展示</Tag></div><p className="runtime-muted">默认分值区间与决策映射。</p>
          {riskPolicy?.rules.map(row => <div className="runtime-risk-row" key={row.risk_level}>{riskTag(row.risk_level)}<span>{row.min_score.toFixed(2)} – {row.max_score.toFixed(2)}</span><Tag color={row.decision === "BLOCK" ? "red" : row.decision === "CONFIRM" ? "orange" : "blue"}>{row.display_decision}</Tag></div>)}
          {!riskPolicy && <Text type="secondary">{errors.risk ? "风险策略暂不可用" : "正在读取风险策略…"}</Text>}
        </div>
      </div>
    </Card>
    <Card className="runtime-main-card" title={<div><strong>AgentType 专属配置列表</strong><p className="runtime-muted">为不同类型 Agent 配置专属规则、黑名单与风险判定方式。</p></div>} extra={<Button icon={<ReloadOutlined />} onClick={() => setTypeQuery(old => ({ ...old }))}>刷新列表</Button>}>
      <Space wrap className="runtime-filters">
        <Input.Search allowClear placeholder="搜索 AgentType / 厂商 / 运行时" className="governance-search-agent-type" onSearch={keyword => setTypeQuery(old => ({ ...old, keyword, page: 1 }))}/>
        <Select aria-label="AgentType 检测状态" value={typeQuery.enabled} options={enabledOptions} onChange={enabled => setTypeQuery(old => ({ ...old, enabled, page: 1 }))}/>
        <Select aria-label="继承通用规则筛选" value={typeQuery.inherit_global_rules ?? "all"} options={[{ value: "all", label: "全部继承方式" }, { value: "true", label: "继承通用规则" }, { value: "false", label: "不继承" }]} onChange={inherit_global_rules => setTypeQuery(old => ({ ...old, inherit_global_rules, page: 1 }))}/>
        <Select aria-label="风险策略筛选" value={typeQuery.risk_policy} options={[{ value: "all", label: "全部风险策略" }, { value: "global", label: "通用策略" }, { value: "custom", label: "自定义策略" }]} onChange={risk_policy => setTypeQuery(old => ({ ...old, risk_policy, page: 1 }))}/>
      </Space>
      <Table<RuntimeTypeRow> rowKey="agent_type_id" loading={loadingTypes} dataSource={types?.items ?? []} scroll={{ x: 960 }} pagination={{ current: typeQuery.page, pageSize: typeQuery.page_size, total: types?.total ?? 0, showSizeChanger: true, showTotal: total => `共 ${total} 个类型`, onChange: (page, page_size) => setTypeQuery(old => ({ ...old, page: old.page_size !== page_size ? 1 : page, page_size })) }} columns={[
            { title: "AgentType", dataIndex: "agent_type_name", render: (value, row) => <div><strong>{value}</strong><div className="runtime-muted">{row.agent_type_key}</div></div> },
            { title: "继承通用检测", dataIndex: "inherit_global_rules", render: value => <Tag color={value ? "blue" : "default"}>{value ? "是" : "否"}</Tag> },
            { title: "专属规则数", dataIndex: "specific_rule_count" }, { title: "黑名单数", dataIndex: "blacklist_count" },
            { title: "风险判定方式", dataIndex: "risk_policy_mode", render: value => <Tag color={value === "custom" ? "orange" : "blue"}>{value === "custom" ? "自定义" : "通用"}</Tag> },
            { title: "状态", dataIndex: "enabled", render: value => <Tag color={value ? "green" : "default"}>{value ? "启用" : "停用"}</Tag> },
            { title: "操作", render: (_, row) => <Button type="primary" ghost onClick={() => setTypeId(row.agent_type_id)}>详情</Button> },
        ]}/>
    </Card>
    {job && <Alert showIcon type={jobError || job.status === "failed" ? "error" : job.status === "completed" ? "success" : "info"} title={`历史重放 · ${{ queued: "排队中", running: "运行中", completed: "完成", failed: "失败", cancelled: "已取消" }[job.status] ?? job.status}`} description={<><Text>任务 {jobId}</Text><Progress percent={job.progress ?? 0} status={job.status === "failed" ? "exception" : undefined}/><div>{jobError || job.error || job.phase}</div></>} action={jobError ? <Button onClick={() => setPollRetry(old => old + 1)}>重新查询</Button> : undefined}/>}
    <RuleEditor open={!!editor} rule={editor?.rule} onClose={() => setEditor(undefined)} onSaved={refresh}/>
    {typeId !== undefined && <RuntimeTypeDialog key={typeId} typeId={typeId} onClose={() => setTypeId(undefined)} onChanged={refresh} onReplay={value => { setJob(value); setJobError(""); }}/>}
  </div>;
}
const riskOptions = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(value => ({ value, label: value }));
const enabledOptions = [{ value: "all", label: "全部状态" }, { value: "true", label: "启用" }, { value: "false", label: "停用" }];
const matchOptions = [{ value: "exact", label: "完全相等" }, { value: "contains", label: "包含" }, { value: "prefix", label: "前缀" }, { value: "glob", label: "通配符（* / ?）" }, { value: "regex", label: "正则表达式（RE2）" }];
const categoryOptions = [{ value: "attack", label: "攻击 · attack" }, { value: "suspicious", label: "可疑 · suspicious" }, { value: "hygiene", label: "安全卫生 · hygiene" }];
const matcherFields = ["target", "tool_name", "mcp_server", "path", "operation", "detail"] as const;
const conditionOptions = [{ value: "target", label: "操作目标" }, { value: "tool_name", label: "工具名称" }, { value: "mcp_server", label: "MCP 服务" }, { value: "path", label: "文件路径" }, { value: "operation", label: "操作" }, { value: "detail", label: "事件描述" }];
type Condition = RuntimePattern & {
    field: typeof matcherFields[number];
};
type RuleValues = Partial<RuntimeRule> & {
    event_type?: string;
    event_category?: string;
    event_source?: string;
    conditions?: Condition[];
};
const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
function RuleEditor({ open, rule, typeId, onClose, onSaved }: {
    open: boolean;
    rule?: RuntimeRule;
    typeId?: number;
    onClose: () => void;
    onSaved: () => void;
}) {
    const [form] = Form.useForm<RuleValues>();
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    const builtin = rule?.system ?? false;
    const matcher = rule?.matcher;
    const initialValues: RuleValues = {
        category: "suspicious", severity: "MEDIUM", confidence: 0.8, priority: 100, enabled: true, ...rule,
        event_type: matcher?.event_type, event_category: matcher?.event_category, event_source: matcher?.event_source,
        conditions: matcherFields.flatMap(field => matcher?.[field] ? [{ field, ...matcher[field]! }] : []),
    };
    useEffect(() => {
        if (!open)
            return;
        form.resetFields();
        setError("");
    }, [open, rule, form]);
    const save = async () => {
        let values: RuleValues;
        try {
            values = await form.validateFields();
        }
        catch {
            return;
        }
        setBusy(true);
        setError("");
        try {
            const { conditions = [], event_type, event_category, event_source, ...fields } = values;
            let matcher: RuntimeMatcher | undefined;
            if (!builtin) {
                if (!event_type && !event_category && !event_source && !conditions.length)
                    throw new Error("请填写至少一个事件条件或匹配条件。");
                if (new Set(conditions.map(c => c.field)).size !== conditions.length)
                    throw new Error("同一个字段只能设置一个匹配条件。");
                matcher = { kind: "event_match", event_type: event_type || undefined, event_category: event_category || undefined, event_source: event_source || undefined };
                for (const condition of conditions)
                    matcher[condition.field] = { match_type: condition.match_type, value: condition.value };
            }
            const body = { ...fields, ...(matcher ? { matcher } : {}), ...(rule ? { version: rule.version } : {}) };
            if (rule)
                await patchRuntimeRule(rule.id, body, typeId);
            else
                await createRuntimeRule(body, typeId);
            onSaved();
            onClose();
        }
        catch (failure) {
            setError(errorText(failure));
        }
        finally {
            setBusy(false);
        }
    };
    return <Modal title={rule ? "编辑异常检测规则" : "新增异常检测规则"} open={open} onCancel={() => !busy && onClose()} onOk={() => void save()} confirmLoading={busy} okText="保存规则" cancelText="取消" width={780} destroyOnHidden maskClosable={!busy}>
    {error && <Alert type="error" showIcon title="规则未保存" description={error}/>}
    {builtin && <Alert type="info" showIcon title="内置规则" description="可调整启用状态、严重度、置信度、优先级和处置说明。规则身份与匹配算法由系统维护；修改严重度或置信度后，该字段将覆盖内置动态判定。"/>}
    <Form form={form} initialValues={initialValues} layout="vertical" preserve={false} className="runtime-editor-form">
      <div className="runtime-form-grid">
        <Form.Item name="rule_name" label="规则名称" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} maxLength={256}/></Form.Item>
        <Form.Item name="rule_id" label="规则标识" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} maxLength={128}/></Form.Item>
        <Form.Item name="detection_type" label="检测类型" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} placeholder="如 dangerous_command" maxLength={128}/></Form.Item>
        <Form.Item name="category" label="分类" rules={[{ required: true }]}><Select disabled={builtin} options={categoryOptions}/></Form.Item>
        <Form.Item name="severity" label="严重级别" rules={[{ required: true }]}><Select options={riskOptions}/></Form.Item>
        <Form.Item name="confidence" label="置信度" rules={[{ required: true }]}><InputNumber min={0} max={1} step={0.01} className="governance-full-width"/></Form.Item>
        <Form.Item name="priority" label="优先级（数值越小越先执行）" rules={[{ required: true }]}><InputNumber min={0} max={100000} precision={0}/></Form.Item>
        <Form.Item name="enabled" label="启用规则" valuePropName="checked"><Switch /></Form.Item>
      </div>
      {!builtin && <>
        <div className="runtime-form-grid">
          <Form.Item name="event_type" label="事件类型"><Input placeholder="如 tool.pre_call；留空匹配全部"/></Form.Item>
          <Form.Item name="event_category" label="事件分类"><Select allowClear options={["tool", "file", "network", "process", "prompt", "content", "lifecycle"].map(value => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="event_source" label="事件来源"><Select allowClear options={["agent_hook", "guardrail", "proxy", "os-sensor", "desktop-behavior"].map(value => ({ value, label: value }))}/></Form.Item>
        </div>
        <p className="runtime-muted">所有已填写条件必须同时满足。通配符 * 可跨目录，? 匹配一个字符；匹配区分大小写。</p>
        <Form.List name="conditions">{(fields, { add, remove }) => <>
          {fields.map(field => <div className="runtime-condition" key={field.key}>
            <Form.Item name={[field.name, "field"]} rules={[{ required: true, message: "选择字段" }]}><Select placeholder="匹配字段" options={conditionOptions}/></Form.Item>
            <Form.Item name={[field.name, "match_type"]} rules={[{ required: true, message: "选择方式" }]}><Select options={matchOptions}/></Form.Item>
            <Form.Item name={[field.name, "value"]} rules={[{ required: true, message: "填写匹配内容" }]}><Input placeholder="匹配内容" maxLength={1024}/></Form.Item>
            <Button aria-label="删除匹配条件" icon={<DeleteOutlined />} onClick={() => remove(field.name)}/>
          </div>)}
          <Button icon={<PlusOutlined />} onClick={() => add({ field: "target", match_type: "contains", value: "" })}>添加匹配条件</Button>
        </>}</Form.List>
      </>}
      <Form.Item name="detail" label="检测说明"><Input.TextArea rows={2} maxLength={8192}/></Form.Item>
      <Form.Item name="remediation" label="处置建议"><Input.TextArea rows={2} maxLength={8192}/></Form.Item>
    </Form>
  </Modal>;
}
function BlacklistEditor({ open, item, typeId, onClose, onSaved }: {
    open: boolean;
    item?: RuntimeBlacklist;
    typeId: number;
    onClose: () => void;
    onSaved: () => void;
}) {
    const [form] = Form.useForm<Partial<RuntimeBlacklist>>();
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState("");
    useEffect(() => {
        if (!open)
            return;
        setError("");
        form.resetFields();
    }, [open, item, form]);
    const save = async () => {
        let values: Partial<RuntimeBlacklist>;
        try {
            values = await form.validateFields();
        }
        catch {
            return;
        }
        setBusy(true);
        setError("");
        try {
            if (item)
                await patchRuntimeBlacklist(typeId, item.id, { ...values, version: item.version });
            else
                await createRuntimeBlacklist(typeId, values);
            onSaved();
            onClose();
        }
        catch (failure) {
            setError(errorText(failure));
        }
        finally {
            setBusy(false);
        }
    };
    return <Modal title={item ? "编辑黑名单" : "新增黑名单"} open={open} onCancel={() => !busy && onClose()} onOk={() => void save()} confirmLoading={busy} okText="保存黑名单" cancelText="取消" width={660} destroyOnHidden maskClosable={!busy}>
    {error && <Alert type="error" showIcon title="黑名单未保存" description={error}/>}
    <Form form={form} initialValues={{ target_type: "command", match_type: "contains", category: "attack", detection_type: "blacklist_match", severity: "HIGH", confidence: 0.9, priority: 50, enabled: true, ...item }} layout="vertical" preserve={false} className="runtime-editor-form">
      <div className="runtime-form-grid">
        <Form.Item name="target_type" label="目标类型" rules={[{ required: true }]}><Select options={["command", "path", "tool", "mcp", "domain", "url", "process"].map(value => ({ value, label: value }))}/></Form.Item>
        <Form.Item name="match_type" label="匹配方式" rules={[{ required: true }]}><Select options={matchOptions}/></Form.Item>
      </div>
      <Form.Item name="value" label="匹配内容" rules={[{ required: true }]} extra="域名按小写主机名匹配，不含协议和端口。通配符支持 * 和 ?。"><Input maxLength={1024}/></Form.Item>
      <div className="runtime-form-grid">
        <Form.Item name="detection_type" label="检测类型" rules={[{ required: true }]}><Input maxLength={128}/></Form.Item>
        <Form.Item name="category" label="分类" rules={[{ required: true }]}><Select options={categoryOptions}/></Form.Item>
        <Form.Item name="severity" label="严重级别" rules={[{ required: true }]}><Select options={riskOptions}/></Form.Item>
        <Form.Item name="confidence" label="置信度" rules={[{ required: true }]}><InputNumber min={0} max={1} step={0.01}/></Form.Item>
        <Form.Item name="priority" label="优先级" rules={[{ required: true }]}><InputNumber min={0} max={100000} precision={0}/></Form.Item>
        <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
      </div>
      <Form.Item name="reason" label="原因与说明"><Input.TextArea rows={3} maxLength={8192}/></Form.Item>
    </Form>
  </Modal>;
}
const riskTag = (level: string) => <Tag color={({ LOW: "green", MEDIUM: "gold", HIGH: "orange", CRITICAL: "red" } as Record<string, string>)[level] ?? "default"}>{level}</Tag>;
const decisions = [{ value: "ALLOW", label: "ALLOW" }, { value: "ALERT", label: "ALERT" }, { value: "CONFIRM", label: "ASK" }, { value: "BLOCK", label: "BLOCK" }];
function validateRiskRows(rows: RuntimeRiskPolicyRule[]) {
    let next = 0;
    const sorted = [...rows].sort((a, b) => a.min_score - b.min_score);
    for (const row of sorted) {
        if (!Number.isFinite(row.min_score) || !Number.isFinite(row.max_score) || row.min_score < 0 || row.max_score > 1 || row.min_score > row.max_score)
            throw new Error("风险分数必须在 0～1 之间，最小值不得大于最大值。");
        if (Math.abs(row.min_score * 100 - Math.round(row.min_score * 100)) > 1e-8 || Math.abs(row.max_score * 100 - Math.round(row.max_score * 100)) > 1e-8)
            throw new Error("风险区间最多保留两位小数。");
        if (Math.round(row.min_score * 100) !== next)
            throw new Error("风险区间须完整覆盖 0.00～1.00，不得交叉或留空。相邻区间相差 0.01。");
        next = Math.round(row.max_score * 100) + 1;
    }
    if (rows.length !== 4 || next !== 101)
        throw new Error("请完整配置四个风险等级。");
}
function RuntimeTypeDialog({ typeId, onClose, onChanged, onReplay }: {
    typeId: number;
    onClose: () => void;
    onChanged: () => void;
    onReplay: (job: StaticResourceScanAccepted) => void;
}) {
    const [detail, setDetail] = useState<RuntimeTypeDetail>();
    const [draft, setDraft] = useState<RuntimeTypeSettings>();
    const [riskRows, setRiskRows] = useState<RuntimeRiskPolicyRule[]>([]);
    const [globalRows, setGlobalRows] = useState<RuntimeRiskPolicyRule[]>([]);
    const [riskName, setRiskName] = useState("");
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [error, setError] = useState("");
    const [ruleEditor, setRuleEditor] = useState<{
        rule?: RuntimeRule;
    }>();
    const [blacklistEditor, setBlacklistEditor] = useState<{
        item?: RuntimeBlacklist;
    }>();
    const [mutation, setMutation] = useState("");
    const [ruleKeyword, setRuleKeyword] = useState("");
    const [blacklistKeyword, setBlacklistKeyword] = useState("");
    const [trialEvent, setTrialEvent] = useState('{\n  "event_type": "tool.pre_call",\n  "tool_name": "shell",\n  "target": ""\n}');
    const [trial, setTrial] = useState<RuntimeEvaluation>();
    const [trialBusy, setTrialBusy] = useState(false);
    const requestId = useRef(0);
    const reload = useCallback(async (resetDraft: boolean) => {
        const id = ++requestId.current;
        setLoading(true);
        try {
            const [value, global] = await Promise.all([getRuntimeTypeDetail(typeId), getGlobalRuntimeRiskPolicy()]);
            if (id !== requestId.current)
                return;
            setDetail(value);
            setGlobalRows(global.rules);
            if (resetDraft) {
                setDraft(value.settings);
                const custom = value.risk_policy.custom_policy ?? value.risk_policy.policy;
                setRiskRows((custom ?? value.risk_policy.effective_policy).rules.map(row => ({ ...row })));
                setRiskName(custom?.name ?? `${value.agent_type.agent_type_name} 风险策略`);
            }
        }
        catch (failure) {
            if (id === requestId.current)
                setError(errorText(failure));
        }
        finally {
            if (id === requestId.current)
                setLoading(false);
        }
    }, [typeId]);
    useEffect(() => { void reload(true); return () => { requestId.current++; }; }, [reload]);
    const changed = () => { void reload(false); onChanged(); setTrial(undefined); };
    const mutate = async (key: string, work: () => Promise<unknown>) => {
        setMutation(key);
        setError("");
        try {
            await work();
            changed();
        }
        catch (failure) {
            setError(errorText(failure));
        }
        finally {
            setMutation("");
        }
    };
    const save = async (replay: boolean) => {
        if (!draft || !detail)
            return;
        setError("");
        try {
            if (!draft.use_global_risk_policy) {
                validateRiskRows(riskRows);
                if (!riskName.trim())
                    throw new Error("请填写自定义风险策略名称。");
            }
        }
        catch (failure) {
            setError(errorText(failure));
            return;
        }
        setSaving(true);
        let policySaved = false;
        let settingsSaved = false;
        try {
            await saveRuntimeRiskPolicy(typeId, draft.use_global_risk_policy, draft.use_global_risk_policy ? undefined : { name: riskName, rules: riskRows });
            policySaved = true;
            await patchRuntimeTypeSettings(typeId, { enabled: draft.enabled, inherit_global_rules: draft.inherit_global_rules, use_global_risk_policy: draft.use_global_risk_policy });
            settingsSaved = true;
            onChanged();
            await reload(true);
            if (replay) {
                const job = await createRuntimeEventReplay({ agentTypeId: typeId });
                if (!job.job_id && !job.scan_id)
                    throw new Error("网关未返回重放任务 ID");
                onReplay(job);
                message.success("配置已保存，已创建当前 AgentType 的历史重放任务");
            }
            else
                message.success("配置已保存，将影响后续事件；历史数据需显式重放");
        }
        catch (failure) {
            setError(`${settingsSaved ? "配置已保存，但重放创建失败。" : policySaved ? "风险策略已保存，但基础设置保存失败，请重试。" : "配置未保存。"}${errorText(failure)}`);
        }
        finally {
            setSaving(false);
        }
    };
    const evaluate = async () => {
        setTrialBusy(true);
        setError("");
        setTrial(undefined);
        try {
            const event: unknown = JSON.parse(trialEvent);
            if (!event || Array.isArray(event) || typeof event !== "object")
                throw new Error("试算事件必须是 JSON 对象。");
            setTrial(await evaluateRuntimeEvent(typeId, event as Record<string, unknown>));
        }
        catch (failure) {
            setError(errorText(failure));
        }
        finally {
            setTrialBusy(false);
        }
    };
    const rows = detail?.specific_rules.filter(r => `${r.rule_name} ${r.rule_id}`.toLowerCase().includes(ruleKeyword.toLowerCase())) ?? [];
    const blacklist = detail?.blacklist.filter(r => `${r.value} ${r.reason}`.toLowerCase().includes(blacklistKeyword.toLowerCase())) ?? [];
    return <>
    <Modal open onCancel={() => !saving && onClose()} width="min(1360px, 94vw)" className="runtime-type-dialog" title={<div><strong>{detail?.agent_type.agent_type_name ?? "AgentType"} 专属异常检测配置</strong><p className="runtime-muted">维护专属规则、黑名单与风险判定方式。</p></div>} footer={<Space><Button disabled={saving} onClick={onClose}>取消</Button><Button loading={saving} disabled={!draft || !!mutation} onClick={() => void save(false)}>保存</Button><Button type="primary" loading={saving} disabled={!draft || !!mutation} onClick={() => void save(true)}>保存并重放</Button></Space>} maskClosable={!saving}>
      <Spin spinning={loading}>
        {error && <Alert type="error" showIcon title="操作未完成" description={error} action={<Button size="small" onClick={() => { setError(""); void reload(!draft); }}>重新读取</Button>}/>}
        <Alert className="runtime-effective-explanation" type="info" title="最终生效规则 = 继承的通用规则 + 专属规则 + 黑名单" description="关闭继承后仅使用专属规则和黑名单。专属规则、黑名单逐项保存；上方开关与风险区间通过底部按钮保存。"/>
        {draft && detail && <>
          <div className="runtime-toggle-grid">
            {([["enabled", "启用异常检测", "关闭后不产生新的异常检测"], ["inherit_global_rules", "继承通用异常检测规则", "在通用规则基础上补充专属规则"], ["use_global_risk_policy", "使用通用风险判定规则", "关闭后可编辑自定义风险策略"]] as const).map(([key, title, help]) => <div className="runtime-toggle" key={key}><div><strong>{title}</strong><p>{help}</p></div><Switch checked={draft[key]} disabled={saving} onChange={checked => setDraft({ ...draft, [key]: checked })}/></div>)}
          </div>
          <div className="runtime-dialog-columns">
            <Card title="① 专属异常检测规则" extra={<Button icon={<PlusOutlined />} onClick={() => setRuleEditor({})}>新增规则</Button>}>
              <Input.Search allowClear placeholder="搜索规则" onSearch={setRuleKeyword}/>
              <Table<RuntimeRule> size="small" rowKey="id" dataSource={rows} pagination={{ pageSize: 5, hideOnSinglePage: true }} scroll={{ x: 530 }} columns={[
                { title: "规则", dataIndex: "rule_name", render: (_, r) => <div><strong>{r.rule_name}</strong><div className="runtime-muted">{r.detection_type}</div></div> },
                { title: "严重级别", dataIndex: "severity", width: 112, render: riskTag },
                { title: "状态", width: 66, render: (_, r) => <Switch size="small" checked={r.enabled} disabled={!!mutation} loading={mutation === `rule-${r.id}`} onChange={enabled => void mutate(`rule-${r.id}`, () => patchRuntimeRule(r.id, { enabled, version: r.version }, typeId))}/> },
                { title: "操作", width: 105, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setRuleEditor({ rule: r })}>编辑</Button><Popconfirm title="删除该专属规则？" onConfirm={() => mutate(`rule-${r.id}`, () => deleteRuntimeRule(r.id, typeId))}><Button type="link" danger size="small" disabled={!!mutation}>删除</Button></Popconfirm></Space> },
            ]}/>
            </Card>
            <Card title="② 黑名单" extra={<Button icon={<PlusOutlined />} onClick={() => setBlacklistEditor({})}>新增黑名单</Button>}>
              <Input.Search allowClear placeholder="搜索匹配内容或原因" onSearch={setBlacklistKeyword}/>
              <Table<RuntimeBlacklist> size="small" rowKey="id" dataSource={blacklist} pagination={{ pageSize: 5, hideOnSinglePage: true }} scroll={{ x: 530 }} columns={[
                { title: "类型", dataIndex: "target_type", width: 84, render: value => <Tag>{value}</Tag> },
                { title: "匹配内容", dataIndex: "value", render: (value, r) => <div className="runtime-wrap">{value}<div className="runtime-muted">{r.match_type}</div></div> },
                { title: "风险", dataIndex: "severity", width: 108, render: riskTag },
                { title: "启用", width: 60, render: (_, r) => <Switch size="small" checked={r.enabled} disabled={!!mutation} onChange={enabled => void mutate(`blacklist-${r.id}`, () => patchRuntimeBlacklist(typeId, r.id, { enabled, version: r.version }))}/> },
                { title: "操作", width: 105, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setBlacklistEditor({ item: r })}>编辑</Button><Popconfirm title="删除该黑名单项？" onConfirm={() => mutate(`blacklist-${r.id}`, () => deleteRuntimeBlacklist(typeId, r.id))}><Button type="link" danger size="small" disabled={!!mutation}>删除</Button></Popconfirm></Space> },
            ]}/>
            </Card>
          </div>
          <div className="runtime-risk-bottom">
            <Card title="③ 风险判定方式" extra={<Tag color={draft.use_global_risk_policy ? "blue" : "orange"}>{draft.use_global_risk_policy ? "通用策略" : "自定义策略"}</Tag>}>
              {!draft.use_global_risk_policy && <Input aria-label="风险策略名称" value={riskName} onChange={e => setRiskName(e.target.value)} maxLength={256}/>}
              <p className="runtime-muted">分数按两位小数判定；区间完整覆盖 0～1。ASK 对应后端 CONFIRM。</p>
              {(draft.use_global_risk_policy ? globalRows : riskRows).map((row, index) => <div className="runtime-risk-edit-row" key={row.risk_level}>
                {riskTag(row.risk_level)}
                <InputNumber aria-label={`${row.risk_level} 最低分`} value={row.min_score} min={0} max={1} step={0.01} precision={2} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, min_score: value ?? NaN } : r))}/>
                <span>～</span>
                <InputNumber aria-label={`${row.risk_level} 最高分`} value={row.max_score} min={0} max={1} step={0.01} precision={2} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, max_score: value ?? NaN } : r))}/>
                <span>→</span>
                <Select aria-label={`${row.risk_level} 决策`} value={row.decision} options={decisions} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, decision: value } : r))}/>
              </div>)}
              {draft.use_global_risk_policy !== detail.settings.use_global_risk_policy && <Text type="secondary">策略切换在保存后生效；保存后重新读取对应风险区间。</Text>}
            </Card>
            <Card title="已保存的有效配置" extra={<Button aria-label="刷新有效配置" icon={<ReloadOutlined />} onClick={() => void reload(false)}/>}>
              {[["通用规则", detail.effective_summary.global_rule_count], ["专属规则", detail.effective_summary.specific_rule_count], ["黑名单规则", detail.effective_summary.blacklist_count], ["合计", detail.effective_summary.effective_rule_count]].map(([label, value]) => <div className="runtime-effective-count" key={label}><span>{label}</span><strong>{value}</strong></div>)}
              <Text type="secondary">待保存的更改不会计入此处。</Text>
            </Card>
          </div>
          <Card title="事件试算" extra={<Button loading={trialBusy} onClick={() => void evaluate()}>使用已保存配置试算</Button>}>
            <p className="runtime-muted">输入一个事件，检查匹配规则与风险决策。试算不会保存事件、生成检测记录或执行阻断。</p>
            <Input.TextArea aria-label="试算事件 JSON" rows={5} value={trialEvent} onChange={event => setTrialEvent(event.target.value)}/>
            {trial && <Alert className="governance-trial-result" type={trial.matched ? "warning" : "success"} showIcon title={trial.matched ? `命中 ${trial.matched_rules.length} 条规则 · ${trial.risk_level} · ${trial.risk_score.toFixed(2)} · ${trial.decision === "CONFIRM" ? "ASK" : trial.decision}` : "未命中规则"} description={trial.matched_rules.map(r => `${r.rule_id} (${r.source}, ${r.severity})`).join("；")}/>}
          </Card>
        </>}
      </Spin>
    </Modal>
    <RuleEditor open={!!ruleEditor} rule={ruleEditor?.rule} typeId={typeId} onClose={() => setRuleEditor(undefined)} onSaved={changed}/>
    <BlacklistEditor open={!!blacklistEditor} item={blacklistEditor?.item} typeId={typeId} onClose={() => setBlacklistEditor(undefined)} onSaved={changed}/>
  </>;
}
