import { useCallback, useEffect, useRef, useState } from "react";
import { Alert, Button, Card, Input, InputNumber, Modal, Popconfirm, Select, Space, Spin, Switch, Table, Tag, Typography, message } from "antd";
import { PlusOutlined, ReloadOutlined } from "@ant-design/icons";
import { createRuntimeEventReplay } from "../bridge";
import type { StaticResourceScanAccepted } from "../types";
import { deleteRuntimeBlacklist, deleteRuntimeRule, evaluateRuntimeEvent, getGlobalRuntimeRiskPolicy, getRuntimeTypeDetail, patchRuntimeBlacklist, patchRuntimeRule, patchRuntimeTypeSettings, saveRuntimeRiskPolicy } from "./api";
import { BlacklistEditor, RuleEditor, errorText } from "./Editors";
import type { RuntimeBlacklist, RuntimeEvaluation, RuntimeRiskPolicyRule, RuntimeRule, RuntimeTypeDetail, RuntimeTypeSettings } from "./types";

const { Text } = Typography;
export const riskTag = (level: string) => <Tag color={({ LOW: "green", MEDIUM: "gold", HIGH: "orange", CRITICAL: "red" } as Record<string, string>)[level] ?? "default"}>{level}</Tag>;
const decisions = [{ value: "ALLOW", label: "ALLOW" }, { value: "ALERT", label: "ALERT" }, { value: "CONFIRM", label: "ASK" }, { value: "BLOCK", label: "BLOCK" }];
function validateRiskRows(rows: RuntimeRiskPolicyRule[]) {
  let next = 0;
  const sorted = [...rows].sort((a, b) => a.min_score - b.min_score);
  for (const row of sorted) {
    if (!Number.isFinite(row.min_score) || !Number.isFinite(row.max_score) || row.min_score < 0 || row.max_score > 1 || row.min_score > row.max_score) throw new Error("风险分数必须在 0～1 之间，最小值不得大于最大值。");
    if (Math.abs(row.min_score * 100 - Math.round(row.min_score * 100)) > 1e-8 || Math.abs(row.max_score * 100 - Math.round(row.max_score * 100)) > 1e-8) throw new Error("风险区间最多保留两位小数。");
    if (Math.round(row.min_score * 100) !== next) throw new Error("风险区间须完整覆盖 0.00～1.00，不得交叉或留空。相邻区间相差 0.01。");
    next = Math.round(row.max_score * 100) + 1;
  }
  if (rows.length !== 4 || next !== 101) throw new Error("请完整配置四个风险等级。");
}

export function RuntimeTypeDialog({ typeId, onClose, onChanged, onReplay }: { typeId: number; onClose: () => void; onChanged: () => void; onReplay: (job: StaticResourceScanAccepted) => void }) {
  const [detail, setDetail] = useState<RuntimeTypeDetail>();
  const [draft, setDraft] = useState<RuntimeTypeSettings>();
  const [riskRows, setRiskRows] = useState<RuntimeRiskPolicyRule[]>([]);
  const [globalRows, setGlobalRows] = useState<RuntimeRiskPolicyRule[]>([]);
  const [riskName, setRiskName] = useState("");
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [ruleEditor, setRuleEditor] = useState<{ rule?: RuntimeRule }>();
  const [blacklistEditor, setBlacklistEditor] = useState<{ item?: RuntimeBlacklist }>();
  const [mutation, setMutation] = useState("");
  const [ruleKeyword, setRuleKeyword] = useState("");
  const [blacklistKeyword, setBlacklistKeyword] = useState("");
  const [trialEvent, setTrialEvent] = useState('{\n  "event_type": "tool.pre_call",\n  "tool_name": "shell",\n  "target": ""\n}');
  const [trial, setTrial] = useState<RuntimeEvaluation>();
  const [trialBusy, setTrialBusy] = useState(false);
  const requestId = useRef(0);
  const reload = useCallback(async (resetDraft: boolean) => {
    const id = ++requestId.current; setLoading(true);
    try {
      const [value, global] = await Promise.all([getRuntimeTypeDetail(typeId), getGlobalRuntimeRiskPolicy()]);
      if (id !== requestId.current) return;
      setDetail(value);
      setGlobalRows(global.rules);
      if (resetDraft) {
        setDraft(value.settings);
        const custom = value.risk_policy.custom_policy ?? value.risk_policy.policy;
        setRiskRows((custom ?? value.risk_policy.effective_policy).rules.map(row => ({ ...row })));
        setRiskName(custom?.name ?? `${value.agent_type.agent_type_name} 风险策略`);
      }
    } catch (failure) { if (id === requestId.current) setError(errorText(failure)); }
    finally { if (id === requestId.current) setLoading(false); }
  }, [typeId]);
  useEffect(() => { void reload(true); return () => { requestId.current++; }; }, [reload]);
  const changed = () => { void reload(false); onChanged(); setTrial(undefined); };
  const mutate = async (key: string, work: () => Promise<unknown>) => {
    setMutation(key); setError("");
    try { await work(); changed(); } catch (failure) { setError(errorText(failure)); } finally { setMutation(""); }
  };
  const save = async (replay: boolean) => {
    if (!draft || !detail) return;
    setError("");
    try { if (!draft.use_global_risk_policy) { validateRiskRows(riskRows); if (!riskName.trim()) throw new Error("请填写自定义风险策略名称。"); } } catch (failure) { setError(errorText(failure)); return; }
    setSaving(true);
    let policySaved = false; let settingsSaved = false;
    try {
      await saveRuntimeRiskPolicy(typeId, draft.use_global_risk_policy, draft.use_global_risk_policy ? undefined : { name: riskName, rules: riskRows });
      policySaved = true;
      await patchRuntimeTypeSettings(typeId, { enabled: draft.enabled, inherit_global_rules: draft.inherit_global_rules, use_global_risk_policy: draft.use_global_risk_policy });
      settingsSaved = true; onChanged(); await reload(true);
      if (replay) {
        const job = await createRuntimeEventReplay({ agentTypeId: typeId });
        if (!job.job_id && !job.scan_id) throw new Error("网关未返回重放任务 ID");
        onReplay(job);
        message.success("配置已保存，已创建当前 AgentType 的历史重放任务");
      } else message.success("配置已保存，将影响后续事件；历史数据需显式重放");
    } catch (failure) {
      setError(`${settingsSaved ? "配置已保存，但重放创建失败。" : policySaved ? "风险策略已保存，但基础设置保存失败，请重试。" : "配置未保存。"}${errorText(failure)}`);
    } finally { setSaving(false); }
  };
  const evaluate = async () => {
    setTrialBusy(true); setError(""); setTrial(undefined);
    try {
      const event: unknown = JSON.parse(trialEvent);
      if (!event || Array.isArray(event) || typeof event !== "object") throw new Error("试算事件必须是 JSON 对象。");
      setTrial(await evaluateRuntimeEvent(typeId, event as Record<string, unknown>));
    } catch (failure) { setError(errorText(failure)); } finally { setTrialBusy(false); }
  };
  const rows = detail?.specific_rules.filter(r => `${r.rule_name} ${r.rule_id}`.toLowerCase().includes(ruleKeyword.toLowerCase())) ?? [];
  const blacklist = detail?.blacklist.filter(r => `${r.value} ${r.reason}`.toLowerCase().includes(blacklistKeyword.toLowerCase())) ?? [];
  return <>
    <Modal open onCancel={() => !saving && onClose()} width="min(1360px, 94vw)" className="runtime-type-dialog" title={<div><strong>{detail?.agent_type.agent_type_name ?? "AgentType"} 专属异常检测配置</strong><p className="runtime-muted">维护专属规则、黑名单与风险判定方式。</p></div>} footer={<Space><Button disabled={saving} onClick={onClose}>取消</Button><Button loading={saving} disabled={!draft || !!mutation} onClick={() => void save(false)}>保存</Button><Button type="primary" loading={saving} disabled={!draft || !!mutation} onClick={() => void save(true)}>保存并重放</Button></Space>} maskClosable={!saving}>
      <Spin spinning={loading}>
        {error && <Alert type="error" showIcon title="操作未完成" description={error} action={<Button size="small" onClick={() => { setError(""); void reload(!draft); }}>重新读取</Button>} />}
        <Alert className="runtime-effective-explanation" type="info" title="最终生效规则 = 继承的通用规则 + 专属规则 + 黑名单" description="关闭继承后仅使用专属规则和黑名单。专属规则、黑名单逐项保存；上方开关与风险区间通过底部按钮保存。" />
        {draft && detail && <>
          <div className="runtime-toggle-grid">
            {([ ["enabled", "启用异常检测", "关闭后不产生新的异常检测"], ["inherit_global_rules", "继承通用异常检测规则", "在通用规则基础上补充专属规则"], ["use_global_risk_policy", "使用通用风险判定规则", "关闭后可编辑自定义风险策略"] ] as const).map(([key, title, help]) => <div className="runtime-toggle" key={key}><div><strong>{title}</strong><p>{help}</p></div><Switch checked={draft[key]} disabled={saving} onChange={checked => setDraft({ ...draft, [key]: checked })} /></div>)}
          </div>
          <div className="runtime-dialog-columns">
            <Card title="① 专属异常检测规则" extra={<Button icon={<PlusOutlined />} onClick={() => setRuleEditor({})}>新增规则</Button>}>
              <Input.Search allowClear placeholder="搜索规则" onSearch={setRuleKeyword} />
              <Table<RuntimeRule> size="small" rowKey="id" dataSource={rows} pagination={{ pageSize: 5, hideOnSinglePage: true }} scroll={{ x: 530 }} columns={[
                { title: "规则", dataIndex: "rule_name", render: (_, r) => <div><strong>{r.rule_name}</strong><div className="runtime-muted">{r.detection_type}</div></div> },
                { title: "严重级别", dataIndex: "severity", width: 112, render: riskTag },
                { title: "状态", width: 66, render: (_, r) => <Switch size="small" checked={r.enabled} disabled={!!mutation} loading={mutation === `rule-${r.id}`} onChange={enabled => void mutate(`rule-${r.id}`, () => patchRuntimeRule(r.id, { enabled, version: r.version }, typeId))} /> },
                { title: "操作", width: 105, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setRuleEditor({ rule: r })}>编辑</Button><Popconfirm title="删除该专属规则？" onConfirm={() => mutate(`rule-${r.id}`, () => deleteRuntimeRule(r.id, typeId))}><Button type="link" danger size="small" disabled={!!mutation}>删除</Button></Popconfirm></Space> },
              ]} />
            </Card>
            <Card title="② 黑名单" extra={<Button icon={<PlusOutlined />} onClick={() => setBlacklistEditor({})}>新增黑名单</Button>}>
              <Input.Search allowClear placeholder="搜索匹配内容或原因" onSearch={setBlacklistKeyword} />
              <Table<RuntimeBlacklist> size="small" rowKey="id" dataSource={blacklist} pagination={{ pageSize: 5, hideOnSinglePage: true }} scroll={{ x: 530 }} columns={[
                { title: "类型", dataIndex: "target_type", width: 84, render: value => <Tag>{value}</Tag> },
                { title: "匹配内容", dataIndex: "value", render: (value, r) => <div className="runtime-wrap">{value}<div className="runtime-muted">{r.match_type}</div></div> },
                { title: "风险", dataIndex: "severity", width: 108, render: riskTag },
                { title: "启用", width: 60, render: (_, r) => <Switch size="small" checked={r.enabled} disabled={!!mutation} onChange={enabled => void mutate(`blacklist-${r.id}`, () => patchRuntimeBlacklist(typeId, r.id, { enabled, version: r.version }))} /> },
                { title: "操作", width: 105, render: (_, r) => <Space size={4}><Button type="link" size="small" onClick={() => setBlacklistEditor({ item: r })}>编辑</Button><Popconfirm title="删除该黑名单项？" onConfirm={() => mutate(`blacklist-${r.id}`, () => deleteRuntimeBlacklist(typeId, r.id))}><Button type="link" danger size="small" disabled={!!mutation}>删除</Button></Popconfirm></Space> },
              ]} />
            </Card>
          </div>
          <div className="runtime-risk-bottom">
            <Card title="③ 风险判定方式" extra={<Tag color={draft.use_global_risk_policy ? "blue" : "orange"}>{draft.use_global_risk_policy ? "通用策略" : "自定义策略"}</Tag>}>
              {!draft.use_global_risk_policy && <Input aria-label="风险策略名称" value={riskName} onChange={e => setRiskName(e.target.value)} maxLength={256} />}
              <p className="runtime-muted">分数按两位小数判定；区间完整覆盖 0～1。ASK 对应后端 CONFIRM。</p>
              {(draft.use_global_risk_policy ? globalRows : riskRows).map((row, index) => <div className="runtime-risk-edit-row" key={row.risk_level}>
                {riskTag(row.risk_level)}
                <InputNumber aria-label={`${row.risk_level} 最低分`} value={row.min_score} min={0} max={1} step={0.01} precision={2} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, min_score: value ?? NaN } : r))} />
                <span>～</span>
                <InputNumber aria-label={`${row.risk_level} 最高分`} value={row.max_score} min={0} max={1} step={0.01} precision={2} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, max_score: value ?? NaN } : r))} />
                <span>→</span>
                <Select aria-label={`${row.risk_level} 决策`} value={row.decision} options={decisions} disabled={draft.use_global_risk_policy || saving} onChange={value => setRiskRows(old => old.map((r, i) => i === index ? { ...r, decision: value } : r))} />
              </div>)}
              {draft.use_global_risk_policy !== detail.settings.use_global_risk_policy && <Text type="secondary">策略切换在保存后生效；保存后重新读取对应风险区间。</Text>}
            </Card>
            <Card title="已保存的有效配置" extra={<Button aria-label="刷新有效配置" icon={<ReloadOutlined />} onClick={() => void reload(false)} />}>
              {[["通用规则", detail.effective_summary.global_rule_count], ["专属规则", detail.effective_summary.specific_rule_count], ["黑名单规则", detail.effective_summary.blacklist_count], ["合计", detail.effective_summary.effective_rule_count]].map(([label, value]) => <div className="runtime-effective-count" key={label}><span>{label}</span><strong>{value}</strong></div>)}
              <Text type="secondary">待保存的更改不会计入此处。</Text>
            </Card>
          </div>
          <Card title="事件试算" extra={<Button loading={trialBusy} onClick={() => void evaluate()}>使用已保存配置试算</Button>}>
            <p className="runtime-muted">输入一个事件，检查匹配规则与风险决策。试算不会保存事件、生成检测记录或执行阻断。</p>
            <Input.TextArea aria-label="试算事件 JSON" rows={5} value={trialEvent} onChange={event => setTrialEvent(event.target.value)} />
            {trial && <Alert style={{ marginTop: 12 }} type={trial.matched ? "warning" : "success"} showIcon title={trial.matched ? `命中 ${trial.matched_rules.length} 条规则 · ${trial.risk_level} · ${trial.risk_score.toFixed(2)} · ${trial.decision === "CONFIRM" ? "ASK" : trial.decision}` : "未命中规则"} description={trial.matched_rules.map(r => `${r.rule_id} (${r.source}, ${r.severity})`).join("；")} />}
          </Card>
        </>}
      </Spin>
    </Modal>
    <RuleEditor open={!!ruleEditor} rule={ruleEditor?.rule} typeId={typeId} onClose={() => setRuleEditor(undefined)} onSaved={changed} />
    <BlacklistEditor open={!!blacklistEditor} item={blacklistEditor?.item} typeId={typeId} onClose={() => setBlacklistEditor(undefined)} onSaved={changed} />
  </>;
}
