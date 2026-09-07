import { useEffect, useState } from "react";
import { Alert, Button, Form, Input, InputNumber, Modal, Select, Switch } from "antd";
import { DeleteOutlined, PlusOutlined } from "@ant-design/icons";
import { createRuntimeBlacklist, createRuntimeRule, patchRuntimeBlacklist, patchRuntimeRule } from "./api";
import type { RuntimeBlacklist, RuntimeMatcher, RuntimePattern, RuntimeRule } from "./types";

export const riskOptions = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].map(value => ({ value, label: value }));
export const enabledOptions = [{ value: "all", label: "全部状态" }, { value: "true", label: "启用" }, { value: "false", label: "停用" }];
export const matchOptions = [{ value: "exact", label: "完全相等" }, { value: "contains", label: "包含" }, { value: "prefix", label: "前缀" }, { value: "glob", label: "通配符（* / ?）" }, { value: "regex", label: "正则表达式（RE2）" }];
const categoryOptions = [{ value: "attack", label: "攻击 · attack" }, { value: "suspicious", label: "可疑 · suspicious" }, { value: "hygiene", label: "安全卫生 · hygiene" }];
const matcherFields = ["target", "tool_name", "mcp_server", "path", "operation", "detail"] as const;
const conditionOptions = [{ value: "target", label: "操作目标" }, { value: "tool_name", label: "工具名称" }, { value: "mcp_server", label: "MCP 服务" }, { value: "path", label: "文件路径" }, { value: "operation", label: "操作" }, { value: "detail", label: "事件描述" }];
type Condition = RuntimePattern & { field: typeof matcherFields[number] };
type RuleValues = Partial<RuntimeRule> & { event_type?: string; event_category?: string; event_source?: string; conditions?: Condition[] };
export const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);

export function RuleEditor({ open, rule, typeId, onClose, onSaved }: { open: boolean; rule?: RuntimeRule; typeId?: number; onClose: () => void; onSaved: () => void }) {
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
    if (!open) return;
    form.resetFields(); setError("");
  }, [open, rule, form]);
  const save = async () => {
    let values: RuleValues;
    try { values = await form.validateFields(); } catch { return; }
    setBusy(true); setError("");
    try {
      const { conditions = [], event_type, event_category, event_source, ...fields } = values;
      let matcher: RuntimeMatcher | undefined;
      if (!builtin) {
        if (!event_type && !event_category && !event_source && !conditions.length) throw new Error("请填写至少一个事件条件或匹配条件。");
        if (new Set(conditions.map(c => c.field)).size !== conditions.length) throw new Error("同一个字段只能设置一个匹配条件。");
        matcher = { kind: "event_match", event_type: event_type || undefined, event_category: event_category || undefined, event_source: event_source || undefined };
        for (const condition of conditions) matcher[condition.field] = { match_type: condition.match_type, value: condition.value };
      }
      const body = { ...fields, ...(matcher ? { matcher } : {}), ...(rule ? { version: rule.version } : {}) };
      if (rule) await patchRuntimeRule(rule.id, body, typeId); else await createRuntimeRule(body, typeId);
      onSaved(); onClose();
    } catch (failure) { setError(errorText(failure)); } finally { setBusy(false); }
  };
  return <Modal title={rule ? "编辑异常检测规则" : "新增异常检测规则"} open={open} onCancel={() => !busy && onClose()} onOk={() => void save()} confirmLoading={busy} okText="保存规则" cancelText="取消" width={780} destroyOnHidden maskClosable={!busy}>
    {error && <Alert type="error" showIcon title="规则未保存" description={error} />}
    {builtin && <Alert type="info" showIcon title="内置规则" description="可调整启用状态、严重度、置信度、优先级和处置说明。规则身份与匹配算法由系统维护；修改严重度或置信度后，该字段将覆盖内置动态判定。" />}
    <Form form={form} initialValues={initialValues} layout="vertical" preserve={false} className="runtime-editor-form">
      <div className="runtime-form-grid">
        <Form.Item name="rule_name" label="规则名称" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} maxLength={256} /></Form.Item>
        <Form.Item name="rule_id" label="规则标识" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} maxLength={128} /></Form.Item>
        <Form.Item name="detection_type" label="检测类型" rules={[{ required: true, whitespace: true }]}><Input disabled={builtin} placeholder="如 dangerous_command" maxLength={128} /></Form.Item>
        <Form.Item name="category" label="分类" rules={[{ required: true }]}><Select disabled={builtin} options={categoryOptions} /></Form.Item>
        <Form.Item name="severity" label="严重级别" rules={[{ required: true }]}><Select options={riskOptions} /></Form.Item>
        <Form.Item name="confidence" label="置信度" rules={[{ required: true }]}><InputNumber min={0} max={1} step={0.01} style={{ width: "100%" }} /></Form.Item>
        <Form.Item name="priority" label="优先级（数值越小越先执行）" rules={[{ required: true }]}><InputNumber min={0} max={100000} precision={0} /></Form.Item>
        <Form.Item name="enabled" label="启用规则" valuePropName="checked"><Switch /></Form.Item>
      </div>
      {!builtin && <>
        <div className="runtime-form-grid">
          <Form.Item name="event_type" label="事件类型"><Input placeholder="如 tool.pre_call；留空匹配全部" /></Form.Item>
          <Form.Item name="event_category" label="事件分类"><Select allowClear options={["tool", "file", "network", "process", "prompt", "content", "lifecycle"].map(value => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="event_source" label="事件来源"><Select allowClear options={["agent_hook", "guardrail", "proxy", "os-sensor", "desktop-behavior"].map(value => ({ value, label: value }))} /></Form.Item>
        </div>
        <p className="runtime-muted">所有已填写条件必须同时满足。通配符 * 可跨目录，? 匹配一个字符；匹配区分大小写。</p>
        <Form.List name="conditions">{(fields, { add, remove }) => <>
          {fields.map(field => <div className="runtime-condition" key={field.key}>
            <Form.Item name={[field.name, "field"]} rules={[{ required: true, message: "选择字段" }]}><Select placeholder="匹配字段" options={conditionOptions} /></Form.Item>
            <Form.Item name={[field.name, "match_type"]} rules={[{ required: true, message: "选择方式" }]}><Select options={matchOptions} /></Form.Item>
            <Form.Item name={[field.name, "value"]} rules={[{ required: true, message: "填写匹配内容" }]}><Input placeholder="匹配内容" maxLength={1024} /></Form.Item>
            <Button aria-label="删除匹配条件" icon={<DeleteOutlined />} onClick={() => remove(field.name)} />
          </div>)}
          <Button icon={<PlusOutlined />} onClick={() => add({ field: "target", match_type: "contains", value: "" })}>添加匹配条件</Button>
        </>}</Form.List>
      </>}
      <Form.Item name="detail" label="检测说明"><Input.TextArea rows={2} maxLength={8192} /></Form.Item>
      <Form.Item name="remediation" label="处置建议"><Input.TextArea rows={2} maxLength={8192} /></Form.Item>
    </Form>
  </Modal>;
}

export function BlacklistEditor({ open, item, typeId, onClose, onSaved }: { open: boolean; item?: RuntimeBlacklist; typeId: number; onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<Partial<RuntimeBlacklist>>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    setError(""); form.resetFields();
  }, [open, item, form]);
  const save = async () => {
    let values: Partial<RuntimeBlacklist>; try { values = await form.validateFields(); } catch { return; }
    setBusy(true); setError("");
    try {
      if (item) await patchRuntimeBlacklist(typeId, item.id, { ...values, version: item.version }); else await createRuntimeBlacklist(typeId, values);
      onSaved(); onClose();
    } catch (failure) { setError(errorText(failure)); } finally { setBusy(false); }
  };
  return <Modal title={item ? "编辑黑名单" : "新增黑名单"} open={open} onCancel={() => !busy && onClose()} onOk={() => void save()} confirmLoading={busy} okText="保存黑名单" cancelText="取消" width={660} destroyOnHidden maskClosable={!busy}>
    {error && <Alert type="error" showIcon title="黑名单未保存" description={error} />}
    <Form form={form} initialValues={{ target_type: "command", match_type: "contains", category: "attack", detection_type: "blacklist_match", severity: "HIGH", confidence: 0.9, priority: 50, enabled: true, ...item }} layout="vertical" preserve={false} className="runtime-editor-form">
      <div className="runtime-form-grid">
        <Form.Item name="target_type" label="目标类型" rules={[{ required: true }]}><Select options={["command", "path", "tool", "mcp", "domain", "url", "process"].map(value => ({ value, label: value }))} /></Form.Item>
        <Form.Item name="match_type" label="匹配方式" rules={[{ required: true }]}><Select options={matchOptions} /></Form.Item>
      </div>
      <Form.Item name="value" label="匹配内容" rules={[{ required: true }]} extra="域名按小写主机名匹配，不含协议和端口。通配符支持 * 和 ?。"><Input maxLength={1024} /></Form.Item>
      <div className="runtime-form-grid">
        <Form.Item name="detection_type" label="检测类型" rules={[{ required: true }]}><Input maxLength={128} /></Form.Item>
        <Form.Item name="category" label="分类" rules={[{ required: true }]}><Select options={categoryOptions} /></Form.Item>
        <Form.Item name="severity" label="严重级别" rules={[{ required: true }]}><Select options={riskOptions} /></Form.Item>
        <Form.Item name="confidence" label="置信度" rules={[{ required: true }]}><InputNumber min={0} max={1} step={0.01} /></Form.Item>
        <Form.Item name="priority" label="优先级" rules={[{ required: true }]}><InputNumber min={0} max={100000} precision={0} /></Form.Item>
        <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
      </div>
      <Form.Item name="reason" label="原因与说明"><Input.TextArea rows={3} maxLength={8192} /></Form.Item>
    </Form>
  </Modal>;
}
