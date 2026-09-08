import { Button, Card, Input, Segmented, Space, Switch, Table, Tag, Typography } from "antd";
import type { EnvironmentComponent, GuardPolicy } from "../types";

const { Text, Title } = Typography;

export interface PoliciesPageProps {
  policy?: GuardPolicy;
  guardComponent?: EnvironmentComponent;
  enabledRules: number;
  savingPolicy: boolean;
  onModeChange: (mode: string | number) => void;
  onPersistPolicy: (policy: GuardPolicy) => void;
  onSetPolicy: (policy: GuardPolicy) => void;
  onRequestGuardAction: (action: "install" | "apply" | "uninstall") => void;
  onUpdateBlacklist: (id: string, patch: Partial<GuardPolicy["fileGuard"]["blacklist"][number]>, save?: boolean) => void;
  onAddBlacklistRule: () => void;
}

export function PoliciesPage({ policy, guardComponent, enabledRules, savingPolicy, onModeChange, onPersistPolicy, onSetPolicy, onRequestGuardAction, onUpdateBlacklist, onAddBlacklistRule }: PoliciesPageProps) {
  return (
    <section className="workspace-page policies-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">PROCESS GUARD</Text>
          <Title level={2}>Agent 命令黑名单</Title>
          <Text type="secondary">精确匹配 Agent 子进程的可执行文件名；强制模式由管理员服务执行。</Text>
        </div>
        <Segmented disabled={!policy || savingPolicy} options={[{ label: "仅观察", value: "observe" }, { label: "强制终止", value: "enforce" }]} value={policy?.mode ?? "observe"} onChange={onModeChange} />
      </div>
      <Card bordered={false} className="policy-summary workspace-info-card">
        <div>
          <Text strong>Windows 进程守护</Text>
          <div><Text type="secondary">开启后规则进入工作集；只有已安装的管理员服务才能执行终止动作。</Text></div>
        </div>
        <Space>
          <Tag color={guardComponent?.state === "ready" ? "success" : "default"}>{guardComponent?.state === "ready" ? "服务运行中" : "服务未运行"}</Tag>
          {guardComponent?.state === "missing" ? <Button onClick={() => onRequestGuardAction("install")}>安装管理员服务</Button> : <Button onClick={() => onRequestGuardAction("apply")}>应用到管理员服务</Button>}
          <Switch checkedChildren="启用" unCheckedChildren="关闭" loading={savingPolicy} checked={policy?.enabled} disabled={!policy} onChange={(enabled) => policy && onPersistPolicy({ ...policy, enabled })} />
        </Space>
      </Card>
      <Card bordered={false} className="workspace-table-card" title={`规则（${enabledRules} 条启用）`}>
        <Table rowKey="id" pagination={false} dataSource={policy?.rules ?? []} columns={[
          { title: "启用", dataIndex: "enabled", render: (value: boolean, rule) => <Switch checkedChildren="启用" unCheckedChildren="关闭" checked={value} loading={savingPolicy} onChange={(enabled) => policy && onPersistPolicy({ ...policy, rules: policy.rules.map((item) => item.id === rule.id ? { ...item, enabled } : item) })} /> },
          { title: "可执行文件", dataIndex: "executable", render: (value: string) => <Text code>{value}</Text> },
          { title: "动作", dataIndex: "action", render: (value: string) => <Tag color={value === "terminateAgentTree" ? "red" : "gold"}>{value === "terminateAgentTree" ? "终止 Agent 进程树" : "仅审计"}</Tag> },
          { title: "说明", dataIndex: "description" },
        ]} />
      </Card>
      <Card bordered={false} className="workspace-form-card" title="文件访问监控范围">
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          <Space><Switch checkedChildren="启用" unCheckedChildren="关闭" checked={policy?.trace.enabled} disabled={!policy} loading={savingPolicy} onChange={(enabled) => policy && onPersistPolicy({ ...policy, trace: { ...policy.trace, enabled } })} /><Text>启用 Go 后端行为追踪</Text></Space>
          <Text type="secondary">每行一个绝对目录。应用到管理员服务时会启用 Windows 文件系统审计并写入 SACL；空列表时只记录进程行为。</Text>
          <Input.TextArea rows={3} value={(policy?.fileGuard.auditRoots ?? []).join("\n")} placeholder={"C:\\Projects\\AgentWorkspace\nC:\\Users\\Public\\Documents"} onChange={(event) => policy && onSetPolicy({ ...policy, fileGuard: { ...policy.fileGuard, auditRoots: event.target.value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean) } })} onBlur={() => policy && onPersistPolicy(policy)} />
        </Space>
      </Card>
      <Card bordered={false} className="workspace-table-card" title={<Space><span>敏感文件黑名单</span><Tag color="blue">返回空内容</Tag></Space>} extra={<Space><Switch checkedChildren="启用" unCheckedChildren="关闭" checked={policy?.fileGuard.enabled} disabled={!policy} loading={savingPolicy} onChange={(enabled) => policy && onPersistPolicy({ ...policy, fileGuard: { ...policy.fileGuard, enabled } })} /><Button onClick={onAddBlacklistRule}>新增规则</Button></Space>}>
        <Table rowKey="id" pagination={false} dataSource={policy?.fileGuard.blacklist ?? []} locale={{ emptyText: "尚未配置敏感文件" }} columns={[
          { title: "启用", width: 96, dataIndex: "enabled", render: (value: boolean, rule) => <Switch checkedChildren="启用" unCheckedChildren="关闭" checked={value} loading={savingPolicy} onChange={(enabled) => onUpdateBlacklist(rule.id, { enabled }, true)} /> },
          { title: "文件或目录", dataIndex: "path", render: (value: string, rule) => <Input value={value} className="mono" onChange={(event) => onUpdateBlacklist(rule.id, { path: event.target.value })} onBlur={() => policy && onPersistPolicy(policy)} /> },
          { title: "匹配", width: 180, dataIndex: "matchKind", render: (value: string, rule) => <Segmented value={value} options={[{ label: "精确文件", value: "exact" }, { label: "整个目录", value: "subtree" }]} onChange={(matchKind) => onUpdateBlacklist(rule.id, { matchKind: String(matchKind) as "exact" | "subtree" }, true)} /> },
          { title: "访问类型", width: 110, render: () => <Tag color="volcano">全部访问</Tag> },
          { title: "操作", width: 90, render: (_, rule) => <Button danger type="link" onClick={() => policy && onPersistPolicy({ ...policy, fileGuard: { ...policy.fileGuard, blacklist: policy.fileGuard.blacklist.filter((item) => item.id !== rule.id) } })}>删除</Button> },
        ]} />
        <div className="inline-warning">文件黑名单不再终止 Agent。当前 Windows 审计在访问完成后才通知服务，因此只能记录直接文件访问，不能替换已经返回的内容；真正返回空内容需要读取工具拦截或签名的 Windows Minifilter 驱动。</div>
      </Card>
    </section>
  );
}
