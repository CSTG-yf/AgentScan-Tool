import { useEffect, useMemo, useState } from "react";
import {
  AlertOutlined,
  AuditOutlined,
  BugOutlined,
  CloudServerOutlined,
  DashboardOutlined,
  ExperimentOutlined,
  FileProtectOutlined,
  RadarChartOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from "@ant-design/icons";
import { Badge, Button, Card, Input, Layout, Menu, message, Modal, Progress, Segmented, Space, Switch, Table, Tag, Tooltip, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import ReactECharts from "echarts-for-react";
import { applyProcessGuardPolicy, getAgentProcesses, getEnvironment, getGuardPolicy, getProcessGuardAudit, getRangeStatus, installProcessGuard, saveGuardPolicy, saveRangeRoot, setGatewayRunning, setRangeRunning, uninstallProcessGuard } from "./bridge";
import type { AgentProcess, EnvironmentComponent, EnvironmentSnapshot, GuardAuditEvent, GuardAuditSnapshot, GuardPolicy, RangeStatus } from "./types";

const { Header, Sider, Content } = Layout;
const { Text, Title } = Typography;

const navigation = [
  { key: "overview", icon: <DashboardOutlined />, label: "安全总览" },
  { key: "range", icon: <ExperimentOutlined />, label: "靶场控制" },
  { key: "agents", icon: <RadarChartOutlined />, label: "Agent 检测" },
  { key: "alerts", icon: <AlertOutlined />, label: "告警中心" },
  { key: "chain", icon: <AuditOutlined />, label: "攻击链" },
  { key: "policies", icon: <FileProtectOutlined />, label: "策略中心" },
  { key: "evidence", icon: <SafetyCertificateOutlined />, label: "报告与证据" },
  { key: "settings", icon: <SettingOutlined />, label: "系统设置" },
];

const stateMeta = {
  ready: { color: "success", text: "就绪" },
  degraded: { color: "warning", text: "降级" },
  stopped: { color: "default", text: "已停止" },
  missing: { color: "error", text: "未安装" },
  unknown: { color: "processing", text: "检测中" },
} as const;

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分`;
}

function formatTimestamp(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value || "—" : timestamp.toLocaleString();
}

function outcomeTag(outcome: string) {
  const color = outcome === "terminated" || outcome === "debugPrivilegeEnabled" ? "success" : outcome === "terminationFailed" || outcome === "debugPrivilegeUnavailable" ? "error" : outcome === "terminationPending" ? "warning" : "processing";
  const label: Record<string, string> = {
    terminated: "已终止",
    terminationFailed: "终止失败",
    terminationPending: "准备终止",
    observed: "已观察",
    debugPrivilegeEnabled: "调试特权已启用",
    debugPrivilegeUnavailable: "调试特权不可用",
  };
  return <Tag color={color}>{(label[outcome] ?? outcome) || "未知"}</Tag>;
}

const auditColumns: ColumnsType<GuardAuditEvent> = [
  { title: "时间", dataIndex: "timestamp", width: 180, render: formatTimestamp },
  { title: "结果", dataIndex: "outcome", width: 150, render: outcomeTag },
  { title: "Agent", render: (_, row) => row.agentExecutable ? <Space direction="vertical" size={0}><Text strong>{row.agentExecutable}</Text><Text type="secondary" className="mono">PID {row.agentPid ?? "—"}</Text></Space> : <Text type="secondary">守护服务</Text> },
  { title: "子进程 / 规则", render: (_, row) => row.childExecutable ? <Space direction="vertical" size={0}><Text code>{row.childExecutable}</Text><Text type="secondary">{row.ruleId ?? "—"}</Text></Space> : "—" },
  { title: "证据详情", dataIndex: "detail", ellipsis: true },
];

function ComponentCard({ component, onGatewayAction }: { component: EnvironmentComponent; onGatewayAction: (running: boolean) => void }) {
  const meta = stateMeta[component.state];
  return (
    <Card className="component-card" bordered={false}>
      <div className="component-heading">
        <div className={`component-icon component-icon-${component.state}`}>
          {component.id === "docker" ? <CloudServerOutlined /> : component.id === "agentrange" ? <ExperimentOutlined /> : component.id === "processGuard" ? <SafetyCertificateOutlined /> : <BugOutlined />}
        </div>
        <Tag color={meta.color}>{meta.text}</Tag>
      </div>
      <Title level={5}>{component.label}</Title>
      <Text type="secondary">{component.detail}</Text>
      {component.id === "gateway" && <div className="component-action"><Button size="small" type={component.state === "ready" ? "default" : "primary"} danger={component.state === "ready"} onClick={() => onGatewayAction(component.state !== "ready")}>{component.state === "ready" ? "停止网关" : "启动网关"}</Button></div>}
      {component.requiresElevation && <div className="elevation-note">敏感操作按需请求管理员权限</div>}
    </Card>
  );
}

export default function App() {
  const [active, setActive] = useState("overview");
  const [environment, setEnvironment] = useState<EnvironmentSnapshot>();
  const [agents, setAgents] = useState<AgentProcess[]>([]);
  const [agentWarning, setAgentWarning] = useState("");
  const [policy, setPolicy] = useState<GuardPolicy>();
  const [rangeStatus, setRangeStatus] = useState<RangeStatus>();
  const [rangeRoot, setRangeRoot] = useState("");
  const [audit, setAudit] = useState<GuardAuditSnapshot>();
  const [loading, setLoading] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);

  const persistPolicy = async (next: GuardPolicy) => {
    setSavingPolicy(true);
    try {
      const saved = await saveGuardPolicy(next);
      setPolicy(saved);
      message.success("进程守护策略已保存");
    } catch (error) {
      message.error(`保存失败：${String(error)}`);
    } finally {
      setSavingPolicy(false);
    }
  };

  const changeMode = (mode: string | number) => {
    if (!policy) return;
    const next = { ...policy, mode: String(mode) as GuardPolicy["mode"] };
    if (mode === "enforce") {
      Modal.confirm({
        title: "切换为强制终止模式？",
        content: "命中启用规则后，管理员监控服务将终止所属 Agent 进程树。服务未安装时策略只会被保存，不会执行终止。",
        okText: "确认切换",
        okButtonProps: { danger: true },
        cancelText: "取消",
        onOk: () => persistPolicy(next),
      });
      return;
    }
    void persistPolicy(next);
  };

  const refresh = async () => {
    setLoading(true);
    const results = await Promise.allSettled([getEnvironment(), getAgentProcesses(), getGuardPolicy(), getRangeStatus(), getProcessGuardAudit()]);
    if (results[0].status === "fulfilled") setEnvironment(results[0].value);
    if (results[1].status === "fulfilled") {
      setAgents(results[1].value.processes);
      setAgentWarning(results[1].value.warning ?? "");
    }
    if (results[2].status === "fulfilled") setPolicy(results[2].value);
    if (results[3].status === "fulfilled") {
      setRangeStatus(results[3].value);
      if (results[3].value.root) setRangeRoot(results[3].value.root);
    }
    if (results[4].status === "fulfilled") setAudit(results[4].value);
    setLoading(false);
  };

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 15_000);
    return () => window.clearInterval(timer);
  }, []);

  const readyCount = environment?.components.filter((item) => item.state === "ready").length ?? 0;
  const totalCount = environment?.components.length ?? 4;
  const enabledRules = policy?.rules.filter((rule) => rule.enabled).length ?? 0;
  const guardComponent = environment?.components.find((component) => component.id === "processGuard");
  const posture = Math.round((readyCount / totalCount) * 100);
  const guardEvents = useMemo(() => [...(audit?.events ?? [])].reverse(), [audit]);
  const commandEvents = useMemo(() => guardEvents.filter((event) => event.eventType === "agent-command-rule-matched"), [guardEvents]);
  const terminatedCount = commandEvents.filter((event) => event.outcome === "terminated").length;

  const requestGuardAction = async (action: "install" | "apply" | "uninstall") => {
    try {
      if (action === "install") await installProcessGuard();
      else if (action === "apply") await applyProcessGuardPolicy();
      else await uninstallProcessGuard();
      message.info("已发起管理员权限请求，请在 Windows UAC 窗口中确认");
      window.setTimeout(() => void refresh(), 3000);
    } catch (error) {
      message.error(`操作失败：${String(error)}`);
    }
  };

  const changeGatewayState = async (running: boolean) => {
    setLoading(true);
    try {
      const result = await setGatewayRunning(running);
      if (result.success) message.success(running ? "网关已启动" : "网关已停止");
      else message.error(result.message || "网关操作失败");
    } catch (error) {
      message.error(`网关操作失败：${String(error)}`);
    } finally {
      await refresh();
    }
  };

  const configureRange = async () => {
    try {
      const status = await saveRangeRoot(rangeRoot);
      setRangeStatus(status);
      message.success("AgentRange 路径已保存");
    } catch (error) {
      message.error(`靶场路径无效：${String(error)}`);
    }
  };

  const changeRangeState = async (running: boolean) => {
    setLoading(true);
    try {
      const status = await setRangeRunning(running);
      setRangeStatus(status);
      message.success(running ? "AgentRange 已启动" : "AgentRange 已停止");
    } catch (error) {
      message.error(`靶场操作失败：${String(error)}`);
    } finally {
      setLoading(false);
    }
  };

  const chartOption = useMemo(() => ({
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    series: [{
      type: "pie",
      radius: ["68%", "88%"],
      center: ["50%", "52%"],
      label: { show: false },
      data: [
        { value: readyCount, name: "就绪", itemStyle: { color: "#44d7b6" } },
        { value: Math.max(totalCount - readyCount, 0), name: "待处理", itemStyle: { color: "#213348" } },
      ],
    }],
    graphic: [{ type: "text", left: "center", top: "42%", style: { text: `${posture}%`, fill: "#edf7ff", font: "700 28px Segoe UI" } }, { type: "text", left: "center", top: "60%", style: { text: "环境就绪度", fill: "#7890a8", font: "12px Segoe UI" } }],
  }), [posture, readyCount, totalCount]);

  const columns: ColumnsType<AgentProcess> = [
    { title: "Agent", dataIndex: "product", render: (_, row) => <Space direction="vertical" size={0}><Text strong>{row.product}</Text><Text type="secondary" className="mono">{row.name}</Text></Space> },
    { title: "厂商", dataIndex: "vendor", render: (value) => value || "—" },
    { title: "PID / PPID", render: (_, row) => <Text className="mono">{row.pid} / {row.ppid || "—"}</Text> },
    { title: "运行时间", dataIndex: "uptimeSec", render: formatUptime },
    { title: "来源", dataIndex: "source", render: (value) => <Tag color={value === "gateway" ? "blue" : "cyan"}>{value === "gateway" ? "网关" : "Windows 原生"}</Tag> },
    { title: "状态", render: () => <Badge status="success" text="运行中" /> },
  ];

  return (
    <Layout className="app-shell">
      <Sider width={238} className="sidebar" theme="dark">
        <div className="brand">
          <div className="brand-mark"><SafetyCertificateOutlined /></div>
          <div><div className="brand-title">DefenseClaw</div><div className="brand-subtitle">DESKTOP CONTROL PLANE</div></div>
        </div>
        <Menu mode="inline" selectedKeys={[active]} items={navigation} onClick={({ key }) => setActive(key)} />
        <div className="sidebar-footer"><Badge status={readyCount ? "success" : "warning"} /><span>本机控制平面</span><span className="version">v0.1</span></div>
      </Sider>
      <Layout>
        <Header className="topbar">
          <div><Text className="eyebrow">WINDOWS 安全工作台</Text><Title level={3}>{navigation.find((item) => item.key === active)?.label}</Title></div>
          <Space><Tooltip title="每 15 秒自动刷新"><Button icon={<ReloadOutlined spin={loading} />} onClick={() => void refresh()}>刷新状态</Button></Tooltip><Button type="primary" icon={<SafetyCertificateOutlined />} onClick={() => setActive("policies")}>进入防护模式</Button></Space>
        </Header>
        <Content className="content">
          {active === "range" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">AGENTRANGE RUNTIME</Text><Title level={2}>靶场控制</Title><Text type="secondary">验证本地 AgentRange Compose 工程，并通过固定 Docker 参数启动或停止服务。</Text></div><Tag color={rangeStatus?.state === "running" ? "success" : rangeStatus?.state === "invalid" ? "error" : "default"}>{rangeStatus?.state === "running" ? "运行中" : rangeStatus?.state === "stopped" ? "已停止" : "未就绪"}</Tag></div>
              <Card bordered={false} className="range-hero">
                <div className="range-status-icon"><ExperimentOutlined /></div>
                <div className="range-status-copy"><Title level={4}>AgentRange-player</Title><Text type="secondary">{rangeStatus?.detail ?? "正在检测靶场环境"}</Text><div className="range-path"><Input value={rangeRoot} onChange={(event) => setRangeRoot(event.target.value)} placeholder="例如 C:\\SecurityLabs\\AgentRange-player" /><Button onClick={() => void configureRange()}>验证并保存</Button></div></div>
                <Space><Button size="large" type="primary" disabled={!rangeStatus?.configured || !rangeStatus.dockerAvailable || rangeStatus.state === "running"} loading={loading} onClick={() => void changeRangeState(true)}>启动靶场</Button><Button size="large" danger disabled={rangeStatus?.state !== "running"} loading={loading} onClick={() => void changeRangeState(false)}>停止靶场</Button></Space>
              </Card>
              <Card bordered={false} title={`运行服务（${rangeStatus?.runningServices.length ?? 0}）`}><div className="service-list">{rangeStatus?.runningServices.length ? rangeStatus.runningServices.map((service) => <Tag key={service} color="cyan">{service}</Tag>) : <Text type="secondary">当前没有运行中的 Compose 服务</Text>}</div>{rangeStatus?.composeFile && <div className="compose-path"><Text type="secondary">Compose：</Text><Text className="mono">{rangeStatus.composeFile}</Text></div>}</Card>
            </section>
          ) : active === "agents" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">LOCAL INVENTORY</Text><Title level={2}>已运行的 Agent</Title><Text type="secondary">由 Windows 原生进程快照识别，列表不会采集命令行参数。</Text></div><Tag color="cyan">{agents.length} 个进程</Tag></div>
              {agentWarning && <div className="inline-warning">{agentWarning}</div>}
              <Card bordered={false}><Table rowKey={(row) => `${row.pid}-${row.startedAt ?? "unknown"}`} columns={columns} dataSource={agents} pagination={false} locale={{ emptyText: "当前没有检测到常见 Agent 进程" }} /></Card>
            </section>
          ) : active === "policies" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">PROCESS GUARD</Text><Title level={2}>Agent 命令黑名单</Title><Text type="secondary">精确匹配 Agent 子进程的可执行文件名；强制模式由管理员服务执行。</Text></div><Segmented disabled={!policy || savingPolicy} options={[{ label: "仅观察", value: "observe" }, { label: "强制终止", value: "enforce" }]} value={policy?.mode ?? "observe"} onChange={changeMode} /></div>
              <Card bordered={false} className="policy-summary"><div><Text strong>Windows 进程守护</Text><div><Text type="secondary">开启后规则进入工作集；只有已安装的管理员服务才能执行终止动作。</Text></div></div><Space><Tag color={guardComponent?.state === "ready" ? "success" : "default"}>{guardComponent?.state === "ready" ? "服务运行中" : "服务未运行"}</Tag>{guardComponent?.state === "missing" ? <Button onClick={() => void requestGuardAction("install")}>安装管理员服务</Button> : <Button onClick={() => void requestGuardAction("apply")}>应用到管理员服务</Button>}<Switch loading={savingPolicy} checked={policy?.enabled} disabled={!policy} onChange={(enabled) => policy && void persistPolicy({ ...policy, enabled })} /></Space></Card>
              <Card bordered={false} title={`规则（${enabledRules} 条启用）`}>
                <Table rowKey="id" pagination={false} dataSource={policy?.rules ?? []} columns={[
                  { title: "启用", dataIndex: "enabled", render: (value: boolean, rule) => <Switch checked={value} loading={savingPolicy} onChange={(enabled) => policy && void persistPolicy({ ...policy, rules: policy.rules.map((item) => item.id === rule.id ? { ...item, enabled } : item) })} /> },
                  { title: "可执行文件", dataIndex: "executable", render: (value: string) => <Text code>{value}</Text> },
                  { title: "动作", dataIndex: "action", render: (value: string) => <Tag color={value === "terminateAgentTree" ? "red" : "gold"}>{value === "terminateAgentTree" ? "终止 Agent 进程树" : "仅审计"}</Tag> },
                  { title: "说明", dataIndex: "description" },
                ]} />
              </Card>
            </section>
          ) : active === "alerts" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">PROCESS GUARD SIGNALS</Text><Title level={2}>告警中心</Title><Text type="secondary">来自 LocalSystem 进程守护的真实规则命中与处置结果。</Text></div><Space><Tag color="red">{terminatedCount} 次已终止</Tag><Tag color="cyan">{commandEvents.length} 条事件</Tag></Space></div>
              {audit?.warning && <div className="inline-warning">{audit.warning}</div>}
              <Card bordered={false}><Table rowKey={(row) => `${row.timestamp}-${row.outcome}-${row.agentPid ?? 0}`} columns={auditColumns} dataSource={commandEvents} pagination={{ pageSize: 15 }} locale={{ emptyText: "尚无 Agent 命令规则命中" }} /></Card>
            </section>
          ) : active === "chain" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">PROCESS ANCESTRY</Text><Title level={2}>攻击链</Title><Text type="secondary">按时间还原 Agent、黑名单子进程与最终处置之间的因果关系。</Text></div><Tag color="purple">最近 {Math.min(commandEvents.length, 12)} 条</Tag></div>
              <div className="chain-list">{commandEvents.slice(0, 12).map((event, index) => <Card bordered={false} className="chain-card" key={`${event.timestamp}-${index}`}><div className="chain-time">{formatTimestamp(event.timestamp)}</div><div className="chain-flow"><div><Text type="secondary">Agent 根进程</Text><strong>{event.agentExecutable ?? "未知 Agent"}</strong><span className="mono">PID {event.agentPid ?? "—"}</span></div><span className="chain-arrow">→</span><div><Text type="secondary">创建命令</Text><strong>{event.childExecutable ?? "未知进程"}</strong><span>{event.ruleId ?? "未标记规则"}</span></div><span className="chain-arrow">→</span><div><Text type="secondary">守护处置</Text>{outcomeTag(event.outcome)}<span>{event.detail}</span></div></div></Card>)}{commandEvents.length === 0 && <Card bordered={false}><Text type="secondary">尚无可还原的进程攻击链。</Text></Card>}</div>
            </section>
          ) : active === "evidence" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">LOCAL JSONL EVIDENCE</Text><Title level={2}>报告与证据</Title><Text type="secondary">审计先落盘后执行终止；证据写入失败时系统不会执行破坏性动作。</Text></div><Tag color="geekblue">{audit?.events.length ?? 0} 条载入</Tag></div>
              <Card bordered={false} className="evidence-path"><Text type="secondary">本机证据文件</Text><Text className="mono" copyable>{audit?.path ?? "正在定位…"}</Text></Card>
              <Card bordered={false}><Table rowKey={(row) => `${row.timestamp}-${row.eventType}-${row.outcome}`} columns={auditColumns} dataSource={guardEvents} pagination={{ pageSize: 20 }} locale={{ emptyText: "尚无审计证据" }} /></Card>
            </section>
          ) : active === "settings" ? (
            <section>
              <div className="section-heading"><div><Text className="eyebrow">PRIVILEGE BOUNDARY</Text><Title level={2}>系统设置</Title><Text type="secondary">桌面 UI 保持普通权限，仅服务安装、系统策略应用和服务卸载触发 UAC。</Text></div>{outcomeTag(guardComponent?.state === "ready" ? "debugPrivilegeEnabled" : "observed")}</div>
              <div className="settings-grid">
                <Card bordered={false} title="Windows 进程守护"><Space direction="vertical" size="middle"><Text>{guardComponent?.detail ?? "正在检测服务状态"}</Text><Space><Button type="primary" disabled={guardComponent?.state === "ready"} onClick={() => void requestGuardAction("install")}>安装 / 修复服务</Button><Button disabled={guardComponent?.state !== "ready"} onClick={() => void requestGuardAction("apply")}>应用当前策略</Button><Button danger disabled={guardComponent?.state === "missing"} onClick={() => void requestGuardAction("uninstall")}>卸载服务</Button></Space></Space></Card>
                <Card bordered={false} title="权限模型"><Space direction="vertical"><Badge status="success" text="UI：当前用户、非提权" /><Badge status="processing" text="守护：LocalSystem Windows Service" /><Badge status="warning" text="终止：PID + 创建时间二次校验" /><Badge status="default" text="受保护进程：仅审计，不承诺终止" /></Space></Card>
              </div>
            </section>
          ) : (
            <section>
              <div className="hero-grid">
                <Card bordered={false} className="hero-card">
                  <div><Text className="eyebrow">DEFENSE POSTURE</Text><Title>本机 AI Agent 防御控制台</Title><Text type="secondary">统一查看网关、靶场、Agent 进程与命令策略。敏感动作由独立管理员服务执行并写入审计证据。</Text><div className="hero-actions"><Button type="primary" size="large" onClick={() => setActive("agents")}>查看 Agent 列表</Button><Button size="large" onClick={() => setActive("policies")}>配置防护规则</Button></div></div>
                  <ReactECharts option={chartOption} className="posture-chart" />
                </Card>
                <Card bordered={false} className="signal-card"><Text className="eyebrow">LIVE SIGNALS</Text><div className="signal-number">{agents.length}</div><Text>运行中的常见 Agent 进程</Text><div className="signal-divider" /><Space direction="vertical"><Badge status={policy?.mode === "enforce" ? "error" : "processing"} text={`进程守护：${policy?.enabled ? policy.mode : "未启用"}`} /><Badge status={enabledRules ? "warning" : "default"} text={`${enabledRules} 条命令规则已启用`} /></Space></Card>
              </div>
              <div className="section-heading compact"><div><Text className="eyebrow">RUNTIME HEALTH</Text><Title level={4}>运行环境</Title></div><Text type="secondary">更新于 {environment ? new Date(environment.capturedAt).toLocaleTimeString() : "—"}</Text></div>
              <div className="component-grid">{environment?.components.map((component) => <ComponentCard key={component.id} component={component} onGatewayAction={(running) => void changeGatewayState(running)} />) ?? <Progress percent={20} status="active" />}</div>
            </section>
          )}
        </Content>
      </Layout>
    </Layout>
  );
}
