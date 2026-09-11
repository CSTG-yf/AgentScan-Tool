import { useMemo, useState } from "react";
import {
  BellOutlined, CloudServerOutlined, DatabaseOutlined, DownloadOutlined, ExperimentOutlined,
  LockOutlined, ReloadOutlined, SearchOutlined, SettingOutlined, SafetyCertificateOutlined,
  ToolOutlined, WarningOutlined,
} from "@ant-design/icons";
import { Alert, Badge, Button, Card, Input, Modal, Select, Space, Tag, Typography } from "antd";
import type { EnvironmentComponent, RangeMode } from "../types";

const { Text, Title } = Typography;
type SectionKey = "services" | "storage" | "privacy" | "notifications" | "updates" | "diagnostics";
type GuardAction = "install" | "start" | "stop" | "apply" | "uninstall";

const sections: Array<{ key: SectionKey; label: string; description: string; icon: React.ReactNode }> = [
  { key: "services", label: "服务管理", description: "Gateway 与 Windows 守护", icon: <CloudServerOutlined /> },
  { key: "storage", label: "数据与存储", description: "数据保留和本机容量", icon: <DatabaseOutlined /> },
  { key: "privacy", label: "隐私与脱敏", description: "敏感内容采集和导出", icon: <LockOutlined /> },
  { key: "notifications", label: "通知", description: "桌面安全通知", icon: <BellOutlined /> },
  { key: "updates", label: "更新与版本", description: "组件版本和兼容性", icon: <DownloadOutlined /> },
  { key: "diagnostics", label: "诊断与高级设置", description: "健康检查和诊断信息", icon: <ToolOutlined /> },
];

interface SettingsPageProps {
  gatewayComponent?: EnvironmentComponent;
  guardComponent?: EnvironmentComponent;
  defenseMode: RangeMode;
  gatewayStartup: "auto" | "manual" | "disabled";
  refreshedAt?: string;
  busy?: boolean;
  onRefresh: () => void;
  onGatewayAction: (action: "start" | "stop" | "restart" | "health") => void;
  onGatewayStartupChange: (value: "auto" | "manual" | "disabled") => void;
  onGuardAction: (action: GuardAction) => void;
}

export function SettingsPage({ gatewayComponent, guardComponent, defenseMode, gatewayStartup, refreshedAt, busy, onRefresh, onGatewayAction, onGatewayStartupChange, onGuardAction }: SettingsPageProps) {
  const [section, setSection] = useState<SectionKey>("services");
  const [query, setQuery] = useState("");
  const visible = useMemo(() => sections.filter(item => `${item.label} ${item.description}`.toLowerCase().includes(query.trim().toLowerCase())), [query]);
  const gatewayReady = gatewayComponent?.state === "ready";
  const guardReady = guardComponent?.state === "ready";
  const guardMissing = guardComponent?.state === "missing";
  const abnormal = [gatewayComponent, guardComponent].filter(item => item && !["ready", "missing"].includes(item.state)).length;

  const uninstall = () => Modal.confirm({
    title: "卸载 Windows 进程守护？",
    icon: <WarningOutlined />,
    content: "卸载后系统级进程防护将停止，已有审计记录不会自动删除。",
    okText: "确认卸载", okButtonProps: { danger: true }, cancelText: "取消",
    onOk: () => onGuardAction("uninstall"),
  });

  return <section className="system-settings-page">
    <header className="settings-header">
      <div><Text className="eyebrow">SYSTEM SETTINGS</Text><Title level={2}>系统设置</Title><Text type="secondary">管理本机服务、数据、隐私、通知、更新与诊断能力。</Text></div>
      <div className="settings-header-tools">
        <Input allowClear prefix={<SearchOutlined />} placeholder="搜索设置" value={query} onChange={event => setQuery(event.target.value)} />
        <span className="settings-save-state"><Badge status="success" /> 已保存</span>
        <Text type="secondary">状态更新于 {refreshedAt ? new Date(refreshedAt).toLocaleTimeString("zh-CN", { hour12: false }) : "—"}</Text>
        <Button icon={<ReloadOutlined />} loading={busy} onClick={onRefresh}>刷新状态</Button>
      </div>
    </header>
    <div className="settings-mobile-nav"><Select value={section} options={visible.map(item => ({ value: item.key, label: item.label }))} onChange={setSection} /></div>
    <div className="settings-layout">
      <nav className="settings-navigation" aria-label="系统设置分类">
        {visible.map(item => <button key={item.key} className={section === item.key ? "active" : ""} onClick={() => setSection(item.key)}>
          <span className="settings-nav-icon">{item.icon}</span><span><strong>{item.label}</strong><small>{item.description}</small></span>
        </button>)}
        {!visible.length && <Text type="secondary">没有匹配的设置</Text>}
      </nav>
      <main className="settings-content">
        {section === "services" && <>
          <div className="settings-section-heading"><div><Title level={3}>服务管理</Title><Text type="secondary">查看真实运行状态并管理本机安全服务生命周期。</Text></div><Tag color={abnormal ? "orange" : "green"}>{abnormal ? `${abnormal} 项异常` : "服务正常"}</Tag></div>
          <div className="service-summary">
            <Metric label="运行中服务" value={[gatewayReady, guardReady].filter(Boolean).length} note="当前受管服务" />
            <Metric label="异常服务" value={abnormal} note="降级或停止" tone={abnormal ? "warning" : "normal"} />
            <Metric label="需要重启" value={0} note="尚未生效的配置" />
          </div>
          <ServiceCard
            icon={<CloudServerOutlined />} title="TraceBastion Gateway" state={gatewayComponent?.state} detail={gatewayComponent?.detail}
            facts={[["监听地址", "127.0.0.1:18970"], ["运行模式", defenseMode === "baseline" ? "Baseline（Gateway 不启动）" : defenseMode === "action" ? "Action" : "Observe"], ["版本", gatewayComponent?.version || "随桌面应用"], ["健康检查", refreshedAt ? new Date(refreshedAt).toLocaleTimeString("zh-CN", { hour12: false }) : "未检查"]]}
            actions={gatewayReady
              ? <><Button type="primary" loading={busy} onClick={() => onGatewayAction("restart")}>重启</Button><Button loading={busy} onClick={() => onGatewayAction("stop")}>停止</Button><Button onClick={() => onGatewayAction("health")}>健康检查</Button></>
              : <><Button type="primary" disabled={defenseMode === "baseline"} loading={busy} onClick={() => onGatewayAction("start")}>启动</Button><Button onClick={() => onGatewayAction("health")}>健康检查</Button></>}
          />
          <Card className="service-preferences-card" title="Gateway 启动设置">
            <div><div><Text strong>随应用启动</Text><Text type="secondary">自动会在桌面应用启动时确保 Gateway 就绪；手动和禁用不会自动启动。</Text></div>
              <Select aria-label="Gateway 启动方式" value={gatewayStartup} style={{ width: 170 }} options={[{ value: "auto", label: "随应用自动启动" }, { value: "manual", label: "手动启动" }, { value: "disabled", label: "禁用" }]} onChange={onGatewayStartupChange} />
            </div>
          </Card>
          {defenseMode === "baseline" && <Alert showIcon type="info" message="Baseline 模式不启动 Gateway" description="请在顶部全局防护模式中切换为 Observe 或 Action 后再启动。" />}
          <ServiceCard
            icon={<SafetyCertificateOutlined />} title="Windows 进程守护" state={guardComponent?.state} detail={guardComponent?.detail}
            facts={[["Windows Service", "TraceBastionProcessGuard"], ["运行账户", "LocalSystem"], ["启动类型", guardMissing ? "未安装" : "自动"], ["防护模式", defenseMode === "action" ? "Enforce" : "Observe"]]}
            actions={<>
              {!guardReady && <Button type="primary" loading={busy} onClick={() => onGuardAction(guardMissing ? "install" : "start")}>{guardMissing ? "安装 / 修复服务" : "启动服务"}</Button>}
              {guardReady && <Button loading={busy} onClick={() => onGuardAction("stop")}>停止服务</Button>}
              <Button disabled={!guardReady} loading={busy} onClick={() => onGuardAction("apply")}>应用最新策略</Button>
            </>}
          />
          <Card className="settings-danger-zone" title={<span><WarningOutlined /> 危险操作</span>}>
            <div><div><Text strong>卸载 Windows 进程守护</Text><Text type="secondary">停止系统级防护并移除 Windows Service，审计数据仍会保留。</Text></div><Button danger disabled={guardMissing} onClick={uninstall}>卸载服务</Button></div>
          </Card>
        </>}
        {section !== "services" && <CapabilitySection section={section} />}
      </main>
    </div>
  </section>;
}

function Metric({ label, value, note, tone = "normal" }: { label: string; value: number; note: string; tone?: string }) {
  return <Card className={`service-summary-card ${tone}`}><Text type="secondary">{label}</Text><strong>{value}</strong><Text type="secondary">{note}</Text></Card>;
}

function ServiceCard({ icon, title, state, detail, facts, actions }: { icon: React.ReactNode; title: string; state?: string; detail?: string; facts: string[][]; actions: React.ReactNode }) {
  const ready = state === "ready";
  const stateText = ready ? "在线" : state === "missing" ? "未安装" : state === "degraded" ? "已停止 / 降级" : state || "状态未知";
  return <Card className="managed-service-card">
    <div className="managed-service-heading"><span className={ready ? "ready" : "inactive"}>{icon}</span><div><Title level={4}>{title}</Title><Text type="secondary">{detail || "正在读取服务状态"}</Text></div><Tag color={ready ? "green" : state === "missing" ? "default" : "orange"}>{stateText}</Tag></div>
    <div className="service-facts">{facts.map(([label, value]) => <div key={label}><Text type="secondary">{label}</Text><strong>{value}</strong></div>)}</div>
    <div className="service-actions"><Space wrap>{actions}</Space></div>
  </Card>;
}

function CapabilitySection({ section }: { section: Exclude<SectionKey, "services"> }) {
  const copy: Record<typeof section, { title: string; description: string; items: string[]; icon: React.ReactNode }> = {
    storage: { title: "数据与存储", description: "管理数据保留、存储容量与安全清理。", items: ["行为与异常事件保留", "数据库和日志容量", "完整性检查与清理预览"], icon: <DatabaseOutlined /> },
    privacy: { title: "隐私与脱敏", description: "控制敏感内容采集、持久化和导出。", items: ["日志敏感字段脱敏", "Prompt 与 Completion 持久化", "路径、用户名和凭据隐藏"], icon: <LockOutlined /> },
    notifications: { title: "通知", description: "配置本机 Critical、High 和服务异常通知。", items: ["风险和处置失败通知", "服务离线与磁盘通知", "免打扰和通知冷却"], icon: <BellOutlined /> },
    updates: { title: "更新与版本", description: "检查桌面端及安全组件兼容性。", items: ["TraceBastion Desktop 0.1.2", "Gateway 与进程守护版本", "规则包和检测签名版本"], icon: <DownloadOutlined /> },
    diagnostics: { title: "诊断与高级设置", description: "检查服务、端口、数据库和策略同步状态。", items: ["Gateway API 与端口检查", "Windows Service 状态检查", "脱敏诊断包与修复建议"], icon: <ExperimentOutlined /> },
  };
  const item = copy[section];
  return <><div className="settings-section-heading"><div><Title level={3}>{item.title}</Title><Text type="secondary">{item.description}</Text></div></div>
    <Card className="capability-placeholder"><span className="capability-icon">{item.icon}</span><Title level={4}>配置接口接入中</Title><Text type="secondary">当前桌面后端尚未提供此分类的持久化接口，因此本页不会展示无法生效的模拟开关。</Text><div>{item.items.map(value => <span key={value}><SettingOutlined /> {value}</span>)}</div></Card>
  </>;
}
