import { useEffect, useMemo, useState } from "react";
import {
  BellOutlined, CloudServerOutlined, DatabaseOutlined, DownloadOutlined, ExperimentOutlined,
  LockOutlined, ReloadOutlined, SearchOutlined, SettingOutlined, SafetyCertificateOutlined,
  ToolOutlined, WarningOutlined,
} from "@ant-design/icons";
import { Alert, Button, Card, Input, InputNumber, Modal, Select, Space, Switch, Tag, Typography } from "antd";
import { getNotificationSettings, getPrivacySettings, saveNotificationSettings, savePrivacySettings } from "../bridge";
import type { NotificationSettings, PrivacySettings } from "../bridge";
import type { EnvironmentComponent, RangeMode } from "../types";

const { Text, Title } = Typography;
type SectionKey = "services" | "storage" | "privacy" | "notifications" | "updates" | "diagnostics";
type GuardAction = "install" | "start" | "stop" | "apply" | "uninstall";

const sections: Array<{ key: SectionKey; label: string; description: string; icon: React.ReactNode }> = [
  { key: "services", label: "服务管理", description: "Gateway 与系统进程守护", icon: <CloudServerOutlined /> },
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
    title: "卸载系统进程守护？",
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
        <span className="settings-save-state">配置由 Gateway 管理</span>
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
            icon={<SafetyCertificateOutlined />} title={guardComponent?.label || "系统进程守护"} state={guardComponent?.state} detail={guardComponent?.detail}
            facts={[["系统服务", "DefenseClawProcessGuard / systemd"], ["运行账户", "系统服务账户"], ["启动类型", guardMissing ? "未安装" : "自动"], ["防护模式", defenseMode === "action" ? "Enforce" : "Observe"]]}
            actions={<>
              {!guardReady && <Button type="primary" loading={busy} onClick={() => onGuardAction(guardMissing ? "install" : "start")}>{guardMissing ? "安装 / 修复服务" : "启动服务"}</Button>}
              {guardReady && <Button loading={busy} onClick={() => onGuardAction("stop")}>停止服务</Button>}
              <Button disabled={!guardReady} loading={busy} onClick={() => onGuardAction("apply")}>应用最新策略</Button>
            </>}
          />
          <Card className="settings-danger-zone" title={<span><WarningOutlined /> 危险操作</span>}>
            <div><div><Text strong>卸载系统进程守护</Text><Text type="secondary">停止系统级防护并移除系统服务，审计数据仍会保留。</Text></div><Button danger disabled={guardMissing} onClick={uninstall}>卸载服务</Button></div>
          </Card>
        </>}
        {section === "privacy" && <PrivacySettingsSection />}
        {section === "notifications" && <NotificationSettingsSection />}
        {section !== "services" && section !== "privacy" && section !== "notifications" && <CapabilitySection section={section} />}
      </main>
    </div>
  </section>;
}

function PrivacySettingsSection() {
  const [settings, setSettings] = useState<PrivacySettings>();
  const [original, setOriginal] = useState<PrivacySettings>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [restart, setRestart] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    void getPrivacySettings().then(value => {
      if (active) { setSettings(value); setOriginal(value); setError(""); }
    }).catch(cause => { if (active) setError(String(cause)); });
    return () => { active = false; };
  }, []);
  const persist = async () => {
    if (!settings) return;
    setBusy(true);
    setError("");
    try {
      const result = await savePrivacySettings(settings);
      setSettings(result.settings);
      setOriginal(result.settings);
      setRestart(result.restartRequired);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  };
  const save = () => {
    if (original?.redactionEnabled && settings && !settings.redactionEnabled) {
      Modal.confirm({
        title: "关闭敏感内容脱敏？",
        content: "关闭后，审计、日志和外部接收端可能获得未脱敏内容。仅应在受控单租户环境使用。",
        okText: "确认关闭并保存", okButtonProps: { danger: true }, cancelText: "取消",
        onOk: persist,
      });
      return;
    }
    void persist();
  };
  return <><div className="settings-section-heading"><div><Title level={3}>隐私与脱敏</Title><Text type="secondary">以下值来自 Gateway 配置，保存后写入本机配置文件。</Text></div></div>
    {error && <Alert showIcon type="error" message="设置不可用" description={error} />}
    {restart.length > 0 && <Alert showIcon type="warning" message="需要重启 Gateway" description={`变更 ${restart.join("、")} 已保存，但需重启后完整生效。`} />}
    {settings && <Card title="采集与持久化">
      <div className="settings-form-row"><div><Text strong>敏感字段脱敏</Text><br /><Text type="secondary">控制审计、日志和遥测接收端的统一脱敏。</Text></div><Switch checked={settings.redactionEnabled} onChange={value => setSettings({ ...settings, redactionEnabled: value })} /></div>
      <div className="settings-form-row"><div><Text strong>保留 Judge 原始响应</Text><br /><Text type="secondary">保留本地取证内容；关闭后新响应不再持久化，现有数据不会自动删除。</Text></div><Switch checked={settings.retainJudgeBodies} onChange={value => setSettings({ ...settings, retainJudgeBodies: value })} /></div>
      {!settings.redactionEnabled && <Alert showIcon type="warning" message="脱敏已关闭，敏感数据可能流向持久化和外部接收端。" />}
      <div className="service-actions"><Button type="primary" loading={busy} disabled={JSON.stringify(settings) === JSON.stringify(original)} onClick={save}>保存隐私设置</Button></div>
    </Card>}
  </>;
}

function NotificationSettingsSection() {
  const [settings, setSettings] = useState<NotificationSettings>();
  const [original, setOriginal] = useState<NotificationSettings>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [restart, setRestart] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    void getNotificationSettings().then(value => {
      if (active) { setSettings(value); setOriginal(value); setError(""); }
    }).catch(cause => { if (active) setError(String(cause)); });
    return () => { active = false; };
  }, []);
  const save = async () => {
    if (!settings) return;
    setBusy(true);
    setError("");
    try {
      const result = await saveNotificationSettings(settings);
      setSettings(result.settings);
      setOriginal(result.settings);
      setRestart(result.restartRequired);
    } catch (cause) {
      setError(String(cause));
    } finally {
      setBusy(false);
    }
  };
  const toggle = (field: keyof NotificationSettings, value: boolean) => setSettings(current => current ? { ...current, [field]: value } : current);
  return <><div className="settings-section-heading"><div><Title level={3}>通知</Title><Text type="secondary">配置真实的本机安全通知和去重节流。</Text></div></div>
    {error && <Alert showIcon type="error" message="设置不可用" description={error} />}
    {restart.length > 0 && <Alert showIcon type="warning" message="需要重启 Gateway" description={restart.join("、")} />}
    {settings && <Card title="本机通知">
      {([
        ["enabled", "启用通知"], ["blockEnforced", "实际阻断"], ["blockWouldBlock", "Observe 模式预阻断"],
        ["hitlApproval", "人工审批"], ["hook", "Agent Hook 来源"], ["guardrail", "Guardrail 来源"], ["assetPolicy", "资源策略来源"],
      ] as Array<[keyof NotificationSettings, string]>).map(([field, label]) => <div className="settings-form-row" key={field}><Text strong>{label}</Text><Switch checked={Boolean(settings[field])} onChange={value => toggle(field, value)} /></div>)}
      <div className="settings-form-row"><Text strong>相同通知去重（秒）</Text><InputNumber min={1} max={3600} value={settings.dedupSeconds} onChange={value => value !== null && setSettings({ ...settings, dedupSeconds: value })} /></div>
      <div className="settings-form-row"><Text strong>每分钟通知上限</Text><InputNumber min={1} max={600} value={settings.maxPerMinute} onChange={value => value !== null && setSettings({ ...settings, maxPerMinute: value })} /></div>
      <div className="service-actions"><Button type="primary" loading={busy} disabled={JSON.stringify(settings) === JSON.stringify(original)} onClick={() => void save()}>保存通知设置</Button></div>
    </Card>}
  </>;
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
    updates: { title: "更新与版本", description: "检查桌面端及安全组件兼容性。", items: ["TraceBastion Desktop 0.2.0", "Gateway 与进程守护版本", "规则包和检测签名版本"], icon: <DownloadOutlined /> },
    diagnostics: { title: "诊断与高级设置", description: "检查服务、端口、数据库和策略同步状态。", items: ["Gateway API 与端口检查", "系统守护服务状态检查", "脱敏诊断包与修复建议"], icon: <ExperimentOutlined /> },
  };
  const item = copy[section];
  return <><div className="settings-section-heading"><div><Title level={3}>{item.title}</Title><Text type="secondary">{item.description}</Text></div></div>
    <Card className="capability-placeholder"><span className="capability-icon">{item.icon}</span><Title level={4}>配置接口接入中</Title><Text type="secondary">当前桌面后端尚未提供此分类的持久化接口，因此本页不会展示无法生效的模拟开关。</Text><div>{item.items.map(value => <span key={value}><SettingOutlined /> {value}</span>)}</div></Card>
  </>;
}
