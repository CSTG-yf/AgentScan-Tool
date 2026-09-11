import { useEffect, useMemo, useRef, useState } from "react";
import { EyeInvisibleOutlined, EyeOutlined, MenuFoldOutlined, MenuUnfoldOutlined, ReloadOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Badge, Button, Layout, Menu, message, Modal, Result, Segmented, Space, Tag, Tooltip, Typography } from "antd";
import {
  applyProcessGuardPolicy,
  ensureGatewayReady,
  getAgents,
  getChanges,
  getAgentTrace,
  getAttackChains,
  getEnvironment,
  getGatewayAudit,
  getGuardPolicy,
  getProcessGuardAudit,
  getRangeReplayStatus,
  getRangeStatus,
  getScanScheduleSettings,
  getStaticResourceAgents,
  getStaticResourceScanSettings,
  installProcessGuard,
  startProcessGuard,
  saveDefenseMode,
  saveGuardPolicy,
  saveScanScheduleSettings,
  saveStaticResourceScanSettings,
  setGatewayRunning,
  setRangeRunning,
  startRangeReplay,
  stopRangeReplay,
  uninstallProcessGuard,
} from "./bridge";
import { defenseModeColors, defenseModeDescriptions, defenseModeLabels } from "./app/display";
import { navigation, type PageKey } from "./app/navigation";
import { defaultReplayCommand, replayCommandForScenario } from "./data/range";
import { AgentsPage } from "./pages/AgentsPage";
import { AgentGovernancePage } from "./pages/AgentGovernancePage";
import { AlertsPage } from "./pages/AlertsPage";
import { AttackChainPage } from "./pages/AttackChainPage";
import { EventsPage } from "./pages/EventsPage";
import { EvidencePage } from "./pages/EvidencePage";
import { OverviewPage } from "./pages/OverviewPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { RangePage } from "./pages/RangePage";
import { SettingsPage } from "./pages/SettingsPage";
import { StaticAssetsPage } from "./pages/StaticAssetsPage";
import { TracePage } from "./pages/TracePage";
import type { AgentInventory, AgentSnapshot, AgentTraceSnapshot, AttackChainSnapshot, EnvironmentSnapshot, GatewayAuditSnapshot, GuardAuditSnapshot, GuardPolicy, RangeMode, RangeReplayStatus, RangeStatus, ScanScheduleSettings, ScanTaskKey, StaticResourceScanSettings } from "./types";

const { Header, Sider, Content } = Layout;
const { Text, Title } = Typography;
export default function App() {
  const [active, setActive] = useState<PageKey>("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [sidebarHidden, setSidebarHidden] = useState(false);
  const [environment, setEnvironment] = useState<EnvironmentSnapshot>();
  const [agents, setAgents] = useState<AgentInventory[]>([]);
  const [agentTotal, setAgentTotal] = useState(0);
  const [agentWarning, setAgentWarning] = useState("");
  const [policy, setPolicy] = useState<GuardPolicy>();
  const [rangeStatus, setRangeStatus] = useState<RangeStatus>();
  const [defenseMode, setDefenseMode] = useState<RangeMode>("baseline");
  const [replayCommand, setReplayCommand] = useState(defaultReplayCommand);
  const [replayStatus, setReplayStatus] = useState<RangeReplayStatus>();
  const [audit, setAudit] = useState<GuardAuditSnapshot>();
  const [trace, setTrace] = useState<AgentTraceSnapshot>();
  const [gatewayAudit, setGatewayAudit] = useState<GatewayAuditSnapshot>();
  const [attackChains, setAttackChains] = useState<AttackChainSnapshot>();
  const [scanSettings, setScanSettings] = useState<ScanScheduleSettings>();
  const [staticScanSettings, setStaticScanSettings] = useState<StaticResourceScanSettings>();
  const [loading, setLoading] = useState(false);
  const [savingPolicy, setSavingPolicy] = useState(false);
  const [savingScanSettings, setSavingScanSettings] = useState(false);
  const [savingStaticScanSettings, setSavingStaticScanSettings] = useState(false);
  const [switchingDefenseMode, setSwitchingDefenseMode] = useState(false);
  const [replayBusy, setReplayBusy] = useState(false);
  const [staticRefreshTick, setStaticRefreshTick] = useState(0);
  const [eventRefreshTick, setEventRefreshTick] = useState(0);
  const [gatewayBootState, setGatewayBootState] = useState<"starting" | "ready" | "failed">("starting");
  const [gatewayBootError, setGatewayBootError] = useState("");

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

  const persistScanSettings = async (next: ScanScheduleSettings) => {
    setSavingScanSettings(true);
    try {
      const saved = await saveScanScheduleSettings(next);
      setScanSettings(saved);
      message.success("扫描任务刷新间隔已保存");
    } catch (error) {
      message.error(`保存扫描任务刷新间隔失败：${String(error)}`);
    } finally {
      setSavingScanSettings(false);
    }
  };

  const persistStaticScanSettings = async (next: StaticResourceScanSettings) => {
    setSavingStaticScanSettings(true);
    try {
      const saved = await saveStaticResourceScanSettings(next);
      setStaticScanSettings(saved);
      message.success("后端静态资源扫描配置已保存");
    } catch (error) {
      message.error(`保存后端静态资源扫描配置失败：${String(error)}`);
    } finally {
      setSavingStaticScanSettings(false);
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

  const applyAgentSnapshot = (snapshot: AgentSnapshot) => {
    setAgents(snapshot.agents);
    setAgentTotal(snapshot.total && snapshot.total > 0 ? snapshot.total : snapshot.agents.length);
    setAgentWarning(snapshot.warning ?? "");
  };

  const refreshTask = async (task: ScanTaskKey) => {
    switch (task) {
      case "environment":
        setEnvironment(await getEnvironment());
        return;
      case "agentDiscovery": {
        const snapshot = await getAgents();
        applyAgentSnapshot(snapshot);
        return;
      }
      case "behaviorTrace":
        setTrace(await getAgentTrace());
        return;
      case "processGuardAudit":
        setAudit(await getProcessGuardAudit());
        return;
      case "gatewayAudit":
        setGatewayAudit(await getGatewayAudit());
        return;
      case "eventDetection": {
        setAttackChains(await getAttackChains());
        setEventRefreshTick((tick) => tick + 1);
        return;
      }
      case "staticAssets":
        setStaticRefreshTick((tick) => tick + 1);
        return;
      case "rangeStatus": {
        const status = await getRangeStatus();
        setRangeStatus(status);
        setDefenseMode(status.mode ?? "baseline");
        return;
      }
      default:
        return;
    }
  };

  const refreshAttackChains = async () => {
    setAttackChains(await getAttackChains());
  };

  const refresh = async () => {
    setLoading(true);
    const results = await Promise.allSettled([getEnvironment(), getAgents(), getGuardPolicy(), getRangeStatus(), getProcessGuardAudit(), getAgentTrace(), getGatewayAudit(), getRangeReplayStatus(), getStaticResourceAgents(), getAttackChains()]);
    if (results[0].status === "fulfilled") setEnvironment(results[0].value);
    if (results[1].status === "fulfilled") {
      applyAgentSnapshot(results[1].value);
    }
    if (results[2].status === "fulfilled") setPolicy(results[2].value);
    if (results[3].status === "fulfilled") {
      setRangeStatus(results[3].value);
      setDefenseMode(results[3].value.mode ?? "baseline");
    }
    if (results[4].status === "fulfilled") setAudit(results[4].value);
    if (results[5].status === "fulfilled") setTrace(results[5].value);
    if (results[6].status === "fulfilled") setGatewayAudit(results[6].value);
    if (results[7].status === "fulfilled") setReplayStatus(results[7].value);
    if (results[9].status === "fulfilled") setAttackChains(results[9].value);
    setLoading(false);
  };

  const bootstrap = async () => {
      setGatewayBootState("starting");
      setGatewayBootError("");
      try {
        const result = await ensureGatewayReady();
        if (!result.success) throw new Error(result.message || "内置 Go Gateway 启动失败");
        setGatewayBootState("ready");
      } catch (error) {
        const detail = String(error);
        setGatewayBootState("failed");
        setGatewayBootError(detail);
        message.error({ key: "gateway-bootstrap", content: `本地安全服务启动失败：${detail}`, duration: 6 });
        return;
      }

      const settings = await Promise.allSettled([getScanScheduleSettings(), getStaticResourceScanSettings()]);
      if (settings[0].status === "fulfilled") setScanSettings(settings[0].value);
      if (settings[1].status === "fulfilled") setStaticScanSettings(settings[1].value);
      await refresh();
  };

  useEffect(() => {
    void bootstrap();
  }, []);

  const changeCursorRef = useRef(0);

  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    let timer: number | undefined;
    let consecutiveFailures = 0;
    const refreshConfig = (() => {
      if (!scanSettings) return undefined;
      switch (active) {
        case "overview": return scanSettings.environment;
        case "agents": return scanSettings.agentDiscovery;
        case "staticAssets": return scanSettings.staticAssets;
        case "trace": return scanSettings.behaviorTrace;
        case "events": return scanSettings.eventDetection;
        case "chain": return scanSettings.processGuardAudit;
        case "alerts": return scanSettings.gatewayAudit;
        case "range": return scanSettings.rangeStatus;
        default: return undefined;
      }
    })();
    if (!refreshConfig?.enabled) return;
    const baseDelay = Math.max(3, refreshConfig.intervalSec) * 1000;
    const scheduleNext = () => {
      if (disposed) return;
      const delay = Math.min(60_000, baseDelay * 2 ** Math.min(consecutiveFailures, 4));
      timer = window.setTimeout(() => void syncChanges(), delay);
    };
    const syncChanges = async () => {
      if (disposed || inFlight) return;
      if (document.hidden) {
        scheduleNext();
        return;
      }
      inFlight = true;
      try {
        const changes = await getChanges(changeCursorRef.current, ["agents", "static_resources", "scan_findings", "behavior_events", "runtime_detections", "runtime_decisions", "runtime_response_actions", "runtime_attack_chains", "runtime_attack_chain_events", "scan_jobs"]);
        if (disposed) return;
        consecutiveFailures = 0;
        changeCursorRef.current = Math.max(changeCursorRef.current, changes.next_cursor || 0);
        const domains = new Set(changes.changed_domains ?? []);
        if (domains.has("agents") && (active === "agents" || active === "overview")) await refreshTask("agentDiscovery");
        if (["static_resources", "scan_findings"].some((domain) => domains.has(domain)) && (active === "staticAssets" || active === "overview")) setStaticRefreshTick((tick) => tick + 1);
        const runtimeChanged = ["behavior_events", "runtime_detections", "runtime_decisions", "runtime_response_actions"].some((domain) => domains.has(domain));
        if (runtimeChanged && (active === "events" || active === "overview")) setEventRefreshTick((tick) => tick + 1);
        if (domains.has("behavior_events") && active === "trace") await refreshTask("behaviorTrace");
        if (["runtime_attack_chains", "runtime_attack_chain_events"].some((domain) => domains.has(domain)) && (active === "chain" || active === "overview")) await refreshAttackChains();
        // Host-derived surfaces do not have SQLite change domains. Their own
        // configured interval remains the source of truth for read refreshes.
        if (active === "overview") await refreshTask("environment");
        if (active === "alerts") await Promise.all([refreshTask("processGuardAudit"), refreshTask("gatewayAudit")]);
        if (active === "range") await refreshTask("rangeStatus");
      } catch (error) {
        consecutiveFailures += 1;
        console.warn("change cursor sync failed", error);
      } finally {
        inFlight = false;
        scheduleNext();
      }
    };
    void syncChanges();
    return () => {
      disposed = true;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [active, scanSettings]);

  useEffect(() => {
    if (active !== "range" && !replayStatus?.running) return;
    const refreshReplay = async () => {
      try {
        setReplayStatus(await getRangeReplayStatus());
      } catch {
        // Main refresh surfaces host errors; keep the progress poll quiet.
      }
    };
    void refreshReplay();
    const timer = window.setInterval(() => void refreshReplay(), replayStatus?.running ? 1000 : 3000);
    return () => window.clearInterval(timer);
  }, [active, replayStatus?.running]);

  const readyCount = environment?.components.filter((item) => item.state === "ready").length ?? 0;
  const totalCount = environment?.components.length ?? 3;
  const enabledRules = policy?.rules.filter((rule) => rule.enabled).length ?? 0;
  const guardComponent = environment?.components.find((component) => component.id === "processGuard");
  const guardEvents = useMemo(() => [...(audit?.events ?? [])].reverse(), [audit]);
  const commandEvents = useMemo(() => guardEvents.filter((event) => event.eventType === "agent-command-rule-matched"), [guardEvents]);
  const terminatedCount = commandEvents.filter((event) => event.outcome === "terminated").length;
  const traceEvents = trace?.events ?? [];
  const fileTraceCount = traceEvents.filter((event) => event.eventType.startsWith("file") || event.eventType === "blacklistFileAccess").length;

  const updateBlacklist = (id: string, patch: Partial<GuardPolicy["fileGuard"]["blacklist"][number]>, save = false) => {
    if (!policy) return;
    const next = { ...policy, fileGuard: { ...policy.fileGuard, blacklist: policy.fileGuard.blacklist.map((rule) => rule.id === id ? { ...rule, ...patch } : rule) } };
    setPolicy(next);
    if (save) void persistPolicy(next);
  };

  const addBlacklistRule = () => {
    if (!policy) return;
    const suffix = Date.now().toString(36);
    void persistPolicy({
      ...policy,
      fileGuard: {
        ...policy.fileGuard,
        blacklist: [...policy.fileGuard.blacklist, { id: `file.custom.${suffix}`, enabled: false, path: "C:\\Users\\Public", matchKind: "exact", access: ["any"], action: "returnEmptyContent", description: "自定义敏感文件规则" }],
      },
    });
  };

  const guardActionPending = useRef(false);
  const requestGuardAction = async (action: "install" | "start" | "apply" | "uninstall") => {
    if (guardActionPending.current) return;
    guardActionPending.current = true;
    const dismiss = message.loading("正在执行管理员操作；如 Windows 请求授权，请确认。已有管理员权限时可能不弹出 UAC。", 0);
    try {
      if (action === "install") await installProcessGuard();
      else if (action === "start") await startProcessGuard();
      else if (action === "apply") await applyProcessGuardPolicy();
      else await uninstallProcessGuard();
      message.success(action === "install" ? "管理员服务已安装" : action === "start" ? "管理员服务已启动" : action === "apply" ? "系统策略已应用" : "管理员服务已卸载");
      await refresh();
    } catch (error) {
      message.error(`操作失败：${String(error)}`);
    } finally {
      dismiss();
      guardActionPending.current = false;
    }
  };

  const changeGatewayState = async (running: boolean) => {
    setLoading(true);
    try {
      if (running) {
        if (defenseMode === "baseline") {
          message.info("Baseline 模式不启动 TraceBastion Gateway，请先切换到 Observe 或 Action");
          return;
        }
        const status = await saveDefenseMode(defenseMode);
        setRangeStatus(status);
        message.success(`网关已按 ${defenseModeLabels[defenseMode]} 模式启动`);
      } else {
        const result = await setGatewayRunning(false);
        if (result.success) message.success("网关已停止");
        else message.error(result.message || "网关操作失败");
      }
    } catch (error) {
      message.error(`网关操作失败：${String(error)}`);
    } finally {
      await refresh();
    }
  };

  const configureDefenseMode = async (mode: string | number) => {
    const nextMode = String(mode) as RangeMode;
    setDefenseMode(nextMode);
    setSwitchingDefenseMode(true);
    try {
      const status = await saveDefenseMode(nextMode);
      setRangeStatus(status);
      setDefenseMode(status.mode ?? nextMode);
      message.success(`全局防护模式已切换为 ${defenseModeLabels[nextMode]}`);
    } catch (error) {
      message.error(`全局防护模式切换失败：${String(error)}`);
      void refresh();
    } finally {
      setSwitchingDefenseMode(false);
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

  const fillReplayScenario = (scenario: string) => {
    setReplayCommand(replayCommandForScenario(scenario));
  };

  const startReplay = async (commandOverride?: string) => {
    const commandToRun = commandOverride ?? replayCommand;
    setReplayCommand(commandToRun);
    setReplayBusy(true);
    try {
      const status = await startRangeReplay(commandToRun);
      setReplayStatus(status);
      message.success("攻击回放已启动");
    } catch (error) {
      message.error(`攻击回放启动失败：${String(error)}`);
    } finally {
      setReplayBusy(false);
    }
  };

  const stopReplay = async () => {
    setReplayBusy(true);
    try {
      const status = await stopRangeReplay();
      setReplayStatus(status);
      message.info("攻击回放已停止");
    } catch (error) {
      message.error(`停止攻击回放失败：${String(error)}`);
    } finally {
      setReplayBusy(false);
    }
  };

  const replayTotal = replayStatus?.total ?? 0;
  const replayCompleted = replayStatus?.completed ?? 0;
  const replayRemaining = replayStatus?.remaining ?? Math.max(replayTotal - replayCompleted, 0);
  const replayPercent = replayTotal > 0 ? Math.min(100, Math.round((replayCompleted / replayTotal) * 100)) : 0;

  const renderPage = () => {
    if (gatewayBootState !== "ready") {
      const starting = gatewayBootState === "starting";
      return (
        <Result
          status={starting ? "info" : "error"}
          icon={starting ? <ReloadOutlined spin /> : undefined}
          title={starting ? "正在启动本地安全服务" : "本地安全服务启动失败"}
          subTitle={starting ? "Go Gateway 已集成在桌面应用中，正在等待服务就绪。" : gatewayBootError}
          extra={!starting ? <Button type="primary" onClick={() => void bootstrap()}>重新启动</Button> : undefined}
        />
      );
    }
    switch (active) {
      case "range":
        return (
          <RangePage
            rangeStatus={rangeStatus}
            defenseMode={defenseMode}
            loading={loading}
            replayCommand={replayCommand}
            replayStatus={replayStatus}
            replayBusy={replayBusy}
            replayTotal={replayTotal}
            replayCompleted={replayCompleted}
            replayRemaining={replayRemaining}
            replayPercent={replayPercent}
            onChangeRangeState={(running) => void changeRangeState(running)}
            onReplayCommandChange={setReplayCommand}
            onFillReplayScenario={fillReplayScenario}
            onStartReplay={(command) => void startReplay(command)}
            onStopReplay={() => void stopReplay()}
          />
        );
      case "agents":
        return <AgentsPage agents={agents} totalAgents={agentTotal} warning={agentWarning} loading={loading} onRefresh={() => refreshTask("agentDiscovery")} />;
      case "governance":
        return <AgentGovernancePage
          scanSettings={scanSettings}
          staticScanSettings={staticScanSettings}
          savingScanSettings={savingScanSettings}
          savingStaticScanSettings={savingStaticScanSettings}
          onScanSettingsChange={persistScanSettings}
          onStaticScanSettingsChange={persistStaticScanSettings}
          onRefreshData={refresh}
        />;
      case "trace":
        return <TracePage trace={trace} events={traceEvents} fileTraceCount={fileTraceCount} />;
      case "staticAssets":
        return <StaticAssetsPage loading={loading} refreshNonce={staticRefreshTick} onRefresh={() => refreshTask("staticAssets")} />;
      case "events":
        return <EventsPage loading={loading} refreshNonce={eventRefreshTick} onRefresh={() => refreshTask("eventDetection")} />;
      case "policies":
        return (
          <PoliciesPage
            policy={policy}
            guardComponent={guardComponent}
            enabledRules={enabledRules}
            savingPolicy={savingPolicy}
            onModeChange={changeMode}
            onPersistPolicy={(next) => void persistPolicy(next)}
            onSetPolicy={setPolicy}
            onRequestGuardAction={(action) => void requestGuardAction(action)}
            onUpdateBlacklist={updateBlacklist}
            onAddBlacklistRule={addBlacklistRule}
          />
        );
      case "alerts":
        return <AlertsPage audit={audit} commandEvents={commandEvents} terminatedCount={terminatedCount} />;
      case "chain":
        return <AttackChainPage defenseMode={defenseMode} gatewayAudit={gatewayAudit} snapshot={attackChains} loading={loading} onRefresh={() => refreshAttackChains()} />;
      case "evidence":
        return <EvidencePage audit={audit} guardEvents={guardEvents} />;
      case "settings":
        return (
          <SettingsPage
            guardComponent={guardComponent}
            scanSettings={scanSettings}
            staticScanSettings={staticScanSettings}
            savingScanSettings={savingScanSettings}
            savingStaticScanSettings={savingStaticScanSettings}
            onScanSettingsChange={(next) => void persistScanSettings(next)}
            onStaticScanSettingsChange={(next) => void persistStaticScanSettings(next)}
            onRunRefreshAll={() => void refresh()}
            onRequestGuardAction={(action) => void requestGuardAction(action)}
          />
        );
      case "overview":
      default:
        return <OverviewPage environment={environment} policy={policy} refreshNonce={eventRefreshTick + staticRefreshTick} onNavigate={setActive} />;
    }
  };

  const activeTitle = navigation.find((item) => item.key === active)?.label ?? "TraceBastion";

  return (
    <Layout className={`app-shell ${sidebarHidden ? "sidebar-hidden" : ""}`}>
      {!sidebarHidden && (
        <Sider width={238} collapsedWidth={80} collapsed={sidebarCollapsed} trigger={null} className={`sidebar ${sidebarCollapsed ? "sidebar-collapsed" : ""}`} theme="dark">
          <div className="brand">
            <div className="brand-mark"><SafetyCertificateOutlined /></div>
            {!sidebarCollapsed && <div><div className="brand-title">TraceBastion</div><div className="brand-subtitle">AGENT SECURITY CONTROL PLANE</div></div>}
          </div>
          <Menu mode="inline" selectedKeys={[active]} items={navigation} onClick={({ key }) => setActive(key as PageKey)} />
          <div className="sidebar-footer"><Badge status={readyCount ? "success" : "warning"} />{!sidebarCollapsed && <><span>本机控制平面</span><span className="version">v0.1</span></>}</div>
        </Sider>
      )}
      <Layout className="main-layout" style={{ marginLeft: sidebarHidden ? 0 : sidebarCollapsed ? 80 : 238 }}>
        <Header className="topbar">
          <div>
            <Text className="eyebrow">WINDOWS 安全工作台</Text>
            <Title level={3}>{activeTitle}</Title>
          </div>
          <div className="topbar-controls">
            <Space.Compact>
              <Tooltip title={sidebarHidden ? "显示菜单栏" : "隐藏菜单栏"}>
                <Button icon={sidebarHidden ? <EyeOutlined /> : <EyeInvisibleOutlined />} onClick={() => setSidebarHidden((hidden) => !hidden)} />
              </Tooltip>
              <Tooltip title={sidebarCollapsed ? "展开菜单栏" : "收起菜单栏"}>
                <Button icon={sidebarCollapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} disabled={sidebarHidden} onClick={() => setSidebarCollapsed((collapsed) => !collapsed)} />
              </Tooltip>
            </Space.Compact>
            <div className="global-mode">
              <Text className="global-mode-label">全局防护模式</Text>
              <Segmented
                value={defenseMode}
                disabled={loading || switchingDefenseMode}
                options={[
                  { label: "Baseline", value: "baseline" },
                  { label: "Observe", value: "observe" },
                  { label: "Action", value: "action" },
                ]}
                onChange={configureDefenseMode}
              />
              <Tag color={defenseModeColors[defenseMode]}>{defenseModeLabels[defenseMode]}</Tag>
              <Text type="secondary" className="global-mode-detail">{defenseModeDescriptions[defenseMode]}</Text>
            </div>
            <Tooltip title="自动刷新间隔可在系统设置中按任务配置"><Button icon={<ReloadOutlined spin={loading || gatewayBootState === "starting"} />} disabled={gatewayBootState !== "ready"} onClick={() => void refresh()}>刷新状态</Button></Tooltip>
          </div>
        </Header>
        <Content className="content">{renderPage()}</Content>
      </Layout>
    </Layout>
  );
}
