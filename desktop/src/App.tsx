import { useEffect, useMemo, useRef, useState } from "react";
import { EyeInvisibleOutlined, EyeOutlined, MenuFoldOutlined, MenuUnfoldOutlined, ReloadOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Badge, Button, Layout, Menu, message, Modal, Segmented, Space, Tag, Tooltip, Typography } from "antd";
import {
  applyProcessGuardPolicy,
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
  saveDefenseMode,
  saveGuardPolicy,
  saveRangeRoot,
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
  const [rangeRoot, setRangeRoot] = useState("");
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
        if (status.root) setRangeRoot(status.root);
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
      if (results[3].value.root) setRangeRoot(results[3].value.root);
      setDefenseMode(results[3].value.mode ?? "baseline");
    }
    if (results[4].status === "fulfilled") setAudit(results[4].value);
    if (results[5].status === "fulfilled") setTrace(results[5].value);
    if (results[6].status === "fulfilled") setGatewayAudit(results[6].value);
    if (results[7].status === "fulfilled") setReplayStatus(results[7].value);
    if (results[9].status === "fulfilled") setAttackChains(results[9].value);
    setLoading(false);
  };

  useEffect(() => {
    const bootstrap = async () => {
      try {
        setScanSettings(await getScanScheduleSettings());
      } catch (error) {
        message.error(`读取扫描任务刷新间隔失败：${String(error)}`);
      }
      try {
        setStaticScanSettings(await getStaticResourceScanSettings());
      } catch (error) {
        message.error(`读取后端静态资源扫描配置失败：${String(error)}`);
      }
      await refresh();
    };

    void bootstrap();
  }, []);

  const changeCursorRef = useRef(0);

  useEffect(() => {
    let disposed = false;
    let inFlight = false;
    const syncChanges = async () => {
      if (disposed || inFlight) return;
      inFlight = true;
      try {
        const changes = await getChanges(changeCursorRef.current, ["agents", "static_resources", "behavior_events", "runtime_detections", "runtime_decisions", "runtime_response_actions", "runtime_attack_chains", "scan_jobs"]);
        if (disposed) return;
        changeCursorRef.current = Math.max(changeCursorRef.current, changes.next_cursor || 0);
        const domains = new Set(changes.changed_domains ?? []);
        if (domains.has("agents") && (active === "agents" || active === "overview")) await refreshTask("agentDiscovery");
        if (domains.has("static_resources") && (active === "staticAssets" || active === "overview")) setStaticRefreshTick((tick) => tick + 1);
        const runtimeChanged = ["behavior_events", "runtime_detections", "runtime_decisions", "runtime_response_actions"].some((domain) => domains.has(domain));
        if (runtimeChanged && (active === "events" || active === "overview")) setEventRefreshTick((tick) => tick + 1);
        if (domains.has("runtime_attack_chains") && (active === "chain" || active === "overview")) await refreshAttackChains();
      } catch (error) {
        console.warn("change cursor sync failed", error);
      } finally {
        inFlight = false;
      }
    };
    void syncChanges();
    const timer = window.setInterval(() => void syncChanges(), 3000);
    return () => {
      disposed = true;
      window.clearInterval(timer);
    };
  }, [active]);

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
        blacklist: [...policy.fileGuard.blacklist, { id: `file.custom.${suffix}`, enabled: false, path: "C:\\Users\\Public", matchKind: "exact", access: ["any"], action: "terminateAgentTree", description: "自定义敏感文件规则" }],
      },
    });
  };

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

  const configureRange = async () => {
    try {
      const status = await saveRangeRoot(rangeRoot);
      setRangeStatus(status);
      message.success("AgentRange 路径已保存");
    } catch (error) {
      message.error(`靶场路径无效：${String(error)}`);
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
    switch (active) {
      case "range":
        return (
          <RangePage
            rangeStatus={rangeStatus}
            rangeRoot={rangeRoot}
            defenseMode={defenseMode}
            loading={loading}
            replayCommand={replayCommand}
            replayStatus={replayStatus}
            replayBusy={replayBusy}
            replayTotal={replayTotal}
            replayCompleted={replayCompleted}
            replayRemaining={replayRemaining}
            replayPercent={replayPercent}
            onRangeRootChange={setRangeRoot}
            onConfigureRange={() => void configureRange()}
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
        return <AgentGovernancePage />;
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
        return <OverviewPage environment={environment} agentsCount={agentTotal || agents.length} policy={policy} enabledRules={enabledRules} readyCount={readyCount} totalCount={totalCount} onNavigate={setActive} onGatewayAction={(running) => void changeGatewayState(running)} />;
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
            <Tooltip title="自动刷新间隔可在系统设置中按任务配置"><Button icon={<ReloadOutlined spin={loading} />} onClick={() => void refresh()}>刷新状态</Button></Tooltip>
          </div>
        </Header>
        <Content className="content">{renderPage()}</Content>
      </Layout>
    </Layout>
  );
}
