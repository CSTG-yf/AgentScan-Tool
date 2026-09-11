import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertOutlined, ApartmentOutlined, ArrowRightOutlined, CheckCircleFilled, ClockCircleOutlined, ReloadOutlined, SafetyCertificateOutlined, TeamOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Empty, Segmented, Skeleton, Tag, Tooltip, Typography } from "antd";
import ReactECharts from "echarts-for-react";
import { getAttackChains, getRuntimeDetections, getRuntimeEnforcements, getRuntimeSecurityAgents, getRuntimeSecurityMode } from "../bridge";
import type { PageKey } from "../app/navigation";
import type { AttackChain, EnvironmentSnapshot, GuardPolicy, RuntimeDetection, RuntimeEnforcementRecord, RuntimeSecurityAgent, RuntimeSecurityMode } from "../types";

const { Text, Title } = Typography;
type RangeKey = "24h" | "today" | "7d";
type OverviewData = { detections: RuntimeDetection[]; chains: AttackChain[]; agents: RuntimeSecurityAgent[]; enforcements: RuntimeEnforcementRecord[]; mode?: RuntimeSecurityMode; capturedAt: Date };
const severityRank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
const openStatuses = new Set(["open", "active", "pending", "unresolved", "new"]);
const successStatuses = new Set(["success", "succeeded", "executed", "completed", "applied", "blocked", "contained"]);
const rangeStart = (range: RangeKey) => {
  const now = new Date();
  if (range === "today") return new Date(now.getFullYear(), now.getMonth(), now.getDate());
  return new Date(now.getTime() - (range === "7d" ? 7 : 1) * 86400000);
};
const eventTime = (item: RuntimeDetection) => new Date(item.lastSeenAt || item.createdAt || item.firstSeenAt || 0);
const formatTime = (value?: string | Date) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "—";
const severityTag = (value?: string) => {
  const severity = (value || "info").toLowerCase();
  return <Tag color={severity === "critical" ? "red" : severity === "high" ? "orange" : severity === "medium" ? "gold" : "blue"}>{severity.toUpperCase()}</Tag>;
};
const statusLabel = (status?: string) => ({ open: "未处置", active: "进行中", blocked: "已阻断", contained: "已阻断", resolved: "已解决", mitigated: "已缓解" }[String(status || "").toLowerCase()] || status || "待核实");

export interface OverviewPageProps {
  environment?: EnvironmentSnapshot;
  policy?: GuardPolicy;
  refreshNonce?: number;
  onNavigate: (page: PageKey) => void;
}

export function OverviewPage({ environment, policy, refreshNonce = 0, onNavigate }: OverviewPageProps) {
  const [range, setRange] = useState<RangeKey>("24h");
  const [data, setData] = useState<OverviewData>();
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);
  const [revision, setRevision] = useState(0);

  const load = useCallback(async () => {
    data ? setRefreshing(true) : setLoading(true);
    const startTime = rangeStart(range).toISOString();
    const results = await Promise.allSettled([
      getRuntimeDetections({ startTime, limit: 1000, sort: "latest" }),
      getAttackChains({ startTime, page: 1, pageSize: 1000, sort: "latest" }),
      getRuntimeSecurityAgents(1000),
      getRuntimeEnforcements(),
      getRuntimeSecurityMode(),
    ]);
    setErrors(results.flatMap((result, index) => result.status === "rejected" ? [`${["风险事件", "攻击链", "Agent 风险", "响应动作", "运行模式"][index]}：${String(result.reason)}`] : []));
    setData(previous => ({
      detections: results[0].status === "fulfilled" ? results[0].value.items : previous?.detections ?? [],
      chains: results[1].status === "fulfilled" ? results[1].value.chains : previous?.chains ?? [],
      agents: results[2].status === "fulfilled" ? results[2].value : previous?.agents ?? [],
      enforcements: results[3].status === "fulfilled" ? results[3].value.items : previous?.enforcements ?? [],
      mode: results[4].status === "fulfilled" ? results[4].value : previous?.mode,
      capturedAt: new Date(),
    }));
    setLoading(false); setRefreshing(false);
  }, [range, revision, refreshNonce]);
  useEffect(() => { void load(); }, [load]);

  const view = useMemo(() => {
    const cutoff = rangeStart(range).getTime();
    const scopedDetections = (data?.detections ?? []).filter(item => eventTime(item).getTime() >= cutoff);
    const openHigh = scopedDetections.filter(item => severityRank[item.severity?.toLowerCase()] >= 4 && openStatuses.has(item.status?.toLowerCase()));
    const activeChains = (data?.chains ?? []).filter(item => openStatuses.has((item.rawStatus || item.status || "").toLowerCase()));
    const actualBlocks = (data?.enforcements ?? []).filter(item => successStatuses.has((item.status || "").toLowerCase()) && new Date(item.added_at || 0).getTime() >= cutoff);
    const riskAgents = (data?.agents ?? []).filter(item => item.highOrAboveCount > 0 || item.attackCount > 0);
    return { scopedDetections, openHigh, activeChains, actualBlocks, riskAgents };
  }, [data, range]);

  const buckets = useMemo(() => {
    const count = range === "7d" ? 7 : 24;
    const unit = range === "7d" ? 86400000 : 3600000;
    const end = Date.now();
    const rows = Array.from({ length: count }, (_, index) => {
      const start = end - (count - index) * unit;
      return { start, end: start + unit, label: range === "7d" ? new Date(start).toLocaleDateString("zh-CN", { month: "numeric", day: "numeric" }) : new Date(start).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit", hour12: false }), detections: 0, attacks: 0, blocks: 0 };
    });
    for (const item of view.scopedDetections) {
      const time = eventTime(item).getTime(); const bucket = rows.find(row => time >= row.start && time < row.end);
      if (bucket) { bucket.detections++; if (item.category?.toLowerCase() === "attack" || item.detectionType?.toLowerCase().includes("attack")) bucket.attacks++; }
    }
    for (const item of view.actualBlocks) {
      const time = new Date(item.added_at || 0).getTime(); const bucket = rows.find(row => time >= row.start && time < row.end); if (bucket) bucket.blocks++;
    }
    return rows;
  }, [view, range]);

  const stale = data ? Date.now() - data.capturedAt.getTime() > 120000 : false;
  const topDetections = [...view.scopedDetections].sort((a, b) => (severityRank[b.severity?.toLowerCase()] - severityRank[a.severity?.toLowerCase()]) || eventTime(b).getTime() - eventTime(a).getTime()).slice(0, 5);
  const topChains = [...(data?.chains ?? [])].sort((a, b) => (severityRank[b.risk] - severityRank[a.risk]) || new Date(b.startedAt).getTime() - new Date(a.startedAt).getTime()).slice(0, 5);
  const workItems = topDetections.filter(item => openStatuses.has(item.status?.toLowerCase())).slice(0, 5);
  const gateway = environment?.components.find(item => item.id === "gateway");
  const guard = environment?.components.find(item => item.id === "processGuard");
  const alertTone = errors.length ? "error" : view.openHigh.some(item => item.severity?.toLowerCase() === "critical") ? "critical" : view.openHigh.length ? "high" : data ? "safe" : "neutral";

  if (loading && !data) return <section className="security-overview"><Skeleton active paragraph={{ rows: 12 }} /></section>;
  return <section className="security-overview">
    <header className="overview-header">
      <div><Title level={2}>安全总览</Title><Text type="secondary">本机 Agent 风险、攻击链与防护执行态势</Text></div>
      <div className="overview-header-actions">
        <Segmented value={range} options={[{ label: "24 小时", value: "24h" }, { label: "今天", value: "today" }, { label: "7 天", value: "7d" }]} onChange={value => setRange(value as RangeKey)} />
        <span className={`freshness ${stale ? "stale" : ""}`}><span />{stale ? "数据已过期" : errors.length ? "部分数据异常" : "数据实时"}</span>
        <Text type="secondary">更新于 {formatTime(data?.capturedAt)}</Text>
        <Button icon={<ReloadOutlined />} loading={refreshing} onClick={() => setRevision(value => value + 1)}>刷新</Button>
      </div>
    </header>
    <div className={`priority-banner tone-${alertTone}`}>
      <AlertOutlined /><strong>{errors.length ? `有 ${errors.length} 个数据源读取失败，请检查本地安全服务` : view.openHigh.length ? `发现 ${view.openHigh.length} 个高危未处置事件，涉及 ${new Set(view.openHigh.map(item => item.agentId).filter(Boolean)).size} 个 Agent` : "当前时间范围内未发现未处置高危事件"}</strong>
      <Button type={view.openHigh.length ? "primary" : "default"} danger={view.openHigh.length > 0} onClick={() => onNavigate(errors.length ? "settings" : "events")}>{errors.length ? "检查服务" : "立即查看"}<ArrowRightOutlined /></Button>
    </div>
    {errors.length > 0 && <Alert className="overview-source-error" type="error" showIcon message="部分模块保留上次成功数据" description={errors.join("；")} />}
    <div className="overview-metrics">
      {[
        { label: "未处置高危", value: view.openHigh.length, note: "Critical / High 且状态未关闭", icon: <AlertOutlined />, tone: "danger", page: "events" as PageKey },
        { label: "活跃攻击链", value: view.activeChains.length, note: "状态为 active / open", icon: <ApartmentOutlined />, tone: "attack", page: "chain" as PageKey },
        { label: "已阻断", value: view.actualBlocks.length, note: "仅统计实际执行成功", icon: <SafetyCertificateOutlined />, tone: "safe", page: "alerts" as PageKey },
        { label: "风险 Agent", value: view.riskAgents.length, note: `共发现 ${data?.agents.length ?? 0} 个 Agent`, icon: <TeamOutlined />, tone: "agent", page: "agents" as PageKey },
      ].map(item => <Card key={item.label} className={`overview-metric tone-${item.tone}`} onClick={() => onNavigate(item.page)}>
        <div className="overview-metric-icon">{item.icon}</div><div><Tooltip title={item.note}><Text strong>{item.label}</Text></Tooltip><strong>{item.value}</strong><Text type="secondary">{item.note}</Text></div>
      </Card>)}
    </div>
    <div className="overview-main-grid">
      <Card className="overview-panel trend-panel" title="风险趋势" extra={<div className="chart-legend"><span className="blue">异常事件</span><span className="red">攻击事件</span><span className="green">实际阻断</span></div>}>
        <ReactECharts className="overview-chart" option={{ tooltip: { trigger: "axis" }, grid: { left: 34, right: 18, top: 20, bottom: 34 }, xAxis: { type: "category", data: buckets.map(item => item.label), axisLabel: { color: "#64748b", interval: range === "7d" ? 0 : 3 } }, yAxis: { type: "value", minInterval: 1, axisLabel: { color: "#64748b" }, splitLine: { lineStyle: { color: "#e9eef5" } } }, series: [{ name: "异常事件", type: "line", smooth: true, symbol: "circle", data: buckets.map(item => item.detections), lineStyle: { color: "#1677ff" }, itemStyle: { color: "#1677ff" } }, { name: "攻击事件", type: "line", smooth: true, symbol: "diamond", data: buckets.map(item => item.attacks), lineStyle: { color: "#ef4444", type: "dashed" }, itemStyle: { color: "#ef4444" } }, { name: "实际阻断", type: "line", smooth: true, symbol: "triangle", data: buckets.map(item => item.blocks), lineStyle: { color: "#16a36a" }, itemStyle: { color: "#16a36a" }, areaStyle: { color: "rgba(22,163,106,.08)" } }] }} />
      </Card>
      <OverviewList title="待处置事项" action={() => onNavigate("events")} empty="暂无待处置事项" rows={workItems.map(item => ({ id: item.detectionId, badge: severityTag(item.severity), title: item.agentName || item.agentId || "未知 Agent", detail: item.title, status: statusLabel(item.status), time: formatTime(item.lastSeenAt || item.createdAt) }))} />
    </div>
    <div className="overview-bottom-grid">
      <OverviewList title="最近高危告警" action={() => onNavigate("events")} empty="当前范围无高危告警" rows={topDetections.filter(item => severityRank[item.severity?.toLowerCase()] >= 4).map(item => ({ id: item.detectionId, badge: severityTag(item.severity), title: item.agentName || "未知 Agent", detail: item.title, status: statusLabel(item.status), time: formatTime(item.lastSeenAt || item.createdAt) }))} />
      <OverviewList title="最近攻击链" action={() => onNavigate("chain")} empty="当前范围无攻击链" rows={topChains.map(item => ({ id: item.id, badge: severityTag(item.risk), title: item.agent, detail: item.summary, status: statusLabel(item.rawStatus || item.status), time: formatTime(item.startedAt) }))} />
      <Card className="overview-panel protection-panel" title="防护状态" extra={<Button type="link" onClick={() => onNavigate("settings")}>服务设置 <ArrowRightOutlined /></Button>}>
        <ProtectionRow label="运行模式" value={data?.mode === "action" ? "强制防护" : data?.mode === "observe" ? "观察模式" : "未知"} ok={Boolean(data?.mode)} />
        <ProtectionRow label="网关" value={gateway?.state === "ready" ? "在线" : gateway?.detail || "未检测"} ok={gateway?.state === "ready"} />
        <ProtectionRow label="进程守护" value={guard?.state === "ready" ? "已启用" : guard?.detail || "未检测"} ok={guard?.state === "ready"} />
        <ProtectionRow label="策略" value={policy?.enabled ? `${policy.rules.filter(rule => rule.enabled).length} 条规则启用` : "未启用"} ok={Boolean(policy?.enabled)} />
        <ProtectionRow label="数据采集" value={errors.length ? "部分异常" : "正常"} ok={!errors.length} />
      </Card>
    </div>
  </section>;
}

function OverviewList({ title, action, rows, empty }: { title: string; action: () => void; rows: Array<{ id: string; badge: React.ReactNode; title: string; detail: string; status: string; time: string }>; empty: string }) {
  return <Card className="overview-panel overview-list" title={title} extra={<Button type="link" onClick={action}>查看全部 <ArrowRightOutlined /></Button>}>
    {rows.length ? rows.map(row => <button key={row.id} onClick={action}><span>{row.badge}</span><span className="overview-row-copy"><strong>{row.title}</strong><Text type="secondary" ellipsis={{ tooltip: row.detail }}>{row.detail}</Text></span><span className="overview-row-state"><span>{row.status}</span><small>{row.time}</small></span></button>) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={empty} />}
  </Card>;
}
function ProtectionRow({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return <div className="protection-row"><span>{ok ? <CheckCircleFilled /> : <ClockCircleOutlined />}{label}</span><strong className={ok ? "ok" : "warn"}>{value}</strong></div>;
}
