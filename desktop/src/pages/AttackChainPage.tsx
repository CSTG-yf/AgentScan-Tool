import { useCallback, useEffect, useMemo, useState } from "react";
import { CaretRightOutlined, DownloadOutlined, PauseOutlined, ReloadOutlined, StepBackwardOutlined, StepForwardOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Empty, Space, Table, Tag, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { chainKindTag, defenseModeColors, defenseModeLabels, eventStatusTag, formatClock, formatTimestamp, staticRiskTag } from "../app/display";
import { chainKindMeta } from "../data/attackChains";
import { staticRiskMeta } from "../data/staticAssets";
import { createAttackChainRebuildJob, getAttackChainAgentTypeSummaries, getScanStatus } from "../bridge";
import type { AttackChain, AttackChainAgentTypeSummary, AttackChainSnapshot, ChainEvidenceRow, GatewayAuditEvent, GatewayAuditSnapshot, RangeMode, StaticRisk } from "../types";

const { Text, Title } = Typography;

interface AttackChainPageProps {
  defenseMode: RangeMode;
  gatewayAudit?: GatewayAuditSnapshot;
  snapshot?: AttackChainSnapshot;
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
}

interface ChainAgentSummary {
  key: string;
  agent: string;
  runtime: string;
  count: number;
  stepCount: number;
  evidenceCount: number;
  blockedCount: number;
  maxRisk: StaticRisk;
  lastSeen: string;
  sources: string[];
}

function riskRank(risk: StaticRisk) {
  return staticRiskMeta[risk]?.rank ?? 0;
}

function chainAgentKey(chain: Pick<AttackChain, "agent" | "runtime">) {
  return `${chain.agent}::${chain.runtime}`;
}

function selectedChainId(chains: AttackChain[], current: string) {
  if (!chains.length) return "";
  return chains.some((chain) => chain.id === current) ? current : chains[0].id;
}

function chainIdentity(chain: AttackChain) {
  if (chain.traceId) return `Trace ${chain.traceId}`;
  if (chain.sessionId) return `Session ${chain.sessionId}`;
  return `${chain.agent} 时间窗口`;
}

function filenameSafe(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9\u4e00-\u9fa5]+/gi, "-").replace(/^-+|-+$/g, "") || "attack-chain";
}

function dynamicCountEntries(counts?: Record<string, number>) {
  return Object.entries(counts ?? {})
    .filter(([, count]) => Number.isFinite(count) && count > 0)
    .sort(([left], [right]) => left.localeCompare(right));
}

function buildAgentSummaries(chains: AttackChain[]): ChainAgentSummary[] {
  const map = new Map<string, ChainAgentSummary>();
  for (const chain of chains) {
    const key = chainAgentKey(chain);
    const item = map.get(key) ?? {
      key,
      agent: chain.agent,
      runtime: chain.runtime,
      count: 0,
      stepCount: 0,
      evidenceCount: 0,
      blockedCount: 0,
      maxRisk: "info",
      lastSeen: chain.endedAt || chain.startedAt,
      sources: [],
    };
    item.count += 1;
    item.stepCount += chain.stepCount || chain.steps.length;
    item.evidenceCount += chain.evidenceCount || chain.evidence.length;
    if (chain.status === "blocked") item.blockedCount += 1;
    if (riskRank(chain.risk) > riskRank(item.maxRisk)) item.maxRisk = chain.risk;
    if ((chain.endedAt || chain.startedAt) > item.lastSeen) item.lastSeen = chain.endedAt || chain.startedAt;
    for (const source of chain.sources) {
      if (source && !item.sources.includes(source)) item.sources.push(source);
    }
    map.set(key, item);
  }
  return [...map.values()].sort((left, right) => riskRank(right.maxRisk) - riskRank(left.maxRisk) || right.count - left.count || left.agent.localeCompare(right.agent));
}

function gatewayEventMatchesChain(event: GatewayAuditEvent, chain?: AttackChain, selectedAgent?: ChainAgentSummary) {
  if (!chain && !selectedAgent) return Boolean(event.traceId) || event.action.startsWith("agentrange-runtime");
  if (chain?.traceId && event.traceId === chain.traceId) return true;
  if (chain?.sessionId && event.sessionId === chain.sessionId) return true;
  if (chain && event.agentName && event.agentName === chain.agent) return true;
  if (selectedAgent && event.agentName && event.agentName === selectedAgent.agent) return true;
  return false;
}

async function waitForChainRebuild(scanId?: string): Promise<void> {
  if (!scanId) return;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = await getScanStatus(scanId);
    if (status.status === "completed") return;
    if (status.status === "failed") throw new Error(status.error || "攻击链重建失败");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new Error("攻击链重建等待超时，请稍后刷新");
}

export function AttackChainPage({ defenseMode, gatewayAudit, snapshot, loading = false, onRefresh }: AttackChainPageProps) {
  const [selectedAgentKey, setSelectedAgentKey] = useState("");
  const [chainId, setChainId] = useState("");
  const [agentTypeSummaries, setAgentTypeSummaries] = useState<AttackChainAgentTypeSummary[]>([]);
  const [agentTypeSummaryLoading, setAgentTypeSummaryLoading] = useState(false);
  const [agentTypeSummaryError, setAgentTypeSummaryError] = useState("");
  const [stepIndex, setStepIndex] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);
  const chains = useMemo(
    () => [...(snapshot?.chains ?? [])].sort((left, right) => new Date(right.endedAt).getTime() - new Date(left.endedAt).getTime()),
    [snapshot],
  );
  const agentSummaries = useMemo(() => buildAgentSummaries(chains), [chains]);

  const loadAgentTypeSummaries = useCallback(async () => {
    setAgentTypeSummaryLoading(true);
    try {
      const response = await getAttackChainAgentTypeSummaries();
      setAgentTypeSummaries(response.items ?? response.list ?? []);
      setAgentTypeSummaryError("");
    } catch (error) {
      setAgentTypeSummaryError(`读取 AgentType 攻击链汇总失败：${String(error)}`);
    } finally {
      setAgentTypeSummaryLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAgentTypeSummaries();
  }, [loadAgentTypeSummaries, snapshot?.capturedAt]);

  useEffect(() => {
    if (!agentSummaries.length) {
      setSelectedAgentKey("");
      setChainId("");
      setStepIndex(0);
      setPlaying(false);
      return;
    }
    if (!selectedAgentKey || !agentSummaries.some((agent) => agent.key === selectedAgentKey)) {
      setSelectedAgentKey(agentSummaries[0].key);
      setChainId("");
      setStepIndex(0);
      setPlaying(false);
    }
  }, [agentSummaries, selectedAgentKey]);

  const selectedAgent = agentSummaries.find((agent) => agent.key === selectedAgentKey);
  const agentChains = useMemo(
    () => selectedAgentKey ? chains.filter((chain) => chainAgentKey(chain) === selectedAgentKey) : [],
    [chains, selectedAgentKey],
  );
  const selectedId = selectedChainId(agentChains, chainId);
  const chain = agentChains.find((item) => item.id === selectedId) ?? agentChains[0];
  const activeStep = chain?.steps[Math.min(stepIndex, Math.max(chain.steps.length - 1, 0))];
  const activeStepTime = activeStep?.occurredAt ?? chain?.startedAt ?? "";
  const evidenceRows = useMemo<ChainEvidenceRow[]>(() => chain?.evidence ?? [], [chain]);
  const gatewayTraceEvents = useMemo<GatewayAuditEvent[]>(
    () => (gatewayAudit?.events ?? []).filter((event) => gatewayEventMatchesChain(event, chain, selectedAgent)),
    [chain, gatewayAudit, selectedAgent],
  );

  useEffect(() => {
    const next = selectedChainId(agentChains, chainId);
    if (next !== chainId) {
      setChainId(next);
      setStepIndex(0);
      setPlaying(false);
    }
  }, [agentChains, chainId]);

  useEffect(() => {
    setStepIndex(0);
    setPlaying(false);
  }, [selectedId]);

  useEffect(() => {
    if (!playing || !chain) return;
    const timer = window.setInterval(() => {
      setStepIndex((index) => {
        if (index >= chain.steps.length - 1) {
          setPlaying(false);
          return index;
        }
        return index + 1;
      });
    }, 1600);
    return () => window.clearInterval(timer);
  }, [chain, playing]);

  const selectAgent = (key: string) => {
    setSelectedAgentKey(key);
    setChainId("");
    setStepIndex(0);
    setPlaying(false);
  };

  const refreshChains = async () => {
    if (!onRefresh) return;
    setRefreshing(true);
    try {
      await onRefresh();
      await loadAgentTypeSummaries();
      message.success("已刷新后端攻击链数据");
    } catch (error) {
      message.error(`刷新攻击链失败：${String(error)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const rebuildChains = async () => {
    setRebuilding(true);
    try {
      const accepted = await createAttackChainRebuildJob(5000);
      await waitForChainRebuild(accepted.scan_id);
      await onRefresh?.();
      await loadAgentTypeSummaries();
      message.success("攻击链重建完成");
    } catch (error) {
      message.error(`重建攻击链失败：${String(error)}`);
    } finally {
      setRebuilding(false);
    }
  };

  const agentTypeSummaryColumns: ColumnsType<AttackChainAgentTypeSummary> = [
    {
      title: "AgentType",
      width: 210,
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{row.agentType || row.agentTypeName || row.agentTypeKey || "unknown"}</Text>
          <Text type="secondary">ID {row.agentTypeId}{row.agentTypeName ? ` · ${row.agentTypeName}` : ""}</Text>
        </Space>
      ),
    },
    {
      title: "攻击链",
      dataIndex: "totalChains",
      width: 100,
      render: (value: number) => <Text strong>{value}</Text>,
    },
    {
      title: "状态分布（后端动态）",
      dataIndex: "statusCounts",
      render: (value: Record<string, number>) => {
        const entries = dynamicCountEntries(value);
        return entries.length ? (
          <Space wrap size={[4, 4]}>
            {entries.map(([status, count]) => <Tag key={status}>{status}: {count}</Tag>)}
          </Space>
        ) : <Text type="secondary">暂无状态</Text>;
      },
    },
    {
      title: "严重度分布",
      dataIndex: "severityCounts",
      render: (value: Record<string, number>) => {
        const entries = dynamicCountEntries(value);
        return entries.length ? (
          <Space wrap size={[4, 4]}>
            {entries.map(([severity, count]) => <Tag key={severity}>{severity}: {count}</Tag>)}
          </Space>
        ) : <Text type="secondary">暂无严重度</Text>;
      },
    },
    {
      title: "最近结束",
      dataIndex: "latestAt",
      width: 176,
      render: (value: string) => <Text className="mono">{formatTimestamp(value || "")}</Text>,
    },
  ];

  const evidenceColumns: ColumnsType<ChainEvidenceRow> = [
    { title: "步骤", dataIndex: "index", width: 82, render: (value) => <Tag color="geekblue">#{value}</Tag> },
    { title: "时间", dataIndex: "occurredAt", width: 176, render: (value) => <Text className="mono chain-table-nowrap">{formatTimestamp(value)}</Text> },
    { title: "阶段", dataIndex: "stage", width: 150, render: (value) => <Text className="chain-table-nowrap">{value || "-"}</Text> },
    { title: "Agent / 组件", dataIndex: "agent", width: 180, render: (value) => <Text className="chain-table-nowrap">{value || "-"}</Text> },
    { title: "工具 / 子类型", dataIndex: "tool", width: 180, render: (value) => <Text code className="chain-table-wrap">{value || "-"}</Text> },
    { title: "资源 / 目标", dataIndex: "resource", width: 260, render: (value) => <Text className="chain-table-wrap">{value || "-"}</Text> },
    { title: "处置决策", dataIndex: "decision", width: 170, render: (value) => <Text className="chain-table-wrap">{value || "-"}</Text> },
    { title: "证据", dataIndex: "evidence", width: 320, render: (value) => <Text className="chain-table-wrap">{value || "-"}</Text> },
    { title: "来源", dataIndex: "source", width: 130, render: (value) => <Tag>{value || "-"}</Tag> },
  ];

  const gatewayColumns: ColumnsType<GatewayAuditEvent> = [
    { title: "时间", dataIndex: "timestamp", width: 176, render: (value) => <Text className="mono chain-table-nowrap">{formatTimestamp(value)}</Text> },
    { title: "Trace", dataIndex: "traceId", width: 190, render: (value) => <Text code className="chain-table-wrap">{value || "-"}</Text> },
    { title: "Agent", dataIndex: "agentName", width: 160, render: (value) => <Text className="chain-table-wrap">{value || "-"}</Text> },
    { title: "阶段", dataIndex: "stage", width: 150, render: (value, row) => <Text className="chain-table-wrap">{value || row.action || "-"}</Text> },
    { title: "目标", dataIndex: "destinationApp", width: 190, render: (value, row) => <Text className="chain-table-wrap">{value || row.target || "-"}</Text> },
    { title: "工具", dataIndex: "toolName", width: 190, render: (value, row) => <Text code className="chain-table-wrap">{value || row.mcpServer || "-"}</Text> },
    { title: "决策", dataIndex: "decision", width: 110, render: (value) => <Tag color={value === "block" ? "red" : value === "alert" ? "gold" : "blue"}>{value || "audit"}</Tag> },
    { title: "原因 / Prompt", width: 360, render: (_, row) => <Space direction="vertical" size={0}><Text className="chain-table-wrap">{row.reason || row.details || "-"}</Text>{row.prompt && <Text code className="event-evidence chain-table-wrap">{row.prompt}</Text>}</Space> },
  ];

  const exportMarkdown = () => {
    if (!chain) return;
    const lines = [
      `# ${chain.category}`,
      "",
      `- Agent: ${chain.agent}`,
      `- Runtime: ${chain.runtime}`,
      `- ${chainIdentity(chain)}`,
      `- 风险: ${staticRiskMeta[chain.risk].label}`,
      `- 状态: ${chain.status}`,
      `- 链路开始: ${formatTimestamp(chain.startedAt)}`,
      `- 链路结束: ${formatTimestamp(chain.endedAt)}`,
      `- 数据源: ${chain.sources.join(", ") || "-"}`,
      "",
      "## 摘要",
      chain.summary,
      "",
      "## 真实链路步骤",
      ...chain.steps.flatMap((step) => [
        "",
        `### ${step.order}. ${step.title}`,
        `- 时间: ${formatTimestamp(step.occurredAt)}`,
        `- 阶段: ${step.stage}`,
        `- 类型: ${chainKindMeta[step.kind].label}`,
        `- 组件: ${step.actor}`,
        `- 工具: ${step.tool}`,
        `- 资源: ${step.resource}`,
        `- 证据: ${step.evidence}`,
        `- 决策: ${step.decision}`,
        `- 来源事件: ${step.sourceEventId}`,
        `- 数据源: ${step.source}`,
        `- 栈归因: ${step.stack.join(" -> ") || "-"}`,
      ]),
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${filenameSafe(chain.id)}.md`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="workspace-page attack-chain-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">ATTACK CHAIN RECONSTRUCTION</Text>
          <Title level={2}>攻击链</Title>
          <Text type="secondary">按 Agent 展示后端持久化的 Detection/Evidence 攻击链；历史数据需要通过“重建攻击链”任务更新。</Text>
        </div>
        <Space wrap>
          <Tag color={defenseModeColors[defenseMode]}>{defenseModeLabels[defenseMode]}</Tag>
          <Tag color="purple">{snapshot?.total ?? chains.length} 条链路</Tag>
          <Tag color="blue">{agentSummaries.length} Agents</Tag>
          <Button className="chain-action-button" icon={<ReloadOutlined />} loading={loading || refreshing} onClick={() => void refreshChains()}>
            刷新数据
          </Button>
          <Button className="chain-action-button" loading={rebuilding} onClick={() => void rebuildChains()}>
            重建攻击链
          </Button>
        </Space>
      </div>

      {snapshot?.warning ? <Alert type="warning" showIcon message={snapshot.warning} /> : null}
      {agentTypeSummaryError ? <Alert type="warning" showIcon message={agentTypeSummaryError} /> : null}

      <Card
        bordered={false}
        className="workspace-table-card agent-type-summary-card"
        title="AgentType 攻击链汇总"
        extra={<Text type="secondary">数据库实时聚合 · {agentTypeSummaries.length} 类</Text>}
      >
        <Table
          rowKey={(row) => `${row.agentTypeId}:${row.agentType}`}
          size="small"
          loading={loading || agentTypeSummaryLoading}
          columns={agentTypeSummaryColumns}
          dataSource={agentTypeSummaries}
          pagination={false}
          scroll={{ x: 920 }}
          locale={{ emptyText: "暂无按 AgentType 聚合的攻击链" }}
        />
      </Card>

      <div className="chain-workbench">
        <aside className="chain-agent-panel static-agent-panel">
          <div className="static-panel-heading">
            <Text type="secondary">Agents</Text>
            <Tag color="blue">{agentSummaries.length}</Tag>
          </div>
          <div className="static-agent-list">
            {agentSummaries.length ? agentSummaries.map((agent) => (
              <button
                key={agent.key}
                className={`static-agent-item ${selectedAgentKey === agent.key ? "static-agent-item-active" : ""}`}
                type="button"
                onClick={() => selectAgent(agent.key)}
              >
                <span className="static-agent-name">{agent.agent}</span>
                <span className="static-agent-source">{agent.runtime}</span>
                <span className="static-agent-meta">
                  <span>{agent.count} Chains</span>
                  <span className={agent.blockedCount ? "static-agent-risk" : ""}>
                    {agent.stepCount} Steps · {agent.blockedCount} Blocked
                  </span>
                </span>
              </button>
            )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent 攻击链" />}
          </div>
        </aside>

        <main className="chain-main-panel">
          {selectedAgent && chain ? (
            <>
              <div className="chain-agent-context">
                <div>
                  <Title level={3}>{selectedAgent.agent}</Title>
                  <Text type="secondary">
                    {selectedAgent.count} Chains · {selectedAgent.stepCount} Steps · {selectedAgent.evidenceCount} Evidence
                  </Text>
                </div>
                <Space direction="vertical" align="end" size={6}>
                  <Text className="mono chain-agent-path">{selectedAgent.runtime}</Text>
                  <Space wrap>
                    {staticRiskTag(selectedAgent.maxRisk)}
                    <Tag color="blue">来源 {selectedAgent.sources.length}</Tag>
                    <Tag>最近 {formatTimestamp(selectedAgent.lastSeen)}</Tag>
                  </Space>
                </Space>
              </div>

              <div className="chain-selector-strip">
                {agentChains.map((item) => (
                  <button
                    key={item.id}
                    className={`chain-selector-card ${item.id === selectedId ? "chain-selector-card-active" : ""}`}
                    type="button"
                    onClick={() => setChainId(item.id)}
                  >
                    <strong>{item.category}</strong>
                    <span>{item.stepCount || item.steps.length} Steps · {item.evidenceCount || item.evidence.length} Evidence</span>
                    <em>{chainIdentity(item)}</em>
                    <span className="chain-selector-card-footer">
                      {staticRiskTag(item.risk)}
                      {eventStatusTag(item.status)}
                    </span>
                  </button>
                ))}
              </div>

              <Card bordered={false} className="chain-control-card">
                <div className="chain-control-main">
                  <Space direction="vertical" size={4}>
                    <Text type="secondary">当前链路</Text>
                    <Title level={4}>{chain.category}</Title>
                    <Text type="secondary">{chain.summary}</Text>
                  </Space>
                  <Space>
                    <Button className="chain-nav-button" icon={<StepBackwardOutlined />} disabled={stepIndex === 0} onClick={() => setStepIndex((index) => Math.max(index - 1, 0))}>上一步</Button>
                    <Button className="chain-play-button" type="primary" icon={playing ? <PauseOutlined /> : <CaretRightOutlined />} disabled={!chain.steps.length} onClick={() => setPlaying((value) => !value)}>{playing ? "暂停" : "播放"}</Button>
                    <Button className="chain-nav-button" icon={<StepForwardOutlined />} disabled={stepIndex >= chain.steps.length - 1} onClick={() => setStepIndex((index) => Math.min(index + 1, chain.steps.length - 1))}>下一步</Button>
                    <Button className="chain-action-button" icon={<DownloadOutlined />} onClick={exportMarkdown}>导出证据</Button>
                  </Space>
                </div>
                <div className="chain-mode-grid">
                  <div><Text type="secondary">归并依据</Text><p>{chainIdentity(chain)}</p></div>
                  <div><Text type="secondary">数据来源</Text><p>{chain.sources.join(" / ") || snapshot?.source || "-"}</p></div>
                  <div><Text type="secondary">处置状态</Text><p><Space>{eventStatusTag(chain.status)}{staticRiskTag(chain.risk)}</Space></p></div>
                </div>
                <div className="chain-time-strip">
                  <div><Text type="secondary">链路开始</Text><strong>{formatTimestamp(chain.startedAt)}</strong></div>
                  <div><Text type="secondary">当前步骤</Text><strong>{formatTimestamp(activeStepTime)}</strong></div>
                  <div><Text type="secondary">链路结束</Text><strong>{formatTimestamp(chain.endedAt)}</strong></div>
                </div>
              </Card>

              <div className="chain-replay-grid">
                <Card bordered={false} className="chain-timeline-card">
                  <div className="chain-scenario-heading">
                    <div><Title level={4}>{chain.category}</Title><Text type="secondary">{chain.summary}</Text></div>
                    <Space><Tag color="red">{chain.stepCount} 个步骤</Tag>{staticRiskTag(chain.risk)}</Space>
                  </div>
                  <div className="chain-node-row">
                    {chain.steps.map((step, index) => (
                      <button key={step.id} className={`chain-node ${index === stepIndex ? "chain-node-active" : ""} ${index < stepIndex ? "chain-node-complete" : ""}`} type="button" onClick={() => setStepIndex(index)}>
                        <span className="chain-node-index">{step.order}</span>
                        <span className="chain-node-time">{formatClock(step.occurredAt)}</span>
                        <span className="chain-node-title">{step.title}</span>
                        <span className="chain-node-kind">{chainKindMeta[step.kind].label}</span>
                      </button>
                    ))}
                  </div>
                </Card>
                <Card bordered={false} className="chain-detail-card" title="当前步骤详情">
                  {activeStep ? (
                    <Space direction="vertical" size="middle">
                      <div><Text type="secondary">阶段</Text><div><Space>{chainKindTag(activeStep.kind)}<Text strong>{activeStep.title}</Text>{staticRiskTag(activeStep.severity)}</Space></div></div>
                      <div className="chain-detail-pair"><Text type="secondary">发生时间</Text><Text className="mono">{formatTimestamp(activeStep.occurredAt)}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">组件 / Agent</Text><Text>{activeStep.actor}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">Prompt / 意图</Text><Text code>{activeStep.prompt}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">工具调用</Text><Text code>{activeStep.tool}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">访问资源</Text><Text>{activeStep.resource}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">检测证据</Text><Text>{activeStep.evidence}</Text></div>
                      <div className="chain-detail-pair"><Text type="secondary">处置依据</Text><Text>{activeStep.decision}</Text></div>
                      <div className="chain-stack">{activeStep.stack.map((frame) => <Tag key={frame} color="geekblue">{frame}</Tag>)}</div>
                    </Space>
                  ) : (
                    <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无步骤详情" />
                  )}
                </Card>
              </div>

              <Card bordered={false} className="workspace-table-card chain-evidence-card" title="结构化攻击链证据">
                <Table className="chain-evidence-table" rowKey="key" columns={evidenceColumns} dataSource={evidenceRows} pagination={false} scroll={{ x: 1638 }} />
              </Card>
            </>
          ) : (
            <Card bordered={false} className="chain-control-card">
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无后端攻击链重建结果">
                <Button className="chain-action-button" icon={<ReloadOutlined />} loading={loading || refreshing} onClick={() => void refreshChains()}>
                  刷新数据
                </Button>
                <Button className="chain-action-button" loading={rebuilding} onClick={() => void rebuildChains()}>
                  重建攻击链
                </Button>
              </Empty>
            </Card>
          )}
        </main>
      </div>

      <Card bordered={false} className="chain-live-audit workspace-table-card" title="当前 Agent / 链路的近期网关审计事件">
        {gatewayAudit?.warning && <div className="inline-warning">{gatewayAudit.warning}</div>}
        <Table className="chain-gateway-table" rowKey={(row) => `${row.timestamp}-${row.traceId}-${row.action}-${row.target}`} columns={gatewayColumns} dataSource={gatewayTraceEvents} pagination={{ pageSize: 8 }} scroll={{ x: 1526 }} locale={{ emptyText: "运行 Observe / Action 模式并执行靶场回放后，这里会显示当前 Agent 或当前链路相关的真实审计事件" }} />
      </Card>
    </section>
  );
}
