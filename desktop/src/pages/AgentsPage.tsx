import { useEffect, useMemo, useState } from "react";
import {
  AppstoreOutlined,
  CheckCircleFilled,
  CodeOutlined,
  DesktopOutlined,
  DownloadOutlined,
  InfoCircleOutlined,
  LeftOutlined,
  MoreOutlined,
  PauseCircleOutlined,
  PlayCircleFilled,
  ReloadOutlined,
  RightOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  UnorderedListOutlined,
  WarningOutlined,
} from "@ant-design/icons";
import { Avatar, Button, Card, Descriptions, Drawer, Dropdown, Empty, Input, Select, Space, Table, Tag, Tooltip, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { formatUptime } from "../app/display";
import type { AgentInventory, AgentStatus } from "../types";

const { Text, Title } = Typography;

type AgentRisk = "safe" | "medium" | "high" | "critical";
type StatusFilter = AgentStatus | "all";
type TypeFilter = string | "all";
type RiskFilter = AgentRisk | "all";
type SortKey = "name" | "risk" | "status" | "resources";

interface AgentsPageProps {
  agents: AgentInventory[];
  warning: string;
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
}

const statusMeta: Record<AgentStatus, { label: string; color: string; dot: string; description: string }> = {
  running: { label: "运行中", color: "success", dot: "#18c56e", description: "当前活跃" },
  stopped: { label: "未运行", color: "default", dot: "#a8b3c5", description: "当前停止" },
  unknown: { label: "未知", color: "warning", dot: "#f5a623", description: "状态待确认" },
};

const riskMeta: Record<AgentRisk, { label: string; color: string; rank: number }> = {
  safe: { label: "安全", color: "green", rank: 0 },
  medium: { label: "中风险", color: "orange", rank: 2 },
  high: { label: "高风险", color: "red", rank: 3 },
  critical: { label: "严重风险", color: "volcano", rank: 4 },
};

function agentRisk(agent: AgentInventory): AgentRisk {
  if (agent.criticalResourceCount > 0) return "critical";
  if (agent.riskResourceCount >= 5) return "high";
  if (agent.riskResourceCount > 0) return "medium";
  return "safe";
}

function agentTypeLabel(agent: AgentInventory) {
  const text = `${agent.kind} ${agent.description} ${agent.executableNames.join(" ")}`.toLowerCase();
  if (text.includes("cli") || text.includes("terminal")) return "CLI Agent";
  if (text.includes("ide") || text.includes("editor")) return "IDE Agent";
  if (text.includes("platform")) return "Agent Platform";
  return "Desktop Agent";
}

function agentTypeIcon(agent: AgentInventory) {
  const label = agentTypeLabel(agent);
  if (label === "CLI Agent") return <CodeOutlined />;
  if (label === "IDE Agent") return <AppstoreOutlined />;
  if (label === "Agent Platform") return <RobotOutlined />;
  return <DesktopOutlined />;
}

function agentVersion(_agent?: AgentInventory) {
  return "待识别";
}

function formatTimestamp(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function shortTimestamp(value?: string) {
  const formatted = formatTimestamp(value);
  return formatted === "-" ? ["-", ""] : formatted.split(" ");
}

function primaryPath(agent: AgentInventory) {
  return agent.configRoots[0]?.path || agent.source || "-";
}

function lastSeen(agent: AgentInventory) {
  return agent.lastStaticScanAt || agent.startedAt;
}

function newestTimestamp(values: Array<string | undefined>) {
  return values
    .filter(Boolean)
    .sort((left, right) => new Date(right ?? "").getTime() - new Date(left ?? "").getTime())[0];
}

function sourceTags(source: string) {
  return source
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => <Tag key={item}>{item}</Tag>);
}

function avatarClass(agent: AgentInventory) {
  const key = agent.id || agent.product;
  const index = Math.abs([...key].reduce((total, char) => total + char.charCodeAt(0), 0)) % 6;
  return `agent-avatar agent-avatar-${index}`;
}

function exportAgentsReport(agents: AgentInventory[]) {
  const report = {
    generatedAt: new Date().toISOString(),
    total: agents.length,
    agents,
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `agent-inventory-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function AgentsPage({ agents, warning, loading = false, onRefresh }: AgentsPageProps) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("name");
  const [selectedAgentId, setSelectedAgentId] = useState<string>();
  const [agentDetailOpen, setAgentDetailOpen] = useState(false);
  const [agentListCollapsed, setAgentListCollapsed] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  const runningCount = agents.filter((agent) => agent.running).length;
  const stoppedCount = agents.filter((agent) => !agent.running).length;
  const riskCount = agents.filter((agent) => agentRisk(agent) !== "safe").length;
  const latestScan = newestTimestamp(agents.map((agent) => agent.lastStaticScanAt));

  const typeOptions = useMemo(() => {
    const values = [...new Set(agents.map(agentTypeLabel))].sort();
    return [{ label: "全部类型", value: "all" }, ...values.map((value) => ({ label: value, value }))];
  }, [agents]);

  const filteredAgents = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    const rows = agents.filter((agent) => {
      if (statusFilter !== "all" && agent.status !== statusFilter) return false;
      if (typeFilter !== "all" && agentTypeLabel(agent) !== typeFilter) return false;
      if (riskFilter !== "all" && agentRisk(agent) !== riskFilter) return false;
      if (!normalizedQuery) return true;
      return [
        agent.product,
        agent.vendor,
        agent.kind,
        agent.description,
        primaryPath(agent),
        agent.executableNames.join(" "),
        agent.source,
      ]
        .join(" ")
        .toLowerCase()
        .includes(normalizedQuery);
    });

    return rows.sort((left, right) => {
      if (sortKey === "risk") return riskMeta[agentRisk(right)].rank - riskMeta[agentRisk(left)].rank || left.product.localeCompare(right.product);
      if (sortKey === "status") return Number(right.running) - Number(left.running) || left.product.localeCompare(right.product);
      if (sortKey === "resources") return right.staticResourceCount - left.staticResourceCount || left.product.localeCompare(right.product);
      return left.product.localeCompare(right.product);
    });
  }, [agents, query, riskFilter, sortKey, statusFilter, typeFilter]);

  useEffect(() => {
    if (!filteredAgents.length) {
      setSelectedAgentId(undefined);
      setAgentDetailOpen(false);
      return;
    }
    if (selectedAgentId && filteredAgents.some((agent) => agent.id === selectedAgentId)) return;
    if (selectedAgentId) {
      setSelectedAgentId(undefined);
      setAgentDetailOpen(false);
    }
  }, [filteredAgents, selectedAgentId]);

  const selectedAgent = filteredAgents.find((agent) => agent.id === selectedAgentId);

  const selectAgent = (agent: AgentInventory) => {
    setSelectedAgentId(agent.id);
  };

  const openAgentDetail = (agent: AgentInventory) => {
    setSelectedAgentId(agent.id);
    setAgentDetailOpen(true);
  };

  const refreshAgents = async () => {
    if (!onRefresh) return;
    setRefreshing(true);
    try {
      await onRefresh();
      message.success("Agent 扫描完成");
    } catch (error) {
      message.error(`Agent 扫描失败：${String(error)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const columns: ColumnsType<AgentInventory> = [
    {
      title: "Agent 信息",
      dataIndex: "product",
      width: 320,
      render: (_, row) => (
        <div className="agent-info-cell">
          <Avatar shape="square" size={48} className={avatarClass(row)} icon={<RobotOutlined />} />
          <div>
            <Space size={6}>
              <Text strong className="agent-name">{row.product}</Text>
              <CheckCircleFilled className="agent-verified" />
            </Space>
            <Text type="secondary">{row.vendor} · {row.kind}</Text>
            <Text className="agent-path">{primaryPath(row)}</Text>
          </div>
        </div>
      ),
    },
    {
      title: "状态",
      dataIndex: "status",
      width: 150,
      render: (_, row) => {
        const meta = statusMeta[row.status] ?? statusMeta.unknown;
        return (
          <Space direction="vertical" size={2}>
            <Space size={8}>
              <span className="agent-status-dot" style={{ background: meta.dot }} />
              <Text strong>{meta.label}</Text>
            </Space>
            {row.running ? (
              <>
                <Text type="secondary">PID {row.pids.length ? row.pids.join(", ") : "-"}</Text>
                <Text type="secondary">运行 {row.uptimeSec ? formatUptime(row.uptimeSec) : "-"}</Text>
              </>
            ) : (
              <Text type="secondary">{lastSeen(row) ? `最后运行 ${formatTimestamp(lastSeen(row))}` : "从未运行过"}</Text>
            )}
          </Space>
        );
      },
    },
    {
      title: "类型",
      width: 145,
      render: (_, row) => (
        <Space>
          <span className="agent-type-icon">{agentTypeIcon(row)}</span>
          <Text>{agentTypeLabel(row)}</Text>
        </Space>
      ),
    },
    {
      title: "版本",
      width: 120,
      render: (_, row) => <Text>{agentVersion(row)}</Text>,
    },
    {
      title: "风险等级",
      width: 150,
      render: (_, row) => {
        const risk = agentRisk(row);
        return (
          <Space direction="vertical" size={2}>
            <Tag color={riskMeta[risk].color}>{riskMeta[risk].label}</Tag>
            <Text type={row.riskResourceCount ? "danger" : "secondary"}>{row.riskResourceCount} 个风险项</Text>
          </Space>
        );
      },
    },
    {
      title: "发现时间",
      width: 150,
      render: (_, row) => {
        const [date, time] = shortTimestamp(lastSeen(row));
        return (
          <Space direction="vertical" size={2}>
            <Text>{date}</Text>
            <Text type="secondary">{time}</Text>
          </Space>
        );
      },
    },
    {
      title: "操作",
      width: 130,
      fixed: "right",
      render: (_, row) => (
        <Space onClick={(event) => event.stopPropagation()}>
          <Button size="small" type="primary" ghost onClick={() => openAgentDetail(row)}>
            详情
          </Button>
          <Dropdown
            menu={{
              items: [
                { key: "copy", label: "复制路径", onClick: () => void navigator.clipboard?.writeText(primaryPath(row)) },
                { key: "export", label: "导出该 Agent", onClick: () => exportAgentsReport([row]) },
              ],
            }}
          >
            <Button size="small" icon={<MoreOutlined />} />
          </Dropdown>
        </Space>
      ),
    },
  ];

  return (
    <section className="agent-management-page">
      <div className="agent-page-header">
        <div>
          <Title level={2}>Agent 管理</Title>
          <Text type="secondary">发现并管理系统中的 AI Agent，查看 Agent 状态、版本及安全情况</Text>
        </div>
        <div className="agent-header-actions">
          <Space>
            <Button icon={<DownloadOutlined />} onClick={() => exportAgentsReport(filteredAgents)}>
              导出报告
            </Button>
            <Button type="primary" icon={<ReloadOutlined />} loading={loading || refreshing} onClick={() => void refreshAgents()}>
              立即扫描
            </Button>
          </Space>
          <Space className="agent-last-scan">
            <Text type="secondary">最近扫描：</Text>
            <Text>{latestScan ? formatTimestamp(latestScan) : "-"}</Text>
            <span className="agent-scan-dot" />
            <Text className="agent-scan-ok">扫描完成</Text>
          </Space>
        </div>
      </div>

      {warning ? <div className="agent-warning">{warning}</div> : null}

      <div className="agent-stat-grid">
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-blue"><RobotOutlined /></div>
          <div>
            <Space>
              <Text type="secondary">Agent 总数</Text>
              <Tooltip title="后端合并进程、配置目录和静态扫描结果后的 Agent 数量"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{agents.length}</strong>
            <Text type="secondary">已识别 Agent</Text>
          </div>
        </Card>
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-green"><PlayCircleFilled /></div>
          <div>
            <Space>
              <Text type="secondary">正在运行</Text>
              <Tooltip title="当前存在运行进程或靶场运行服务的 Agent"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{runningCount}</strong>
            <Text className="agent-green-text">当前活跃</Text>
          </div>
        </Card>
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-slate"><PauseCircleOutlined /></div>
          <div>
            <Space>
              <Text type="secondary">未运行</Text>
              <Tooltip title="当前未发现运行进程，但仍可扫描静态配置和资源"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{stoppedCount}</strong>
            <Text type="secondary">当前停止</Text>
          </div>
        </Card>
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-orange"><WarningOutlined /></div>
          <div>
            <Space>
              <Text type="secondary">存在风险</Text>
              <Tooltip title="至少存在一个静态资源风险项的 Agent"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{riskCount}</strong>
            <Text className="agent-orange-text">需关注</Text>
          </div>
        </Card>
      </div>

      <div className={`agent-workbench ${agentListCollapsed ? "agent-workbench-collapsed" : ""}`}>
        <aside className="agent-list-panel">
          <div className="agent-list-header">
            {!agentListCollapsed ? (
              <div>
                <Text type="secondary">Agents</Text>
                <strong>{filteredAgents.length}</strong>
              </div>
            ) : (
              <Tooltip title="展开 Agents 列表" placement="right">
                <Button type="text" icon={<UnorderedListOutlined />} onClick={() => setAgentListCollapsed(false)} />
              </Tooltip>
            )}
            <Tooltip title={agentListCollapsed ? "展开列表" : "收起列表"}>
              <Button
                type="text"
                icon={agentListCollapsed ? <RightOutlined /> : <LeftOutlined />}
                onClick={() => setAgentListCollapsed((collapsed) => !collapsed)}
              />
            </Tooltip>
          </div>

          {!agentListCollapsed ? (
            <div className="agent-side-list">
              {filteredAgents.length ? filteredAgents.map((agent) => {
                const risk = agentRisk(agent);
                const meta = statusMeta[agent.status] ?? statusMeta.unknown;
                return (
                  <button
                    key={agent.id}
                    type="button"
                    className={`agent-side-item ${agent.id === selectedAgentId ? "agent-side-item-active" : ""}`}
                    onClick={() => selectAgent(agent)}
                    onDoubleClick={() => openAgentDetail(agent)}
                  >
                    <Avatar shape="square" className={avatarClass(agent)} icon={<RobotOutlined />} />
                    <span>
                      <Text strong>{agent.product}</Text>
                      <Text type="secondary">{agent.vendor || agentTypeLabel(agent)}</Text>
                      <Text className="agent-side-path">{primaryPath(agent)}</Text>
                    </span>
                    <em>
                      <span className="agent-status-dot" style={{ background: meta.dot }} />
                      {agent.riskResourceCount ? <b>{agent.riskResourceCount}</b> : <small>0</small>}
                      <Tag color={riskMeta[risk].color}>{riskMeta[risk].label}</Tag>
                    </em>
                  </button>
                );
              }) : (
                <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent" />
              )}
            </div>
          ) : (
            <div className="agent-list-rail">
              <Text>{filteredAgents.length}</Text>
            </div>
          )}
        </aside>

        <Card bordered={false} className="agent-table-card">
        <div className="agent-toolbar">
          <Input
            allowClear
            prefix={<SearchOutlined />}
            placeholder="搜索 Agent 名称、描述或路径..."
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <Select
            value={statusFilter}
            options={[
              { label: "全部状态", value: "all" },
              { label: "运行中", value: "running" },
              { label: "未运行", value: "stopped" },
              { label: "未知", value: "unknown" },
            ]}
            onChange={(value) => setStatusFilter(value)}
          />
          <Select value={typeFilter} options={typeOptions} onChange={(value) => setTypeFilter(value)} />
          <Select
            value={riskFilter}
            options={[
              { label: "全部风险等级", value: "all" },
              { label: "安全", value: "safe" },
              { label: "中风险", value: "medium" },
              { label: "高风险", value: "high" },
              { label: "严重风险", value: "critical" },
            ]}
            onChange={(value) => setRiskFilter(value)}
          />
          <Select
            value={sortKey}
            options={[
              { label: "按名称排序", value: "name" },
              { label: "按风险排序", value: "risk" },
              { label: "按状态排序", value: "status" },
              { label: "按资源数排序", value: "resources" },
            ]}
            onChange={(value) => setSortKey(value)}
          />
          
        </div>

        <Table
          rowKey={(row) => row.id}
          loading={loading || refreshing}
          columns={columns}
          dataSource={filteredAgents}
          pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (total) => `共 ${total} 条记录` }}
          locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有发现 Agent" /> }}
          scroll={{ x: 1220 }}
          rowClassName={(row) => row.id === selectedAgentId ? "agent-row-active" : ""}
          onRow={(row) => ({ onClick: () => openAgentDetail(row) })}
        />
        </Card>
      </div>

      <Drawer
        className="agent-detail-drawer"
        width={560}
        open={agentDetailOpen && Boolean(selectedAgent)}
        onClose={() => {
          setAgentDetailOpen(false);
          setSelectedAgentId(undefined);
        }}
        title={selectedAgent ? (
          <Space>
            <Avatar shape="square" className={avatarClass(selectedAgent)} icon={<RobotOutlined />} />
            <div>
              <Text strong>{selectedAgent.product}</Text>
              <br />
              <Text type="secondary">{selectedAgent.vendor} · {agentTypeLabel(selectedAgent)}</Text>
            </div>
          </Space>
        ) : "Agent 详情"}
      >
        {selectedAgent ? (
          <Space direction="vertical" size={16} className="agent-detail-stack">
            <Descriptions column={1} bordered size="small">
              <Descriptions.Item label="状态">
                <Space>
                  <span className="agent-status-dot" style={{ background: statusMeta[selectedAgent.status]?.dot }} />
                  {statusMeta[selectedAgent.status]?.label ?? selectedAgent.status}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <Tag color={riskMeta[agentRisk(selectedAgent)].color}>{riskMeta[agentRisk(selectedAgent)].label}</Tag>
              </Descriptions.Item>
              <Descriptions.Item label="版本">{agentVersion(selectedAgent)}</Descriptions.Item>
              <Descriptions.Item label="进程">{selectedAgent.pids.length ? selectedAgent.pids.join(", ") : "-"}</Descriptions.Item>
              <Descriptions.Item label="静态资源">{selectedAgent.staticResourceCount} 个资源 · {selectedAgent.riskResourceCount} 个风险 · {selectedAgent.criticalResourceCount} 个严重</Descriptions.Item>
              <Descriptions.Item label="最近扫描">{formatTimestamp(selectedAgent.lastStaticScanAt)}</Descriptions.Item>
              <Descriptions.Item label="数据来源"><Space wrap>{sourceTags(selectedAgent.source)}</Space></Descriptions.Item>
              <Descriptions.Item label="说明">{selectedAgent.description}</Descriptions.Item>
            </Descriptions>
            <Card size="small" title="配置位置">
              {selectedAgent.configRoots.length ? (
                <Space direction="vertical" size={6} className="agent-config-list">
                  {selectedAgent.configRoots.map((root) => (
                    <Text key={root.path} className="mono">{root.kind}: {root.path}</Text>
                  ))}
                </Space>
              ) : (
                <Text type="secondary">暂无配置路径</Text>
              )}
            </Card>
            <Card size="small" title="可执行文件">
              {selectedAgent.executableNames.length ? selectedAgent.executableNames.map((name) => <Tag key={name}>{name}</Tag>) : <Text type="secondary">暂无进程文件名</Text>}
            </Card>
          </Space>
        ) : null}
      </Drawer>
    </section>
  );
}
