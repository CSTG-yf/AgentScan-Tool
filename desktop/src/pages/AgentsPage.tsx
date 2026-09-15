import { useEffect, useMemo, useState } from "react";
import {
  AppstoreOutlined,
  CheckCircleFilled,
  CodeOutlined,
  CopyOutlined,
  DesktopOutlined,
  DownloadOutlined,
  InfoCircleOutlined,
  PauseCircleOutlined,
  PlayCircleFilled,
  ReloadOutlined,
  RobotOutlined,
  SearchOutlined,
} from "@ant-design/icons";
import { theme, ConfigProvider, Avatar, Button, Card, Descriptions, Drawer, Empty, Input, Select, Space, Spin, Table, Tag, Tooltip, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { formatUptime } from "../app/display";
import { exportAgentsReportPdf, getAgentDetail, getScanStatus, triggerAgentScan } from "../bridge";
import type { AgentInventory, AgentStatus } from "../types";

const { Text, Title } = Typography;

const detectionTheme = {
  algorithm: theme.defaultAlgorithm,
  token: {
    colorPrimary: "#2563eb",
    colorBgContainer: "#ffffff",
    colorBgElevated: "#ffffff",
    colorText: "#14213a",
    colorTextSecondary: "#475467",
    colorTextPlaceholder: "#667085",
    colorBorder: "#d9e1ee",
    colorBorderSecondary: "#e7ebf3",
    borderRadius: 8,
  },
};

const pageStyles = String.raw`
.agent-detection-surface .ant-select,
.agent-detection-surface .ant-select-selector,
.agent-detection-surface .ant-input,
.agent-detection-surface .ant-input-affix-wrapper {
  color: #14213a !important;
  background: #fff !important;
  border-color: #d9e1ee !important;
  border-radius: 6px !important;
}
.agent-detection-surface .ant-select-selection-item,
.agent-detection-surface .ant-select-selection-placeholder,
.agent-detection-surface .ant-select-content,
.agent-detection-surface .ant-select-placeholder {
  color: #475467 !important;
  -webkit-text-fill-color: #475467 !important;
  opacity: 1 !important;
}
.agent-detection-surface .ant-btn:not(.ant-btn-dangerous) {
  color: #14213a !important;
  -webkit-text-fill-color: #14213a !important;
  background: #fff !important;
  border-color: #cbd5e1 !important;
}
.agent-detection-surface .ant-btn:not(.ant-btn-dangerous):not(:disabled):hover {
  color: #175cd3 !important;
  background: #eff6ff !important;
  border-color: #93b4ef !important;
}
.agent-detection-surface .ant-btn:disabled { color: #667085 !important; -webkit-text-fill-color: #667085 !important; background: #f2f4f7 !important; }
.agent-detection-surface .detection-actions-cell .ant-btn-primary { color: #fff !important; -webkit-text-fill-color: #fff !important; background: #2563eb !important; border-color: #2563eb !important; }
.agent-detection-filter-popup.ant-select-dropdown,
.agent-detection-filter-menu .ant-dropdown-menu { color: #14213a !important; background: #fff !important; }
.agent-detection-filter-popup .ant-select-item,
.agent-detection-filter-menu .ant-dropdown-menu-item { color: #14213a !important; }
.agent-detection-filter-popup .ant-select-item-option-active { background: #f2f6fc !important; }
.agent-detection-filter-popup .ant-select-item-option-selected { color: #175cd3 !important; background: #eaf2ff !important; }

.agent-detection-detail-drawer .ant-drawer-content,
.agent-detection-detail-drawer .ant-drawer-header,
.agent-detection-detail-drawer .ant-drawer-body,
.agent-detection-detail-drawer .ant-drawer-footer,
.agent-detection-detail-drawer .ant-card,
.agent-detection-detail-drawer .ant-table,
.agent-detection-detail-drawer .ant-table-tbody > tr > td {
  color: #14213a !important;
  background: #fff !important;
  border-color: #e7ebf3 !important;
}
.agent-detection-detail-drawer .ant-typography,
.agent-detection-detail-drawer .ant-drawer-title,
.agent-detection-detail-drawer .ant-tabs-tab-btn,
.agent-detection-detail-drawer .ant-descriptions-item-content,
.agent-detection-detail-drawer .ant-empty-description,
.agent-detection-detail-drawer .ant-list-item-meta-title { color: #14213a !important; }
.agent-detection-detail-drawer .ant-typography-secondary,
.agent-detection-detail-drawer .ant-descriptions-item-label,
.agent-detection-detail-drawer .ant-drawer-close { color: #475467 !important; }
.agent-detection-detail-drawer .ant-descriptions-item-label,
.agent-detection-detail-drawer .ant-table-thead > tr > th { color: #475467 !important; background: #f8fafc !important; }
.agent-detection-detail-drawer .static-finding-card,
.agent-detection-detail-drawer .static-soft-note,
.agent-detection-detail-drawer .static-relation-item,
.agent-detection-detail-drawer .static-content-preview { color: #14213a !important; background: #f8fafc !important; border-color: #e7ebf3 !important; }

.agent-detection-surface .ant-tag { --tag-color: #64748b; color: #fff !important; -webkit-text-fill-color: #fff !important; background: var(--tag-color) !important; border-color: var(--tag-color) !important; }
.agent-detection-surface .ant-tag-blue,
.agent-detection-surface .ant-tag-processing { --tag-color: #2563eb; }
.agent-detection-surface .ant-tag-red,
.agent-detection-surface .ant-tag-error { --tag-color: #dc2626; }
.agent-detection-surface .ant-tag-green,
.agent-detection-surface .ant-tag-success { --tag-color: #15803d; }
.agent-detection-surface .ant-tag-orange,
.agent-detection-surface .ant-tag-volcano,
.agent-detection-surface .ant-tag-warning { --tag-color: #c2410c; }
.agent-detection-surface .ant-tag-gold { --tag-color: #a16207; }
.agent-detection-surface .ant-tag-purple { --tag-color: #7c3aed; }
.agent-detection-surface .ant-tag-geekblue { --tag-color: #4f46e5; }
.agent-detection-surface .ant-tag-cyan { --tag-color: #0e7490; }
.agent-detection-surface .ant-tag-magenta { --tag-color: #be185d; }
.agent-detection-surface .ant-tag-lime { --tag-color: #4d7c0f; }
.agent-detection-surface .ant-tag span { color: inherit !important; -webkit-text-fill-color: inherit !important; }
`;

type StatusFilter = AgentStatus | "all";
type DateSort = "none" | "asc" | "desc";

interface AgentsPageProps {
  agents: AgentInventory[];
  totalAgents?: number;
  warning: string;
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
}

const statusMeta: Record<AgentStatus, { label: string; color: string; dot: string; description: string }> = {
  running: { label: "运行中", color: "success", dot: "#18c56e", description: "当前活跃" },
  stopped: { label: "未运行", color: "default", dot: "#a8b3c5", description: "当前停止" },
  unknown: { label: "未知", color: "warning", dot: "#f5a623", description: "状态待确认" },
};

function normalizeStatus(value?: string): AgentStatus {
  if (value === "running" || value === "stopped" || value === "unknown") return value;
  if (value === "installed" || value === "missing") return "stopped";
  return "unknown";
}

function agentStatus(agent: AgentInventory): AgentStatus {
  return normalizeStatus(agent.runtimeStatus || agent.status || (agent.running ? "running" : "unknown"));
}

function agentTypeLabel(agent: AgentInventory) {
  const text = `${agent.kind} ${agent.description} ${(agent.executableNames ?? []).join(" ")}`.toLowerCase();
  if (text.includes("cli") || text.includes("terminal")) return "CLI Agent";
  if (text.includes("ide") || text.includes("editor")) return "IDE Agent";
  if (text.includes("platform")) return "Agent Platform";
  return agent.kind || "Desktop Agent";
}

function agentTypeIcon(agent: AgentInventory) {
  const label = agentTypeLabel(agent);
  if (label === "CLI Agent") return <CodeOutlined />;
  if (label === "IDE Agent") return <AppstoreOutlined />;
  if (label === "Agent Platform") return <RobotOutlined />;
  return <DesktopOutlined />;
}

function agentName(agent: AgentInventory) {
  return agent.product || agent.id || "未知 Agent";
}

function agentVersion(agent: AgentInventory) {
  return agent.version?.trim() || "待识别";
}

function primaryPath(agent: AgentInventory) {
  return agent.primaryPath || agent.configRoots?.[0]?.path || agent.installPaths?.[0] || agent.source || "-";
}

function firstSeen(agent: AgentInventory) {
  return agent.firstSeenScanAt || agent.startedAt;
}

function lastSeen(agent: AgentInventory) {
  return agent.lastSeenScanAt || agent.runtimeLatestAt || agent.lastStaticScanAt || agent.startedAt;
}

function discoveryLabel(agent: AgentInventory) {
  const status = (agent.discoveryStatus || agent.inventoryState || "").toLowerCase();
  if (status === "running") return "已识别 / 运行中";
  if (status === "installed" || status === "discovered") return "已识别";
  if (status === "runtime_observed") return "运行时观测";
  if (status === "missing") return "曾发现 / 当前缺失";
  return agent.discoveryStatus || agent.inventoryState || "待识别";
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

function timestampValue(value?: string) {
  if (!value) return 0;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function compareOptionalTime(left?: string, right?: string, order: DateSort = "desc") {
  const leftTime = timestampValue(left);
  const rightTime = timestampValue(right);
  if (leftTime === rightTime) return 0;
  if (!leftTime) return 1;
  if (!rightTime) return -1;
  return order === "asc" ? leftTime - rightTime : rightTime - leftTime;
}

function newestTimestamp(values: Array<string | undefined>) {
  return values.filter(Boolean).sort((left, right) => compareOptionalTime(left, right, "desc"))[0];
}

function sourceTags(source?: string) {
  return (source || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
    .map((item) => <Tag key={item}>{item}</Tag>);
}

function avatarClass(agent: AgentInventory) {
  const key = agent.id || agentName(agent);
  const index = Math.abs([...key].reduce((total, char) => total + char.charCodeAt(0), 0)) % 6;
  return `agent-avatar agent-avatar-${index}`;
}

function matchesQuery(agent: AgentInventory, query: string) {
  if (!query) return true;
  return [
    agent.id,
    agentName(agent),
    agent.vendor,
    agent.kind,
    agentVersion(agent),
    discoveryLabel(agent),
    primaryPath(agent),
    agent.source,
    agent.description,
    ...(agent.executableNames ?? []),
    ...(agent.installPaths ?? []),
    ...(agent.configRoots ?? []).map((root) => `${root.kind} ${root.path}`),
  ]
    .join(" ")
    .toLowerCase()
    .includes(query);
}

function pidsText(agent: AgentInventory) {
  return agent.pids?.length ? agent.pids.join(", ") : "-";
}

function reportFileName(agents: AgentInventory[]) {
  const prefix = agents.length === 1 ? `agent-${agentName(agents[0])}` : "agents-report";
  return `${prefix.replace(/[<>:"/\\|?*\u0000-\u001f]/g, "-")}-${new Date().toISOString().slice(0, 10)}.pdf`;
}

async function waitForAgentScan(scanId?: string): Promise<void> {
  if (!scanId) return;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = await getScanStatus(scanId);
    if (status.status === "completed") return;
    if (status.status === "failed") throw new Error(status.error || "Agent 发现扫描失败");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new Error("Agent 发现扫描等待超时，请稍后刷新");
}

export function AgentsPage({ agents, totalAgents, warning, loading = false, onRefresh }: AgentsPageProps) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [firstSeenSort, setFirstSeenSort] = useState<DateSort>("none");
  const [lastSeenSort, setLastSeenSort] = useState<DateSort>("desc");
  const [selectedAgentId, setSelectedAgentId] = useState<string>();
  const [selectedAgent, setSelectedAgent] = useState<AgentInventory>();
  const [agentDetailOpen, setAgentDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [listRefreshing, setListRefreshing] = useState(false);
  const [exporting, setExporting] = useState(false);

  const normalizedQuery = query.trim().toLowerCase();
  const filteredAgents = useMemo(() => {
    const rows = agents
      .filter((agent) => statusFilter === "all" || agentStatus(agent) === statusFilter)
      .filter((agent) => matchesQuery(agent, normalizedQuery));

    return [...rows].sort((left, right) => {
      if (firstSeenSort !== "none") {
        return compareOptionalTime(firstSeen(left), firstSeen(right), firstSeenSort) || agentName(left).localeCompare(agentName(right));
      }
      if (lastSeenSort !== "none") {
        return compareOptionalTime(lastSeen(left), lastSeen(right), lastSeenSort) || agentName(left).localeCompare(agentName(right));
      }
      return agentName(left).localeCompare(agentName(right));
    });
  }, [agents, firstSeenSort, lastSeenSort, normalizedQuery, statusFilter]);

  useEffect(() => {
    if (selectedAgentId && !agents.some((agent) => agent.id === selectedAgentId)) {
      setSelectedAgentId(undefined);
      setSelectedAgent(undefined);
      setAgentDetailOpen(false);
    }
  }, [agents, selectedAgentId]);

  const runningCount = agents.filter((agent) => agentStatus(agent) === "running").length;
  const stoppedCount = agents.filter((agent) => agentStatus(agent) === "stopped").length;
  const unknownCount = agents.filter((agent) => agentStatus(agent) === "unknown").length;
  const latestScan = newestTimestamp(agents.map(lastSeen));
  const displayAgentTotal = totalAgents && totalAgents > 0 ? totalAgents : agents.length;

  const openAgentDetail = async (agent: AgentInventory) => {
    setSelectedAgentId(agent.id);
    setSelectedAgent(agent);
    setAgentDetailOpen(true);
    setDetailLoading(true);
    try {
      const detail = await getAgentDetail(agent.id);
      setSelectedAgent(detail);
    } catch (error) {
      message.error(`读取 Agent 详情失败：${String(error)}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const refreshAgents = async () => {
    if (!onRefresh) return;
    setRefreshing(true);
    try {
      const idempotencyKey = globalThis.crypto?.randomUUID?.() ?? `agent-discovery-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const accepted = await triggerAgentScan("full", idempotencyKey);
      await waitForAgentScan(accepted.scan_id);
      await onRefresh();
      message.success("Agent 扫描完成");
    } catch (error) {
      message.error(`Agent 扫描失败：${String(error)}`);
    } finally {
      setRefreshing(false);
    }
  };

  const refreshAgentList = async () => {
    if (!onRefresh) return;
    setListRefreshing(true);
    try {
      await onRefresh();
    } catch (error) {
      message.error(`刷新 Agent 列表失败：${String(error)}`);
    } finally {
      setListRefreshing(false);
    }
  };

  const loadDetailsForExport = async (rows: AgentInventory[]) => {
    const results = await Promise.allSettled(rows.map((agent) => getAgentDetail(agent.id)));
    const details = results.map((result, index) => (result.status === "fulfilled" ? result.value : rows[index]));
    const failed = results.filter((result) => result.status === "rejected").length;
    if (failed > 0) {
      message.warning(`${failed} 个 Agent 详情读取失败，已使用列表信息导出`);
    }
    return details;
  };

  const exportReport = async (rows: AgentInventory[]) => {
    if (!rows.length) {
      message.warning("当前没有可导出的 Agent");
      return;
    }
    setExporting(true);
    try {
      const details = await loadDetailsForExport(rows);
      const path = await exportAgentsReportPdf(details, reportFileName(details));
      if (path) {
        message.success(`PDF 报告已导出：${path}`);
      } else {
        message.info("已取消导出");
      }
    } catch (error) {
      message.error(`导出 PDF 报告失败：${String(error)}`);
    } finally {
      setExporting(false);
    }
  };

  const columns: ColumnsType<AgentInventory> = [
    {
      title: "Agent 信息",
      dataIndex: "product",
      width: 340,
      render: (_, row) => (
        <div className="agent-info-cell">
          <Avatar shape="square" size={48} className={avatarClass(row)} icon={<RobotOutlined />} />
          <div>
            <Space size={6}>
              <Text strong className="agent-name">{agentName(row)}</Text>
              <CheckCircleFilled className="agent-verified" />
            </Space>
            <Text type="secondary">{row.vendor || "Unknown"}</Text>
            <Text className="agent-path">{primaryPath(row)}</Text>
          </div>
        </div>
      ),
    },
    {
      title: "状态",
      dataIndex: "runtimeStatus",
      width: 180,
      render: (_, row) => {
        const status = agentStatus(row);
        const meta = statusMeta[status];
        return (
          <Space direction="vertical" size={2}>
            <Space size={8}>
              <span className="agent-status-dot" style={{ background: meta.dot }} />
              <Text strong>{meta.label}</Text>
            </Space>
            <Text type="secondary">PID {pidsText(row)}</Text>
            {status === "running" ? <Text type="secondary">运行 {row.uptimeSec ? formatUptime(row.uptimeSec) : "-"}</Text> : null}
          </Space>
        );
      },
    },
    {
      title: "类型",
      width: 150,
      render: (_, row) => (
        <Space>
          <span className="agent-type-icon">{agentTypeIcon(row)}</span>
          <Tag color="blue">{agentTypeLabel(row)}</Tag>
        </Space>
      ),
    },
    {
      title: "版本",
      width: 120,
      render: (_, row) => <Text>{agentVersion(row)}</Text>,
    },
    {
      title: "发现状态",
      width: 150,
      render: (_, row) => <Tag color={agentStatus(row) === "running" ? "processing" : "default"}>{discoveryLabel(row)}</Tag>,
    },
    {
      title: "首次发现",
      width: 160,
      render: (_, row) => {
        const [date, time] = shortTimestamp(firstSeen(row));
        return (
          <Space direction="vertical" size={2}>
            <Text>{date}</Text>
            <Text type="secondary">{time}</Text>
          </Space>
        );
      },
    },
    {
      title: "最近发现",
      width: 160,
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
      className: "detection-actions-cell",
      width: 220,
      fixed: "right",
      render: (_, row) => (
        <Space onClick={(event) => event.stopPropagation()}>
          <Button size="small" type="primary" ghost onClick={() => void openAgentDetail(row)}>
            详情
          </Button>
          <Tooltip title="复制主路径">
            <Button size="small" icon={<CopyOutlined />} onClick={() => void navigator.clipboard?.writeText(primaryPath(row))} />
          </Tooltip>
          <Button size="small" onClick={() => void exportReport([row])}>
            导出 Agent
          </Button>
        </Space>
      ),
    },
  ];

  const detailAgent = selectedAgent;
  const detailStatus = detailAgent ? agentStatus(detailAgent) : "unknown";

  return (
    <ConfigProvider theme={detectionTheme}><section className="agent-management-page agent-detection-surface">
      <style>{pageStyles}</style>
      <div className="agent-page-header">
        <div>
          <Title level={2}>Agent 管理</Title>
          <Text type="secondary">发现并管理系统中的 AI Agent，查看运行状态、发现时间和安全上下文</Text>
        </div>
        <div className="agent-header-actions">
          <Space>
            <Button type="primary" icon={<DownloadOutlined />} loading={exporting} disabled={!agents.length} onClick={() => void exportReport(agents)}>
              导出报告
            </Button>
            <Tooltip title="重新读取数据库中的 Agent 列表，不执行扫描">
              <Button icon={<ReloadOutlined />} loading={listRefreshing} disabled={!onRefresh || loading || refreshing} onClick={() => void refreshAgentList()}>
                刷新列表
              </Button>
            </Tooltip>
            <Button type="primary" icon={<SearchOutlined />} loading={refreshing} disabled={!onRefresh || loading || listRefreshing} onClick={() => void refreshAgents()}>
              重新扫描
            </Button>
          </Space>
          <Space className="agent-last-scan">
            <Text type="secondary">最近发现：</Text>
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
            <strong>{displayAgentTotal}</strong>
            <Text type="secondary">{displayAgentTotal === agents.length ? "已识别 Agent" : `当前加载 ${agents.length} 条`}</Text>
          </div>
        </Card>
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-green"><PlayCircleFilled /></div>
          <div>
            <Space>
              <Text type="secondary">正在运行</Text>
              <Tooltip title="当前存在运行进程的 Agent"><InfoCircleOutlined /></Tooltip>
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
              <Tooltip title="已发现但当前没有运行进程的 Agent"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{stoppedCount}</strong>
            <Text type="secondary">当前停止</Text>
          </div>
        </Card>
        <Card bordered={false} className="agent-stat-card">
          <div className="agent-stat-icon agent-stat-orange"><InfoCircleOutlined /></div>
          <div>
            <Space>
              <Text type="secondary">状态未知</Text>
              <Tooltip title="缺少可信运行态信号的 Agent"><InfoCircleOutlined /></Tooltip>
            </Space>
            <strong>{unknownCount}</strong>
            <Text type="secondary">待确认</Text>
          </div>
        </Card>
      </div>

      <div className="agent-workbench">
        <Card bordered={false} className="agent-table-card">
          <div className="agent-toolbar">
            <Input
              allowClear
              prefix={<SearchOutlined />}
              placeholder="搜索 Agent 名称、厂商、路径或版本..."
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
            <Select
              classNames={{ popup: { root: "agent-detection-filter-popup" } }}
              value={statusFilter}
              options={[
                { label: "全部运行状态", value: "all" },
                { label: "运行中", value: "running" },
                { label: "未运行", value: "stopped" },
                { label: "未知", value: "unknown" },
              ]}
              onChange={(value) => setStatusFilter(value)}
            />
            <Select
              classNames={{ popup: { root: "agent-detection-filter-popup" } }}
              value={firstSeenSort}
              options={[
                { label: "默认", value: "none" },
                { label: "首次发现从早到晚", value: "asc" },
                { label: "首次发现从晚到早", value: "desc" },
              ]}
              onChange={(value) => {
                setFirstSeenSort(value);
                if (value !== "none") setLastSeenSort("none");
              }}
            />
            <Select
              classNames={{ popup: { root: "agent-detection-filter-popup" } }}
              value={lastSeenSort}
              options={[
                { label: "默认", value: "none" },
                { label: "最近发现从晚到早", value: "desc" },
                { label: "最近发现从早到晚", value: "asc" },
              ]}
              onChange={(value) => {
                setLastSeenSort(value);
                if (value !== "none") setFirstSeenSort("none");
              }}
            />
          </div>

          <Table
            rowKey={(row) => row.id}
            loading={loading || refreshing || listRefreshing}
            columns={columns}
            dataSource={filteredAgents}
            pagination={{ pageSize: 10, showSizeChanger: true, showTotal: (total) => `共 ${total} 条记录` }}
            locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有发现 Agent" /> }}
            scroll={{ x: 1320 }}
            rowClassName={(row) => row.id === selectedAgentId ? "agent-row-active" : ""}
            onRow={(row) => ({ onClick: () => void openAgentDetail(row) })}
          />
        </Card>
      </div>

      <Drawer
        className="agent-detail-drawer agent-detection-detail-drawer agent-detection-surface"
        width={620}
        open={agentDetailOpen && Boolean(detailAgent)}
        onClose={() => {
          setAgentDetailOpen(false);
          setSelectedAgentId(undefined);
          setSelectedAgent(undefined);
        }}
        title={detailAgent ? (
          <Space>
            <Avatar shape="square" className={avatarClass(detailAgent)} icon={<RobotOutlined />} />
            <div>
              <Text strong>{agentName(detailAgent)}</Text>
              <br />
              <Text type="secondary">{detailAgent.vendor || "Unknown"} · {agentTypeLabel(detailAgent)}</Text>
            </div>
          </Space>
        ) : "Agent 详情"}
        extra={detailAgent ? (
          <Button size="small" icon={<DownloadOutlined />} loading={exporting} onClick={() => void exportReport([detailAgent])}>
            导出 Agent
          </Button>
        ) : null}
      >
        {detailAgent ? (
          <Spin spinning={detailLoading}>
            <Space direction="vertical" size={16} className="agent-detail-stack">
              <Descriptions column={1} bordered size="small">
                <Descriptions.Item label="Agent 信息">
                  <Space wrap>
                    <Tag>name</Tag><Text>{agentName(detailAgent)}</Text>
                    <Tag>vendor</Tag><Text>{detailAgent.vendor || "Unknown"}</Text>
                    <Tag>primary_path</Tag><Text className="mono">{primaryPath(detailAgent)}</Text>
                  </Space>
                </Descriptions.Item>
                <Descriptions.Item label="状态">
                  <Space wrap>
                    <Tag>runtime_status</Tag>
                    <span className="agent-status-dot" style={{ background: statusMeta[detailStatus].dot }} />
                    <Text>{statusMeta[detailStatus].label}</Text>
                    <Tag>pids</Tag><Text>{pidsText(detailAgent)}</Text>
                  </Space>
                </Descriptions.Item>
                <Descriptions.Item label="类型"><Tag>kind</Tag> {agentTypeLabel(detailAgent)}</Descriptions.Item>
                <Descriptions.Item label="版本"><Tag>version</Tag> {agentVersion(detailAgent)}</Descriptions.Item>
                <Descriptions.Item label="发现状态"><Tag>discovery_status</Tag> {discoveryLabel(detailAgent)}</Descriptions.Item>
                <Descriptions.Item label="首次发现"><Tag>first_seen_at</Tag> {formatTimestamp(firstSeen(detailAgent))}</Descriptions.Item>
                <Descriptions.Item label="最近发现"><Tag>last_seen_at</Tag> {formatTimestamp(lastSeen(detailAgent))}</Descriptions.Item>
                <Descriptions.Item label="静态资源">{detailAgent.staticResourceCount} 个资源 · {detailAgent.riskResourceCount} 个风险 · {detailAgent.criticalResourceCount} 个严重</Descriptions.Item>
                <Descriptions.Item label="运行检测">{detailAgent.runtimeDetectionCount ?? 0} 个检测 · {detailAgent.runtimeAttackCount ?? 0} 个攻击 · {detailAgent.runtimeBlockedCount ?? 0} 个阻断</Descriptions.Item>
                <Descriptions.Item label="数据来源"><Space wrap>{sourceTags(detailAgent.source)}</Space></Descriptions.Item>
                <Descriptions.Item label="说明">{detailAgent.description || "-"}</Descriptions.Item>
              </Descriptions>

              <Card size="small" title="配置位置">
                {detailAgent.configRoots?.length ? (
                  <Space direction="vertical" size={6} className="agent-config-list">
                    {detailAgent.configRoots.map((root) => (
                      <Text key={root.path} className="mono">{root.kind}: {root.path}</Text>
                    ))}
                  </Space>
                ) : (
                  <Text type="secondary">暂无配置路径</Text>
                )}
              </Card>

              <Card size="small" title="可执行文件">
                {detailAgent.executableNames?.length ? detailAgent.executableNames.map((name) => <Tag key={name}>{name}</Tag>) : <Text type="secondary">暂无进程文件名</Text>}
              </Card>

              {detailAgent.processes?.length ? (
                <Card size="small" title="进程">
                  <Table
                    size="small"
                    rowKey={(row) => `${row.pid}-${row.name}`}
                    pagination={false}
                    dataSource={detailAgent.processes}
                    columns={[
                      { title: "PID", dataIndex: "pid", width: 90 },
                      { title: "名称", dataIndex: "name" },
                      { title: "启动时间", render: (_, row) => formatTimestamp(row.startedAt) },
                    ]}
                  />
                </Card>
              ) : null}
            </Space>
          </Spin>
        ) : null}
      </Drawer>
    </section></ConfigProvider>
  );
}
