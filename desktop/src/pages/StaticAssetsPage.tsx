import { useCallback, useEffect, useMemo, useState } from "react";
import { CopyOutlined, DownloadOutlined, EyeOutlined, FileTextOutlined, ReloadOutlined, SearchOutlined, SecurityScanOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Descriptions, Drawer, Empty, Input, List, message, Select, Space, Spin, Table, Tabs, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { staticRiskTag } from "../app/display";
import { isRiskResource, staticRiskMeta, staticTypeMeta } from "../data/staticAssets";
import {
  getStaticResourceAgents,
  getStaticResourceContent,
  getStaticResourceDetail,
  getStaticResourceFindings,
  getStaticResourceRelations,
  getStaticResources,
  getStaticResourceSummary,
  triggerStaticResourceRescan,
  triggerStaticResourceScan,
} from "../bridge";
import type {
  StaticResourceAgentSummary,
  StaticResourceContentResponse,
  StaticResourceDetailResponse,
  StaticResourceFindingItem,
  StaticResourceListItem,
  StaticResourceRelationItem,
  StaticResourceSummaryResponse,
} from "../types";

const { Text, Title } = Typography;

const PAGE_SIZE = 20;

/** API resource_type (lowercase) → display type used by the type meta table. */
const API_TYPE_TO_DISPLAY: Record<string, string> = {
  config: "Config",
  skill: "Skills",
  mcp: "MCP",
  plugin: "Plugin",
  prompt: "Prompt",
  credential: "Credential",
  environment: "Environment",
};

const DISPLAY_TYPE_TO_API: Record<string, string> = Object.fromEntries(
  Object.entries(API_TYPE_TO_DISPLAY).map(([api, display]) => [display, api]),
);

const ALL_TYPES = Object.keys(API_TYPE_TO_DISPLAY);

/** API risk_level → StaticRisk (clean maps onto the neutral "info" bucket). */
function apiRisk(risk: string): "critical" | "high" | "medium" | "low" | "info" {
  const normalized = (risk ?? "").toLowerCase();
  if (normalized === "critical" || normalized === "high" || normalized === "medium" || normalized === "low") return normalized;
  return "info";
}

const STATUS_META: Record<string, { color: string; label: string }> = {
  discovered: { color: "processing", label: "已发现" },
  review: { color: "success", label: "已复核" },
  needs_review: { color: "warning", label: "待复核" },
  missing: { color: "error", label: "已消失" },
  changed: { color: "warning", label: "已变更" },
  ignored: { color: "default", label: "已忽略" },
};

const SCAN_STATUS_META: Record<string, { color: string; label: string }> = {
  completed: { color: "success", label: "已完成" },
  pending: { color: "processing", label: "待扫描" },
  never_scanned: { color: "default", label: "从未扫描" },
};

function typeTag(apiType: string) {
  const display = API_TYPE_TO_DISPLAY[apiType] ?? "Config";
  const meta = staticTypeMeta[display as keyof typeof staticTypeMeta] ?? staticTypeMeta.Config;
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

function statusTag(status: string) {
  const meta = STATUS_META[status] ?? STATUS_META.discovered;
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

function scanStatusTag(scanStatus: string) {
  const meta = SCAN_STATUS_META[scanStatus] ?? SCAN_STATUS_META.never_scanned;
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

function formatTimestamp(value?: string) {
  if (!value) return "尚无扫描结果";
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

function formatSize(size?: number) {
  if (size === undefined || size === null) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

interface StaticAssetsPageProps {
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
}

type TypeFilter = string | "all";
type RiskFilter = string | "all";
type StatusFilter = string | "all";

export function StaticAssetsPage({ loading = false }: StaticAssetsPageProps) {
  // ── Agent list (left panel) ────────────────────────────────────────────
  const [agents, setAgents] = useState<StaticResourceAgentSummary[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [agentsError, setAgentsError] = useState<string>();
  const [selectedAgentId, setSelectedAgentId] = useState<string>();

  // ── Summary (header + type cards) ─────────────────────────────────────
  const [summary, setSummary] = useState<StaticResourceSummaryResponse>();

  // ── Resource table (server-side filters + pagination) ─────────────────
  const [selectedType, setSelectedType] = useState<TypeFilter>("all");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [page, setPage] = useState(1);
  const [listItems, setListItems] = useState<StaticResourceListItem[]>([]);
  const [listTotal, setListTotal] = useState(0);
  const [listLoading, setListLoading] = useState(false);
  const [listReloadNonce, setListReloadNonce] = useState(0);

  // ── Drawer (detail + lazy tabs) ────────────────────────────────────────
  const [resourceDetailOpen, setResourceDetailOpen] = useState(false);
  const [detailResourceId, setDetailResourceId] = useState<string>();
  const [detail, setDetail] = useState<StaticResourceDetailResponse>();
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailTab, setDetailTab] = useState("overview");
  const [findings, setFindings] = useState<StaticResourceFindingItem[]>([]);
  const [findingsSummary, setFindingsSummary] = useState<Record<string, number>>({});
  const [findingsScannedAt, setFindingsScannedAt] = useState<string>();
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [content, setContent] = useState<StaticResourceContentResponse>();
  const [contentLoading, setContentLoading] = useState(false);
  const [relations, setRelations] = useState<StaticResourceRelationItem[]>([]);
  const [relationsLoading, setRelationsLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  const inTauri = "__TAURI_INTERNALS__" in window;

  // Debounce the search keyword.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(query.trim()), 350);
    return () => clearTimeout(timer);
  }, [query]);

  const loadAgents = useCallback(async (selectFirst = true) => {
    setAgentsLoading(true);
    setAgentsError(undefined);
    try {
      const response = await getStaticResourceAgents();
      setAgents(response.items ?? []);
      if (selectFirst && response.items?.length) {
        setSelectedAgentId((current) => current ?? response.items[0].agent_id);
      }
    } catch (error) {
      setAgentsError(String(error));
      setAgents([]);
    } finally {
      setAgentsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAgents();
  }, [loadAgents]);

  // Auto-select the first agent once the list arrives.
  useEffect(() => {
    if (!agents.length) {
      setSelectedAgentId(undefined);
      return;
    }
    if (!selectedAgentId || !agents.some((agent) => agent.agent_id === selectedAgentId)) {
      setSelectedAgentId(agents[0].agent_id);
    }
  }, [agents, selectedAgentId]);

  // Summary follows the selected agent.
  useEffect(() => {
    if (!selectedAgentId) {
      setSummary(undefined);
      return;
    }
    let cancelled = false;
    getStaticResourceSummary(selectedAgentId)
      .then((response) => {
        if (!cancelled) setSummary(response);
      })
      .catch(() => {
        if (!cancelled) setSummary(undefined);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedAgentId]);

  // Resource table follows every filter change (server-side).
  useEffect(() => {
    if (!selectedAgentId) {
      setListItems([]);
      setListTotal(0);
      return;
    }
    let cancelled = false;
    setListLoading(true);
    getStaticResources({
      agentId: selectedAgentId,
      resourceType: selectedType === "all" ? undefined : DISPLAY_TYPE_TO_API[selectedType],
      riskLevel: riskFilter === "all" ? undefined : riskFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
      keyword: debouncedQuery || undefined,
      page,
      pageSize: PAGE_SIZE,
    })
      .then((response) => {
        if (cancelled) return;
        setListItems(response.items ?? []);
        setListTotal(response.total ?? 0);
      })
      .catch((error) => {
        if (cancelled) return;
        setListItems([]);
        setListTotal(0);
        message.error(`加载资源列表失败：${String(error)}`);
      })
      .finally(() => {
        if (!cancelled) setListLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedAgentId, selectedType, riskFilter, statusFilter, debouncedQuery, page, listReloadNonce]);

  // Reset pagination whenever the filter shape (not the page) changes.
  useEffect(() => {
    setPage(1);
  }, [selectedAgentId, selectedType, riskFilter, statusFilter, debouncedQuery]);

  const selectedAgent = useMemo(
    () => agents.find((agent) => agent.agent_id === selectedAgentId),
    [agents, selectedAgentId],
  );

  const refreshListAndSummary = useCallback(async () => {
    if (selectedAgentId) {
      getStaticResourceSummary(selectedAgentId).then(setSummary).catch(() => undefined);
    }
    // Bump the nonce so the list effect re-runs even when page is unchanged.
    setListReloadNonce((nonce) => nonce + 1);
  }, [selectedAgentId]);

  // ── Drawer lazy loaders ────────────────────────────────────────────────
  const loadDetail = useCallback(async (resourceId: string) => {
    setDetailLoading(true);
    try {
      setDetail(await getStaticResourceDetail(resourceId));
    } catch (error) {
      message.error(`加载资源详情失败：${String(error)}`);
      setDetail(undefined);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const loadFindings = useCallback(async (resourceId: string) => {
    setFindingsLoading(true);
    try {
      const response = await getStaticResourceFindings(resourceId);
      setFindings(response.items ?? []);
      setFindingsSummary(response.summary ?? {});
      setFindingsScannedAt(response.scanned_at);
    } catch (error) {
      message.error(`加载风险发现失败：${String(error)}`);
      setFindings([]);
    } finally {
      setFindingsLoading(false);
    }
  }, []);

  const loadContent = useCallback(async (resourceId: string) => {
    setContentLoading(true);
    try {
      setContent(await getStaticResourceContent(resourceId));
    } catch (error) {
      message.error(`加载资源内容失败：${String(error)}`);
      setContent(undefined);
    } finally {
      setContentLoading(false);
    }
  }, []);

  const loadRelations = useCallback(async (resourceId: string) => {
    setRelationsLoading(true);
    try {
      const response = await getStaticResourceRelations(resourceId);
      setRelations(response.items ?? []);
    } catch (error) {
      message.error(`加载关联资源失败：${String(error)}`);
      setRelations([]);
    } finally {
      setRelationsLoading(false);
    }
  }, []);

  // Tab switch drives lazy loading.
  const handleDetailTabChange = useCallback(
    (tab: string) => {
      setDetailTab(tab);
      if (!detailResourceId) return;
      if (tab === "risk") void loadFindings(detailResourceId);
      if (tab === "content") void loadContent(detailResourceId);
      if (tab === "relations") void loadRelations(detailResourceId);
    },
    [detailResourceId, loadContent, loadFindings, loadRelations],
  );

  const handleOpenResource = useCallback(
    (resource: StaticResourceListItem) => {
      setDetailResourceId(resource.resource_id);
      setResourceDetailOpen(true);
      setDetailTab("overview");
      setFindings([]);
      setFindingsSummary({});
      setContent(undefined);
      setRelations([]);
      void loadDetail(resource.resource_id);
    },
    [loadDetail],
  );

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgentId(agentId);
    setSelectedType("all");
    setRiskFilter("all");
    setStatusFilter("all");
    setQuery("");
    setResourceDetailOpen(false);
    setDetailResourceId(undefined);
  };

  const handleRefresh = async () => {
    await loadAgents(false);
    await refreshListAndSummary();
    if (detailResourceId) await loadDetail(detailResourceId);
    message.success("已刷新静态资源数据");
  };

  const handleRescanAgent = async () => {
    if (!selectedAgentId) return;
    setRescanning(true);
    try {
      await triggerStaticResourceRescan(selectedAgentId);
      message.success("已提交重新扫描任务，稍后刷新查看结果");
    } catch (error) {
      message.error(`提交重新扫描失败：${String(error)}`);
    } finally {
      setRescanning(false);
    }
  };

  const handleScanOne = async () => {
    if (!detailResourceId) return;
    setScanning(true);
    try {
      await triggerStaticResourceScan(detailResourceId);
      message.success("已提交扫描任务，稍后自动刷新");
      // Give the backend a moment, then refresh what we are looking at.
      setTimeout(() => {
        void loadDetail(detailResourceId);
        void loadFindings(detailResourceId);
        void refreshListAndSummary();
      }, 2500);
    } catch (error) {
      message.error(`提交扫描失败：${String(error)}`);
    } finally {
      setScanning(false);
    }
  };

  const copyResourcePath = async (path?: string) => {
    if (!path) return;
    try {
      await navigator.clipboard.writeText(path);
      message.success("资源路径已复制");
    } catch {
      message.warning("复制失败，请在详情中手动复制路径");
    }
  };

  const downloadResourceSummary = (resource: StaticResourceDetailResponse | StaticResourceListItem | undefined) => {
    if (!resource) return;
    const lines = [
      `资源名称：${resource.name}`,
      `类型：${resource.resource_type}`,
      `路径：${resource.path}`,
      `风险等级：${resource.risk_level}`,
      `状态：${resource.status}`,
      `发现时间：${formatTimestamp("updated_at" in resource ? resource.updated_at : undefined)}`,
    ];
    if ("finding_count" in resource) lines.push(`风险项数量：${resource.finding_count}`);
    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${resource.name.replace(/[\\/:*?"<>|]/g, "_")}.scan-summary.txt`;
    anchor.click();
    URL.revokeObjectURL(url);
    message.success("资源扫描摘要已导出");
  };

  const columns: ColumnsType<StaticResourceListItem> = [
    {
      title: "名称",
      dataIndex: "name",
      width: 220,
      render: (_, resource) => (
        <Space direction="vertical" size={0}>
          <Text strong>{resource.name}</Text>
          <Space size={4}>
            {resource.malicious ? <Tag color="red">恶意</Tag> : null}
            {resource.finding_count ? <Text type="secondary">{resource.finding_count} 项发现</Text> : null}
          </Space>
        </Space>
      ),
    },
    {
      title: "类型",
      dataIndex: "resource_type",
      width: 110,
      render: (value) => typeTag(value),
    },
    {
      title: "位置",
      dataIndex: "path",
      render: (value) => <Text className="static-location mono">{value}</Text>,
    },
    {
      title: "风险等级",
      dataIndex: "risk_level",
      width: 118,
      render: (value) => staticRiskTag(apiRisk(value)),
    },
    {
      title: "状态",
      dataIndex: "status",
      width: 108,
      render: (value) => statusTag(value),
    },
    {
      title: "更新时间",
      dataIndex: "updated_at",
      width: 168,
      render: (value) => <Text type="secondary">{formatTimestamp(value)}</Text>,
    },
  ];

  const typeCards = useMemo(() => {
    const byType = new Map(summary?.by_type?.map((item) => [item.resource_type, item]) ?? []);
    return ALL_TYPES.map((apiType) => {
      const item = byType.get(apiType);
      return {
        apiType,
        display: API_TYPE_TO_DISPLAY[apiType],
        count: item?.count ?? 0,
        risks: item?.risk_count ?? 0,
        malicious: item?.malicious_count ?? 0,
      };
    });
  }, [summary]);

  const selectedTypeLabel =
    selectedType === "all" ? "全部资源" : staticTypeMeta[(API_TYPE_TO_DISPLAY[selectedType] ?? "Config") as keyof typeof staticTypeMeta]?.label ?? selectedType;

  const summaryHeader = summary ?? {
    total_resources: listTotal,
    resource_type_count: typeCards.filter((card) => card.count > 0).length,
    risk_resource_count: 0,
    malicious_resource_count: 0,
    critical_resource_count: 0,
  };

  return (
    <section className="static-assets-page">
      <div className="static-page-header">
        <div>
          <Text className="eyebrow">STATIC ASSET INVENTORY</Text>
          <Title level={2}>静态资源</Title>
          <Text type="secondary">基于 Agent 资源规则发现并检测配置、技能、插件、MCP 服务、提示词、凭据与环境变量。</Text>
        </div>
        <div className="static-header-actions">
          <Button
            type="primary"
            icon={<SecurityScanOutlined />}
            loading={rescanning}
            disabled={!selectedAgentId}
            onClick={() => void handleRescanAgent()}
          >
            重新扫描 Agent
          </Button>
          <Button icon={<ReloadOutlined />} loading={agentsLoading || listLoading} onClick={() => void handleRefresh()}>
            刷新结果
          </Button>
        </div>
      </div>

      {!inTauri ? (
        <Alert type="warning" showIcon message="浏览器预览模式不会连接 Go 后端；请在桌面应用中查看真实静态资源扫描结果。" />
      ) : null}
      {agentsError ? <Alert type="error" showIcon message={agentsError} /> : null}

      <div className="static-summary-grid">
        <Card bordered={false} className="static-metric-card">
          <Text type="secondary">系统内 Agent</Text>
          <div className="static-metric-value"><span>{agents.length}</span><small>Agents</small></div>
          <Text>来自后端 Agent 发现与资源归属</Text>
        </Card>
        <Card bordered={false} className="static-metric-card">
          <Text type="secondary">当前 Agent 资源</Text>
          <div className="static-metric-value resource"><span>{summaryHeader.total_resources}</span><small>Resources</small></div>
          <Text>{summaryHeader.resource_type_count} 种资源类型</Text>
        </Card>
        <Card bordered={false} className="static-metric-card static-metric-card-risk">
          <Text type="secondary">风险资源数量</Text>
          <div className="static-metric-value warning"><span>{summaryHeader.risk_resource_count}</span><small>Risks</small></div>
          <Text>中风险及以上资源需要复核</Text>
        </Card>
        <Card bordered={false} className="static-metric-card static-metric-card-critical">
          <Text type="secondary">严重风险数量</Text>
          <div className="static-metric-value danger"><span>{summaryHeader.critical_resource_count}</span><small>Critical</small></div>
          <Text>恶意资源 {summaryHeader.malicious_resource_count} 个</Text>
        </Card>
      </div>

      <div className="static-assets-workbench">
        <aside className="static-agent-panel">
          <div className="static-panel-heading">
            <Text type="secondary">Agents</Text>
            <Tag color="blue">{agents.length}</Tag>
          </div>
          <div className="static-agent-list">
            {agentsLoading && !agents.length ? (
              <div style={{ padding: 24, textAlign: "center" }}><Spin /></div>
            ) : agents.length ? agents.map((agent) => (
              <button
                key={agent.agent_id}
                className={`static-agent-item ${agent.agent_id === selectedAgentId ? "static-agent-item-active" : ""}`}
                type="button"
                onClick={() => handleSelectAgent(agent.agent_id)}
              >
                <span className="static-agent-name">{agent.name}</span>
                <span className="static-agent-source">{agent.agent_type || agent.kind || "agent"}</span>
                <span className="static-agent-meta">
                  <span>{agent.resource_count} Resources</span>
                  <span className={agent.risk_resource_count ? "static-agent-risk" : ""}>{agent.risk_resource_count} Risks</span>
                </span>
              </button>
            )) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无 Agent 资源" />}
          </div>
        </aside>

        <main className="static-resource-panel">
          {selectedAgent ? (
            <>
              <div className="static-agent-context">
                <div>
                  <Title level={3}>{selectedAgent.name}</Title>
                  <Text type="secondary">
                    {summaryHeader.total_resources} Resources · {summaryHeader.resource_type_count} Types · {summaryHeader.risk_resource_count} Risks
                    {summaryHeader.critical_resource_count ? ` · ${summaryHeader.critical_resource_count} Critical` : ""}
                    {summaryHeader.malicious_resource_count ? ` · ${summaryHeader.malicious_resource_count} Malicious` : ""}
                  </Text>
                </div>
                <Text className="mono static-agent-path">{selectedAgent.agent_id}</Text>
              </div>

              <div className="static-type-grid">
                <button
                  className={`static-type-card static-type-card-all ${selectedType === "all" ? "static-type-card-active" : ""}`}
                  type="button"
                  onClick={() => setSelectedType("all")}
                >
                  <span>全部资源</span>
                  <strong>{summaryHeader.total_resources} Resources</strong>
                  <em>{summaryHeader.risk_resource_count} Risks</em>
                </button>
                {typeCards.map((card) => (
                  <button
                    key={card.apiType}
                    className={`static-type-card ${card.count === 0 ? "static-type-card-empty" : ""} ${selectedType === card.apiType ? "static-type-card-active" : ""}`}
                    type="button"
                    onClick={() => setSelectedType(card.apiType)}
                  >
                    <span>{staticTypeMeta[card.display as keyof typeof staticTypeMeta]?.label ?? card.display}</span>
                    <strong>{card.count} Resources</strong>
                    <em className={card.risks ? "static-type-risk" : ""}>{card.risks} Risks</em>
                  </button>
                ))}
              </div>

              <Card bordered={false} className="static-table-card">
                <div className="static-filter-bar">
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索资源名称或路径"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  <Select
                    value={selectedType}
                    onChange={(value) => setSelectedType(value as TypeFilter)}
                    options={[
                      { value: "all", label: "全部类型" },
                      ...typeCards.map((card) => ({
                        value: card.apiType,
                        label: staticTypeMeta[card.display as keyof typeof staticTypeMeta]?.label ?? card.display,
                      })),
                    ]}
                  />
                  <Select
                    value={riskFilter}
                    onChange={(value) => setRiskFilter(value as RiskFilter)}
                    options={[
                      { value: "all", label: "全部风险" },
                      ...Object.entries(staticRiskMeta).map(([risk, meta]) => ({ value: risk, label: meta.label })),
                    ]}
                  />
                  <Select
                    value={statusFilter}
                    onChange={(value) => setStatusFilter(value as StatusFilter)}
                    options={[
                      { value: "all", label: "全部状态" },
                      ...Object.entries(STATUS_META).map(([status, meta]) => ({ value: status, label: meta.label })),
                    ]}
                  />
                </div>
                <div className="static-table-title">
                  <Text strong>{selectedTypeLabel}</Text>
                  <Text type="secondary">{listTotal} 项资源</Text>
                </div>
                <Table
                  rowKey="resource_id"
                  columns={columns}
                  dataSource={listItems}
                  loading={listLoading || loading}
                  locale={{ emptyText: "当前筛选条件下没有资源" }}
                  pagination={{
                    current: page,
                    pageSize: PAGE_SIZE,
                    total: listTotal,
                    showSizeChanger: false,
                    onChange: (next) => setPage(next),
                  }}
                  rowClassName={(resource) => (resource.resource_id === detailResourceId ? "static-table-row-active" : "")}
                  onRow={(resource) => ({ onClick: () => handleOpenResource(resource) })}
                  scroll={{ x: 960 }}
                />
              </Card>
            </>
          ) : (
            <Card bordered={false} className="static-table-card">
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无后端静态资源扫描结果" />
            </Card>
          )}
        </main>
      </div>

      <Drawer
        className="static-detail-drawer"
        width={520}
        open={resourceDetailOpen}
        onClose={() => {
          setResourceDetailOpen(false);
          setDetailResourceId(undefined);
        }}
        title={
          detail ? (
            <div className="static-detail-title">
              <Text strong>{detail.name}</Text>
              <Space size={6}>
                {typeTag(detail.resource_type)}
                {staticRiskTag(apiRisk(detail.risk_level))}
                {detail.malicious ? <Tag color="red">恶意</Tag> : null}
              </Space>
            </div>
          ) : null
        }
        footer={
          detail ? (
            <div className="static-detail-actions">
              <Button icon={<SecurityScanOutlined />} loading={scanning} onClick={() => void handleScanOne()}>重新扫描</Button>
              <Button icon={<EyeOutlined />} onClick={() => handleDetailTabChange("content")}>查看内容</Button>
              <Button icon={<CopyOutlined />} onClick={() => void copyResourcePath(detail.path)}>复制路径</Button>
              <Button icon={<DownloadOutlined />} onClick={() => downloadResourceSummary(detail)}>导出摘要</Button>
            </div>
          ) : null
        }
      >
        {detailLoading && !detail ? (
          <div style={{ padding: 48, textAlign: "center" }}><Spin /></div>
        ) : detail ? (
          <Tabs
            activeKey={detailTab}
            onChange={handleDetailTabChange}
            items={[
              {
                key: "overview",
                label: "概览",
                children: (
                  <Space direction="vertical" size="middle" className="static-detail-stack">
                    <Descriptions
                      column={1}
                      size="small"
                      items={[
                        { key: "name", label: "资源名称", children: detail.name },
                        { key: "type", label: "类型", children: typeTag(detail.resource_type) },
                        { key: "agent", label: "所属 Agent", children: detail.agent?.name ?? "-" },
                        { key: "path", label: "路径", children: <Text className="mono static-detail-path">{detail.path}</Text> },
                        { key: "size", label: "大小", children: formatSize(detail.size) },
                        { key: "mtime", label: "最近扫描", children: formatTimestamp(detail.last_scan_at) },
                        { key: "permission", label: "文件权限", children: detail.permission ?? "-" },
                        { key: "status", label: "状态", children: statusTag(detail.status) },
                        { key: "scan", label: "扫描状态", children: scanStatusTag(detail.scan_status) },
                        { key: "hash", label: "Hash", children: <Text className="mono static-detail-path">{detail.content_hash || "-"}</Text> },
                        ...(detail.resource_rule ? [{ key: "rule", label: "发现规则", children: `${detail.resource_rule.name} (#${detail.resource_rule.rule_id})` }] : []),
                        ...(detail.scan_profile ? [{ key: "profile", label: "检测方案", children: `${detail.scan_profile.name} (#${detail.scan_profile.profile_id})` }] : []),
                      ]}
                    />
                    <div className="static-risk-summary">
                      <Text strong>风险摘要</Text>
                      {detail.finding_count > 0 ? (
                        <>
                          <Space size={8} wrap>
                            {Object.entries(findingsSummary).filter(([, count]) => count > 0).map(([severity, count]) => (
                              <span key={severity}>{staticRiskTag(apiRisk(severity))} × {count}</span>
                            ))}
                          </Space>
                          <div className="static-soft-note">
                            共 {detail.finding_count} 个风险项，切换到“风险”标签查看完整发现详情。
                          </div>
                        </>
                      ) : (
                        <div className="static-soft-note">当前资源没有风险发现，仍建议在策略变更后重新扫描。</div>
                      )}
                    </div>
                  </Space>
                ),
              },
              {
                key: "content",
                label: "内容",
                children: contentLoading ? (
                  <div style={{ padding: 32, textAlign: "center" }}><Spin /></div>
                ) : content?.type === "directory" ? (
                  <List
                    size="small"
                    dataSource={content.files ?? []}
                    locale={{ emptyText: "目录为空" }}
                    renderItem={(file) => (
                      <List.Item>
                        <List.Item.Meta
                          avatar={<FileTextOutlined />}
                          title={file.name}
                          description={<Text className="mono" type="secondary">{file.path} · {formatSize(file.size)}</Text>}
                        />
                      </List.Item>
                    )}
                  />
                ) : content?.type === "virtual" ? (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={content.content ?? "该资源没有可展示的静态内容。"} />
                ) : (
                  <Space direction="vertical" size="middle" className="static-detail-stack" style={{ width: "100%" }}>
                    {content?.truncated ? <Alert type="warning" showIcon message="内容超过 256 KB，已截断显示。" /> : null}
                    {content?.redacted ? <Alert type="info" showIcon message={`敏感信息（密钥、令牌、密码）已由后端脱敏后返回${content.redaction_count ? `，共 ${content.redaction_count} 处` : ""}。`} /> : null}
                    <pre className="static-content-preview">{content?.content || "（空文件）"}</pre>
                  </Space>
                ),
              },
              {
                key: "risk",
                label: "风险",
                children: findingsLoading ? (
                  <div style={{ padding: 32, textAlign: "center" }}><Spin /></div>
                ) : findings.length ? (
                  <div className="static-finding-list">
                    <Space size={8} wrap style={{ marginBottom: 12 }}>
                      {Object.entries(findingsSummary).filter(([, count]) => count > 0).map(([severity, count]) => (
                        <span key={severity}>{staticRiskTag(apiRisk(severity))} × {count}</span>
                      ))}
                      {findingsScannedAt ? <Text type="secondary">扫描于 {formatTimestamp(findingsScannedAt)}</Text> : null}
                    </Space>
                    {findings.map((finding) => (
                      <div key={finding.finding_id} className="static-finding-card">
                        <Space direction="vertical" size={8}>
                          <Space wrap>{staticRiskTag(apiRisk(finding.severity))}<Text strong>{finding.title}</Text>
                            {finding.rule_id ? <Tag>{finding.rule_id}</Tag> : null}
                            {finding.category ? <Tag color="blue">{finding.category}</Tag> : null}
                          </Space>
                          {finding.description ? <Text>{finding.description}</Text> : null}
                          {finding.location ? <Text type="secondary">位置：{finding.location}{finding.line_number ? ` (line ${finding.line_number})` : ""}</Text> : null}
                          {finding.scanner ? <Text type="secondary">扫描器：{finding.scanner}</Text> : null}
                        </Space>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无风险发现" />
                ),
              },
              {
                key: "relations",
                label: "关联资源",
                children: relationsLoading ? (
                  <div style={{ padding: 32, textAlign: "center" }}><Spin /></div>
                ) : relations.length ? (
                  <div className="static-relation-list">
                    {relations.map((relation) => (
                      <div key={relation.resource_id} className="static-relation-item">
                        <div>
                          <Text strong>{relation.name}</Text>
                          <Text type="secondary">{relation.relation_type}</Text>
                        </div>
                        <Space>
                          {typeTag(relation.resource_type)}
                          {staticRiskTag(apiRisk(relation.risk_level))}
                        </Space>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无关联资源" />
                ),
              },
            ]}
          />
        ) : null}
      </Drawer>
    </section>
  );
}
