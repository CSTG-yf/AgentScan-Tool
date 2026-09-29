import { useCallback, useEffect, useMemo, useState } from "react";
import type { ComponentProps } from "react";
import { CopyOutlined, DownloadOutlined, EyeOutlined, FileTextOutlined, FolderOpenOutlined, ReloadOutlined, SearchOutlined, SecurityScanOutlined } from "@ant-design/icons";
import { theme, ConfigProvider, Alert, Button, Card, DatePicker, Descriptions, Drawer, Dropdown, Empty, Input, List, message, Modal, Select, Space, Spin, Table, Tabs, Tag, Tooltip, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { staticRiskTag } from "../app/display";
import { chooseExportDirectory, exportFileToDirectory } from "../app/reportExport";
import { buildStaticResourceReport } from "../app/staticResourceReport";
import { staticRiskMeta, staticTypeMeta } from "../data/staticAssets";
import {
  getStaticResourceAgents,
  getStaticResourceContent,
  getStaticResourceDetail,
  getStaticResourceFindings,
  getStaticResourceScans,
  getStaticResources,
  revealStaticResourcePath,
  getStaticResourceSummary,
  getScanStatus,
  triggerStaticResourceRescan,
  triggerStaticResourceScan,
  updateStaticResourceStatus,
} from "../bridge";
import type {
  StaticResourceAgentSummary,
  StaticResourceContentResponse,
  StaticResourceDetailResponse,
  StaticResourceFindingItem,
  StaticResourceListItem,
  StaticResourceScanHistoryItem,
  StaticResourceSummaryResponse,
} from "../types";

const { Text, Title } = Typography;
type RangeValue = Parameters<NonNullable<ComponentProps<typeof DatePicker.RangePicker>["onChange"]>>[0];

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


const DEFAULT_PAGE_SIZE = 20;

function toFilterTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const timestamp = new Date(value);
  return Number.isFinite(timestamp.getTime()) ? timestamp.toISOString() : undefined;
}

async function waitForScanCompletion(scanId?: string): Promise<void> {
  if (!scanId) return;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = await getScanStatus(scanId);
    if (status.status === "completed") return;
    if (status.status === "failed") throw new Error(status.error || "扫描任务失败");
    await new Promise<void>((resolve) => window.setTimeout(resolve, 1000));
  }
  throw new Error("扫描任务等待超时，请稍后查看扫描历史");
}

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
  unknown: { color: "default", label: "未知" },
};

/** Manual review statuses an operator can set from the status dropdown. */
const MANUAL_STATUS_OPTIONS: { value: string; label: string }[] = [
  { value: "review", label: "标记为已复核" },
  { value: "needs_review", label: "标记为待复核" },
  { value: "ignored", label: "标记为已忽略" },
  { value: "discovered", label: "恢复为已发现" },
];

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

function safeReportName(value: string, extension = "pdf") {
  const base = (value || "static-resources-report")
    .replace(/[<>:"/\\|?*\u0000-\u001f]/g, "_")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^[._-]+|[._-]+$/g, "")
    .slice(0, 120) || "static-resources-report";
  return base.toLowerCase().endsWith(`.${extension}`) ? base : `${base}.${extension}`;
}

interface StaticAssetsPageProps {
  loading?: boolean;
  onRefresh?: () => Promise<void> | void;
  refreshNonce?: number;
}

type TypeFilter = string | "all";
type RiskFilter = string | "all";
type StatusFilter = string | "all";

export function StaticAssetsPage({ loading = false, refreshNonce = 0 }: StaticAssetsPageProps) {
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
  const [exportAgentType, setExportAgentType] = useState("all");
  const [startTime, setStartTime] = useState("");
  const [endTime, setEndTime] = useState("");
  const [dateRange, setDateRange] = useState<RangeValue>(null);
  const [query, setQuery] = useState("");
  const [debouncedQuery, setDebouncedQuery] = useState("");
  const [advancedFilters, setAdvancedFilters] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
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
  const [scans, setScans] = useState<StaticResourceScanHistoryItem[]>([]);
  const [scansTotal, setScansTotal] = useState(0);
  const [scansLoading, setScansLoading] = useState(false);
  const [revealOpen, setRevealOpen] = useState(false);
  const [revealPath, setRevealPath] = useState("");
  const [statusSaving, setStatusSaving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [summaryExporting, setSummaryExporting] = useState(false);
  const [allReportExporting, setAllReportExporting] = useState(false);
  const [agentReportExporting, setAgentReportExporting] = useState(false);

  const inTauri = "__TAURI_INTERNALS__" in window;

  // Debounce the search keyword.
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedQuery(query.trim());
      setPage(1);
    }, 350);
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
      resourceType: selectedType === "all" ? undefined : selectedType,
      riskLevel: riskFilter === "all" ? undefined : riskFilter,
      status: statusFilter === "all" ? undefined : statusFilter,
      keyword: debouncedQuery || undefined,
      startTime: toFilterTimestamp(startTime),
      endTime: toFilterTimestamp(endTime),
      page,
      pageSize,
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
  }, [selectedAgentId, selectedType, riskFilter, statusFilter, debouncedQuery, startTime, endTime, page, pageSize, listReloadNonce]);

  const selectedAgent = useMemo(
    () => agents.find((agent) => agent.agent_id === selectedAgentId),
    [agents, selectedAgentId],
  );
  const globalResources = useMemo(() => agents.reduce((totals, agent) => ({
    resources: totals.resources + agent.resource_count,
    risks: totals.risks + agent.risk_resource_count,
    critical: totals.critical + agent.critical_resource_count,
  }), { resources: 0, risks: 0, critical: 0 }), [agents]);
  const currentSummary = summary?.agent.agent_id === selectedAgentId ? summary : undefined;

  const refreshListAndSummary = useCallback(async () => {
    if (selectedAgentId) {
      getStaticResourceSummary(selectedAgentId).then(setSummary).catch(() => undefined);
    }
    // Bump the nonce so the list effect re-runs even when page is unchanged.
    setListReloadNonce((nonce) => nonce + 1);
  }, [selectedAgentId]);

  useEffect(() => {
    if (refreshNonce <= 0) return;
    void loadAgents(false);
    void refreshListAndSummary();
  }, [loadAgents, refreshListAndSummary, refreshNonce]);

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

  const loadScans = useCallback(async (resourceId: string) => {
    setScansLoading(true);
    try {
      const response = await getStaticResourceScans(resourceId);
      setScans(response.items ?? []);
      setScansTotal(response.total ?? 0);
    } catch (error) {
      message.error(`加载扫描历史失败：${String(error)}`);
      setScans([]);
      setScansTotal(0);
    } finally {
      setScansLoading(false);
    }
  }, []);

  // Tab switch drives lazy loading.
  const handleDetailTabChange = useCallback(
    (tab: string) => {
      setDetailTab(tab);
      if (!detailResourceId) return;
      if (tab === "risk") void loadFindings(detailResourceId);
      if (tab === "content") void loadContent(detailResourceId);
      if (tab === "history") void loadScans(detailResourceId);
    },
    [detailResourceId, loadContent, loadFindings, loadScans],
  );

  const handleOpenResource = useCallback(
    (resource: StaticResourceListItem) => {
      setDetailResourceId(resource.resource_id);
      setResourceDetailOpen(true);
      setDetailTab("overview");
      setFindings([]);
      setFindingsSummary({});
      setContent(undefined);
      setScans([]);
      setScansTotal(0);
      void loadDetail(resource.resource_id);
    },
    [loadDetail],
  );

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgentId(agentId);
    setPage(1);
    setSelectedType("all");
    setRiskFilter("all");
    setStatusFilter("all");
    setQuery("");
    setResourceDetailOpen(false);
    setDetailResourceId(undefined);
  };

  const resetListFilters = () => {
    setSelectedType("all");
    setRiskFilter("all");
    setStatusFilter("all");
    setQuery("");
    setDebouncedQuery("");
    setStartTime("");
    setEndTime("");
    setDateRange(null);
    setPage(1);
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
      const idempotencyKey = globalThis.crypto?.randomUUID?.() ?? `resource-rescan-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const accepted = await triggerStaticResourceRescan(selectedAgentId, idempotencyKey);
      await waitForScanCompletion(accepted.scan_id);
      message.success("静态资源重新扫描完成");
      const resourceId = detailResourceId;
      await loadAgents(false);
      await refreshListAndSummary();
      if (resourceId) {
        await loadDetail(resourceId);
        await loadFindings(resourceId);
        await loadScans(resourceId);
      }
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
      const idempotencyKey = globalThis.crypto?.randomUUID?.() ?? `resource-scan-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const accepted = await triggerStaticResourceScan(detailResourceId, idempotencyKey);
      await waitForScanCompletion(accepted.scan_id);
      message.success("资源扫描完成");
      const resourceId = detailResourceId;
      await loadDetail(resourceId);
      await loadFindings(resourceId);
      await loadScans(resourceId);
      await refreshListAndSummary();
    } catch (error) {
      message.error(`提交扫描失败：${String(error)}`);
    } finally {
      setScanning(false);
    }
  };

  const handleStatusChange = useCallback(
    async (resourceId: string, nextStatus: string) => {
      setStatusSaving(true);
      try {
        await updateStaticResourceStatus(resourceId, nextStatus);
        message.success("资源状态已更新");
        await refreshListAndSummary();
        if (detailResourceId === resourceId) void loadDetail(resourceId);
      } catch (error) {
        message.error(`更新资源状态失败：${String(error)}`);
      } finally {
        setStatusSaving(false);
      }
    },
    [detailResourceId, loadDetail, refreshListAndSummary],
  );

  const openRevealDialog = (path?: string) => {
    if (!path) {
      message.warning("该资源没有可定位的磁盘路径");
      return;
    }
    setRevealPath(path);
    setRevealOpen(true);
  };

  const handleRevealInExplorer = async () => {
    if (!revealPath) return;
    try {
      await revealStaticResourcePath(revealPath);
      setRevealOpen(false);
    } catch (error) {
      message.error(`${String(error)}`);
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

  const savePdfReport = (html: string, defaultFileName: string, directory: string | undefined) =>
    exportFileToDirectory(directory, { content: html, defaultFileName, format: "pdf" });

  const reportFilters = {
    "资源类型": selectedType === "all" ? "全部" : API_TYPE_TO_DISPLAY[selectedType] ?? selectedType,
    "风险等级": riskFilter === "all" ? "全部" : staticRiskMeta[apiRisk(riskFilter)]?.label ?? riskFilter,
    "资源状态": statusFilter === "all" ? "全部" : STATUS_META[statusFilter]?.label ?? statusFilter,
    "关键词": debouncedQuery || "不限",
    "开始时间": startTime ? formatTimestamp(startTime) : "不限",
    "结束时间": endTime ? formatTimestamp(endTime) : "不限",
  };

  const fetchAllResourcesForAgent = useCallback(async (agentId: string, applyFilters = false) => {
    const pageSize = 200;
    let nextPage = 1;
    let total = Number.POSITIVE_INFINITY;
    const rows: StaticResourceListItem[] = [];
    while (rows.length < total) {
      const response = await getStaticResources({
        agentId,
        resourceType: applyFilters && selectedType !== "all" ? selectedType : undefined,
        riskLevel: applyFilters && riskFilter !== "all" ? riskFilter : undefined,
        status: applyFilters && statusFilter !== "all" ? statusFilter : undefined,
        keyword: applyFilters ? debouncedQuery || undefined : undefined,
        startTime: applyFilters ? toFilterTimestamp(startTime) : undefined,
        endTime: applyFilters ? toFilterTimestamp(endTime) : undefined,
        page: nextPage,
        pageSize,
      });
      const items = response.items ?? [];
      rows.push(...items);
      total = response.total ?? rows.length;
      if (!items.length || rows.length >= total) break;
      nextPage += 1;
    }
    return rows;
  }, [debouncedQuery, endTime, startTime, riskFilter, selectedType, statusFilter]);

  const exportResourceSummary = async (resource: StaticResourceDetailResponse | StaticResourceListItem | undefined) => {
    if (!resource) return;
    setSummaryExporting(true);
    try {
      const directory = await chooseExportDirectory("选择资源扫描摘要导出文件夹");
      if (directory === undefined) throw new Error("请在桌面应用中导出 PDF 报告");
      if (directory === null) {
        message.info("已取消导出");
        return;
      }
      const fileName = safeReportName(`${resource.name || "resource"}-scan-summary.pdf`);
      const html = buildStaticResourceReport([{
        agent: { agent_id: resource.agent_id, name: "agent" in resource ? resource.agent.name : resource.agent_id, agent_type: "agent" in resource ? resource.agent.agent_type ?? "" : "" },
        resources: [resource],
      }], { title: "静态资源扫描摘要", summary: true });
      const path = await savePdfReport(html, fileName, directory);
      message.success(`资源扫描摘要已导出：${path}`);
    } catch (error) {
      message.error(`导出摘要失败：${String(error)}`);
    } finally {
      setSummaryExporting(false);
    }
  };

  const exportCurrentAgentResources = async () => {
    if (!selectedAgent) {
      message.warning("请先选择一个 Agent");
      return;
    }
    setAgentReportExporting(true);
    try {
      const directory = await chooseExportDirectory("选择静态资源报告导出文件夹");
      if (directory === undefined) throw new Error("请在桌面应用中导出 PDF 报告");
      if (directory === null) {
        message.info("已取消导出");
        return;
      }
      const resources = await fetchAllResourcesForAgent(selectedAgent.agent_id, true);
      const contentText = buildStaticResourceReport([{ agent: selectedAgent, resources }], { filters: reportFilters });
      const fileName = safeReportName(`${selectedAgent.name || selectedAgent.agent_id}-static-resources-${new Date().toISOString().slice(0, 10)}.pdf`);
      const path = await savePdfReport(contentText, fileName, directory);
      message.success(`当前 Agent 资源报告已导出：${path}`);
    } catch (error) {
      message.error(`导出当前 Agent 资源失败：${String(error)}`);
    } finally {
      setAgentReportExporting(false);
    }
  };

  const exportAllAgentResources = async () => {
    const scopedAgents = exportAgentType === "all" ? agents : agents.filter(agent => agent.agent_type === exportAgentType);
    if (!scopedAgents.length) {
      message.warning("当前没有可导出的 Agent 资源");
      return;
    }
    setAllReportExporting(true);
    try {
      const directory = await chooseExportDirectory("选择静态资源报告导出文件夹");
      if (directory === undefined) throw new Error("请在桌面应用中导出 PDF 报告");
      if (directory === null) {
        message.info("已取消导出");
        return;
      }
      const sections: Array<{ agent: StaticResourceAgentSummary; resources: StaticResourceListItem[] }> = [];
      for (const agent of scopedAgents) {
        const resources = await fetchAllResourcesForAgent(agent.agent_id, true);
        sections.push({ agent, resources });
      }
      const contentText = buildStaticResourceReport(sections, { filters: { ...reportFilters, "Agent 类型": exportAgentType === "all" ? "全部" : exportAgentType } });
      const fileName = safeReportName(`static-resources-report-${new Date().toISOString().slice(0, 10)}.pdf`);
      const path = await savePdfReport(contentText, fileName, directory);
      message.success(`静态资源报告已导出：${path}`);
    } catch (error) {
      message.error(`导出静态资源报告失败：${String(error)}`);
    } finally {
      setAllReportExporting(false);
    }
  };

  const renderStatusCell = (resource: StaticResourceListItem | StaticResourceDetailResponse) => (
    <span className="static-status-cell" onClick={(event) => event.stopPropagation()}>
      <Dropdown
          overlayClassName="static-detection-filter-menu"
        trigger={["click"]}
        menu={{
          items: MANUAL_STATUS_OPTIONS.map((option) => ({
            key: option.value,
            label: option.label,
            disabled: option.value === resource.status || statusSaving,
          })),
          onClick: ({ key }) => void handleStatusChange(resource.resource_id, key),
        }}
      >
        <span title="点击修改审查状态" style={{ cursor: "pointer" }}>{statusTag(resource.status)}</span>
      </Dropdown>
    </span>
  );

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
      render: (_, resource) => renderStatusCell(resource),
    },
    {
      title: "更新时间",
      dataIndex: "updated_at",
      width: 168,
      render: (value) => <Text type="secondary">{formatTimestamp(value)}</Text>,
    },
  ];

  const typeCards = useMemo(() => {
    const byType = new Map(currentSummary?.by_type?.map((item) => [item.resource_type, item]) ?? []);
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
  }, [currentSummary]);

  const selectedTypeLabel =
    selectedType === "all" ? "全部资源" : staticTypeMeta[(API_TYPE_TO_DISPLAY[selectedType] ?? "Config") as keyof typeof staticTypeMeta]?.label ?? selectedType;

  const summaryHeader = currentSummary ?? {
    total_resources: selectedAgent?.resource_count ?? 0,
    resource_type_count: typeCards.filter((card) => card.count > 0).length,
    risk_resource_count: selectedAgent?.risk_resource_count ?? 0,
    malicious_resource_count: selectedAgent?.malicious_resource_count ?? 0,
    critical_resource_count: selectedAgent?.critical_resource_count ?? 0,
  };

  return (
    <ConfigProvider theme={detectionTheme}><section className="static-assets-page static-detection-surface">
      <div className="static-page-header">
        <div>
          <Text className="eyebrow">STATIC ASSET INVENTORY</Text>
          <Title level={2}>静态资源</Title>
          <Text type="secondary">基于 Agent 资源规则发现并检测配置、技能、插件、MCP 服务、提示词、凭据与环境变量。</Text>
        </div>
        <div className="static-header-actions">
          <Select value={exportAgentType} style={{ minWidth: 150 }} options={[{ value: "all", label: "全部 AgentType" }, ...[...new Set(agents.map(agent => agent.agent_type).filter(Boolean))].map(value => ({ value, label: value }))]} onChange={setExportAgentType} />
          <Button
            icon={<DownloadOutlined />}
            loading={allReportExporting}
            disabled={!agents.length}
            onClick={() => void exportAllAgentResources()}
          >
            导出静态资源检测报告
          </Button>
          <Button
            type="primary"
            icon={<SecurityScanOutlined />}
            loading={rescanning}
            disabled={!selectedAgentId}
            onClick={() => void handleRescanAgent()}
          >
            重新扫描 Agent资源
          </Button>
          <Button icon={<ReloadOutlined />} loading={agentsLoading || listLoading} onClick={() => void handleRefresh()}>
            刷新Agent资源
          </Button>
        </div>
      </div>

      {!inTauri ? (
        <Alert type="warning" showIcon message="浏览器预览模式不会连接 Go 后端；请在桌面应用中查看真实静态资源扫描结果。" />
      ) : null}
      {agentsError ? <Alert type="error" showIcon message={agentsError} /> : null}

      <div className="static-summary-grid static-global-summary">
        <Card bordered={false} className="static-metric-card">
          <Text type="secondary">全部资源</Text>
          <div className="static-metric-value resource"><span>{agentsLoading || agentsError ? "—" : globalResources.resources}</span></div>
          <Text type="secondary">所有 Agent 总体统计</Text>
        </Card>
        <Card bordered={false} className="static-metric-card static-metric-card-risk">
          <Text type="secondary">风险资源数量</Text>
          <div className="static-metric-value warning"><span>{agentsLoading || agentsError ? "—" : globalResources.risks}</span></div>
          <Text type="secondary">所有 Agent 的中危及以上资源</Text>
        </Card>
        <Card bordered={false} className="static-metric-card static-metric-card-critical">
          <Text type="secondary">严重风险数量</Text>
          <div className="static-metric-value danger"><span>{agentsLoading || agentsError ? "—" : globalResources.critical}</span></div>
          <Text type="secondary">所有 Agent 的严重风险资源</Text>
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
                <span className="static-agent-source">{agent.agent_type ||  "未知agent类型"}</span>
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
              <div className="static-agent-context static-current-summary">
                <div className="static-current-heading">
                  <Title level={3}>{selectedAgent.name}</Title>
                  <Text className="mono static-agent-path">{selectedAgent.agent_id}</Text>
                </div>
                <div className="static-current-metrics">
                  <div><Text type="secondary">资源数</Text><strong>{summaryHeader.total_resources}</strong></div>
                  <div className="risk"><Text type="secondary">风险资源数</Text><strong>{summaryHeader.risk_resource_count}</strong></div>
                  <div className="critical"><Text type="secondary">严重风险数</Text><strong>{summaryHeader.critical_resource_count}</strong></div>
                </div>
              </div>

              <div className="static-type-grid">
                <button
                  className={`static-type-card static-type-card-all ${selectedType === "all" ? "static-type-card-active" : ""}`}
                  type="button"
                  onClick={() => { setSelectedType("all"); setPage(1); }}
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
                    onClick={() => { setSelectedType(card.apiType); setPage(1); }}
                  >
                    <span>{staticTypeMeta[card.display as keyof typeof staticTypeMeta]?.label ?? card.display}</span>
                    <strong>{card.count} Resources</strong>
                    <em className={card.risks ? "static-type-risk" : ""}>{card.risks} Risks</em>
                  </button>
                ))}
              </div>

              <Card bordered={false} className="static-table-card">
                <div className="event-filters standard-filter-bar static-resource-filters">
                  <Input
                    allowClear
                    prefix={<SearchOutlined />}
                    placeholder="搜索资源名称或路径"
                    value={query}
                    onChange={(event) => setQuery(event.target.value)}
                  />
                  <Select
              classNames={{ popup: { root: "static-detection-filter-popup" } }}
                    value={selectedType}
                    onChange={(value) => { setSelectedType(value as TypeFilter); setPage(1); }}
                    options={[
                      { value: "all", label: "全部类型" },
                      ...typeCards.map((card) => ({
                        value: card.apiType,
                        label: staticTypeMeta[card.display as keyof typeof staticTypeMeta]?.label ?? card.display,
                      })),
                    ]}
                  />
                  <DatePicker.RangePicker
                    aria-label="更新时间范围"
                    showTime
                    value={dateRange}
                    onChange={(value) => {
                      setDateRange(value);
                      setStartTime(value?.[0]?.toISOString() ?? "");
                      setEndTime(value?.[1]?.toISOString() ?? "");
                      setPage(1);
                    }}
                  />
                  <Button onClick={() => setAdvancedFilters(value => !value)}>{advancedFilters ? "收起" : "高级筛选"}</Button>
                  <Button onClick={resetListFilters}>重置</Button>
                </div>
                {advancedFilters && <div className="event-filters advanced standard-filter-bar standard-filter-advanced static-filter-advanced">
                  <Select
              classNames={{ popup: { root: "static-detection-filter-popup" } }}
                    value={riskFilter}
                    onChange={(value) => { setRiskFilter(value as RiskFilter); setPage(1); }}
                    options={[
                      { value: "all", label: "全部风险" },
                      ...Object.entries(staticRiskMeta).map(([risk, meta]) => ({ value: risk, label: meta.label })),
                    ]}
                  />
                  <Select
              classNames={{ popup: { root: "static-detection-filter-popup" } }}
                    value={statusFilter}
                    onChange={(value) => { setStatusFilter(value as StatusFilter); setPage(1); }}
                    options={[
                      { value: "all", label: "全部状态" },
                      ...Object.entries(STATUS_META).map(([status, meta]) => ({ value: status, label: meta.label })),
                    ]}
                  />
                </div>}
                <div className="static-table-title">
                  <Space>
                    <Text strong>{selectedTypeLabel}</Text>
                    <Button
                      size="small"
                      icon={<DownloadOutlined />}
                      loading={agentReportExporting}
                      disabled={!selectedAgent}
                      onClick={(event) => {
                        event.stopPropagation();
                        void exportCurrentAgentResources();
                      }}
                    >
                      导出筛选结果
                    </Button>
                  </Space>
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
                    pageSize,
                    total: listTotal,
                    showSizeChanger: true,
                    pageSizeOptions: [10, 20, 50, 100, 200],
                    showTotal: (total) => `共 ${total} 条`,
                    onChange: (nextPage, nextPageSize) => {
                      setPage(nextPageSize === pageSize ? nextPage : 1);
                      setPageSize(nextPageSize);
                    },
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
        className="static-detail-drawer static-detection-detail-drawer static-detection-surface"
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
              <Button icon={<FolderOpenOutlined />} onClick={() => openRevealDialog(detail.path)}>定位文件</Button>
              <Button icon={<DownloadOutlined />} loading={summaryExporting} onClick={() => void exportResourceSummary(detail)}>导出摘要</Button>
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
                        { key: "status", label: "状态", children: renderStatusCell(detail) },
                        { key: "scan", label: "扫描状态", children: scanStatusTag(detail.scan_status) },
                        { key: "hash", label: "Hash", children: <Text className="mono static-detail-path">{detail.content_hash || "-"}</Text> },
                        ...(detail.resource_rule ? [{ key: "rule", label: "发现规则", children: `${detail.resource_rule.name} (#${detail.resource_rule.rule_id})` }] : []),
                        ...(detail.scan_profile ? [{ key: "profile", label: "检测方案", children: `${detail.scan_profile.name} (#${detail.scan_profile.profile_id})` }] : []),
                        ...(detail.scan_capabilities?.length
                          ? [{
                              key: "capabilities",
                              label: "检测能力",
                              children: (
                                <Space size={4} wrap>
                                  {detail.scan_capabilities.map((capability) => (
                                    <Tooltip key={capability.capability_id} title={capability.description || capability.scanner || undefined}>
                                      <Tag color={capability.enabled ? "blue" : "default"}>{capability.name}</Tag>
                                    </Tooltip>
                                  ))}
                                </Space>
                              ),
                            }]
                          : []),
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
                key: "history",
                label: "历史",
                children: scansLoading ? (
                  <div style={{ padding: 32, textAlign: "center" }}><Spin /></div>
                ) : scans.length ? (
                  <div className="static-history-list">
                    <Text type="secondary">共 {scansTotal} 次扫描，展示最近 {scans.length} 次。</Text>
                    <Table
                      size="small"
                      rowKey="scan_id"
                      pagination={false}
                      dataSource={scans}
                      columns={[
                        { title: "扫描时间", dataIndex: "scanned_at", width: 150, render: (value) => formatTimestamp(value) },
                        { title: "扫描器", dataIndex: "scanner", render: (value) => value || "-" },
                        { title: "发现数", dataIndex: "finding_count", width: 76 },
                        { title: "最高风险", dataIndex: "max_severity", width: 100, render: (value) => (value ? staticRiskTag(apiRisk(value)) : "-") },
                        { title: "耗时", dataIndex: "duration_ms", width: 88, render: (value) => (value === undefined || value === null ? "-" : `${value} ms`) },
                        { title: "Scan ID", dataIndex: "scan_id", width: 120, render: (value) => <Text className="mono" style={{ fontSize: 12 }}>{value}</Text> },
                      ]}
                    />
                  </div>
                ) : (
                  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无扫描历史" />
                ),
              },
            ]}
          />
        ) : null}
      </Drawer>

      <Modal
        open={revealOpen}
        title="资源文件位置"
        okText="在资源管理器中显示"
        cancelText="关闭"
        onOk={() => void handleRevealInExplorer()}
        onCancel={() => setRevealOpen(false)}
      >
        <Space direction="vertical" size={8} style={{ width: "100%" }}>
          <Text type="secondary">
            在文件资源管理器中打开该资源所在位置，人工审查文件内容后，可在资源状态处将结果标记为已复核 / 待复核 / 已忽略。
          </Text>
          <Text className="mono static-detail-path" copyable>{revealPath}</Text>
        </Space>
      </Modal>
    </section></ConfigProvider>
  );
}
