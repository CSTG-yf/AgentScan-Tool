// Manual visual review entry. Served only by TestRuntimeSettingsUIReviewServer.
// All configuration reads and writes use the real Go handlers and a temporary DB.
import React from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { RuntimeDetectionSettingsPage } from "../src/runtime-detection/SettingsPage";
import { AttackChainPage } from "../src/pages/AttackChainPage";
import { EventsPage } from "../src/pages/EventsPage";
import { ScanRefreshSettingsPage } from "../src/pages/ScanRefreshSettingsPage";
import { getScanScheduleSettings, getStaticResourceScanSettings, saveScanScheduleSettings, saveStaticResourceScanSettings } from "../src/bridge";
import type { ScanScheduleSettings, StaticResourceScanSettings } from "../src/types";
import "../src/styles.css";

Object.defineProperty(window, "__TAURI_INTERNALS__", { value: {
  async invoke(command: string, args: Record<string, any> = {}) {
    const paths: Record<string, string> = { get_attack_chains: "/api/v1/attack-chains", get_attack_chain_agent_type_summaries: "/api/v1/attack-chains/summary/agent-types", get_attack_chain_detail: `/api/v1/attack-chains/${args.chainId}`, get_runtime_detections: "/api/v1/runtime-detections", get_runtime_detection_agent_type_summaries: "/api/v1/runtime-detections/summary/agent-types", get_runtime_security_agents: "/api/v1/agents", get_runtime_security_summary: "/api/v1/runtime-security/summary", get_runtime_security_mode: "/api/v1/runtime-security/mode", get_runtime_decisions: "/api/v1/runtime-decisions", get_runtime_detection_detail: `/api/v1/runtime-detections/${args.detectionId}`, get_runtime_decision_detail: `/api/v1/runtime-decisions/${args.decisionId}` };
    let path = args.path?.startsWith("/api/v1/") ? args.path : `/api/v1/runtime-detection-settings${args.path}`;
    let method = args.method ?? "GET";
    let requestBody = args.body;
    if (command === "get_scan_schedule_settings") path = "/api/v1/page-refresh-settings";
    if (command === "save_scan_schedule_settings") { path = "/api/v1/page-refresh-settings"; method = "PUT"; requestBody = args.settings; }
    if (command === "get_static_resource_scan_settings") path = "/api/v1/static-resource-scan-settings";
    if (command === "save_static_resource_scan_settings") { path = "/api/v1/static-resource-scan-settings"; method = "PUT"; requestBody = args.settings; }
    if (command === "get_scan_schedules") path = "/api/v1/scan-schedules";
    if (command === "update_scan_schedule") { path = `/api/v1/scan-schedules/${args.taskType}`; method = "PUT"; requestBody = { enabled: args.enabled, interval_sec: args.intervalSec, mode: args.mode, scope: args.scope }; }
    if (command === "create_scan_job") { path = "/api/v1/jobs"; method = "POST"; requestBody = { task_type: args.taskType, mode: args.mode, trigger: "manual", scope: args.scope, idempotency_key: args.idempotencyKey }; }
    if (command === "get_scan_jobs") {
      const query = new URLSearchParams();
      if (args.taskType) query.set("task_type", args.taskType); if (args.status) query.set("status", args.status); if (args.trigger) query.set("trigger", args.trigger);
      query.set("limit", String(args.limit ?? 20)); query.set("offset", String(args.offset ?? 0)); path = `/api/v1/jobs?${query}`;
    }
    if (command === "get_scan_job") path = `/api/v1/jobs/${args.jobId}`;
    if (command === "cancel_scan_job") { path = `/api/v1/jobs/${args.jobId}/cancel`; method = "POST"; requestBody = {}; }
    const directCommands = new Set(["get_scan_schedule_settings", "save_scan_schedule_settings", "get_static_resource_scan_settings", "save_static_resource_scan_settings", "get_scan_schedules", "update_scan_schedule", "create_scan_job", "get_scan_jobs", "get_scan_job", "cancel_scan_job"]);
    if (command !== "runtime_detection_settings_request" && !directCommands.has(command)) {
      if (!paths[command]) throw new Error("此验证环境不开放主机执行服务。");
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(args.filters ?? args)) if (value !== undefined && value !== null) query.set(key === "agentTypeId" ? "AgenttypeId" : key.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`), String(value));
      if (command === "get_attack_chains") {
        query.set("page", String(args.page ?? 1)); query.set("page_size", String(args.pageSize ?? 20));
        if (args.sort) query.set("sort", String(args.sort));
      }
      path = `${paths[command]}?${query}`;
    }
    const response = await fetch(path, {
      method,
      headers: { "Content-Type": "application/json", "X-Review-Fixture": "runtime-settings" },
      body: requestBody === undefined || requestBody === null ? undefined : JSON.stringify(requestBody),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    if (["runtime_detection_settings_request", "get_attack_chain_detail", "get_scan_schedule_settings", "save_scan_schedule_settings", "get_scan_schedules", "update_scan_schedule", "create_scan_job", "get_scan_jobs", "get_scan_job", "cancel_scan_job"].includes(command)) return body;
    if (command === "get_static_resource_scan_settings") return body;
    if (command === "save_static_resource_scan_settings") return body.settings;
    if (command === "get_runtime_security_mode") return body.mode;
    if (command === "get_runtime_security_agents") return (body.agents ?? body.items ?? []).map((a: any) => ({ agentId:a.id, agentName:a.name ?? a.product, agentType:a.kind, detectionCount:a.runtimeDetectionCount ?? a.runtime_detection_count ?? 0, highOrAboveCount:a.runtimeHighOrAboveCount ?? a.runtime_high_or_above_count ?? 0 }));
    const camel = (value: any, key = ""): any => {
      if (["risk_counts", "severity_counts", "status_counts", "attributes"].includes(key)) return value;
      if (Array.isArray(value)) return value.map(item => camel(item));
      if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, item]) => [key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase()), camel(item,key)]));
      return value;
    };
    return camel(body);
  },
} });

function ReviewScanRefresh() {
  const [refresh, setRefresh] = React.useState<ScanScheduleSettings>();
  const [staticSettings, setStaticSettings] = React.useState<StaticResourceScanSettings>();
  React.useEffect(() => { void getScanScheduleSettings().then(setRefresh); void getStaticResourceScanSettings().then(setStaticSettings); }, []);
  return <ScanRefreshSettingsPage
    scanSettings={refresh}
    staticScanSettings={staticSettings}
    onScanSettingsChange={async (next) => setRefresh(await saveScanScheduleSettings(next))}
    onStaticScanSettingsChange={async (next) => setStaticSettings(await saveStaticResourceScanSettings(next))}
    onRefreshData={() => undefined}
  />;
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode><ConfigProvider locale={zhCN}>
    <main style={{ padding: 28, background: "#f3f6fb", minHeight: "100vh" }}>
      <p>界面验收环境 · 临时数据库 · 真实配置与任务 API · 不开放主机处置</p>
      {new URLSearchParams(location.search).has("refresh") ? <ReviewScanRefresh /> : new URLSearchParams(location.search).has("chains") ? <AttackChainPage defenseMode="observe" /> : new URLSearchParams(location.search).has("events") ? <EventsPage /> : <RuntimeDetectionSettingsPage />}
    </main>
  </ConfigProvider></React.StrictMode>,
);
