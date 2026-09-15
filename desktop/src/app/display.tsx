import { Tag } from "antd";
import type { RangeMode } from "../types";
import { chainKindMeta, type ChainNodeKind } from "../data/attackChains";
import { eventKindMeta, eventStatusMeta, type EventKind, type EventStatus } from "../data/events";
import { staticRiskMeta, type StaticRisk } from "../data/staticAssets";

export const defenseModeLabels: Record<RangeMode, string> = {
  baseline: "Baseline",
  observe: "Observe",
  action: "Action",
};

export const defenseModeDescriptions: Record<RangeMode, string> = {
  baseline: "原始运行，不接入 TraceBastion 运行时防护",
  observe: "观察审计，检测本机 Agent 和靶场流量但不阻断",
  action: "主动防护，检测并阻断高风险行为",
};

export const defenseModeColors: Record<RangeMode, string> = {
  baseline: "default",
  observe: "processing",
  action: "error",
};

export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds} 秒`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟`;
  return `${Math.floor(seconds / 3600)} 小时 ${Math.floor((seconds % 3600) / 60)} 分`;
}

export function formatTimestamp(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value || "-" : timestamp.toLocaleString();
}

export function formatClock(value: string): string {
  const timestamp = new Date(value);
  return Number.isNaN(timestamp.getTime()) ? value || "-" : timestamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function offsetIso(anchor: Date, offsetMs: number): string {
  return new Date(anchor.getTime() + offsetMs).toISOString();
}

export function outcomeTag(outcome: string) {
  const color = outcome === "terminated" || outcome === "debugPrivilegeEnabled" ? "success" : outcome === "terminationFailed" || outcome === "debugPrivilegeUnavailable" ? "error" : outcome === "terminationPending" ? "warning" : "processing";
  const label: Record<string, string> = {
    terminated: "已终止",
    terminationFailed: "终止失败",
    terminationPending: "准备终止",
    observed: "已观察",
    allowed: "已放行",
    flagged: "发现风险",
    blocked: "已阻断",
    error: "失败",
    debugPrivilegeEnabled: "调试特权已启用",
    debugPrivilegeUnavailable: "调试特权不可用",
  };
  return <Tag color={color}>{(label[outcome] ?? outcome) || "未知"}</Tag>;
}

export function staticRiskTag(risk: StaticRisk) {
  const meta = staticRiskMeta[risk];
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

export function eventKindTag(kind: EventKind) {
  const meta = eventKindMeta[kind];
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

export function eventStatusTag(status: EventStatus) {
  const meta = eventStatusMeta[status];
  return <Tag color={meta.color}>{meta.label}</Tag>;
}

export function chainKindTag(kind: ChainNodeKind) {
  const meta = chainKindMeta[kind];
  return <Tag color={meta.color}>{meta.label}</Tag>;
}
