import type { EventKind, EventStatus } from "../types";

export type { EventFilter, EventKind, EventStatus } from "../types";

export const eventKindMeta: Record<EventKind, { color: string; label: string; description: string }> = {
  security: {
    color: "blue",
    label: "安全事件",
    description: "审计、规则命中、运行时观察和低中风险行为。",
  },
  attack: {
    color: "red",
    label: "攻击事件",
    description: "高风险行为、阻断动作、提示词注入、命令执行、凭据访问或外联事件。",
  },
};

export const eventStatusMeta: Record<EventStatus, { color: string; label: string }> = {
  detected: { color: "gold", label: "已检测" },
  audited: { color: "processing", label: "已审计" },
  blocked: { color: "red", label: "已阻断" },
  pending: { color: "default", label: "待处置" },
};
