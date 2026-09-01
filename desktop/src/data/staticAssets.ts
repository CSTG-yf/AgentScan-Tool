import type { StaticResourceStatus, StaticResourceType, StaticRisk } from "../types";

export type { StaticResourceStatus, StaticResourceType, StaticRisk } from "../types";

export const staticResourceTypes: StaticResourceType[] = [
  "Config",
  "Skills",
  "MCP",
  "Plugin",
  "Prompt",
  "Credential",
  "Environment",
];

export const staticRiskMeta: Record<StaticRisk, { color: string; label: string; rank: number }> = {
  critical: { color: "red", label: "严重", rank: 5 },
  high: { color: "volcano", label: "高风险", rank: 4 },
  medium: { color: "gold", label: "中风险", rank: 3 },
  low: { color: "blue", label: "低风险", rank: 2 },
  info: { color: "default", label: "信息", rank: 1 },
};

export const staticTypeMeta: Record<StaticResourceType, { color: string; label: string; description: string }> = {
  Plugin: { color: "green", label: "Plugin", description: "Agent 插件、扩展包和可执行扩展能力" },
  Config: { color: "blue", label: "Config", description: "配置文件、运行参数和策略开关" },
  Skills: { color: "purple", label: "Skills", description: "Agent 可调用的技能、工具脚本和动作能力" },
  MCP: { color: "cyan", label: "MCP", description: "MCP 服务、工具端点和外部能力桥接" },
  Prompt: { color: "geekblue", label: "Prompt", description: "系统提示词、项目规则和长期上下文" },
  Credential: { color: "magenta", label: "Credential", description: "令牌、密钥、凭据引用和身份材料" },
  Environment: { color: "lime", label: "Environment", description: "环境变量、容器参数和运行边界" },
};

export const staticStatusMeta: Record<StaticResourceStatus, { color: string; label: string }> = {
  discovered: { color: "processing", label: "已发现" },
  reviewed: { color: "success", label: "已复核" },
  changed: { color: "warning", label: "已变更" },
  ignored: { color: "default", label: "已忽略" },
};

export function isRiskResource(risk: StaticRisk) {
  return risk === "critical" || risk === "high" || risk === "medium";
}
