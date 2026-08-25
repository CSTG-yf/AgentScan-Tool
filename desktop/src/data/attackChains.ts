import type { ChainNodeKind } from "../types";

export type { ChainNodeKind } from "../types";

export const chainKindMeta: Record<ChainNodeKind, { color: string; label: string }> = {
  entry: { color: "cyan", label: "入口" },
  agent: { color: "blue", label: "Agent" },
  llm: { color: "geekblue", label: "推理" },
  tool: { color: "gold", label: "工具" },
  mcp: { color: "orange", label: "MCP" },
  data: { color: "volcano", label: "数据" },
  network: { color: "red", label: "外联" },
  defense: { color: "green", label: "防护" },
};
