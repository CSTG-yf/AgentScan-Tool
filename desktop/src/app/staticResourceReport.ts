import type { StaticResourceAgentSummary, StaticResourceDetailResponse, StaticResourceListItem } from "../types";

type Resource = StaticResourceListItem | StaticResourceDetailResponse;
export interface ResourceReportSection {
  agent: Pick<StaticResourceAgentSummary, "agent_id" | "name" | "agent_type">;
  resources: Resource[];
}

const escape = (value: unknown): string => String(value ?? "").replace(/[&<>"']/g, character => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[character] ?? character));
const types: Record<string, string> = { config: "配置", skill: "技能", mcp: "MCP", plugin: "插件", prompt: "提示词", credential: "凭据", environment: "环境" };
const risks: Record<string, string> = { critical: "严重", high: "高风险", medium: "中风险", low: "低风险", info: "信息", clean: "无风险" };
const statuses: Record<string, string> = { discovered: "已发现", review: "已复核", reviewed: "已复核", needs_review: "待复核", missing: "已消失", changed: "已变更", ignored: "已忽略", unknown: "未知" };
const time = (value?: string): string => {
  if (!value) return "尚无扫描结果";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false });
};
const isRisk = (resource: Resource) => ["critical", "high", "medium"].includes(resource.risk_level?.toLowerCase());
const riskBadge = (value: string) => {
  const key = value?.toLowerCase();
  return `<span class="badge ${Object.hasOwn(risks, key) ? key : "info"}">${escape(risks[key] ?? value ?? "未知")}</span>`;
};

/** Self-contained HTML: all resource values are escaped, no external assets. */
export function buildStaticResourceReport(
  sections: ResourceReportSection[],
  options: { title?: string; filters?: Record<string, string>; summary?: boolean; generatedAt?: string } = {},
): string {
  const resources = sections.flatMap(section => section.resources);
  const title = options.title ?? "静态资源检测报告";
  const filters = Object.entries(options.filters ?? {}).map(([key, value]) =>
    `<span><b>${escape(key)}</b> ${escape(value)}</span>`,
  ).join("");
  const metrics = [
    ["资源总数", resources.length, ""],
    ["风险资源", resources.filter(isRisk).length, "risk"],
    ["严重风险", resources.filter(resource => resource.risk_level?.toLowerCase() === "critical").length, "critical"],
    ["恶意资源", resources.filter(resource => resource.malicious).length, "risk"],
  ].map(([label, count, color]) => `<div class="metric ${color}"><span>${label}</span><strong>${count}</strong></div>`).join("");
  const body = sections.map((section, index) => {
    const heading = `<div class="section-heading"><span class="number">${String(index + 1).padStart(2, "0")}</span><div><h2>${escape(section.agent.name || section.agent.agent_id)}</h2><p>${escape(section.agent.agent_type || "未分类")} · ${escape(section.agent.agent_id)}</p></div><span class="section-total">${section.resources.length} 项资源 · ${section.resources.filter(isRisk).length} 项风险</span></div>`;
    if (!section.resources.length) return `<section>${heading}<p class="empty">当前范围内没有静态资源。</p></section>`;
    if (options.summary) {
      return `<section>${heading}${section.resources.map(resource => {
        const fields: Array<[string, string | number]> = [
          ["资源名称", resource.name], ["资源 ID", resource.resource_id],
          ["资源类型", types[resource.resource_type] ?? resource.resource_type], ["资源位置", resource.path || "-"],
          ["是否恶意", resource.malicious ? "是" : "否"], ["风险发现数", resource.finding_count],
          ["资源状态", statuses[resource.status] ?? resource.status], ["最近扫描", time(resource.last_scan_at)],
          ["更新时间", time(resource.updated_at)],
        ];
        return `<div class="detail-title">${escape(resource.name)} ${riskBadge(resource.risk_level)}</div><table class="detail"><tbody>${fields.map(([key, value]) => `<tr><th>${escape(key)}</th><td>${escape(value)}</td></tr>`).join("")}</tbody></table>`;
      }).join("")}</section>`;
    }
    return `<section>${heading}<table class="resources"><colgroup><col style="width:5%"><col style="width:41%"><col style="width:9%"><col style="width:10%"><col style="width:8%"><col style="width:10%"><col style="width:17%"></colgroup><thead><tr><th>序号</th><th>资源 / 位置</th><th>类型</th><th>风险等级</th><th>发现数</th><th>状态</th><th>最近扫描</th></tr></thead><tbody>${section.resources.map((resource, row) => `<tr><td class="muted">${row + 1}</td><td><strong>${escape(resource.name)}</strong><div class="path">${escape(resource.path || "-")}</div></td><td>${escape(types[resource.resource_type] ?? resource.resource_type)}</td><td>${riskBadge(resource.risk_level)}${resource.malicious ? '<div class="malicious">恶意资源</div>' : ""}</td><td>${escape(resource.finding_count)}</td><td>${escape(statuses[resource.status] ?? resource.status)}</td><td class="muted">${escape(time(resource.last_scan_at))}</td></tr>`).join("")}</tbody></table></section>`;
  }).join("");
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><title>${escape(title)}</title><style>
@page { size: ${options.summary ? "A4" : "A4 landscape"}; margin: 14mm 13mm 16mm; }
* { box-sizing: border-box; }
body { margin: 0; color: #243247; background: #fff; font: 11px/1.6 "Microsoft YaHei", "Noto Sans CJK SC", "WenQuanYi Zen Hei", sans-serif; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
.header { border-top: 5px solid #2563eb; padding: 16px 0 14px; border-bottom: 1px solid #dce4ef; }
.brand { color: #2563eb; font-size: 11px; font-weight: 700; letter-spacing: 1.4px; }
h1 { margin: 5px 0; font-size: 27px; line-height: 1.4; color: #14213a; }
.meta, .muted, .section-heading p { color: #64748b; }
.metrics { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 18px 0 10px; break-inside: avoid; }
.metric { background: #f5f8fc; border: 1px solid #e0e7f0; border-radius: 8px; padding: 12px 16px; }
.metric span { color: #64748b; }.metric strong { display: block; color: #2563eb; font-size: 29px; line-height: 1.4; }
.metric.risk strong { color: #b45309; }.metric.critical strong { color: #b91c1c; }
.note { font-size: 10px; color: #64748b; margin: 0 0 16px; }
.filters { display: flex; flex-wrap: wrap; gap: 6px 16px; padding: 10px 12px; background: #f8fafc; border-left: 3px solid #94a3b8; margin: 12px 0 20px; overflow-wrap: anywhere; }
.filters b { color: #475569; margin-right: 5px; }
section { margin: 20px 0; }.section-heading { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; break-after: avoid; }
.number { color: #2563eb; background: #eff6ff; padding: 4px 9px; border-radius: 5px; font-weight: 700; }
h2 { margin: 0; font-size: 16px; overflow-wrap: anywhere; }.section-heading p { margin: 0; font-size: 10px; overflow-wrap: anywhere; }.section-heading > div { min-width: 0; flex: 1; }
.section-total { margin-left: auto; white-space: nowrap; color: #64748b; }
table { width: 100%; border-collapse: collapse; table-layout: fixed; }thead { display: table-header-group; }
th { text-align: left; background: #edf2f8; color: #475569; font-weight: 600; }
td, th { padding: 9px 8px; border-bottom: 1px solid #e2e8f0; vertical-align: top; overflow-wrap: anywhere; }
tr { break-inside: avoid; }tbody tr:nth-child(even) { background: #f8fafc; }
.path { font-family: "Microsoft YaHei", "Noto Sans CJK SC", sans-serif; font-size: 10px; color: #64748b; margin-top: 3px; word-break: break-all; }
.badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10px; white-space: nowrap; background: #eef2f6; color: #475569; }
.badge.critical { background: #fee2e2; color: #991b1b; }.badge.high { background: #ffedd5; color: #9a3412; }.badge.medium { background: #fef3c7; color: #92400e; }.badge.low { background: #dbeafe; color: #1e40af; }.badge.clean { background: #dcfce7; color: #166534; }
.malicious { color: #b91c1c; font-size: 10px; margin-top: 4px; }.detail-title { font-size: 17px; margin: 14px 0; overflow-wrap: anywhere; break-after: avoid; }.detail th { width: 18%; }.empty { padding: 20px; background: #f8fafc; color: #64748b; }
footer { margin-top: 22px; padding-top: 10px; border-top: 1px solid #dce4ef; color: #64748b; font-size: 10px; }
</style></head><body><header class="header"><div class="brand">TRACEBASTION / STATIC RESOURCE SECURITY</div><h1>${escape(title)}</h1><div class="meta">生成时间：${escape(time(options.generatedAt ?? new Date().toISOString()))} · 覆盖 ${sections.length} 个 Agent</div></header><div class="metrics">${metrics}</div><p class="note">统计基于本次导出的资源；风险资源指中风险、高风险及严重风险资源。扫描结果反映最近一次记录。</p>${filters ? `<div class="filters">${filters}</div>` : ""}${body || '<p class="empty">当前范围内没有静态资源。</p>'}<footer>TraceBastion · 静态资源安全检测报告</footer></body></html>`;
}
