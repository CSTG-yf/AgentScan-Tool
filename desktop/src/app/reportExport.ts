import { exportPageReportPdf } from "../bridge";

export const escapeHtml = (value: unknown) => String(value ?? "").replace(/[&<>"']/g, character => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character] || character));

export async function collectAllPages<T>(load: (page: number, pageSize: number) => Promise<{ items?: T[]; total?: number }>, pageSize = 500) {
  const rows: T[] = [];
  for (let page = 1; ; page += 1) {
    const response = await load(page, pageSize);
    const items = response.items ?? [];
    rows.push(...items);
    if (!items.length || rows.length >= (response.total ?? rows.length)) break;
  }
  return rows;
}

export async function exportTablePdf(options: { title: string; fileName: string; filters: Record<string, unknown>; columns: string[]; rows: unknown[][] }) {
  const filterRows = Object.entries(options.filters).filter(([, value]) => value !== undefined && value !== "" && value !== false);
  const filters = filterRows.length ? filterRows.map(([key, value]) => `<span><b>${escapeHtml(key)}</b>：${escapeHtml(value)}</span>`).join("") : "<span>无筛选条件</span>";
  const head = options.columns.map(column => `<th>${escapeHtml(column)}</th>`).join("");
  const body = options.rows.map(row => `<tr>${row.map(value => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`).join("");
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>@page{size:A4 landscape;margin:11mm}*{box-sizing:border-box}body{color:#172033;font:11px/1.5 "Microsoft YaHei",sans-serif}h1{font-size:22px;margin:0 0 4px}.meta{color:#667085;margin-bottom:12px}.filters{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 14px}.filters span{padding:3px 7px;background:#edf4ff;border-radius:4px}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:6px;border:1px solid #dfe5ef;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f3f6fa;color:#475467}tr{break-inside:avoid}</style></head><body><h1>${escapeHtml(options.title)}</h1><div class="meta">导出时间：${escapeHtml(new Date().toLocaleString("zh-CN"))} · 共 ${options.rows.length} 条</div><div class="filters">${filters}</div><table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${options.columns.length}">暂无数据</td></tr>`}</tbody></table></body></html>`;
  return exportPageReportPdf(html, options.fileName);
}
