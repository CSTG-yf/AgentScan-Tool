import { exportPageReportPdf, exportTextFileToDirectory, isDesktopRuntime, selectExportDirectory } from "../bridge";

export type ExportFormat = "pdf" | "markdown" | "json" | "csv";

export interface ExportFileOptions {
  defaultFileName: string;
  content: string;
  format: ExportFormat;
}

/** `undefined` means browser preview mode; `null` means the desktop picker was cancelled. */
export async function chooseExportDirectory(title: string): Promise<string | null | undefined> {
  if (!isDesktopRuntime()) return undefined;
  return selectExportDirectory(title);
}

export async function exportFileToDirectory(directory: string | undefined, options: ExportFileOptions): Promise<string> {
  if (directory !== undefined) {
    if (options.format === "pdf") {
      return exportPageReportPdf(options.content, options.defaultFileName, directory);
    }
    return exportTextFileToDirectory(directory, options.content, options.defaultFileName);
  }

  if (options.format === "pdf") {
    throw new Error("浏览器预览模式不支持生成 PDF，请在桌面应用中导出");
  }
  const mimeType = {
    markdown: "text/markdown;charset=utf-8",
    json: "application/json;charset=utf-8",
    csv: "text/csv;charset=utf-8",
  }[options.format];
  const url = URL.createObjectURL(new Blob([options.content], { type: mimeType }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = options.defaultFileName;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return options.defaultFileName;
}

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

export async function exportTablePdf(options: { directory: string | undefined; title: string; fileName: string; filters: Record<string, unknown>; columns: string[]; rows: unknown[][] }) {
  const filterRows = Object.entries(options.filters).filter(([, value]) => value !== undefined && value !== "" && value !== false);
  const filters = filterRows.length ? filterRows.map(([key, value]) => `<span><b>${escapeHtml(key)}</b>：${escapeHtml(value)}</span>`).join("") : "<span>无筛选条件</span>";
  const head = options.columns.map(column => `<th>${escapeHtml(column)}</th>`).join("");
  const body = options.rows.map(row => `<tr>${row.map(value => `<td>${escapeHtml(value)}</td>`).join("")}</tr>`).join("");
  const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><style>@page{size:A4 landscape;margin:11mm}*{box-sizing:border-box}body{color:#172033;font:11px/1.5 "Microsoft YaHei",sans-serif}h1{font-size:22px;margin:0 0 4px}.meta{color:#667085;margin-bottom:12px}.filters{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 14px}.filters span{padding:3px 7px;background:#edf4ff;border-radius:4px}table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:6px;border:1px solid #dfe5ef;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f3f6fa;color:#475467}tr{break-inside:avoid}</style></head><body><h1>${escapeHtml(options.title)}</h1><div class="meta">导出时间：${escapeHtml(new Date().toLocaleString("zh-CN"))} · 共 ${options.rows.length} 条</div><div class="filters">${filters}</div><table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${options.columns.length}">暂无数据</td></tr>`}</tbody></table></body></html>`;
  return exportFileToDirectory(options.directory, { content: html, defaultFileName: options.fileName, format: "pdf" });
}
