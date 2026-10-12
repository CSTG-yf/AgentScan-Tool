import { invoke } from "@tauri-apps/api/core";
export interface EvaluationMetric {
  key: string;
  domain: string;
  value: number | null;
  numerator: number | null;
  denominator: number | null;
  unit: string;
  formula: string;
  target: string;
  status: string;
  reason: string;
}
export interface EvaluationCounts {
  expected_unknown: number;
  discovered_unknown: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  unknown: number;
  expected: number;
  discovered: number;
  total: number;
}
export interface EvaluationInstance {
  id: string;
  domain: string;
  asset_type?: string;
  risk_kind?: string;
  scenario?: string;
  connector?: string;
  expected: boolean | null;
  predicted: boolean | null;
  business_success: boolean | null;
  decision?: string;
  response_status?: string;
  actually_blocked: boolean | null;
  side_effect_occurred: boolean | null;
  outcome: string;
  evidence: Record<string, string[]>;
}
export interface EvaluationArtifact {
  id: string;
  kind: string;
  source: string;
  sha256: string;
  content: string;
}
export interface EvaluationDistribution {
  id: string;
  kind: string;
  scope: string;
  basis: string;
  samples: number;
  expected_samples: number;
  window_start: string;
  window_end: string;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  status: string;
  artifact_id: string;
}
export interface EvaluationRun {
  id: string;
  name: string;
  mode: string;
  platform: string;
  code_version: string;
  config_hash: string;
  image_digest: string;
  dataset_hash: string;
  static_dataset_hash: string;
  comparison_group: string;
  static_truth: { artifact_id: string; dataset_hash: string; sha256: string };
  runtime_truth: { artifact_id: string; dataset_hash: string; sha256: string };
  started_at: string;
  finished_at: string;
  created_at: string;
  status: string;
  evidence_directory: string;
  notes: string[];
  report: {
    counts: Record<string, EvaluationCounts>;
    metrics: EvaluationMetric[];
    capability_status: Record<string, string>;
    breakdowns: Array<{
      dimension: string;
      name: string;
      domain: string;
      counts: EvaluationCounts;
      metrics: EvaluationMetric[];
    }>;
    distributions: EvaluationDistribution[];
    decisions: Record<string, number>;
    responses: Record<string, number>;
    business: Record<string, number>;
    risk_hits: Record<string, number>;
  };
}
export interface EvaluationFilters {
  domain?: string;
  outcome?: string;
  scenario?: string;
  connector?: string;
  limit?: number;
  offset?: number;
}
export async function evaluationRequest<T>(
  path = "",
  method = "GET",
  body?: unknown,
): Promise<T> {
  const fullPath = `/api/v1/evaluations${path}`;
  if ("__TAURI_INTERNALS__" in window)
    return invoke<T>("evaluation_request", {
      path: fullPath,
      method,
      body: body ?? null,
    });
  // Browser development uses a local Vite proxy; credentials stay in the proxy process.
  const response = await fetch(fullPath, {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const raw = await response.text();
  let data: { error?: string };
  try {
    data = JSON.parse(raw);
  } catch {
    throw new Error(
      response.ok
        ? "评测服务返回了无效数据"
        : `无法连接评测服务（HTTP ${response.status}）`,
    );
  }
  if (!response.ok)
    throw new Error(data.error || `评测服务返回 ${response.status}`);
  return data as T;
}
export const evaluationMetricNames: Record<string, string> = {
  asset_precision: "资产盘点准确率",
  asset_fnr: "资产盘点漏报率",
  risk_precision: "风险识别准确率",
  risk_recall: "风险识别召回率",
  risk_fnr: "风险识别漏报率",
  risk_fpr: "风险识别误报率",
  runtime_precision: "Precision",
  runtime_recall: "检出率 / Recall",
  runtime_fpr: "误报率 / FPR",
  runtime_fnr: "漏报率 / FNR",
  effective_block_rate: "有效阻断率",
  inspect_p95: "检查响应时间 P95",
  cpu_increment: "CPU 增量",
  business_success_rate: "正常业务成功率",
};
export const evaluationStatusNames: Record<string, string> = {
  passed: "达标",
  failed: "未达标",
  not_evaluated: "未评测",
  insufficient_evidence: "证据不足",
  incomplete_sampling: "采样不完整",
  complete: "采样完整",
  completed: "已完成",
  running: "进行中",
  cancelled: "已取消",
  unknown: "未知",
};
export function formatEvaluationMetric(metric?: EvaluationMetric) {
  if (!metric || metric.value === null) return "未评测";
  const number = metric.unit === "ratio" ? metric.value * 100 : metric.value;
  return `${number.toFixed(2)}${metric.unit === "ratio" ? "%" : metric.unit === "ms" ? " ms" : " 个百分点"}`;
}
