import { invoke } from "@tauri-apps/api/core";
import type { RuntimeBlacklist, RuntimeEvaluation, RuntimeRiskData, RuntimeRiskPolicy, RuntimeRiskPolicyRule, RuntimeRule, RuntimeSettingsOverview, RuntimeSettingsPage, RuntimeSettingsQuery, RuntimeTypeDetail, RuntimeTypeRow, RuntimeTypeSettings } from "./types";

async function request<T>(method: "GET" | "POST" | "PATCH" | "PUT" | "DELETE", path: string, body?: unknown): Promise<T> {
  if (!("__TAURI_INTERNALS__" in window)) throw new Error("异常检测设置需要连接桌面网关。请在 TraceBastion 桌面应用中打开此页面。");
  return invoke<T>("runtime_detection_settings_request", { method, path, body: body ?? null });
}
function queryPath(path: string, query: RuntimeSettingsQuery) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) if (value !== undefined && value !== "") params.set(key, String(value));
  return `${path}?${params}`;
}
const typePath = (id: number) => `/agent-types/${id}`;
const rulesPath = (typeId?: number) => typeId === undefined ? "/rules" : `${typePath(typeId)}/rules`;

export const getRuntimeSettingsOverview = () => request<RuntimeSettingsOverview>("GET", "/overview");
export const getGlobalRuntimeRiskPolicy = () => request<RuntimeRiskPolicy>("GET", "/risk-policy/global");
export const getRuntimeRules = (query: RuntimeSettingsQuery, typeId?: number) => request<RuntimeSettingsPage<RuntimeRule>>("GET", queryPath(rulesPath(typeId), query));
export const createRuntimeRule = (body: Partial<RuntimeRule>, typeId?: number) => request<RuntimeRule>("POST", rulesPath(typeId), body);
export const patchRuntimeRule = (id: number, body: Partial<RuntimeRule>, typeId?: number) => request<RuntimeRule>("PATCH", `${rulesPath(typeId)}/${id}`, body);
export const deleteRuntimeRule = (id: number, typeId?: number) => request<{ deleted: boolean }>("DELETE", `${rulesPath(typeId)}/${id}`);
export const getRuntimeTypes = (query: RuntimeSettingsQuery) => request<RuntimeSettingsPage<RuntimeTypeRow>>("GET", queryPath("/agent-types", query));
export const getRuntimeTypeDetail = (id: number) => request<RuntimeTypeDetail>("GET", typePath(id));
export const patchRuntimeTypeSettings = (id: number, body: Pick<RuntimeTypeSettings, "enabled" | "inherit_global_rules" | "use_global_risk_policy">) => request<RuntimeTypeSettings>("PATCH", `${typePath(id)}/settings`, body);
export const getRuntimeBlacklist = (id: number, query: RuntimeSettingsQuery) => request<RuntimeSettingsPage<RuntimeBlacklist>>("GET", queryPath(`${typePath(id)}/blacklist`, query));
export const createRuntimeBlacklist = (typeId: number, body: Partial<RuntimeBlacklist>) => request<RuntimeBlacklist>("POST", `${typePath(typeId)}/blacklist`, body);
export const patchRuntimeBlacklist = (typeId: number, id: number, body: Partial<RuntimeBlacklist>) => request<RuntimeBlacklist>("PATCH", `${typePath(typeId)}/blacklist/${id}`, body);
export const deleteRuntimeBlacklist = (typeId: number, id: number) => request<{ deleted: boolean }>("DELETE", `${typePath(typeId)}/blacklist/${id}`);
export const saveRuntimeRiskPolicy = (typeId: number, useGlobal: boolean, policy?: { name: string; rules: RuntimeRiskPolicyRule[] }) => request<RuntimeRiskData>("PUT", `${typePath(typeId)}/risk-policy`, { use_global_risk_policy: useGlobal, policy });
export const evaluateRuntimeEvent = (typeId: number, event: Record<string, unknown>) => request<RuntimeEvaluation>("POST", `${typePath(typeId)}/evaluate`, { event });
