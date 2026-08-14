import { invoke } from "@tauri-apps/api/core";
import type { AgentSnapshot, EnvironmentSnapshot, GatewayAuditSnapshot, GuardAuditSnapshot, GuardPolicy, RangeMode, RangeReplayStatus, RangeStatus } from "./types";

const inTauri = (): boolean => "__TAURI_INTERNALS__" in window;

const browserEnvironment = (): EnvironmentSnapshot => ({
  capturedAt: new Date().toISOString(),
  components: [
    { id: "gateway", label: "DefenseClaw Gateway", state: "unknown", detail: "桌面宿主未连接" },
    { id: "docker", label: "Docker Desktop", state: "unknown", detail: "桌面宿主未连接" },
    { id: "agentrange", label: "AgentRange 靶场", state: "unknown", detail: "桌面宿主未连接" },
    { id: "processGuard", label: "Windows 进程守护", state: "unknown", detail: "桌面宿主未连接", requiresElevation: true },
  ],
});

export async function getEnvironment(): Promise<EnvironmentSnapshot> {
  return inTauri() ? invoke<EnvironmentSnapshot>("get_environment_snapshot") : browserEnvironment();
}

export async function getAgentProcesses(): Promise<AgentSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), processes: [], warning: "浏览器预览模式不具备本机进程访问权限" };
  }
  return invoke<AgentSnapshot>("get_agent_processes");
}

export async function getGuardPolicy(): Promise<GuardPolicy> {
  if (!inTauri()) {
    return {
      version: 1,
      enabled: false,
      mode: "observe",
      agentNames: [],
      rules: [],
      termination: { gracePeriodMs: 1500, verifyProcessIdentity: true, protectedProcessBehavior: "auditOnly" },
    };
  }
  return invoke<GuardPolicy>("get_guard_policy");
}

export async function saveGuardPolicy(policy: GuardPolicy): Promise<GuardPolicy> {
  if (!inTauri()) return policy;
  return invoke<GuardPolicy>("save_guard_policy", { policy });
}

export async function installProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以安装 Windows 服务");
  await invoke("install_process_guard");
}

export async function applyProcessGuardPolicy(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以应用系统策略");
  await invoke("apply_process_guard_policy");
}

export async function uninstallProcessGuard(): Promise<void> {
  if (!inTauri()) throw new Error("仅桌面应用可以卸载 Windows 服务");
  await invoke("uninstall_process_guard");
}

export async function getProcessGuardAudit(limit = 200): Promise<GuardAuditSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), path: "C:\\ProgramData\\DefenseClaw\\audit\\process-guard.jsonl", events: [], warning: "浏览器预览模式不读取本机审计文件" };
  }
  return invoke<GuardAuditSnapshot>("get_process_guard_audit", { limit });
}

export async function getGatewayAudit(limit = 200): Promise<GatewayAuditSnapshot> {
  if (!inTauri()) {
    return { capturedAt: new Date().toISOString(), source: "defenseclaw-gateway audit export", events: [], warning: "浏览器预览模式不读取网关审计数据库" };
  }
  return invoke<GatewayAuditSnapshot>("get_gateway_audit", { limit });
}

export interface LifecycleResult {
  action: string;
  success: boolean;
  message: string;
}

export async function setGatewayRunning(running: boolean): Promise<LifecycleResult> {
  if (!inTauri()) throw new Error("仅桌面应用可以控制网关");
  return invoke<LifecycleResult>(running ? "start_gateway" : "stop_gateway");
}

export async function getRangeStatus(): Promise<RangeStatus> {
  if (!inTauri()) return { configured: false, root: "", composeFile: "", adapterComposeFile: "", mode: "baseline", dockerAvailable: false, runningServices: [], state: "unconfigured", detail: "Desktop host is not connected" };
  return invoke<RangeStatus>("get_range_status");
}

export async function saveRangeRoot(root: string): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can configure the range");
  return invoke<RangeStatus>("set_range_root", { root });
}

export async function saveDefenseMode(mode: RangeMode): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can configure the DefenseClaw mode");
  return invoke<RangeStatus>("set_range_mode", { mode });
}

export const saveRangeMode = saveDefenseMode;

export async function setRangeRunning(running: boolean): Promise<RangeStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can control the range");
  return invoke<RangeStatus>(running ? "start_range" : "stop_range");
}

export async function getRangeReplayStatus(): Promise<RangeReplayStatus> {
  if (!inTauri()) return { running: false, command: "", scenario: "", startedAt: "", completed: 0, total: 0, remaining: 0, detail: "Desktop host is not connected", log: [] };
  return invoke<RangeReplayStatus>("get_range_replay_status");
}

export async function startRangeReplay(command: string): Promise<RangeReplayStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can run AgentRange replay");
  return invoke<RangeReplayStatus>("start_range_replay", { command });
}

export async function stopRangeReplay(): Promise<RangeReplayStatus> {
  if (!inTauri()) throw new Error("Only the desktop app can stop AgentRange replay");
  return invoke<RangeReplayStatus>("stop_range_replay");
}
