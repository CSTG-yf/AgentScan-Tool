import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  CloseCircleOutlined,
  DatabaseOutlined,
  PlayCircleOutlined,
  ReloadOutlined,
  SaveOutlined,
  SyncOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  InputNumber,
  Progress,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType } from "antd/es/table";
import {
  cancelScanJob,
  createScanJob,
  getBackendScanSchedules,
  getScanJob,
  getScanJobs,
  updateBackendScanSchedule,
} from "../bridge";
import type {
  BackendScanSchedule,
  ScanJob,
  ScanScheduleSettings,
  ScanTaskKey,
  ScanTaskType,
  StaticResourceScanSettings,
} from "../types";
import "./runtime-workbench.css";

const { Text, Title } = Typography;

const TASK_COPY: Record<ScanTaskType, { title: string; description: string }> = {
  agent_discovery: { title: "Agent 发现", description: "重新枚举 Agent 实例并更新清单" },
  static_assets: { title: "静态资源扫描", description: "扫描资源及其风险发现" },
  runtime_detections: { title: "事件检测重放", description: "基于历史行为事件重新检测" },
  attack_chains: { title: "攻击链重建", description: "重新生成攻击链和关联证据" },
  behavior_trace: { title: "行为追踪", description: "由运行时事件流持续采集" },
  environment: { title: "环境状态", description: "由桌面原生宿主负责采集" },
};

const MANUAL_TASKS: ScanTaskType[] = ["agent_discovery", "static_assets", "runtime_detections", "attack_chains"];
const MODE_BY_TASK: Record<ScanTaskType, BackendScanSchedule["mode"]> = {
  agent_discovery: "full",
  static_assets: "full",
  runtime_detections: "replay",
  attack_chains: "rebuild",
  behavior_trace: "incremental",
  environment: "incremental",
};
const NATIVE_OWNED = new Set<ScanTaskType>(["behavior_trace", "environment"]);

const REFRESH_COPY: Record<ScanTaskKey, { title: string; description: string }> = {
  environment: { title: "安全总览", description: "环境、Agent、异常事件和攻击链摘要" },
  agentDiscovery: { title: "Agent 检测", description: "Agent 清单与运行状态" },
  staticAssets: { title: "静态资源检测", description: "资源与风险发现" },
  behaviorTrace: { title: "行为追踪", description: "行为事件和轨迹" },
  eventDetection: { title: "事件检测", description: "异常检测列表与汇总" },
  processGuardAudit: { title: "攻击链", description: "攻击链列表与汇总" },
  gatewayAudit: { title: "告警中心", description: "异常告警与响应动作" },
  rangeStatus: { title: "靶场状态", description: "靶场服务与回放状态" },
};
const REFRESH_KEYS = Object.keys(REFRESH_COPY) as ScanTaskKey[];

function statusTag(status?: string) {
  const normalized = status === "success" ? "completed" : status || "unknown";
  const copy: Record<string, string> = { queued: "排队中", running: "运行中", completed: "成功", failed: "失败", cancelled: "已取消" };
  const color: Record<string, string> = { queued: "blue", running: "processing", completed: "success", failed: "error", cancelled: "default" };
  return <Tag color={color[normalized]}>{copy[normalized] ?? normalized}</Tag>;
}

function formatTime(value?: string) {
  if (!value) return "-";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString("zh-CN", { hour12: false });
}

export interface ScanRefreshSettingsPageProps {
  scanSettings?: ScanScheduleSettings;
  staticScanSettings?: StaticResourceScanSettings;
  savingScanSettings?: boolean;
  savingStaticScanSettings?: boolean;
  onScanSettingsChange: (settings: ScanScheduleSettings) => void | Promise<void>;
  onStaticScanSettingsChange: (settings: StaticResourceScanSettings) => void | Promise<void>;
  onRefreshData: () => void | Promise<void>;
}

export function ScanRefreshSettingsPage({
  scanSettings,
  staticScanSettings,
  savingScanSettings,
  savingStaticScanSettings,
  onScanSettingsChange,
  onStaticScanSettingsChange,
  onRefreshData,
}: ScanRefreshSettingsPageProps) {
  const [schedules, setSchedules] = useState<BackendScanSchedule[]>([]);
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [jobsTotal, setJobsTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [savingTask, setSavingTask] = useState<ScanTaskType>();
  const [startingTask, setStartingTask] = useState<ScanTaskType>();
  const [selectedJob, setSelectedJob] = useState<ScanJob>();
  const [refreshDraft, setRefreshDraft] = useState(scanSettings);
  const [staticDraft, setStaticDraft] = useState(staticScanSettings);
  const runningIDsRef = useRef<Set<string>>(new Set());

  useEffect(() => setRefreshDraft(scanSettings), [scanSettings]);
  useEffect(() => setStaticDraft(staticScanSettings), [staticScanSettings]);

  const loadServerData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const [scheduleResponse, jobResponse] = await Promise.all([getBackendScanSchedules(), getScanJobs({ limit: 20 })]);
      setSchedules(scheduleResponse.items ?? []);
      setJobs(jobResponse.items ?? jobResponse.jobs ?? []);
      setJobsTotal(jobResponse.total ?? 0);
    } catch (error) {
      if (!quiet) message.error(`读取扫描策略失败：${String(error)}`);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => { void loadServerData(); }, [loadServerData]);

  const runningJobs = useMemo(() => jobs.filter((job) => job.status === "queued" || job.status === "running"), [jobs]);
  useEffect(() => {
    const next = new Set(runningJobs.map((job) => job.job_id));
    const completedSinceLastPoll = [...runningIDsRef.current].some((id) => !next.has(id));
    runningIDsRef.current = next;
    if (completedSinceLastPoll) void onRefreshData();
  }, [runningJobs, onRefreshData]);

  useEffect(() => {
    if (runningJobs.length === 0) return;
    const timer = window.setInterval(() => void loadServerData(true), 1000);
    return () => window.clearInterval(timer);
  }, [loadServerData, runningJobs.length]);

  const patchSchedule = (taskType: ScanTaskType, patch: Partial<BackendScanSchedule>) => {
    setSchedules((current) => current.map((item) => item.task_type === taskType ? { ...item, ...patch } : item));
  };

  const saveSchedule = async (schedule: BackendScanSchedule) => {
    setSavingTask(schedule.task_type);
    try {
      const saved = await updateBackendScanSchedule(schedule);
      patchSchedule(schedule.task_type, saved);
      message.success(`${TASK_COPY[schedule.task_type].title}策略已保存`);
    } catch (error) {
      message.error(`保存扫描策略失败：${String(error)}`);
      await loadServerData(true);
    } finally {
      setSavingTask(undefined);
    }
  };

  const startJob = async (taskType: ScanTaskType) => {
    setStartingTask(taskType);
    try {
      const job = await createScanJob(taskType, MODE_BY_TASK[taskType]);
      message.success(`已创建任务 ${job.job_id}`);
      await loadServerData(true);
    } catch (error) {
      message.error(`创建任务失败：${String(error)}`);
    } finally {
      setStartingTask(undefined);
    }
  };

  const cancelJob = async (job: ScanJob) => {
    try {
      await cancelScanJob(job.job_id);
      message.success("已请求取消任务");
      await loadServerData(true);
    } catch (error) {
      message.error(`取消任务失败：${String(error)}`);
    }
  };

  const openJob = async (job: ScanJob) => {
    setSelectedJob(job);
    try {
      setSelectedJob(await getScanJob(job.job_id));
    } catch (error) {
      message.error(`读取任务详情失败：${String(error)}`);
    }
  };

  const columns: ColumnsType<ScanJob> = [
    { title: "任务", dataIndex: "task_type", width: 150, render: (value: ScanTaskType) => TASK_COPY[value]?.title ?? value },
    { title: "触发", dataIndex: "trigger", width: 90, render: (value) => <Tag>{value}</Tag> },
    { title: "状态", dataIndex: "status", width: 90, render: statusTag },
    { title: "阶段", dataIndex: "phase", width: 110, render: (value) => value || "-" },
    {
      title: "进度", width: 180, render: (_, job) => (
        <Space direction="vertical" size={0} style={{ width: "100%" }}>
          <Progress percent={job.progress ?? 0} size="small" status={job.status === "failed" ? "exception" : undefined} />
          <Text type="secondary">{job.total ? `${job.current ?? 0} / ${job.total}` : `${job.progress ?? 0}%`}</Text>
        </Space>
      ),
    },
    { title: "开始时间", dataIndex: "started_at", width: 180, render: formatTime },
    { title: "错误", dataIndex: "error", ellipsis: true, render: (value) => value ? <Text type="danger">{value}</Text> : "-" },
    {
      title: "操作", width: 90, fixed: "right", render: (_, job) => (
        job.status === "queued" || job.status === "running"
          ? <Button danger type="link" size="small" onClick={(event) => { event.stopPropagation(); void cancelJob(job); }}>取消</Button>
          : <Button type="link" size="small" onClick={(event) => { event.stopPropagation(); void openJob(job); }}>详情</Button>
      ),
    },
  ];

  const latestJob = jobs[0];
  const configurableScheduleCount = schedules.filter((item) => !NATIVE_OWNED.has(item.task_type)).length;
  const enabledScheduleCount = schedules.some((item) => item.enabled) ? 1 : 0;
  const enabledRefreshCount = refreshDraft ? REFRESH_KEYS.filter((key) => refreshDraft[key].enabled).length : 0;
  const enabledTriggers = (staticDraft?.realtimeEnabled ? 1 : 0) + (enabledScheduleCount || staticDraft?.rescanEnabled ? 1 : 0);

  return (
    <section className="scan-refresh-page">
      <div className="runtime-workbench-heading">
        <div>
          <Text className="eyebrow">SCAN AND REFRESH</Text>
          <Title level={3}>扫描与刷新策略</Title>
          <Text type="secondary">刷新只读取数据库；扫描、重放和重建会创建可追踪的后端任务。</Text>
        </div>
        <Button icon={<ReloadOutlined />} loading={loading} onClick={() => { void loadServerData(); void onRefreshData(); }}>刷新数据</Button>
      </div>

      <div className="runtime-workbench-metrics scan-refresh-metrics">
        <Card className="runtime-workbench-metric"><DatabaseOutlined /><Text>后端扫描策略</Text><strong>{configurableScheduleCount}</strong></Card>
        <Card className="runtime-workbench-metric metric-1"><SyncOutlined /><Text>已启用扫描触发</Text><strong>{enabledTriggers}</strong></Card>
        <Card className="runtime-workbench-metric metric-2"><ReloadOutlined /><Text>自动刷新页面</Text><strong>{enabledRefreshCount}</strong></Card>
        <Card className="runtime-workbench-metric metric-3"><PlayCircleOutlined /><Text>最近扫描任务</Text><div className="scan-refresh-latest">{latestJob ? statusTag(latestJob.status) : <Tag>暂无</Tag>}<Text>{latestJob ? TASK_COPY[latestJob.task_type]?.title : "尚无记录"}</Text></div></Card>
      </div>

      <Card title="后端扫描策略" extra={<Text type="secondary">各任务独立调度，同类任务运行时自动去重</Text>}>
        <div className="scan-refresh-policy-list">
          {schedules.map((schedule) => {
            const nativeOwned = NATIVE_OWNED.has(schedule.task_type);
            return (
              <div className="scan-refresh-policy-row" key={schedule.task_type}>
                <div><Text strong>{TASK_COPY[schedule.task_type].title}</Text><Text type="secondary">{TASK_COPY[schedule.task_type].description}</Text></div>
                <Switch disabled={nativeOwned} checked={schedule.enabled} onChange={(enabled) => patchSchedule(schedule.task_type, { enabled })} />
                <InputNumber min={3} max={86400} addonAfter="秒" value={schedule.interval_sec} disabled={nativeOwned} onChange={(value) => patchSchedule(schedule.task_type, { interval_sec: value ?? schedule.interval_sec })} />
                <Select value={schedule.mode} disabled={nativeOwned} onChange={(mode) => patchSchedule(schedule.task_type, { mode })} options={[
                  { value: "full", label: "全量" }, { value: "incremental", label: "增量" }, { value: "replay", label: "重放" }, { value: "rebuild", label: "重建" },
                ]} />
                {nativeOwned ? <Tag>事件驱动</Tag> : <Button icon={<SaveOutlined />} loading={savingTask === schedule.task_type} onClick={() => void saveSchedule(schedule)}>保存</Button>}
              </div>
            );
          })}
        </div>
      </Card>

      {staticDraft && (
        <Card title="静态资源 Watcher" extra={<Button icon={<SaveOutlined />} loading={savingStaticScanSettings} onClick={() => void onStaticScanSettingsChange(staticDraft)}>保存 Watcher 配置</Button>}>
          <div className="scan-refresh-watcher-grid">
            <label><Text>文件变化实时扫描</Text><Switch checked={staticDraft.realtimeEnabled} onChange={(value) => setStaticDraft({ ...staticDraft, realtimeEnabled: value })} /></label>
            <label><Text>定时兜底复扫</Text><Switch checked={staticDraft.rescanEnabled} onChange={(value) => setStaticDraft({ ...staticDraft, rescanEnabled: value })} /></label>
            <label><Text>实时扫描防抖</Text><InputNumber min={100} max={60000} addonAfter="ms" value={staticDraft.debounceMs} onChange={(value) => setStaticDraft({ ...staticDraft, debounceMs: value ?? 500 })} /></label>
            {(["credentialIntervalMin", "mcpIntervalMin", "skillIntervalMin", "pluginIntervalMin", "promptIntervalMin", "environmentIntervalMin"] as const).map((key) => (
              <label key={key}><Text>{({ credentialIntervalMin: "Credential", mcpIntervalMin: "MCP", skillIntervalMin: "Skill", pluginIntervalMin: "Plugin", promptIntervalMin: "Prompt", environmentIntervalMin: "Environment" })[key]} 复扫</Text><InputNumber min={1} max={1440} addonAfter="分钟" value={staticDraft[key]} onChange={(value) => setStaticDraft({ ...staticDraft, [key]: value ?? 1 })} /></label>
            ))}
          </div>
        </Card>
      )}

      <Card title={`手动扫描任务 · 最近 20 条 / 共 ${jobsTotal} 条`} extra={<Text type="secondary">任务完成后自动刷新页面数据</Text>}>
        <div className="scan-refresh-actions">
          {MANUAL_TASKS.map((taskType) => {
            const running = runningJobs.some((job) => job.task_type === taskType);
            return <div className="scan-refresh-action-card" key={taskType}>
              <div><Text strong>{TASK_COPY[taskType].title}</Text><Text type="secondary">{TASK_COPY[taskType].description}</Text></div>
              <Button type="primary" icon={running ? <SyncOutlined spin /> : <PlayCircleOutlined />} loading={startingTask === taskType} disabled={running} onClick={() => void startJob(taskType)}>{running ? "扫描中" : "开始扫描"}</Button>
            </div>;
          })}
        </div>
        <Table<ScanJob> rowKey="job_id" size="small" loading={loading} columns={columns} dataSource={jobs} scroll={{ x: 1100 }} pagination={false} onRow={(job) => ({ onClick: () => void openJob(job) })} />
      </Card>

      {refreshDraft && (
        <Card title="页面自动刷新策略" extra={<Button type="primary" icon={<SaveOutlined />} loading={savingScanSettings} onClick={() => void onScanSettingsChange(refreshDraft)}>保存刷新配置</Button>}>
          <Alert showIcon type="info" message="页面切到后台时暂停轮询；连续失败时自动退避。打开的事件和攻击链详情不会被定时刷新替换。" />
          <div className="scan-refresh-policy-list scan-refresh-page-list">
            {REFRESH_KEYS.map((key) => (
              <div className="scan-refresh-policy-row" key={key}>
                <div><Text strong>{REFRESH_COPY[key].title}</Text><Text type="secondary">{REFRESH_COPY[key].description}</Text></div>
                <Switch checked={refreshDraft[key].enabled} onChange={(enabled) => setRefreshDraft({ ...refreshDraft, [key]: { ...refreshDraft[key], enabled } })} />
                <InputNumber min={3} max={3600} addonAfter="秒" value={refreshDraft[key].intervalSec} onChange={(value) => setRefreshDraft({ ...refreshDraft, [key]: { ...refreshDraft[key], intervalSec: value ?? 3 } })} />
              </div>
            ))}
          </div>
        </Card>
      )}

      <Drawer title="扫描任务详情" width={720} open={!!selectedJob} onClose={() => setSelectedJob(undefined)}>
        {selectedJob && <Space direction="vertical" size={16} style={{ width: "100%" }}>
          {selectedJob.error && <Alert type="error" showIcon message="任务失败" description={selectedJob.error} />}
          <Descriptions bordered size="small" column={2} items={[
            { key: "id", label: "Job ID", span: 2, children: selectedJob.job_id },
            { key: "task", label: "任务", children: TASK_COPY[selectedJob.task_type]?.title ?? selectedJob.task_type },
            { key: "status", label: "状态", children: statusTag(selectedJob.status) },
            { key: "trigger", label: "触发来源", children: selectedJob.trigger },
            { key: "mode", label: "模式", children: selectedJob.mode || "-" },
            { key: "phase", label: "阶段", children: selectedJob.phase || "-" },
            { key: "progress", label: "进度", children: `${selectedJob.progress ?? 0}% (${selectedJob.current ?? 0}/${selectedJob.total ?? 0})` },
            { key: "started", label: "开始", children: formatTime(selectedJob.started_at) },
            { key: "finished", label: "结束", children: formatTime(selectedJob.finished_at) },
          ]} />
          <div><Text strong>范围</Text><pre className="scan-refresh-json">{JSON.stringify(selectedJob.scope ?? {}, null, 2)}</pre></div>
          <div><Text strong>结果</Text><pre className="scan-refresh-json">{JSON.stringify(selectedJob.result ?? {}, null, 2)}</pre></div>
          {(selectedJob.status === "queued" || selectedJob.status === "running") && <Button danger icon={<CloseCircleOutlined />} onClick={() => void cancelJob(selectedJob)}>取消任务</Button>}
        </Space>}
      </Drawer>
    </section>
  );
}
