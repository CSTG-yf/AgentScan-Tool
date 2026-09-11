import { Alert, Badge, Button, Card, Divider, InputNumber, Space, Switch, Typography } from "antd";
import { ReloadOutlined, UndoOutlined } from "@ant-design/icons";
import { outcomeTag } from "../app/display";
import type {
  EnvironmentComponent,
  ScanScheduleSettings,
  ScanTaskKey,
  StaticResourceScanSettings,
} from "../types";

const { Text, Title } = Typography;

const scanTaskKeys: ScanTaskKey[] = [
  "environment",
  "agentDiscovery",
  "staticAssets",
  "behaviorTrace",
  "eventDetection",
  "processGuardAudit",
  "gatewayAudit",
  "rangeStatus",
];

const scanTaskCopy: Record<ScanTaskKey, { title: string; description: string }> = {
  environment: { title: "安全总览", description: "刷新总览中的环境、Agent、风险事件和攻击链摘要。" },
  agentDiscovery: { title: "Agent 发现", description: "重新枚举系统中的 Agent 进程和运行时信息。" },
  staticAssets: { title: "静态资源页面刷新", description: "刷新配置、技能、MCP、提示词等静态资源页面数据。" },
  behaviorTrace: { title: "行为追踪页面刷新", description: "刷新 Agent 进程、命令和文件访问轨迹。" },
  eventDetection: { title: "事件检测页面刷新", description: "刷新风险事件归并和检测结果展示。" },
  processGuardAudit: { title: "攻击链页面刷新", description: "刷新攻击链汇总和列表。" },
  gatewayAudit: { title: "告警中心页面刷新", description: "刷新异常检测和响应动作告警。" },
  rangeStatus: { title: "靶场状态", description: "检测 AgentRange 配置和服务运行状态。" },
};

const defaultScanSettings = (): ScanScheduleSettings => ({
  version: 1,
  environment: { enabled: true, intervalSec: 10 },
  agentDiscovery: { enabled: true, intervalSec: 15 },
  staticAssets: { enabled: true, intervalSec: 10 },
  behaviorTrace: { enabled: true, intervalSec: 15 },
  eventDetection: { enabled: true, intervalSec: 8 },
  processGuardAudit: { enabled: true, intervalSec: 10 },
  gatewayAudit: { enabled: true, intervalSec: 10 },
  rangeStatus: { enabled: true, intervalSec: 30 },
});

const recommendedStaticScanSettings = (): StaticResourceScanSettings => ({
  version: 1,
  realtimeEnabled: true,
  rescanEnabled: true,
  debounceMs: 500,
  skillIntervalMin: 15,
  pluginIntervalMin: 30,
  mcpIntervalMin: 10,
  promptIntervalMin: 15,
  credentialIntervalMin: 5,
  environmentIntervalMin: 30,
});

type StaticIntervalKey =
  | "credentialIntervalMin"
  | "mcpIntervalMin"
  | "skillIntervalMin"
  | "pluginIntervalMin"
  | "promptIntervalMin"
  | "environmentIntervalMin";

const staticIntervalRows: Array<{
  key: StaticIntervalKey;
  title: string;
  description: string;
  tone: "critical" | "high" | "medium" | "normal";
}> = [
  {
    key: "credentialIntervalMin",
    title: "Credential / API Key / Token",
    description: "风险最高，建议短间隔复扫，避免明文密钥长时间暴露。",
    tone: "critical",
  },
  {
    key: "mcpIntervalMin",
    title: "MCP 服务配置",
    description: "MCP 可能引入外部工具、命令或远程服务，建议高频复扫。",
    tone: "high",
  },
  {
    key: "skillIntervalMin",
    title: "Skill",
    description: "Skill 可能声明命令、文件、网络能力，安装和修改后需要及时复查。",
    tone: "high",
  },
  {
    key: "promptIntervalMin",
    title: "Prompt / Rules",
    description: "提示词和规则会影响 Agent 行为，内容变化需要被持续发现。",
    tone: "medium",
  },
  {
    key: "pluginIntervalMin",
    title: "Plugin",
    description: "插件可能执行代码，但变更频率通常低于 MCP 和 Skill。",
    tone: "medium",
  },
  {
    key: "environmentIntervalMin",
    title: "Environment",
    description: "环境变量变化不一定能被文件监听捕获，主要依赖周期复扫。",
    tone: "normal",
  },
];

interface SettingsPageProps {
  guardComponent?: EnvironmentComponent;
  scanSettings?: ScanScheduleSettings;
  staticScanSettings?: StaticResourceScanSettings;
  savingScanSettings: boolean;
  savingStaticScanSettings: boolean;
  onScanSettingsChange: (settings: ScanScheduleSettings) => void;
  onStaticScanSettingsChange: (settings: StaticResourceScanSettings) => void;
  onRunRefreshAll: () => void;
  onRequestGuardAction: (action: "install" | "start" | "apply" | "uninstall") => void;
}

export function SettingsPage({
  guardComponent,
  scanSettings,
  staticScanSettings,
  savingScanSettings,
  savingStaticScanSettings,
  onScanSettingsChange,
  onStaticScanSettingsChange,
  onRunRefreshAll,
  onRequestGuardAction,
}: SettingsPageProps) {
  const settings = scanSettings ?? defaultScanSettings();
  const staticSettings = staticScanSettings ?? recommendedStaticScanSettings();

  const updateTask = (task: ScanTaskKey, patch: Partial<ScanScheduleSettings[ScanTaskKey]>) => {
    onScanSettingsChange({
      ...settings,
      [task]: {
        ...settings[task],
        ...patch,
      },
    });
  };

  const updateStaticScan = (patch: Partial<StaticResourceScanSettings>) => {
    onStaticScanSettingsChange({
      ...staticSettings,
      ...patch,
    });
  };

  return (
    <section className="workspace-page settings-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">PRIVILEGE BOUNDARY</Text>
          <Title level={2}>系统设置</Title>
          <Text type="secondary">配置本机防护服务、权限边界，以及后台扫描和页面刷新策略。</Text>
        </div>
        {outcomeTag(guardComponent?.state === "ready" ? "debugPrivilegeEnabled" : "observed")}
      </div>

      <div className="settings-grid">
        <Card bordered={false} title="后端静态资源扫描" className="settings-wide-card">
          <div className="scan-settings-header">
            <div>
              <Text strong>实时扫描 + 定时兜底复扫</Text>
              <br />
              <Text type="secondary">这些设置会写入 exe 使用的后端 `watch:` 配置，控制真实的静态资源检测任务。</Text>
            </div>
            <Button
              icon={<UndoOutlined />}
              loading={savingStaticScanSettings}
              onClick={() => onStaticScanSettingsChange(recommendedStaticScanSettings())}
            >
              恢复推荐值
            </Button>
          </div>
          <Alert
            className="settings-alert"
            type="info"
            showIcon
            message="保存后会更新后端 config.yaml。若 Gateway 正在运行，请重启 Gateway，让 watcher 按新间隔重新启动。"
          />
          <Divider />

          <div className="static-scan-switches">
            <div className="scan-task-row static-scan-control">
              <div className="scan-task-copy">
                <Text strong>事件触发实时扫描</Text>
                <Text type="secondary">监听文件变化、安装变化和配置变化，变化后立即触发对应静态资源扫描。</Text>
              </div>
              <div className="scan-task-controls">
                <Switch
                  checked={staticSettings.realtimeEnabled}
                  checkedChildren="启用"
                  unCheckedChildren="关闭"
                  loading={savingStaticScanSettings}
                  onChange={(realtimeEnabled) => updateStaticScan({ realtimeEnabled })}
                />
              </div>
            </div>

            <div className="scan-task-row static-scan-control">
              <div className="scan-task-copy">
                <Text strong>定时兜底复扫</Text>
                <Text type="secondary">周期性全量或增量复扫，覆盖离线修改、监听丢事件和权限异常等漏检场景。</Text>
              </div>
              <div className="scan-task-controls">
                <Switch
                  checked={staticSettings.rescanEnabled}
                  checkedChildren="启用"
                  unCheckedChildren="关闭"
                  loading={savingStaticScanSettings}
                  onChange={(rescanEnabled) => updateStaticScan({ rescanEnabled })}
                />
              </div>
            </div>

            <div className="scan-task-row static-scan-control">
              <div className="scan-task-copy">
                <Text strong>实时扫描防抖</Text>
                <Text type="secondary">同一资源短时间内连续变化时合并处理，避免重复扫描。</Text>
              </div>
              <div className="scan-task-controls">
                <InputNumber
                  min={100}
                  max={10000}
                  step={100}
                  value={staticSettings.debounceMs}
                  disabled={!staticSettings.realtimeEnabled || savingStaticScanSettings}
                  onChange={(value) => {
                    if (typeof value === "number") updateStaticScan({ debounceMs: value });
                  }}
                />
                <Text type="secondary">ms</Text>
              </div>
            </div>
          </div>

          <Divider>定时复扫间隔</Divider>
          <div className="static-interval-grid">
            {staticIntervalRows.map((row) => (
              <div className={`static-interval-row static-interval-${row.tone}`} key={row.key}>
                <div className="scan-task-copy">
                  <Text strong>{row.title}</Text>
                  <Text type="secondary">{row.description}</Text>
                </div>
                <div className="scan-task-controls">
                  <InputNumber
                    min={1}
                    max={1440}
                    value={staticSettings[row.key]}
                    disabled={!staticSettings.rescanEnabled || savingStaticScanSettings}
                    onChange={(value) => {
                      if (typeof value === "number") updateStaticScan({ [row.key]: value });
                    }}
                  />
                  <Text type="secondary">分钟</Text>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card bordered={false} title="自动刷新任务" className="settings-wide-card">
          <div className="scan-settings-header">
            <Text type="secondary">这些间隔只控制 exe 页面数据刷新；真实静态资源检测由上面的后端扫描配置控制。</Text>
            <Button icon={<ReloadOutlined />} onClick={onRunRefreshAll}>立即刷新全部</Button>
          </div>
          <Divider />
          <div className="scan-task-list">
            {scanTaskKeys.map((task) => (
              <div className="scan-task-row" key={task}>
                <div className="scan-task-copy">
                  <Text strong>{scanTaskCopy[task].title}</Text>
                  <Text type="secondary">{scanTaskCopy[task].description}</Text>
                </div>
                <div className="scan-task-controls">
                  <Switch
                    checked={settings[task].enabled}
                    checkedChildren="启用"
                    unCheckedChildren="暂停"
                    loading={savingScanSettings}
                    onChange={(enabled) => updateTask(task, { enabled })}
                  />
                  <InputNumber
                    min={3}
                    max={3600}
                    value={settings[task].intervalSec}
                    disabled={!settings[task].enabled || savingScanSettings}
                    onChange={(value) => {
                      if (typeof value === "number") updateTask(task, { intervalSec: value });
                    }}
                  />
                  <Text type="secondary">秒</Text>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card bordered={false} title="Windows 进程守护">
          <Space direction="vertical" size="middle">
            <Text>{guardComponent?.detail ?? "正在检测服务状态"}</Text>
            <Space wrap>
              <Button type="primary" disabled={guardComponent?.state === "ready"} onClick={() => onRequestGuardAction("install")}>安装 / 修复服务</Button>
              <Button disabled={guardComponent?.state === "ready" || guardComponent?.state === "missing"} onClick={() => onRequestGuardAction("start")}>启动服务</Button>
              <Button disabled={guardComponent?.state !== "ready"} onClick={() => onRequestGuardAction("apply")}>应用当前策略</Button>
              <Button danger disabled={guardComponent?.state === "missing"} onClick={() => onRequestGuardAction("uninstall")}>卸载服务</Button>
            </Space>
          </Space>
        </Card>

        <Card bordered={false} title="权限模型">
          <Space direction="vertical">
            <Badge status="success" text="UI：当前用户，非提权运行" />
            <Badge status="processing" text="守护：LocalSystem Windows Service" />
            <Badge status="warning" text="终止：PID + 创建时间二次校验" />
            <Badge status="default" text="受保护进程：仅审计，不承诺终止" />
          </Space>
        </Card>
      </div>
    </section>
  );
}
