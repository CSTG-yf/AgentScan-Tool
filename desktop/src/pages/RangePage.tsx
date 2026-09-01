import { CaretRightOutlined, ExperimentOutlined, StopOutlined } from "@ant-design/icons";
import { Button, Card, Input, Progress, Space, Tag, Typography } from "antd";
import { defenseModeColors, defenseModeLabels } from "../app/display";
import { rangeAttackEvents } from "../data/range";
import type { RangeMode, RangeReplayStatus, RangeStatus } from "../types";

const { Text, Title } = Typography;

export interface RangePageProps {
  rangeStatus?: RangeStatus;
  rangeRoot: string;
  defenseMode: RangeMode;
  loading: boolean;
  replayCommand: string;
  replayStatus?: RangeReplayStatus;
  replayBusy: boolean;
  replayTotal: number;
  replayCompleted: number;
  replayRemaining: number;
  replayPercent: number;
  onRangeRootChange: (value: string) => void;
  onConfigureRange: () => void;
  onChangeRangeState: (running: boolean) => void;
  onReplayCommandChange: (value: string) => void;
  onFillReplayScenario: (scenario: string) => void;
  onStartReplay: (commandOverride?: string) => void;
  onStopReplay: () => void;
}

export function RangePage({
  rangeStatus,
  rangeRoot,
  defenseMode,
  loading,
  replayCommand,
  replayStatus,
  replayBusy,
  replayTotal,
  replayCompleted,
  replayRemaining,
  replayPercent,
  onRangeRootChange,
  onConfigureRange,
  onChangeRangeState,
  onReplayCommandChange,
  onFillReplayScenario,
  onStartReplay,
  onStopReplay,
}: RangePageProps) {
  return (
    <section>
      <div className="section-heading">
        <div>
          <Text className="eyebrow">AGENTRANGE RUNTIME</Text>
          <Title level={2}>靶场控制</Title>
          <Text type="secondary">验证本地 AgentRange Compose 工程，并通过兼容的容器运行时启动或停止服务。</Text>
        </div>
        <Tag color={rangeStatus?.state === "running" ? "success" : rangeStatus?.state === "invalid" ? "error" : "default"}>{rangeStatus?.state === "running" ? "运行中" : rangeStatus?.state === "stopped" ? "已停止" : "未就绪"}</Tag>
      </div>
      <Card bordered={false} className="range-hero">
        <div className="range-status-icon"><ExperimentOutlined /></div>
        <div className="range-status-copy">
          <Title level={4}>AgentRange-player</Title>
          <Text type="secondary">{rangeStatus?.detail ?? "正在检测靶场环境"}</Text>
          <div className="range-path">
            <Input value={rangeRoot} onChange={(event) => onRangeRootChange(event.target.value)} placeholder="例如 C:\\SecurityLabs\\AgentRange-player" />
            <Button onClick={onConfigureRange}>验证并保存</Button>
          </div>
        </div>
        <Space direction="vertical" size={10} className="range-actions">
          <Tag color={defenseModeColors[defenseMode]}>当前全局模式：{defenseModeLabels[defenseMode]}</Tag>
          <Space>
            <Button size="large" type="primary" disabled={!rangeStatus?.configured || !rangeStatus.dockerAvailable || rangeStatus.state === "running"} loading={loading} onClick={() => onChangeRangeState(true)}>启动靶场</Button>
            <Button className="range-stop-button" size="large" type="primary" danger icon={<StopOutlined />} disabled={rangeStatus?.state !== "running"} loading={loading} onClick={() => onChangeRangeState(false)}>停止靶场</Button>
          </Space>
        </Space>
      </Card>
      <Card bordered={false} title={`运行服务（${rangeStatus?.runningServices.length ?? 0}）`}>
        <div className="service-list">
          {rangeStatus?.runningServices.length ? rangeStatus.runningServices.map((service) => <Tag key={service} color="cyan">{service}</Tag>) : <Text type="secondary">当前没有运行中的 Compose 服务</Text>}
        </div>
        {rangeStatus?.composeFile && <div className="compose-path"><Text type="secondary">Compose：</Text><Text className="mono">{rangeStatus.composeFile}</Text></div>}
      </Card>
      <Card bordered={false} className="range-attack-card" title="攻击事件快捷执行">
        <div className="range-attack-grid">
          {rangeAttackEvents.map((event) => (
            <div key={event.scenario} className="range-attack-item">
              <div className="range-attack-heading"><Tag color={event.color}>{event.scenario}</Tag><Text type="secondary">{event.category}</Text></div>
              <strong>{event.title}</strong>
              <Text type="secondary">{event.trigger}</Text>
              <div className="range-attack-target"><Text type="secondary">入口：</Text><Text className="mono">{event.target}</Text></div>
              <div className="range-attack-command mono">{event.command}</div>
              <div className="range-attack-footer">
                <Tag color={event.color}>{event.risk}</Tag>
                <Space>
                  <Button size="small" onClick={() => onFillReplayScenario(event.scenario)}>填入命令</Button>
                  <Button className="range-execute-button" size="small" type="primary" icon={<CaretRightOutlined />} disabled={rangeStatus?.state !== "running" || replayStatus?.running} loading={replayBusy} onClick={() => onStartReplay(event.command)}>执行</Button>
                </Space>
              </div>
            </div>
          ))}
        </div>
      </Card>
      <Card bordered={false} className="range-replay-card" title="攻击回放命令">
        <div className="range-replay-toolbar">
          <Input.TextArea value={replayCommand} rows={3} onChange={(event) => onReplayCommandChange(event.target.value)} placeholder={'uv run --with httpx python ".\\task\\AgentRange-player\\scenario-runner\\runner.py" C2-A'} />
          <Space direction="vertical" className="range-replay-actions">
            <Button type="primary" size="large" disabled={rangeStatus?.state !== "running" || replayStatus?.running} loading={replayBusy} onClick={() => onStartReplay()}>运行攻击命令</Button>
            <Button danger size="large" disabled={!replayStatus?.running} loading={replayBusy} onClick={onStopReplay}>停止回放</Button>
          </Space>
        </div>
        <div className="range-replay-presets">
          <Text type="secondary">快捷场景</Text>
          {["C1-A", "C1-B", "C2-A", "C2-B", "C2-C", "C2-D", "M-1", "all"].map((scenario) => <Button key={scenario} size="small" onClick={() => onFillReplayScenario(scenario)}>{scenario === "all" ? "全部" : scenario}</Button>)}
        </div>
        <div className="range-progress-grid">
          <div><Text type="secondary">已完成事件</Text><strong>{replayCompleted}</strong></div>
          <div><Text type="secondary">剩余事件</Text><strong>{replayRemaining}</strong></div>
          <div><Text type="secondary">事件总数</Text><strong>{replayTotal}</strong></div>
          <div><Text type="secondary">当前场景</Text><strong>{replayStatus?.scenario || "未运行"}</strong></div>
        </div>
        <Progress percent={replayPercent} status={replayStatus?.running ? "active" : replayStatus?.exitCode === 0 ? "success" : replayStatus?.error ? "exception" : "normal"} />
        <div className="range-replay-meta">
          <Tag color={replayStatus?.running ? "processing" : replayStatus?.exitCode === 0 ? "success" : replayStatus?.error ? "error" : "default"}>{replayStatus?.running ? "回放进行中" : replayStatus?.exitCode === 0 ? "已完成" : replayStatus?.error ? "已停止/异常" : "未运行"}</Tag>
          {replayStatus?.pid && <Text type="secondary">PID {replayStatus.pid}</Text>}
          <Text type="secondary">{replayStatus?.detail ?? "尚未启动攻击回放"}</Text>
        </div>
        <div className="range-replay-log">{replayStatus?.log.length ? replayStatus.log.map((line, index) => <div key={`${index}-${line}`} className="mono">{line}</div>) : <Text type="secondary">回放输出将在这里显示。</Text>}</div>
      </Card>
    </section>
  );
}
