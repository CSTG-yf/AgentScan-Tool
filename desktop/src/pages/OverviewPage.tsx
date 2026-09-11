import { Button, Card, Progress, Space, Badge, Typography } from "antd";
import ReactECharts from "echarts-for-react";
import { ComponentCard } from "../components/ComponentCard";
import type { PageKey } from "../app/navigation";
import type { EnvironmentSnapshot, GuardPolicy } from "../types";

const { Text, Title } = Typography;

export interface OverviewPageProps {
  environment?: EnvironmentSnapshot;
  agentsCount: number;
  policy?: GuardPolicy;
  enabledRules: number;
  readyCount: number;
  totalCount: number;
  onNavigate: (page: PageKey) => void;
  onGatewayAction: (running: boolean) => void;
  onProcessGuardInstall: () => void;
  onProcessGuardStart: () => void;
}

export function OverviewPage({ environment, agentsCount, policy, enabledRules, readyCount, totalCount, onNavigate, onGatewayAction, onProcessGuardInstall, onProcessGuardStart }: OverviewPageProps) {
  const posture = Math.round((readyCount / totalCount) * 100);
  const chartOption = {
    backgroundColor: "transparent",
    tooltip: { trigger: "item" },
    series: [{
      type: "pie",
      radius: ["68%", "88%"],
      center: ["50%", "52%"],
      label: { show: false },
      data: [
        { value: readyCount, name: "就绪", itemStyle: { color: "#44d7b6" } },
        { value: Math.max(totalCount - readyCount, 0), name: "待处理", itemStyle: { color: "#213348" } },
      ],
    }],
    graphic: [
      { type: "text", left: "center", top: "42%", style: { text: `${posture}%`, fill: "#14213a", font: "800 30px Segoe UI" } },
      { type: "text", left: "center", top: "60%", style: { text: "环境就绪度", fill: "#475467", font: "600 12px Segoe UI" } },
    ],
  };

  return (
    <section>
      <div className="hero-grid">
        <Card bordered={false} className="hero-card">
          <div>
            <Text className="eyebrow">TRACEBASTION POSTURE</Text>
            <Title>本机 AI Agent 安全控制台</Title>
            <Text type="secondary">统一查看网关、靶场、Agent 进程与命令策略。敏感动作由独立管理员服务执行并写入审计证据。</Text>
            <div className="hero-actions">
              <Button type="primary" size="large" onClick={() => onNavigate("agents")}>查看 Agent 列表</Button>
              <Button size="large" onClick={() => onNavigate("policies")}>配置防护规则</Button>
            </div>
          </div>
          <ReactECharts option={chartOption} className="posture-chart" />
        </Card>
        <Card bordered={false} className="signal-card">
          <Text className="eyebrow">LIVE SIGNALS</Text>
          <div className="signal-number">{agentsCount}</div>
          <Text>运行中的常见 Agent 进程</Text>
          <div className="signal-divider" />
          <Space direction="vertical">
            <Badge status={policy?.mode === "enforce" ? "error" : "processing"} text={`进程守护：${policy?.enabled ? policy.mode : "未启用"}`} />
            <Badge status={enabledRules ? "warning" : "default"} text={`${enabledRules} 条命令规则已启用`} />
          </Space>
        </Card>
      </div>
      <div className="section-heading compact">
        <div>
          <Text className="eyebrow">RUNTIME HEALTH</Text>
          <Title level={4}>运行环境</Title>
        </div>
        <Text type="secondary">更新于 {environment ? new Date(environment.capturedAt).toLocaleTimeString() : "-"}</Text>
      </div>
      <div className="component-grid">
        {environment?.components.map((component) => <ComponentCard key={component.id} component={component} onGatewayAction={onGatewayAction} onProcessGuardInstall={onProcessGuardInstall} onProcessGuardStart={onProcessGuardStart} />) ?? <Progress percent={20} status="active" />}
      </div>
    </section>
  );
}
