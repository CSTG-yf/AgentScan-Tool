import { BugOutlined, ExperimentOutlined, SafetyCertificateOutlined } from "@ant-design/icons";
import { Button, Card, Space, Tag, Typography } from "antd";
import type { EnvironmentComponent } from "../types";

const { Text, Title } = Typography;

const stateMeta = {
  ready: { color: "success", text: "就绪" },
  degraded: { color: "warning", text: "降级" },
  stopped: { color: "default", text: "已停止" },
  missing: { color: "error", text: "未安装" },
  unknown: { color: "processing", text: "检测中" },
} as const;

interface ComponentCardProps {
  component: EnvironmentComponent;
  onGatewayAction: (running: boolean) => void;
  onProcessGuardInstall: () => void;
  onProcessGuardStart: () => void;
}

export function ComponentCard({ component, onGatewayAction, onProcessGuardInstall, onProcessGuardStart }: ComponentCardProps) {
  const meta = stateMeta[component.state];
  const canInstallProcessGuard = component.id === "processGuard" && component.state !== "ready" && component.state !== "unknown";
  return (
    <Card className="component-card" bordered={false}>
      <div className="component-heading">
        <div className={`component-icon component-icon-${component.state}`}>
          {component.id === "agentrange" ? <ExperimentOutlined /> : component.id === "processGuard" ? <SafetyCertificateOutlined /> : <BugOutlined />}
        </div>
        <Tag color={meta.color}>{meta.text}</Tag>
      </div>
      <Title level={5}>{component.label}</Title>
      <Text type="secondary">{component.detail}</Text>
      {component.id === "gateway" && (
        <div className="component-action">
          <Button size="small" type={component.state === "ready" ? "default" : "primary"} danger={component.state === "ready"} onClick={() => onGatewayAction(component.state !== "ready")}>
            {component.state === "ready" ? "停止网关" : "启动网关"}
          </Button>
        </div>
      )}
      {canInstallProcessGuard && (
        <div className="component-action">
          <Space wrap>
            {component.state === "stopped" && <Button size="small" type="primary" onClick={onProcessGuardStart}>启动服务</Button>}
            <Button size="small" type={component.state === "missing" ? "primary" : "default"} onClick={onProcessGuardInstall}>
              {component.state === "missing" ? "安装服务" : "修复安装"}
            </Button>
          </Space>
        </div>
      )}
      {component.requiresElevation && <div className="elevation-note">敏感操作按需请求管理员权限</div>}
    </Card>
  );
}
