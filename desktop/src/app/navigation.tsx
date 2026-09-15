import {
  AlertOutlined,
  AuditOutlined,
  BugOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  ExperimentOutlined,
  FileProtectOutlined,
  RadarChartOutlined,
  SafetyCertificateOutlined,
  SettingOutlined,
} from "@ant-design/icons";

export type PageKey =
  | "overview"
  | "range"
  | "agents"
  | "governance"
  | "trace"
  | "auditEvents"
  | "staticAssets"
  | "events"
  | "alerts"
  | "chain"
  | "policies"
  | "evidence"
  | "settings";

export const navigation: Array<{ key: PageKey; icon: React.ReactNode; label: string }> = [
  { key: "overview", icon: <DashboardOutlined />, label: "安全总览" },
  { key: "range", icon: <ExperimentOutlined />, label: "靶场控制" },
  { key: "governance", icon: <SafetyCertificateOutlined />, label: "Agent 治理中心" },
  { key: "agents", icon: <RadarChartOutlined />, label: "Agent 检测" },
  { key: "staticAssets", icon: <DatabaseOutlined />, label: "静态资源检测" },
  { key: "events", icon: <BugOutlined />, label: "事件检测" },
  { key: "chain", icon: <AuditOutlined />, label: "攻击链" },
  { key: "trace", icon: <AuditOutlined />, label: "行为追踪" },
  { key: "auditEvents", icon: <FileProtectOutlined />, label: "事件审计" },
  { key: "settings", icon: <SettingOutlined />, label: "系统设置" },
  // { key: "alerts", icon: <AlertOutlined />, label: "告警中心" },
  // { key: "policies", icon: <FileProtectOutlined />, label: "策略中心" },
  // { key: "evidence", icon: <SafetyCertificateOutlined />, label: "报告与证据" },
];
