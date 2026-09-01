import { Card, Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { formatTimestamp, outcomeTag } from "../app/display";
import type { AgentTraceEvent, AgentTraceSnapshot } from "../types";

const { Text, Title } = Typography;

interface TracePageProps {
  trace?: AgentTraceSnapshot;
  events: AgentTraceEvent[];
  fileTraceCount: number;
}

export function TracePage({ trace, events, fileTraceCount }: TracePageProps) {
  const columns: ColumnsType<AgentTraceEvent> = [
    { title: "时间", dataIndex: "timestamp", width: 180, render: formatTimestamp },
    {
      title: "行为",
      dataIndex: "eventType",
      width: 160,
      render: (value: string) => (
        <Tag color={value === "blacklistFileAccess" ? "red" : value.startsWith("file") ? "blue" : "cyan"}>{value}</Tag>
      ),
    },
    {
      title: "Agent / 执行进程",
      render: (_, row) => (
        <Space direction="vertical" size={0}>
          <Text strong>{row.agentExecutable} · PID {row.agentPid}</Text>
          <Text type="secondary" className="mono">{row.actorExecutable} · PID {row.actorPid}</Text>
        </Space>
      ),
    },
    {
      title: "文件",
      dataIndex: "path",
      ellipsis: true,
      render: (value?: string) => value ? <Text className="mono" copyable>{value}</Text> : "-",
    },
    { title: "结果", dataIndex: "outcome", width: 140, render: outcomeTag },
    { title: "来源", dataIndex: "source", width: 180 },
  ];

  return (
    <section className="workspace-page trace-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">AGENT ACTIVITY TRACE</Text>
          <Title level={2}>Agent 行为追踪</Title>
          <Text type="secondary">记录 Agent 进程、子命令以及文件读取、写入、创建和删除；行为数据统一写入 Go 后端 audit.db。</Text>
        </div>
        <Space>
          <Tag color="cyan">{events.length} 条事件</Tag>
          <Tag color="blue">{fileTraceCount} 条文件行为</Tag>
        </Space>
      </div>
      {trace?.warning && <div className="inline-warning">{trace.warning}</div>}
      <Card bordered={false} className="evidence-path workspace-info-card">
        <Text type="secondary">Go 后端行为事件库</Text>
        <Text className="mono">{trace?.databasePath || "audit.db:behavior_events"}</Text>
      </Card>
      <Card bordered={false} className="workspace-table-card">
        <Table
          rowKey="id"
          columns={columns}
          dataSource={events}
          pagination={{ pageSize: 20 }}
          locale={{ emptyText: "尚未捕获 Agent 行为" }}
        />
      </Card>
    </section>
  );
}
