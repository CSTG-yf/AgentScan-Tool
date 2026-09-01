import { Card, Space, Table, Tag, Typography } from "antd";
import { auditColumns } from "../app/auditColumns";
import type { GuardAuditEvent, GuardAuditSnapshot } from "../types";

const { Text, Title } = Typography;

export function AlertsPage({ audit, commandEvents, terminatedCount }: { audit?: GuardAuditSnapshot; commandEvents: GuardAuditEvent[]; terminatedCount: number }) {
  return (
    <section className="workspace-page alerts-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">PROCESS GUARD SIGNALS</Text>
          <Title level={2}>告警中心</Title>
          <Text type="secondary">来自 LocalSystem 进程守护的真实规则命中与处置结果。</Text>
        </div>
        <Space><Tag color="red">{terminatedCount} 次已终止</Tag><Tag color="cyan">{commandEvents.length} 条事件</Tag></Space>
      </div>
      {audit?.warning && <div className="inline-warning">{audit.warning}</div>}
      <Card bordered={false} className="workspace-table-card"><Table rowKey={(row) => `${row.timestamp}-${row.outcome}-${row.agentPid ?? 0}`} columns={auditColumns} dataSource={commandEvents} pagination={{ pageSize: 15 }} locale={{ emptyText: "暂无 Agent 命令规则命中" }} /></Card>
    </section>
  );
}
