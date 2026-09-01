import { Card, Table, Tag, Typography } from "antd";
import { auditColumns } from "../app/auditColumns";
import type { GuardAuditEvent, GuardAuditSnapshot } from "../types";

const { Text, Title } = Typography;

export function EvidencePage({ audit, guardEvents }: { audit?: GuardAuditSnapshot; guardEvents: GuardAuditEvent[] }) {
  return (
    <section className="workspace-page evidence-page">
      <div className="section-heading">
        <div>
          <Text className="eyebrow">LOCAL JSONL EVIDENCE</Text>
          <Title level={2}>报告与证据</Title>
          <Text type="secondary">审计先落盘后执行终止；证据写入失败时系统不会执行破坏性动作。</Text>
        </div>
        <Tag color="geekblue">{audit?.events.length ?? 0} 条载入</Tag>
      </div>
      <Card bordered={false} className="evidence-path workspace-info-card"><Text type="secondary">本机证据文件</Text><Text className="mono">process-guard.jsonl · 本机受保护存储</Text></Card>
      <Card bordered={false} className="workspace-table-card"><Table rowKey={(row) => `${row.timestamp}-${row.eventType}-${row.outcome}`} columns={auditColumns} dataSource={guardEvents} pagination={{ pageSize: 20 }} locale={{ emptyText: "暂无审计证据" }} /></Card>
    </section>
  );
}
