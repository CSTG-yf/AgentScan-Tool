import { Space, Table, Tag, Typography } from "antd";
import type { ColumnsType } from "antd/es/table";
import { formatTimestamp, outcomeTag } from "./display";
import type { GuardAuditEvent } from "../types";

const { Text } = Typography;

export const auditColumns: ColumnsType<GuardAuditEvent> = [
  { title: "时间", dataIndex: "timestamp", width: 180, render: formatTimestamp },
  { title: "结果", dataIndex: "outcome", width: 150, render: outcomeTag },
  {
    title: "Agent",
    render: (_, row) =>
      row.agentExecutable ? (
        <Space direction="vertical" size={0}>
          <Text strong>{row.agentExecutable}</Text>
          <Text type="secondary" className="mono">PID {row.agentPid ?? "-"}</Text>
        </Space>
      ) : (
        <Text type="secondary">守护服务</Text>
      ),
  },
  {
    title: "子进程 / 规则",
    render: (_, row) =>
      row.childExecutable ? (
        <Space direction="vertical" size={0}>
          <Text code>{row.childExecutable}</Text>
          <Text type="secondary">{row.ruleId ?? "-"}</Text>
        </Space>
      ) : (
        "-"
      ),
  },
  { title: "证据详情", dataIndex: "detail", ellipsis: true },
];

export type AuditTableProps = React.ComponentProps<typeof Table<GuardAuditEvent>>;
