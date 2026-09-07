import { Descriptions, Empty, Space, Tag, Timeline, Typography } from "antd";
import { formatTimestamp } from "../app/display";
import type { AttackChainDetail } from "../types";

const { Text, Title } = Typography;
const text = (value: unknown) => value === null || value === undefined || value === "" ? "—" : String(value);
const time = (value: unknown) => typeof value === "string" && value && !value.startsWith("0001-") ? formatTimestamp(value) : "—";
const fields = (rows: Array<[string, unknown]>) => <Descriptions column={1} size="small" items={rows.map(([label, value]) => ({ key: label, label, children: text(value) }))} />;
const raw = (value: unknown) => <details className="runtime-raw-record"><summary>查看原始记录</summary><pre>{JSON.stringify(value, null, 2)}</pre></details>;
const responseLabels: Record<string, string> = { executed: "已执行", would_block: "仅观察，未执行", dispatched: "已派发，等待执行确认", planned: "已计划", executing: "执行中", failed: "执行失败", expired: "已过期", rolled_back: "已回滚" };

export function attackChainDetailTabs(detail: AttackChainDetail) {
  const chain = detail.attack_chain;
  const decision = detail.decision;
  const steps = detail.nodes?.length ? detail.nodes : detail.chain.steps ?? [];
  const responses = detail.responses?.length ? detail.responses : detail.response?.response_id ? [detail.response] : [];
  const timeline = steps.length ? <Timeline items={steps.map(step => ({ key: step.id, content: <div className="runtime-chain-step">
    <Text strong>#{step.order} {step.title}</Text><div><Text type="secondary">{time(step.occurredAt)} · {step.stage}</Text></div>
    {fields([["工具", step.tool], ["资源", step.resource], ["事件 ID", step.sourceEventId], ["来源", step.source]])}
    {step.evidence && <p className="runtime-record-text">{step.evidence}</p>}
  </div> }))} /> : <Empty description="暂无关联步骤" />;
  const actionSummary = decision?.decision_id ? <div className="runtime-chain-step"><Space wrap><Tag>{text(decision.decision)}</Tag><Tag>{text(decision.mode)}</Tag><Text>预计阻断：{decision.would_block === true ? "是" : "否"}</Text></Space><p className="runtime-record-text">{text(decision.reason)}</p></div> : <Empty description="暂无策略决策" />;
  return [
    { key: "overview", label: "概览", children: <>
      <Title level={5}>链路身份</Title>
      {fields([["Attack Chain ID", chain.attack_chain_id], ["Agent", chain.agent_name], ["Agent ID", chain.agent_id], ["Agent 类型", chain.agent_type_name || detail.chain.agentTypeName], ["类型 ID", chain.agent_type_id ?? detail.chain.agentTypeId], ["攻击类型", chain.attack_type], ["原始状态", chain.status], ["展示状态", detail.chain.status], ["Severity", chain.severity], ["Detection ID", chain.detection_id], ["Decision ID", chain.decision_id], ["Session", chain.session_id], ["Trace", chain.trace_id], ["开始时间", time(chain.start_time)], ["结束时间", time(chain.end_time)]])}
      <Title level={5}>链路摘要</Title><div className="runtime-chain-step">{text(chain.attack_type)} 链路当前状态为 {text(chain.status)}，包含 {steps.length} 个步骤与 {detail.evidence?.length ?? 0} 条证据。</div>
      <Title level={5}>攻击步骤</Title>{timeline}
      <Title level={5}>处置与响应</Title>{actionSummary}<p><Text type="secondary">已执行响应 {responses.filter(response => response.status === "executed").length} 条；执行结果以响应记录及行为 outcome 为准。</Text></p>
    </> },
    { key: "steps", label: "步骤", children: <>{timeline}<Title level={5}>构建来源</Title>{fields([["构建版本", chain.builder_version], ["策略版本", chain.policy_version], ["重建任务", chain.evaluation_job_id]])}</> },
    { key: "evidence", label: "证据", children: <>
      {detail.evidence?.length ? detail.evidence.map(row => <section className="runtime-evidence-event" key={row.key}><Text strong>{row.stage} · {row.tool || row.resource || "行为证据"}</Text>{fields([["发生时间", time(row.occurredAt)], ["事件 ID", row.sourceEventId], ["来源", row.source], ["资源", row.resource], ["决策", row.decision]])}<p className="runtime-record-text">{row.evidence}</p></section>) : <Empty description="暂无证据" />}
      <Title level={5}>原始行为结果</Title>{detail.events?.map((link, index) => {
        const event = link.event && typeof link.event === "object" ? link.event as Record<string, unknown> : link;
        return <section className="runtime-evidence-event" key={String(event.id ?? index)}>{fields([["事件 ID", event.id], ["事件类型", event.event_type], ["关联角色", link.relation], ["Outcome", event.outcome], ["工具", event.tool_name], ["目标", event.target]])}{raw(link)}</section>;
      })}
    </> },
    { key: "detections", label: "检测", children: detail.detections?.length ? detail.detections.map((detection, index) => <section className="runtime-evidence-event" key={String(detection.detection_id ?? index)}><Title level={5}>{text(detection.title || detection.detection_type)}</Title>{fields([["Detection ID", detection.detection_id], ["风险", detection.severity], ["状态", detection.status], ["规则", detection.rule_id], ["规则版本", detection.rule_version], ["置信度", detection.confidence]])}<p className="runtime-record-text">{text(detection.detail)}</p>{!!detection.remediation && <p className="runtime-record-text">建议：{text(detection.remediation)}</p>}{raw(detection)}</section>) : <Empty description="暂无关联检测" /> },
    { key: "actions", label: "决策与响应", children: <><Title level={5}>策略决策</Title>{actionSummary}{decision?.decision_id && <>{fields([["Decision ID", decision.decision_id], ["风险分数", decision.risk_score], ["策略", decision.policy_id], ["策略版本", decision.policy_version], ["执行点", decision.enforcement_point], ["决策时间", time(decision.created_at)]])}{raw(decision)}</>}
      <Title level={5}>实际响应记录</Title>{responses.length ? responses.map((response, index) => <section className="runtime-response" key={String(response.response_id ?? index)}><Space><Tag>{responseLabels[String(response.status)] || text(response.status)}</Tag><Text strong>{text(response.action_type)}</Text></Space>{fields([["Response ID", response.response_id], ["原始状态", response.status], ["执行器", response.executor], ["目标", response.target], ["执行时间", time(response.executed_at)], ["支持回滚", response.rollback_supported === true ? "是" : "否"]])}<p className="runtime-record-text">{text(response.result)}</p>{raw(response)}</section>) : <Empty description="尚无执行记录" />}
    </> },
  ];
}
