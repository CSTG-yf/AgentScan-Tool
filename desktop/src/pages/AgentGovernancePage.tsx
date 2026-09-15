import { useCallback, useEffect, useState } from "react";
import { ReloadOutlined } from "@ant-design/icons";
import { Button, ConfigProvider, Tabs, Tooltip, Typography, message } from "antd";
import { getGovernanceSummary, type GovernanceSummary } from "../bridge";
import type { ScanRefreshStrategyPageProps } from "../components/agent-governance/ScanRefreshStrategyPage";
import { AgentDiscoveryRulesPage, AgentTypeManagementPage, AllowedScanProfilesPage, DecisionsAndActionsPage, ResourceDiscoveryRulesPage, RiskExplanationPage, RuntimeDetectionSettingsSubpage, ScanRefreshStrategyPage } from "../components/agent-governance";
import { governanceTheme } from "../components/agent-governance/theme";
import "../components/agent-governance/governance.css";
export type AgentGovernancePageProps = ScanRefreshStrategyPageProps;
export function AgentGovernancePage(props: AgentGovernancePageProps) {
    const [activeTab, setActiveTab] = useState("types");
    const [summary, setSummary] = useState<GovernanceSummary>();
    const [loading, setLoading] = useState(false);
    const refreshSummary = useCallback(async () => {
        setLoading(true);
        try {
            setSummary(await getGovernanceSummary());
        }
        catch (error) {
            message.error(`读取治理统计失败：${String(error)}`);
        }
        finally {
            setLoading(false);
        }
    }, []);
    useEffect(() => { void refreshSummary(); }, [refreshSummary]);
    const metrics = [
        { label: "Agent 类型", value: summary?.agent_type_count },
        { label: "发现规则", value: summary?.discovery_rule_count },
        { label: "资源规则", value: summary?.resource_rule_count },
        { label: "扫描方案", value: summary?.scan_profile_count },
        { label: "决策方案", value: summary?.decision_profile_count, detail: "Pre-scan / Post-scan 方案" },
        { label: "风险解释", value: summary?.risk_rule_count, detail: "Severity / Rule ID 前缀 / Category 规则" },
        { label: "异常检测", value: summary && summary.runtime_rule_count + summary.runtime_blacklist_count + summary.runtime_risk_policy_count,
            detail: summary && `规则 ${summary.runtime_rule_count} · 黑名单 ${summary.runtime_blacklist_count} · 风险策略 ${summary.runtime_risk_policy_count}` },
        { label: "扫描与刷新", value: summary && summary.scan_schedule_count + summary.page_refresh_policy_count,
            detail: summary && `扫描 ${summary.scan_schedule_count} · 页面刷新 ${summary.page_refresh_policy_count}` },
    ];
    return <ConfigProvider theme={governanceTheme} select={{ classNames: { popup: { root: "governance-select-popup" } } }} modal={{ classNames: { root: "governance-overlay" } }} drawer={{ classNames: { root: "governance-overlay" } }} popconfirm={{ classNames: { root: "governance-overlay" } }}>
    <section className="workspace-page governance-page governance-workbench">
      <div className="page-heading">
        <div><Typography.Text className="eyebrow">AGENT GOVERNANCE</Typography.Text><Typography.Title level={2}>Agent 治理中心</Typography.Title></div>
        <Button icon={<ReloadOutlined />} onClick={() => void refreshSummary()} loading={loading}>刷新</Button>
      </div>
      <div className="governance-summary-strip" aria-label="治理统计">
        {metrics.map(item => <Tooltip key={item.label} title={item.detail}><div className="governance-summary-item"><span>{item.label}</span><strong>{item.value ?? "—"}</strong></div></Tooltip>)}
      </div>
      <Tabs activeKey={activeTab} onChange={setActiveTab} destroyOnHidden items={[
            { key: "types", label: "Agent 类型管理", children: <AgentTypeManagementPage /> },
            { key: "discovery", label: "Agent 发现规则", children: <AgentDiscoveryRulesPage /> },
            { key: "resources", label: "资源发现规则", children: <ResourceDiscoveryRulesPage /> },
            { key: "profiles", label: "当资源决策为allowed时的扫描方案", children: <AllowedScanProfilesPage /> },
            { key: "decisions", label: "决策与动作", children: <DecisionsAndActionsPage /> },
            { key: "risk", label: "风险解释", children: <RiskExplanationPage /> },
            { key: "runtime-detection-settings", label: "异常检测设置", children: <RuntimeDetectionSettingsSubpage /> },
            { key: "scan-refresh-settings", label: "扫描与刷新策略", children: <ScanRefreshStrategyPage {...props}/> },
        ]}/>
    </section>
  </ConfigProvider>;
}
