import type { Dispatch, SetStateAction } from "react";
import { useCallback, useEffect, useState } from "react";
import { ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Input, Select, Space, Table, Tag, Typography, message, Card } from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { getGovernanceRiskCategoryMatches, getGovernanceRiskRulePrefixMatches, getGovernanceRiskSeverityMappings } from "../../bridge";
import type { GovernancePage, GovernanceRiskCategoryMatch, GovernanceRiskRulePrefixMatch, GovernanceRiskSeverityMapping } from "../../types";
const { Text } = Typography;
const RISK_LEVELS = ["clean", "low", "medium", "high", "critical"];
const RISK_LEVEL_OPTIONS = [{ value: "all", label: "全部风险" }, ...RISK_LEVELS.map((value) => ({ value, label: value }))];
const ENABLED_OPTIONS = [
    { value: "all", label: "全部状态" },
    { value: "enabled", label: "启用" },
    { value: "disabled", label: "停用" },
] as const;
type EnabledFilter = (typeof ENABLED_OPTIONS)[number]["value"];
type PageQueryState = {
    keyword: string;
    enabled: EnabledFilter;
    page: number;
    pageSize: number;
};
type RiskQueryState = PageQueryState & {
    riskLevel: string;
};
function emptyPage<T>(page = 1, pageSize = 10): GovernancePage<T> {
    return { total: 0, page, page_size: pageSize, items: [] };
}
function enabledFilterValue(value: EnabledFilter): boolean | undefined {
    if (value === "enabled")
        return true;
    if (value === "disabled")
        return false;
    return undefined;
}
function queryFromState(state: PageQueryState) {
    return {
        keyword: state.keyword || undefined,
        enabled: enabledFilterValue(state.enabled),
        page: state.page,
        pageSize: state.pageSize,
    };
}
function riskQueryFromState(state: RiskQueryState) {
    return {
        ...queryFromState(state),
        riskLevel: state.riskLevel === "all" ? undefined : state.riskLevel,
    };
}
function tablePagination<T>(page: GovernancePage<T>, query: PageQueryState): TablePaginationConfig {
    return {
        current: page.page || query.page,
        pageSize: page.page_size || query.pageSize,
        total: page.total,
        showSizeChanger: true,
        showTotal: (total) => `共 ${total} 条`,
    };
}
function enabledTag(enabled: boolean) {
    return enabled ? <Tag color="success">启用</Tag> : <Tag>停用</Tag>;
}
function riskLevelTag(value: string) {
    const color = value === "critical" ? "red" : value === "high" ? "volcano" : value === "medium" ? "orange" : value === "low" ? "blue" : "green";
    return <Tag color={color}>{value || "-"}</Tag>;
}
type RuleSectionModel<T extends object> = {
    keyword: string;
    setKeyword: Dispatch<SetStateAction<string>>;
    enabled: EnabledFilter;
    setEnabled: Dispatch<SetStateAction<EnabledFilter>>;
    enabledOptions: typeof ENABLED_OPTIONS;
    applyFilter: () => void;
    resetFilter: () => void;
    reload: () => Promise<void>;
    loading: boolean;
    columns: ColumnsType<T>;
    page: GovernancePage<T>;
    query: RiskQueryState;
    setQuery: Dispatch<SetStateAction<RiskQueryState>>;
    pagination: typeof tablePagination;
    placeholder: string;
    level: string;
    setLevel: Dispatch<SetStateAction<string>>;
    levelOptions: typeof RISK_LEVEL_OPTIONS;
};
function RuleSection<T extends object>({ title, description, section }: {
    title: string;
    description: string;
    section: RuleSectionModel<T>;
}) {
    return <Card bordered={false} className="workspace-table-card"><Space direction="vertical" size={16} className="governance-full-width">
    <div><Text strong>{title}</Text><br /><Text type="secondary">{description}</Text></div>
    <Space className="governance-toolbar" wrap>
      <Input.Search allowClear placeholder={section.placeholder} value={section.keyword} onChange={event => section.setKeyword(event.target.value)} onSearch={section.applyFilter} className="governance-search-wide"/>
      <Select value={section.level} onChange={section.setLevel} options={section.levelOptions} className="governance-filter-select"/>
      <Select value={section.enabled} onChange={section.setEnabled} options={[...section.enabledOptions]} className="governance-filter-select"/>
      <Button icon={<SearchOutlined />} onClick={section.applyFilter}>查询</Button><Button onClick={section.resetFilter}>重置</Button>
      <Button aria-label={`刷新${title}`} icon={<ReloadOutlined />} onClick={() => void section.reload()}/>
    </Space>
    <Table rowKey="id" size="small" loading={section.loading} columns={section.columns} dataSource={section.page.items} scroll={{ x: 980 }} pagination={section.pagination(section.page, section.query)} onChange={value => section.setQuery((previous) => ({ ...previous, page: value.current ?? 1, pageSize: value.pageSize ?? previous.pageSize }))}/>
  </Space></Card>;
}
export function RiskExplanationPage() {
    const [riskLoading, setRiskLoading] = useState(false);
    const [riskSeverityPage, setRiskSeverityPage] = useState<GovernancePage<GovernanceRiskSeverityMapping>>(emptyPage(1, 5));
    const [riskRulePrefixPage, setRiskRulePrefixPage] = useState<GovernancePage<GovernanceRiskRulePrefixMatch>>(emptyPage(1, 5));
    const [riskCategoryPage, setRiskCategoryPage] = useState<GovernancePage<GovernanceRiskCategoryMatch>>(emptyPage(1, 5));
    const [riskSeverityQuery, setRiskSeverityQuery] = useState<RiskQueryState>({ keyword: "", enabled: "all", riskLevel: "all", page: 1, pageSize: 5 });
    const [riskSeverityKeyword, setRiskSeverityKeyword] = useState("");
    const [riskSeverityEnabled, setRiskSeverityEnabled] = useState<EnabledFilter>("all");
    const [riskSeverityLevel, setRiskSeverityLevel] = useState("all");
    const [riskRulePrefixQuery, setRiskRulePrefixQuery] = useState<RiskQueryState>({ keyword: "", enabled: "all", riskLevel: "all", page: 1, pageSize: 5 });
    const [riskRulePrefixKeyword, setRiskRulePrefixKeyword] = useState("");
    const [riskRulePrefixEnabled, setRiskRulePrefixEnabled] = useState<EnabledFilter>("all");
    const [riskRulePrefixLevel, setRiskRulePrefixLevel] = useState("all");
    const [riskCategoryQuery, setRiskCategoryQuery] = useState<RiskQueryState>({ keyword: "", enabled: "all", riskLevel: "all", page: 1, pageSize: 5 });
    const [riskCategoryKeyword, setRiskCategoryKeyword] = useState("");
    const [riskCategoryEnabled, setRiskCategoryEnabled] = useState<EnabledFilter>("all");
    const [riskCategoryLevel, setRiskCategoryLevel] = useState("all");
    const loadRiskExplain = useCallback(async () => {
        setRiskLoading(true);
        try {
            const [severityPage, prefixPage, categoryPage] = await Promise.all([
                getGovernanceRiskSeverityMappings(riskQueryFromState(riskSeverityQuery)),
                getGovernanceRiskRulePrefixMatches(riskQueryFromState(riskRulePrefixQuery)),
                getGovernanceRiskCategoryMatches(riskQueryFromState(riskCategoryQuery)),
            ]);
            setRiskSeverityPage(severityPage);
            setRiskRulePrefixPage(prefixPage);
            setRiskCategoryPage(categoryPage);
        }
        catch (error) {
            message.error(`读取风险解释规则失败：${String(error)}`);
        }
        finally {
            setRiskLoading(false);
        }
    }, [riskSeverityQuery, riskRulePrefixQuery, riskCategoryQuery]);
    useEffect(() => {
        void loadRiskExplain();
    }, [loadRiskExplain]);
    const applyRiskSeverityFilter = () => {
        setRiskSeverityQuery((prev) => ({ ...prev, page: 1, keyword: riskSeverityKeyword.trim(), enabled: riskSeverityEnabled, riskLevel: riskSeverityLevel }));
    };
    const resetRiskSeverityFilter = () => {
        setRiskSeverityKeyword("");
        setRiskSeverityEnabled("all");
        setRiskSeverityLevel("all");
        setRiskSeverityQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all", riskLevel: "all" }));
    };
    const applyRiskRulePrefixFilter = () => {
        setRiskRulePrefixQuery((prev) => ({ ...prev, page: 1, keyword: riskRulePrefixKeyword.trim(), enabled: riskRulePrefixEnabled, riskLevel: riskRulePrefixLevel }));
    };
    const resetRiskRulePrefixFilter = () => {
        setRiskRulePrefixKeyword("");
        setRiskRulePrefixEnabled("all");
        setRiskRulePrefixLevel("all");
        setRiskRulePrefixQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all", riskLevel: "all" }));
    };
    const applyRiskCategoryFilter = () => {
        setRiskCategoryQuery((prev) => ({ ...prev, page: 1, keyword: riskCategoryKeyword.trim(), enabled: riskCategoryEnabled, riskLevel: riskCategoryLevel }));
    };
    const resetRiskCategoryFilter = () => {
        setRiskCategoryKeyword("");
        setRiskCategoryEnabled("all");
        setRiskCategoryLevel("all");
        setRiskCategoryQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all", riskLevel: "all" }));
    };
    const riskSeverityColumns: ColumnsType<GovernanceRiskSeverityMapping> = [
        { title: "Severity", dataIndex: "source_severity", width: 140 },
        { title: "Risk Level", dataIndex: "risk_level", width: 140, render: riskLevelTag },
        { title: "说明", dataIndex: "description", ellipsis: true },
        { title: "优先级", dataIndex: "priority", width: 100 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        { title: "更新时间", dataIndex: "updated_at", width: 190 },
    ];
    const riskRulePrefixColumns: ColumnsType<GovernanceRiskRulePrefixMatch> = [
        { title: "Rule ID 前缀", dataIndex: "rule_id_prefix", width: 180 },
        { title: "命中风险等级", dataIndex: "risk_level", width: 150, render: riskLevelTag },
        { title: "说明", dataIndex: "description", ellipsis: true },
        { title: "优先级", dataIndex: "priority", width: 100 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        { title: "更新时间", dataIndex: "updated_at", width: 190 },
    ];
    const riskCategoryColumns: ColumnsType<GovernanceRiskCategoryMatch> = [
        { title: "Category", dataIndex: "category", width: 220 },
        { title: "命中风险等级", dataIndex: "risk_level", width: 150, render: riskLevelTag },
        { title: "说明", dataIndex: "description", ellipsis: true },
        { title: "优先级", dataIndex: "priority", width: 100 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        { title: "更新时间", dataIndex: "updated_at", width: 190 },
    ];
    const model = {
        severity: { placeholder: "搜索 Severity / Risk Level / 说明", keyword: riskSeverityKeyword, setKeyword: setRiskSeverityKeyword, level: riskSeverityLevel, setLevel: setRiskSeverityLevel, levelOptions: RISK_LEVEL_OPTIONS, enabled: riskSeverityEnabled, setEnabled: setRiskSeverityEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyRiskSeverityFilter, resetFilter: resetRiskSeverityFilter, reload: loadRiskExplain, loading: riskLoading, columns: riskSeverityColumns, page: riskSeverityPage, query: riskSeverityQuery, setQuery: setRiskSeverityQuery, pagination: tablePagination },
        prefix: { placeholder: "搜索 Rule ID 前缀 / Risk Level / 说明", keyword: riskRulePrefixKeyword, setKeyword: setRiskRulePrefixKeyword, level: riskRulePrefixLevel, setLevel: setRiskRulePrefixLevel, levelOptions: RISK_LEVEL_OPTIONS, enabled: riskRulePrefixEnabled, setEnabled: setRiskRulePrefixEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyRiskRulePrefixFilter, resetFilter: resetRiskRulePrefixFilter, reload: loadRiskExplain, loading: riskLoading, columns: riskRulePrefixColumns, page: riskRulePrefixPage, query: riskRulePrefixQuery, setQuery: setRiskRulePrefixQuery, pagination: tablePagination },
        category: { placeholder: "搜索 Category / Risk Level / 说明", keyword: riskCategoryKeyword, setKeyword: setRiskCategoryKeyword, level: riskCategoryLevel, setLevel: setRiskCategoryLevel, levelOptions: RISK_LEVEL_OPTIONS, enabled: riskCategoryEnabled, setEnabled: setRiskCategoryEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyRiskCategoryFilter, resetFilter: resetRiskCategoryFilter, reload: loadRiskExplain, loading: riskLoading, columns: riskCategoryColumns, page: riskCategoryPage, query: riskCategoryQuery, setQuery: setRiskCategoryQuery, pagination: tablePagination },
    };
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>风险解释</Typography.Title></div><Space direction="vertical" size={16} className="governance-full-width">
    <Alert type="info" showIcon message="风险判定优先级：Rule ID 前缀 > Category > Severity > 默认 clean。前三类规则都只读取启用且未删除的数据。"/>
    <RuleSection title="Severity 风险等级映射" description="当 finding 没有命中更高优先级的前缀或 Category 规则时，按扫描器 Severity 映射资源风险等级。" section={model.severity}/>
    <RuleSection title="规则 ID 前缀匹配规则" description="Rule ID 前缀是最高优先级规则，适合把一类扫描器规则整体提升到指定风险等级。" section={model.prefix}/>
    <RuleSection title="Category 匹配规则" description="Category 是第二优先级规则，用于把 malware、c2、credential_harvest 等风险类别映射到资源风险等级。" section={model.category}/>
  </Space></section>;
}
