import { useCallback, useEffect, useMemo, useState } from "react";
import { DeleteOutlined, EditOutlined, EyeOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Descriptions, Drawer, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { createGovernanceDiscoveryCondition, createGovernanceDiscoveryRule, deleteGovernanceDiscoveryCondition, deleteGovernanceDiscoveryRule, getGovernanceAgentTypes, getGovernanceDiscoveryRule, getGovernanceDiscoveryRules, updateGovernanceDiscoveryCondition, updateGovernanceDiscoveryRule } from "../../bridge";
import type { GovernanceAgentType, GovernanceDiscoveryCondition, GovernanceDiscoveryConditionInput, GovernanceDiscoveryRule, GovernanceDiscoveryRuleInput, GovernancePage } from "../../types";
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
export function AgentDiscoveryRulesPage() {
    const [referenceLoading, setReferenceLoading] = useState(false);
    const [discoveryLoading, setDiscoveryLoading] = useState(false);
    const [agentTypeCatalog, setAgentTypeCatalog] = useState<GovernanceAgentType[]>([]);
    const [discoveryPage, setDiscoveryPage] = useState<GovernancePage<GovernanceDiscoveryRule>>(emptyPage());
    const [discoveryQuery, setDiscoveryQuery] = useState<PageQueryState>({ keyword: "", enabled: "enabled", page: 1, pageSize: 10 });
    const [discoveryKeyword, setDiscoveryKeyword] = useState("");
    const [discoveryEnabled, setDiscoveryEnabled] = useState<EnabledFilter>("enabled");
    const [discoveryForm] = Form.useForm<GovernanceDiscoveryRuleInput>();
    const [discoveryModalOpen, setDiscoveryModalOpen] = useState(false);
    const [editingDiscoveryRule, setEditingDiscoveryRule] = useState<GovernanceDiscoveryRule>();
    const [discoveryDetailOpen, setDiscoveryDetailOpen] = useState(false);
    const [discoveryDetail, setDiscoveryDetail] = useState<GovernanceDiscoveryRule>();
    const [conditionForm] = Form.useForm<GovernanceDiscoveryConditionInput>();
    const [conditionModalOpen, setConditionModalOpen] = useState(false);
    const [editingCondition, setEditingCondition] = useState<GovernanceDiscoveryCondition>();
    const agentTypeOptions = useMemo(() => agentTypeCatalog.map((item) => ({ label: `${item.name} (${item.type_key})`, value: item.id })), [agentTypeCatalog]);
    const loadDiscoveryRules = useCallback(async () => {
        setDiscoveryLoading(true);
        try {
            setDiscoveryPage(await getGovernanceDiscoveryRules(queryFromState(discoveryQuery)));
        }
        catch (error) {
            message.error(`读取 Agent 发现规则失败：${String(error)}`);
        }
        finally {
            setDiscoveryLoading(false);
        }
    }, [discoveryQuery]);
    const loadReferences = useCallback(async () => { setReferenceLoading(true); try {
        await Promise.all([getGovernanceAgentTypes({ page: 1, pageSize: 500 }).then(value => setAgentTypeCatalog(value.items ?? []))]);
    }
    catch (error) {
        message.error(`读取配置失败：${String(error)}`);
    }
    finally {
        setReferenceLoading(false);
    } }, []);
    useEffect(() => {
        void loadReferences();
    }, [loadReferences]);
    useEffect(() => {
        void loadDiscoveryRules();
    }, [loadDiscoveryRules]);
    const applyDiscoveryFilter = () => {
        setDiscoveryQuery((prev) => ({ ...prev, page: 1, keyword: discoveryKeyword.trim(), enabled: discoveryEnabled }));
    };
    const resetDiscoveryFilter = () => {
        setDiscoveryKeyword("");
        setDiscoveryEnabled("enabled");
        setDiscoveryQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "enabled" }));
    };
    const openDiscoveryModal = (record?: GovernanceDiscoveryRule) => {
        setEditingDiscoveryRule(record);
        discoveryForm.setFieldsValue(record ?? { enabled: true, threshold: 60 });
        setDiscoveryModalOpen(true);
    };
    const saveDiscoveryRule = async () => {
        const values = await discoveryForm.validateFields();
        if (editingDiscoveryRule) {
            await updateGovernanceDiscoveryRule(editingDiscoveryRule.id, values);
            message.success("发现规则已更新");
        }
        else {
            await createGovernanceDiscoveryRule({ ...values, enabled: values.enabled ?? true });
            message.success("发现规则已创建");
        }
        setDiscoveryModalOpen(false);
        await Promise.all([loadReferences(), loadDiscoveryRules()]);
    };
    const removeDiscoveryRule = async (record: GovernanceDiscoveryRule) => {
        await deleteGovernanceDiscoveryRule(record.id);
        message.success("发现规则已删除");
        if (discoveryDetail?.id === record.id) {
            setDiscoveryDetailOpen(false);
            setDiscoveryDetail(undefined);
        }
        await Promise.all([loadReferences(), loadDiscoveryRules()]);
    };
    const viewDiscoveryRule = async (record: GovernanceDiscoveryRule) => {
        try {
            const detail = await getGovernanceDiscoveryRule(record.id);
            setDiscoveryDetail(detail);
            setDiscoveryDetailOpen(true);
        }
        catch (error) {
            message.error(`读取规则详情失败：${String(error)}`);
        }
    };
    const openConditionModal = (condition?: GovernanceDiscoveryCondition) => {
        setEditingCondition(condition);
        conditionForm.setFieldsValue(condition ?? { enabled: true, required: false, weight: 10 });
        setConditionModalOpen(true);
    };
    const saveCondition = async () => {
        if (!discoveryDetail)
            return;
        const values = await conditionForm.validateFields();
        if (editingCondition) {
            await updateGovernanceDiscoveryCondition(editingCondition.id, values);
            message.success("条件已更新");
        }
        else {
            await createGovernanceDiscoveryCondition(discoveryDetail.id, { ...values, enabled: values.enabled ?? true });
            message.success("条件已创建");
        }
        setConditionModalOpen(false);
        const detail = await getGovernanceDiscoveryRule(discoveryDetail.id);
        setDiscoveryDetail(detail);
        await Promise.all([loadDiscoveryRules(), loadReferences()]);
    };
    const removeCondition = async (record: GovernanceDiscoveryCondition) => {
        if (!discoveryDetail)
            return;
        await deleteGovernanceDiscoveryCondition(record.id);
        message.success("条件已删除");
        const detail = await getGovernanceDiscoveryRule(discoveryDetail.id);
        setDiscoveryDetail(detail);
        await Promise.all([loadDiscoveryRules(), loadReferences()]);
    };
    const discoveryColumns: ColumnsType<GovernanceDiscoveryRule> = [
        { title: "Agent Type", dataIndex: "agent_type_key", width: 150 },
        { title: "规则名称", dataIndex: "rule_name" },
        { title: "阈值", dataIndex: "threshold", width: 90 },
        { title: "条件数", dataIndex: "condition_count", width: 90 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        {
            title: "操作",
            fixed: "right",
            width: 240,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => void viewDiscoveryRule(record)}>详情</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openDiscoveryModal(record)}>编辑</Button>
          <Popconfirm title="删除该发现规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeDiscoveryRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={discoveryLoading}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const conditionColumns: ColumnsType<GovernanceDiscoveryCondition> = [
        { title: "类型", dataIndex: "condition_type", width: 120 },
        { title: "字段", dataIndex: "field", width: 120 },
        { title: "操作符", dataIndex: "operator", width: 110 },
        { title: "值", dataIndex: "value" },
        { title: "权重", dataIndex: "weight", width: 80 },
        { title: "必需", dataIndex: "required", width: 80, render: (value) => (value ? "是" : "否") },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        {
            title: "操作",
            width: 180,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openConditionModal(record)}>编辑</Button>
          <Popconfirm title="删除该条件？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeCondition(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const model = { keyword: discoveryKeyword, setKeyword: setDiscoveryKeyword, enabled: discoveryEnabled, setEnabled: setDiscoveryEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyDiscoveryFilter, resetFilter: resetDiscoveryFilter, openCreate: () => openDiscoveryModal(), reload: loadDiscoveryRules, loading: discoveryLoading, columns: discoveryColumns, page: discoveryPage, query: discoveryQuery, setQuery: setDiscoveryQuery, pagination: tablePagination };
    const { keyword, setKeyword, enabled, setEnabled, enabledOptions, applyFilter, resetFilter, openCreate, reload, loading, columns, page, query, setQuery, pagination } = model;
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>Agent 发现规则</Typography.Title></div><Space direction="vertical" size={16} className="governance-full-width">
    <Space className="governance-toolbar" wrap>
      <Input.Search allowClear placeholder="搜索规则名 / Agent Type" value={keyword} onChange={event => setKeyword(event.target.value)} onSearch={applyFilter} className="governance-search"/>
      <Select value={enabled} onChange={setEnabled} options={[...enabledOptions]} className="governance-filter-select"/>
      <Button icon={<SearchOutlined />} onClick={applyFilter}>查询</Button><Button onClick={resetFilter}>重置</Button>
      <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增发现规则</Button>
      <Button aria-label="刷新发现规则" icon={<ReloadOutlined />} onClick={() => void reload()}/>
    </Space>
    <Table rowKey="id" loading={loading} columns={columns} dataSource={page.items} scroll={{ x: 900 }} pagination={pagination(page, query)} onChange={value => setQuery((previous) => ({ ...previous, page: value.current ?? 1, pageSize: value.pageSize ?? previous.pageSize }))}/>
  </Space><Modal title={editingDiscoveryRule ? "编辑发现规则" : "新增发现规则"} open={discoveryModalOpen} onCancel={() => setDiscoveryModalOpen(false)} onOk={() => void saveDiscoveryRule()} destroyOnHidden>
        <Form form={discoveryForm} layout="vertical">
          <Form.Item name="agent_type_id" label="Agent Type" rules={[{ required: true }]}><Select options={agentTypeOptions}/></Form.Item>
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="threshold" label="命中阈值"><InputNumber min={1} max={100} className="governance-full-width"/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    <Drawer title="发现规则条件" open={discoveryDetailOpen} onClose={() => setDiscoveryDetailOpen(false)} width={920}>
        {discoveryDetail ? (<Space direction="vertical" size={16} className="governance-full-width">
            <Descriptions size="small" bordered column={3} items={[
                { key: "name", label: "规则", children: discoveryDetail.rule_name },
                { key: "type", label: "Agent Type", children: discoveryDetail.agent_type_key },
                { key: "threshold", label: "阈值", children: discoveryDetail.threshold },
            ]}/>
            <Alert type="info" showIcon message="条件命中后按权重累加；required 条件必须命中；总分达到阈值后该规则才会命中。"/>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openConditionModal()}>新增条件</Button>
            <Table rowKey="id" columns={conditionColumns} dataSource={discoveryDetail.conditions ?? []} pagination={false}/>
          </Space>) : null}
      </Drawer>
    <Modal title={editingCondition ? "编辑发现条件" : "新增发现条件"} open={conditionModalOpen} onCancel={() => setConditionModalOpen(false)} onOk={() => void saveCondition()} destroyOnHidden>
        <Form form={conditionForm} layout="vertical">
          <Form.Item name="condition_type" label="条件类型" rules={[{ required: true }]}><Input placeholder="cli / directory / process"/></Form.Item>
          <Form.Item name="field" label="字段"><Input placeholder="name / path / command_line"/></Form.Item>
          <Form.Item name="operator" label="操作符" rules={[{ required: true }]}><Input placeholder="exists / contains"/></Form.Item>
          <Form.Item name="value" label="值" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="weight" label="权重"><InputNumber min={0} max={100} className="governance-full-width"/></Form.Item>
          <Form.Item name="required" label="必需" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal></section>;
}
