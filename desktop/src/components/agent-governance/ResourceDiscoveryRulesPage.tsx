import { useCallback, useEffect, useMemo, useState } from "react";
import { DeleteOutlined, EditOutlined, EyeOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message, List } from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { createGovernanceResourceRule, deleteGovernanceResourceRule, getGovernanceAgentTypes, getGovernancePostScanProfiles, getGovernancePreScanProfiles, getGovernanceResourceRules, getGovernanceScanProfiles, previewGovernanceResourceRule, updateGovernanceResourceRule } from "../../bridge";
import type { GovernanceAgentType, GovernancePage, GovernancePostScanProfile, GovernancePreScanProfile, GovernanceResourceRule, GovernanceResourceRuleInput, GovernanceScanProfile } from "../../types";
const { Text } = Typography;
const RESOURCE_TYPES = ["skill", "mcp", "plugin", "config", "prompt", "credential", "environment"];
const ENUMERATION_MODES = ["exact", "children", "glob", "recursive"];
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
export function ResourceDiscoveryRulesPage() {
    const [referenceLoading, setReferenceLoading] = useState(false);
    const [resourceLoading, setResourceLoading] = useState(false);
    const [agentTypeCatalog, setAgentTypeCatalog] = useState<GovernanceAgentType[]>([]);
    const [resourcePage, setResourcePage] = useState<GovernancePage<GovernanceResourceRule>>(emptyPage());
    const [scanProfiles, setScanProfiles] = useState<GovernanceScanProfile[]>([]);
    const [preScanProfileCatalog, setPreScanProfileCatalog] = useState<GovernancePreScanProfile[]>([]);
    const [postScanProfileCatalog, setPostScanProfileCatalog] = useState<GovernancePostScanProfile[]>([]);
    const [selectedResourceAgentTypeID, setSelectedResourceAgentTypeID] = useState<number | undefined>();
    const [resourceQuery, setResourceQuery] = useState<PageQueryState>({ keyword: "", enabled: "enabled", page: 1, pageSize: 10 });
    const [resourceKeyword, setResourceKeyword] = useState("");
    const [resourceEnabled, setResourceEnabled] = useState<EnabledFilter>("enabled");
    const [resourceRuleForm] = Form.useForm<GovernanceResourceRuleInput>();
    const [resourceRuleModalOpen, setResourceRuleModalOpen] = useState(false);
    const [editingResourceRule, setEditingResourceRule] = useState<GovernanceResourceRule>();
    const [previewOpen, setPreviewOpen] = useState(false);
    const [previewRows, setPreviewRows] = useState<Array<{
        name: string;
        target: string;
        exists: boolean;
        type: string;
    }>>([]);
    const agentTypeOptions = useMemo(() => agentTypeCatalog.map((item) => ({ label: `${item.name} (${item.type_key})`, value: item.id })), [agentTypeCatalog]);
    const profileOptions = useMemo(() => scanProfiles.map((item) => ({ label: `${item.name} / ${item.resource_type}`, value: item.id })), [scanProfiles]);
    const preScanProfileOptions = useMemo(() => preScanProfileCatalog.map((item) => ({ label: `${item.name}${item.is_default ? "（默认）" : ""}`, value: item.id })), [preScanProfileCatalog]);
    const postScanProfileOptions = useMemo(() => postScanProfileCatalog.map((item) => ({ label: `${item.name}${item.is_default ? "（默认）" : ""}`, value: item.id })), [postScanProfileCatalog]);
    const defaultPreScanProfileID = preScanProfileCatalog.find((item) => item.is_default)?.id ?? preScanProfileCatalog[0]?.id;
    const defaultPostScanProfileID = postScanProfileCatalog.find((item) => item.is_default)?.id ?? postScanProfileCatalog[0]?.id;
    const selectedResourceAgentType = useMemo(() => agentTypeCatalog.find((item) => item.id === selectedResourceAgentTypeID), [agentTypeCatalog, selectedResourceAgentTypeID]);
    const loadResourceRules = useCallback(async () => {
        setResourceLoading(true);
        try {
            setResourcePage(await getGovernanceResourceRules({ ...queryFromState(resourceQuery), agentTypeId: selectedResourceAgentTypeID }));
        }
        catch (error) {
            message.error(`读取资源发现规则失败：${String(error)}`);
        }
        finally {
            setResourceLoading(false);
        }
    }, [resourceQuery, selectedResourceAgentTypeID]);
    const loadReferences = useCallback(async () => { setReferenceLoading(true); try {
        await Promise.all([getGovernanceAgentTypes({ page: 1, pageSize: 500 }).then(value => setAgentTypeCatalog(value.items ?? [])), getGovernanceScanProfiles({ page: 1, pageSize: 500 }).then(value => setScanProfiles(value.items ?? [])), getGovernancePreScanProfiles({ page: 1, pageSize: 500 }).then(value => setPreScanProfileCatalog(value.items ?? [])), getGovernancePostScanProfiles({ page: 1, pageSize: 500 }).then(value => setPostScanProfileCatalog(value.items ?? []))]);
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
        void loadResourceRules();
    }, [loadResourceRules]);
    const applyResourceFilter = () => {
        setResourceQuery((prev) => ({ ...prev, page: 1, keyword: resourceKeyword.trim(), enabled: resourceEnabled }));
    };
    const resetResourceFilter = () => {
        setResourceKeyword("");
        setResourceEnabled("enabled");
        setResourceQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "enabled" }));
    };
    const openResourceRuleModal = (record?: GovernanceResourceRule) => {
        const fallbackAgentTypeID = selectedResourceAgentTypeID ?? agentTypeCatalog[0]?.id;
        setEditingResourceRule(record);
        resourceRuleForm.setFieldsValue(record ?? {
            agent_type_id: fallbackAgentTypeID,
            enabled: true,
            priority: 100,
            enumeration_mode: "children",
            resource_type: "skill",
            pre_scan_profile_id: defaultPreScanProfileID,
            post_scan_profile_id: defaultPostScanProfileID,
        });
        setResourceRuleModalOpen(true);
    };
    const saveResourceRule = async () => {
        const values = await resourceRuleForm.validateFields();
        const body = {
            ...values,
            enabled: values.enabled ?? true,
            priority: values.priority ?? 100,
            pre_scan_profile_id: values.pre_scan_profile_id ?? defaultPreScanProfileID,
            post_scan_profile_id: values.post_scan_profile_id ?? defaultPostScanProfileID,
        };
        if (editingResourceRule) {
            await updateGovernanceResourceRule(editingResourceRule.id, body);
            message.success("资源发现规则已更新");
        }
        else {
            await createGovernanceResourceRule(body);
            message.success("资源发现规则已创建");
        }
        setResourceRuleModalOpen(false);
        await Promise.all([loadReferences(), loadResourceRules()]);
    };
    const removeResourceRule = async (record: GovernanceResourceRule) => {
        await deleteGovernanceResourceRule(record.id);
        message.success("资源发现规则已删除");
        await Promise.all([loadReferences(), loadResourceRules()]);
    };
    const previewRule = async (record: GovernanceResourceRule) => {
        try {
            const result = await previewGovernanceResourceRule({
                agent_type_id: record.agent_type_id,
                path_pattern: record.path_pattern,
                enumeration_mode: record.enumeration_mode,
            });
            setPreviewRows(result.targets ?? []);
            setPreviewOpen(true);
        }
        catch (error) {
            message.error(`预览失败：${String(error)}`);
        }
    };
    const resourceRuleColumns: ColumnsType<GovernanceResourceRule> = [
        { title: "Agent Type", dataIndex: "agent_type_key", width: 150 },
        { title: "名称", dataIndex: "name", width: 180 },
        { title: "资源类型", dataIndex: "resource_type", width: 110, render: (value) => <Tag>{value}</Tag> },
        { title: "路径模式", dataIndex: "path_pattern", ellipsis: true },
        { title: "枚举", dataIndex: "enumeration_mode", width: 100 },
        { title: "扫描方案", dataIndex: "scan_profile_name", width: 160 },
        { title: "Pre-scan", dataIndex: "pre_scan_profile_name", width: 170, render: (value) => value || "-" },
        { title: "Post-scan", dataIndex: "post_scan_profile_name", width: 170, render: (value) => value || "-" },
        { title: "命中资源", dataIndex: "resource_count", width: 100 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        {
            title: "操作",
            fixed: "right",
            width: 240,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => void previewRule(record)}>预览</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openResourceRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该资源规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeResourceRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={resourceLoading}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const model = { agentTypes: agentTypeCatalog, selectedTypeId: selectedResourceAgentTypeID, setSelectedTypeId: setSelectedResourceAgentTypeID, selectedType: selectedResourceAgentType, setQuery: setResourceQuery, keyword: resourceKeyword, setKeyword: setResourceKeyword, enabled: resourceEnabled, setEnabled: setResourceEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyResourceFilter, resetFilter: resetResourceFilter, openCreate: () => openResourceRuleModal(), reload: loadResourceRules, loading: resourceLoading, columns: resourceRuleColumns, page: resourcePage, query: resourceQuery, pagination: tablePagination };
    const { agentTypes, selectedTypeId, setSelectedTypeId, selectedType, setQuery, keyword, setKeyword, enabled, setEnabled, enabledOptions, applyFilter, resetFilter, openCreate, reload, loading, columns, page, query, pagination } = model;
    const selectType = (id?: number) => { setSelectedTypeId(id); setQuery((previous) => ({ ...previous, page: 1 })); };
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>资源发现规则</Typography.Title></div><div className="governance-resource-layout">
    <aside className="governance-agent-type-panel">
      <div className="governance-agent-type-heading"><Text strong>Agent Type</Text><Text type="secondary">{agentTypes.length}</Text></div>
      <button type="button" className={`governance-agent-type-item ${selectedTypeId === undefined ? "active" : ""}`} onClick={() => selectType()}><span>全部 Agent Type</span><Tag>{agentTypes.reduce((sum: number, item: GovernanceAgentType) => sum + item.resource_rule_count, 0)}</Tag></button>
      <List dataSource={agentTypes} renderItem={(item: GovernanceAgentType) => <List.Item><button type="button" className={`governance-agent-type-item ${selectedTypeId === item.id ? "active" : ""}`} onClick={() => selectType(item.id)}><span><strong>{item.name}</strong><em>{item.type_key}</em></span><Tag color={item.enabled ? "blue" : "default"}>{item.resource_rule_count}</Tag></button></List.Item>}/>
    </aside>
    <div className="governance-resource-main"><Space direction="vertical" size={16} className="governance-full-width">
      <Space className="governance-toolbar" wrap>
        <Button type="primary" icon={<PlusOutlined />} disabled={!agentTypes.length} onClick={openCreate}>新增资源规则</Button>
        {selectedType ? <Tag color="blue">{selectedType.name}</Tag> : <Tag>全部 Agent Type</Tag>}
        <Input.Search allowClear placeholder="搜索规则名 / 路径模式" value={keyword} onChange={event => setKeyword(event.target.value)} onSearch={applyFilter} className="governance-search"/>
        <Select value={enabled} onChange={setEnabled} options={[...enabledOptions]} className="governance-filter-select"/>
        <Button icon={<SearchOutlined />} onClick={applyFilter}>查询</Button><Button onClick={resetFilter}>重置</Button>
        <Button aria-label="刷新资源规则" icon={<ReloadOutlined />} onClick={() => void reload()}/>
      </Space>
      <Table rowKey="id" loading={loading} columns={columns} dataSource={page.items} scroll={{ x: 1160 }} pagination={pagination(page, query)} onChange={value => setQuery((previous) => ({ ...previous, page: value.current ?? 1, pageSize: value.pageSize ?? previous.pageSize }))}/>
    </Space></div>
  </div><Modal title={editingResourceRule ? "编辑资源发现规则" : "新增资源发现规则"} open={resourceRuleModalOpen} onCancel={() => setResourceRuleModalOpen(false)} onOk={() => void saveResourceRule()} destroyOnHidden>
        <Form form={resourceRuleForm} layout="vertical">
          <Form.Item name="agent_type_id" label="Agent Type" rules={[{ required: true }]}><Select options={agentTypeOptions}/></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}><Select options={RESOURCE_TYPES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="path_pattern" label="路径模式" rules={[{ required: true }]}><Input placeholder="${CONFIG_ROOT}/skills"/></Form.Item>
          <Form.Item name="enumeration_mode" label="枚举模式" rules={[{ required: true }]}><Select options={ENUMERATION_MODES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="scan_profile_id" label="扫描方案"><Select allowClear options={profileOptions}/></Form.Item>
          <Form.Item name="pre_scan_profile_id" label="Pre-scan 方案"><Select options={preScanProfileOptions}/></Form.Item>
          <Form.Item name="post_scan_profile_id" label="Post-scan 方案"><Select options={postScanProfileOptions}/></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} className="governance-full-width"/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    <Modal title="资源发现预览" open={previewOpen} onCancel={() => setPreviewOpen(false)} footer={null} width={900}>
        <Table rowKey="target" size="small" dataSource={previewRows} pagination={{ pageSize: 8 }} columns={[
            { title: "名称", dataIndex: "name", width: 180 },
            { title: "类型", dataIndex: "type", width: 100 },
            { title: "存在", dataIndex: "exists", width: 90, render: (value) => (value ? <Tag color="success">是</Tag> : <Tag>否</Tag>) },
            { title: "路径", dataIndex: "target", ellipsis: true },
        ]}/>
      </Modal></section>;
}
