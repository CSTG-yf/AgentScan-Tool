import { useCallback, useEffect, useState } from "react";
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Button, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { createGovernanceAgentType, deleteGovernanceAgentType, getGovernanceAgentTypes, updateGovernanceAgentType } from "../../bridge";
import type { GovernanceAgentType, GovernanceAgentTypeInput, GovernancePage } from "../../types";
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
export function AgentTypeManagementPage() {
    const [agentLoading, setAgentLoading] = useState(false);
    const [agentPage, setAgentPage] = useState<GovernancePage<GovernanceAgentType>>(emptyPage());
    const [agentQuery, setAgentQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 10 });
    const [agentKeyword, setAgentKeyword] = useState("");
    const [agentEnabled, setAgentEnabled] = useState<EnabledFilter>("all");
    const [agentForm] = Form.useForm<GovernanceAgentTypeInput>();
    const [agentModalOpen, setAgentModalOpen] = useState(false);
    const [editingAgentType, setEditingAgentType] = useState<GovernanceAgentType>();
    const loadAgentTypes = useCallback(async () => {
        setAgentLoading(true);
        try {
            setAgentPage(await getGovernanceAgentTypes(queryFromState(agentQuery)));
        }
        catch (error) {
            message.error(`读取 Agent Type 失败：${String(error)}`);
        }
        finally {
            setAgentLoading(false);
        }
    }, [agentQuery]);
    useEffect(() => {
        void loadAgentTypes();
    }, [loadAgentTypes]);
    const applyAgentFilter = () => {
        setAgentQuery((prev) => ({ ...prev, page: 1, keyword: agentKeyword.trim(), enabled: agentEnabled }));
    };
    const resetAgentFilter = () => {
        setAgentKeyword("");
        setAgentEnabled("all");
        setAgentQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
    };
    const openAgentModal = (record?: GovernanceAgentType) => {
        setEditingAgentType(record);
        agentForm.setFieldsValue(record ?? { enabled: true, kind: "cli", runtime: "local" });
        setAgentModalOpen(true);
    };
    const saveAgentType = async () => {
        const values = await agentForm.validateFields();
        if (editingAgentType) {
            await updateGovernanceAgentType(editingAgentType.id, values);
            message.success("Agent Type 已更新");
        }
        else {
            await createGovernanceAgentType({ ...values, enabled: values.enabled ?? true });
            message.success("Agent Type 已创建");
        }
        setAgentModalOpen(false);
        await Promise.all([loadAgentTypes()]);
    };
    const removeAgentType = async (record: GovernanceAgentType) => {
        await deleteGovernanceAgentType(record.id);
        message.success("Agent Type 已删除");
        await Promise.all([loadAgentTypes()]);
    };
    const agentColumns: ColumnsType<GovernanceAgentType> = [
        { title: "Type Key", dataIndex: "type_key", width: 160 },
        { title: "名称", dataIndex: "name", width: 180 },
        { title: "厂商", dataIndex: "vendor", width: 140 },
        { title: "类型", dataIndex: "kind", width: 110 },
        { title: "运行时", dataIndex: "runtime", width: 120 },
        { title: "Agent", dataIndex: "agent_count", width: 90 },
        { title: "发现规则", dataIndex: "discovery_rule_count", width: 100 },
        { title: "资源规则", dataIndex: "resource_rule_count", width: 100 },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        {
            title: "操作",
            fixed: "right",
            width: 180,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openAgentModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Agent Type？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeAgentType(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={agentLoading}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const model = { keyword: agentKeyword, setKeyword: setAgentKeyword, enabled: agentEnabled, setEnabled: setAgentEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyAgentFilter, resetFilter: resetAgentFilter, openCreate: () => openAgentModal(), reload: loadAgentTypes, loading: agentLoading, columns: agentColumns, page: agentPage, query: agentQuery, setQuery: setAgentQuery, pagination: tablePagination };
    const { keyword, setKeyword, enabled, setEnabled, enabledOptions, applyFilter, resetFilter, openCreate, reload, loading, columns, page, query, setQuery, pagination } = model;
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>Agent 类型管理</Typography.Title></div><Space direction="vertical" size={16} className="governance-full-width">
    <Space className="governance-toolbar" wrap>
      <Input.Search allowClear placeholder="搜索 Type Key / 名称 / 厂商" value={keyword} onChange={event => setKeyword(event.target.value)} onSearch={applyFilter} className="governance-search"/>
      <Select value={enabled} onChange={setEnabled} options={[...enabledOptions]} className="governance-filter-select"/>
      <Button icon={<SearchOutlined />} onClick={applyFilter}>查询</Button><Button onClick={resetFilter}>重置</Button>
      <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增 Agent Type</Button>
      <Button aria-label="刷新 Agent Type" icon={<ReloadOutlined />} onClick={() => void reload()}/>
    </Space>
    <Table rowKey="id" loading={loading} columns={columns} dataSource={page.items} scroll={{ x: 1120 }} pagination={pagination(page, query)} onChange={value => setQuery((previous) => ({ ...previous, page: value.current ?? 1, pageSize: value.pageSize ?? previous.pageSize }))}/>
  </Space><Modal title={editingAgentType ? "编辑 Agent Type" : "新增 Agent Type"} open={agentModalOpen} onCancel={() => setAgentModalOpen(false)} onOk={() => void saveAgentType()} destroyOnHidden>
        <Form form={agentForm} layout="vertical">
          <Form.Item name="type_key" label="Type Key" rules={[{ required: true }]}><Input disabled={!!editingAgentType}/></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="vendor" label="厂商"><Input /></Form.Item>
          <Form.Item name="kind" label="类型"><Input /></Form.Item>
          <Form.Item name="runtime" label="运行时"><Input /></Form.Item>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3}/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal></section>;
}
