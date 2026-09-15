import { useCallback, useEffect, useMemo, useState } from "react";
import { DeleteOutlined, EditOutlined, PlusOutlined } from "@ant-design/icons";
import { Button, Form, Input, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message } from "antd";
import type { ColumnsType } from "antd/es/table";
import { createGovernanceScanProfile, deleteGovernanceScanProfile, getGovernanceScanCapabilities, getGovernanceScanProfiles, replaceGovernanceScanProfileCapabilities, updateGovernanceScanProfile } from "../../bridge";
import type { GovernanceScanCapability, GovernanceScanProfile, GovernanceScanProfileInput } from "../../types";
const RESOURCE_TYPES = ["skill", "mcp", "plugin", "config", "prompt", "credential", "environment"];
function enabledTag(enabled: boolean) {
    return enabled ? <Tag color="success">启用</Tag> : <Tag>停用</Tag>;
}
export function AllowedScanProfilesPage() {
    const [referenceLoading, setReferenceLoading] = useState(false);
    const [scanProfiles, setScanProfiles] = useState<GovernanceScanProfile[]>([]);
    const [scanCapabilities, setScanCapabilities] = useState<GovernanceScanCapability[]>([]);
    const [profileForm] = Form.useForm<GovernanceScanProfileInput>();
    const [profileModalOpen, setProfileModalOpen] = useState(false);
    const [editingProfile, setEditingProfile] = useState<GovernanceScanProfile>();
    const [profileCapabilityIDs, setProfileCapabilityIDs] = useState<number[]>([]);
    const capabilityOptions = useMemo(() => scanCapabilities.map((item) => ({ label: `${item.name} (${item.capability_key})`, value: item.id })), [scanCapabilities]);
    const loadReferences = useCallback(async () => { setReferenceLoading(true); try {
        await Promise.all([getGovernanceScanProfiles({ page: 1, pageSize: 500 }).then(value => setScanProfiles(value.items ?? [])), getGovernanceScanCapabilities().then(value => setScanCapabilities(value.items ?? []))]);
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
    const openProfileModal = (record?: GovernanceScanProfile) => {
        setEditingProfile(record);
        profileForm.setFieldsValue(record ?? { enabled: true, resource_type: "skill" });
        setProfileCapabilityIDs((record?.capabilities ?? []).map((item) => item.capability_id));
        setProfileModalOpen(true);
    };
    const saveProfile = async () => {
        const values = await profileForm.validateFields();
        const body = { ...values, enabled: values.enabled ?? true };
        const saved = editingProfile
            ? await updateGovernanceScanProfile(editingProfile.id, body)
            : await createGovernanceScanProfile(body);
        await replaceGovernanceScanProfileCapabilities(saved.id, profileCapabilityIDs.map((id, index) => ({ capability_id: id, priority: (index + 1) * 10, enabled: true, config_json: "{}" })));
        message.success(editingProfile ? "扫描方案已更新" : "扫描方案已创建");
        setProfileModalOpen(false);
        await Promise.all([loadReferences()]);
    };
    const removeProfile = async (record: GovernanceScanProfile) => {
        await deleteGovernanceScanProfile(record.id);
        message.success("扫描方案已删除");
        await Promise.all([loadReferences()]);
    };
    const profileColumns: ColumnsType<GovernanceScanProfile> = [
        { title: "名称", dataIndex: "name", width: 180 },
        { title: "资源类型", dataIndex: "resource_type", width: 110, render: (value) => <Tag>{value}</Tag> },
        { title: "能力", dataIndex: "capability_count", width: 90 },
        { title: "引用规则", dataIndex: "rule_count", width: 100 },
        { title: "资源数", dataIndex: "resource_count", width: 90 },
        { title: "描述", dataIndex: "description", ellipsis: true },
        { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
        {
            title: "操作",
            width: 170,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openProfileModal(record)}>编辑</Button>
          <Popconfirm title="删除该扫描方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const model = { openCreate: () => openProfileModal(), loading: referenceLoading, profileColumns, profiles: scanProfiles, capabilityColumns: [{ title: "Capability Key", dataIndex: "capability_key" }, { title: "名称", dataIndex: "name" }, { title: "Scanner", dataIndex: "scanner_name" }, { title: "状态", dataIndex: "enabled", render: enabledTag }], capabilities: scanCapabilities };
    const { openCreate, loading, profiles, capabilityColumns, capabilities } = model;
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>当资源决策为 allowed 时的扫描方案</Typography.Title></div><Space direction="vertical" size={16} className="governance-full-width">
    <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>新增扫描方案</Button>
    <Table rowKey="id" loading={loading} columns={profileColumns} dataSource={profiles} pagination={{ pageSize: 10 }}/>
    <Table rowKey="id" size="small" columns={capabilityColumns} dataSource={capabilities} pagination={false}/>
  </Space><Modal title={editingProfile ? "编辑扫描方案" : "新增扫描方案"} open={profileModalOpen} onCancel={() => setProfileModalOpen(false)} onOk={() => void saveProfile()} destroyOnHidden>
        <Form form={profileForm} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}><Select options={RESOURCE_TYPES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3}/></Form.Item>
          <Form.Item label="扫描能力"><Select mode="multiple" value={profileCapabilityIDs} onChange={setProfileCapabilityIDs} options={capabilityOptions}/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal></section>;
}
