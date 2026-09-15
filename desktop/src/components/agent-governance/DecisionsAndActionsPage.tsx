import type { Dispatch, SetStateAction } from "react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { DeleteOutlined, EditOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from "@ant-design/icons";
import { Alert, Button, Form, Input, InputNumber, Modal, Popconfirm, Select, Space, Switch, Table, Tag, Typography, message, Card } from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import { createGovernancePostScanProfile, createGovernancePostScanRule, createGovernancePreScanProfile, createGovernancePreScanRule, deleteGovernancePostScanProfile, deleteGovernancePostScanRule, deleteGovernancePreScanProfile, deleteGovernancePreScanRule, getGovernanceAgentTypes, getGovernancePostScanProfiles, getGovernancePostScanRules, getGovernancePreScanProfiles, getGovernancePreScanRules, updateGovernancePostScanProfile, updateGovernancePostScanRule, updateGovernancePreScanProfile, updateGovernancePreScanRule } from "../../bridge";
import type { GovernanceAgentType, GovernancePage, GovernancePostScanProfile, GovernancePostScanProfileInput, GovernancePostScanRule, GovernancePostScanRuleInput, GovernancePreScanProfile, GovernancePreScanProfileInput, GovernancePreScanRule, GovernancePreScanRuleInput } from "../../types";
const { Text, Title } = Typography;
const RESOURCE_TYPES = ["skill", "mcp", "plugin", "config", "prompt", "credential", "environment"];
const DECISION_RESOURCE_TYPES = ["all", ...RESOURCE_TYPES];
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const RISK_LEVELS = ["clean", "low", "medium", "high", "critical"];
const PRE_SCAN_DECISIONS = ["scan", "skip", "allow", "alert", "review", "block", "reject"];
const POST_SCAN_DECISIONS = ["allow", "alert", "review", "block", "reject", "clean", "ignore"];
const INSTALL_ACTIONS = ["none", "allow", "block"];
const FILE_ACTIONS = ["none", "quarantine"];
const RUNTIME_ACTIONS = ["none", "allow", "block", "disable", "enable"];
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
type DraftPreScanRule = GovernancePreScanRuleInput & {
    draft_id: string;
};
type DraftPostScanRule = GovernancePostScanRuleInput & {
    draft_id: string;
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
function verdictTag(value: string) {
    const color = value === "rejected" || value === "blocked" ? "red" : value === "warning" ? "orange" : value === "scan" ? "blue" : "green";
    return <Tag color={color}>{value || "-"}</Tag>;
}
function actionText(action?: string) {
    return action && action !== "none" ? action : "-";
}
function makeProfileKey(prefix: "pre" | "post") {
    return `${prefix}-scan-${Date.now().toString(36)}`;
}
function defaultPreScanRuleValues(): GovernancePreScanRuleInput {
    return {
        rule_name: "新建 Pre-scan 规则",
        priority: 100,
        resource_type: "all",
        path_pattern: "",
        source_trust: "",
        decision: "scan",
        install_action: "none",
        file_action: "none",
        runtime_action: "allow",
        enabled: true,
    };
}
function defaultPostScanRuleValues(): GovernancePostScanRuleInput {
    return {
        rule_name: "新建 Post-scan 规则",
        priority: 100,
        resource_type: "all",
        severity: "HIGH",
        risk_level: "high",
        malicious: false,
        finding_category: "",
        scanner: "",
        decision: "alert",
        install_action: "none",
        file_action: "none",
        runtime_action: "allow",
        enabled: true,
    };
}
type ProfileSectionModel<T extends object> = {
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
    query: PageQueryState;
    setQuery: Dispatch<SetStateAction<PageQueryState>>;
    pagination: typeof tablePagination;
    kind: string;
    openCreate: () => void;
};
function ProfileSection<T extends object>({ title, side }: {
    title: string;
    side: ProfileSectionModel<T>;
}) {
    return <Card bordered={false} className="workspace-table-card"><Space direction="vertical" size={16} className="governance-full-width">
    <Space className="governance-toolbar" wrap>
      <Text strong>{title}</Text>
      <Input.Search allowClear placeholder="搜索方案 Key / 名称 / 描述" value={side.keyword} onChange={event => side.setKeyword(event.target.value)} onSearch={side.applyFilter} className="governance-search"/>
      <Select value={side.enabled} onChange={side.setEnabled} options={[...side.enabledOptions]} className="governance-filter-select"/>
      <Button icon={<SearchOutlined />} onClick={side.applyFilter}>查询</Button><Button onClick={side.resetFilter}>重置</Button>
      <Button type="primary" icon={<PlusOutlined />} onClick={side.openCreate}>新增 {side.kind} 方案</Button>
      <Button aria-label={`刷新${title}`} icon={<ReloadOutlined />} onClick={() => void side.reload()}/>
    </Space>
    <Table rowKey="id" loading={side.loading} columns={side.columns} dataSource={side.page.items} scroll={{ x: 1060 }} pagination={side.pagination(side.page, side.query)} onChange={value => side.setQuery((previous) => ({ ...previous, page: value.current ?? 1, pageSize: value.pageSize ?? previous.pageSize }))}/>
  </Space></Card>;
}
export function DecisionsAndActionsPage() {
    const [referenceLoading, setReferenceLoading] = useState(false);
    const [agentTypeCatalog, setAgentTypeCatalog] = useState<GovernanceAgentType[]>([]);
    const [preScanProfilePage, setPreScanProfilePage] = useState<GovernancePage<GovernancePreScanProfile>>(emptyPage(1, 8));
    const [postScanProfilePage, setPostScanProfilePage] = useState<GovernancePage<GovernancePostScanProfile>>(emptyPage(1, 8));
    const [preScanRulePage, setPreScanRulePage] = useState<GovernancePage<GovernancePreScanRule>>(emptyPage(1, 6));
    const [postScanRulePage, setPostScanRulePage] = useState<GovernancePage<GovernancePostScanRule>>(emptyPage(1, 6));
    const [decisionLoading, setDecisionLoading] = useState(false);
    const [preScanQuery, setPreScanQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 8 });
    const [preScanKeyword, setPreScanKeyword] = useState("");
    const [preScanEnabled, setPreScanEnabled] = useState<EnabledFilter>("all");
    const [postScanQuery, setPostScanQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 8 });
    const [postScanKeyword, setPostScanKeyword] = useState("");
    const [postScanEnabled, setPostScanEnabled] = useState<EnabledFilter>("all");
    const [preScanProfileForm] = Form.useForm<GovernancePreScanProfileInput>();
    const [preScanProfileModalOpen, setPreScanProfileModalOpen] = useState(false);
    const [editingPreScanProfile, setEditingPreScanProfile] = useState<GovernancePreScanProfile>();
    const [preScanRuleQuery, setPreScanRuleQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 6 });
    const [preScanRuleKeyword, setPreScanRuleKeyword] = useState("");
    const [preScanRuleEnabled, setPreScanRuleEnabled] = useState<EnabledFilter>("all");
    const [preScanRuleForm] = Form.useForm<GovernancePreScanRuleInput>();
    const [preScanRuleModalOpen, setPreScanRuleModalOpen] = useState(false);
    const [editingPreScanRule, setEditingPreScanRule] = useState<GovernancePreScanRule>();
    const [draftPreScanRules, setDraftPreScanRules] = useState<DraftPreScanRule[]>([]);
    const [editingDraftPreScanRuleID, setEditingDraftPreScanRuleID] = useState<string>();
    const [postScanProfileForm] = Form.useForm<GovernancePostScanProfileInput>();
    const [postScanProfileModalOpen, setPostScanProfileModalOpen] = useState(false);
    const [editingPostScanProfile, setEditingPostScanProfile] = useState<GovernancePostScanProfile>();
    const [postScanRuleQuery, setPostScanRuleQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 6 });
    const [postScanRuleKeyword, setPostScanRuleKeyword] = useState("");
    const [postScanRuleEnabled, setPostScanRuleEnabled] = useState<EnabledFilter>("all");
    const [postScanRuleForm] = Form.useForm<GovernancePostScanRuleInput>();
    const [postScanRuleModalOpen, setPostScanRuleModalOpen] = useState(false);
    const [editingPostScanRule, setEditingPostScanRule] = useState<GovernancePostScanRule>();
    const [draftPostScanRules, setDraftPostScanRules] = useState<DraftPostScanRule[]>([]);
    const [editingDraftPostScanRuleID, setEditingDraftPostScanRuleID] = useState<string>();
    const agentTypeOptions = useMemo(() => agentTypeCatalog.map((item) => ({ label: `${item.name} (${item.type_key})`, value: item.id })), [agentTypeCatalog]);
    const loadDecisionProfiles = useCallback(async () => {
        setDecisionLoading(true);
        try {
            const [prePage, postPage] = await Promise.all([
                getGovernancePreScanProfiles(queryFromState(preScanQuery)),
                getGovernancePostScanProfiles(queryFromState(postScanQuery)),
            ]);
            setPreScanProfilePage(prePage);
            setPostScanProfilePage(postPage);
        }
        catch (error) {
            message.error(`读取决策方案失败：${String(error)}`);
        }
        finally {
            setDecisionLoading(false);
        }
    }, [preScanQuery, postScanQuery]);
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
        void loadDecisionProfiles();
    }, [loadDecisionProfiles]);
    const applyPreScanFilter = () => {
        setPreScanQuery((prev) => ({ ...prev, page: 1, keyword: preScanKeyword.trim(), enabled: preScanEnabled }));
    };
    const resetPreScanFilter = () => {
        setPreScanKeyword("");
        setPreScanEnabled("all");
        setPreScanQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
    };
    const applyPostScanFilter = () => {
        setPostScanQuery((prev) => ({ ...prev, page: 1, keyword: postScanKeyword.trim(), enabled: postScanEnabled }));
    };
    const resetPostScanFilter = () => {
        setPostScanKeyword("");
        setPostScanEnabled("all");
        setPostScanQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
    };
    const applyPreScanRuleFilter = () => {
        setPreScanRuleQuery((prev) => ({ ...prev, page: 1, keyword: preScanRuleKeyword.trim(), enabled: preScanRuleEnabled }));
    };
    const resetPreScanRuleFilter = () => {
        setPreScanRuleKeyword("");
        setPreScanRuleEnabled("all");
        setPreScanRuleQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
    };
    const applyPostScanRuleFilter = () => {
        setPostScanRuleQuery((prev) => ({ ...prev, page: 1, keyword: postScanRuleKeyword.trim(), enabled: postScanRuleEnabled }));
    };
    const resetPostScanRuleFilter = () => {
        setPostScanRuleKeyword("");
        setPostScanRuleEnabled("all");
        setPostScanRuleQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
    };
    const loadPreScanRules = useCallback(async (profileID = editingPreScanProfile?.id) => {
        if (!profileID)
            return;
        try {
            setPreScanRulePage(await getGovernancePreScanRules(profileID, queryFromState(preScanRuleQuery)));
        }
        catch (error) {
            message.error(`读取 Pre-scan 规则失败：${String(error)}`);
        }
    }, [editingPreScanProfile?.id, preScanRuleQuery]);
    const loadPostScanRules = useCallback(async (profileID = editingPostScanProfile?.id) => {
        if (!profileID)
            return;
        try {
            setPostScanRulePage(await getGovernancePostScanRules(profileID, queryFromState(postScanRuleQuery)));
        }
        catch (error) {
            message.error(`读取 Post-scan 规则失败：${String(error)}`);
        }
    }, [editingPostScanProfile?.id, postScanRuleQuery]);
    useEffect(() => {
        if (preScanProfileModalOpen && editingPreScanProfile) {
            void loadPreScanRules(editingPreScanProfile.id);
        }
    }, [preScanProfileModalOpen, editingPreScanProfile, loadPreScanRules]);
    useEffect(() => {
        if (postScanProfileModalOpen && editingPostScanProfile) {
            void loadPostScanRules(editingPostScanProfile.id);
        }
    }, [postScanProfileModalOpen, editingPostScanProfile, loadPostScanRules]);
    const openPreScanProfileModal = (record?: GovernancePreScanProfile) => {
        setEditingPreScanProfile(record);
        preScanProfileForm.setFieldsValue(record ?? {
            profile_key: makeProfileKey("pre"),
            name: "",
            description: "",
            enabled: true,
            is_default: false,
        });
        setDraftPreScanRules([]);
        setEditingDraftPreScanRuleID(undefined);
        resetPreScanRuleFilter();
        setPreScanRulePage(emptyPage(1, 6));
        setPreScanProfileModalOpen(true);
    };
    const savePreScanProfile = async () => {
        const values = await preScanProfileForm.validateFields();
        const body = {
            ...values,
            enabled: values.enabled ?? true,
            is_default: values.is_default ?? false,
            rules: editingPreScanProfile ? undefined : draftPreScanRules.map(({ draft_id: _draftID, ...rule }) => rule),
        };
        if (editingPreScanProfile) {
            await updateGovernancePreScanProfile(editingPreScanProfile.id, body);
            message.success("Pre-scan 方案已更新");
        }
        else {
            await createGovernancePreScanProfile(body);
            message.success("Pre-scan 方案已创建");
        }
        setPreScanProfileModalOpen(false);
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const removePreScanProfile = async (record: GovernancePreScanProfile) => {
        await deleteGovernancePreScanProfile(record.id);
        message.success("Pre-scan 方案已删除");
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const togglePreScanProfile = async (record: GovernancePreScanProfile, enabled: boolean) => {
        await updateGovernancePreScanProfile(record.id, { enabled });
        message.success(enabled ? "Pre-scan 方案已启用" : "Pre-scan 方案已停用");
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const openPreScanRuleModal = (record?: GovernancePreScanRule | DraftPreScanRule) => {
        const draftID = record && "draft_id" in record ? record.draft_id : undefined;
        setEditingPreScanRule(record && !("draft_id" in record) ? record : undefined);
        setEditingDraftPreScanRuleID(draftID);
        preScanRuleForm.setFieldsValue(record ?? defaultPreScanRuleValues());
        setPreScanRuleModalOpen(true);
    };
    const savePreScanRule = async () => {
        const values = await preScanRuleForm.validateFields();
        const body = { ...defaultPreScanRuleValues(), ...values, enabled: values.enabled ?? true };
        if (editingPreScanProfile) {
            if (editingPreScanRule) {
                await updateGovernancePreScanRule(editingPreScanRule.id, body);
                message.success("Pre-scan 规则已更新");
            }
            else {
                await createGovernancePreScanRule(editingPreScanProfile.id, body);
                message.success("Pre-scan 规则已创建");
            }
            await Promise.all([loadPreScanRules(editingPreScanProfile.id), loadDecisionProfiles(), loadReferences()]);
        }
        else {
            if (editingDraftPreScanRuleID) {
                setDraftPreScanRules((prev) => prev.map((item) => (item.draft_id === editingDraftPreScanRuleID ? { ...body, draft_id: item.draft_id } : item)));
            }
            else {
                setDraftPreScanRules((prev) => [...prev, { ...body, draft_id: `draft-${Date.now()}-${prev.length}` }]);
            }
            message.success(editingDraftPreScanRuleID ? "草稿规则已更新" : "草稿规则已添加");
        }
        setPreScanRuleModalOpen(false);
        setEditingPreScanRule(undefined);
        setEditingDraftPreScanRuleID(undefined);
    };
    const removePreScanRule = async (record: GovernancePreScanRule) => {
        await deleteGovernancePreScanRule(record.id);
        message.success("Pre-scan 规则已删除");
        await Promise.all([loadPreScanRules(record.profile_id), loadDecisionProfiles(), loadReferences()]);
    };
    const togglePreScanRule = async (record: GovernancePreScanRule, enabled: boolean) => {
        await updateGovernancePreScanRule(record.id, { enabled });
        message.success(enabled ? "Pre-scan 规则已启用" : "Pre-scan 规则已停用");
        await Promise.all([loadPreScanRules(record.profile_id), loadDecisionProfiles(), loadReferences()]);
    };
    const removeDraftPreScanRule = (record: DraftPreScanRule) => {
        setDraftPreScanRules((prev) => prev.filter((item) => item.draft_id !== record.draft_id));
        message.success("草稿规则已删除");
    };
    const openPostScanProfileModal = (record?: GovernancePostScanProfile) => {
        setEditingPostScanProfile(record);
        postScanProfileForm.setFieldsValue(record ?? {
            profile_key: makeProfileKey("post"),
            name: "",
            description: "",
            enabled: true,
            is_default: false,
        });
        setDraftPostScanRules([]);
        setEditingDraftPostScanRuleID(undefined);
        resetPostScanRuleFilter();
        setPostScanRulePage(emptyPage(1, 6));
        setPostScanProfileModalOpen(true);
    };
    const savePostScanProfile = async () => {
        const values = await postScanProfileForm.validateFields();
        const body = {
            ...values,
            enabled: values.enabled ?? true,
            is_default: values.is_default ?? false,
            rules: editingPostScanProfile ? undefined : draftPostScanRules.map(({ draft_id: _draftID, ...rule }) => rule),
        };
        if (editingPostScanProfile) {
            await updateGovernancePostScanProfile(editingPostScanProfile.id, body);
            message.success("Post-scan 方案已更新");
        }
        else {
            await createGovernancePostScanProfile(body);
            message.success("Post-scan 方案已创建");
        }
        setPostScanProfileModalOpen(false);
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const removePostScanProfile = async (record: GovernancePostScanProfile) => {
        await deleteGovernancePostScanProfile(record.id);
        message.success("Post-scan 方案已删除");
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const togglePostScanProfile = async (record: GovernancePostScanProfile, enabled: boolean) => {
        await updateGovernancePostScanProfile(record.id, { enabled });
        message.success(enabled ? "Post-scan 方案已启用" : "Post-scan 方案已停用");
        await Promise.all([loadReferences(), loadDecisionProfiles()]);
    };
    const openPostScanRuleModal = (record?: GovernancePostScanRule | DraftPostScanRule) => {
        const draftID = record && "draft_id" in record ? record.draft_id : undefined;
        setEditingPostScanRule(record && !("draft_id" in record) ? record : undefined);
        setEditingDraftPostScanRuleID(draftID);
        postScanRuleForm.setFieldsValue(record ?? defaultPostScanRuleValues());
        setPostScanRuleModalOpen(true);
    };
    const savePostScanRule = async () => {
        const values = await postScanRuleForm.validateFields();
        const body = { ...defaultPostScanRuleValues(), ...values, enabled: values.enabled ?? true, malicious: values.malicious ?? false };
        if (editingPostScanProfile) {
            if (editingPostScanRule) {
                await updateGovernancePostScanRule(editingPostScanRule.id, body);
                message.success("Post-scan 规则已更新");
            }
            else {
                await createGovernancePostScanRule(editingPostScanProfile.id, body);
                message.success("Post-scan 规则已创建");
            }
            await Promise.all([loadPostScanRules(editingPostScanProfile.id), loadDecisionProfiles(), loadReferences()]);
        }
        else {
            if (editingDraftPostScanRuleID) {
                setDraftPostScanRules((prev) => prev.map((item) => (item.draft_id === editingDraftPostScanRuleID ? { ...body, draft_id: item.draft_id } : item)));
            }
            else {
                setDraftPostScanRules((prev) => [...prev, { ...body, draft_id: `draft-${Date.now()}-${prev.length}` }]);
            }
            message.success(editingDraftPostScanRuleID ? "草稿规则已更新" : "草稿规则已添加");
        }
        setPostScanRuleModalOpen(false);
        setEditingPostScanRule(undefined);
        setEditingDraftPostScanRuleID(undefined);
    };
    const removePostScanRule = async (record: GovernancePostScanRule) => {
        await deleteGovernancePostScanRule(record.id);
        message.success("Post-scan 规则已删除");
        await Promise.all([loadPostScanRules(record.profile_id), loadDecisionProfiles(), loadReferences()]);
    };
    const togglePostScanRule = async (record: GovernancePostScanRule, enabled: boolean) => {
        await updateGovernancePostScanRule(record.id, { enabled });
        message.success(enabled ? "Post-scan 规则已启用" : "Post-scan 规则已停用");
        await Promise.all([loadPostScanRules(record.profile_id), loadDecisionProfiles(), loadReferences()]);
    };
    const removeDraftPostScanRule = (record: DraftPostScanRule) => {
        setDraftPostScanRules((prev) => prev.filter((item) => item.draft_id !== record.draft_id));
        message.success("草稿规则已删除");
    };
    const preScanProfileColumns: ColumnsType<GovernancePreScanProfile> = [
        { title: "方案 Key", dataIndex: "profile_key", width: 170 },
        { title: "方案名称", dataIndex: "name", width: 180 },
        { title: "默认", dataIndex: "is_default", width: 80, render: (value) => (value ? <Tag color="blue">默认</Tag> : "-") },
        { title: "规则数", dataIndex: "rule_count", width: 90 },
        { title: "引用规则", dataIndex: "resource_rule_count", width: 100 },
        { title: "描述", dataIndex: "description", ellipsis: true },
        {
            title: "启用",
            dataIndex: "enabled",
            width: 90,
            render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePreScanProfile(record, checked)}/>,
        },
        {
            title: "操作",
            fixed: "right",
            width: 170,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanProfileModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Pre-scan 方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePreScanProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={record.is_default}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const preScanRuleColumns: ColumnsType<GovernancePreScanRule> = [
        { title: "优先级", dataIndex: "priority", width: 80 },
        { title: "规则名称", dataIndex: "rule_name", width: 170 },
        { title: "Agent Type", dataIndex: "agent_type_key", width: 140, render: (value) => value || "全部" },
        { title: "资源类型", dataIndex: "resource_type", width: 100, render: (value) => <Tag>{value}</Tag> },
        { title: "路径模式", dataIndex: "path_pattern", ellipsis: true },
        { title: "可信来源", dataIndex: "source_trust", width: 120, render: (value) => value || "-" },
        { title: "决策", dataIndex: "decision", width: 100, render: verdictTag },
        { title: "Install", dataIndex: "install_action", width: 90, render: actionText },
        { title: "File", dataIndex: "file_action", width: 110, render: actionText },
        { title: "Runtime", dataIndex: "runtime_action", width: 110, render: actionText },
        {
            title: "启用",
            dataIndex: "enabled",
            width: 80,
            render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePreScanRule(record, checked)}/>,
        },
        {
            title: "操作",
            fixed: "right",
            width: 160,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Pre-scan 规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePreScanRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const draftPreScanRuleColumns: ColumnsType<DraftPreScanRule> = [
        { title: "优先级", dataIndex: "priority", width: 80 },
        { title: "规则名称", dataIndex: "rule_name", width: 170 },
        { title: "资源类型", dataIndex: "resource_type", width: 100, render: (value) => <Tag>{value}</Tag> },
        { title: "路径模式", dataIndex: "path_pattern", ellipsis: true, render: (value) => value || "不限" },
        { title: "决策", dataIndex: "decision", width: 100, render: verdictTag },
        { title: "Install", dataIndex: "install_action", width: 90, render: actionText },
        { title: "File", dataIndex: "file_action", width: 110, render: actionText },
        { title: "Runtime", dataIndex: "runtime_action", width: 110, render: actionText },
        { title: "状态", dataIndex: "enabled", width: 80, render: enabledTag },
        {
            title: "操作",
            fixed: "right",
            width: 160,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanRuleModal(record)}>编辑</Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => removeDraftPreScanRule(record)}>删除</Button>
        </Space>),
        },
    ];
    const postScanProfileColumns: ColumnsType<GovernancePostScanProfile> = [
        { title: "方案 Key", dataIndex: "profile_key", width: 170 },
        { title: "方案名称", dataIndex: "name", width: 180 },
        { title: "默认", dataIndex: "is_default", width: 80, render: (value) => (value ? <Tag color="blue">默认</Tag> : "-") },
        { title: "规则数", dataIndex: "rule_count", width: 90 },
        { title: "引用规则", dataIndex: "resource_rule_count", width: 100 },
        { title: "描述", dataIndex: "description", ellipsis: true },
        {
            title: "启用",
            dataIndex: "enabled",
            width: 90,
            render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePostScanProfile(record, checked)}/>,
        },
        {
            title: "操作",
            fixed: "right",
            width: 170,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanProfileModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Post-scan 方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePostScanProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={record.is_default}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const postScanRuleColumns: ColumnsType<GovernancePostScanRule> = [
        { title: "优先级", dataIndex: "priority", width: 80 },
        { title: "规则名称", dataIndex: "rule_name", width: 170 },
        { title: "资源类型", dataIndex: "resource_type", width: 100, render: (value) => <Tag>{value}</Tag> },
        { title: "严重级别", dataIndex: "severity", width: 110 },
        { title: "风险等级", dataIndex: "risk_level", width: 110 },
        { title: "恶意", dataIndex: "malicious", width: 80, render: (value) => (value ? <Tag color="red">是</Tag> : "否") },
        { title: "Finding Category", dataIndex: "finding_category", width: 150, render: (value) => value || "-" },
        { title: "Scanner", dataIndex: "scanner", width: 130, render: (value) => value || "-" },
        { title: "决策", dataIndex: "decision", width: 100, render: verdictTag },
        { title: "Install", dataIndex: "install_action", width: 90, render: actionText },
        { title: "File", dataIndex: "file_action", width: 110, render: actionText },
        { title: "Runtime", dataIndex: "runtime_action", width: 110, render: actionText },
        {
            title: "启用",
            dataIndex: "enabled",
            width: 80,
            render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePostScanRule(record, checked)}/>,
        },
        {
            title: "操作",
            fixed: "right",
            width: 160,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Post-scan 规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePostScanRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>),
        },
    ];
    const draftPostScanRuleColumns: ColumnsType<DraftPostScanRule> = [
        { title: "优先级", dataIndex: "priority", width: 80 },
        { title: "规则名称", dataIndex: "rule_name", width: 170 },
        { title: "资源类型", dataIndex: "resource_type", width: 100, render: (value) => <Tag>{value}</Tag> },
        { title: "严重级别", dataIndex: "severity", width: 110 },
        { title: "风险等级", dataIndex: "risk_level", width: 110 },
        { title: "恶意", dataIndex: "malicious", width: 80, render: (value) => (value ? <Tag color="red">是</Tag> : "否") },
        { title: "决策", dataIndex: "decision", width: 100, render: verdictTag },
        { title: "Install", dataIndex: "install_action", width: 90, render: actionText },
        { title: "File", dataIndex: "file_action", width: 110, render: actionText },
        { title: "Runtime", dataIndex: "runtime_action", width: 110, render: actionText },
        { title: "状态", dataIndex: "enabled", width: 80, render: enabledTag },
        {
            title: "操作",
            fixed: "right",
            width: 160,
            render: (_, record) => (<Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanRuleModal(record)}>编辑</Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => removeDraftPostScanRule(record)}>删除</Button>
        </Space>),
        },
    ];
    const model = { preScan: { kind: "Pre-scan", keyword: preScanKeyword, setKeyword: setPreScanKeyword, enabled: preScanEnabled, setEnabled: setPreScanEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyPreScanFilter, resetFilter: resetPreScanFilter, openCreate: () => openPreScanProfileModal(), reload: loadDecisionProfiles, loading: decisionLoading, columns: preScanProfileColumns, page: preScanProfilePage, query: preScanQuery, setQuery: setPreScanQuery, pagination: tablePagination }, postScan: { kind: "Post-scan", keyword: postScanKeyword, setKeyword: setPostScanKeyword, enabled: postScanEnabled, setEnabled: setPostScanEnabled, enabledOptions: ENABLED_OPTIONS, applyFilter: applyPostScanFilter, resetFilter: resetPostScanFilter, openCreate: () => openPostScanProfileModal(), reload: loadDecisionProfiles, loading: decisionLoading, columns: postScanProfileColumns, page: postScanProfilePage, query: postScanQuery, setQuery: setPostScanQuery, pagination: tablePagination } };
    return <section className="governance-subpage"><div className="governance-subpage-heading"><Typography.Title level={3}>决策与动作</Typography.Title></div><Space direction="vertical" size={16} className="governance-full-width">
    <Alert type="info" showIcon message="资源发现规则会绑定一套 Pre-scan 方案和一套 Post-scan 方案；新增资源规则时默认使用系统默认方案，也可以按业务选择其他方案。"/>
    <ProfileSection title="资源 Pre-scan 方案" side={model.preScan}/>
    <ProfileSection title="资源 Post-scan 方案" side={model.postScan}/>
  </Space><Modal title={editingPreScanProfile ? "编辑 Pre-scan 方案" : "新增 Pre-scan 方案"} open={preScanProfileModalOpen} onCancel={() => setPreScanProfileModalOpen(false)} onOk={() => void savePreScanProfile()} destroyOnHidden width={1080}>
        <Space direction="vertical" size={16} className="governance-full-width">
          <Form form={preScanProfileForm} layout="vertical">
            <Form.Item name="profile_key" label="方案 Key" rules={[{ required: true }]}><Input disabled={!!editingPreScanProfile}/></Form.Item>
            <Form.Item name="name" label="方案名称" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="description" label="描述"><Input.TextArea rows={2}/></Form.Item>
            <Space size={24}>
              <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
              <Form.Item name="is_default" label="默认方案" valuePropName="checked"><Switch /></Form.Item>
            </Space>
          </Form>
          <Alert type="info" showIcon message={editingPreScanProfile ? "下方规则会直接保存到当前方案，按优先级从小到大匹配。" : "新建方案时，下方规则先作为草稿保存，点击确定后会和方案一起创建。"}/>
          <Space className="governance-toolbar" wrap>
            <Text strong>Pre-scan 规则</Text>
            {editingPreScanProfile ? (<>
                <Input.Search allowClear placeholder="搜索规则名 / 路径 / 可信来源" value={preScanRuleKeyword} onChange={(event) => setPreScanRuleKeyword(event.target.value)} onSearch={applyPreScanRuleFilter} className="governance-search"/>
                <Select value={preScanRuleEnabled} onChange={setPreScanRuleEnabled} options={[...ENABLED_OPTIONS]} className="governance-filter-select"/>
                <Button icon={<SearchOutlined />} onClick={applyPreScanRuleFilter}>查询</Button>
                <Button onClick={resetPreScanRuleFilter}>重置</Button>
              </>) : null}
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openPreScanRuleModal()}>新增规则</Button>
          </Space>
          {editingPreScanProfile ? (<Table rowKey="id" size="small" columns={preScanRuleColumns} dataSource={preScanRulePage.items} scroll={{ x: 1280 }} pagination={tablePagination(preScanRulePage, preScanRuleQuery)} onChange={(pagination) => setPreScanRuleQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}/>) : (<Table rowKey="draft_id" size="small" columns={draftPreScanRuleColumns} dataSource={draftPreScanRules} scroll={{ x: 1280 }} pagination={{ pageSize: 6, showSizeChanger: true }}/>)}
        </Space>
      </Modal>
    <Modal title={editingPreScanRule || editingDraftPreScanRuleID ? "编辑 Pre-scan 规则" : "新增 Pre-scan 规则"} open={preScanRuleModalOpen} onCancel={() => setPreScanRuleModalOpen(false)} onOk={() => void savePreScanRule()} destroyOnHidden width={760}>
        <Form form={preScanRuleForm} layout="vertical">
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} className="governance-full-width"/></Form.Item>
          <Form.Item name="agent_type_id" label="Agent Type 条件"><Select allowClear options={agentTypeOptions} placeholder="留空表示全部 Agent Type"/></Form.Item>
          <Form.Item name="resource_type" label="资源类型"><Select options={DECISION_RESOURCE_TYPES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="path_pattern" label="路径模式"><Input placeholder="可留空，表示不限路径"/></Form.Item>
          <Form.Item name="source_trust" label="来源可信度"><Input placeholder="trusted / unknown / external，可留空"/></Form.Item>
          <Form.Item name="decision" label="Pre-scan 决策"><Select options={PRE_SCAN_DECISIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="install_action" label="Install"><Select options={INSTALL_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="file_action" label="File"><Select options={FILE_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="runtime_action" label="Runtime"><Select options={RUNTIME_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>
    <Modal title={editingPostScanProfile ? "编辑 Post-scan 方案" : "新增 Post-scan 方案"} open={postScanProfileModalOpen} onCancel={() => setPostScanProfileModalOpen(false)} onOk={() => void savePostScanProfile()} destroyOnHidden width={1080}>
        <Space direction="vertical" size={16} className="governance-full-width">
          <Form form={postScanProfileForm} layout="vertical">
            <Form.Item name="profile_key" label="方案 Key" rules={[{ required: true }]}><Input disabled={!!editingPostScanProfile}/></Form.Item>
            <Form.Item name="name" label="方案名称" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="description" label="描述"><Input.TextArea rows={2}/></Form.Item>
            <Space size={24}>
              <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
              <Form.Item name="is_default" label="默认方案" valuePropName="checked"><Switch /></Form.Item>
            </Space>
          </Form>
          <Alert type="info" showIcon message={editingPostScanProfile ? "下方规则会直接保存到当前方案，扫描完成后按优先级从小到大匹配。" : "新建方案时，下方规则先作为草稿保存，点击确定后会和方案一起创建。"}/>
          <Space className="governance-toolbar" wrap>
            <Text strong>Post-scan 规则</Text>
            {editingPostScanProfile ? (<>
                <Input.Search allowClear placeholder="搜索规则名 / Category / Scanner" value={postScanRuleKeyword} onChange={(event) => setPostScanRuleKeyword(event.target.value)} onSearch={applyPostScanRuleFilter} className="governance-search"/>
                <Select value={postScanRuleEnabled} onChange={setPostScanRuleEnabled} options={[...ENABLED_OPTIONS]} className="governance-filter-select"/>
                <Button icon={<SearchOutlined />} onClick={applyPostScanRuleFilter}>查询</Button>
                <Button onClick={resetPostScanRuleFilter}>重置</Button>
              </>) : null}
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openPostScanRuleModal()}>新增规则</Button>
          </Space>
          {editingPostScanProfile ? (<Table rowKey="id" size="small" columns={postScanRuleColumns} dataSource={postScanRulePage.items} scroll={{ x: 1420 }} pagination={tablePagination(postScanRulePage, postScanRuleQuery)} onChange={(pagination) => setPostScanRuleQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}/>) : (<Table rowKey="draft_id" size="small" columns={draftPostScanRuleColumns} dataSource={draftPostScanRules} scroll={{ x: 1420 }} pagination={{ pageSize: 6, showSizeChanger: true }}/>)}
        </Space>
      </Modal>
    <Modal title={editingPostScanRule || editingDraftPostScanRuleID ? "编辑 Post-scan 规则" : "新增 Post-scan 规则"} open={postScanRuleModalOpen} onCancel={() => setPostScanRuleModalOpen(false)} onOk={() => void savePostScanRule()} destroyOnHidden width={760}>
        <Form form={postScanRuleForm} layout="vertical">
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} className="governance-full-width"/></Form.Item>
          <Form.Item name="resource_type" label="资源类型"><Select options={DECISION_RESOURCE_TYPES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="severity" label="严重级别"><Select options={SEVERITIES.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="risk_level" label="风险等级"><Select options={RISK_LEVELS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="malicious" label="恶意资源" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="finding_category" label="Finding Category"><Input placeholder="可留空，表示不限分类"/></Form.Item>
          <Form.Item name="scanner" label="Scanner"><Input placeholder="可留空，表示不限扫描器"/></Form.Item>
          <Form.Item name="decision" label="Post-scan 决策"><Select options={POST_SCAN_DECISIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="install_action" label="Install"><Select options={INSTALL_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="file_action" label="File"><Select options={FILE_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="runtime_action" label="Runtime"><Select options={RUNTIME_ACTIONS.map((value) => ({ value, label: value }))}/></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal></section>;
}
