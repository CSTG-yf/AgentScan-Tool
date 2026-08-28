import { useCallback, useEffect, useMemo, useState } from "react";
import {
  DeleteOutlined,
  EditOutlined,
  EyeOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
} from "@ant-design/icons";
import {
  Alert,
  Button,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  List,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  message,
} from "antd";
import type { ColumnsType, TablePaginationConfig } from "antd/es/table";
import {
  createGovernanceAgentType,
  createGovernanceDiscoveryCondition,
  createGovernanceDiscoveryRule,
  createGovernanceResourceAction,
  createGovernanceResourceRule,
  createGovernanceScanProfile,
  deleteGovernanceAgentType,
  deleteGovernanceDiscoveryCondition,
  deleteGovernanceDiscoveryRule,
  deleteGovernanceResourceAction,
  deleteGovernanceResourceRule,
  deleteGovernanceScanProfile,
  evaluateGovernanceAdmission,
  evaluateGovernanceRisk,
  getGovernanceAdmissionMatrix,
  getGovernanceAgentTypes,
  getGovernanceDiscoveryRule,
  getGovernanceDiscoveryRules,
  getGovernanceResourceActions,
  getGovernanceResourceRules,
  getGovernanceRiskModel,
  getGovernanceScanCapabilities,
  getGovernanceScanProfiles,
  previewGovernanceResourceRule,
  replaceGovernanceScanProfileCapabilities,
  updateGovernanceAgentType,
  updateGovernanceDiscoveryCondition,
  updateGovernanceDiscoveryRule,
  updateGovernanceResourceAction,
  updateGovernanceResourceRule,
  updateGovernanceScanProfile,
} from "../bridge";
import type {
  GovernanceAdmissionEvaluateResponse,
  GovernanceAdmissionMatrixItem,
  GovernanceAgentType,
  GovernanceAgentTypeInput,
  GovernanceDiscoveryCondition,
  GovernanceDiscoveryConditionInput,
  GovernanceDiscoveryRule,
  GovernanceDiscoveryRuleInput,
  GovernancePage,
  GovernanceResourceAction,
  GovernanceResourceActionInput,
  GovernanceResourceRule,
  GovernanceResourceRuleInput,
  GovernanceRiskEvaluateResponse,
  GovernanceRiskModelResponse,
  GovernanceScanCapability,
  GovernanceScanProfile,
  GovernanceScanProfileInput,
} from "../types";

const { Text, Title } = Typography;

const RESOURCE_TYPES = ["skill", "mcp", "plugin", "config", "prompt", "credential", "environment"];
const ENUMERATION_MODES = ["exact", "children", "glob", "recursive"];
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
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
  if (value === "enabled") return true;
  if (value === "disabled") return false;
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

export function AgentGovernancePage() {
  const [referenceLoading, setReferenceLoading] = useState(false);
  const [agentLoading, setAgentLoading] = useState(false);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [resourceLoading, setResourceLoading] = useState(false);

  const [agentTypeCatalog, setAgentTypeCatalog] = useState<GovernanceAgentType[]>([]);
  const [agentPage, setAgentPage] = useState<GovernancePage<GovernanceAgentType>>(emptyPage());
  const [discoveryPage, setDiscoveryPage] = useState<GovernancePage<GovernanceDiscoveryRule>>(emptyPage());
  const [resourcePage, setResourcePage] = useState<GovernancePage<GovernanceResourceRule>>(emptyPage());
  const [scanProfiles, setScanProfiles] = useState<GovernanceScanProfile[]>([]);
  const [scanCapabilities, setScanCapabilities] = useState<GovernanceScanCapability[]>([]);
  const [resourceActions, setResourceActions] = useState<GovernanceResourceAction[]>([]);
  const [admissionMatrix, setAdmissionMatrix] = useState<GovernanceAdmissionMatrixItem[]>([]);
  const [riskModel, setRiskModel] = useState<GovernanceRiskModelResponse>();

  const [agentQuery, setAgentQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 10 });
  const [agentKeyword, setAgentKeyword] = useState("");
  const [agentEnabled, setAgentEnabled] = useState<EnabledFilter>("all");

  const [discoveryQuery, setDiscoveryQuery] = useState<PageQueryState>({ keyword: "", enabled: "enabled", page: 1, pageSize: 10 });
  const [discoveryKeyword, setDiscoveryKeyword] = useState("");
  const [discoveryEnabled, setDiscoveryEnabled] = useState<EnabledFilter>("enabled");

  const [selectedResourceAgentTypeID, setSelectedResourceAgentTypeID] = useState<number | undefined>();
  const [resourceQuery, setResourceQuery] = useState<PageQueryState>({ keyword: "", enabled: "enabled", page: 1, pageSize: 10 });
  const [resourceKeyword, setResourceKeyword] = useState("");
  const [resourceEnabled, setResourceEnabled] = useState<EnabledFilter>("enabled");

  const [agentForm] = Form.useForm<GovernanceAgentTypeInput>();
  const [agentModalOpen, setAgentModalOpen] = useState(false);
  const [editingAgentType, setEditingAgentType] = useState<GovernanceAgentType>();

  const [discoveryForm] = Form.useForm<GovernanceDiscoveryRuleInput>();
  const [discoveryModalOpen, setDiscoveryModalOpen] = useState(false);
  const [editingDiscoveryRule, setEditingDiscoveryRule] = useState<GovernanceDiscoveryRule>();
  const [discoveryDetailOpen, setDiscoveryDetailOpen] = useState(false);
  const [discoveryDetail, setDiscoveryDetail] = useState<GovernanceDiscoveryRule>();
  const [conditionForm] = Form.useForm<GovernanceDiscoveryConditionInput>();
  const [conditionModalOpen, setConditionModalOpen] = useState(false);
  const [editingCondition, setEditingCondition] = useState<GovernanceDiscoveryCondition>();

  const [resourceRuleForm] = Form.useForm<GovernanceResourceRuleInput>();
  const [resourceRuleModalOpen, setResourceRuleModalOpen] = useState(false);
  const [editingResourceRule, setEditingResourceRule] = useState<GovernanceResourceRule>();
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewRows, setPreviewRows] = useState<Array<{ name: string; target: string; exists: boolean; type: string }>>([]);

  const [profileForm] = Form.useForm<GovernanceScanProfileInput>();
  const [profileModalOpen, setProfileModalOpen] = useState(false);
  const [editingProfile, setEditingProfile] = useState<GovernanceScanProfile>();
  const [profileCapabilityIDs, setProfileCapabilityIDs] = useState<number[]>([]);

  const [actionForm] = Form.useForm<GovernanceResourceActionInput>();
  const [actionModalOpen, setActionModalOpen] = useState(false);
  const [editingAction, setEditingAction] = useState<GovernanceResourceAction>();

  const [admissionForm] = Form.useForm();
  const [admissionResult, setAdmissionResult] = useState<GovernanceAdmissionEvaluateResponse>();
  const [riskForm] = Form.useForm();
  const [riskResult, setRiskResult] = useState<GovernanceRiskEvaluateResponse>();

  const loading = referenceLoading || agentLoading || discoveryLoading || resourceLoading;

  const agentTypeOptions = useMemo(
    () => agentTypeCatalog.map((item) => ({ label: `${item.name} (${item.type_key})`, value: item.id })),
    [agentTypeCatalog],
  );
  const profileOptions = useMemo(
    () => scanProfiles.map((item) => ({ label: `${item.name} / ${item.resource_type}`, value: item.id })),
    [scanProfiles],
  );
  const capabilityOptions = useMemo(
    () => scanCapabilities.map((item) => ({ label: `${item.name} (${item.capability_key})`, value: item.id })),
    [scanCapabilities],
  );
  const selectedResourceAgentType = useMemo(
    () => agentTypeCatalog.find((item) => item.id === selectedResourceAgentTypeID),
    [agentTypeCatalog, selectedResourceAgentTypeID],
  );

  const loadAgentTypes = useCallback(async () => {
    setAgentLoading(true);
    try {
      setAgentPage(await getGovernanceAgentTypes(queryFromState(agentQuery)));
    } catch (error) {
      message.error(`读取 Agent Type 失败：${String(error)}`);
    } finally {
      setAgentLoading(false);
    }
  }, [agentQuery]);

  const loadDiscoveryRules = useCallback(async () => {
    setDiscoveryLoading(true);
    try {
      setDiscoveryPage(await getGovernanceDiscoveryRules(queryFromState(discoveryQuery)));
    } catch (error) {
      message.error(`读取 Agent 发现规则失败：${String(error)}`);
    } finally {
      setDiscoveryLoading(false);
    }
  }, [discoveryQuery]);

  const loadResourceRules = useCallback(async () => {
    setResourceLoading(true);
    try {
      setResourcePage(await getGovernanceResourceRules({ ...queryFromState(resourceQuery), agentTypeId: selectedResourceAgentTypeID }));
    } catch (error) {
      message.error(`读取资源发现规则失败：${String(error)}`);
    } finally {
      setResourceLoading(false);
    }
  }, [resourceQuery, selectedResourceAgentTypeID]);

  const loadReferences = useCallback(async () => {
    setReferenceLoading(true);
    try {
      const [agentCatalog, profilePage, capabilityResp, actionPage, matrix, risk] = await Promise.all([
        getGovernanceAgentTypes({ page: 1, pageSize: 500 }),
        getGovernanceScanProfiles({ page: 1, pageSize: 500 }),
        getGovernanceScanCapabilities(),
        getGovernanceResourceActions({ page: 1, pageSize: 200 }),
        getGovernanceAdmissionMatrix(),
        getGovernanceRiskModel(),
      ]);
      setAgentTypeCatalog(agentCatalog.items ?? []);
      setScanProfiles(profilePage.items ?? []);
      setScanCapabilities(capabilityResp.items ?? []);
      setResourceActions(actionPage.items ?? []);
      setAdmissionMatrix(matrix.items ?? []);
      setRiskModel(risk);
    } catch (error) {
      message.error(`读取 Agent 治理配置失败：${String(error)}`);
    } finally {
      setReferenceLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadReferences(), loadAgentTypes(), loadDiscoveryRules(), loadResourceRules()]);
  }, [loadReferences, loadAgentTypes, loadDiscoveryRules, loadResourceRules]);

  useEffect(() => {
    void loadReferences();
  }, [loadReferences]);

  useEffect(() => {
    void loadAgentTypes();
  }, [loadAgentTypes]);

  useEffect(() => {
    void loadDiscoveryRules();
  }, [loadDiscoveryRules]);

  useEffect(() => {
    void loadResourceRules();
  }, [loadResourceRules]);

  const applyAgentFilter = () => {
    setAgentQuery((prev) => ({ ...prev, page: 1, keyword: agentKeyword.trim(), enabled: agentEnabled }));
  };

  const resetAgentFilter = () => {
    setAgentKeyword("");
    setAgentEnabled("all");
    setAgentQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "all" }));
  };

  const applyDiscoveryFilter = () => {
    setDiscoveryQuery((prev) => ({ ...prev, page: 1, keyword: discoveryKeyword.trim(), enabled: discoveryEnabled }));
  };

  const resetDiscoveryFilter = () => {
    setDiscoveryKeyword("");
    setDiscoveryEnabled("enabled");
    setDiscoveryQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "enabled" }));
  };

  const applyResourceFilter = () => {
    setResourceQuery((prev) => ({ ...prev, page: 1, keyword: resourceKeyword.trim(), enabled: resourceEnabled }));
  };

  const resetResourceFilter = () => {
    setResourceKeyword("");
    setResourceEnabled("enabled");
    setResourceQuery((prev) => ({ ...prev, page: 1, keyword: "", enabled: "enabled" }));
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
    } else {
      await createGovernanceAgentType({ ...values, enabled: values.enabled ?? true });
      message.success("Agent Type 已创建");
    }
    setAgentModalOpen(false);
    await Promise.all([loadReferences(), loadAgentTypes(), loadDiscoveryRules(), loadResourceRules()]);
  };

  const removeAgentType = async (record: GovernanceAgentType) => {
    await deleteGovernanceAgentType(record.id);
    message.success("Agent Type 已删除");
    await Promise.all([loadReferences(), loadAgentTypes(), loadDiscoveryRules(), loadResourceRules()]);
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
    } else {
      await createGovernanceDiscoveryRule({ ...values, enabled: values.enabled ?? true });
      message.success("发现规则已创建");
    }
    setDiscoveryModalOpen(false);
    await Promise.all([loadReferences(), loadDiscoveryRules(), loadAgentTypes()]);
  };

  const removeDiscoveryRule = async (record: GovernanceDiscoveryRule) => {
    await deleteGovernanceDiscoveryRule(record.id);
    message.success("发现规则已删除");
    if (discoveryDetail?.id === record.id) {
      setDiscoveryDetailOpen(false);
      setDiscoveryDetail(undefined);
    }
    await Promise.all([loadReferences(), loadDiscoveryRules(), loadAgentTypes()]);
  };

  const viewDiscoveryRule = async (record: GovernanceDiscoveryRule) => {
    try {
      const detail = await getGovernanceDiscoveryRule(record.id);
      setDiscoveryDetail(detail);
      setDiscoveryDetailOpen(true);
    } catch (error) {
      message.error(`读取规则详情失败：${String(error)}`);
    }
  };

  const openConditionModal = (condition?: GovernanceDiscoveryCondition) => {
    setEditingCondition(condition);
    conditionForm.setFieldsValue(condition ?? { enabled: true, required: false, weight: 10 });
    setConditionModalOpen(true);
  };

  const saveCondition = async () => {
    if (!discoveryDetail) return;
    const values = await conditionForm.validateFields();
    if (editingCondition) {
      await updateGovernanceDiscoveryCondition(editingCondition.id, values);
      message.success("条件已更新");
    } else {
      await createGovernanceDiscoveryCondition(discoveryDetail.id, { ...values, enabled: values.enabled ?? true });
      message.success("条件已创建");
    }
    setConditionModalOpen(false);
    const detail = await getGovernanceDiscoveryRule(discoveryDetail.id);
    setDiscoveryDetail(detail);
    await Promise.all([loadDiscoveryRules(), loadReferences()]);
  };

  const removeCondition = async (record: GovernanceDiscoveryCondition) => {
    if (!discoveryDetail) return;
    await deleteGovernanceDiscoveryCondition(record.id);
    message.success("条件已删除");
    const detail = await getGovernanceDiscoveryRule(discoveryDetail.id);
    setDiscoveryDetail(detail);
    await Promise.all([loadDiscoveryRules(), loadReferences()]);
  };

  const openResourceRuleModal = (record?: GovernanceResourceRule) => {
    const fallbackAgentTypeID = selectedResourceAgentTypeID ?? agentTypeCatalog[0]?.id;
    setEditingResourceRule(record);
    resourceRuleForm.setFieldsValue(record ?? { agent_type_id: fallbackAgentTypeID, enabled: true, priority: 100, enumeration_mode: "children", resource_type: "skill" });
    setResourceRuleModalOpen(true);
  };

  const saveResourceRule = async () => {
    const values = await resourceRuleForm.validateFields();
    const body = { ...values, enabled: values.enabled ?? true, priority: values.priority ?? 100 };
    if (editingResourceRule) {
      await updateGovernanceResourceRule(editingResourceRule.id, body);
      message.success("资源发现规则已更新");
    } else {
      await createGovernanceResourceRule(body);
      message.success("资源发现规则已创建");
    }
    setResourceRuleModalOpen(false);
    await Promise.all([loadReferences(), loadResourceRules(), loadAgentTypes()]);
  };

  const removeResourceRule = async (record: GovernanceResourceRule) => {
    await deleteGovernanceResourceRule(record.id);
    message.success("资源发现规则已删除");
    await Promise.all([loadReferences(), loadResourceRules(), loadAgentTypes()]);
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
    } catch (error) {
      message.error(`预览失败：${String(error)}`);
    }
  };

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
    await replaceGovernanceScanProfileCapabilities(
      saved.id,
      profileCapabilityIDs.map((id, index) => ({ capability_id: id, priority: (index + 1) * 10, enabled: true, config_json: "{}" })),
    );
    message.success(editingProfile ? "扫描方案已更新" : "扫描方案已创建");
    setProfileModalOpen(false);
    await Promise.all([loadReferences(), loadResourceRules()]);
  };

  const openActionModal = (record?: GovernanceResourceAction) => {
    setEditingAction(record);
    actionForm.setFieldsValue(record ?? { actions: { install: "block", file: "none", runtime: "allow" } });
    setActionModalOpen(true);
  };

  const saveAction = async () => {
    const values = await actionForm.validateFields();
    if (editingAction) {
      await updateGovernanceResourceAction(editingAction.id, values);
      message.success("目标动作已更新");
    } else {
      await createGovernanceResourceAction(values);
      message.success("目标动作已创建");
    }
    setActionModalOpen(false);
    await loadReferences();
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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openAgentModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Agent Type？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeAgentType(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={agentLoading}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => void viewDiscoveryRule(record)}>详情</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openDiscoveryModal(record)}>编辑</Button>
          <Popconfirm title="删除该发现规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeDiscoveryRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={discoveryLoading}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const resourceRuleColumns: ColumnsType<GovernanceResourceRule> = [
    { title: "Agent Type", dataIndex: "agent_type_key", width: 150 },
    { title: "名称", dataIndex: "name", width: 180 },
    { title: "资源类型", dataIndex: "resource_type", width: 110, render: (value) => <Tag>{value}</Tag> },
    { title: "路径模式", dataIndex: "path_pattern", ellipsis: true },
    { title: "枚举", dataIndex: "enumeration_mode", width: 100 },
    { title: "扫描方案", dataIndex: "scan_profile_name", width: 160 },
    { title: "命中资源", dataIndex: "resource_count", width: 100 },
    { title: "状态", dataIndex: "enabled", width: 90, render: enabledTag },
    {
      title: "操作",
      fixed: "right",
      width: 240,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EyeOutlined />} onClick={() => void previewRule(record)}>预览</Button>
          <Button size="small" icon={<EditOutlined />} onClick={() => openResourceRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该资源规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeResourceRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={resourceLoading}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openProfileModal(record)}>编辑</Button>
          <Popconfirm title="停用该扫描方案？" okText="停用" okButtonProps={{ danger: true }} onConfirm={() => deleteGovernanceScanProfile(record.id).then(() => loadReferences())}>
            <Button size="small" danger icon={<DeleteOutlined />}>停用</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const actionColumns: ColumnsType<GovernanceResourceAction> = [
    { title: "目标类型", dataIndex: "target_type", width: 120 },
    { title: "目标名称", dataIndex: "target_name", width: 180 },
    { title: "Connector", dataIndex: "connector", width: 120, render: (value) => value || "全局" },
    { title: "Install", render: (_, record) => actionText(record.actions.install), width: 100 },
    { title: "File", render: (_, record) => actionText(record.actions.file), width: 110 },
    { title: "Runtime", render: (_, record) => actionText(record.actions.runtime), width: 110 },
    { title: "原因", dataIndex: "reason", ellipsis: true },
    {
      title: "操作",
      width: 170,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openActionModal(record)}>编辑</Button>
          <Popconfirm title="删除该目标动作？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => deleteGovernanceResourceAction(record.id).then(() => loadReferences())}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openConditionModal(record)}>编辑</Button>
          <Popconfirm title="删除该条件？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeCondition(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const matrixColumns: ColumnsType<GovernanceAdmissionMatrixItem> = [
    { title: "阶段", dataIndex: "phase", width: 110 },
    { title: "资源类型", dataIndex: "resource_type", width: 110 },
    { title: "严重级别", dataIndex: "severity", width: 110 },
    { title: "决策", dataIndex: "verdict", width: 110, render: verdictTag },
    { title: "Install", dataIndex: "install_action", width: 100 },
    { title: "File", dataIndex: "file_action", width: 110 },
    { title: "Runtime", dataIndex: "runtime_action", width: 110 },
    { title: "来源", dataIndex: "source" },
  ];

  const tabs = [
    {
      key: "types",
      label: "Agent 类型管理",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Space className="governance-toolbar" wrap>
            <Input.Search
              allowClear
              placeholder="搜索 Type Key / 名称 / 厂商"
              value={agentKeyword}
              onChange={(event) => setAgentKeyword(event.target.value)}
              onSearch={applyAgentFilter}
              style={{ width: 260 }}
            />
            <Select value={agentEnabled} onChange={setAgentEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
            <Button icon={<SearchOutlined />} onClick={applyAgentFilter}>查询</Button>
            <Button onClick={resetAgentFilter}>重置</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openAgentModal()}>新增 Agent Type</Button>
            <Button icon={<ReloadOutlined />} onClick={() => void loadAgentTypes()} />
          </Space>
          <Table
            rowKey="id"
            loading={agentLoading}
            columns={agentColumns}
            dataSource={agentPage.items}
            scroll={{ x: 1120 }}
            pagination={tablePagination(agentPage, agentQuery)}
            onChange={(pagination) => setAgentQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
          />
        </Space>
      ),
    },
    {
      key: "discovery",
      label: "Agent 发现规则",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Space className="governance-toolbar" wrap>
            <Input.Search
              allowClear
              placeholder="搜索规则名 / Agent Type"
              value={discoveryKeyword}
              onChange={(event) => setDiscoveryKeyword(event.target.value)}
              onSearch={applyDiscoveryFilter}
              style={{ width: 260 }}
            />
            <Select value={discoveryEnabled} onChange={setDiscoveryEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
            <Button icon={<SearchOutlined />} onClick={applyDiscoveryFilter}>查询</Button>
            <Button onClick={resetDiscoveryFilter}>重置</Button>
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openDiscoveryModal()}>新增发现规则</Button>
            <Button icon={<ReloadOutlined />} onClick={() => void loadDiscoveryRules()} />
          </Space>
          <Table
            rowKey="id"
            loading={discoveryLoading}
            columns={discoveryColumns}
            dataSource={discoveryPage.items}
            scroll={{ x: 900 }}
            pagination={tablePagination(discoveryPage, discoveryQuery)}
            onChange={(pagination) => setDiscoveryQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
          />
        </Space>
      ),
    },
    {
      key: "resources",
      label: "资源发现规则",
      children: (
        <div className="governance-resource-layout">
          <aside className="governance-agent-type-panel">
            <div className="governance-agent-type-heading">
              <Text strong>Agent Type</Text>
              <Text type="secondary">{agentTypeCatalog.length}</Text>
            </div>
            <button
              type="button"
              className={`governance-agent-type-item ${selectedResourceAgentTypeID === undefined ? "active" : ""}`}
              onClick={() => {
                setSelectedResourceAgentTypeID(undefined);
                setResourceQuery((prev) => ({ ...prev, page: 1 }));
              }}
            >
              <span>全部 Agent Type</span>
              <Tag>{agentTypeCatalog.reduce((sum, item) => sum + item.resource_rule_count, 0)}</Tag>
            </button>
            <List
              dataSource={agentTypeCatalog}
              renderItem={(item) => (
                <List.Item>
                  <button
                    type="button"
                    className={`governance-agent-type-item ${selectedResourceAgentTypeID === item.id ? "active" : ""}`}
                    onClick={() => {
                      setSelectedResourceAgentTypeID(item.id);
                      setResourceQuery((prev) => ({ ...prev, page: 1 }));
                    }}
                  >
                    <span>
                      <strong>{item.name}</strong>
                      <em>{item.type_key}</em>
                    </span>
                    <Tag color={item.enabled ? "blue" : "default"}>{item.resource_rule_count}</Tag>
                  </button>
                </List.Item>
              )}
            />
          </aside>
          <div className="governance-resource-main">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <Space className="governance-toolbar" wrap>
                <Button type="primary" icon={<PlusOutlined />} disabled={agentTypeCatalog.length === 0} onClick={() => openResourceRuleModal()}>
                  新增资源规则
                </Button>
                {selectedResourceAgentType ? <Tag color="blue">{selectedResourceAgentType.name}</Tag> : <Tag>全部 Agent Type</Tag>}
                <Input.Search
                  allowClear
                  placeholder="搜索规则名 / 路径模式"
                  value={resourceKeyword}
                  onChange={(event) => setResourceKeyword(event.target.value)}
                  onSearch={applyResourceFilter}
                  style={{ width: 260 }}
                />
                <Select value={resourceEnabled} onChange={setResourceEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyResourceFilter}>查询</Button>
                <Button onClick={resetResourceFilter}>重置</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadResourceRules()} />
              </Space>
              <Table
                rowKey="id"
                loading={resourceLoading}
                columns={resourceRuleColumns}
                dataSource={resourcePage.items}
                scroll={{ x: 1160 }}
                pagination={tablePagination(resourcePage, resourceQuery)}
                onChange={(pagination) => setResourceQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </div>
        </div>
      ),
    },
    {
      key: "profiles",
      label: "扫描方案",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openProfileModal()}>新增扫描方案</Button>
          <Table rowKey="id" loading={referenceLoading} columns={profileColumns} dataSource={scanProfiles} pagination={{ pageSize: 10 }} />
          <Table
            rowKey="id"
            size="small"
            columns={[
              { title: "Capability Key", dataIndex: "capability_key" },
              { title: "名称", dataIndex: "name" },
              { title: "Scanner", dataIndex: "scanner_name" },
              { title: "状态", dataIndex: "enabled", render: enabledTag },
            ]}
            dataSource={scanCapabilities}
            pagination={false}
          />
        </Space>
      ),
    },
    {
      key: "decisions",
      label: "决策与动作",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Alert
            type="info"
            showIcon
            message="这里管理的是静态资源扫描后的处置策略：全局矩阵解释默认规则，目标动作可以覆盖单个资源的 install/file/runtime 动作。"
          />
          <Button type="primary" icon={<PlusOutlined />} onClick={() => openActionModal()}>新增目标动作</Button>
          <Table rowKey="id" loading={referenceLoading} columns={actionColumns} dataSource={resourceActions} pagination={{ pageSize: 8 }} />
          <Table rowKey={(row) => `${row.phase}-${row.resource_type}-${row.severity}`} size="small" columns={matrixColumns} dataSource={admissionMatrix} pagination={{ pageSize: 8 }} />
          <Form form={admissionForm} layout="inline" onFinish={(values) => evaluateGovernanceAdmission({ resource_type: values.resource_type, target_name: values.target_name, scan_result: { max_severity: values.max_severity, total_findings: values.total_findings } }).then(setAdmissionResult)}>
            <Form.Item name="resource_type" rules={[{ required: true }]} initialValue="skill"><Select style={{ width: 130 }} options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
            <Form.Item name="target_name" rules={[{ required: true }]}><Input placeholder="目标名称" /></Form.Item>
            <Form.Item name="max_severity" initialValue="HIGH"><Select style={{ width: 130 }} options={SEVERITIES.map((value) => ({ value, label: value }))} /></Form.Item>
            <Form.Item name="total_findings" initialValue={1}><InputNumber min={0} /></Form.Item>
            <Button htmlType="submit">决策试算</Button>
          </Form>
          {admissionResult ? <Descriptions bordered size="small" column={5} items={[
            { key: "verdict", label: "决策", children: verdictTag(admissionResult.verdict) },
            { key: "install", label: "Install", children: admissionResult.install_action },
            { key: "file", label: "File", children: admissionResult.file_action },
            { key: "runtime", label: "Runtime", children: admissionResult.runtime_action },
            { key: "reason", label: "原因", children: admissionResult.reason },
          ]} /> : null}
        </Space>
      ),
    },
    {
      key: "risk",
      label: "风险解释",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Alert type="info" showIcon message="风险模型当前用于解释扫描 finding 如何映射为 clean/low/medium/high/critical，并支持基于 finding 的试算。" />
          <Table rowKey="severity" size="small" pagination={false} dataSource={riskModel?.severity_mapping ?? []} columns={[
            { title: "Severity", dataIndex: "severity" },
            { title: "Risk Level", dataIndex: "risk_level" },
          ]} />
          <Table rowKey={(row) => `${row.match_type}-${row.match_value}`} size="small" pagination={{ pageSize: 8 }} dataSource={riskModel?.malicious_indicators ?? []} columns={[
            { title: "匹配类型", dataIndex: "match_type" },
            { title: "匹配值", dataIndex: "match_value" },
          ]} />
          <Form form={riskForm} layout="inline" onFinish={(values) => evaluateGovernanceRisk({ resource_type: values.resource_type, findings: [{ rule_id: values.rule_id, category: values.category, severity: values.severity, title: values.title, tags: String(values.tags ?? "").split(",").map((item) => item.trim()).filter(Boolean) }] }).then(setRiskResult)}>
            <Form.Item name="resource_type" initialValue="prompt"><Select style={{ width: 130 }} options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
            <Form.Item name="severity" initialValue="HIGH"><Select style={{ width: 130 }} options={SEVERITIES.map((value) => ({ value, label: value }))} /></Form.Item>
            <Form.Item name="rule_id"><Input placeholder="Rule ID" /></Form.Item>
            <Form.Item name="category"><Input placeholder="Category" /></Form.Item>
            <Form.Item name="tags"><Input placeholder="tag1,tag2" /></Form.Item>
            <Form.Item name="title"><Input placeholder="Title" /></Form.Item>
            <Button htmlType="submit">风险试算</Button>
          </Form>
          {riskResult ? <Descriptions bordered size="small" column={4} items={[
            { key: "risk", label: "风险等级", children: <Tag color={riskResult.risk_level === "critical" || riskResult.risk_level === "high" ? "red" : "blue"}>{riskResult.risk_level}</Tag> },
            { key: "malicious", label: "恶意", children: riskResult.malicious ? <Tag color="red">是</Tag> : <Tag>否</Tag> },
            { key: "severity", label: "最高级别", children: riskResult.max_severity },
            { key: "count", label: "Finding", children: riskResult.finding_count },
          ]} /> : null}
        </Space>
      ),
    },
  ];

  return (
    <section className="workspace-page governance-page">
      <div className="page-heading">
        <div>
          <Text className="eyebrow">AGENT GOVERNANCE</Text>
          <Title level={2}>Agent 治理中心</Title>
          <Text type="secondary">统一维护 Agent 类型、发现规则、资源规则、扫描方案和动作策略。</Text>
        </div>
        <Button icon={<ReloadOutlined />} onClick={() => void refreshAll()} loading={loading}>刷新</Button>
      </div>
      <div className="metric-grid">
        <div className="metric-card"><SafetyCertificateOutlined /><Text>Agent Type</Text><Title level={3}>{agentPage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>发现规则</Text><Title level={3}>{discoveryPage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>资源规则</Text><Title level={3}>{resourcePage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>扫描方案</Text><Title level={3}>{scanProfiles.length}</Title></div>
      </div>
      <Tabs items={tabs} />

      <Modal title={editingAgentType ? "编辑 Agent Type" : "新增 Agent Type"} open={agentModalOpen} onCancel={() => setAgentModalOpen(false)} onOk={() => void saveAgentType()} destroyOnHidden>
        <Form form={agentForm} layout="vertical">
          <Form.Item name="type_key" label="Type Key" rules={[{ required: true }]}><Input disabled={!!editingAgentType} /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="vendor" label="厂商"><Input /></Form.Item>
          <Form.Item name="kind" label="类型"><Input /></Form.Item>
          <Form.Item name="runtime" label="运行时"><Input /></Form.Item>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={editingDiscoveryRule ? "编辑发现规则" : "新增发现规则"} open={discoveryModalOpen} onCancel={() => setDiscoveryModalOpen(false)} onOk={() => void saveDiscoveryRule()} destroyOnHidden>
        <Form form={discoveryForm} layout="vertical">
          <Form.Item name="agent_type_id" label="Agent Type" rules={[{ required: true }]}><Select options={agentTypeOptions} /></Form.Item>
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="threshold" label="命中阈值"><InputNumber min={1} max={100} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Drawer title="发现规则条件" open={discoveryDetailOpen} onClose={() => setDiscoveryDetailOpen(false)} width={920}>
        {discoveryDetail ? (
          <Space direction="vertical" size={16} style={{ width: "100%" }}>
            <Descriptions size="small" bordered column={3} items={[
              { key: "name", label: "规则", children: discoveryDetail.rule_name },
              { key: "type", label: "Agent Type", children: discoveryDetail.agent_type_key },
              { key: "threshold", label: "阈值", children: discoveryDetail.threshold },
            ]} />
            <Alert type="info" showIcon message="条件命中后按权重累加；required 条件必须命中；总分达到阈值后该规则才会命中。" />
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openConditionModal()}>新增条件</Button>
            <Table rowKey="id" columns={conditionColumns} dataSource={discoveryDetail.conditions ?? []} pagination={false} />
          </Space>
        ) : null}
      </Drawer>

      <Modal title={editingCondition ? "编辑发现条件" : "新增发现条件"} open={conditionModalOpen} onCancel={() => setConditionModalOpen(false)} onOk={() => void saveCondition()} destroyOnHidden>
        <Form form={conditionForm} layout="vertical">
          <Form.Item name="condition_type" label="条件类型" rules={[{ required: true }]}><Input placeholder="cli / directory / process" /></Form.Item>
          <Form.Item name="field" label="字段"><Input placeholder="name / path / command_line" /></Form.Item>
          <Form.Item name="operator" label="操作符" rules={[{ required: true }]}><Input placeholder="exists / contains" /></Form.Item>
          <Form.Item name="value" label="值" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="weight" label="权重"><InputNumber min={0} max={100} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="required" label="必需" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={editingResourceRule ? "编辑资源发现规则" : "新增资源发现规则"} open={resourceRuleModalOpen} onCancel={() => setResourceRuleModalOpen(false)} onOk={() => void saveResourceRule()} destroyOnHidden>
        <Form form={resourceRuleForm} layout="vertical">
          <Form.Item name="agent_type_id" label="Agent Type" rules={[{ required: true }]}><Select options={agentTypeOptions} /></Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}><Select options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="path_pattern" label="路径模式" rules={[{ required: true }]}><Input placeholder="${CONFIG_ROOT}/skills" /></Form.Item>
          <Form.Item name="enumeration_mode" label="枚举模式" rules={[{ required: true }]}><Select options={ENUMERATION_MODES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="scan_profile_id" label="扫描方案"><Select allowClear options={profileOptions} /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title="资源发现预览" open={previewOpen} onCancel={() => setPreviewOpen(false)} footer={null} width={900}>
        <Table rowKey="target" size="small" dataSource={previewRows} pagination={{ pageSize: 8 }} columns={[
          { title: "名称", dataIndex: "name", width: 180 },
          { title: "类型", dataIndex: "type", width: 100 },
          { title: "存在", dataIndex: "exists", width: 90, render: (value) => (value ? <Tag color="success">是</Tag> : <Tag>否</Tag>) },
          { title: "路径", dataIndex: "target", ellipsis: true },
        ]} />
      </Modal>

      <Modal title={editingProfile ? "编辑扫描方案" : "新增扫描方案"} open={profileModalOpen} onCancel={() => setProfileModalOpen(false)} onOk={() => void saveProfile()} destroyOnHidden>
        <Form form={profileForm} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="resource_type" label="资源类型" rules={[{ required: true }]}><Select options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="description" label="描述"><Input.TextArea rows={3} /></Form.Item>
          <Form.Item label="扫描能力"><Select mode="multiple" value={profileCapabilityIDs} onChange={setProfileCapabilityIDs} options={capabilityOptions} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={editingAction ? "编辑目标动作" : "新增目标动作"} open={actionModalOpen} onCancel={() => setActionModalOpen(false)} onOk={() => void saveAction()} destroyOnHidden>
        <Form form={actionForm} layout="vertical">
          <Form.Item name="target_type" label="目标类型" rules={[{ required: true }]}><Select options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="target_name" label="目标名称" rules={[{ required: true }]}><Input disabled={!!editingAction} /></Form.Item>
          <Form.Item name="connector" label="Connector"><Input placeholder="留空表示全局" disabled={!!editingAction} /></Form.Item>
          <Form.Item name="source_path" label="源路径"><Input /></Form.Item>
          <Form.Item name={["actions", "install"]} label="Install"><Select options={["none", "allow", "block"].map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name={["actions", "file"]} label="File"><Select options={["none", "quarantine"].map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name={["actions", "runtime"]} label="Runtime"><Select options={["allow", "disable", "enable"].map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="reason" label="原因"><Input.TextArea rows={3} /></Form.Item>
        </Form>
      </Modal>
    </section>
  );
}
