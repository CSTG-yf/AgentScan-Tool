import { useCallback, useEffect, useMemo, useState } from "react";
import { RuntimeDetectionSettingsPage } from "../runtime-detection/SettingsPage";
import { ScanRefreshSettingsPage, type ScanRefreshSettingsPageProps } from "./ScanRefreshSettingsPage";
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
  Card,
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
  createGovernancePostScanProfile,
  createGovernancePostScanRule,
  createGovernancePreScanProfile,
  createGovernancePreScanRule,
  createGovernanceResourceAction,
  createGovernanceResourceRule,
  createGovernanceScanProfile,
  deleteGovernanceAgentType,
  deleteGovernanceDiscoveryCondition,
  deleteGovernanceDiscoveryRule,
  deleteGovernancePostScanProfile,
  deleteGovernancePostScanRule,
  deleteGovernancePreScanProfile,
  deleteGovernancePreScanRule,
  deleteGovernanceResourceAction,
  deleteGovernanceResourceRule,
  deleteGovernanceScanProfile,
  evaluateGovernanceAdmission,
  evaluateGovernanceRisk,
  getGovernanceAdmissionMatrix,
  getGovernanceAgentTypes,
  getGovernanceDiscoveryRule,
  getGovernanceDiscoveryRules,
  getGovernancePostScanProfiles,
  getGovernancePostScanRules,
  getGovernancePreScanProfiles,
  getGovernancePreScanRules,
  getGovernanceResourceActions,
  getGovernanceResourceRules,
  getGovernanceRiskCategoryMatches,
  getGovernanceRiskRulePrefixMatches,
  getGovernanceRiskSeverityMappings,
  getGovernanceScanCapabilities,
  getGovernanceScanProfiles,
  previewGovernanceResourceRule,
  replaceGovernanceScanProfileCapabilities,
  updateGovernanceAgentType,
  updateGovernanceDiscoveryCondition,
  updateGovernanceDiscoveryRule,
  updateGovernancePostScanProfile,
  updateGovernancePostScanRule,
  updateGovernancePreScanProfile,
  updateGovernancePreScanRule,
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
  GovernancePostScanProfile,
  GovernancePostScanProfileInput,
  GovernancePostScanRule,
  GovernancePostScanRuleInput,
  GovernancePreScanProfile,
  GovernancePreScanProfileInput,
  GovernancePreScanRule,
  GovernancePreScanRuleInput,
  GovernanceResourceAction,
  GovernanceResourceActionInput,
  GovernanceResourceRule,
  GovernanceResourceRuleInput,
  GovernanceRiskCategoryMatch,
  GovernanceRiskEvaluateResponse,
  GovernanceRiskRulePrefixMatch,
  GovernanceRiskSeverityMapping,
  GovernanceScanCapability,
  GovernanceScanProfile,
  GovernanceScanProfileInput,
} from "../types";

const { Text, Title } = Typography;

const RESOURCE_TYPES = ["skill", "mcp", "plugin", "config", "prompt", "credential", "environment"];
const DECISION_RESOURCE_TYPES = ["all", ...RESOURCE_TYPES];
const ENUMERATION_MODES = ["exact", "children", "glob", "recursive"];
const SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const RISK_LEVELS = ["clean", "low", "medium", "high", "critical"];
const RISK_LEVEL_OPTIONS = [{ value: "all", label: "全部风险" }, ...RISK_LEVELS.map((value) => ({ value, label: value }))];
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

type RiskQueryState = PageQueryState & {
  riskLevel: string;
};

type DraftPreScanRule = GovernancePreScanRuleInput & { draft_id: string };
type DraftPostScanRule = GovernancePostScanRuleInput & { draft_id: string };

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

export type AgentGovernancePageProps = ScanRefreshSettingsPageProps;

export function AgentGovernancePage(props: AgentGovernancePageProps) {
  const [activeGovernanceTab, setActiveGovernanceTab] = useState("types");
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
  const [preScanProfileCatalog, setPreScanProfileCatalog] = useState<GovernancePreScanProfile[]>([]);
  const [postScanProfileCatalog, setPostScanProfileCatalog] = useState<GovernancePostScanProfile[]>([]);
  const [preScanProfilePage, setPreScanProfilePage] = useState<GovernancePage<GovernancePreScanProfile>>(emptyPage(1, 8));
  const [postScanProfilePage, setPostScanProfilePage] = useState<GovernancePage<GovernancePostScanProfile>>(emptyPage(1, 8));
  const [preScanRulePage, setPreScanRulePage] = useState<GovernancePage<GovernancePreScanRule>>(emptyPage(1, 6));
  const [postScanRulePage, setPostScanRulePage] = useState<GovernancePage<GovernancePostScanRule>>(emptyPage(1, 6));
  const [resourceActions, setResourceActions] = useState<GovernanceResourceAction[]>([]);
  const [admissionMatrix, setAdmissionMatrix] = useState<GovernanceAdmissionMatrixItem[]>([]);
  const [riskLoading, setRiskLoading] = useState(false);
  const [riskSeverityPage, setRiskSeverityPage] = useState<GovernancePage<GovernanceRiskSeverityMapping>>(emptyPage(1, 5));
  const [riskRulePrefixPage, setRiskRulePrefixPage] = useState<GovernancePage<GovernanceRiskRulePrefixMatch>>(emptyPage(1, 5));
  const [riskCategoryPage, setRiskCategoryPage] = useState<GovernancePage<GovernanceRiskCategoryMatch>>(emptyPage(1, 5));

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

  const [decisionLoading, setDecisionLoading] = useState(false);
  const [preScanQuery, setPreScanQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 8 });
  const [preScanKeyword, setPreScanKeyword] = useState("");
  const [preScanEnabled, setPreScanEnabled] = useState<EnabledFilter>("all");
  const [postScanQuery, setPostScanQuery] = useState<PageQueryState>({ keyword: "", enabled: "all", page: 1, pageSize: 8 });
  const [postScanKeyword, setPostScanKeyword] = useState("");
  const [postScanEnabled, setPostScanEnabled] = useState<EnabledFilter>("all");

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

  const [admissionForm] = Form.useForm();
  const [admissionResult, setAdmissionResult] = useState<GovernanceAdmissionEvaluateResponse>();
  const [riskForm] = Form.useForm();
  const [riskResult, setRiskResult] = useState<GovernanceRiskEvaluateResponse>();

  const loading = referenceLoading || agentLoading || discoveryLoading || resourceLoading || decisionLoading || riskLoading;

  const agentTypeOptions = useMemo(
    () => agentTypeCatalog.map((item) => ({ label: `${item.name} (${item.type_key})`, value: item.id })),
    [agentTypeCatalog],
  );
  const profileOptions = useMemo(
    () => scanProfiles.map((item) => ({ label: `${item.name} / ${item.resource_type}`, value: item.id })),
    [scanProfiles],
  );
  const preScanProfileOptions = useMemo(
    () => preScanProfileCatalog.map((item) => ({ label: `${item.name}${item.is_default ? "（默认）" : ""}`, value: item.id })),
    [preScanProfileCatalog],
  );
  const postScanProfileOptions = useMemo(
    () => postScanProfileCatalog.map((item) => ({ label: `${item.name}${item.is_default ? "（默认）" : ""}`, value: item.id })),
    [postScanProfileCatalog],
  );
  const defaultPreScanProfileID = preScanProfileCatalog.find((item) => item.is_default)?.id ?? preScanProfileCatalog[0]?.id;
  const defaultPostScanProfileID = postScanProfileCatalog.find((item) => item.is_default)?.id ?? postScanProfileCatalog[0]?.id;
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

  const loadDecisionProfiles = useCallback(async () => {
    setDecisionLoading(true);
    try {
      const [prePage, postPage] = await Promise.all([
        getGovernancePreScanProfiles(queryFromState(preScanQuery)),
        getGovernancePostScanProfiles(queryFromState(postScanQuery)),
      ]);
      setPreScanProfilePage(prePage);
      setPostScanProfilePage(postPage);
    } catch (error) {
      message.error(`读取决策方案失败：${String(error)}`);
    } finally {
      setDecisionLoading(false);
    }
  }, [preScanQuery, postScanQuery]);

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
    } catch (error) {
      message.error(`读取风险解释规则失败：${String(error)}`);
    } finally {
      setRiskLoading(false);
    }
  }, [riskSeverityQuery, riskRulePrefixQuery, riskCategoryQuery]);

  const loadReferences = useCallback(async () => {
    setReferenceLoading(true);
    try {
      const [agentCatalog, profilePage, capabilityResp, actionPage, matrix, preProfiles, postProfiles] = await Promise.all([
        getGovernanceAgentTypes({ page: 1, pageSize: 500 }),
        getGovernanceScanProfiles({ page: 1, pageSize: 500 }),
        getGovernanceScanCapabilities(),
        getGovernanceResourceActions({ page: 1, pageSize: 200 }),
        getGovernanceAdmissionMatrix(),
        getGovernancePreScanProfiles({ page: 1, pageSize: 500 }),
        getGovernancePostScanProfiles({ page: 1, pageSize: 500 }),
      ]);
      setAgentTypeCatalog(agentCatalog.items ?? []);
      setScanProfiles(profilePage.items ?? []);
      setScanCapabilities(capabilityResp.items ?? []);
      setResourceActions(actionPage.items ?? []);
      setAdmissionMatrix(matrix.items ?? []);
      setPreScanProfileCatalog(preProfiles.items ?? []);
      setPostScanProfileCatalog(postProfiles.items ?? []);
    } catch (error) {
      message.error(`读取 Agent 治理配置失败：${String(error)}`);
    } finally {
      setReferenceLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadReferences(), loadAgentTypes(), loadDiscoveryRules(), loadResourceRules(), loadDecisionProfiles(), loadRiskExplain()]);
  }, [loadReferences, loadAgentTypes, loadDiscoveryRules, loadResourceRules, loadDecisionProfiles, loadRiskExplain]);

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

  useEffect(() => {
    void loadDecisionProfiles();
  }, [loadDecisionProfiles]);

  useEffect(() => {
    void loadRiskExplain();
  }, [loadRiskExplain]);

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

  const loadPreScanRules = useCallback(async (profileID = editingPreScanProfile?.id) => {
    if (!profileID) return;
    try {
      setPreScanRulePage(await getGovernancePreScanRules(profileID, queryFromState(preScanRuleQuery)));
    } catch (error) {
      message.error(`读取 Pre-scan 规则失败：${String(error)}`);
    }
  }, [editingPreScanProfile?.id, preScanRuleQuery]);

  const loadPostScanRules = useCallback(async (profileID = editingPostScanProfile?.id) => {
    if (!profileID) return;
    try {
      setPostScanRulePage(await getGovernancePostScanRules(profileID, queryFromState(postScanRuleQuery)));
    } catch (error) {
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

  const removeProfile = async (record: GovernanceScanProfile) => {
    await deleteGovernanceScanProfile(record.id);
    message.success("扫描方案已删除");
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

  const removeAction = async (record: GovernanceResourceAction) => {
    await deleteGovernanceResourceAction(record.id);
    message.success("目标动作已删除");
    await loadReferences();
  };

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
    } else {
      await createGovernancePreScanProfile(body);
      message.success("Pre-scan 方案已创建");
    }
    setPreScanProfileModalOpen(false);
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
  };

  const removePreScanProfile = async (record: GovernancePreScanProfile) => {
    await deleteGovernancePreScanProfile(record.id);
    message.success("Pre-scan 方案已删除");
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
  };

  const togglePreScanProfile = async (record: GovernancePreScanProfile, enabled: boolean) => {
    await updateGovernancePreScanProfile(record.id, { enabled });
    message.success(enabled ? "Pre-scan 方案已启用" : "Pre-scan 方案已停用");
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
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
      } else {
        await createGovernancePreScanRule(editingPreScanProfile.id, body);
        message.success("Pre-scan 规则已创建");
      }
      await Promise.all([loadPreScanRules(editingPreScanProfile.id), loadDecisionProfiles(), loadReferences()]);
    } else {
      if (editingDraftPreScanRuleID) {
        setDraftPreScanRules((prev) => prev.map((item) => (item.draft_id === editingDraftPreScanRuleID ? { ...body, draft_id: item.draft_id } : item)));
      } else {
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
    } else {
      await createGovernancePostScanProfile(body);
      message.success("Post-scan 方案已创建");
    }
    setPostScanProfileModalOpen(false);
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
  };

  const removePostScanProfile = async (record: GovernancePostScanProfile) => {
    await deleteGovernancePostScanProfile(record.id);
    message.success("Post-scan 方案已删除");
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
  };

  const togglePostScanProfile = async (record: GovernancePostScanProfile, enabled: boolean) => {
    await updateGovernancePostScanProfile(record.id, { enabled });
    message.success(enabled ? "Post-scan 方案已启用" : "Post-scan 方案已停用");
    await Promise.all([loadReferences(), loadDecisionProfiles(), loadResourceRules()]);
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
      } else {
        await createGovernancePostScanRule(editingPostScanProfile.id, body);
        message.success("Post-scan 规则已创建");
      }
      await Promise.all([loadPostScanRules(editingPostScanProfile.id), loadDecisionProfiles(), loadReferences()]);
    } else {
      if (editingDraftPostScanRuleID) {
        setDraftPostScanRules((prev) => prev.map((item) => (item.draft_id === editingDraftPostScanRuleID ? { ...body, draft_id: item.draft_id } : item)));
      } else {
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
    { title: "Pre-scan", dataIndex: "pre_scan_profile_name", width: 170, render: (value) => value || "-" },
    { title: "Post-scan", dataIndex: "post_scan_profile_name", width: 170, render: (value) => value || "-" },
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
          <Popconfirm title="删除该扫描方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
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
          <Popconfirm title="删除该目标动作？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removeAction(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

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
      render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePreScanProfile(record, checked)} />,
    },
    {
      title: "操作",
      fixed: "right",
      width: 170,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanProfileModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Pre-scan 方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePreScanProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={record.is_default}>删除</Button>
          </Popconfirm>
        </Space>
      ),
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
      render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePreScanRule(record, checked)} />,
    },
    {
      title: "操作",
      fixed: "right",
      width: 160,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Pre-scan 规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePreScanRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPreScanRuleModal(record)}>编辑</Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => removeDraftPreScanRule(record)}>删除</Button>
        </Space>
      ),
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
      render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePostScanProfile(record, checked)} />,
    },
    {
      title: "操作",
      fixed: "right",
      width: 170,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanProfileModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Post-scan 方案？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePostScanProfile(record)}>
            <Button size="small" danger icon={<DeleteOutlined />} disabled={record.is_default}>删除</Button>
          </Popconfirm>
        </Space>
      ),
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
      render: (value, record) => <Switch size="small" checked={value} onChange={(checked) => void togglePostScanRule(record, checked)} />,
    },
    {
      title: "操作",
      fixed: "right",
      width: 160,
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanRuleModal(record)}>编辑</Button>
          <Popconfirm title="删除该 Post-scan 规则？" okText="删除" okButtonProps={{ danger: true }} onConfirm={() => removePostScanRule(record)}>
            <Button size="small" danger icon={<DeleteOutlined />}>删除</Button>
          </Popconfirm>
        </Space>
      ),
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
      render: (_, record) => (
        <Space>
          <Button size="small" icon={<EditOutlined />} onClick={() => openPostScanRuleModal(record)}>编辑</Button>
          <Button size="small" danger icon={<DeleteOutlined />} onClick={() => removeDraftPostScanRule(record)}>删除</Button>
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
      label: "当资源决策为allowed时的扫描方案",
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
      key: "scan-refresh-settings",
      label: "扫描与刷新策略",
      children: <ScanRefreshSettingsPage {...props} />,
    },
    {
      key: "decisions",
      label: "决策与动作",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Alert
            type="info"
            showIcon
            message="资源发现规则会绑定一套 Pre-scan 方案和一套 Post-scan 方案；新增资源规则时默认使用系统默认方案，也可以按业务选择其他方案。"
          />
          <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <Space className="governance-toolbar" wrap>
                <Text strong>资源 Pre-scan 方案</Text>
                <Input.Search
                  allowClear
                  placeholder="搜索方案 Key / 名称 / 描述"
                  value={preScanKeyword}
                  onChange={(event) => setPreScanKeyword(event.target.value)}
                  onSearch={applyPreScanFilter}
                  style={{ width: 260 }}
                />
                <Select value={preScanEnabled} onChange={setPreScanEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyPreScanFilter}>查询</Button>
                <Button onClick={resetPreScanFilter}>重置</Button>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openPreScanProfileModal()}>新增 Pre-scan 方案</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadDecisionProfiles()} />
              </Space>
              <Table
                rowKey="id"
                loading={decisionLoading}
                columns={preScanProfileColumns}
                dataSource={preScanProfilePage.items}
                scroll={{ x: 1060 }}
                pagination={tablePagination(preScanProfilePage, preScanQuery)}
                onChange={(pagination) => setPreScanQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </Card>
          <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <Space className="governance-toolbar" wrap>
                <Text strong>资源 Post-scan 方案</Text>
                <Input.Search
                  allowClear
                  placeholder="搜索方案 Key / 名称 / 描述"
                  value={postScanKeyword}
                  onChange={(event) => setPostScanKeyword(event.target.value)}
                  onSearch={applyPostScanFilter}
                  style={{ width: 260 }}
                />
                <Select value={postScanEnabled} onChange={setPostScanEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyPostScanFilter}>查询</Button>
                <Button onClick={resetPostScanFilter}>重置</Button>
                <Button type="primary" icon={<PlusOutlined />} onClick={() => openPostScanProfileModal()}>新增 Post-scan 方案</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadDecisionProfiles()} />
              </Space>
              <Table
                rowKey="id"
                loading={decisionLoading}
                columns={postScanProfileColumns}
                dataSource={postScanProfilePage.items}
                scroll={{ x: 1060 }}
                pagination={tablePagination(postScanProfilePage, postScanQuery)}
                onChange={(pagination) => setPostScanQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </Card>
        </Space>
      ),
    },
    {
      key: "risk",
      label: "风险解释",
      children: (
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Alert
            type="info"
            showIcon
            message="风险判定优先级：Rule ID 前缀 > Category > Severity > 默认 clean。前三类规则都只读取启用且未删除的数据。"
          />
          <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <div>
                <Text strong>Severity 风险等级映射</Text>
                <br />
                <Text type="secondary">当 finding 没有命中更高优先级的前缀或 Category 规则时，按扫描器 Severity 映射资源风险等级。</Text>
              </div>
              <Space className="governance-toolbar" wrap>
                <Input.Search
                  allowClear
                  placeholder="搜索 Severity / Risk Level / 说明"
                  value={riskSeverityKeyword}
                  onChange={(event) => setRiskSeverityKeyword(event.target.value)}
                  onSearch={applyRiskSeverityFilter}
                  style={{ width: 280 }}
                />
                <Select value={riskSeverityLevel} onChange={setRiskSeverityLevel} options={RISK_LEVEL_OPTIONS} style={{ width: 130 }} />
                <Select value={riskSeverityEnabled} onChange={setRiskSeverityEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyRiskSeverityFilter}>查询</Button>
                <Button onClick={resetRiskSeverityFilter}>重置</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadRiskExplain()} />
              </Space>
              <Table
                rowKey="id"
                size="small"
                loading={riskLoading}
                columns={riskSeverityColumns}
                dataSource={riskSeverityPage.items}
                scroll={{ x: 980 }}
                pagination={tablePagination(riskSeverityPage, riskSeverityQuery)}
                onChange={(pagination) => setRiskSeverityQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </Card>
          <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <div>
                <Text strong>规则 ID 前缀匹配规则</Text>
                <br />
                <Text type="secondary">Rule ID 前缀是最高优先级规则，适合把一类扫描器规则整体提升到指定风险等级。</Text>
              </div>
              <Space className="governance-toolbar" wrap>
                <Input.Search
                  allowClear
                  placeholder="搜索 Rule ID 前缀 / Risk Level / 说明"
                  value={riskRulePrefixKeyword}
                  onChange={(event) => setRiskRulePrefixKeyword(event.target.value)}
                  onSearch={applyRiskRulePrefixFilter}
                  style={{ width: 300 }}
                />
                <Select value={riskRulePrefixLevel} onChange={setRiskRulePrefixLevel} options={RISK_LEVEL_OPTIONS} style={{ width: 130 }} />
                <Select value={riskRulePrefixEnabled} onChange={setRiskRulePrefixEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyRiskRulePrefixFilter}>查询</Button>
                <Button onClick={resetRiskRulePrefixFilter}>重置</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadRiskExplain()} />
              </Space>
              <Table
                rowKey="id"
                size="small"
                loading={riskLoading}
                columns={riskRulePrefixColumns}
                dataSource={riskRulePrefixPage.items}
                scroll={{ x: 980 }}
                pagination={tablePagination(riskRulePrefixPage, riskRulePrefixQuery)}
                onChange={(pagination) => setRiskRulePrefixQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </Card>
          <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <div>
                <Text strong>Category 匹配规则</Text>
                <br />
                <Text type="secondary">Category 是第二优先级规则，用于把 malware、c2、credential_harvest 等风险类别映射到资源风险等级。</Text>
              </div>
              <Space className="governance-toolbar" wrap>
                <Input.Search
                  allowClear
                  placeholder="搜索 Category / Risk Level / 说明"
                  value={riskCategoryKeyword}
                  onChange={(event) => setRiskCategoryKeyword(event.target.value)}
                  onSearch={applyRiskCategoryFilter}
                  style={{ width: 300 }}
                />
                <Select value={riskCategoryLevel} onChange={setRiskCategoryLevel} options={RISK_LEVEL_OPTIONS} style={{ width: 130 }} />
                <Select value={riskCategoryEnabled} onChange={setRiskCategoryEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyRiskCategoryFilter}>查询</Button>
                <Button onClick={resetRiskCategoryFilter}>重置</Button>
                <Button icon={<ReloadOutlined />} onClick={() => void loadRiskExplain()} />
              </Space>
              <Table
                rowKey="id"
                size="small"
                loading={riskLoading}
                columns={riskCategoryColumns}
                dataSource={riskCategoryPage.items}
                scroll={{ x: 980 }}
                pagination={tablePagination(riskCategoryPage, riskCategoryQuery)}
                onChange={(pagination) => setRiskCategoryQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
              />
            </Space>
          </Card>
          {/* <Card bordered={false} className="workspace-table-card">
            <Space direction="vertical" size={16} style={{ width: "100%" }}>
              <div>
                <Text strong>风险试算器</Text>
                <br />
                <Text type="secondary">输入一条 finding 的关键字段，查看最终风险等级、命中的规则类型和值，以及判定原因。</Text>
              </div>
              <Form
                form={riskForm}
                layout="inline"
                onFinish={(values) => {
                  void evaluateGovernanceRisk({
                    resource_type: values.resource_type,
                    severity: values.severity,
                    rule_id: values.rule_id,
                    category: values.category,
                    tags: values.tags,
                    title: values.title,
                  }).then(setRiskResult).catch((error) => message.error(`风险试算失败：${String(error)}`));
                }}
              >
                <Form.Item name="resource_type" initialValue="prompt"><Select style={{ width: 130 }} options={RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
                <Form.Item name="severity" initialValue="HIGH"><Select style={{ width: 130 }} options={SEVERITIES.map((value) => ({ value, label: value }))} /></Form.Item>
                <Form.Item name="rule_id"><Input placeholder="Rule ID" /></Form.Item>
                <Form.Item name="category"><Input placeholder="Category" /></Form.Item>
                <Form.Item name="tags"><Input placeholder="tag1,tag2" /></Form.Item>
                <Form.Item name="title"><Input placeholder="Title" /></Form.Item>
                <Button htmlType="submit" type="primary">风险试算</Button>
              </Form>
              {riskResult ? <Descriptions bordered size="small" column={2} items={[
                { key: "risk", label: "最终风险等级", children: riskLevelTag(riskResult.risk_level) },
                { key: "type", label: "命中规则类型", children: riskResult.matched_type },
                { key: "value", label: "命中规则值", children: riskResult.matched_value || "-" },
                { key: "precedence", label: "优先级链路", children: riskResult.precedence.join(" > ") },
                { key: "reason", label: "判定原因", children: riskResult.reason },
              ]} /> : null}
            </Space>
          </Card> */}
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
        {activeGovernanceTab !== "scan-refresh-settings" && <Button icon={<ReloadOutlined />} onClick={() => void refreshAll()} loading={loading}>刷新</Button>}
      </div>
      {activeGovernanceTab !== "runtime-detection-settings" && activeGovernanceTab !== "scan-refresh-settings" && <div className="metric-grid">
        <div className="metric-card"><SafetyCertificateOutlined /><Text>Agent Type</Text><Title level={3}>{agentPage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>发现规则</Text><Title level={3}>{discoveryPage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>资源规则</Text><Title level={3}>{resourcePage.total}</Title></div>
        <div className="metric-card"><SafetyCertificateOutlined /><Text>扫描方案</Text><Title level={3}>{scanProfiles.length}</Title></div>
      </div>}
      <Tabs items={[
        ...tabs,
        { key: "runtime-detection-settings", label: "异常检测设置", children: <RuntimeDetectionSettingsPage /> },
      ]} activeKey={activeGovernanceTab} onChange={setActiveGovernanceTab} />

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
          <Form.Item name="pre_scan_profile_id" label="Pre-scan 方案"><Select options={preScanProfileOptions} /></Form.Item>
          <Form.Item name="post_scan_profile_id" label="Post-scan 方案"><Select options={postScanProfileOptions} /></Form.Item>
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

      <Modal title={editingPreScanProfile ? "编辑 Pre-scan 方案" : "新增 Pre-scan 方案"} open={preScanProfileModalOpen} onCancel={() => setPreScanProfileModalOpen(false)} onOk={() => void savePreScanProfile()} destroyOnHidden width={1080}>
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Form form={preScanProfileForm} layout="vertical">
            <Form.Item name="profile_key" label="方案 Key" rules={[{ required: true }]}><Input disabled={!!editingPreScanProfile} /></Form.Item>
            <Form.Item name="name" label="方案名称" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="description" label="描述"><Input.TextArea rows={2} /></Form.Item>
            <Space size={24}>
              <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
              <Form.Item name="is_default" label="默认方案" valuePropName="checked"><Switch /></Form.Item>
            </Space>
          </Form>
          <Alert type="info" showIcon message={editingPreScanProfile ? "下方规则会直接保存到当前方案，按优先级从小到大匹配。" : "新建方案时，下方规则先作为草稿保存，点击确定后会和方案一起创建。"} />
          <Space className="governance-toolbar" wrap>
            <Text strong>Pre-scan 规则</Text>
            {editingPreScanProfile ? (
              <>
                <Input.Search
                  allowClear
                  placeholder="搜索规则名 / 路径 / 可信来源"
                  value={preScanRuleKeyword}
                  onChange={(event) => setPreScanRuleKeyword(event.target.value)}
                  onSearch={applyPreScanRuleFilter}
                  style={{ width: 260 }}
                />
                <Select value={preScanRuleEnabled} onChange={setPreScanRuleEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyPreScanRuleFilter}>查询</Button>
                <Button onClick={resetPreScanRuleFilter}>重置</Button>
              </>
            ) : null}
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openPreScanRuleModal()}>新增规则</Button>
          </Space>
          {editingPreScanProfile ? (
            <Table
              rowKey="id"
              size="small"
              columns={preScanRuleColumns}
              dataSource={preScanRulePage.items}
              scroll={{ x: 1280 }}
              pagination={tablePagination(preScanRulePage, preScanRuleQuery)}
              onChange={(pagination) => setPreScanRuleQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
            />
          ) : (
            <Table
              rowKey="draft_id"
              size="small"
              columns={draftPreScanRuleColumns}
              dataSource={draftPreScanRules}
              scroll={{ x: 1280 }}
              pagination={{ pageSize: 6, showSizeChanger: true }}
            />
          )}
        </Space>
      </Modal>

      <Modal title={editingPreScanRule || editingDraftPreScanRuleID ? "编辑 Pre-scan 规则" : "新增 Pre-scan 规则"} open={preScanRuleModalOpen} onCancel={() => setPreScanRuleModalOpen(false)} onOk={() => void savePreScanRule()} destroyOnHidden width={760}>
        <Form form={preScanRuleForm} layout="vertical">
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="agent_type_id" label="Agent Type 条件"><Select allowClear options={agentTypeOptions} placeholder="留空表示全部 Agent Type" /></Form.Item>
          <Form.Item name="resource_type" label="资源类型"><Select options={DECISION_RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="path_pattern" label="路径模式"><Input placeholder="可留空，表示不限路径" /></Form.Item>
          <Form.Item name="source_trust" label="来源可信度"><Input placeholder="trusted / unknown / external，可留空" /></Form.Item>
          <Form.Item name="decision" label="Pre-scan 决策"><Select options={PRE_SCAN_DECISIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="install_action" label="Install"><Select options={INSTALL_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="file_action" label="File"><Select options={FILE_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="runtime_action" label="Runtime"><Select options={RUNTIME_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
        </Form>
      </Modal>

      <Modal title={editingPostScanProfile ? "编辑 Post-scan 方案" : "新增 Post-scan 方案"} open={postScanProfileModalOpen} onCancel={() => setPostScanProfileModalOpen(false)} onOk={() => void savePostScanProfile()} destroyOnHidden width={1080}>
        <Space direction="vertical" size={16} style={{ width: "100%" }}>
          <Form form={postScanProfileForm} layout="vertical">
            <Form.Item name="profile_key" label="方案 Key" rules={[{ required: true }]}><Input disabled={!!editingPostScanProfile} /></Form.Item>
            <Form.Item name="name" label="方案名称" rules={[{ required: true }]}><Input /></Form.Item>
            <Form.Item name="description" label="描述"><Input.TextArea rows={2} /></Form.Item>
            <Space size={24}>
              <Form.Item name="enabled" label="启用" valuePropName="checked"><Switch /></Form.Item>
              <Form.Item name="is_default" label="默认方案" valuePropName="checked"><Switch /></Form.Item>
            </Space>
          </Form>
          <Alert type="info" showIcon message={editingPostScanProfile ? "下方规则会直接保存到当前方案，扫描完成后按优先级从小到大匹配。" : "新建方案时，下方规则先作为草稿保存，点击确定后会和方案一起创建。"} />
          <Space className="governance-toolbar" wrap>
            <Text strong>Post-scan 规则</Text>
            {editingPostScanProfile ? (
              <>
                <Input.Search
                  allowClear
                  placeholder="搜索规则名 / Category / Scanner"
                  value={postScanRuleKeyword}
                  onChange={(event) => setPostScanRuleKeyword(event.target.value)}
                  onSearch={applyPostScanRuleFilter}
                  style={{ width: 260 }}
                />
                <Select value={postScanRuleEnabled} onChange={setPostScanRuleEnabled} options={[...ENABLED_OPTIONS]} style={{ width: 130 }} />
                <Button icon={<SearchOutlined />} onClick={applyPostScanRuleFilter}>查询</Button>
                <Button onClick={resetPostScanRuleFilter}>重置</Button>
              </>
            ) : null}
            <Button type="primary" icon={<PlusOutlined />} onClick={() => openPostScanRuleModal()}>新增规则</Button>
          </Space>
          {editingPostScanProfile ? (
            <Table
              rowKey="id"
              size="small"
              columns={postScanRuleColumns}
              dataSource={postScanRulePage.items}
              scroll={{ x: 1420 }}
              pagination={tablePagination(postScanRulePage, postScanRuleQuery)}
              onChange={(pagination) => setPostScanRuleQuery((prev) => ({ ...prev, page: pagination.current ?? 1, pageSize: pagination.pageSize ?? prev.pageSize }))}
            />
          ) : (
            <Table
              rowKey="draft_id"
              size="small"
              columns={draftPostScanRuleColumns}
              dataSource={draftPostScanRules}
              scroll={{ x: 1420 }}
              pagination={{ pageSize: 6, showSizeChanger: true }}
            />
          )}
        </Space>
      </Modal>

      <Modal title={editingPostScanRule || editingDraftPostScanRuleID ? "编辑 Post-scan 规则" : "新增 Post-scan 规则"} open={postScanRuleModalOpen} onCancel={() => setPostScanRuleModalOpen(false)} onOk={() => void savePostScanRule()} destroyOnHidden width={760}>
        <Form form={postScanRuleForm} layout="vertical">
          <Form.Item name="rule_name" label="规则名称" rules={[{ required: true }]}><Input /></Form.Item>
          <Form.Item name="priority" label="优先级"><InputNumber min={1} style={{ width: "100%" }} /></Form.Item>
          <Form.Item name="resource_type" label="资源类型"><Select options={DECISION_RESOURCE_TYPES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="severity" label="严重级别"><Select options={SEVERITIES.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="risk_level" label="风险等级"><Select options={RISK_LEVELS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="malicious" label="恶意资源" valuePropName="checked"><Switch /></Form.Item>
          <Form.Item name="finding_category" label="Finding Category"><Input placeholder="可留空，表示不限分类" /></Form.Item>
          <Form.Item name="scanner" label="Scanner"><Input placeholder="可留空，表示不限扫描器" /></Form.Item>
          <Form.Item name="decision" label="Post-scan 决策"><Select options={POST_SCAN_DECISIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="install_action" label="Install"><Select options={INSTALL_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="file_action" label="File"><Select options={FILE_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
          <Form.Item name="runtime_action" label="Runtime"><Select options={RUNTIME_ACTIONS.map((value) => ({ value, label: value }))} /></Form.Item>
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
