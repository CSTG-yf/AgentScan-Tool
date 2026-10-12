import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Empty,
  Row,
  Select,
  Space,
  Spin,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
  Upload,
  message,
} from "antd";
import { ReloadOutlined, UploadOutlined } from "@ant-design/icons";
import {
  evaluationRequest,
  evaluationMetricNames,
  evaluationStatusNames,
  formatEvaluationMetric,
  type EvaluationArtifact,
  type EvaluationCounts,
  type EvaluationDistribution,
  type EvaluationFilters,
  type EvaluationInstance,
  type EvaluationMetric,
  type EvaluationRun,
} from "../evaluations";
const { Title, Text, Paragraph } = Typography;
const modes = ["baseline", "observe", "action"];
const domains = { asset: "资产盘点", risk: "风险识别", runtime: "运行时检测" };
const stages = [
  ["event", "原始行为事件"],
  ["scan", "静态扫描"],
  ["detection", "Detection"],
  ["decision", "Decision"],
  ["response", "Response Action"],
  ["side_effect", "副作用验证"],
  ["attack_chain", "Attack Chain"],
];
const truthValue = (v: boolean | null) =>
  v === null ? "未知" : v ? "是" : "否";
const stamp = (s: string) =>
  s ? new Date(s).toLocaleString("zh-CN", { hour12: false }) : "未记录";
function Status({ value }: { value: string }) {
  return (
    <Tag
      color={
        value === "passed" || value === "complete"
          ? "success"
          : value === "failed"
            ? "error"
            : "warning"
      }
    >
      {evaluationStatusNames[value] || value}
    </Tag>
  );
}
const expectedCount = (c: EvaluationCounts) =>
  c.expected_unknown
    ? c.expected
      ? `${c.expected} + ${c.expected_unknown} 未知`
      : "未知"
    : c.expected;
const discoveredCount = (c: EvaluationCounts) =>
  c.discovered_unknown
    ? `${c.discovered} + ${c.discovered_unknown} 未知`
    : c.discovered;
function Counts({ value }: { value?: EvaluationCounts }) {
  if (!value || value.total === 0)
    return <Text type="secondary">未评测：没有可评分实例</Text>;
  return (
    <Space wrap>
      {["tp", "fp", "tn", "fn", "unknown"].map((k) => (
        <Tag key={k}>
          {k.toUpperCase()}：{value[k as keyof EvaluationCounts]}
        </Tag>
      ))}
      <Tag>预期 {expectedCount(value)}</Tag>
      <Tag>发现 {discoveredCount(value)}</Tag>
      <Tag>实例 {value.total}</Tag>
    </Space>
  );
}

export function EvaluationsPage() {
  const [runs, setRuns] = useState<EvaluationRun[]>([]);
  const [totalRuns, setTotalRuns] = useState(0);
  const [historyPage, setHistoryPage] = useState(1);
  const [runID, setRunID] = useState("");
  const [run, setRun] = useState<EvaluationRun>();
  const [comparison, setComparison] = useState<Record<string, EvaluationRun>>(
    {},
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState<EvaluationFilters>({});
  const [instances, setInstances] = useState<EvaluationInstance[]>([]);
  const [instanceTotal, setInstanceTotal] = useState(0);
  const [instanceLoading, setInstanceLoading] = useState(false);
  const [instanceError, setInstanceError] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<EvaluationInstance>();
  const [artifact, setArtifact] = useState<EvaluationArtifact>();
  const [artifactLoading, setArtifactLoading] = useState(false);
  const [artifactError, setArtifactError] = useState("");
  const [uploading, setUploading] = useState(false);
  const runSequence = useRef(0);
  const instanceSequence = useRef(0);
  const artifactSequence = useRef(0);
  const listSequence = useRef(0);
  const refreshHistory = useCallback(async () => {
    const seq = ++listSequence.current;
    try {
      const result = await evaluationRequest<{
        runs: EvaluationRun[];
        total: number;
      }>(`?limit=20&offset=${(historyPage - 1) * 20}`);
      if (seq !== listSequence.current) return;
      setRuns(result.runs);
      setTotalRuns(result.total);
      setRunID((id) => id || result.runs[0]?.id || "");
      setError("");
    } catch (e) {
      if (seq === listSequence.current) setError(String(e));
    }
  }, [historyPage]);
  useEffect(() => {
    void refreshHistory();
    return () => {
      listSequence.current++;
    };
  }, [refreshHistory]);
  const refreshRun = useCallback(async () => {
    if (!runID) return;
    const seq = ++runSequence.current;
    setLoading(true);
    setError("");
    setRun(undefined);
    setComparison({});
    try {
      const [detail, compared] = await Promise.all([
        evaluationRequest<EvaluationRun>(`/${runID}`),
        evaluationRequest<{ modes: Record<string, EvaluationRun> }>(
          `/${runID}/comparison`,
        ),
      ]);
      if (seq !== runSequence.current) return;
      setRun(detail);
      setComparison(compared.modes);
    } catch (e) {
      if (seq === runSequence.current) setError(String(e));
    } finally {
      if (seq === runSequence.current) setLoading(false);
    }
  }, [runID]);
  useEffect(() => {
    setFilters({});
    setPage(1);
    setSelected(undefined);
    setArtifact(undefined);
    artifactSequence.current++;
    void refreshRun();
    return () => {
      runSequence.current++;
    };
  }, [refreshRun]);
  useEffect(() => {
    if (run?.status !== "running") return;
    const timer = setInterval(() => {
      void refreshRun();
      void refreshHistory();
    }, 10000);
    return () => clearInterval(timer);
  }, [run?.status, refreshRun, refreshHistory]);
  useEffect(() => {
    if (!runID) return;
    const seq = ++instanceSequence.current;
    setInstanceLoading(true);
    setInstances([]);
    setInstanceTotal(0);
    setInstanceError("");
    const query = new URLSearchParams({
      limit: "20",
      offset: String((page - 1) * 20),
    });
    Object.entries(filters).forEach(([key, value]) => {
      if (value) query.set(key, String(value));
    });
    evaluationRequest<{ instances: EvaluationInstance[]; total: number }>(
      `/${runID}/instances?${query}`,
    )
      .then((result) => {
        if (seq === instanceSequence.current) {
          setInstances(result.instances);
          setInstanceTotal(result.total);
        }
      })
      .catch((e) => {
        if (seq === instanceSequence.current) setInstanceError(String(e));
      })
      .finally(() => {
        if (seq === instanceSequence.current) setInstanceLoading(false);
      });
    return () => {
      instanceSequence.current++;
    };
  }, [runID, filters, page]);
  useEffect(
    () => () => {
      artifactSequence.current++;
    },
    [],
  );
  const openArtifact = async (id: string) => {
    const seq = ++artifactSequence.current;
    setArtifact(undefined);
    setArtifactError("");
    setArtifactLoading(true);
    try {
      const result = await evaluationRequest<EvaluationArtifact>(
        `/${runID}/artifacts/${encodeURIComponent(id)}`,
      );
      if (seq === artifactSequence.current) setArtifact(result);
    } catch (e) {
      if (seq === artifactSequence.current) setArtifactError(String(e));
    } finally {
      if (seq === artifactSequence.current) setArtifactLoading(false);
    }
  };
  const inspectInstance = (i: EvaluationInstance) => {
    artifactSequence.current++;
    setSelected(i);
    setArtifact(undefined);
    setArtifactError("");
    setArtifactLoading(false);
  };
  const drillMetric = (m: EvaluationMetric) => {
    setFilters({ domain: m.domain });
    setPage(1);
    document
      .getElementById("evaluation-instances")
      ?.scrollIntoView({ behavior: "smooth" });
  };
  const metricTable = (metrics: EvaluationMetric[]) => (
    <Table
      size="small"
      rowKey="key"
      pagination={false}
      dataSource={metrics}
      className="evaluation-metrics"
      tableLayout="fixed"
      columns={[
        {
          title: "指标",
          dataIndex: "key",
          render: (key: string, m: EvaluationMetric) => (
            <Tooltip
              title={
                <>
                  {m.formula}
                  <br />
                  {m.reason}
                </>
              }
            >
              <Button type="link" onClick={() => drillMetric(m)}>
                {evaluationMetricNames[key] || key}
              </Button>
            </Tooltip>
          ),
        },
        {
          title: "结果",
          render: (_, m: EvaluationMetric) => (
            <Text strong>{formatEvaluationMetric(m)}</Text>
          ),
        },
        {
          title: "分子 / 分母",
          render: (_, m: EvaluationMetric) =>
            m.numerator === null
              ? "见采样明细"
              : m.denominator === 0
                ? "无可用分母"
                : `${m.numerator} / ${m.denominator}`,
        },
        { title: "目标", dataIndex: "target" },
        {
          title: "达标情况",
          render: (_, m: EvaluationMetric) => <Status value={m.status} />,
        },
      ]}
    />
  );
  return (
    <section className="evaluation-page">
      <div className="section-heading">
        <div>
          <Title level={2}>能力评测</Title>
          <Text type="secondary">查看赛题两项能力、达标指标和实例证据。</Text>
        </div>
        <Space wrap>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => {
              void refreshHistory();
              void refreshRun();
            }}
            loading={loading}
          >
            刷新
          </Button>
          <Upload
            accept=".json"
            showUploadList={false}
            beforeUpload={async (file) => {
              if (file.size > 32 * 1024 * 1024) {
                message.error("评测文件不能超过 32 MB");
                return false;
              }
              setUploading(true);
              try {
                const report = JSON.parse(await file.text());
                const result = await evaluationRequest<EvaluationRun>(
                  "",
                  "POST",
                  report,
                );
                setHistoryPage(1);
                setRunID(result.id);
                await refreshHistory();
                message.success("评测报告已保存为新批次");
              } catch (e) {
                message.error(`导入失败：${String(e)}`);
              } finally {
                setUploading(false);
              }
              return false;
            }}
          >
            <Button icon={<UploadOutlined />} loading={uploading}>
              导入评测报告
            </Button>
          </Upload>
        </Space>
      </div>
      {error && (
        <Alert
          type="error"
          showIcon
          title="无法读取评测数据"
          description={error}
        />
      )}
      <Space wrap>
        <Text strong>当前查看批次</Text>
        <Select
          aria-label="选择评测批次"
          style={{ minWidth: 320, maxWidth: "100%" }}
          value={runID || undefined}
          placeholder="尚无评测批次"
          onChange={setRunID}
          options={[
            ...(run && !runs.some((r) => r.id === run.id) ? [run] : []),
            ...runs,
          ].map((r) => ({
            value: r.id,
            label: `${r.name} · ${r.mode} · ${r.id.slice(0, 8)}`,
          }))}
        />
      </Space>
      <Spin spinning={loading}>
        {run && (
          <>
            <Row gutter={[16, 16]}>
              <Col xs={24} lg={12}>
                <Card
                  title="Agent 资产风险识别能力"
                  extra={<Status value={run.report.capability_status.static} />}
                >
                  <Counts value={run.report.counts.asset} />
                  <Paragraph type="secondary">
                    静态真值集：{run.static_truth.sha256 || "未提供"}
                    。总能力达标需要覆盖 Agent、模型、MCP、Skill、插件和工具。
                  </Paragraph>
                  {metricTable(
                    run.report.metrics.filter(
                      (m) =>
                        m.domain === "asset" ||
                        (m.domain === "risk" && m.key !== "risk_fpr"),
                    ),
                  )}
                </Card>
              </Col>
              <Col xs={24} lg={12}>
                <Card
                  title="Agent 风险监控与阻断能力"
                  extra={
                    <Status value={run.report.capability_status.runtime} />
                  }
                >
                  <Counts value={run.report.counts.runtime} />
                  <Paragraph type="secondary">
                    运行时真值集：{run.runtime_truth.sha256 || "未提供"}
                  </Paragraph>
                  {metricTable(
                    run.report.metrics.filter((m) => m.domain === "runtime"),
                  )}
                </Card>
              </Col>
            </Row>
            {run.notes?.length > 0 && (
              <Alert
                type="info"
                showIcon
                title="证据范围说明"
                description={run.notes.map((note, i) => (
                  <div key={i}>{note}</div>
                ))}
              />
            )}
            <Card title="模式比较">
              <Text type="secondary">
                相同平台、代码、配置、镜像、数据集和运行时真值的批次才参与比较。CPU
                使用整体防御链路的相同统计口径。
              </Text>
              <Table
                size="small"
                rowKey="key"
                pagination={false}
                scroll={{ x: 760 }}
                dataSource={run.report.metrics}
                columns={[
                  {
                    title: "指标",
                    dataIndex: "key",
                    render: (key: string) => evaluationMetricNames[key] || key,
                  },
                  ...modes.map((mode) => ({
                    title: mode[0].toUpperCase() + mode.slice(1),
                    key: mode,
                    render: (_: unknown, m: EvaluationMetric) => {
                      const candidate = comparison[mode];
                      if (
                        mode !== run.mode &&
                        m.domain !== "runtime" &&
                        candidate &&
                        (!run.static_truth.sha256 ||
                          candidate.static_truth.sha256 !==
                            run.static_truth.sha256 ||
                          candidate.static_truth.dataset_hash !==
                            run.static_truth.dataset_hash ||
                          run.static_truth.dataset_hash !==
                            (run.static_dataset_hash || run.dataset_hash))
                      ) {
                        return (
                          <Text type="secondary">未评测 / 静态真值不可比</Text>
                        );
                      }
                      const measured = comparison[mode]?.report.metrics.find(
                        (x) => x.key === m.key,
                      );
                      return measured ? (
                        <>
                          <Text>{formatEvaluationMetric(measured)}</Text>
                          <br />
                          <Status value={measured.status} />
                          <Text type="secondary"> {comparison[mode].name}</Text>
                        </>
                      ) : (
                        <Text type="secondary">未评测 / 缺少可比批次</Text>
                      );
                    },
                  })),
                ]}
              />
            </Card>
            <Card title="分类、场景与 Connector 分解">
              <Tabs
                items={[
                  {
                    key: "asset_type",
                    label: "资产分类",
                    children: (
                      <>
                        <Space wrap>
                          {[
                            "agent",
                            "model",
                            "mcp",
                            "skill",
                            "plugin",
                            "tool",
                          ].map((type) => {
                            const c = run.report.breakdowns.find(
                              (x) =>
                                x.dimension === "asset_type" &&
                                x.domain === "asset" &&
                                x.name === type,
                            )?.counts;
                            return (
                              <Tag key={type}>
                                {type.toUpperCase()}：
                                {c
                                  ? `预期 ${expectedCount(c)} / 发现 ${discoveredCount(c)}`
                                  : "未评测"}
                              </Tag>
                            );
                          })}
                          {run.report.breakdowns
                            .filter(
                              (b) =>
                                b.domain === "asset" &&
                                b.dimension === "asset_type" &&
                                ![
                                  "agent",
                                  "model",
                                  "mcp",
                                  "skill",
                                  "plugin",
                                  "tool",
                                ].includes(b.name),
                            )
                            .map((b) => (
                              <Tag key={b.name}>
                                {b.name}：预期 {expectedCount(b.counts)} / 发现{" "}
                                {discoveredCount(b.counts)}
                              </Tag>
                            ))}
                        </Space>
                        <Paragraph>
                          恶意 Skill 命中{" "}
                          {run.report.risk_hits.malicious_skill ?? "未评测"}
                          ；恶意 MCP 命中{" "}
                          {run.report.risk_hits.malicious_mcp ?? "未评测"}
                          ；危险配置命中{" "}
                          {run.report.risk_hits.dangerous_config ?? "未评测"}
                        </Paragraph>
                        <Counts value={run.report.counts.risk} />
                      </>
                    ),
                  },
                  ...["scenario", "connector"].map((dimension) => ({
                    key: dimension,
                    label: dimension === "scenario" ? "攻击场景" : "Connector",
                    children: (
                      <Table
                        size="small"
                        rowKey="name"
                        dataSource={run.report.breakdowns.filter(
                          (b) =>
                            b.domain === "runtime" && b.dimension === dimension,
                        )}
                        pagination={false}
                        scroll={{ x: 680 }}
                        columns={[
                          { title: "维度", dataIndex: "name" },
                          {
                            title: "混淆矩阵",
                            render: (_, b) => <Counts value={b.counts} />,
                          },
                          {
                            title: "Precision / Recall / FPR / FNR",
                            render: (_, b) =>
                              ["precision", "recall", "fpr", "fnr"]
                                .map((key) =>
                                  formatEvaluationMetric(
                                    b.metrics.find(
                                      (m) => m.key === `runtime_${key}`,
                                    ),
                                  ),
                                )
                                .join(" / "),
                          },
                          {
                            title: "有效阻断 / 业务成功",
                            render: (_, b) =>
                              b.metrics
                                .slice(4)
                                .map((m) => formatEvaluationMetric(m))
                                .join(" / "),
                          },
                          {
                            title: "实例",
                            render: (_, b) => (
                              <Button
                                type="link"
                                onClick={() => {
                                  setFilters({
                                    domain: "runtime",
                                    [dimension]:
                                      b.name === "unknown" ? undefined : b.name,
                                  });
                                  setPage(1);
                                }}
                              >
                                查看证据
                              </Button>
                            ),
                          },
                        ]}
                      />
                    ),
                  })),
                ]}
              />
            </Card>
            <Card title="Decision、Response Action 与正常业务">
              <Row gutter={[16, 16]}>
                {[
                  ["Decision", run.report.decisions],
                  [
                    "Response Action",
                    {
                      executed: run.report.responses.executed ?? 0,
                      failed: run.report.responses.failed ?? 0,
                      would_block: run.report.responses.would_block ?? 0,
                      unknown: run.report.responses[""] ?? 0,
                    },
                  ],
                  ["正常业务", run.report.business],
                ].map(([label, values]) => (
                  <Col key={String(label)} xs={24} md={8}>
                    <Text strong>{String(label)}</Text>
                    <div>
                      {run.report.counts.runtime.total === 0 ? (
                        <Text type="secondary">未评测</Text>
                      ) : (
                        Object.entries(values as Record<string, number>).map(
                          ([key, value]) => (
                            <Tag key={key}>
                              {key || "未知"}：{value}
                            </Tag>
                          ),
                        )
                      )}
                    </div>
                  </Col>
                ))}
              </Row>
            </Card>
            <Card title="时延与 CPU 采样">
              <Paragraph type="secondary">
                P50、P95、P99 使用 nearest-rank 分位数；CPU
                为原始采样口径下的百分比。
              </Paragraph>
              <Table
                size="small"
                rowKey="id"
                pagination={false}
                dataSource={run.report.distributions}
                scroll={{ x: 1050 }}
                columns={[
                  {
                    title: "采样",
                    render: (_, d: EvaluationDistribution) => (
                      <>
                        <Text strong>
                          {d.kind} · {d.scope}
                        </Text>
                        <div>{d.basis}</div>
                      </>
                    ),
                  },
                  {
                    title: "样本 / 预期",
                    render: (_, d) => `${d.samples} / ${d.expected_samples}`,
                  },
                  {
                    title: "P50 / P95 / P99",
                    render: (_, d) =>
                      [d.p50, d.p95, d.p99]
                        .map((v) => (v === null ? "未评测" : v.toFixed(3)))
                        .join(" / ") + (d.kind === "cpu_pct" ? " %" : " ms"),
                  },
                  {
                    title: "采样窗口",
                    render: (_, d) => (
                      <>
                        {stamp(d.window_start)}
                        <br />
                        {stamp(d.window_end)}
                      </>
                    ),
                  },
                  {
                    title: "完整性",
                    render: (_, d) => <Status value={d.status} />,
                  },
                  {
                    title: "原始证据",
                    render: (_, d) => (
                      <Button
                        type="link"
                        onClick={() => {
                          setSelected(undefined);
                          void openArtifact(d.artifact_id);
                        }}
                      >
                        查看样本
                      </Button>
                    ),
                  },
                ]}
                locale={{ emptyText: "未评测：没有原始采样数据" }}
              />
            </Card>
            <Card id="evaluation-instances" title="实例与证据">
              <Space wrap className="evaluation-filters">
                {[
                  {
                    key: "domain",
                    label: "能力",
                    options: Object.entries(domains).map(([value, label]) => ({
                      value,
                      label,
                    })),
                  },
                  {
                    key: "outcome",
                    label: "识别结果",
                    options: ["tp", "fp", "tn", "fn", "unknown"].map(
                      (value) => ({ value, label: value.toUpperCase() }),
                    ),
                  },
                ].map((f) => (
                  <Select
                    key={f.key}
                    aria-label={f.label}
                    placeholder={`全部${f.label}`}
                    allowClear
                    style={{ width: 170 }}
                    value={
                      filters[f.key as keyof EvaluationFilters] as
                        | string
                        | undefined
                    }
                    options={f.options}
                    onChange={(value) => {
                      setFilters((v) => ({ ...v, [f.key]: value }));
                      setPage(1);
                    }}
                  />
                ))}
                <Button
                  onClick={() => {
                    setFilters({});
                    setPage(1);
                  }}
                >
                  清除筛选
                </Button>
              </Space>
              {instanceError && <Alert type="error" title={instanceError} />}
              <Table
                size="small"
                rowKey={(i) => `${i.domain}:${i.id}`}
                loading={instanceLoading}
                dataSource={instances}
                scroll={{ x: 900 }}
                pagination={{
                  current: page,
                  total: instanceTotal,
                  pageSize: 20,
                  showSizeChanger: false,
                  onChange: setPage,
                }}
                columns={[
                  { title: "实例", dataIndex: "id" },
                  {
                    title: "能力",
                    dataIndex: "domain",
                    render: (domain: string) =>
                      domains[domain as keyof typeof domains],
                  },
                  {
                    title: "场景 / Connector",
                    render: (_, i) =>
                      `${i.scenario || "—"} / ${i.connector || "—"}`,
                  },
                  {
                    title: "真值 / 预测",
                    render: (_, i) =>
                      `${truthValue(i.expected)} / ${truthValue(i.predicted)}`,
                  },
                  {
                    title: "结果",
                    dataIndex: "outcome",
                    render: (v: string) => (
                      <Tag
                        color={
                          v === "fp" || v === "fn"
                            ? "error"
                            : v === "unknown"
                              ? "warning"
                              : "success"
                        }
                      >
                        {v.toUpperCase()}
                      </Tag>
                    ),
                  },
                  {
                    title: "决策 / 响应",
                    render: (_, i) =>
                      `${i.decision || "未知"} / ${i.response_status || "未知"}`,
                  },
                  {
                    title: "证据",
                    render: (_, i) => (
                      <Button type="link" onClick={() => inspectInstance(i)}>
                        查看链路
                      </Button>
                    ),
                  },
                ]}
              />
            </Card>
            <Card
              title="批次来源与复现信息"
              extra={
                run.status === "running" && (
                  <Button
                    danger
                    onClick={async () => {
                      try {
                        await evaluationRequest(
                          `/${run.id}/cancel`,
                          "POST",
                          {},
                        );
                        await refreshRun();
                        await refreshHistory();
                      } catch (e) {
                        message.error(String(e));
                      }
                    }}
                  >
                    取消批次记录
                  </Button>
                )
              }
            >
              <Descriptions
                column={{ xs: 1, md: 2 }}
                items={[
                  ["批次 ID", run.id],
                  ["模式 / 平台", `${run.mode} / ${run.platform || "未记录"}`],
                  ["代码版本", run.code_version],
                  ["配置哈希", run.config_hash],
                  ["镜像摘要", run.image_digest],
                  ["运行时数据集哈希", run.dataset_hash],
                  ["静态数据集哈希", run.static_dataset_hash],
                  ["静态真值集", run.static_truth.sha256],
                  ["运行时真值集", run.runtime_truth.sha256],
                  ["执行开始", stamp(run.started_at)],
                  ["执行结束", stamp(run.finished_at)],
                  ["导入时间", stamp(run.created_at)],
                  ["证据目录", run.evidence_directory],
                  ["比较组", run.comparison_group],
                ].map(([label, value]) => ({
                  key: label,
                  label,
                  children: <Text copyable={!!value}>{value || "未记录"}</Text>,
                }))}
              />
              <Space>
                {[run.static_truth, run.runtime_truth]
                  .filter((t) => t.artifact_id)
                  .map((t, i) => (
                    <Button
                      key={t.artifact_id}
                      onClick={() => {
                        setSelected(undefined);
                        void openArtifact(t.artifact_id);
                      }}
                    >
                      {i === 0 && t === run.static_truth ? "静态" : "运行时"}
                      真值证据
                    </Button>
                  ))}
              </Space>
            </Card>
          </>
        )}
      </Spin>
      <Card className="evaluation-history" title="历史与当前批次">
        <Table
          size="small"
          rowKey="id"
          dataSource={runs}
          scroll={{ x: 700 }}
          pagination={{
            current: historyPage,
            total: totalRuns,
            pageSize: 20,
            onChange: setHistoryPage,
            showSizeChanger: false,
          }}
          columns={[
            {
              title: "批次",
              render: (_, r: EvaluationRun) => (
                <Button
                  type={r.id === runID ? "primary" : "link"}
                  onClick={() => setRunID(r.id)}
                >
                  {r.name} · {r.id.slice(0, 8)}
                </Button>
              ),
            },
            { title: "模式", dataIndex: "mode" },
            { title: "平台", dataIndex: "platform" },
            {
              title: "状态",
              render: (_, r: EvaluationRun) => <Status value={r.status} />,
            },
            {
              title: "执行时间",
              render: (_, r: EvaluationRun) => stamp(r.started_at),
            },
            {
              title: "两项能力",
              render: (_, r: EvaluationRun) => (
                <Space>
                  <span>
                    静态 <Status value={r.report.capability_status.static} />
                  </span>
                  <span>
                    运行时 <Status value={r.report.capability_status.runtime} />
                  </span>
                </Space>
              ),
            },
          ]}
          locale={{
            emptyText: (
              <Empty description="尚无评测批次。导入带实例、独立真值集和原始证据的评测报告后即可查看。" />
            ),
          }}
        />
      </Card>
      <Drawer
        title={selected ? `实例 ${selected.id}` : "原始证据"}
        open={!!selected || !!artifact || artifactLoading || !!artifactError}
        size="large"
        onClose={() => {
          artifactSequence.current++;
          setSelected(undefined);
          setArtifact(undefined);
          setArtifactError("");
          setArtifactLoading(false);
        }}
      >
        {selected && (
          <>
            <Descriptions
              column={1}
              items={[
                ["识别结果", selected.outcome.toUpperCase()],
                ["实际阻断", truthValue(selected.actually_blocked)],
                ["副作用发生", truthValue(selected.side_effect_occurred)],
                ["业务成功", truthValue(selected.business_success)],
              ].map(([label, children]) => ({ key: label, label, children }))}
            />
            {stages.map(([key, label]) => (
              <Card size="small" key={key} title={label}>
                {selected.evidence?.[key]?.length ? (
                  selected.evidence[key].map((id) => (
                    <Button
                      key={id}
                      type="link"
                      onClick={() => void openArtifact(id)}
                    >
                      {id}
                    </Button>
                  ))
                ) : (
                  <Text type="secondary">证据不足：未收集</Text>
                )}
              </Card>
            ))}
          </>
        )}
        {artifactLoading && <Spin />}
        {artifactError && (
          <Alert
            type="error"
            title="证据读取失败"
            description={artifactError}
          />
        )}
        {artifact && (
          <>
            <Descriptions
              column={1}
              items={[
                { key: "source", label: "来源", children: artifact.source },
                {
                  key: "hash",
                  label: "SHA-256",
                  children: <Text copyable>{artifact.sha256}</Text>,
                },
              ]}
            />
            <pre className="evaluation-raw">
              {(() => {
                try {
                  return JSON.stringify(JSON.parse(artifact.content), null, 2);
                } catch {
                  return artifact.content;
                }
              })()}
            </pre>
          </>
        )}
      </Drawer>
    </section>
  );
}
