# 赛题能力与指标看板（编号 1）

桌面导航的 **能力评测** 页从本机 Gateway 读取评测批次。指标由后端依据独立真值、实例、原始采样和证据计算，桌面不再在编译时导入比赛结果 JSON。

本次实现覆盖编号 1 的看板、评测记录、指标计算、报告导入和证据查询。评测报告导入保存为新批次；`running` 状态表示外部评测的当前记录，取消仅关闭该记录并保留证据。自动运行三模式和停止实际回放属于编号 2。

## 页面能力

- 同页展示资产风险识别和运行时监控阻断两项能力的达标情况。
- 资产盘点准确率 ≥99%、漏报率 <5%；风险识别准确率、召回率 ≥95%、漏报率 <5%。
- 检出率 ≥95%、误报率 <5%、有效阻断率 ≥95%、Inspect P95 <1000ms、整体防御链路 Action P95 CPU 减 Baseline P95 CPU ≤5 个百分点、正常业务成功率 100%。
- Agent、模型、MCP、Skill、插件、工具分类，恶意 Skill/MCP 和危险配置命中，漏报和误报实例筛选。
- TP、FP、TN、FN、未知数量；Decision 与 executed / failed / would_block 分开统计。
- 按场景、Connector 展示 Precision、Recall、FPR、FNR、阻断率和业务成功率。
- 显示 Inspect、端到端、Gateway、各容器和整体防御链路的原始样本数量、统计口径、窗口、P50/P95/P99。分位数使用 nearest-rank，可能与旧报告采用的 round-index 方法略有差异。
- 历史分页、当前批次、三模式比较，以及 实例 → Event/Scan → Detection → Decision → Response → 副作用 → Attack Chain 证据钻取。原始证据保存在数据库并附 SHA-256，原文件路径用于定位来源。

完整代码、配置、镜像、数据集与执行时间缺失时，整体能力显示“证据不足”。无分母显示“未评测”；未知实例或批次未完成显示“证据不足”；原始采样不全显示“采样不完整”。静态六类资产没有完整覆盖时，整体静态能力不显示达标，已有样本的单项指标仍可查看。实际阻断必须同时有执行回执、明确的阻断结果和副作用未发生的验证证据。

模式比较要求比较组、平台、代码版本、配置哈希、镜像摘要、运行时数据集和运行时真值一致，且元数据齐全。CPU 只使用相同统计口径的完整整体防御链路采样；容器 CPU、Gateway CPU 单独显示。旧历史包缺少配置哈希和镜像摘要时，不计算跨模式 CPU 增量。

## 持久化与接口

追加数据库迁移创建 `evaluation_runs`、`evaluation_instances`、`evaluation_metrics`、`evaluation_artifacts`。一次导入在事务内保存记录，重启后可以继续读取；重复导入创建新 ID。

| 接口 | 作用 |
| --- | --- |
| `GET /api/v1/evaluations?mode=&status=&limit=20&offset=0` | 历史批次，最多每页 200 条 |
| `GET /api/v1/evaluations/latest` | 最近导入批次，可用 mode/status 过滤 |
| `GET /api/v1/evaluations/{id}` | 批次、指标和采样摘要 |
| `GET /api/v1/evaluations/{id}/instances?domain=&outcome=&scenario=&connector=` | 可分页的实例和证据索引 |
| `GET /api/v1/evaluations/{id}/artifacts/{artifact_id}` | 原始 JSON 证据文本及 SHA-256 |
| `GET /api/v1/evaluations/{id}/comparison` | 可比的 Baseline/Observe/Action 批次 |
| `POST /api/v1/evaluations` | 导入规范报告（最大 32 MiB）；后端重新计算指标 |
| `POST /api/v1/evaluations/{id}/cancel` | 取消未完成的评测记录，保留已收集证据 |

接口使用现有 Gateway token 和 CSRF 防护。桌面通过限定在评测路由的 Tauri 命令访问。浏览器开发预览可用 `TRACEBASTION_EVALUATION_PROXY` 指定本机 Gateway，并通过 `TRACEBASTION_GATEWAY_TOKEN` 在代理进程中提供认证，不把凭证放进浏览器。

## 报告合同

顶层字段包括 `name`、`mode`、`platform`、`code_version`、`config_hash`、`image_digest`、`dataset_hash`（运行时公开样本哈希）、`static_dataset_hash`（静态扫描目标哈希）、`comparison_group`、`started_at`、`finished_at`、`status`、`evidence_directory`、`notes`、`static_truth`、`runtime_truth`、`instances`、`series`、`artifacts`。

真值引用格式为 `{"artifact_id":"static-truth","dataset_hash":"目标哈希"}`。静态和运行时真值必须引用不同的 `ground_truth` artifact；静态真值与 `static_dataset_hash` 绑定，运行时真值与 `dataset_hash` 绑定。未提供 `static_dataset_hash` 的旧报告使用 `dataset_hash`。哈希不匹配时保留证据并将该能力的实例标记未知。

Artifact 格式为 `{"id":"proof","kind":"event","source":"文件:行号","content":"原始 JSON 文本","sha256":"content UTF-8 字节的 SHA256"}`。`content` 是字符串，避免 JSON 重新排版破坏校验。独立真值文本包含 `{"asset":{"asset-id":true},"risk":{"rule:asset":true}}` 或 `{"runtime":{"instance-id":true,"benign-id":false}}`。运行时真值没有的实例保留为未知；静态真值外发现的资产或风险作为 FP。缺少的真值实例自动补入未知记录，禁止静默缩小分母。

实例字段包括 `id`、`domain`（asset/risk/runtime）、`asset_type`、`risk_kind`、`scenario`、`connector`、`predicted`、`business_success`、`decision`、`response_status`、`actually_blocked`、`side_effect_occurred`，以及按阶段引用 artifacts 的 `evidence`。布尔字段可以为 null。客户端提供的 expected/outcome/report 会被后端重新生成。

采样序列含 `id`、`kind`（inspect_ms/e2e_ms/cpu_pct）、`scope`、`basis`、`window_start`、`window_end`、`expected_samples`、`complete`、`artifact_id`、`samples`（`[{"at":"RFC3339 时间","value":12.3}]`）。原始 artifact 必须包含相同采样数组；CPU 还核对窗口边缘和采样间隔覆盖，缺失时不显示通过。

## 从已有结果导入

先转换为规范报告，再在能力评测页点击“导入评测报告”。转换器仅读取已有证据，不启动靶场或修改检测算法：

```bash
python -m integration.evaluation_export \
  --run-dir bench/runs/20261009-mac-full-pair/action \
  --platform macos-arm64 \
  --output bench/runs/dashboard-imports/action.json

python -m integration.evaluation_export \
  --static-scan docs/evidence/20260930-static-independent/static-scan.json \
  --static-truth integration/agentrange_contracts/static-ground-truth.yaml \
  --output bench/runs/dashboard-imports/static.json
```

静态转换需要 PyYAML。运行时导入核对 run manifest 中的公开样本与独立真值哈希。可同时提供 `--static-scan`、`--static-truth` 把两项能力附到同一批次；静态目标哈希不匹配时显示证据不足。配置哈希、镜像摘要可用 `--config-hash`、`--image-digest` 指定，但只能填写该历史运行实际记录的值。不要用当前配置补写历史值。

运行时转换按实例保留前三条原始审计事件和全部风险事件，恶意实例保留完整攻击链；每份证据均指出源文件和行号，完整原始包仍保留在原目录。历史连接器分组来自独立真值，仅用于评测统计。运行时标签与静态标签不会进入生产检测接口。

## 2026-10-12 实现验收

- 9 项 Go 评测指标、存储与 API 合同测试通过，4 项 Python 证据转换测试通过。整个审计存储包测试通过。
- TypeScript 检查和 Vite 生产构建通过。浏览器核对两项能力状态、场景分解、场景筛选及 C1-A-102 的原始执行回执和 SHA-256。
- 真实历史报告经 HTTP 导入成功：5,200 个运行时实例和 40 个静态实例。2026-10-09 运行时为 TP=80、TN=5,120、FP=FN=unknown=0。旧静态真值与本轮目标哈希不一致时保持未知；旧批次缺少配置与镜像元数据时不进行 CPU 增量比较。
- 完整 Gateway 回归中，既有 `TestFileReadGuardHTTPChain`、`TestFileReadGuardConnectorOutputs`、`TestFileReadGuardShellReturnsZeroBytes`、`TestFileReadGuardRejectsNonemptySubstitute` 在本机失败，原因为缓存中的替代文件不是空普通文件。相关代码和测试未在编号 1 中修改；这些测试不调用新评测模块。全仓库测试与门禁属于编号 4。

## 当前靶场静态能力实测

2026-10-12 已按当前靶场冻结独立真值并执行静态扫描：[证据与导入文件](evidence/20261012-static-current/README.md)。资产发现 27/37，漏报 10 个独立 MCP 工具，资产准确率 100%、漏报率 27.03%；13 项标注风险全部识别。插件没有样本，保持未评测。看板显示资产风险识别能力未达标。可用 `integration.static_run` 复现扫描、评分、版本与哈希记录以及看板文件导出。

## 独立 MCP 工具识别优化（2026-10-13）

新增已注册工具的 AST 发现，使用原冻结真值复测：37 项资产全部发现，10 个独立工具全部发现，13 项风险全部识别，五项静态指标达标。[新证据](evidence/20261013-static-mcp-tools/README.md)。插件无样本继续保持未评测。Desktop v0.2.3 随安装包提供扫描器与参考评测，靶场控制页可发起真实静态扫描。

## 公开靶场运行时记录（Desktop v0.2.4）

安装包首次启动后会将 [2026-10-09 防护组回放](evidence/20261009-mac-full-pair/README.md) 导入本机 **能力评测**，用户无需另行导入文件即可查看 5,200 个实例及逐项的审计、Detection、执行回执、副作用探针和性能采样。记录来自历史源码 `11d6a7f` 的本机公开靶场，80/80 攻击在副作用前阻断、5,120/5,120 正常请求成功；它不会出现在实时告警或阻断列表中。公开副本移除了自由文本提示词、请求/响应正文和攻击链正文。原始历史数据未记配置哈希和镜像摘要，故看板不据此显示跨模式 CPU 增量或整体运行时能力达标；原回放报告中的 0.19 个百分点 CPU 增量和 12/12 门槛结果仍可在配套报告中查阅。

## 安全总览中的公开实测数据（Desktop v0.2.5）

安全总览读取随安装包导入的评测记录，展示当前靶场静态扫描和运行时攻防回放的摘要，并保留实测日期和“历史结果 · 非实时告警”标识。实时事件、攻击链和防护状态仍只读取本机当前运行数据；点击实测卡片可进入能力评测查看逐实例证据。静态扫描展示资产识别、漏报和风险识别；运行时回放展示攻击检出、实际阻断、误报、正常请求成功率与 Inspect P95。
