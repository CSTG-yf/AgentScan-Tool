# DefenseClaw 面向 AgentRange 靶场改造实施计划书 v1.0

副标题：需求基线、技术方案、任务分解、联调验证与交付验收

版本：v1.0
日期：2026-07-19
适用范围：DefenseClaw 主工程与 `task/AgentRange-player-full` 测试靶场
实施约束：不运行 Go 测试；不建设 CI/CD；不依赖 GitHub 测试；不得使用靶场答案接口或固定实例特征参与检测。

## 1. 执行摘要

本计划将 DefenseClaw 从“面向已有 connector 的通用安全产品”改造成“可通过标准 inspect 接口保护 AgentRange 中 OpsPilot 与 Langflow 的检测、决策和审计中心”。改造坚持核心通用、靶场解耦：DefenseClaw 核心只新增通用身份上下文、运行时检查和规则能力；AgentRange 的请求格式、证据落盘、场景回放与指标计算均在靶场适配层完成。

最终应呈现一条可演示、可复核的安全闭环：静态盘点发现危险 Skill/MCP 与配置风险；运行时在 Prompt、Tool Call、Tool Result、Final Response 和 Langflow Ingress 等观察点检查行为；observe 模式只告警留证，action 模式在危险副作用发生前阻断；审计证据按 instance/trace 还原攻击链；benchmark 输出 Recall、FPR、延迟、资源增量和正常业务成功率。

## 2. 背景与问题定义

AgentRange-player-full 模拟一个由 OpsPilot Agent、Langflow、LLM Stub、PostgreSQL、8 个 MCP、7 个 Skill、内部网络和模拟外网组成的企业 Agent 环境。靶场包含提示注入、恶意 Skill/MCP、敏感数据外传、下载执行、跨租户访问、命令执行和正常业务等流量。

原 DefenseClaw 已具备 Skill/MCP 扫描、CodeGuard、`/api/v1/inspect/*`、规则引擎、observe/action、审计与可观测能力，但缺少与靶场一致的身份上下文、四阶段调用、Langflow 入站保护、统一 RangeEvent 证据、靶场资产分母、攻击链还原和可复现三模式 benchmark。因此需要同时改造 DefenseClaw 通用能力与 AgentRange 适配层，不能只在靶场脚本中伪造检测结果。

## 3. 改造目标与成功定义

### 3.1 业务目标

- 在 DefenseClaw 未配置时保持原靶场行为，不破坏 baseline。
- 在 observe 模式完整记录潜在阻断，但不造成业务中断。
- 在 action 模式于危险副作用发生前阻断高置信度 HIGH/CRITICAL 行为。
- 支持资产、风险、事件、决策、攻击链和指标结果的端到端追溯。
- 形成可按模块分配、独立开发、按合同集成的任务包。

### 3.2 量化验收目标

| 指标 | 目标 | 统计口径 |
|---|---:|---|
| Agent 相关资产盘点准确率 | ≥99% | 以冻结资产清单为分母 |
| 恶意 Skill/MCP 与配置风险识别准确率 | ≥95% | 以风险 taxonomy 与人工标签为准 |
| 恶意实例 Recall | ≥95% | instance 级 TP/(TP+FN) |
| 正常实例 FPR | <5% | instance 级 FP/(FP+TN) |
| inspect 阻断响应 p95 | <1 秒 | 适配器发起检查至获得决策 |
| DefenseClaw 增量 CPU | ≤5% | 同规格 baseline/observe/action 对照 |
| normal 业务中断 | 0 | 正常实例成功率与错误清单 |

### 3.3 非目标

- MVP 不扩展其他 Agent connector，不以 eBPF 作为阻断前置条件。
- 不把外部 LLM Judge 放进默认同步阻断链路。
- 不读取 `/admin/trajectories`、scenario ID、固定 prompt 或 instance ID 作为检测特征。
- 不新增 CI/CD、GitHub Actions 或远端自动测试流程。
- 按项目约束不运行 Go 测试；Go 代码仅执行格式化、静态编译和接口烟雾验证。

## 4. 设计原则与安全边界

### 4.1 核心通用、适配解耦

DefenseClaw 核心接收通用字段：connector、session_id、tool、args、content、direction 和 context。核心不得识别 AgentRange 场景编号或靶场固定样本。OpsPilot JWT、tenant、MCP 名称及 Langflow 请求转换由适配层负责。

### 4.2 检测与 Ground Truth 隔离

Ground Truth 仅供 benchmark 在请求结束后进行 instance 级 join。运行时检测模块不得读取 Ground Truth、轨迹管理接口或期望标签。统计程序需将无效请求单独计数，不能把超时或 5xx 伪装成安全阻断。

### 4.3 最小暴露与留痕

inspect API 仅绑定受限地址或通过受控转发供 Docker 访问，必须使用 Token。证据默认脱敏，不记录 Token；需要原始 PII 时走显式审计开关。故障降级、超时和 fail-open/fail-closed 选择均进入证据与报告。

### 4.4 确定性快路径

同步阻断使用本地确定性规则与身份/网络策略，确保 p95 小于 1 秒。语义复核、复杂关联和报告生成走异步或离线路径，不阻塞正常 Agent 调用。

## 5. 目标架构与数据流

### 5.1 组件职责

| 组件 | 职责 | 禁止承担的职责 |
|---|---|---|
| DefenseClaw Gateway | 统一 inspect、规则扫描、模式降级、策略决策、审计 | 识别场景 ID、读取 Ground Truth |
| OpsPilot Adapter | 四阶段转换、JWT/tenant 上下文传递、403 阻断 | 自行判定场景真值 |
| Langflow Guard | 检查方法、路径、查询串、JSON/Multipart 内容 | 直接暴露未鉴权 Gateway |
| Evidence Writer | 输出 RangeEvent JSONL、关联 ID、延迟与降级原因 | 写入 API Token 或秘密明文 |
| Attack Chain Builder | 按 instance/trace 还原 DAG 与阻断点 | 作为同步阻断依赖 |
| Benchmark/Report | 三模式回放、真值 join、指标汇总 | 把无效请求计入 TP/TN |

### 5.2 运行时顺序

1. AgentRange 产生带 `X-Instance-Id` 的请求。
2. OpsPilot 或 Langflow 适配器构造通用 inspect 请求并附加 Token。
3. DefenseClaw 先检查身份 scope，再检查静态 allow/block、工具参数、内容、CodeGuard 与网络策略。
4. Gateway 返回 action、raw_action、would_block、severity、findings、mode 和 reason。
5. observe 模式将潜在 block 降级为 allow；action 模式保留 block。
6. 适配器在危险副作用前抛出阻断或返回 403，并写入 RangeEvent。
7. 离线模块将事件、决策与原始引用关联为 AttackChain，并由报告模块汇总指标。

## 6. 详细需求基线

### 6.1 FR-01 通用 inspect 接口

- 保持并复用 `/api/v1/inspect/request`、`/response`、`/tool`、`/tool-response`。
- `/tool` 请求支持可选 `context`，其内容为上游已认证主体与授权 scope；未知结构必须向后兼容。
- 响应至少包含 `action`、`raw_action`、`would_block`、`severity`、`confidence`、`findings`、`reason` 和 `mode`。
- observe 模式不得返回会触发业务中断的 action，但必须保留原始潜在决策。

### 6.2 FR-02 身份与租户授权

- OpsPilot 从 JWT/请求上下文提取 principal tenant，并写入 inspect `context.scope.tenant`。
- 工具参数出现目标 tenant 时，DefenseClaw 必须比较主体 scope 与请求目标。
- `tenant="*"`、跨租户或缺失必要授权时产生 HIGH finding；同租户正常查询放行。
- 规则只依赖通用 scope/tenant 字段，不依赖 ACME、Globex 等固定名称。

### 6.3 FR-03 OpsPilot 四阶段适配

- Prompt/完整 messages 调用 `/inspect/request`。
- Tool Call 在执行前调用 `/inspect/tool`，并传递 tool、args、MCP server、session 和 context。
- Tool Result 在写回模型前调用 `/inspect/tool-response`。
- Final Response 在返回用户前调用 `/inspect/response`。
- 未配置 Gateway 时四阶段均为 disabled allow；action block 映射为受控异常/HTTP 403。

### 6.4 FR-04 Langflow 入站保护

- 由 langflow-guard 代理宿主端口，真实 Langflow 不直接暴露。
- 检查 HTTP 方法、路径、查询串、Content-Type、JSON/表单/Multipart 内容。
- 保留必要请求头与正文转发，过滤 hop-by-hop 头。
- Gateway 不可用时按配置执行 fail-open 或 fail-closed，并记录降级原因与延迟。

### 6.5 FR-05 运行时行为规则

- 覆盖下载后执行、管道进 shell、定时任务/路径穿越、C2 回连、敏感文件读取、通配租户和跨租户访问。
- 静态描述规则覆盖 ignore/隐藏/不得告知/先读凭据、隐藏工具、启动外传和高危执行语义。
- 每条规则具备稳定 rule_id、severity、confidence、适用 direction、1 个恶意样本和至少 2 个良性样本。
- 单条本地规则合同执行时间上限 5ms，规则不得包含场景编号。

### 6.6 FR-06 模式、策略与故障处理

- baseline：不配置 API Base，行为与原靶场一致。
- observe：潜在 block 只留证，业务 action 为 allow。
- action：高置信度 HIGH/CRITICAL 确定性副作用在执行前阻断。
- 默认 fail-open 保障业务连续性；高危演示可显式 fail-closed。
- 合法 threat-intel 查询、同租户读取、正常 Skill 与正常响应不得误杀。

### 6.7 FR-07 统一事件与证据

- 每条 RangeEvent 必须包含 event_id、instance_id、trace_id、timestamp、stage、asset_id、direction、payload、decision 和 raw_ref。
- decision 至少包含 action、mode、severity、reason、findings 和 latency_ms。
- Token、Authorization 头和 secrets.env 内容不得写入证据。
- 文件写入需线程安全；Compose 将证据目录映射到宿主机 `integration/reports`。

### 6.8 FR-08 静态资产与风险盘点

- 冻结资产分母：1 Agent、1 Model、1 Framework、1 Database、8 MCP、7 Skill、2 Network、6 Host Port，共 27 项。
- 输出资产唯一 ID、类型、位置、关系边和 Finding。
- 风险 taxonomy 至少覆盖隐藏提示、tools/list 与 tools/call 不一致、启动信标、shell=True、任意文件读取、弱 JWT、服务账号越权传播和明文凭据。

### 6.9 FR-09 攻击链还原

- 按 instance_id/trace_id 关联 Prompt、Skill、LLM Tool Call、MCP、文件/数据库/网络访问和 Decision。
- 输出节点、边、sequence 类型、evidence level、阻断点、未执行副作用和 raw_ref。
- 优先支持敏感读取→同步/外联、外部内容→命令执行、身份 scope→跨租户查询、Langflow ingress→执行链。

### 6.10 FR-10 Benchmark 与报告

- 固定 `seed=1337`、`total=5200`、`malicious_target=80`，覆盖 C1-A/B、C2-A/B/C/D 与 normal。
- 分别输出 baseline、observe、action 原始 JSON；按 instance join Ground Truth 计算 TP/FP/TN/FN。
- 输出 Precision、Recall、FPR、FNR、normal success rate、inspect p50/p95/p99、端到端延迟与 CPU/内存增量。
- 最终报告必须显式标出未测指标、无效请求和未达到阈值项，禁止用推断替代实测。

### 6.11 NFR-01 性能与可用性

- 默认 inspect client 超时 250ms，可通过环境变量覆盖。
- 单次阻断响应目标小于 1 秒，正常业务不因报告/关联模块阻塞。
- 证据写入失败不得泄露秘密；按模式选择是否影响业务。

### 6.12 NFR-02 可维护性与兼容性

- 新字段全部可选，保持已有 connector 和旧调用者兼容。
- 靶场配置集中在 `task/AgentRange-player-full`，核心仓不保存场景样本答案。
- Schema、规则与指标口径通过 Python 合同测试冻结。

## 7. 接口与数据合同

### 7.1 Tool Inspect 请求示例

```json
{
  "tool": "customer_db.query",
  "args": {"tenant": "target-tenant", "sql": "SELECT ..."},
  "direction": "tool_call",
  "session_id": "instance-uuid",
  "connector": "opspilot",
  "mcp_server_name": "customer_db",
  "context": {"principal": {"subject": "user-123"}, "scope": {"tenant": "source-tenant"}}
}
```

### 7.2 决策响应示例

```json
{
  "action": "allow",
  "raw_action": "block",
  "would_block": true,
  "severity": "HIGH",
  "confidence": 1.0,
  "findings": ["AUTHZ-TENANT-SCOPE"],
  "reason": "tool arguments exceed authenticated principal scope",
  "mode": "observe"
}
```

## 8. 代码改造清单

| 改造域 | 主要路径 | 计划动作 |
|---|---|---|
| DefenseClaw 核心 | `internal/gateway/inspect.go`、`rules.go` | 增加通用 context 授权检查和规则映射，保持模式语义 |
| 核心验证 | `internal/gateway/agentrange_adapter_test.go` | 保留为源码合同样例；本项目不执行 Go 测试 |
| OpsPilot Adapter | `task/AgentRange-player-full/opspilot-app/security/defenseclaw.py` | 四阶段、Token、超时、fail mode、证据写入 |
| Langflow Guard | `task/AgentRange-player-full/integration/langflow_guard.py` | 入站检查、403 阻断、转发、证据写入 |
| Compose/环境 | `docker-compose.yml`、`.env.example` | 受控 Gateway 地址、Token、证据卷、保护端口 |
| 合同与资产 | `contracts/`、`integration/static_inventory.py` | 冻结 schema、资产、场景矩阵、风险 taxonomy |
| 规则与策略 | `integration/runtime_rules.yaml`、`policy.yaml` | 攻击/良性合同、三模式与 scope/egress 策略 |
| 关联与报告 | `attack_chain.py`、`report.py` | DAG、证据索引、验收汇总 |
| Benchmark | `scenario-runner/runner.py`、`bench/benchmark.py` | Ground Truth 隔离、三模式回放、指标计算 |

## 9. 实施任务分解与分配

| 任务 ID | Owner 角色 | 依赖 | 交付物 | 完成标准 |
|---|---|---|---|---|
| DC-M0-01 | 架构/数据负责人 | 无 | contracts、27 项资产、7 类场景矩阵 | Schema 校验通过，统计口径冻结 |
| DC-M1-01 | DefenseClaw 核心负责人 | M0 | 通用 context、tenant scope 检查 | 同租户 allow，跨租户/通配 block；无场景硬编码 |
| DC-M2-01 | Agent 集成负责人 | M0/M1 | OpsPilot 四阶段 Adapter | disabled/observe/action/failure 合同通过 |
| DC-M2-02 | Agent 集成负责人 | M0/M1 | Langflow Guard 与 Compose | 真实服务不直暴露，危险入站可阻断 |
| DC-M3-01 | 检测规则负责人 | M0 | 六类行为规则与良性夹具 | 每条 attack+2 benign，单例 <5ms |
| DC-M4-01 | 策略负责人 | M1/M3 | baseline/observe/action、scope/egress | 高危副作用阻断，合法流量放行 |
| DC-M5-01 | 关联审计负责人 | M2/M3 | AttackChain DAG 与 raw_ref | 至少三类完整链可复核 |
| DC-M6-01 | 性能测试负责人 | M2-M5 | 5200 三模式 benchmark | 指标口径一致，原始结果可复现 |
| DC-M7-01 | 集成交付负责人 | 全部 | 操作手册、Demo、最终报告 | 空环境可按文档重现闭环 |
| DC-M8-01 | 质量负责人 | 全部 | 验收证据索引与遗留项 | 每项需求映射到测试/报告，无伪造结论 |

## 10. 实施顺序与里程碑

### 阶段 A：计划与合同冻结

- 发布本计划书 v1.0。
- 冻结资产、事件、决策、Ground Truth 和攻击链 Schema。
- 建立需求追踪矩阵，禁止下游私自修改统计口径。

### 阶段 B：DefenseClaw 核心通用改造

- 为 Tool Inspect 增加可选 context。
- 在静态 allow 前执行 tenant/scope 授权检查，避免 confused deputy。
- 确认 observe/action、raw_action 与 would_block 语义一致。
- 执行 gofmt 与 Go build，不运行 Go 测试。

### 阶段 C：AgentRange Adapter 与规则

- 接入 OpsPilot 四阶段与 Langflow ingress。
- 配置证据卷、Token、超时和 fail mode。
- 建立确定性行为规则、良性夹具与 Python 合同测试。

### 阶段 D：关联、Benchmark 与报告

- 生成静态盘点、运行时事件与 AttackChain。
- 完成 baseline/observe/action 三模式回放。
- 输出最终报告、阈值结果、误报漏报和降级说明。

## 11. 验证方案

### 11.1 允许执行的验证

- Python：contracts、integration、OpsPilot、scenario-runner、bench 的 pytest。
- 结构：JSON Schema、YAML/Compose 配置、Python compileall。
- Go：`gofmt`、`go build` 或仅构建目标 Gateway；不执行 `go test`。
- 运行：Docker Compose 健康检查、baseline/observe/action 烟雾回放与 5200 全量回放。

### 11.2 核心验收用例

| 用例 | 模式 | 期望 |
|---|---|---|
| DefenseClaw 未配置 | baseline | 所有适配点 disabled allow，原靶场可用 |
| 恶意下载执行 | observe | action=allow、raw_action=block、would_block=true |
| 恶意下载执行 | action | 工具执行前 block/403，副作用未发生 |
| 同租户查询 | action | allow，无 AUTHZ finding |
| 跨租户/通配租户 | action | HIGH block，记录主体与目标 scope |
| 合法 threat-intel 出网 | action | allow，不命中外传规则 |
| Gateway 超时 | fail-open | 业务继续，记录 integration-fail-open |
| Gateway 超时 | fail-closed | 受控阻断，记录不可用原因 |

## 12. 联调与运行方案

### 12.1 联调前置

- 本机启动受限监听的 DefenseClaw Gateway，并获取 API Token。
- `.env` 配置 `DEFENSECLAW_API_BASE=http://host.docker.internal:18970` 与 Token。
- 重建 OpsPilot 和 Langflow Guard，确认真实 Langflow 无宿主直连端口。
- 清理旧证据并固定 seed，避免不同模式数据串扰。

### 12.2 三模式运行

- baseline：API Base 为空，记录原始成功率和端到端延迟。
- observe：Gateway 设置 observe，确认所有潜在阻断只留证。
- action：Gateway 设置 action，确认高危副作用在执行前中止。
- 三组结束后统一生成 AttackChain 与 final-report，保留每组原始 JSON。

## 13. 风险与降级方案

| 风险 | 影响 | 控制措施 | 降级 |
|---|---|---|---|
| Gateway 对 Docker 不可达 | observe/action 无检测 | 受限转发、健康检查、Token | 默认 fail-open 留痕 |
| 规则过宽 | normal 误杀 | attack+2 benign、FPR 门禁 | observe 回滚阈值 |
| 证据包含敏感信息 | 数据泄露 | 默认脱敏、禁止记录 Token | 停止证据写入并报警 |
| Ground Truth 污染检测 | 指标失真 | 模块隔离、只在 post-run join | 验收直接判失败 |
| 资源采样不可用 | CPU 目标不可证 | 报告标记 unavailable | 不宣称达标，补测 |
| Go 验证受限 | 核心回归风险 | gofmt、build、HTTP 烟雾、Python 合同 | 列入遗留风险 |

## 14. 交付物与验收证据

- 本计划书与需求追踪矩阵。
- DefenseClaw 核心通用改造源码及构建结果。
- AgentRange contracts、Adapter、规则、策略、攻击链和报告代码。
- 静态资产/风险报告、运行时 JSONL、AttackChain JSON。
- baseline/observe/action 原始 benchmark 和 summary。
- Windows/Linux 操作手册、固定 Demo 顺序和失败降级说明。

验收结论只允许三种状态：通过、未通过、未测试。没有原始证据的指标必须标记未测试，不得根据单元测试或设计推断为通过。

## 15. 理想呈现效果

演示开始时，静态盘点显示 27/27 资产与 8 类关键风险；随后在 observe 模式重放攻击，业务继续但界面/报告显示 would-block、规则、租户、资产、延迟和原始引用；切换 action 后，高危 Tool Call 或 Langflow 入站请求在副作用发生前收到 403/受控异常，数据库、文件和 C2 Sink 中没有新增危险结果；最后以 instance 为单位展示完整攻击链和三模式指标对照。

理想交付结果不是“多写几条靶场正则”，而是形成一套可迁移的 DefenseClaw 接入范式：任何新 Agent 只需实现标准 Adapter 与身份上下文映射，即可复用相同的 Gateway、规则、策略、证据、攻击链和 benchmark 方法。

## 16. 需求追踪矩阵

| 需求 | 代码/配置 | 验证证据 | 责任任务 |
|---|---|---|---|
| FR-01/02 | `internal/gateway/inspect.go` | build、HTTP/合同用例 | DC-M1-01 |
| FR-03 | OpsPilot `defenseclaw.py` | Adapter pytest、事件 JSONL | DC-M2-01 |
| FR-04 | `langflow_guard.py`、Compose | Guard pytest、403 烟雾 | DC-M2-02 |
| FR-05 | `runtime_rules.yaml` | rule-contract.json | DC-M3-01 |
| FR-06 | `policy.yaml`、Gateway mode | policy pytest、三模式结果 | DC-M4-01 |
| FR-07 | contracts 与 Evidence Writer | Schema 校验、JSONL | DC-M0-01/M2 |
| FR-08 | assets、taxonomy、inventory | static-scan.json | DC-M0-01 |
| FR-09 | `attack_chain.py` | attack-chains.json | DC-M5-01 |
| FR-10 | runner、benchmark、report | baseline/observe/action/summary | DC-M6-01/M7 |
| NFR-01/02 | timeout、fail mode、兼容字段 | 延迟/回归/降级报告 | DC-M8-01 |

## 17. 变更控制

任何修改资产分母、Ground Truth、TP/FP/TN/FN 定义、阻断阈值或 fail mode 默认值的变更，必须更新本计划书版本和追踪矩阵，并重新运行 normal 回归。新增规则必须携带恶意样本和至少两个容易混淆的良性样本。交付阶段不得新增 CI/CD 或 GitHub 测试代码。
