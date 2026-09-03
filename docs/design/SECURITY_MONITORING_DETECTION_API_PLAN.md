# 安全监测、异常阻断与攻击链接口改造方案

> 状态：已实现基线（后端接入与 Go 定向验证完成，待 Windows 管理员环境端到端验收）
> 适用版本：当前工作树（基于 `main` 合并 `qjq` 的提交 `a768421d`）  
> 范围：Agent 发现、静态资源检测、运行时事件检测、异常阻断、攻击链、桌面端自动/手动数据同步

## 1. 改造前基线与本轮判断

本节保留改造前审计结论，用来解释为什么要拆分查询、任务、检测和执行；本轮已经落地的结果见第 13 节，不能再把本节的“当前”描述当作现状。

项目已经具备较完整的数据表和多数查询接口，也已经形成以下自动链路：

```text
Guardrail / Agent Hook / Proxy / OS Runtime Event
  -> behavior_events
  -> Runtime Detection Engine
  -> runtime_detections
  -> Runtime Decision Engine
  -> runtime_decisions
  -> runtime_response_actions
  -> runtime_attack_chains
```

改造前还不能把整套功能定义为“闭环可用”，主要原因是：

1. Windows 进程守护上报到旧的 `/api/v1/behavior-events`，只入库，不进入统一检测引擎。
2. 除网络阻断外，Guardrail、Agent Hook、MCP、文件和进程类响应通常只记录为 `dispatched`，没有真正调用执行器；手动阻断后却会直接把 Detection 标记为 `mitigated`。
3. 前端已经封装运行时决策、手动阻断和 enforcement 接口，但没有任何页面使用这些函数。
4. Agent 页面“扫描”、事件页面“重新检测”、攻击链页面“刷新”大部分只是重新 GET 数据；其中事件页面没有历史事件重新检测接口。
5. Agent 的 GET 查询会同步执行本机发现并写数据库，查询与扫描副作用混在一起。
6. 扫描任务状态只放在 Gateway 内存中；前端不轮询任务状态，而是固定等待若干秒后重新拉数据。
7. 桌面端“自动刷新任务”由 React `setInterval` 执行，不是后台调度；App 关闭后不运行，并且静态资源、事件检测任务的刷新对象接错或没有更新页面状态。
8. 攻击链虽已有持久化模型，但仍保留基于字符串启发式的页面级回退重建，且分页总数、重建任务和历史规则升级缺乏完整合同。

因此本轮目标不应只是“再补几个 GET 接口”，而应把命令、任务、查询、执行结果四类语义彻底分开。

## 2. 明确后的产品目标

### G1：Agent 发现

- 后台按计划自动发现本机 Agent，并把快照写入 `agents`。
- 用户可以手动发起一次 Agent 发现任务。
- `GET /agents` 只读数据库，不能再触发系统扫描。
- 页面能显示本次发现任务的进度、完成时间、错误和数据版本。

### G2：静态资源发现与检测

- Watcher 负责实时发现和周期重扫；App 是否打开不影响执行。
- 用户可扫描单个资源、单个 Agent 或全部 Agent。
- 所有手动扫描返回可查询的 `job_id`，页面按任务状态刷新，不使用固定延时猜测完成时间。
- 资源详情、Finding 和扫描历史全部以数据库为准。

### G3：攻击事件监测

- 所有来源统一进入同一个运行时事件入口和同一套事件词汇。
- 新事件入库后立即自动运行 Detection Engine。
- 用户可对指定时间段、Agent、Session 或事件范围发起历史重放检测。
- 检测结果保存规则版本，能够说明“由哪个规则版本、哪些事件产生”。

### G4：异常阻断

- `BLOCK` 决策必须落到真实执行器，不能只记录“已派发”。
- 执行状态明确区分：`planned`、`dispatched`、`executing`、`executed`、`failed`、`expired`、`rolled_back`。
- 只有存在至少一个 `executed` 响应，Detection 才能标记为 `mitigated`。
- 页面支持手动阻断、重试、撤销和查看执行证据。

### G5：攻击链生成

- 攻击链由后端基于结构化 Detection 与 Evidence 增量生成并持久化。
- 页面查询不负责安全语义重建。
- 用户可对历史数据执行一次可追踪的重建任务。
- 链路能够跳转到 Event、Detection、Decision 和 Response。

### G6：自动/手动从数据库拉取

- 自动同步只负责“读取新版本数据”，不偷偷执行扫描。
- 手动刷新只重新读取；“重新扫描/重新检测/重建”必须是独立按钮和 POST 任务。
- 所有列表统一分页、总数、时间范围、游标和 `captured_at` 语义。
- 活跃页面优先使用变更游标或事件流；不能让每个页面独立无上限轮询全量数据。

## 3. 目标数据流

```text
                         ┌─────────────────────┐
自动计划 / 手动按钮 ───> │ Job Orchestrator    │
                         │ durable job records │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼──────────────────────┐
              │                     │                      │
        Agent Discovery       Resource Scanner       Event Replay
              │                     │                      │
              └──────────────┬──────┴──────────────┬───────┘
                             ▼                     ▼
                        SQLite source of truth: agents / static_resources /
                        behavior_events / detections / decisions / responses /
                        attack_chains / jobs
                             ▲
                             │ event-driven write
  Guardrail / Hook / Proxy / Windows Sensor
                             │
                             ▼
                   Runtime Detection Engine
                             │
                             ▼
                     Decision + Executor Router
                             │
               ┌─────────────┼──────────────┐
               ▼             ▼              ▼
          real executor   response audit   attack-chain builder

Desktop GET / cursor sync  <──  SQLite read models
Desktop POST job/action    ──>  Job Orchestrator / Executor Router
```

## 4. 当前数据库对象与职责

| 领域 | 当前表 | 当前职责 | 目标调整 |
|---|---|---|---|
| Agent | `agents`、Agent governance 相关表 | Agent 身份、类型、发现规则、最近状态 | 增加发现批次/版本关联，GET 只读 |
| 静态资源 | `static_resources`、`scan_results`、`scan_findings` | 资源清单、扫描历史、Finding | 保持为权威数据源，关联持久化 Job |
| 运行时事件 | `behavior_events`、`runtime_sessions` | 旧行为事件与统一 Runtime Event 共表 | 统一入口和词汇，所有事件均可检测 |
| 检测 | `runtime_detections`、`runtime_detection_events` | Detection 与证据关联 | 增加 `rule_version`、`evaluation_job_id` |
| 决策 | `runtime_decisions` | 风险决策和 enforcement point | 增加策略版本、人工/自动来源、幂等键 |
| 响应 | `runtime_response_actions` | 记录响应动作 | 改为真实执行状态机和执行证据 |
| 攻击链 | `runtime_attack_chains`、`runtime_attack_chain_events` | 持久化结构化攻击链 | 增加 builder 版本和 rebuild job |
| 设置 | `app_settings` | Runtime mode、桌面刷新间隔等 | 后台计划迁入正式 schedule/job 表 |
| 任务 | `scan_jobs`（本轮新增）、Gateway 内存快速索引 | Agent/资源/重放/重建任务状态、进度和错误 | 继续补充结果摘要、幂等键和执行恢复策略 |

## 5. 接口盘点（改造前问题 + 当前合同）

表格中的“主要问题”描述的是改造前风险；已在本轮修复的条目会在第 13 节列出验证证据。接口路径保持兼容，但调用语义已经分为：GET 只读、POST 创建任务/动作、GET 任务状态。

### 5.1 Agent

| 接口 | 当前用途 | 当前状态 | 主要问题 |
|---|---|---|---|
| `GET /api/v1/agents` | Agent 列表 | 已实现 | 改造前会触发发现；当前只读数据库 |
| `GET /api/v1/agents/summary` | Agent 汇总 | 已实现 | 改造前会触发发现；当前只读数据库 |
| `GET /api/v1/agents/{id}` | Agent 详情 | 已实现 | 改造前会触发发现；当前只读数据库 |
| `POST /api/v1/scans/agents` | 发起 Agent 扫描 | 已实现 | 当前创建持久化 `scan_jobs`，返回 `scan_id` |
| `GET /api/v1/scans/{scan_id}` | 查询扫描状态 | 已实现 | 当前兼容读取内存快速索引或 `scan_jobs` |
| `POST /api/v1/agents/discovery` | 接收 CLI/TUI 发现报告 | 已实现 | 这是“上报发现结果”，不是桌面端发起扫描 |

代码依据：

- `handleAgentsList`：`internal/gateway/unified_runtime_api.go:124`
- `handleAgentScan`：`internal/gateway/unified_runtime_api.go:210`
- `startAPIScan`：`internal/gateway/unified_runtime_api.go:250`
- GET 内执行扫描：`internal/gateway/page_inventory_api.go:800`、`:957`
- Agent 页面按钮实际调用 GET：`desktop/src/pages/AgentsPage.tsx:237`、`desktop/src/App.tsx:140`

### 5.2 静态资源

| 接口 | 当前用途 | 当前状态 | 主要问题 |
|---|---|---|---|
| `GET /api/v1/static-resources/agents` | 按 Agent 汇总资源 | 已实现 | 纯数据库读取，方向正确 |
| `GET /api/v1/static-resources` | 分页资源列表 | 已实现 | 已支持常用过滤 |
| `GET /api/v1/agents/{id}/static-resources/summary` | Agent 资源汇总 | 已实现 | 可保留 |
| `GET /api/v1/static-resources/{id}` | 资源详情 | 已实现 | 可保留 |
| `GET /{id}/findings` | 最新 Finding | 已实现 | 可保留 |
| `GET /{id}/scans` | 扫描历史 | 已实现 | 可保留 |
| `GET /{id}/content` | 脱敏内容/目录 | 已实现 | 可保留，需继续限制权限和大小 |
| `GET /{id}/relations` | 关联资源 | 仅占位 | 永远返回空数组 |
| `PUT /{id}/status` | 人工复核状态 | 已实现 | 可保留 |
| `POST /{id}/scan` | 单资源扫描 | 已实现 | 当前创建持久化任务并轮询真实状态 |
| `POST /api/v1/agents/{id}/static-resources/scan` | 单 Agent 重扫 | 已实现 | 当前创建持久化任务并轮询真实状态 |
| `POST /api/v1/static-resources/rescan` | 全量/按 Agent 重扫 | 已实现 | 已接入路由；返回持久化任务 |

代码依据：

- 资源路由：`internal/gateway/static_resources_api.go:54`
- 未接入路由的 rescan 处理器：`internal/gateway/static_resources_api.go:421`
- 固定延时刷新：`desktop/src/pages/StaticAssetsPage.tsx:479`

### 5.3 运行时事件与攻击事件检测

| 接口 | 当前用途 | 当前状态 | 主要问题 |
|---|---|---|---|
| `GET /api/v1/runtime-events` | 查询统一运行时事件 | 已实现 | 当前额外返回真实 `total`；默认排除旧桌面行为源 |
| `POST /api/v1/runtime-events` | OS Sensor 统一事件上报 | 已实现 | 会立即执行 Detection Engine，方向正确 |
| `GET /api/v1/runtime-events/{id}` | 事件详情 | 已实现 | 可保留 |
| `GET /api/v1/runtime-events/timeline` | 时间桶统计 | 已实现 | 固定最多读取 2000 条，可能截断高流量窗口 |
| `GET /api/v1/runtime-sessions` | Session 列表 | 已实现 | 缺少详情、分页总数和事件游标 |
| `GET /api/v1/runtime-detections` | Detection 列表 | 已实现 | 来源过滤在 Go 内存二次过滤；最大取 5000 条 |
| `GET /api/v1/runtime-detections/{id}` | Detection + Evidence | 已实现 | 可保留 |
| `GET /{id}/events` | Detection 证据事件 | 已实现 | 可保留 |
| `PATCH /{id}` | 修改 Detection 状态 | 已实现 | 状态变更与响应执行没有强一致约束 |
| `GET /api/v1/runtime-security/summary` | 检测汇总 | 已实现 | 可保留 |
| `GET /api/v1/runtime-detections/summary/agent-types` | 按 AgentType 汇总异常 Detection，风险等级动态聚合 | 已实现 | 数据库聚合；支持既有检测筛选条件 |
| `POST /api/v1/behavior-events` | Windows 进程守护事件入库 | 已实现 | 当前作为兼容入口归一化后进入 Detection Engine |
| `POST /api/v1/jobs`，`kind=event_replay` | 历史事件重新检测 | 已实现 | 后端按范围读取事件并重放当前规则 |

代码依据：

- 统一事件 POST 后执行引擎：`internal/gateway/runtime_events.go:864`、`:909`
- 旧行为事件处理器：`internal/gateway/behavior_events_api.go:43`
- Windows Sensor 仍调用旧入口：`desktop/src-tauri/src/trace_store.rs:40`、`:46`
- Detection Engine 只在四个统一适配器调用：`internal/gateway/runtime_events.go:240`、`:363`、`:428`、`:909`
- 事件页面“重新检测”只重新读取：`desktop/src/pages/EventsPage.tsx:307`

### 5.4 决策与异常阻断

| 接口 | 当前用途 | 当前状态 | 主要问题 |
|---|---|---|---|
| `GET /api/v1/runtime-decisions` | 决策列表 | 已实现 | 当前 Events 页面消费并显示 |
| `GET /api/v1/runtime-decisions/{id}` | 决策与响应详情 | 已实现 | 当前 Events 详情可追溯 |
| `GET/PUT /api/v1/runtime-security/mode` | `observe/action` | 已实现 | 当前 Events 页面独立控制运行时模式 |
| `POST /api/v1/runtime-detections/{id}/actions/block` | 人工阻断 Detection | 已实现 | 当前只有执行器返回 `executed` 才标记 `mitigated` |
| `POST /api/v1/runtime-decisions/{id}/enforce` | 执行已有 BLOCK 决策 | 已实现 | 当前复用执行器路由并返回准确状态 |
| `GET /api/v1/enforcements` | 当前处置项 | 已实现 | 读取活动执行器和持久化响应动作 |
| `GET /api/v1/enforcements/{id}` | 处置详情 | 已实现 | 返回目标、执行器、结果和回滚能力 |
| `POST /api/v1/enforcements/{id}/rollback` | 回滚处置 | 已实现 | 仅对可回滚执行器生效，保留审计记录 |
| `DELETE /api/v1/enforcements/{id}` | 兼容解除入口 | 已实现 | 与 rollback 对网络规则兼容；不可逆动作不会伪造回滚 |

前端桥接已经定义但没有任何页面调用：

- `getRuntimeDecisions`：`desktop/src/bridge.ts:660`
- `getRuntimeSecurityMode`：`desktop/src/bridge.ts:671`
- `blockRuntimeDetection`：`desktop/src/bridge.ts:681`
- `enforceRuntimeDecision`：`desktop/src/bridge.ts:686`
- `getRuntimeEnforcements`：`desktop/src/bridge.ts:691`

此外，桥接默认发送 `action_type="BLOCK"`，而 Gateway 的 `manualActionPlan` 只接受
`TOOL_BLOCK`、`MCP_BLOCK`、`BLOCK_NETWORK`、`PROCESS_CONTAIN`、
`DISABLE_RESOURCE`、`QUARANTINE_RESOURCE` 等具体动作。因此即使页面直接使用当前
`blockRuntimeDetection()`，默认请求也会得到 400。Tauri 与 TypeScript 的默认值位于
`desktop/src-tauri/src/commands/runtime_decisions.rs:229` 和
`desktop/src/bridge.ts:681`，Gateway 校验位于
`internal/gateway/unified_runtime_api.go:940`。

执行语义问题代码依据：

- 自动响应默认写 `dispatched`：`internal/detection/policy.go:274`、`:308`
- 手动响应默认写 `dispatched`：`internal/gateway/unified_runtime_api.go:889`、`:896`
- 目前只有 Proxy 分支真正把 host 加入阻断表。

### 5.5 攻击链

| 接口 | 当前用途 | 当前状态 | 主要问题 |
|---|---|---|---|
| `GET /api/v1/attack-chains` | 攻击链列表 | 已实现 | 当前只读持久化链并返回数据库 `total`，无链时明确 warning |
| `GET /api/v1/attack-chains/{id}` | 链路详情 | 已实现 | 可关联 Detection、Decision、Response |
| `GET /api/v1/attack-chains/summary` | 汇总 | 已实现 | 当前只读数据库聚合 |
| `GET /api/v1/attack-chains/summary/agent-types` | 按 AgentType 汇总攻击链数量与状态/严重度 | 已实现 | 数据库聚合；支持既有攻击链筛选条件 |
| `POST /api/v1/jobs`，`kind=attack_chain_rebuild` | 历史攻击链重建 | 已实现 | 后端异步重建，记录 `rule_version` |

改造前持久化方向正确，但仍有以下问题（本轮已关闭回退和 total 两项）：

- 回退链通过标题、路径、`block`、`shell`、`secret` 等字符串分类，可能产生误报。
- persisted chain 列表逐条查询事件，存在 N+1 查询。
- 列表响应的 `total` 使用当前返回链数，不是符合过滤条件的数据库总数。
- 只有“chain-worthy” Detection 才持久化；修改规则后没有历史重建机制。
- builder 版本和 `evaluation_job_id` 还没有进入攻击链表，重建任务目前以 Job 维度追踪。

代码依据：

- 列表与回退：`internal/gateway/page_inventory_api.go:409`
- 持久化列表映射：`internal/gateway/page_inventory_api.go:553`
- 页面刷新：`desktop/src/pages/AttackChainPage.tsx:173`

### 5.6 自动/手动数据库读取

当前桌面端通过 Tauri command 代理 Gateway API，页面刷新与后台任务已拆分；主 App 仍保留短周期 GET 作为兼容兜底，增量游标接口已经可用但尚未替换全部页面轮询。

主要问题：

- Agent discovery 调度已移到 Gateway 后台；静态资源周期扫描仍由 Watcher 负责。
- `agentDiscovery` 不再依赖 `GET /agents` 的扫描副作用。
- 页面定时刷新现在会递增页面 refresh nonce，Events/Static Assets 能重新读取自己的数据。
- Summary、列表和 Timeline 分多次请求，缺少共同 `db_revision`，同一屏可能来自不同数据库时刻。
- `GET /api/v1/changes` 已提供 cursor/delta invalidation；App 尚未将所有页面切换为该游标。

代码依据：`desktop/src/App.tsx:140`、`:159`、`:163`、`:226`。

### 5.7 前端静态/写死内容清单

下面内容目前仍由前端代码提供，需和“后端权威数据”区分；它们不是数据库检测结果。桌面应用运行在 Tauri 模式时，事实数据应全部来自 Gateway，浏览器预览分支只用于让页面可渲染。

| 位置 | 当前静态内容 | 风险/影响 | 处理建议 |
|---|---|---|---|
| `desktop/src/data/staticAssets.ts` | 资源类型、风险等级、状态的标签、颜色、排序和说明 | 属于展示字典，新增后端枚举时前端可能显示降级文本 | 保留为 UI 字典；后端返回未知值时显示原值，并在版本升级时同步字典 |
| `desktop/src/data/events.ts`、`desktop/src/app/display.tsx` | 事件分类和状态标签 | 不影响检测判断，但标签与后端状态枚举漂移会误导操作员 | 以 API 状态为准，统一由共享 DTO/枚举生成 |
| `desktop/src/data/range.ts`、`RangePage.tsx` | AgentRange 场景名称、触发命令、风险说明和默认回放场景 | 这是靶场演示语料，不应当被当作真实攻击事件或生产统计 | 保留为靶场目录；真实结果只读运行时事件/Detection/Chain 表 |
| `desktop/src/bridge.ts` | 浏览器预览下的空列表、默认设置、`browserEnvironment`、`desktop preview` 攻击链提示，以及治理风险模型/规则 mock | 浏览器模式不会访问本机或 SQLite，若误用于生产会显示 0 或示例数据 | 仅允许非 Tauri 预览；桌面模式调用 Gateway，必要时在界面显式标注“预览” |
| `desktop/src/bridge.ts` 治理函数 | 非 Tauri 下的风险映射、类别和规则前缀 mock | 只能用于离线表单预览，不能作为真实策略来源 | 桌面端统一调用 `/agent-governance`；后端返回空数据时显示“未配置”而不是 mock |
| `desktop/src/bridge.ts`、`SettingsPage.tsx` | 扫描/刷新间隔默认值、空数据初始值 | 仅在后端不可用或首次渲染时生效；不代表后台调度已经运行 | 后端保存的 schedule/job 为唯一运行配置，默认值只做初始化 |
| 各页面 JSX | 菜单文案、颜色、按钮文案、分页默认大小、时间轮询间隔 | 展示常量，不是安全事实；修改文案不会改变策略 | 可保留；危险动作和执行状态必须来自 API，不得用文案推断 |

因此本次改造的“去静态化”边界是：Agent、资源、事件、Detection、Decision、Response、Attack Chain、Job 的数量/状态/详情全部由数据库接口提供；展示字典、靶场目录和浏览器预览占位仍可静态存在，但必须明确标注用途，不能参与生产检测或阻断决策。

## 6. 问题优先级与改造建议

### P0：必须先解决，否则“检测/阻断闭环”不成立

#### P0-1 Windows Process Guard 事件接入统一检测链

现状：Rust 将 `agentCommandStart`、`processGuardRuleMatch` 等旧事件 POST 到 `/behavior-events`；Gateway 只入库。

改造：

1. 新增统一的内部函数 `IngestRuntimeEvent(input)`，负责标准化、入库、Session 维护和 `EvaluateEvent`。
2. `/runtime-events`、`/behavior-events`、Guardrail、Hook、Proxy 全部调用该函数。
3. 建立事件映射：
   - `agentCommandStart` -> `process.exec`
   - `fileRead` / `blacklistFileAccess` -> `file.read`
   - `fileWrite` / `fileCreate` -> `file.write`
   - `fileDelete*` -> `file.delete`
   - `processGuardRuleMatch` -> `process.policy_match`
4. Rust Sensor 增加 `canonical_agent_id`、`session_id`、`trace_id` 或稳定的 `process_tree_id`。
5. 保留 `/behavior-events` 兼容旧客户端，但内部必须进入统一链路。

验收：发送一条危险进程/文件事件后，能从 Event 跳到 Detection，再看到 Decision。

#### P0-2 建立真实 Executor Router

现状：Proxy 可真实阻断 host；其他 enforcement point 只写 `dispatched`。

改造：

```go
type RuntimeExecutor interface {
    Kind() string
    Execute(ctx context.Context, action ActionRequest) (ExecutionResult, error)
    Rollback(ctx context.Context, enforcementID string) (ExecutionResult, error)
}
```

至少需要：

- `ProxyExecutor`：加入/移除网络阻断。
- `ProcessGuardExecutor`：向已安装的管理员服务发送 terminate/contain 请求，并等待服务回执。
- `AgentHookExecutor`：写入可被 Hook 同步读取的阻断规则或调用 Hook 管理接口。
- `MCPExecutor`：禁用 MCP/工具或写入 runtime deny rule。
- `FileExecutor`：隔离/恢复资源，记录原路径与校验值。
- `GuardrailExecutor`：更新前置阻断策略，而不是事后声称本次已阻断。

状态规则：

- `dispatched` 不等于 `executed`。
- `mitigated` 必须由执行成功或原始 Evidence 全部已经 `blocked` 推导。
- 执行失败必须保留 Detection 为 `open`，并产生告警。

#### P0-3 把阻断能力接入 UI

在 Events 详情中加入：

- 当前 Detection 状态、Decision、Response Action。
- “阻断”按钮：先显示计划的 enforcement point 和影响范围，再调用 block API。
- “重试执行”按钮：调用 decision enforce。
- “解除/回滚”按钮：调用 enforcement rollback/delete。
- Runtime Security 模式控制必须与 Windows Process Guard 模式分开显示。
- 修正手动阻断 DTO：调用方不传具体动作时应省略 `action_type`，由 Gateway 根据 Detection 选择计划；或让 Gateway 明确支持通用 `BLOCK`。

### P1：使自动/手动任务语义正确且可运维

#### P1-1 查询与任务分离

- `GET /agents` 改为只读 `agents` 表。
- Agent 自动发现和手动发现都走后台 Job。
- 所有“扫描/检测/重建”按钮使用 POST；所有“刷新”按钮只使用 GET。

#### P1-2 持久化 Job

新增 Job 数据模型：

```json
{
  "job_id": "job_01...",
  "kind": "agent_discovery | resource_scan | event_replay | attack_chain_rebuild",
  "trigger": "manual | schedule | realtime | startup",
  "scope": { "agent_id": "codex", "resource_id": "...", "start_time": "..." },
  "status": "queued | running | succeeded | failed | canceled",
  "progress": { "current": 42, "total": 100, "phase": "scan" },
  "result": { "created": 3, "updated": 10, "failed": 1 },
  "rule_version": "runtime-rules-2026-09-01",
  "started_at": "...",
  "finished_at": "...",
  "error": ""
}
```

Job 必须持久化、有限保留、支持重启恢复或明确标记 `interrupted`，并使用幂等键防止重复点击。

#### P1-3 后台 Scheduler

- Agent discovery schedule 由 Gateway 执行。
- 静态资源仍由 Watcher 的 realtime/periodic 机制执行，但统一记录为 Job run。
- Runtime Detection 主要是事件驱动，不应伪装成定时全量扫描。
- Event replay 与 Attack-chain rebuild 只在规则升级、人工操作或修复任务时运行。
- 桌面端设置改为配置后端 schedule，不再只保存 React 刷新间隔。

#### P1-4 历史事件重放检测

新增人工重放任务，并确保幂等：同一 `event_id + rule_id + rule_version` 不重复产生相同 Detection。

### P2：一致性、性能和解释性

- 所有分页返回真实 `total`、`page_size`、`next_cursor`。
- Summary 与列表支持同一 `as_of_revision`。
- 把 detection source 过滤下推到 SQL，移除最多 5000 条的内存过滤。
- Attack Chain 批量查询事件，消除 N+1。
- 移除页面级字符串安全判定；旧数据迁移后关闭 heuristic fallback。
- Detection Rule、Decision Policy、Attack Chain Builder 都记录版本并提供只读查询接口。
- 用 OpenAPI/JSON Schema 生成 Go、Rust、TypeScript DTO，避免 snake_case/camelCase 与默认值继续漂移。
- 实现 Static Resource Relations，或在接口中明确返回 `supported: false`，避免空数组被理解为“没有关系”。

## 7. 建议接口合同

### 7.1 通用任务接口

| 方法 | 接口 | 说明 |
|---|---|---|
| `POST` | `/api/v1/jobs` | 发起 Agent、资源、事件重放或攻击链重建任务 |
| `GET` | `/api/v1/jobs/{job_id}` | 查询任务状态和结果 |
| `GET` | `/api/v1/jobs` | 查询任务历史，支持 kind/status/time 过滤 |
| `POST` | `/api/v1/jobs/{job_id}/cancel` | 取消支持取消的任务 |

兼容策略：现有 `/scans/agents`、`/{resource}/scan` 等接口内部创建 Job，继续返回 `202 + job_id`；`/scans/{id}` 可作为 Job 查询别名。

### 7.2 Agent

| 方法 | 接口 | 目标语义 |
|---|---|---|
| `GET` | `/api/v1/agents` | 只读数据库，支持 status/type/keyword/cursor |
| `GET` | `/api/v1/agents/{id}` | 只读详情 |
| `POST` | `/api/v1/jobs`，`kind=agent_discovery` | 手动或自动发现 |
| `GET` | `/api/v1/agents/discovery-runs` | 最近发现批次和差异 |

### 7.3 静态资源

| 方法 | 接口 | 目标语义 |
|---|---|---|
| `GET` | `/api/v1/static-resources` | 数据库分页查询 |
| `POST` | `/api/v1/jobs`，`kind=resource_scan` | 支持 resource/agent/all scope |
| `GET` | `/api/v1/static-resources/{id}/scans` | 扫描历史 |
| `GET` | `/api/v1/static-resources/{id}/relations` | 返回由资源、Agent 和目标路径推导的关系；当前 `supported:true` |

应修复并保留 `/api/v1/static-resources/rescan` 兼容入口，但新 UI 统一使用 Job 接口。

### 7.4 Runtime Event 与 Detection

| 方法 | 接口 | 目标语义 |
|---|---|---|
| `POST` | `/api/v1/runtime-events` | 所有传感器的统一事件入口 |
| `POST` | `/api/v1/runtime-events/batch` | 批量可靠上报，逐项返回结果 |
| `GET` | `/api/v1/runtime-events` | cursor 分页读取 |
| `GET` | `/api/v1/runtime-detections` | Detection 分页读取 |
| `POST` | `/api/v1/jobs`，`kind=event_replay` | 历史事件重放检测 |
| `GET` | `/api/v1/detection-rules` | 当前规则、版本和启用状态 |

### 7.5 Decision 与 Enforcement

| 方法 | 接口 | 目标语义 |
|---|---|---|
| `GET` | `/api/v1/runtime-decisions` | 决策与执行汇总 |
| `POST` | `/api/v1/runtime-detections/{id}/actions`（兼容 `/actions/block`） | 创建人工动作，body 指定 action_type/reason/idempotency_key |
| `POST` | `/api/v1/runtime-decisions/{id}/execute`（兼容 `/enforce`） | 执行或重试 |
| `GET` | `/api/v1/enforcements` | 所有 executor 的执行实例，不仅是网络 host |
| `GET` | `/api/v1/enforcements/{id}` | 执行证据、错误、目标、过期时间 |
| `POST` | `/api/v1/enforcements/{id}/rollback` | 可回滚动作的统一撤销入口 |

不建议继续用 DELETE 表示所有解除操作，因为进程终止不可逆、文件隔离需要恢复参数、网络规则可直接移除；显式 rollback 更清楚。

### 7.6 Attack Chain

| 方法 | 接口 | 目标语义 |
|---|---|---|
| `GET` | `/api/v1/attack-chains` | 持久化链分页列表，真实 total |
| `GET` | `/api/v1/attack-chains/{id}` | 节点、边、Evidence、Detection、Decision、Response |
| `GET` | `/api/v1/attack-chains/summary` | 数据库聚合 |
| `POST` | `/api/v1/jobs`，`kind=attack_chain_rebuild` | 指定时间段/规则版本重建 |

### 7.7 数据自动同步

第一阶段建议使用轻量 cursor，不必立即引入复杂消息系统：

```http
GET /api/v1/changes?cursor=18420&domains=agents,resources,detections,decisions,chains
```

```json
{
  "next_cursor": 18437,
  "changed_domains": ["detections", "decisions", "chains"],
  "latest_at": "2026-09-01T10:30:00Z"
}
```

桌面端只在活跃页面查询变更；发现相关 domain 变化后，再 GET 对应列表。第二阶段可增加 SSE：

```http
GET /api/v1/stream?domains=detections,decisions,enforcements,jobs
```

手动“刷新数据”直接 GET 当前页面数据；手动“重新扫描/重新检测/重建”创建 Job，两个操作必须在 UI 上分开。

## 8. 统一响应规范

新接口建议统一元数据，不要求一次性改完所有旧接口：

```json
{
  "items": [],
  "meta": {
    "total": 0,
    "page_size": 50,
    "next_cursor": "",
    "captured_at": "2026-09-01T10:30:00Z",
    "db_revision": 18437,
    "source": "sqlite"
  }
}
```

错误格式：

```json
{
  "error": {
    "code": "EXECUTOR_UNAVAILABLE",
    "message": "Windows Process Guard service is not running",
    "retryable": true,
    "details": { "executor": "process_guard" }
  }
}
```

所有写接口继续要求本机认证、`X-DefenseClaw-Client`、JSON Content-Type，并增加：

- `Idempotency-Key`
- 操作者/来源审计字段
- 请求追踪 ID
- 危险动作确认信息

## 9. 前端与 Tauri 改造清单

### App 层

- 删除扫描任务对应的前端全量 `setInterval`。
- 只保留活跃页面的 cursor/SSE 数据同步。
- 后台 schedule 通过 Gateway 设置接口管理。

### Agent 页面

- “刷新数据”：GET `/agents`。
- “重新发现”：POST Job，展示进度并在成功后刷新。
- 显示 `last_discovery_job_id`、`last_discovery_at`、数据来源和错误。

### 静态资源页面

- 使用 `job_id` 轮询或订阅任务完成，移除 1.5/3.5/7 秒固定延时。
- 增加 Agent 全量与全系统扫描 scope。
- 任务失败时保留错误和重试按钮。

### 事件检测页面

- “刷新数据”和“重新检测历史事件”拆成两个按钮。
- 接入 Decision、Response、Enforcement 数据。
- Detection 详情增加阻断、重试、回滚操作。
- “已阻断”只统计 `executed` 或原始 Evidence 已阻断的数据。

### 攻击链页面

- “刷新数据”和“重建攻击链”拆分。
- 只展示持久化链；迁移完成后移除页面启发式回退。
- 展示 builder/rule/policy 版本和每个节点的来源链接。

### 设置页面

- 分成“后台检测计划”和“页面数据同步”两组设置。
- Runtime Security Mode 与 Windows Process Guard Mode 分开。
- 展示各 Executor 健康状态，Action 模式开启前检查依赖。

## 10. 分阶段实施

### M0：修正语义与 P0 闭环

1. Process Guard 事件统一入链。
2. Executor Router 与准确执行状态。
3. Detection 页面接入人工阻断、响应详情和 Runtime Mode。
4. 修正 `mitigated/blocked` 统计语义。

完成标准：一次 Process Guard 危险事件可以产生 Detection；可执行的 BLOCK 有真实回执，不可执行时显示失败且 Detection 保持 open。

### M1：持久化任务与手动检测

1. Job 表和通用 Job API。
2. Agent GET 去副作用。
3. Agent、资源扫描接入 Job。
4. 前端移除固定延时，显示真实任务进度。
5. 增加历史 Event replay。

完成标准：App 重启后仍可查任务；重复点击不会重复执行；按钮文案与实际动作一致。

### M2：后台计划与数据同步

1. Gateway Scheduler。
2. cursor changes API。
3. 活跃页面增量拉取。
4. Summary/list/timeline 数据版本一致。

完成标准：App 关闭时自动发现/扫描仍执行；App 打开后只拉变化数据。

### M3：攻击链与规则治理

1. Attack-chain rebuild Job。
2. 规则/策略/builder 版本化。
3. 移除 heuristic fallback。
4. 批量加载链路 Evidence，修复 total 与 N+1。

完成标准：同一规则版本重建结果可重复、可解释，列表总数与数据库一致。

## 11. 验收测试矩阵

| 场景 | 必须验证 |
|---|---|
| Agent 自动发现 | App 关闭时仍运行；`GET /agents` 不产生扫描副作用 |
| Agent 手动发现 | 返回 job_id；状态可恢复；完成后数据库快照变化 |
| 静态资源实时检测 | 文件变化触发扫描，Finding 和历史写库 |
| 静态资源手动扫描 | 单资源/Agent/全部 scope；页面等待真实完成状态 |
| Guardrail/Hook/Proxy 事件 | 入库后自动产生匹配 Detection |
| Process Guard 事件 | 使用统一词汇进入 Detection Engine，并关联正确 Agent |
| 历史重新检测 | rule_version 变化后可 replay；同版本重复执行幂等 |
| 自动网络阻断 | Proxy 返回 403，Response 状态为 executed，可撤销 |
| 自动进程阻断 | 管理员服务确认后才标记 executed；服务离线时 failed |
| 手动阻断 | 有影响预览、幂等键、执行结果和审计记录 |
| 攻击链 | Event -> Detection -> Decision -> Response 均可追溯 |
| 数据同步 | cursor 单调递增；同一 revision 的汇总和列表一致 |
| 重启恢复 | Job、阻断、模式、链路和扫描历史均可恢复 |

## 12. 本轮不应混淆的概念

- **刷新数据**：只从数据库读取。
- **发现**：枚举 Agent 或资源并更新 Inventory。
- **扫描**：对资源内容运行 Scanner。
- **检测**：根据 Event/Finding 产生 Detection。
- **决策**：根据 Detection 产生 ALLOW/AUDIT/ALERT/CONFIRM/BLOCK。
- **执行**：把 BLOCK 交给真实 Executor 并取得结果。
- **攻击链生成**：把结构化 Evidence 关联为持久化 Chain。
- **重放/重建**：使用指定规则版本重新处理历史数据，是后台 Job，不是 GET 刷新。

按以上定义实施后，页面文案、接口语义、数据库状态和实际防护动作才能保持一致。

## 13. 本轮已落地结果、验证与剩余限制

本节是当前工作树的实现状态，优先级高于第 1 节保留的改造前基线。

### 13.1 已形成的后端闭环

当前事件链已经统一为：

```text
Guardrail / Agent Hook / Proxy / Windows 兼容事件 / OS Sensor
  -> RecordRuntimeEvent（统一 event_type、source、agent/session 归属）
  -> Runtime Detection Engine（原子规则 + 会话窗口关联规则）
  -> runtime_detections（含 rule_version 与 evidence）
  -> Runtime Policy Engine（ALLOW/AUDIT/ALERT/CONFIRM/BLOCK）
  -> runtime_response_actions（planned / would_block / dispatched / executing / executed / failed / expired / rolled_back）
  -> runtime_attack_chains（后端持久化链）
```

已经落地的关键语义：

- 旧版 `/api/v1/behavior-events` 不再只写旧表；兼容适配器会把 `agentProcessStart`、`blacklistFileAccess`、`fileDelete` 等名称映射到 `process.exec`、`file.read/write`、`file.delete`，入库后立即调用检测引擎。
- `GET /api/v1/agents`、静态资源页面读取和攻击链页面读取均为只读数据库操作，不再因为刷新页面而触发发现或重建。
- 扫描、历史事件重放、攻击链重建都有持久化 `scan_jobs` 任务；任务状态可通过 `/api/v1/jobs/{id}` 或兼容的 `/api/v1/scans/{id}` 查询，网关重启会把未完成任务标记为失败。
- `BLOCK` 只有真实执行器确认成功才返回 `executed` 并允许把 Detection 标记为 `mitigated`。当前内置执行器是 Windows `taskkill.exe` 进程树终止和 Proxy host blocklist；未接入的 Guardrail/Hook/MCP/File 执行器会明确返回 `failed`，不会伪报已阻断。
- 攻击链列表、详情、汇总均以 `runtime_attack_chains` 为准；页面不再从标题或事件字符串猜测链路。节点类型由统一事件词汇映射为桌面端有限枚举。

### 13.2 当前可用接口

| 能力 | 当前接口 | 写入/读取边界 |
|---|---|---|
| Agent 查询/发现 | `GET /api/v1/agents`；`POST /api/v1/jobs` (`agent_discovery`)；`POST /api/v1/scans/agents` | GET 只读；发现写 `agents` 与任务表 |
| 静态资源查询/扫描 | `GET /api/v1/static-resources`；`POST /api/v1/jobs` (`resource_scan`)；`POST /api/v1/static-resources/rescan` | 查询读库；扫描由 Watcher 执行并写扫描历史 |
| 实时事件 | `POST/GET /api/v1/runtime-events`；`POST /api/v1/runtime-events/batch` | 统一写 `behavior_events`，随后自动检测 |
| 检测与证据 | `GET /api/v1/runtime-detections`、`/{id}`、`/{id}/events`；`GET /api/v1/detection-rules` | 读 `runtime_detections` 与证据关联 |
| 决策与处置 | `GET /api/v1/runtime-decisions`；`POST /api/v1/runtime-detections/{id}/actions/block`；`POST /api/v1/runtime-decisions/{id}/execute` | 写决策、响应动作和审计状态 |
| 任务与增量同步 | `GET/POST /api/v1/jobs`、`/{id}/cancel`；`GET /api/v1/changes` | 任务和变更游标均持久化 SQLite |
| 攻击链 | `GET /api/v1/attack-chains`、`/{id}`、`/summary`；`POST /api/v1/jobs` (`attack_chain_rebuild`) | 只读持久化链，重建是显式 Job |

`/api/v1/changes` 接受 `agents/resources/events/detections/decisions/chains/jobs` 等短别名，并返回规范 domain 名称；它只是失效通知，页面仍需重新 GET 权威列表。

### 13.3 桌面端已接入的交互

- Agent、静态资源和攻击链页面把“刷新数据”与“重新发现/重新扫描/重建攻击链”分开；后者显示后端任务状态，不再依赖固定 1.5/3.5/7 秒延时。
- 事件页面接入 Runtime Security `observe/action` 模式、检测详情、人工 BLOCK/execute 和历史事件 replay。
- Tauri bridge 已对任务、变更游标、检测 rule version、攻击链分页和 `would_block` 字段做兼容反序列化。
- Windows Process Guard 安装按钮仍保留在策略/设置页面；安装服务与 UAC 流程属于机器端部署，不由 Gateway 假装完成。

### 13.4 已完成的本地验证

- `desktop`：`pnpm check` 通过；`pnpm build` 通过。当前机器 Node 为 `20.18.0`，项目和 Vite 建议 `>=20.19.0`，因此构建会给出版本警告；产物仍成功生成。
- `desktop/src-tauri`：`cargo fmt --check` 通过；`cargo test --locked` 通过，17 个测试全部通过。
- `git diff --check` 通过。
- 当前机器已使用项目内可复现的 Go 工具链完成 `gofmt` 和审计/检测/网关定向测试，覆盖批量事件、任务幂等、执行/回滚、兼容行为事件和静态资源接口；前端与 Tauri 测试也已通过。已尝试完整 `go test ./...`，但当前 Windows 环境有一批与本次改造无关的既有失败（连接器临时目录路径/权限、Unix 文件权限断言、缺少 openshell-sandbox、Windows ACL/DACL 以及子进程占用 SQLite 清理等）；因此完整仓库验收仍需在 CI/Linux 或具备完整本机依赖与管理员权限的环境复核，不能把定向测试等同于全仓库验收。

### 13.5 尚未关闭的风险与下一阶段目标

这些不是前端静态数据问题，而是明确的后续验收项：

1. 在真实 Windows 管理员环境安装并启动 Process Guard，验证服务离线、UAC 拒绝、进程树终止和重复点击幂等；这是 P0 发布门槛。
2. 为 Guardrail、Agent Hook、MCP、File 增加真实 Executor 和统一 `/api/v1/enforcements` 持久化读模型；在此之前这些点必须保持 `failed`/`would_block` 的诚实状态。
3. 静态资源 `relations` 已能从权威资源、Agent 和目标路径推导基础关系并返回 `supported:true`；目前仍是有限图语义，不能把空数组解释成“没有关系”，后续需补充跨资源引用和图构建版本。
4. App 层仍保留定时刷新作为兼容回退；`/api/v1/changes` 已提供但尚未让所有页面完全切换到 cursor/SSE。下一阶段应先按 domain 增量刷新，再移除全局轮询。
5. 需要把检测 source 过滤、攻击链列表详情的 N+1 查询、builder/policy 版本和任务取消的协作式中止进一步工程化；当前实现已经避免错误数据，但性能和可追溯性仍不是最终态。

最终发布目标可以用下面四条验收标准判定：

- **数据真实**：页面所有数量、状态、详情都能在 SQLite 对应表和变更游标中追溯，GET 不产生隐藏扫描副作用。
- **检测闭环**：一条统一事件可追溯到 Detection、Decision、Response 和 Attack Chain，包含规则版本与 Evidence。
- **处置诚实**：只有 Executor 明确成功才显示“已阻断/mitigated”；服务不可用时可重试且显示失败原因。
- **任务可恢复**：App 或 Gateway 重启后仍能查询 Job、扫描历史、决策和攻击链，不依赖前端内存或固定等待时间。
