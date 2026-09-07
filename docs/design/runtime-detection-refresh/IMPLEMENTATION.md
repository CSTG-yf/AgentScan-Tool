# 需求对齐与验收记录

来源：用户提供的“待改”设计文档与效果图（2026-09-05）。按文件夹 1 → 2 → 3 的依赖顺序实施；第 4 部分随后实施。原始 Markdown/SVG 保存在同目录各编号文件夹中。

## 1. 异常检测设置（已完成）

- [x] 五类持久化表及可升级迁移；通用规则、AgentType 设置、专属规则、黑名单、风险策略 CRUD。
- [x] 独立 `/api/v1/runtime-detection-settings` API：总览、分页筛选、风险展示、类型详情、有效配置与无副作用试算。
- [x] 内置算法保留；外层配置决定启停、参数覆盖、通用继承与类型专属/黑名单合并。
- [x] 风险分数按全局或类型策略映射；ASK 规范化为 CONFIRM；区间完整、无交叉。
- [x] 规则身份/版本可追踪；AgentType 隔离；缓存失效；配置审计和 change domain。
- [x] 保存只影响后续事件；历史回放由显式 Job 触发并限定类型范围。
- [x] Tauri 仅转发；治理中心新增异常检测设置 tab、规则编辑、类型弹窗和风险编辑。
- [x] Store/API/检测链路测试；前端构建；与 SVG 比对正常态、编辑态、错误态。

## 2. 异常事件页面（已完成）

- [x] 白色卡片工作台、四项完整汇总、动态 AgentType 风险卡、左侧精确 Agent 实例筛选。
- [x] 全部约定筛选与服务端分页；筛选同步影响汇总，翻页只读列表。
- [x] 深蓝详情抽屉：身份、Evidence、上下文、决策与执行结果；预览后执行阻断。
- [x] 初始化/筛选竞态处理、空态和后端错误；接口及视觉验证。

## 3. 攻击链页面（已完成）

- [x] 四项完整汇总、左侧实例列表与链数/风险提示；主区域不重复 AgentType 卡片。
- [x] 列表/汇总共享过滤，风险大写及 contained 兼容；服务端分页。
- [x] 深蓝详情：原始身份/状态、步骤、证据、检测、决策、实际响应与 outcome。
- [x] 真实执行状态判断；接口及视觉验证。

## 4. 刷新与扫描（已完成）

- [x] 治理中心内部 tab；后台扫描、手动 Job、页面只读刷新三个独立区域。
- [x] 扫描计划与页面刷新设置独立 API，保留旧接口/字段兼容。
- [x] 统一 task_type、trigger 与 Job 进度/取消/幂等；scheduler 和 watcher 进入 Job 历史。
- [x] 各类型独立调度、运行去重、配置变化生效。
- [x] 按页面间隔查询 changes；隐藏页面暂停、错误退避、详情不被自动替换。
- [x] 刷新不得触发扫描；显式扫描完成刷新；真实 Job 状态与失败反馈。

## 验证原则

测试需证明需求行为，不能以原有实现或效果图样例数字替代真实后端数据。全部勾选前不能判定目标完成。README 改动属于本任务此前工作，保留。

## 2026-09-06 验证记录

- `go test ./internal/audit ./internal/detection ./internal/gateway -run 'TestRuntimeSettings|TestRuntimeDetectionSettings|TestConfigured|TestRuntimeRisk' -count=1` 通过。用例分别位于 `internal/audit/runtime_detection_settings_test.go`、`internal/detection/configuration_test.go`、`internal/gateway/runtime_detection_settings_api_test.go`，覆盖旧库升级、类型隔离、版本冲突、审计失败回滚、动态内置判定、立即失效、试算不写入和显式类型重放。
- 新增回归：切换为通用策略后，API 的 `policy` 仍为 null、`effective_policy` 仍为全局策略；`custom_policy` 单独返回保留的自定义配置，避免编辑器覆盖历史自定义区间。
- TypeScript 检查通过；Rust `detection_filter_tests` 通过，验证 Agent 实例与类型同时传递、时间与多值条件编码、汇总不混入分页参数。
- 浏览器实际操作发现并修复了规则/黑名单表单默认值丢失问题。已确认规则默认分类、MEDIUM、0.8、优先级 100、启用状态；无桌面连接时显示失败并保留全部输入。
- 使用临时 SQLite 和真实 Go API 的界面验收入口，验证 12 条内置规则、全局四段风险区间、类型详情、新增黑名单后有效规则由 12 增至 13，以及试算命中该黑名单。
- 界面验证自定义风险策略保存，再保存通用继承，关闭重开类型弹窗并切回自定义，名称与 0.29 / 0.30 区间均保留。此验证不开放主机执行服务或重放；真实重放行为由上述 API/Job 测试验证。
- 已检查正常配置页、类型弹窗的浅色卡片布局和错误状态。仍需逐项与原始 SVG 比对、验证更多编辑/窄窗口交互，因此第一部分视觉验收尚未勾选。
- 第二部分已补齐 bridge/Tauri 的类型、时间、分页参数与可筛选类型汇总。增加 `attack_events` / `attackEvents`，由同一 SQL 过滤集合汇总，测试证明攻击/未解决计数完整且不受 limit/offset 影响。EventsPage 已接入新状态，仍待完整视觉与交互验收。
- 前端生产构建通过（Vite 提示现有主包超过 500 kB）；最新 TypeScript 检查通过。

### 隔离界面验收入口

入口也支持 `?events` 打开事件页面。临时库包含两类 Agent 的 27 条检测与关联行为证据；这些是显式测试数据，由真实存储与策略引擎写入。事件页面仅开放只读 API，主机执行与重放仍不开放。

事件页新增验证：

- 正常态顶部为 27 个异常、18 个攻击、18 个高危、27 个未解决；动态显示 `VENDOR-RISK`，没有将它归为 INFO。
- 第二页显示 7 条，完整汇总仍为 27。选择 Runtime A 后回到第一页，列表与汇总均为 24；再选 Runtime B 实例，AND 条件返回 0。
- 清除类型筛选后实例 B 返回 3 条；详情显示原始行为、Session/Trace、CONFIRM/observe 决策，以及“尚无执行记录”。
- 修复 Tauri 对 Agent 接口 `name` / `runtimeStatus` 的兼容，新增 Rust 回归；保留旧 `product` / `status`。
- 来源过滤统一在 SQL 分页前完成，删除 API 最多拉取 5000 条再过滤的路径；新增测试覆盖显式来源、历史 JSON 来源、关联回退、无效 JSON、多值条件与完整汇总。
- TypeScript 与所选 Store/检测/Gateway 回归通过，Rust 两项事件接口合同测试通过。已查看用户的事件页面及详情 JPG；按图加入概览/证据/上下文/处置四标签与底部处置按钮，并实际点击验证证据和处置内容。主列表提供更多筛选折叠区，以及 Session/Trace、证据数列。仍需覆盖更多筛选组合、竞态与真实处置预览，不据此勾选完整验收。

先在 `desktop/` 启动 `pnpm dev:web --host 127.0.0.1 --port 1420 --strictPort`，再在仓库根目录执行：

```powershell
$env:RUN_RUNTIME_SETTINGS_UI_REVIEW = '1'
go test ./internal/gateway -run '^TestRuntimeSettingsUIReviewServer$' -v -count=1 -timeout 31m
```

打开输出中的 `Temporary runtime settings review` 地址。该测试默认跳过，仅显式启用时创建临时库；30 分钟后退出并清理。页面代码为 `desktop/tests/runtime-settings-review.tsx`，只将配置请求转发到真实处理器，不进入生产前端构建，也不模拟保存成功。关闭后清除环境变量：`Remove-Item Env:RUN_RUNTIME_SETTINGS_UI_REVIEW`。

## 2026-09-07 攻击链页面推进

- 汇总 SQL 增加 `covered_agents` 和按实例 ID 的 `agents`（链路数、高危数）。同名实例分开，单实例跨风险/状态仅计一次，分页不改变汇总；Store 回归验证类型与实例条件取交集。
- Tauri/bridge 共用非分页筛选参数，列表默认 20 条，详情按需读取并保留原始审计对象。`blocked`/`mitigated` 统一查询 `contained`，风险转大写，未知风险/状态不会丢失。新增两项 Rust 合同测试通过，TypeScript 检查通过。
- Go 页面对象增加 `rawStatus` / `rawSeverity`，保留旧展示字段兼容现有调用。API 回归验证完整实例汇总、三种状态查询等价、原始身份及无执行记录时不合成响应。
- AttackChainPage 已替换为四项完整统计、左侧实例、筛选摘要、服务端分页表格和深蓝详情抽屉；不再横向展示 Agent 类型卡片。详情支持概览、步骤、证据、检测、决策与响应，导出明确为当前页或当前详情。
- 隔离验收入口增加 `?chains`。27 条链路由临时库显式写入，仅用于界面合同验证，不代表单事件能够触发关联引擎。已在浏览器验证 2/27/20/18 四项汇总，第一页 20 条、第二页 7 条且汇总不变；选择实例 B 回到第一页，汇总 1/3/2/2、列表 3 条。
- 浏览器打开 `VENDOR-RISK` / `contained` 链路，详情保留原始 Agent、session/trace 和 ALERT/observe 决策，显示 0 条已执行响应与尚无执行记录。
- 第三部分最终对照页面与详情效果图复查；筛选依赖变化时旧请求通过 effect cleanup 失效，详情请求通过 generation 标记防止乱序覆盖。真实重建 Job 已在隔离环境完成并回读详情。

## 2026-09-07 刷新与扫描完成记录

- 新增 `scan_schedules` 迁移与六类任务配置，其中四类具备统一 runner；行为追踪与环境采集明确标为事件/原生宿主驱动，不能配置成伪扫描。
- `/api/v1/jobs` 同时接受规范 `task_type` 和旧 `kind`，校验别名冲突、mode、trigger 与 scope；即时响应和历史记录都返回规范任务类型。同类任务的检查与创建由互斥区保护，重复请求返回当前任务。
- 通用 scheduler 每秒重读策略，各任务按自己的 interval 执行并跳过同类 queued/running Job。Watcher 防抖扫描与周期复扫都写入 Job 历史，并轮询持久化取消标记，把取消传入扫描 context。
- `/api/v1/page-refresh-settings` 与 `/api/v1/scan-schedules` 分开持久化；旧 `/api/v1/desktop-scan-schedule` 继续作为页面刷新兼容别名。默认八个页面间隔为 10 / 15 / 10 / 15 / 8 / 10 / 10 / 30 秒。
- 治理中心 tab 位于扫描方案之后。页面提供 4 项统计、四类手动任务、最近 20 条 Job、进度/取消/错误详情、后端策略、Watcher 参数与八类页面刷新配置。
- App 的固定 3 秒 changes 轮询已改成当前页面独立间隔；页面隐藏时不请求，失败按 2 倍退避至 60 秒。事件与攻击链自动刷新只更新列表/汇总，抽屉由用户显式刷新。
- 临时 SQLite + 真实 Handler 界面验收已确认：4 类可执行策略、2 类触发方式、8 个刷新页面；策略和刷新设置保存后重载仍存在；Agent 发现、静态扫描、事件重放、攻击链重建四个 Job 均成功并显示详情。
- 验证通过：`go test ./internal/audit ./internal/detection ./internal/watcher -count=1`；本需求相关 Gateway 回归；Rust 22 项单元测试；TypeScript；Vite 生产构建；安装文档 3 项 pytest。Gateway 全包仍有仓库既有的 Windows ACL、Windows 不支持 proxy connector 等平台测试失败，失败项与本次文件无关。
