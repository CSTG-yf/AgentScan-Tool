# AgentRange 行为、审计和异常接入

本次接入从原始检查请求产生行为，不读取或解析 `audit_events`。

## 数据流程

1. sidecar 为请求生成 `call_id`，在检查请求中附加可选 `runtime_context`，并传播 session/trace。
2. Go `/api/v1/inspect/request`、`response`、`tool`、`tool-response` 保存行为尝试，再运行原有检查。
3. 检查完成后把规则元数据和最终/原始判定写入行为属性，调用运行时检测引擎；规则命中产生异常及证据。审计是独立的写入，不是检测的数据来源。
4. sidecar 在响应发送后调用认证的 `POST /api/v1/runtime-results`，记录拒绝、收到响应、转发失败或响应阻断。
5. 原有行为、异常、证据、决策和审计 GET 接口返回新增数据。行为追踪增加 Agent、工具、检查状态、结果和调用 ID。

`/validate/code` 记录为 `langflow.validate_code` 工具请求。危险命中记为危险代码提交，不记成进程已执行。HTTP 200 记录为收到接口响应，不证明攻击成功。

检查模式与运行时响应模式分别保留。结构化检查异常的自动防护由检查入口负责，运行时策略不重复执行网络或进程控制。运行时 observe 模式记录拟处置，action 模式先记录计划；只有代理确认实际拒绝/阻断后才确认执行。请求后端执行与响应被阻断是不同事实。

## 去重和恢复

迁移 46 给 `behavior_events` 增加可空 `ingest_key` 和唯一索引。已有记录不修改，旧客户端继续独立插入。

检查和结果重发使用原始事件 ID。事件检查状态和检测完成标记保存在数据库。失败后能重试检查/检测，已完成的检查不被错误覆盖；证据重复关联不增加事件计数。

接口通过 `X-DefenseClaw-Runtime-Status` 和网关日志报告写入或检测失败，不修改原有放行判定。sidecar 在响应发送后最多尝试两轮失败检查及结果上报，不把原始请求写入磁盘队列。没有后台持久队列；如果两轮都失败或代理中途退出，结果可能缺失，需要重新运行新请求或重发原始结果。旧审计不会自动转换。

原有安全扫描的 200ms 超时和 sidecar 的可配置检查超时保留。行为持久化/检测额外使用同步数据库调用，SQLite 争用可能增加延迟；单请求测试的毫秒级耗时不是高负载延迟保证。生产环境如需要严格端到端时限，应进一步采用有界、持久化的任务队列，而不是增加无界 goroutine。

## 更新运行环境

源码修改不会自动替换正在运行的网关或容器。请手动：

1. 在项目根目录构建新的桌面包（会重新构建打包网关）：

   ```powershell
   pnpm -C desktop install --frozen-lockfile --prod=false
   powershell -ExecutionPolicy Bypass -File desktop\scripts\build.ps1 -SkipInstall
   ```

2. 退出旧桌面/网关，使用新的桌面包。网关首次启动通过现有迁移机制升级数据库；不要手工建表。
3. 确认靶场根目录和适配模式，再手动停止并启动适配靶场，以使用新的网关和新打包的 sidecar。仅重启旧容器不一定更新其挂载脚本路径。
4. 用一个新的正常请求和一个新的危险代码场景验证行为、审计、异常及证据。检查调用 ID 是否对应，并核对 observe/action 模式和实际结果。

## 验证命令

```powershell
python test/test_agentrange_runtime.py -v
go test ./internal/audit ./internal/detection -count=1
go test ./internal/gateway -run 'TestInspect|TestRuntime|TestGenericRulesCoverAgentFrameworkExploitShapes|TestBehavior' -count=1
pnpm -C desktop check
cargo check --manifest-path desktop/src-tauri/Cargo.toml --locked
```

测试使用临时数据库和模拟客户端，不向实际审计库写入，不运行靶场攻击或重启用户服务。
