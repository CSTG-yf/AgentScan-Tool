# AgentRange / DefenseClaw 改动、结果与后续计划

更新时间：2026-08-04  
项目目录：`E:\3安全创新赛\AgentScan\AgentScan-Tool-codex-agentrange-defenseclaw-major-refactor-v1`  
工作目录：`task\AgentRange-player`

## 1. 当前总体状态

本阶段已经完成原计划 P0-P6 的执行和证据刷新。

结论分两层：

- 运行时联动闭环已经跑通：Gateway 可被容器访问，OpsPilot 能把请求、工具调用、工具结果、最终响应送入 DefenseClaw，C2-D 在 observe/action 模式下都能形成证据和真实拦截。
- 全量 benchmark 已完成但存在明确差距：`action` 模式无 invalid、无 FP、正常业务成功率 100%，但全量 Recall 只有 65%，未达到 95% 目标。

当前未达标原因已经定位：28 条 FN 主要来自 C1 Langflow 场景。当前闭环主要覆盖 OpsPilot/C2，C1 Langflow 还没有纳入完整 DefenseClaw runtime closure。

## 2. 原始 P0-P6 安排

这一轮执行是按照 `docs/RUNTIME_CLOSURE_CHECKLIST.md` 中的 P0-P6 收口清单推进的。原始安排如下。

### P0：Connect the Gateway

目标：先把 DefenseClaw Gateway 真正接入 AgentRange 运行环境。

验收安排：

- Host 能访问 Gateway health endpoint。
- Docker 容器内也能访问 Gateway。
- `task/AgentRange-player/.env` 或进程环境中有正确的 `DEFENSECLAW_API_BASE` 和 `DEFENSECLAW_API_TOKEN`。
- 从容器发起的 C2-D `inspect/tool` 请求能返回 `action=block`、`mode=action`，并包含 `.env` 读取相关 finding。

作用：P0 是所有 runtime 验证的基础。如果容器无法访问 Gateway，后面的 observe/action、attack chain、benchmark 都只能停留在本地模拟或 fail-open/fail-closed 状态。

### P1：C2-D Observe Minimal Closure

目标：在最小范围内验证 C2-D observe 闭环。

验收安排：

- 只运行 C2-D 场景，不先扩大到全量 benchmark。
- 业务流量不能被中断。
- evidence 中必须出现 `mode=observe`。
- 至少一个事件包含 `raw_action=block` 或 `would_block=true`。
- finding 需要能解释 `.env` 访问或 notes-sync 外传风险。

作用：P1 用来证明“观察模式”能发现风险但不拦截业务，同时能留下可审计证据。

### P2：C2-D Action Minimal Closure

目标：在最小范围内验证 C2-D action 真实拦截。

验收安排：

- 只运行 C2-D 场景。
- 响应返回 HTTP 403。
- 返回体包含 `DEFENSECLAW_BLOCKED`。
- verdict 必须是 `mode=action`，不能是 `integration-fail-closed`。
- 阻断必须发生在敏感读取或同步/外传副作用之前。
- runner 不能再把 C2-D 全部统计成 FN。

作用：P2 用来证明 DefenseClaw 不只是记录，还能在危险副作用发生前真实阻断。

### P3：Harden Runner Blocked Semantics

目标：修正 runner 的统计口径，避免错误地把基础设施失败或 fail-closed 当成安全能力。

验收安排：

- 只有 `DEFENSECLAW_BLOCKED` 且 verdict 为 `mode=action/action=block` 才算 true runtime block。
- `integration-fail-closed` 永远不能算 TP。
- observe 指标使用 evidence 中的 `would_block` 或 `raw_action=block`。
- 5xx、timeout、网络失败保持 invalid。

作用：P3 保证后续 benchmark 的 TP/FP/TN/FN 是可信的，不用“错误状态”冒充安全拦截。

### P4：Generate Attack Chains

目标：把 runtime evidence 还原成攻击链，用于报告和答辩展示。

验收安排：

- `attack-chains.json` 不能为空。
- 至少 C2-D 包含 prompt、skill/tool、decision、raw_ref 等节点。
- `block_node_id` 指向真实 decision 节点。
- `unexecuted_side_effects` 能解释被阻止的外传或命令执行副作用。

作用：P4 把单条日志提升为可解释攻击路径，证明系统能关联“输入、工具调用、风险决策、副作用阻断”。

### P5：Run Full Three-Mode Benchmark

目标：运行 baseline、observe、action 三模式全量对照 benchmark。

验收安排：

- 生成 `baseline.json`、`observe.json`、`action.json`、`summary.json`。
- action 指标需要满足或显式报告以下差距：
  - Recall >= 95%。
  - FPR < 5%。
  - inspect p95 < 1000 ms。
  - normal success rate = 100%。
- CPU 增量要来自真实 Docker stats 证据。

作用：P5 是从“单场景闭环”升级到“全量可复现实验”的阶段，也是最终报告中最关键的量化结果来源。

### P6：Refresh Final Report and Dashboard

目标：把所有证据刷新到最终报告和离线 Dashboard。

验收安排：

- `final-report.json` 和 `final-report.md` 包含非空 benchmark 数据。
- runtime attack chains 数量大于 0。
- evidence index 包含当前 JSONL、三模式 benchmark 结果和 attack chains。
- 未测、失败、边界项必须显式写出，不能推断为通过。

作用：P6 是提交收口阶段，确保评审能直接从报告和 Dashboard 看到指标、证据、攻击链和未达标边界。

## 3. 本阶段核心改动

### 2.1 Gateway connector mode 支持

涉及文件：

- `internal/gateway/inspect_hooks.go`
- `internal/gateway/inspect.go`
- `internal/gateway/gateway_test.go`

改动内容：

- inspect request、response、tool-response 请求结构增加 `connector` 字段。
- 新增 connector 级别模式解析，支持读取 `guardrail.connectors.opspilot.mode`。
- `inspect/tool`、`inspect/request`、`inspect/response`、`inspect/tool-response` 都使用 connector 级别 mode，而不是只依赖全局 `guardrail.mode`。
- 增加 connector mode override 的测试用例。

作用：

- 允许 OpsPilot 单独在 `observe` 和 `action` 间切换。
- 避免全局配置和连接器配置不一致时统计/拦截语义混乱。
- 为后续接入更多连接器提供同一套模式选择机制。

### 2.2 OpsPilot DefenseClaw 客户端补充 connector 上下文

涉及文件：

- `opspilot-app/security/defenseclaw.py`

改动内容：

- `inspect_request` payload 增加 `connector: opspilot`。
- `inspect_response` payload 增加 `connector: opspilot`。
- `inspect_tool_response` payload 增加 `connector: opspilot`。
- 已有的 client name 和 `X-DefenseClaw-Client` 逻辑继续保留。

作用：

- Gateway 可以识别请求来自 OpsPilot connector。
- connector mode override 才能真正生效。
- evidence 中也能保留 connector 来源，方便攻击链和报告关联。

### 2.3 runner 统计语义修正

涉及文件：

- `scenario-runner/runner.py`
- `scenario-runner/test_runner_report.py`

改动内容：

- action 模式只把真实 `DEFENSECLAW_BLOCKED` 且 verdict 为 `mode=action`、`action=block` 的响应计为真实阻断。
- `integration-fail-closed` 不再计为 TP。
- observe 模式不看 HTTP 403，而是从 evidence 中读取 `would_block=true` 或 `raw_action=block` 来统计“检出”。
- 5xx、timeout、网络错误仍计为 invalid，不伪装成安全阻断。
- runner 增加 evidence offset 读取逻辑，避免把历史事件误计入当前实例。
- 修复全量 benchmark 长跑时 JWT 过期问题：`/run` 返回 HTTP 401 后，刷新当前用户 token 并重放一次请求。

作用：

- 避免 observe 模式被错判为 FN。
- 避免 fail-closed 或基础设施错误被错判为 TP。
- 解决 5200 条全量长跑超过 JWT TTL 后连续 401 导致 invalid 激增的问题。

### 2.4 benchmark mode 透传

涉及文件：

- `bench/benchmark.py`
- `bench/test_benchmark.py`

改动内容：

- `run_mode()` 调用 `replay_generated()` 时传入 `mode`。
- 三模式 summary 读取 `baseline.json`、`observe.json`、`action.json`。
- summary 输出每个模式的 counts、metrics、inspect latency、CPU total 和相对 baseline 的 CPU increment。

作用：

- `baseline`、`observe`、`action` 的统计口径一致。
- P5 验收可以直接从 `bench/results/summary.json` 得到。

### 2.5 attack chain 支持 observe would-block

涉及文件：

- `integration/attack_chain.py`

改动内容：

- 攻击链生成时支持把 `would_block=true` 或 `raw_action=block` 识别为阻断决策。
- `block_node_id` 可以指向 observe 模式下的 would-block 节点。

作用：

- observe 不拦截业务，但仍能生成可解释攻击链。
- C2-D 攻击链可以展示 prompt、tool call、tool result、final response 与防护判定的关系。

### 2.6 final report 证据索引和边界说明

涉及文件：

- `integration/report.py`
- `integration/reports/final-report.json`
- `integration/reports/final-report.md`

改动内容：

- evidence index 增加 benchmark 结果文件：
  - `bench/results/baseline.json`
  - `bench/results/observe.json`
  - `bench/results/action.json`
  - `bench/results/summary.json`
- final report 自动读取 `summary.json`。
- 当 action recall 低于 95% 时，自动写入 degradation/boundary 说明。

作用：

- P6 的“证据索引包含三模式 benchmark 结果”已满足。
- 未达标项不会被掩盖，报告中明确写出 Recall gap。

### 2.7 Dashboard 数据刷新

涉及文件：

- `dashboard/build_dashboard.py`
- `dashboard/data.js`
- `dashboard/test_dashboard.py`

改动内容：

- Dashboard 适配当前 `summary.json` 结构，从 `modes.action.inspect_latency_ms.p95` 读取 inspect p95。
- 从 `modes.action.cpu_increment_pct` 读取 CPU 增量。
- Dashboard evidence 链接增加 observe/action/summary/attack chains。
- Dashboard 测试从“action 缺失时等待”更新为“action 存在且 Recall gap 必须显式 fail”。

作用：

- Dashboard 能展示当前真实 action 结果。
- Recall 65% 被标记为 fail，而不是误报为 pass。
- 其他已达标项继续显示 pass。

### 2.8 过程文档更新

涉及文件：

- `docs/RUNTIME_CLOSURE_CHECKLIST.md`
- `docs/PROJECT_PROGRESS_HANDOFF.md`
- `docs/CHANGES_RESULTS_AND_NEXT_PLAN.md`

改动内容：

- `RUNTIME_CLOSURE_CHECKLIST.md` 更新 P0-P6 状态。
- `PROJECT_PROGRESS_HANDOFF.md` 更新为 2026-08-04 当前交接状态。
- 本文件用于记录详细改动、当前结果和后续计划。

## 4. 当前生成的关键结果文件

### 3.1 benchmark 结果

- `bench/results/baseline.json`
- `bench/results/observe.json`
- `bench/results/action.json`
- `bench/results/summary.json`

### 3.2 runtime evidence

- `integration/reports/opspilot-events.jsonl`
- `integration/reports/langflow-events.jsonl`
- `integration/reports/p1-C2-D-observe.json`
- `integration/reports/p2-C2-D-action.json`
- `integration/reports/p3-C2-D-observe-runner.json`
- `integration/reports/p4-C2-D-observe-events.jsonl`
- `integration/reports/p5-resume-C2-D-action.json`

### 3.3 attack chain 和最终报告

- `integration/reports/attack-chains.json`
- `integration/reports/final-report.json`
- `integration/reports/final-report.md`
- `dashboard/data.js`

## 5. 当前 benchmark 指标

### 4.1 baseline

文件：`bench/results/baseline.json`

| 指标 | 数值 |
| --- | ---: |
| total | 5200 |
| valid | 5200 |
| invalid | 0 |
| TP | 0 |
| FP | 0 |
| TN | 5120 |
| FN | 80 |
| precision | 0.0 |
| recall | 0.0 |
| FPR | 0.0 |
| normal_success_rate | 1.0 |
| E2E p95 | 110.8 ms |

解释：这是未接入防护时的基线，攻击样本全部未检出是预期现象。

### 4.2 observe

文件：`bench/results/observe.json`

| 指标 | 数值 |
| --- | ---: |
| total | 5200 |
| valid | 5200 |
| invalid | 0 |
| TP | 52 |
| FP | 0 |
| TN | 5120 |
| FN | 28 |
| precision | 1.0 |
| recall | 0.65 |
| FPR | 0.0 |
| normal_success_rate | 1.0 |
| E2E p95 | 1858.668 ms |
| inspect p95 | 9.898 ms |
| CPU increment | 0.01% |

解释：observe 不阻断业务，正常业务成功率 100%。52 条恶意样本被 evidence 标记为 would-block，28 条 C1 Langflow 样本未进入当前 OpsPilot runtime closure。

### 4.3 action

文件：`bench/results/action.json`

| 指标 | 数值 |
| --- | ---: |
| total | 5200 |
| valid | 5200 |
| invalid | 0 |
| TP | 52 |
| FP | 0 |
| TN | 5120 |
| FN | 28 |
| precision | 1.0 |
| recall | 0.65 |
| FPR | 0.0 |
| normal_success_rate | 1.0 |
| E2E p95 | 1989.733 ms |
| inspect p95 | 10.326 ms |
| CPU increment | 3.04% |

解释：action 已经没有 401 invalid 问题。OpsPilot/C2 范围内防护稳定，正常样本不被误拦截；但 C1 Langflow 未闭环导致全量 Recall 未达标。

## 6. P5 验收状态

来自 `bench/results/summary.json`：

| 验收项 | 状态 | 当前值/说明 |
| --- | --- | --- |
| Recall >= 95% | FAIL | action recall = 65% |
| FPR < 5% | PASS | action FPR = 0% |
| inspect p95 < 1000 ms | PASS | action inspect p95 = 10.326 ms |
| normal success rate = 100% | PASS | action normal_success_rate = 1.0 |
| CPU increment <= 5% | PASS | action CPU increment = 3.04% |

关键判断：P5 数据齐全，环境错误已清理，但全量 Recall 指标未达标。

## 7. P6 验收状态

P6 已完成。

已验证：

- `final-report.json` 包含非空 benchmark 数据。
- `final-report.md` 包含 Acceptance、Evidence index、Degradation and boundaries。
- runtime attack chains 数量为 13。
- blocked chains 数量为 13。
- evidence index 包含当前 JSONL、attack chains、三模式 benchmark 和 summary。
- Recall gap 被明确写出，没有被推断为通过。

final report 当前 degradation note 包含：

```text
Full benchmark action recall is 65.00%; C1 Langflow scenarios remain outside the current OpsPilot runtime closure.
```

## 8. 当前测试状态

已运行：

```powershell
& 'E:\anaconda3\envs\Safe\python.exe' -m pytest integration\test_report.py dashboard\test_dashboard.py bench\test_benchmark.py scenario-runner\test_runner_report.py integration\test_attack_chain.py -q
```

结果：

```text
12 passed in 0.92s
```

说明：

- 报告生成逻辑通过。
- Dashboard 数据构建逻辑通过。
- benchmark summary 逻辑通过。
- runner observe/action 统计语义通过。
- attack chain 生成逻辑通过。

## 9. 当前风险和边界

### 8.1 Recall 未达标

风险：如果比赛要求全量 benchmark Recall >= 95%，当前结果不满足。

原因：C1 Langflow 场景没有纳入完整 runtime closure。当前 DefenseClaw/OpsPilot 链路能覆盖 C2-A/B/C/D，尤其 C2-D 已完成最小闭环和攻击链证据，但 C1-A/C1-B 的 Langflow ingress 风险还没有以同等方式进入 Gateway connector mode、evidence、runner 统计和 action block。

影响：

- 全量 80 条恶意样本中有 28 条 FN。
- Recall 固定在 52/80 = 65%。
- 仅靠重跑 action/observe 不会解决 Recall 问题。

### 8.2 E2E p95 较高但 inspect p95 达标

观察：

- action E2E p95 = 1989.733 ms。
- action inspect p95 = 10.326 ms。

解释：

- E2E 包含整个靶场请求、业务处理、工具调用、Docker/HTTP 开销。
- 验收项要求的是 inspect p95 < 1000 ms，当前已达标。

### 8.3 文档中的中文编码显示问题

现象：部分终端输出中的中文显示为乱码。

判断：文件本身按 UTF-8 写入；乱码主要来自 PowerShell 终端编码显示，不影响 JSON/Markdown 内容本身。

注意：后续不要用 PowerShell `Get-Content` + `Set-Content` 粗暴改写含中文文件。建议继续使用 .NET UTF-8 读写或精准补丁。

## 10. 后续计划

后续分为两个路线。必须先明确比赛提交策略，再决定是否继续开发。

## 方案 A：按 OpsPilot/C2 范围提交

适用条件：比赛展示允许明确说明当前系统范围是 AgentRange OpsPilot runtime closure，C1 Langflow 属于边界外或下一阶段。

目标：不再补 C1，直接整理提交材料，强调已闭环的 C2 能力和明确边界。

执行步骤：

1. 审阅 `final-report.md`。
   - 确认 Acceptance 中 Recall 为 FAIL。
   - 确认 Degradation and boundaries 中写明 C1 Langflow 未纳入当前闭环。

2. 审阅 Dashboard。
   - 打开 `dashboard/index.html`。
   - 确认 scorecard 中“恶意实例 Recall”为 fail。
   - 确认 FPR、inspect p95、CPU、正常业务中断为 pass。

3. 准备答辩表述。
   - 强调 C2-D 完整攻击链：敏感读取到同步/外传被阻断。
   - 强调 observe/action 双模式：observe 记录 would-block，action 真实拦截。
   - 强调统计严谨：fail-closed、401、timeout 不计为 TP。
   - 主动说明全量 Recall gap 来自 C1 Langflow 未闭环。

4. 可选：增加一页“下一阶段工作”。
   - C1 Langflow connector。
   - Langflow ingress evidence。
   - C1 observe/action benchmark。
   - 重新冲 Recall >= 95%。

优点：

- 当前证据完整、可复现。
- 风险透明，不伪造通过。
- 不需要再跑长时间全量 benchmark。

缺点：

- 全量 Recall 不达标，如果评审硬性要求 95%，会扣分。

## 方案 B：补 C1 Langflow runtime closure

适用条件：比赛必须按全量 benchmark 验收，Recall >= 95% 是硬指标。

目标：让 C1-A/C1-B 也进入 DefenseClaw runtime closure，至少把 28 条 FN 中绝大部分转为 TP。

### B1. 阅读和定位 C1 链路

优先阅读：

- `integration/langflow_guard.py`
- `scenario-runner/runner.py`
- `scenario-runner/runner.py` 中 `fire_cat1()`
- `attack/payloads.py` 或相关 C1 payload 生成逻辑
- `integration/reports/langflow-events.jsonl`
- `bench/results/action.json` 中 C1-A/C1-B records

需要确认：

- C1-A 是哪个入口触发。
- C1-B 是哪个上传入口触发。
- 当前 `langflow_guard` 是否已经写 evidence。
- 当前 C1 evidence 是否进入 `EVIDENCE_PATHS`。
- C1 action 模式下是否有真实 403 语义。

### B2. 设计 Langflow connector mode

目标：与 OpsPilot connector 一样支持独立模式。

建议：

- connector 名称使用 `langflow` 或 `langflow-guard`，保持全链路一致。
- Gateway inspect payload 增加 `connector: langflow`。
- 配置中增加或确认：

```yaml
guardrail:
  connectors:
    langflow:
      mode: observe/action
      rule_pack_dir: C:/Users/28354/.defenseclaw/policies/guardrail/strict
```

需要避免：

- 不要把 C1 伪装成 OpsPilot。
- 不要把 5xx 或 guard unavailable 计成 TP。

### B3. 接入 C1 evidence

目标：C1 observe 模式下，即使业务不被阻断，也能写出 `would_block=true` 或 `raw_action=block`。

需要检查/实现：

- C1-A command execution payload 的 inspect 点。
- C1-B path traversal upload payload 的 inspect 点。
- evidence JSONL 中要包含：
  - `instance_id`
  - `trace_id`
  - `stage`
  - `asset_id`
  - `direction`
  - `payload`
  - `decision.mode`
  - `decision.action`
  - `decision.raw_action`
  - `decision.would_block` 或等效字段

### B4. 接入 C1 action block

目标：C1 action 模式下，危险请求在副作用前返回真实 block。

验收：

- C1-A 不执行命令。
- C1-B 不写入 `/etc/cron.d/...` 或其他持久化路径。
- 返回状态可被 runner 识别为真实 block。
- block verdict 为 `mode=action`、`action=block`。

### B5. 修改 runner C1 统计

当前 runner 的重点修复已经覆盖 OpsPilot/C2。补 C1 时需要确保：

- `EVIDENCE_PATHS` 包含 `langflow` 对应 JSONL。
- `fire_cat1()` 的 response block 语义可被 `action_block_status()` 或新的 C1 block parser 正确识别。
- observe 模式 C1 使用 langflow evidence 的 `would_block/raw_action=block` 统计 detected。
- C1 的 fail-open/fail-closed 不计为 TP。

### B6. 增加 C1 focused 验证

建议先跑小范围，不要直接全量：

```powershell
& 'E:\anaconda3\envs\Safe\python.exe' scenario-runner\runner.py C1-A --mode observe --report integration\reports\p7-C1-A-observe.json
& 'E:\anaconda3\envs\Safe\python.exe' scenario-runner\runner.py C1-A --mode action --report integration\reports\p7-C1-A-action.json
& 'E:\anaconda3\envs\Safe\python.exe' scenario-runner\runner.py C1-B --mode observe --report integration\reports\p7-C1-B-observe.json
& 'E:\anaconda3\envs\Safe\python.exe' scenario-runner\runner.py C1-B --mode action --report integration\reports\p7-C1-B-action.json
```

目标：

- C1-A observe detected > 0，blocked = 0。
- C1-A action blocked = total。
- C1-B observe detected > 0，blocked = 0。
- C1-B action blocked = total。
- invalid = 0。

### B7. 重跑全量并刷新报告

完成 C1 后再跑：

```powershell
& 'E:\anaconda3\envs\Safe\python.exe' bench\benchmark.py run --mode observe --output bench\results\observe.json
& 'E:\anaconda3\envs\Safe\python.exe' bench\benchmark.py run --mode action --output bench\results\action.json
& 'E:\anaconda3\envs\Safe\python.exe' bench\benchmark.py summarize --result-dir bench\results --output bench\results\summary.json
& 'E:\anaconda3\envs\Safe\python.exe' integration\report.py
& 'E:\anaconda3\envs\Safe\python.exe' dashboard\build_dashboard.py
```

预期：

- 如果 C1-A/C1-B 全覆盖，Recall 可从 65% 提升到接近或达到 100%。
- FPR 应继续保持 0%。
- normal_success_rate 必须保持 100%。
- inspect p95 应继续低于 1000 ms。

### B8. 更新测试

补 C1 后建议增加：

- C1 observe detected 统计测试。
- C1 action true block 统计测试。
- Langflow connector mode override 测试。
- Langflow evidence redaction 测试。
- C1 fail-open/fail-closed 不计 TP 的测试。

## 11. 推荐下一步

如果目标是比赛得分最大化，推荐走方案 B，补 C1 Langflow runtime closure。原因很直接：当前除 Recall 外全部关键指标已经达标，剩余 28 条 FN 是清晰、集中、可定位的问题。补 C1 的收益最大，能直接解决唯一失败验收项。

如果时间紧，走方案 A 也可以，但要在提交材料和答辩中主动承认边界，不要把全量 Recall 写成通过。

## 12. 操作注意事项

- 不要打印 `.env` 中的 `DEFENSECLAW_API_TOKEN`。
- 不要使用批量删除命令。
- 不要使用 `Remove-Item -Recurse`、`rm -rf`、`rmdir /s` 等命令。
- Python 使用 `E:\anaconda3\envs\Safe\python.exe`。
- Go test 之前被审批拒绝过；除非用户明确同意，不要继续跑 Go test。
- Gateway 绑定保持 `172.30.224.1:18970`，不要随意改为 `0.0.0.0`。
- 修改含中文文件时，优先使用 UTF-8 明确编码写入，避免 PowerShell 默认编码导致乱码。
- 全量 benchmark 耗时较长，建议后台运行并定期查看 `integration/reports/*-events.jsonl` 尾部实例号。

## 13. 快速检查命令

确认没有后台 benchmark：

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" | Select-Object ProcessId,CommandLine
```

确认 Gateway：

```powershell
Get-Process defenseclaw-gateway -ErrorAction SilentlyContinue | Select-Object Id,ProcessName,Path
Invoke-RestMethod -Uri http://172.30.224.1:18970/health | ConvertTo-Json -Depth 4
```

确认 Docker：

```powershell
docker compose ps
```

读取 summary：

```powershell
& 'E:\anaconda3\envs\Safe\python.exe' -c "import json; s=json.load(open('bench/results/summary.json',encoding='utf-8')); print(json.dumps(s['acceptance'],ensure_ascii=False,indent=2)); print(json.dumps(s['modes']['action'],ensure_ascii=False,indent=2))"
```

刷新报告：

```powershell
& 'E:\anaconda3\envs\Safe\python.exe' integration\report.py
& 'E:\anaconda3\envs\Safe\python.exe' dashboard\build_dashboard.py
```