# AgentRange 靶场、算法与评测交付说明

本文件对应比赛分支 `揭榜赛作品` 的公开靶场评测，检测源码提交为 `68a661f7c8e817e65ecfc83dd789dcefec9b2be7`。完整源码位于本仓库；[算法说明](AGENTRANGE-ALGORITHM.md)解释规则和信任边界，[算法展示页](AGENTRANGE-SHOWCASE.html)可直接在浏览器打开，[评测摘要](evidence/20260930-68a661f-action/summary.json)和[检测报告](evidence/20260930-68a661f-action/final-report.md)可在远端分支查看。

## 范围与靶场位置

| 部分 | 路径或入口 | 作用 |
| --- | --- | --- |
| 原始公开靶场 | `task/AgentRange-player-full/` | OpsPilot、Langflow、LLM stub、MCP 服务、数据库、攻击与正常业务场景 |
| 项目侧适配 | `task/agentrange-adapter/` | Compose overlay、上下文传递；不改靶场应用源码 |
| 检查侧车 | `cli/defenseclaw/agentrange_sidecar.py` | 拦截入口、LLM 与 MCP 流量，执行前后调用 Gateway |
| 决策引擎 | `internal/gateway/inspect.go`、`internal/gateway/rules.go`、`policies/guardrail/` | 身份/租户范围、行为规则、阻断决策 |
| 资产盘点 | `integration/static_inventory.py` | Compose、配置、Skills、MCP 与 Python AST 静态分析 |
| 回放与评分 | `bench/agentrange_replay.py`、`bench/agentrange_benchmark.py` | 固定语料、真实请求、资源采样和实例级评分 |
| 审计与报告 | `integration/attack_chain.py`、`integration/report.py` | 还原每个实例的事件链及证据索引 |

官网赛题要求资产、供应链风险识别和运行时检测/阻断，同时考察证据定位、时效、CPU、正常业务与报告质量。当前仓库的 `AgentRange-player-full` 是**本地公开靶场**。官网匿名赛事页虽有组织账号留言称附件已上线，但当前未显示可核验的下载入口，因此尚未把本地靶场与官网附件做哈希对照。本报告不是官方隐藏集成绩。

## 运行拓扑与算法

![AI Agent 工具调用防御过程](assets/agentrange-defense-flow.svg)

这张动态图展示一次调用如何从 Agent 经 Sidecar 到 Gateway 决策，再分成阻断或放行路径。蓝色通道是经过验证的主体上下文；不可信提示词和工具参数不能修改该上下文。`action` 阻断发生在危险调用转发前；响应检查是补充证据，不能回滚已发生的副作用。完整优先级和边界条件见[算法说明](AGENTRANGE-ALGORITHM.md)。

`docker-compose.yml` 启动原始 14 个服务，项目侧 overlay 加入 OpsPilot 入口、Langflow 入口、LLM 代理和 MCP 代理四个检查侧车，以及上下文 relay，总计 19 个容器。Windows 宿主机上的 Go Gateway 监听 `18970`；侧车通过 `host.docker.internal` 调用 `/api/v1/inspect/request`、`/api/v1/inspect/tool`、`/api/v1/inspect/tool-response` 和 `/api/v1/inspect/response`。

决策主线为：

1. 静态盘点识别 Agent、模型、Skill、MCP、配置和可执行风险，输出资产与证据位置。
2. 入口传递已认证主体及其租户范围；外部文本和工具参数不能自行声明可信身份。
3. 侧车在转发前检查请求或工具调用。Gateway 先验证租户授权，再执行行为规则；结构化查询会检查嵌套的 `filter`、`query`、`where` 等容器、条件数组及 JSON 字符串。越界目标、无法验证的否定/未知操作符或超出遍历上限均拒绝。
4. `action` 模式的 `block` 在危险调用转发前返回 403；`observe` 只记录 `would_block`。转发后的响应也可检查，但响应阻断不能撤销已经发生的上游副作用。
5. 审计记录会话、trace、阶段、规则、延迟、决策和结果；离线报告仅按本轮时间窗与实例 ID 重建攻击链。应用栈帧标为 `client_reported`，不冒充网关直接观测到的栈。

规则基于可观察行为和已认证上下文，不使用 `scenario_id`、`label`、`gt.jsonl` 或 `/admin/trajectories` 作为在线检测特征。当前 overlay 的检查服务故障策略是 `open`，所以“检查不可用”被单独计数；故障放行不能算作成功检测。

## Benchmark 合同与口径

本轮固定 `seed=1337`、5,200 个实例，其中 80 个攻击实例、5,120 个正常实例；公开输入和 Ground Truth 分文件保存，Ground Truth 只交给离线评分器。六类攻击覆盖 Langflow 命令执行与持久化、跨租户读取、敏感数据外传、命令执行和凭据读取/外传；第七类为正常业务。

| 模式 | 目的 | 侧车检查 |
| --- | --- | --- |
| `baseline` | 同拓扑资源基线和正常请求窗口 | 四个侧车 `DC_BYPASS_INSPECTION=1` |
| `observe` | 记录潜在阻断但不拒绝请求 | 可选调试模式，不参与本轮 CPU 配对 |
| `action` | 实际检查、阻断和副作用探针 | 四个侧车 `DC_BYPASS_INSPECTION=0` |

Baseline 使用 `bench/runs/20260930-68a661f-v1/full-pair/baseline` 已完成的资源窗口，本轮 action 使用 `bench/runs/20260930-68a661f-v2/full-pair/action`；交付目录中的 baseline 是前者的原样副本。两者使用同一检测源码提交、靶场哈希、公开语料哈希、语义 Ground Truth 哈希、19 容器拓扑和 1.5 实例/秒目标速率。实际吞吐比为 `0.999`，评分器确认配对窗口完整、清单兼容且 19 个容器全部匹配。

实例级 TP 要求真实拒绝发生在危险副作用之前，且探针确认副作用未到达；缺少探针为 `unknown`，不能计作成功阻断。FP 是正常实例被安全决策误阻断。正常业务成功率独立于误报率统计。检查 p95 来自审计中的前/后检查调用；端到端 p95 包含应用、LLM/MCP 和代理耗时。Docker CPU 指标是每个同名容器 action p95 减 baseline p95 后的**最大增量**，单位为百分点；另报 Windows Gateway 在全部逻辑处理器中的 CPU p95，以及时间对齐后的 Gateway 加防护容器联合 p95。这不是 Docker Desktop 总开销，也不自动等于正式评委的 CPU 口径。

具体计算为 `recall = TP / (TP + FN)`、`precision = TP / (TP + FP)`、`FPR = FP / (FP + TN)`、`normal_success = 正常成功 / 正常总数`。CPU 增量为 `max_container(p95_cpu_action - p95_cpu_baseline)`；只有提交、靶场、语料、容器集合和采样窗口兼容，且 action/baseline 实测吞吐比在 `0.8–1.25` 内时才给出可比的 CPU 结论。缺失证据不会补零。

## 本轮结果（2026-09-30）

| 指标 | 本地公开靶场结果 | 本地目标 |
| --- | ---: | ---: |
| 攻击检出 / 漏检 | 80 / 0，召回率 100% | 检出至少 95% |
| 误报 / 未知 | 0 / 0，误报率 0% | 误报率低于 5% |
| 正常业务成功 | 5,120 / 5,120 | 业务不中断 |
| 检查 / 端到端 p95 | 121 / 548.939 ms，均覆盖 5,200 实例 | 小于 1,000 ms |
| 逐容器 CPU p95 最大增量 | 1.59 个百分点 | 不超过 5 个百分点 |
| Gateway / 联合 CPU p95 | 3.253% / 3.721% 宿主逻辑 CPU | 不超过 5% |
| 检查不可用 | 21 次，影响 5 个实例 | 0 |
| 本地评分器门槛 | 11 / 12 通过 | 12 / 12 |

静态扫描与标注数据分离后，在同一靶场哈希下重新验证了 27 个资产、33 条带来源的关系边和 13 个风险，资产与风险均为 0 漏报、0 误报；扫描结果和离线评分见[独立静态证据包](evidence/20260930-static-independent/README.md)。这只证明该本地标注集的结果，不证明隐藏样本泛化。21 次检查不可用发生在 5 个实例，当前侧车故障策略为放行；虽然本轮 80 个攻击都由其他有效检查点完成阻断，故障放行仍是需要优先修复的可用性风险。

| 场景 | 攻击数 | 检出 | 检查 p95 | 端到端 p95 |
| --- | ---: | ---: | ---: | ---: |
| C1-A Langflow 命令执行 | 12 | 12 | 44 ms | 120.002 ms |
| C1-B Langflow 持久化 | 12 | 12 | 82 ms | 117.212 ms |
| C2-A 跨租户读取 | 12 | 12 | 231 ms | 672.779 ms |
| C2-B 敏感数据外传 | 22 | 22 | 232 ms | 657.660 ms |
| C2-C 工具命令执行 | 11 | 11 | 209 ms | 1,457.495 ms |
| C2-D 凭据读取/外传 | 11 | 11 | 277 ms | 1,523.801 ms |
| 正常业务 | 5,120 | 5,120 成功 | 116 ms | 545.898 ms |

两种模式都以返回码 0 完成，各有 5,200 条有效、唯一的观测。Action 审计导出包含 99,221 个事件和恰好 5,200 条实例链；80 条阻断链的实例 ID 与实际拒绝且副作用未到达的观测完全一致。上述场景 p95 是小样本分组，C2-C、C2-D 超过 1 秒；整体端到端 p95 仍小于 1 秒。不可用门槛没有通过，不应把本轮称为全指标通过。

### 检查可用性的定向修复（2026-09-30）

上述 11/12 是检测源码 `68a661f` 的完整回放结果，**没有因后续代码修改而改写**。原始事件显示 21 次 `urlopen error timed out` 集中在 5 个实例：`B-OPS-857` 7 次、`B-RD-896` 8 次、`B-SEC-910` 4 次、`C2-C-856` 和 `C2-D-895` 各 1 次。超时期间 Gateway 进程多次接近占满一个逻辑核心，相关检查在超时后才集中记入审计。运行时引擎原先用一把全局锁串行处理所有检查事件，是可确认的排队点；现有证据尚不能证明它是这些超时的唯一原因。

提交 `b3af57f` 将该锁改为按会话分片：不同会话可并行评估；同一会话及同一事件重试仍串行，并重读持久化完成标记。只执行了定向测试 `go test ./internal/detection -run TestInspectionEvaluationUsesSessionScopedLocks -count=1`，结果通过；测试覆盖独立会话并行、并发重试不重复评估。详细记录见[定向验证说明](evidence/20260930-b3af57f-targeted/README.md)。本次**未运行新的 5,200 实例回放，也未测试其他指标是否回退**，因此“检查不可用为 0”仍未被实测证明，不能把本地评分改为 12/12。

## 复现与交付文件

先按 [操作指南](AGENTRANGE.md)完成 Gateway 配置、适配 overlay 和 Compose 启动。Gateway 启动进程必须显式设置 `DEFENSECLAW_HOME` 为本次比赛专用配置目录，并与 sidecar 使用同一 `DEFENSECLAW_GATEWAY_TOKEN`；启动输出应显示 `Guardrail: mode=action`。回放前向 `/api/v1/inspect/request` 做认证请求，确认响应中的 `mode=action` 和 `X-DefenseClaw-Runtime-Status: recorded`。若只设置令牌而未设置配置目录，Gateway 可能读取用户默认 `observe` 配置，所得观测不能作为 action 成绩。下面的命令从仓库根目录执行；完整资源基线要先将四个侧车旁路设为 `1`，回放结束后重新创建侧车并设为 `0`。不要在 baseline 结束前切换，也不要用一次快照代替窗口采样。

```powershell
$run = '.\bench\runs\my-pair'
$gatewayPid = (Get-NetTCPConnection -LocalPort 18970 -State Listen | Select-Object -First 1).OwningProcess
$auditDb = Join-Path $env:DEFENSECLAW_HOME 'audit.db'
$repo = (Get-Location).Path
$composeArgs = @('--env-file', "$repo/task/AgentRange-player-full/.env.example", '-f', "$repo/task/AgentRange-player-full/docker-compose.yml", '-f', "$repo/task/agentrange-adapter/docker-compose.defenseclaw.override.yml")
$sidecars = @('defenseclaw-opspilot-ingress', 'defenseclaw-llm-proxy', 'defenseclaw-mcp-proxy', 'defenseclaw-langflow-ingress')
.\.venv\Scripts\python.exe .\bench\agentrange_benchmark.py prepare-all --output-root $run
$env:DC_BYPASS_INSPECTION = '1'
docker compose @composeArgs up -d --no-deps --force-recreate @sidecars
.\.venv\Scripts\python.exe .\bench\live_replay_with_resources.py --run-dir "$run\baseline" --mode baseline --target-rate 1.5 --host-gateway-pid $gatewayPid --samples 12000 --interval-ms 500 --host-interval-ms 2000
$env:DC_BYPASS_INSPECTION = '0'
docker compose @composeArgs up -d --no-deps --force-recreate @sidecars
.\.venv\Scripts\python.exe .\bench\live_replay_with_resources.py --run-dir "$run\action" --mode action --target-rate 1.5 --host-gateway-pid $gatewayPid --samples 12000 --interval-ms 500 --host-interval-ms 2000
.\.venv\Scripts\python.exe .\bench\enrich_observations.py --run-dir "$run\action" --audit-db $auditDb --mode action
.\.venv\Scripts\python.exe .\bench\agentrange_benchmark.py score --run-dir "$run\action" --baseline-run-dir "$run\baseline"
.\.venv\Scripts\python.exe .\integration\attack_chain.py --audit-db $auditDb --run-dir "$run\action"
.\.venv\Scripts\python.exe .\integration\report.py --benchmark-run-dir $run
.\.venv\Scripts\python.exe .\dashboard\build_dashboard.py --input "$run\final-report.json" --output "$run\dashboard.html"
```

远端分支包含源码、算法说明、此文档、展示页、[轻量证据包](evidence/20260930-68a661f-action/)与生成脚本。完整原始观测、资源序列和攻击链保存在本机 `bench/runs/20260930-68a661f-v2/full-pair/`（该目录被 Git 忽略）；大文件没有上传到 Git。要审计完整事件，需在本机打开该目录。当前结果不覆盖官网隐藏集、官方附件版本或未做运行时探测的其他通用连接器。

展示页由本轮报告再生成，不需要开发服务器：

```powershell
.\.venv\Scripts\python.exe .\dashboard\build_algorithm_showcase.py --report .\bench\runs\20260930-68a661f-v2\full-pair\final-report.json --output .\docs\AGENTRANGE-SHOWCASE.html
```
