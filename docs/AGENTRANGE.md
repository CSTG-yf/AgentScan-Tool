# AgentRange 集成与评测

本文所有命令均从仓库根目录执行。返回 [项目 README](../README.md)。

行为、审计、异常的接入流程、去重机制与更新步骤见 [AgentRange 运行时事件接入](AGENTRANGE_RUNTIME_EVENTS.md)。

`task/AgentRange-player/` 是原始靶场。适配器在项目侧生成 overlay，将 OpsPilot 入口、LLM、MCP 与 Langflow 流量送入检查 sidecar，不修改靶场源码。其 Compose 文件使用 `!reset []` 重置入口端口，需使用支持该语法的 Docker Compose 版本。

## 启动适配靶场

先完成 [README 中的 CLI/Gateway 源码安装](../README.md#python-cli-与-go-gateway)，并停止占用 `18970` 的其他网关实例。以下步骤在仓库根目录、同一个 PowerShell 会话中执行：

```powershell
# 与适配器生成的 env_file 路径、报告脚本统一
$env:DEFENSECLAW_HOME = Join-Path $PWD '.defenseclaw-home'
$env:DEFENSECLAW_CONFIG = Join-Path $env:DEFENSECLAW_HOME 'config.yaml'
defenseclaw init --skip-install
defenseclaw setup guardrail --mode observe --scanner-mode local --non-interactive
```

在生成的 `.defenseclaw-home/config.yaml` 中合并以下字段，保留其他配置，然后启动网关。`gateway.api_bind` 才是 REST API 的显式监听地址；`setup gateway --host` 配置的是网关连接目标，不能用来替代它。

```yaml
gateway:
  api_bind: "0.0.0.0"
  api_port: 18970
  token_env: DEFENSECLAW_GATEWAY_TOKEN
```

此监听配置用于容器访问宿主机，应限制到受控的本地实验网络。

```powershell
defenseclaw config validate
defenseclaw-gateway start

# 首次启动网关后确认令牌文件已生成，Compose sidecar 会读取它
Test-Path (Join-Path $env:DEFENSECLAW_HOME '.env')

defenseclaw agentrange adapt --range-root .\task\AgentRange-player --output-dir .\task\agentrange-adapter --gateway-base http://host.docker.internal:18970 --force

docker compose --env-file .\task\AgentRange-player\.env.example -f .\task\AgentRange-player\docker-compose.yml -f .\task\agentrange-adapter\docker-compose.defenseclaw.override.yml config --quiet
docker compose --env-file .\task\AgentRange-player\.env.example -f .\task\AgentRange-player\docker-compose.yml -f .\task\agentrange-adapter\docker-compose.defenseclaw.override.yml up -d --build
```

示例直接将靶场的 `.env.example` 作为 Compose 输入。需要自定义时，在项目侧保存环境文件并替换 `--env-file`。适配默认失败放行；若评测要求检查服务异常时也拒绝请求，生成 overlay 时添加 `--fail-mode closed`。更改 overlay 后需要重新执行 Compose `up`。

靶场的数据初始化、健康检查与回放步骤见 [选手手册](../task/AgentRange-player/docs/README.md)；也可在桌面“靶场控制”中配置路径并运行回放。切换 `observe/action` 需更新网关 Guardrail 配置并重启；`baseline` 使用原始 Compose、不加载适配 overlay。

## 生成证据和报告

完成回放后，在上述会话的仓库根目录执行：

```powershell
python .\integration\static_inventory.py --output .\integration\reports\static-scan.json
python .\integration\rule_contract.py --output .\integration\reports\rule-contract.json
python .\integration\attack_chain.py --audit-db "$env:DEFENSECLAW_HOME\audit.db"
python .\bench\benchmark.py summarize
python .\integration\report.py
python .\dashboard\build_dashboard.py
Start-Process .\dashboard\index.html
```

Before a live replay, prepare an isolated benchmark run. The generated
`gt.jsonl` stays in the run directory and must not be mounted into the
detector or sent to `/admin/trajectories`:

```powershell
python .\bench\agentrange_benchmark.py prepare --output-dir .\bench\runs\action-<run-id> --mode action
$env:AGENTRANGE_RUN_DIR = ".\bench\runs\action-<run-id>"
# 在另一终端与回放并行采样，不能在回放结束后用单个快照代替窗口采样：
# python .\bench\resource_sampler.py --output "$env:AGENTRANGE_RUN_DIR\resources.jsonl" --mode action --samples 20 --interval-ms 250
python .\task\AgentRange-player\scenario-runner\runner.py
python .\bench\agentrange_benchmark.py score --run-dir .\bench\runs\action-<run-id>
```

The live runner records request status and timing. Side-effect probes (C2
receipts, database rows, file/cron markers, and command markers) must be
added to `observations.jsonl` before scoring. Missing probes remain
`unknown`; they are never treated as a successful block.

| 产物 | 含义 |
| --- | --- |
| `integration/reports/static-scan.json` | 合同资产覆盖、静态风险命中及良性对照结果 |
| `integration/reports/rule-contract.json` | 通用规则对合同内攻击/良性样例的匹配与耗时检查 |
| `integration/reports/runtime-events.jsonl`、`attack-chains.json` | 从指定审计库导出的 AgentRange 事件与顺序关联链 |
| `bench/results/summary.json` | 运行时统计，以及已有 baseline/observe/action 报告的汇总 |
| `integration/reports/final-report.json`、`final-report.md` | 静态、运行时、评测及需求证据索引 |
| `dashboard/index.html` | 可在浏览器打开的静态评审页面 |

**汇总不等于完成评测。** `bench/benchmark.py summarize` 读取 `bench/results/baseline.json`、`observe.json`、`action.json`，不会启动三种模式的回放或生成这些输入。缺失模式保留在 `missing_modes`；验收还应检查事件数量、延迟样本数、召回率、误报率及实际执行结果。静态合同命中率不能替代真实运行时检出率；`requirements_contract.py` 的 `evidence-ready` 仅表示证据路径存在。

项目侧 Python 报告链按 session/trace 聚合并生成 `observed_before` 边；桌面实时攻击链来自 Go 检测引擎的持久化对象，两者用途与构建逻辑不同。评测标签、场景编号与 Ground Truth 用于评分，不应作为生产检测特征。详见 [数据合同](../integration/agentrange_contracts/README.md)、[需求追踪](../integration/requirements.yaml) 和 [适配说明](../task/agentrange-adapter/README.md)。

停止容器时保留数据卷，便于继续调查：

```powershell
docker compose --env-file .\task\AgentRange-player\.env.example -f .\task\AgentRange-player\docker-compose.yml -f .\task\agentrange-adapter\docker-compose.defenseclaw.override.yml down
defenseclaw-gateway stop
```
