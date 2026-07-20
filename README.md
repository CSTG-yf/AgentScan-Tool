<div align="center">

<pre>
     ____         ____                       ____  _
    / __ \  ___  / __/___   ___   ___  ___  / ___|| | __ _ __      __
   / / / / / _ \/ /_// _ \ / _ \ / __|/ _ \| |    | |/ _` |\ \ /\ / /
  / /_/ / /  __/ __//  __/| | | |\__ \  __/| |___ | | (_| | \ V  V /
 /_____/  \___/_/   \___/ |_| |_||___/\___| \____||_|\__,_|  \_/\_/
</pre>

<h1>DefenseClaw</h1>

<p>
  <strong>Security governance for OpenClaw and agentic AI runtimes.</strong><br />
  Scan capabilities before use, inspect runtime traffic, and export durable audit evidence.
</p>

<p>
  <a href="https://opensource.org/licenses/Apache-2.0"><img alt="License: Apache 2.0" src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" /></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-blue.svg" /></a>
  <a href="https://go.dev/"><img alt="Go 1.26.2" src="https://img.shields.io/badge/go-1.26.2-00ADD8.svg" /></a>
  <a href="https://discord.com/invite/nKWtDcXxtx"><img alt="Discord: Join us" src="https://img.shields.io/badge/Discord-Join%20Us-7289DA?logo=discord&amp;logoColor=white" /></a>
</p>

<p>
  <a href="https://www.cisco.com/site/us/en/products/security/ai-defense/index.html"><img alt="Cisco AI Defense" src="https://img.shields.io/badge/Cisco-AI%20Defense-049fd9?logo=cisco&amp;logoColor=white" /></a>
  <a href="https://learn-cloudsecurity.cisco.com/ai-security-framework"><img alt="AI Security Framework" src="https://img.shields.io/badge/AI%20Security-Framework-orange" /></a>
  <a href="https://deepwiki.com/cisco-ai-defense/defenseclaw"><img alt="Ask DeepWiki" src="https://deepwiki.com/badge.svg" /></a>
</p>

</div>

| Govern | Inspect | Probe |
|--------|---------|-------|
| Skills, MCP servers, plugins, and generated code before they run | Prompts, completions, tool calls, and sandbox activity at runtime | SQLite audit history, JSONL, OTLP, Splunk, webhooks, and TUI views |

DefenseClaw combines a Python operator CLI, a Go gateway sidecar, and an OpenClaw TypeScript plugin. Together they enforce a simple operating rule: untrusted agent capabilities are scanned, governed, logged, and blocked when policy says they are unsafe.

## Highlights

- **Admission control** - scan skills, MCP servers, plugins, and code before they run.
- **Runtime guardrails** - inspect prompts, completions, and tool calls with regex rules, policy, optional LLM judge, and Cisco AI Defense inspection.
- **CodeGuard** - built-in static checks for secrets, dangerous execution, unsafe deserialization, weak crypto, injection patterns, and risky file access.
- **OpenShell sandbox support** - Linux sandbox setup with network, filesystem, syscall, and policy controls.
- **Registries** - ingest external skill / MCP catalogs (corporate HTTPS YAML, [smithery.ai](https://smithery.ai/), [skills.sh](https://skills.sh/), git, ClawHub) with SSRF guards, scanner-driven verdicts, and auto-promotion into asset policy. See [docs/REGISTRIES.md](docs/REGISTRIES.md).
- **Audit and observability** - SQLite audit store, JSONL gateway logs, OTLP export, Splunk HEC, webhooks, Splunk Observability and local Grafana/Splunk bundles.
- **Operator UX** - a CLI and TUI for setup, health checks, alerts, block/allow lists, scanner results, and policy workflows.

---

## AgentRange Major Refactor v1.0（大重构版本）

本分支包含面向 `task/AgentRange-player` 测试靶场的一次大规模重构。DefenseClaw
从单纯复用既有 connector，扩展为可通过通用 inspect 合同保护 OpsPilot、Langflow、
Skill、MCP、数据库和网络副作用的检测、决策、证据与评测中心。

这次重构遵循“核心通用、靶场解耦”：DefenseClaw 核心只接收通用的
`connector/session_id/tool/args/content/direction/context` 字段，不读取 AgentRange
场景编号、固定实例或 Ground Truth；靶场格式转换、回放、证据落盘和指标计算全部
位于 `task/AgentRange-player`。

### 重构范围

- Gateway Tool Inspect 增加通用身份上下文和 tenant scope 检查，在静态工具放行前
  阻止跨租户 confused-deputy 请求。
- OpsPilot 接入 Prompt、Tool Call、Tool Result、Final Response 四阶段同步检查。
- Langflow 宿主端口由 `langflow-guard` 代理，支持方法、路径、查询串、JSON 与
  Multipart 内容检查。
- 运行证据统一为 RangeEvent JSONL，并包含 instance、trace、stage、asset、decision、
  latency 和 raw reference；Token、密码和常见秘密字段会被脱敏。
- 新增 27 项冻结资产清单、风险 taxonomy、六类通用行为规则、三模式策略合同、
  AttackChain DAG、instance 级 benchmark 与最终报告。
- 新增 FR/NFR 需求追踪矩阵，明确区分未实现、已实现待证据和证据齐全，禁止把
  无效请求或未实测指标伪装成安全能力。
- 已裁剪仓库 CI/CD 与 GitHub 测试流程；本靶场交付不依赖远端流水线。

### 计划书与操作文档

| 文档 | 用途 |
|---|---|
| [DefenseClaw AgentRange 改造计划书](task/DefenseClaw_AgentRange靶场改造实施计划书_v1.0.md) | 需求、接口、架构、任务分配、验收与风险基线 |
| [AgentRange 联调方案](task/AgentRange-player/integration/README.md) | DefenseClaw 与靶场接入点、策略和逐场景联调 |
| [运行手册](task/AgentRange-player/docs/OPERATIONS.md) | Windows/Linux 三模式运行与故障降级 |
| [固定演示流程](task/AgentRange-player/docs/DEMO.md) | 资产、observe、action、攻击链和报告演示顺序 |
| [交付证据索引](task/AgentRange-player/docs/DELIVERY.md) | M0-M7 交付物、验证入口和报告文件 |
| [最终测试结果展示页](task/AgentRange-player/dashboard/index.html) | 面向评委的赛题指标、场景覆盖、闭环与证据看板 |

### 运行真实靶场测试（Windows PowerShell）

以下流程会真实启动 Docker 靶场、调用 DefenseClaw Inspect API、回放攻击场景、
采集延迟与容器资源数据，并生成面向评委的静态结果页。项目不要求运行 Go 测试，
也不依赖 CI/CD 或 GitHub 测试。

#### 1. 检查环境并安装靶场依赖

```powershell
cd F:\agentscan2
docker version
docker compose version
python --version
defenseclaw --help
defenseclaw-gateway --help

cd F:\agentscan2\task\AgentRange-player
python -m pip install -r requirements-dev.txt
```

#### 2. 初始化并启动 DefenseClaw

首次运行：

```powershell
cd F:\agentscan2
defenseclaw init --enable-guardrail
defenseclaw setup gateway --host 127.0.0.1 --api-port 18970 --non-interactive --no-verify
defenseclaw setup guardrail --mode observe --scanner-mode local --non-interactive
defenseclaw-gateway start
defenseclaw-gateway status
Invoke-RestMethod http://127.0.0.1:18970/health
```

如果 Gateway 未加入 `PATH`，可将上述生命周期命令替换为
`.\defenseclaw-gateway.exe start/status/restart`。

AgentRange 运行在 Docker 中，因此 Gateway REST API 必须监听容器可达的宿主机地址。
编辑 `$HOME\.defenseclaw\config.yaml`，在已有 `gateway` 节点下确认：

```yaml
gateway:
  api_port: 18970
  api_bind: 0.0.0.0
```

随后运行：

```powershell
defenseclaw-gateway restart
defenseclaw-gateway status
```

`0.0.0.0` 仅适用于受控比赛主机；必须配置 Gateway Token 并用防火墙限制
18970 端口，禁止把无鉴权 Inspect API 暴露到局域网或公网。

#### 3. 配置并启动 AgentRange

```powershell
cd F:\agentscan2\task\AgentRange-player
Copy-Item .env.example .env -Force

$env:DEFENSECLAW_API_BASE = "http://host.docker.internal:18970"
$env:DEFENSECLAW_API_TOKEN = "<DefenseClaw Gateway Token>"
$env:DEFENSECLAW_FAIL_MODE = "open"
$env:DEFENSECLAW_TIMEOUT_SECONDS = "0.25"

docker compose up -d --build
docker compose ps
Invoke-RestMethod http://localhost:8100/health
Invoke-RestMethod http://localhost:7860/guard/health
```

同时把以上四个 `DEFENSECLAW_*` 值写入靶场 `.env`，确保新开 PowerShell 后仍然
生效。`/guard/health` 返回的 `protected` 应为 `true`。

#### 4. 快速真实冒烟测试

observe 只检测和留证，不阻断业务：

```powershell
defenseclaw setup guardrail --mode observe --scanner-mode local --non-interactive --restart
docker compose up -d --build --force-recreate
python .\scenario-runner\runner.py C2-D --mode observe --report .\integration\reports\observe-smoke.json
```

action 会在危险动作执行前阻断：

```powershell
defenseclaw setup guardrail --mode action --scanner-mode local --non-interactive --restart
docker compose up -d --build --force-recreate
python .\scenario-runner\runner.py C2-D --mode action --report .\integration\reports\action-smoke.json
```

action 模式预期出现 HTTP 403、`DEFENSECLAW_BLOCKED` 或对应阻断判定。可以把
`C2-D` 依次替换为 `C1-A`、`C1-B`、`C2-A`、`C2-B`、`C2-C`，验证全部攻击链。

#### 5. 正式三阶段全量测试

下面三个命令会分别重建对应模式的靶场。每个阶段默认使用固定随机种子 `1337`，
执行 5200 条回放且包含至少 80 条恶意样本：

```powershell
cd F:\agentscan2\task\AgentRange-player
.\integration\run.ps1 baseline
.\integration\run.ps1 observe
.\integration\run.ps1 action
```

- `baseline`：不接入 DefenseClaw，作为攻击成功率和性能对照组。
- `observe`：真实检测和记录风险，但不改变业务结果。
- `action`：真实阻断高风险动作，计算 Recall、FPR 和正常业务成功率。

汇总三阶段指标、攻击链和最终报告：

```powershell
python .\bench\benchmark.py summarize
python .\integration\attack_chain.py --output .\integration\reports\attack-chains.json
python .\integration\report.py
python .\dashboard\build_dashboard.py
Start-Process .\dashboard\index.html
```

主要结果位于 `bench/results/`、`integration/reports/`，评委展示入口为
[`dashboard/index.html`](task/AgentRange-player/dashboard/index.html)。最终验收重点检查：
Recall ≥ 95%、FPR < 5%、Inspect p95 < 1000ms、正常场景成功率 100%、CPU 增量 ≤ 5%。

测试结束后清理容器和数据卷：

```powershell
docker compose down -v
```

### 当前验证状态

- Python 合同、集成与静态展示页测试：30 项通过。
- 静态资产：27/27；必要风险：7/7；六条行为规则攻击/良性合同全部通过。
- baseline 烟雾：20/20 有效，正常业务成功率 100%，端到端 p95 约 164ms。
- OpsPilot 与 Langflow Guard 镜像可构建并通过健康检查。
- 需求追踪：12 项均有实现落点；8 项证据齐全，4 项等待真实 Gateway 与三模式全量结果。
- 按项目约束未运行 Go 测试；Go 源码已格式化，容器构建在本地时限内未完成，
  因此不宣称 Gateway 构建、observe/action、5200 全量指标或攻击链实测已经通过。

---

## Scope and Limitations

DefenseClaw is an enforcement and evidence layer for agentic AI deployments. It improves safety by combining scanner results, runtime inspection, policy decisions, sandbox controls, and audit trails, but it does not prove that an agent, skill, plugin, or model interaction is risk-free.

High-risk deployments should pair DefenseClaw with human review, least-privilege credentials, sandboxing, CI gates, and production monitoring. In observe mode, findings are logged without blocking. In action mode, configured HIGH and CRITICAL findings can block prompts, tool calls, or component admission.

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Quick Start](docs/QUICKSTART.md) | First successful local setup and scan flow |
| [Install](docs/INSTALL.md) | macOS, Linux, DGX Spark, source builds, and release installation |
| [CLI Reference](docs/CLI.md) | Python CLI commands and operator workflows |
| [API Reference](docs/API.md) | Gateway REST API and sidecar endpoints |
| [Architecture](docs/ARCHITECTURE.md) | Component model, data flow, and responsibilities |
| [Guardrail](docs/GUARDRAIL.md) | LLM and tool inspection architecture |
| [Guardrail Rule Packs](docs/GUARDRAIL_RULE_PACKS.md) | Rule packs, suppressions, and tuning |
| [Sandbox](docs/SANDBOX.md) | OpenShell sandbox setup, architecture, monitoring, and debugging |
| [Observability](docs/OBSERVABILITY.md) | Audit sinks, OTLP, Splunk, Grafana, and webhook notifications |
| [Splunk App](docs/SPLUNK_APP.md) | Local Splunk app dashboards and investigation flow |
| [Splunk O11y Dashboards](bundles/splunk_o11y_dashboards/README.md) | Splunk Observability Cloud dashboards and detectors for native OTel metrics |
| [TUI](docs/TUI.md) | Terminal dashboard panels and navigation |
| [Config Files](docs/CONFIG_FILES.md) | Config locations, environment variables, and policy files |
| [Registries](docs/REGISTRIES.md) | External skill / MCP catalog ingestion (clawhub, smithery, skills.sh, http, git, file) |
| [Plugin Development](docs/PLUGINS.md) | Custom scanner plugin workflow and example |
| [Testing](docs/TESTING.md) | Python, Go, TypeScript, Rego, docs, and CI checks |
| [Developer Spec](docs/development/DEVELOPER_SPEC.md) | Historical product/developer spec |
| [Gateway Spec](docs/reference/GATEWAY_SPEC.md) | Internal gateway package specification |

Project Markdown documentation is centralized under [docs/](docs/). Package-local READMEs stay beside bundles or examples that need local context.

---

## Installation

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Python | 3.10+ |
| Go | 1.26.2+ |
| Node.js | 18+ for the OpenClaw plugin |
| uv | Recommended for Python installs |
| Docker | Optional, for local observability and Splunk bundles |

### Install from source

```bash
git clone https://github.com/cisco-ai-defense/defenseclaw.git
cd defenseclaw
make all
```

### Install with the release script

```bash
VERSION=0.8.3
INSTALL_URL="https://raw.githubusercontent.com/cisco-ai-defense/defenseclaw/${VERSION}/scripts/install.sh"
curl -LsSf "$INSTALL_URL" | VERSION="$VERSION" bash
defenseclaw init --enable-guardrail
```

For platform-specific steps, see [docs/INSTALL.md](docs/INSTALL.md).

---

## Quick Start

```bash
# Check the local install and dependencies
defenseclaw doctor

# Initialize config, scanner defaults, and guardrail plumbing
defenseclaw init --enable-guardrail

# Scan installed agent capabilities
defenseclaw skill scan all
defenseclaw mcp list
defenseclaw plugin scan extensions/defenseclaw

# Start the Go gateway sidecar
defenseclaw-gateway start

# Open the operator dashboard
defenseclaw tui
```

Run the guardrail in observe mode while tuning:

```bash
defenseclaw setup guardrail --mode observe --restart
```

Switch to action mode when the policy is ready to block:

```bash
defenseclaw setup guardrail --mode action --restart
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full walkthrough.

---

## Architecture

| Component | Runtime | Role |
|-----------|---------|------|
| Python CLI | Python | Operator commands, scanner orchestration, config setup, local bundles |
| Gateway sidecar | Go | REST API, WebSocket bridge, policy engine, guardrail proxy, audit store, telemetry |
| OpenClaw plugin | TypeScript | Fetch interception, tool-call inspection hooks, slash commands, sidecar integration |
| Policies | YAML/Rego | Admission decisions, guardrail actions, sandbox/firewall behavior, scanner profiles |
| Documentation | Markdown/JSON | Centralized docs, package-local READMEs, and DeepWiki configuration |

The gateway exposes local REST APIs for the CLI and plugin, connects to OpenClaw over WebSocket, inspects LLM traffic through a local proxy, and records decisions in a durable audit store.

```text
Agent runtime -> OpenClaw plugin -> DefenseClaw gateway -> policy + scanners + audit
                                    |
                                    +-> guardrail proxy -> LLM provider
                                    +-> OTLP / Splunk / webhooks / JSONL
```

For diagrams and detailed flows, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Scanning and Guardrails

DefenseClaw wraps Cisco AI Defense scanners and local policy into a single admission flow:

| Surface | Scanner or control |
|---------|--------------------|
| Skills | `cisco-ai-skill-scanner`, CodeGuard, policy actions |
| MCP servers | `cisco-ai-mcp-scanner`, block/allow policy |
| Plugins | DefenseClaw plugin scanner, install-source checks, optional LLM analysis |
| Source code | CodeGuard via CLI, sidecar API, and plugin write/edit hooks |
| Prompts and completions | Guardrail proxy with rule packs, suppressions, optional LLM judge, Cisco inspection |
| Tool calls | Tool argument inspection, sensitive path checks, command risk checks, policy verdicts |

Scanner policies live in [policies/scanners/](policies/scanners/). Guardrail rule packs live in [policies/guardrail/](policies/guardrail/).

---

## Observability

DefenseClaw records enforcement and runtime evidence across several channels:

| Channel | Use |
|---------|-----|
| SQLite audit store | Local durable event history |
| Gateway JSONL | Correlated structured runtime events |
| OTLP | Named, independent metrics/logs/traces destinations with native fan-out |
| Splunk HEC | SIEM forwarding and local Splunk app workflows |
| Splunk O11y dashboards | Native Splunk Observability Cloud dashboards and detectors for DefenseClaw metrics |
| Webhooks | Slack, PagerDuty, Webex, and generic event notifications |
| TUI | Operator-facing alerts, health, scans, tools, policy, and setup |

Start local observability with:

```bash
defenseclaw setup local-observability up
defenseclaw-gateway start
defenseclaw setup local-observability status
```

Add Galileo Cloud or self-hosted Galileo without replacing the local route:

```bash
export GALILEO_API_KEY='...'
defenseclaw setup galileo --project defenseclaw --logstream production
defenseclaw setup galileo test
```

See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md), the
[Galileo guide](docs-site/content/docs/observability/galileo.mdx), and
[schema ownership map](schemas/README.md). Splunk-specific setup is in
[docs/SPLUNK_APP.md](docs/SPLUNK_APP.md).

For Splunk Observability Cloud, use the dashboard bundle at
[bundles/splunk_o11y_dashboards/README.md](bundles/splunk_o11y_dashboards/README.md):

```bash
defenseclaw setup splunk dashboards apply \
  --api-url <api-endpoint> \
  --o11y-api-token <api-access-token> \
  --with-detectors \
  --enable-detectors \
  --yes
```

---

## Development

```bash
# Build all components
make build

# Run primary test suites
make test

# Run lint checks
make lint
```

Focused test and development guidance lives in [docs/TESTING.md](docs/TESTING.md) and [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md), and the focused docs for the area you are changing.

## Security

Please report vulnerabilities through the process in [SECURITY.md](SECURITY.md).

## License

Apache 2.0 - see [LICENSE](LICENSE).

Copyright 2026 Cisco Systems, Inc. and its affiliates.
