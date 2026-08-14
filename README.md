<div align="center">

<h1>TraceBastion</h1>

<p>
  <strong>Runtime protection and traceability for local AI Agents.</strong><br />
  Discover Agent processes, enforce command and file policy, and retain durable audit evidence.
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

TraceBastion combines a Windows desktop control plane, a Python operator CLI,
a Go gateway sidecar, and an OpenClaw TypeScript plugin. Together they enforce
a simple operating rule: untrusted Agent capabilities are discovered, scanned,
governed, traced, and blocked when policy says they are unsafe.

## Highlights

- **Admission control** - scan skills, MCP servers, plugins, and code before they run.
- **Runtime guardrails** - inspect prompts, completions, and tool calls with regex rules, policy, optional LLM judge, and Cisco AI Defense inspection.
- **CodeGuard** - built-in static checks for secrets, dangerous execution, unsafe deserialization, weak crypto, injection patterns, and risky file access.
- **OpenShell sandbox support** - Linux sandbox setup with network, filesystem, syscall, and policy controls.
- **Registries** - ingest external skill / MCP catalogs (corporate HTTPS YAML, [smithery.ai](https://smithery.ai/), [skills.sh](https://skills.sh/), git, ClawHub) with SSRF guards, scanner-driven verdicts, and auto-promotion into asset policy. See [docs/REGISTRIES.md](docs/REGISTRIES.md).
- **Audit and observability** - SQLite audit store, JSONL gateway logs, OTLP export, Splunk HEC, webhooks, Splunk Observability and local Grafana/Splunk bundles.
- **Operator UX** - a CLI and TUI for setup, health checks, alerts, block/allow lists, scanner results, and policy workflows.
- **Windows Agent process guard** - discover known Agent processes, monitor their child commands, and terminate configured process trees through a LocalSystem service.
- **File policy and activity Trace** - audit configured Windows paths, enforce a sensitive-file blacklist, and query process/file activity from a retained SQLite Trace store.

## TraceBastion Desktop

The Windows desktop application provides the primary local security console.
It includes Agent discovery, the runtime knowledge catalog, command and file
blacklists, Activity Trace, evidence review, AgentRange controls, and an NSIS
installer with a selectable destination directory.

See [desktop/README.md](desktop/README.md) for architecture, prerequisites,
build instructions, policy behavior, acceptance tests, and upgrade details.
Windows users can download the current x64 installer from
[GitHub Releases](https://github.com/CSTG-yf/AgentScan-Tool/releases/latest).
The existing `defenseclaw` command names, gateway executable, Windows service
key, application identifier, and machine data directory remain unchanged as
internal compatibility identifiers so existing installations can upgrade
without losing policy or evidence.

---

## AgentRange 集成与评测升级

本项目保留 `task/AgentRange-player` 作为未侵入的原始靶场目录；TraceBastion 适配、
运行时证据、静态资产合同、攻击链、benchmark、最终报告和 dashboard 均放在目标项目侧。
这样可以吸收升级版项目的验证与展示能力，同时避免把靶场源码改动误当成 TraceBastion 升级。

### 升级范围

- `cli/defenseclaw/agentrange_adapter.py` 与 `cli/defenseclaw/agentrange_sidecar.py`
  生成项目侧 Compose overlay，通过 sidecar 接入 OpsPilot、Langflow 和 MCP/Skill 相关流量。
- `integration/agentrange_contracts/` 固化资产、场景矩阵、RangeEvent、Decision、AttackChain
  与 Ground Truth 合同。
- `integration/static_inventory.py` 扫描未改动的 `task/AgentRange-player`，并把结果写入
  `integration/reports/static-scan.json`。
- `integration/runtime_rules.yaml`、`integration/rule_contract.py`、`integration/policy.yaml`
  与 `integration/policy_contract.py` 提供规则和策略合同验证。
- `integration/attack_chain.py`、`bench/benchmark.py`、`integration/report.py`
  与 `dashboard/build_dashboard.py` 汇总运行时审计证据、指标、需求追踪和展示页。
- `integration/requirements.yaml` 记录项目侧实现与证据路径，避免引用靶场内迁移脚本作为交付能力。

### 关键文档

| 文档 | 用途 |
|---|---|
| [AgentRange 改造计划书（历史文档）](task/DefenseClaw_AgentRange靶场改造实施计划书_v1.0.md) | 需求、接口、架构、任务分配、验收与风险基线 |
| [非侵入 AgentRange 适配说明](task/agentrange-adapter/README.md) | 项目侧 Compose overlay、sidecar 代理和启动方式 |
| [AgentRange contracts](integration/agentrange_contracts/README.md) | 资产、场景、事件、决策和攻击链数据合同 |
| [需求追踪矩阵](integration/requirements.yaml) | FR/NFR 实现点和证据文件 |
| [最终报告脚本](integration/report.py) | 汇总静态、运行时、benchmark、攻击链和需求证据 |
| [Dashboard 生成脚本](dashboard/build_dashboard.py) | 生成面向评审的静态展示页 |

### 运行方式（Windows PowerShell）

以下命令均从项目根目录运行：

```powershell
cd C:\Users\11388\Desktop\AgentScan-Tool
```

生成或刷新非侵入式靶场适配 overlay：

```powershell
defenseclaw agentrange adapt `
  --range-root .\task\AgentRange-player `
  --output-dir .\task\agentrange-adapter `
  --gateway-base http://host.docker.internal:18970 `
  --force
```

启动 TraceBastion Gateway 后，用原始靶场 Compose 加项目侧 overlay 启动 AgentRange：

```powershell
defenseclaw init --enable-guardrail
defenseclaw setup gateway --host 0.0.0.0 --api-port 18970 --non-interactive --no-verify
defenseclaw setup guardrail --mode observe --scanner-mode local --non-interactive
defenseclaw-gateway start

docker compose `
  -f .\task\AgentRange-player\docker-compose.yml `
  -f .\task\agentrange-adapter\docker-compose.defenseclaw.override.yml `
  up -d --build
```

切换 observe/action 模式时，仍由 TraceBastion Gateway 的 guardrail 配置决定：

```powershell
defenseclaw setup guardrail --mode observe --scanner-mode local --non-interactive --restart
defenseclaw setup guardrail --mode action --scanner-mode local --non-interactive --restart
```

生成静态扫描、规则合同、攻击链、benchmark、最终报告和 dashboard：

```powershell
python .\integration\static_inventory.py --output .\integration\reports\static-scan.json
python .\integration\rule_contract.py --output .\integration\reports\rule-contract.json
python .\integration\attack_chain.py --output .\integration\reports\attack-chains.json
python .\bench\benchmark.py summarize
python .\integration\report.py
python .\dashboard\build_dashboard.py
Start-Process .\dashboard\index.html
```

主要结果位于 `integration/reports/`、`bench/results/` 和 `dashboard/index.html`。
验收时重点查看资产覆盖、规则合同、风险召回、误报率、Inspect p95、攻击链闭环和需求证据状态。

测试结束后清理容器和数据卷：

```powershell
docker compose `
  -f .\task\AgentRange-player\docker-compose.yml `
  -f .\task\agentrange-adapter\docker-compose.defenseclaw.override.yml `
  down -v
```

### 当前验证状态

- Python 脚本语法检查通过：contracts、静态扫描、规则/策略/需求合同、攻击链、benchmark、报告和 dashboard。
- 静态资产扫描通过：27/27 资产命中，7/7 必要风险命中。
- 规则合同通过：6 条通用行为规则均命中攻击样例并避开良性样例。
- 本地审计库可生成攻击链与最终报告；全量 Docker 回放结果以实际运行后的 `bench/results/` 为准。

---

## Scope and Limitations

TraceBastion is an enforcement and evidence layer for agentic AI deployments. It improves safety by combining scanner results, runtime inspection, policy decisions, sandbox controls, and audit trails, but it does not prove that an agent, skill, plugin, or model interaction is risk-free.

High-risk deployments should pair TraceBastion with human review, least-privilege credentials, sandboxing, CI gates, and production monitoring. In observe mode, findings are logged without blocking. In action mode, configured HIGH and CRITICAL findings can block prompts, tool calls, or component admission.

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
Agent runtime -> OpenClaw plugin -> TraceBastion gateway -> policy + scanners + audit
                                    |
                                    +-> guardrail proxy -> LLM provider
                                    +-> OTLP / Splunk / webhooks / JSONL
```

For diagrams and detailed flows, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Scanning and Guardrails

TraceBastion wraps Cisco AI Defense scanners and local policy into a single admission flow:

| Surface | Scanner or control |
|---------|--------------------|
| Skills | `cisco-ai-skill-scanner`, CodeGuard, policy actions |
| MCP servers | `cisco-ai-mcp-scanner`, block/allow policy |
| Plugins | TraceBastion plugin scanner, install-source checks, optional LLM analysis |
| Source code | CodeGuard via CLI, sidecar API, and plugin write/edit hooks |
| Prompts and completions | Guardrail proxy with rule packs, suppressions, optional LLM judge, Cisco inspection |
| Tool calls | Tool argument inspection, sensitive path checks, command risk checks, policy verdicts |

Scanner policies live in [policies/scanners/](policies/scanners/). Guardrail rule packs live in [policies/guardrail/](policies/guardrail/).

---

## Observability

TraceBastion records enforcement and runtime evidence across several channels:

| Channel | Use |
|---------|-----|
| SQLite audit store | Local durable event history |
| Gateway JSONL | Correlated structured runtime events |
| OTLP | Named, independent metrics/logs/traces destinations with native fan-out |
| Splunk HEC | SIEM forwarding and local Splunk app workflows |
| Splunk O11y dashboards | Native Splunk Observability Cloud dashboards and detectors for TraceBastion metrics |
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
