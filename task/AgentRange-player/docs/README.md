# OpsPilot 智能体安全靶场 · 选手手册

OpsPilot 靶场模拟某公司内部上线的企业智能研发运营助手，能够帮助企业员工做工单分析、代码检索、日报生成、邮件总结、数据库查询、运维排障等功能。

选手需要在靶场中识别 Agent 资产、发现配置风险、分析恶意 MCP 与 Skill、监控异常行为，并自行设计检测与阻断方案。

> **模型说明**：为避免不同大模型在推理能力上的差异影响靶场复现效果，赛题内置了确定性模型轨迹回放服务（`llm-stub`），
> 用以模拟 Agent 运行所需的模型调用。选手**无需自行准备或配置任何模型 API**，即可获得稳定、可复现的攻击与检测语料。


docker 环境启动后，可使用 `make replay` 命令，一键启动靶场漏洞复现脚本，参赛队伍可根据相关线索，分析 Agent 安全风险，完成题目所要求的内容。

---

## 一、架构总览

```
                 ┌───────────────────—──────────────────┐
                 │              OpsPilot App            │
                 │  /run 编排入口：Prompt + 工具 + RAG  │
                 │  身份：JWT(可伪造) → 服务账号(confused)│
                 └───┬───────────────┬───────────────┬───┘
                     │               │               │
            ┌────────▼─────┐  ┌──────▼──────┐  ┌─────▼─────────┐
            │  MCP 工具面  │  │  Langflow   │  │   业务后端     │
            │              │  │ (供应链引入)│  │ customer-db(PG)│
            └──────┬───────┘  └─────────────┘  └───────────────┘
                   │
        ┌──────────▼───────────┐   egress-net（出网边界）
        │  c2-sink / mock-internet │
        └──────────────────────┘
```

**两个网络**：`opspilot-net`（内部业务网）与 `egress-net`（出网边界；`shell-runner`、`threat-intel`、`notes-sync` 与 `c2-sink`/
`mock-internet` 接在此处，是"合法出网"与"恶意外传"共享的边界）。

**对外暴露端口**：

| 组件                  | 说明                           | 端口（宿主机） |
|---------------------|------------------------------|---------|
| `opspilot-app`      | 被测智能体应用，`/login`、`/run` 编排入口 | `8100`  |
| `langflow`          | 供应链引入的低代码编排框架（存在漏洞）          | `7860`  |
| `llm-stub`          | 确定性 LLM 桩，按轨迹回放，不联真模型        | `8000`  |
| `postgres-customer` | 多租户客户数据库                     | `55432` |
| `c2-sink`           | 模拟 C2 数据回收端（出网边界内）           | `9100`  |
| `mock-internet`     | 模拟外部情报站点                     | `9000`  |
| `mcp-*`（8 个）        | MCP 工具面，仅内网互通，无对外端口          | —       |

---

## 二、靶场启动方式

依赖：Docker + Docker Compose、Python 3.12+、`pip install -r requirements-dev.txt`（回放/生成脚本用）。

```bash
# 1. 准备环境变量（含身份/传播等风险配置，见下文漏洞说明）
cp .env.example .env

# 2. 拉起全部靶场组件（等价于 docker compose up -d --build）
make up

# 3. 内存生成回放语料（不落盘）
make generate

# 4. 生成多租户 customer-db 数据（acme / globex 两个租户）
make seed

# 5. 健康检查（探测 opspilot-app /health）
make smoke
```

`make up` 会先校验 7 份 Skill 载荷，并从 `integrity/baseline/` 恢复缺失项，再执行 `docker compose up -d --build`。如需直接运行 Compose，先执行 `python integrity/check.py --repair`；若文件内容与基线不同，校验会报错且不会覆盖改动。Dockerfile 还会在构建时复查，阻止缺少 Skill 的镜像生成。桌面端“启动靶场”也会执行同一校验并重建镜像。

如果本机留有隔离副本，可指定 `python integrity/check.py --repair --quarantine-root <隔离目录>/skills`；只有内容与固定基线一致时才会使用它。扫描仍会判定并阻断靶场内的恶意 Skill，但会保留原文件供靶场重建。

可选：`make test` 运行全量单元测试（`pytest -q`）。

启动后可访问：OpsPilot `http://localhost:8100`、Langflow `http://localhost:7860`。

---

## 三、剧本编排（语料回放）启动方式

攻击/正常流量以**内存语料**形式确定性回放。

**语料构成**（由 `make replay` 在内存中生成）：

- 事件流：约 **5200** 条，只存在于 `scenario-runner` 进程内存中。
- 模型轨迹：回放开始前注入 `llm-stub` 内存，回放结束后清空。

**回放命令**：

```bash
make replay                 # 全量回放内存生成的事件流
```

**场景清单**：

| 编号  | 类别     | 标题                           | 主要资产         |
|-----|--------|------------------------------|--------------|
| `1` | cat1   | Langflow 注入命令执行（CWE-94）      | langflow     |
| `2` | cat1   | Langflow 文件上传定时任务落地（CWE-434） | langflow     |
| `3` | cat2   | 直接提示注入诱导越权 SQL（CWE-77/20）    | opspilot-app |
| `4` | cat2   | 知识库间接注入触发数据外传（CWE-77/200）    | opspilot-app |
| `5` | cat2   | PR 描述间接注入触发受管主机代码执行          | opspilot-app |
| `6` | cat2   | 恶意 skill 隐藏指令读取敏感文件          | opspilot-app |
| `7` | normal | 正常运维问答                       | opspilot-app |

---

## 四、选手交付要求

1. 题目旨在考察选手能够开发一套通用算法，针对各类型 Agent 进行风险检测与拦截，本靶场只作为验证最终算法效果使用。
2. Agent 资产风险识别能力：根据给定的环境，发现AI Agent相关资产（包括Agent、AI供应链组件、模型、工具等），并具备配置项安全检测能力，识别恶意Skills与MCP工具，要求资产盘点漏报率低于5%、准确率99%以上，资产风险识别准确率达到95%以上，漏报率低于5%。
3. Agent风险监控与阻断能力：监控 Agent 运行时风险，还原攻击链路，并对攻击进行检测和阻断。要求漏洞利用以及Agent异常行为检测和阻断误报率低于5%，检出95%以上，响应时间小于1秒，同时CPU占用率控制在5%以内，业务0中断影响。
4. 不限制操作系统，不限制外联大模型 API 检测，但要保证核心算法自主实现，同时检测效果满足题目要求指标。
5. 选手无需收集 /admin/trajectories 接口下的内容，需通过应用/系统内收集所需信息。

---

## 五、目录概览

| 目录                  | 作用                |
|---------------------|-------------------|
| `opspilot-app/`     | 被测智能体应用           |
| `langflow/`         | 供应链框架镜像与导入流程      |
| `mcp/`              | 8 个 MCP 工具 server |
| `skills/`           | 技能库               |
| `backends/`         | 业务后端与数据种子         |
| `attack/`           | 攻击载荷与外部设施         |
| `corpus-generator/` | 确定性语料生成器（模板化）     |
| `scenario-runner/`  | 语料回放编排器           |

## 六、常用命令

| 命令                           | 作用              |
|------------------------------|-----------------|
| `make up` / `make down`      | 启动 / 销毁（含数据卷）靶场 |
| `make generate`              | 内存生成校验，不写语料文件   |
| `make seed`                  | 生成多租户客户数据       |
| `make smoke`                 | OpsPilot 健康检查   |
| `make replay [SCENARIO=xxx]` | 全量 / 单场景内存回放    |
| `make test`                  | 运行单元测试          |
