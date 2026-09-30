# AgentRange 检测与阻断算法说明

本文描述比赛分支当前可运行的实现。正式评分以官网发布的 Docker 靶场和隐藏样本为准；公开靶场的本地评测只用于复现与调参。

可直接打开 [交互式算法展示页](AGENTRANGE-SHOWCASE.html) 查看阶段、场景与本轮 benchmark；靶场拓扑和复现命令见 [交付说明](AGENTRANGE-DELIVERY.md)。

## 输入与信任边界

- 静态输入是靶场的 Compose、配置、Skill 和 MCP 源文件。`integration/static_inventory.py` 从 Compose 和源码发现资产，再用 Python AST、配置字段及风险规则检查可执行行为。`integration/risk_taxonomy.yaml` 给出风险类别和证据规则。
- 运行时输入来自项目侧生成的四个 HTTP sidecar：OpsPilot 入口、Langflow 入口、LLM 代理和 MCP 代理。它们在转发前后调用 Gateway 的 `/api/v1/inspect/request`、`/api/v1/inspect/tool`、`/api/v1/inspect/tool-response`、`/api/v1/inspect/response`。原始靶场源码不因适配而修改。
- 已认证主体的租户范围由应用入口的 JWT/上下文传入，并通过会话与 trace 关联到下游工具调用。提示词或工具参数里的文字不能自行声明可信身份；缺失授权上下文时，租户专属检查不据此推断权限。
- 在线决策只使用请求、工具参数、响应、主体上下文和当前策略。`scenario_id`、攻击标签、`gt.jsonl` 与轨迹管理接口仅供离线回放和评分，不能进入检测特征。

## 决策过程

1. 静态盘点先定位资产及调用关系。对 Python 工具定义、`shell=True`、调用者可控的文件路径等使用 AST 识别，避免把注释或普通字符串误当成可执行代码；配置与提示词规则保留原文件、行号和证据。静态输出按资产聚合风险，不代替运行时阻断。
2. Sidecar 在请求转发前选择检查点：用户/应用输入走 request；MCP `tools/call` 走 tool；LLM 返回的工具调用在代理返回给应用前再次走 tool。Gateway 先检查主体授权边界，再检查显式工具策略和通用规则包，最后按连接器的运行模式给出 `action`、`raw_action`、严重度和规则证据。
3. 授权检查针对结构化工具参数中的 `tenant`、`tenant_id`、`tenantId`，并沿 `filter`、`filters`、`query`、`where`、`params`、`parameters` 查询容器检查嵌套目标。常见的 `field/value`、`key/value`、`column/value` 条件、数组以及 JSON 字符串查询会被解析；支持安全的等值和集合匹配，否定或未知操作符按无法验证处理并阻断。任一目标超出已认证主体租户即阻断；遍历上限为 256 个节点、4 层，无法完整验证时也阻断。普通文本与无关 metadata 不作为租户目标。
4. Sidecar 收到 `block` 时在转发前返回 403，并记录检查、阻断和运行结果。允许的请求转发后还要检查工具响应或最终响应；响应阻断只禁止该响应送达调用者，不能声称已撤销上游此前产生的副作用。
5. `observe` 保留 `raw_action` 和 `would_block` 供调试，但不执行拒绝；`action` 才执行阻断。检查服务异常由适配配置的 `DC_FAIL_MODE` 决定，当前公开靶场 overlay 为 `open`，因此评测单独统计检查不可用次数，不能把失败放行算作正常检测。

通用规则位于 `internal/gateway/rules.go` 和 `policies/guardrail/`；租户授权在 `internal/gateway/inspect.go`；流量选择、转发与阻断在 `cli/defenseclaw/agentrange_sidecar.py`。这些规则依赖可观察的行为和授权上下文，不匹配公开靶场的场景编号或实例 ID。

工具调用的核心顺序可写为：

```text
principal_scope = authenticated_context(session, trace)
targets, complete = bounded_structured_query_targets(tool_args)
if principal_scope exists and (!complete or targets exceed principal_scope):
    return block(reason="authorization")
if mcp_server_or_tool_is_explicitly_blocked:
    return block(reason="policy")
if tool_is_explicitly_allowed:
    return code_content_check_if_write_tool_else_allow()
findings = scan_behavior_rules(tool_name, tool_args)
decision = resolve(findings, connector_policy_mode)
record(decision, rule_evidence, timing, actual_forwarding_result)
return decision
```

`bounded_structured_query_targets` 只沿结构化查询键和租户字段遍历，最多 256 个节点、4 层；无法验证的查询返回 `complete=false`。该授权检查先于工具 allow-list，因此允许使用工具不等于允许访问其他租户。`observe` 会保留原始阻断判定，但只在 `action` 执行拒绝。

## 证据与评估

Sidecar 为每次检查记录实例、会话、trace、调用阶段、工具/路径、决策、时延和结果；应用栈帧作为 `client_reported` 来源单独标注，不参与授权判定。`integration/attack_chain.py` 只按本轮 action 回放的时间窗及实例 ID 导出事件，构建有顺序和证据链接的攻击链。离线报告同时给出提示词/工具链、阻断依据和实际结果。

`bench/agentrange_replay.py` 用同一 seed、公开输入、语义 Ground Truth 和靶场哈希运行 baseline/action。Baseline 保留相同 19 容器拓扑，仅让四个检查 sidecar 跳过 Gateway 调用；Action 恢复检查。评分在实例级计算 TP/FN/FP/TN，攻击成功阻断必须有实际拒绝且危险副作用未到达的证据；缺失副作用探针为 unknown。正常业务成功率独立统计。响应时间分别报告检查时延和端到端时延；CPU 用同吞吐量配对窗口的逐容器 p95 差值，并另计 Windows Gateway 的宿主机 CPU。

`task/赛题.docx` 要求资产漏报率低于 5%、资产识别准确率达到 99% 以上；资产风险识别准确率达到 95% 以上且漏报率低于 5%。运行时要求异常行为漏报率低于 5%、检出率达到 95% 以上、响应小于 1 秒、CPU 占用率在 5% 以内、正常业务零中断。本地评分分别核对静态标注集、实例级运行时指标、两种时延、配对 CPU 窗口和正常业务成功率；CPU 的本地定义及公开集结果不自动等同于正式评委的测量口径。

本地通过门槛不等于隐藏集泛化证明。发布前应使用未参与规则开发的新样本验证漏报、误报、正常业务零中断和检查异常时的故障策略，并以官网最终发布的评分说明为准。
