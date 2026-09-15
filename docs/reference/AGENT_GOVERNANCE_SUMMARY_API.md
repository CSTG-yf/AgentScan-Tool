# Agent 治理中心顶部统计

`GET /api/v1/agent-governance/summary`

成功时返回 HTTP 200，包含覆盖全部 8 个子菜单的 11 个数量字段：

```json
{
  "agent_type_count": 13,
  "discovery_rule_count": 12,
  "resource_rule_count": 13,
  "scan_profile_count": 6,
  "decision_profile_count": 2,
  "risk_rule_count": 20,
  "runtime_rule_count": 30,
  "runtime_blacklist_count": 0,
  "runtime_risk_policy_count": 1,
  "scan_schedule_count": 6,
  "page_refresh_policy_count": 8
}
```

以上为示例数量。

| 子菜单 | 统计字段与口径 |
| --- | --- |
| Agent 类型管理 | `agent_type_count`：类型数量 |
| Agent 发现规则 | `discovery_rule_count`：发现规则数量 |
| 资源发现规则 | `resource_rule_count`：资源规则数量 |
| allowed 扫描方案 | `scan_profile_count`：扫描方案数量 |
| 决策与动作 | `decision_profile_count`：Pre-scan 与 Post-scan 方案数之和 |
| 风险解释 | `risk_rule_count`：Severity、Rule ID 前缀、Category 三类规则数之和 |
| 异常检测设置 | `runtime_rule_count`：通用和专属规则；`runtime_blacklist_count`：黑名单条目；`runtime_risk_policy_count`：通用和专属风险策略 |
| 扫描与刷新策略 | `scan_schedule_count`：扫描策略（含事件驱动行）；`page_refresh_policy_count`：页面刷新策略 |

异常检测和扫描刷新卡片分别显示对应字段之和，并附分项数量。方案内部规则、风险策略内部等级行和任务历史不会重复计入方案/策略数。

- 数据库统计包含停用项，排除软删除项。专属异常检测规则、黑名单和策略须关联未删除的 Agent 类型。
- 发现规则、资源规则须关联未删除的 Agent 类型，与子菜单列表的统计口径一致。
- 不接受筛选或分页条件；附带的查询参数不会改变总数。
- 数据库数量由一次查询返回，不加载规则详情。页面刷新策略数量由后端配置结构计算（当前 8 项），未保存过配置时仍与设置 API 返回的默认策略数一致。
- 非 GET 请求返回 405；数据库不可用返回 503，查询失败返回 500。

桌面进入治理中心时加载一次统计，右上角“刷新”只调用此接口。统计与各子菜单列表状态独立，修改配置后可点击该按钮更新总数；子菜单保留各自的数据加载和刷新逻辑。

顶部统计在所有子菜单中保持显示；异常检测设置和扫描与刷新策略子页面不再显示自身的统计卡片。
