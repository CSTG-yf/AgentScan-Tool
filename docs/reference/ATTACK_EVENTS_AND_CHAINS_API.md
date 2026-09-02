# 攻击事件与攻击链接口文档

核对日期：2026-09-02。本文对应本次接口增强后的实现，依据当前路由、响应结构和数据库查询整理，未替代线上联调。

第 1～6 节为**当前接口**及其兼容约定；第 7 节为实现依据。示例中的 ID 和业务内容均为说明用数据，不是实际检测结果。

## 1. 接口范围与调用约定

| 功能 | 方法 | 当前路径 | 主键 |
| --- | --- | --- | --- |
| 攻击事件列表 | GET | `/api/v1/runtime-detections?category=attack` | `detection_id` |
| 攻击事件详情 | GET | `/api/v1/runtime-detections/{detection_id}` | 字符串 |
| 攻击链列表 | GET | `/api/v1/attack-chains` | 列表中的 `id` |
| 攻击链详情 | GET | `/api/v1/attack-chains/{attack_chain_id}` | 字符串 |

这里将“攻击事件”定义为检测引擎产生的安全检测记录（Detection），严格限定攻击类别时加 `category=attack`。不加该参数会查询其他类别的检测。`/api/v1/runtime-events` 是原始行为事件流，包含正常行为，不能直接当作攻击列表；一条 Detection 可以关联多条原始事件。

详情查询本身不限制 `category=attack`，调用方应使用攻击列表返回的 `detection_id`，并核对详情 `category`。目前没有单独的 `/api/v1/attack-events` 路由。

本地 Base URL 示例：`http://127.0.0.1:18970`，实际以 `gateway.api_port` 为准。

```http
Authorization: Bearer <gateway-token>
Accept: application/json
```

也可使用 `X-DefenseClaw-Token: <gateway-token>`。以下四个查询均无请求体，不会启动扫描或重建攻击链，只读取已持久化数据。

时间统一使用 RFC3339 / RFC3339Nano，例如 `2026-09-02T00:00:00Z`；带 `+08:00` 的查询值需正确 URL 编码。以下“可选”字段可能在 JSON 中被省略。

### 1.1 需求支持情况

| 要求 | 攻击事件列表 | 攻击链列表 |
| --- | --- | --- |
| `page` 分页 | 已支持 | 已支持 |
| `pagesize` 页大小 | 已支持；同时兼容 `page_size` / `pageSize` | 同左 |
| `keyword` 关键词 | 已支持 | 已支持 |
| 时间排序 | 支持 `sort` | 支持 `sort`，默认开始时间倒序 |
| 时间范围 | 已支持 | 已支持 |
| `AgenttypeId` 类型筛选 | 已支持；同时兼容 `agent_type_id` / `agentTypeId` | 已支持；同时兼容 `agent_type_id` / `agentTypeId` |
| `agent_id` 实例筛选 | 已支持，不等于 Agent 类型 | 已支持，不等于 Agent 类型 |
| 基础信息数组 `list` | 已返回 `list`，并保留 `items` / `detections` | 已返回 `list`，并保留 `chains` / `items` |
| 根据 ID 查询详情 | 已支持 | 已支持 |

## 2. 攻击事件列表

### 2.1 请求

`GET /api/v1/runtime-detections`

| 参数 | 类型 | 默认值 / 规则 |
| --- | --- | --- |
| `page` | integer | 可选，默认 1，从 1 开始 |
| `page_size` / `pagesize` | integer | 可选，默认 200，最大 1000；兼容 `pageSize`，`page_size` 优先 |
| `keyword` | string | 可选，大小写不敏感的 SQL LIKE 模糊查询 |
| `sort` | string | 可选，默认 `last_seen_at` 倒序；枚举见下表 |
| `agent_id` | string | 可选，Agent 实例 ID，精确匹配 |
| `AgenttypeId` | integer | 可选，兼容 `agent_type_id` / `agentTypeId`，按 Agent 类型 ID 精确筛选 |
| `session_id` / `trace_id` | string | 可选，会话 / 调用链精确匹配 |
| `category` | string | 攻击列表传 `attack`；可逗号分隔多值 |
| `detection_type` | string | 可选，检测类型，可逗号分隔；兼容 `type`，前者优先 |
| `severity` | string | 可选，如 `critical,high`；大小写不敏感 |
| `status` | string | 可选，推荐 `open`、`mitigated`、`resolved`，可逗号分隔 |
| `source` | string | 可选，检测来源，可逗号分隔；不筛选时省略 |
| `start_time` | string(datetime) | 可选，要求记录 `last_seen_at >= start_time` |
| `end_time` | string(datetime) | 可选，要求记录 `first_seen_at <= end_time` |
| `limit` / `offset` | integer | 兼容旧式分页；不建议与 `page/page_size` 混用 |

关键词匹配字段：`detection_id`、`agent_id`、`agent_name`、`session_id`、`trace_id`、`detection_type`、`category`、`rule_id`、`rule_version`、`title`、`detail`、`remediation`。当前 `%` 和 `_` 会按 LIKE 通配符处理，并非转义后的字面搜索。

时间范围是检测持续区间与查询区间相交，不是只按“创建时间”过滤。

| `sort` 值 | 实际排序 |
| --- | --- |
| 不传或 `last_seen_at:desc` | `last_seen_at DESC, detection_id DESC` |
| `oldest` / `last_seen_at:asc` | `last_seen_at ASC, detection_id ASC` |
| `severity:desc` | 严重程度降序，再按最后发现时间降序 |
| `agent:asc` | Agent 名称排序，再按最后发现时间降序 |
| `type:asc` | 检测类型排序，再按最后发现时间降序 |

其他兼容值：`created_at:asc`、`first_seen_at:asc` 实际也按 **last_seen_at** 升序，不应将其解释为首次发现时间排序。未知排序值会回退为默认倒序。

`AgenttypeId`、`agent_type_id`、`agentTypeId` 均表示 `agents.agent_type_id`，是 Agent 类型筛选，不是 Agent 实例 ID；与 `agent_id` 同时传入时取 AND。类型名称可从 `GET /api/v1/agent-governance/agent-types` 获取。

状态兼容别名：单值 `detected` / `pending` → `open`，`blocked` → 查询 `mitigated` 和 `blocked`，`audited` → `resolved`。返回值仍是存储状态；多值查询建议直接传存储状态，不混用别名。

```http
GET /api/v1/runtime-detections?category=attack&page=1&page_size=20&keyword=prompt&sort=last_seen_at%3Adesc&agent_id=agent-demo&start_time=2026-09-01T00%3A00%3A00Z&end_time=2026-09-02T23%3A59%3A59Z
```

### 2.2 响应

HTTP 200。无 `code/data` 包装；`list` 是统一列表字段，`items/detections` 为兼容副本。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `list` | Detection[] | 当前页基础列表，空结果为 `[]` |
| `items` / `detections` | Detection[] | `list` 的兼容副本 |
| `detections` | Detection[] | `items` 的兼容重复字段 |
| `total` | integer | 匹配条件的总条数；来源筛选存在第 5 节所述限制 |
| `count` | integer | 当前页条数 |
| `page` / `page_size` / `pagesize` | integer | 当前页 / 实际 limit |
| `limit` / `offset` | integer | 实际查询分页参数 |
| `summary` | object | `total` 为总量；`attack/blocked/critical/high/open` 仅统计当前页 |

下例为响应节选，省略了重复的 `detections` 与 `summary`，不表示服务端不返回这些字段：

```json
{
  "list": [
    {
      "detection_id": "det-demo-001",
      "agent_id": "agent-demo",
      "agent_name": "Demo Agent",
      "type": "prompt_injection",
      "detection_type": "prompt_injection",
      "category": "attack",
      "severity": "high",
      "confidence": 0.95,
      "rule_id": "rule-demo",
      "status": "open",
      "title": "疑似提示词注入",
      "source": "runtime_detection",
      "created_at": "2026-09-02T08:01:00Z",
      "first_seen_at": "2026-09-02T08:00:00Z",
      "last_seen_at": "2026-09-02T08:01:00Z",
      "event_count": 2
    }
  ],
  "total": 1,
  "count": 1,
  "page": 1,
  "page_size": 20,
  "limit": 20,
  "offset": 0
}
```

### 2.3 Detection 字段

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `detection_id` | string | 攻击事件/检测记录 ID，用于详情查询 |
| `agent_id` | string | Agent 实例 ID，不是类型 ID |
| `agent_name` | string | 可选，Agent 显示名称 |
| `session_id` / `trace_id` | string | 可选，关联会话与 trace |
| `type` / `detection_type` | string | 相同的检测类型值，按规则实际输出，不是 Agent 类型 |
| `category` | string | 检测类别，攻击为 `attack` |
| `severity` | string | 小写风险等级，通常为 `critical/high/medium/low/info` |
| `confidence` | number | 检测置信度 |
| `rule_id` / `rule_version` | string | 规则 ID / 可选版本 |
| `status` | string | `open` 未解决、`mitigated` 已缓解、`resolved` 已确认处理；兼容历史状态 |
| `title` | string | 列表标题 |
| `description` | string | 可选，优先使用 detail，其次 remediation |
| `detail` / `remediation` | string | 可选，检测说明 / 修复建议 |
| `source` | string | 检测来源，如 `runtime_detection`、`correlation_engine`，不是固定枚举 |
| `created_at` | string(datetime) | 可选，当前实现等于 last_seen_at，不能作为真实创建时间 |
| `first_seen_at` / `last_seen_at` | string(datetime) | 可选，首次 / 最后发现时间 |
| `event_count` | integer | 关联原始行为事件数量，不是攻击事件总数 |
| `attributes` | object | 可选，扩展属性，不保证固定键 |

## 3. 攻击事件详情

`GET /api/v1/runtime-detections/{detection_id}`

路径参数 `detection_id` 必填，从列表原样取值并 URL 编码，不能使用证据的数字 `event_id` 替代。

```http
GET /api/v1/runtime-detections/det-demo-001
```

HTTP 200 响应结构：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| 顶层 Detection 字段 | 见 2.3 | 为兼容旧调用方，基础字段直接在顶层展开 |
| `detection` | Detection | 同一条基础信息再次放在该对象内；新接入推荐读取此字段 |
| `evidence` | Evidence[] | 支撑此检测的原始事件，空结果为 `[]` |
| `agent` | object | `{agent_id, name, agent_type_id?, agent_type_name?}`，名称为空时回退为 ID |
| `runtime_session` | object | 可选成员 `session_id`、`trace_id` |
| `trace` | object | 当前与 runtime_session 内容相同 |

Evidence 字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `event_id` | integer(int64) | 数据库行为事件主键，与 detection_id 不同 |
| `detection_id` | string | 可选，关联检测 ID |
| `event_type` | string | 原始行为类型 |
| `sequence` | integer | 原始关联顺序值，不应自行解释为从 1 开始 |
| `role` | string | 可选，`trigger` / `supporting` / `corroborating` |
| `timestamp` | string(datetime) | 可选，行为发生时间 |
| `event_source` / `event_category` | string | 可选，行为来源 / 类别 |
| `agent_id` / `agent_name` / `session_id` / `trace_id` | string | 可选，上下文 |
| `tool_name` / `target` / `operation` / `outcome` | string | 可选，工具、对象、操作、实际结果 |
| `severity` / `detail` | string | 可选，风险等级 / 原始说明 |
| `attributes` | object | 可选，扩展证据 |

可单独读取证据：`GET /api/v1/runtime-detections/{detection_id}/events`，直接返回 Evidence 数组。检测详情不直接返回攻击链 ID；不能仅凭相同 Agent 就断言两条记录属于同一攻击链。

## 4. 攻击链接口

### 4.1 列表请求

`GET /api/v1/attack-chains`

| 参数 | 类型 | 默认值 / 规则 |
| --- | --- | --- |
| `page` | integer | 可选，默认 1，从 1 开始 |
| `page_size` / `pagesize` | integer | 可选，默认 100，最大 200；兼容 `pageSize`，`page_size` 优先 |
| `agent_id` / `session_id` / `trace_id` | string | 可选，单值精确匹配 |
| `AgenttypeId` | integer | 可选，兼容 `agent_type_id` / `agentTypeId`，按 Agent 类型 ID 精确筛选 |
| `attack_type` | string | 可选，攻击类型，单值精确匹配 |
| `severity` | string | 可选，单值，查询前转大写，例如 `HIGH` |
| `status` | string | 可选，原始状态 `active` / `contained`；`blocked`、`mitigated` 映射为 contained |
| `start_time` | string(datetime) | 可选，要求链 `end_time >= start_time` |
| `end_time` | string(datetime) | 可选，要求链 `start_time <= end_time` |
| `keyword` | string | 可选，大小写不敏感的模糊查询，匹配链 ID、Agent、会话、trace、攻击类型、状态及关联检测/决策 ID |
| `sort` | string | 可选；默认 `time_desc`，`time_asc` / `oldest` 为开始时间正序 |
| `limit` / `offset` | integer | 兼容旧分页，limit 最大 200；不建议混用 |

默认按链的 `start_time DESC, attack_chain_id DESC` 稳定排序。时间范围采用区间相交语义。

注意：列表显示状态 `pending`，但后端筛选不能使用 `status=pending`，应传原始状态 `active`。攻击链筛选目前不支持与检测列表相同的逗号多值语义。

```http
GET /api/v1/attack-chains?page=1&pagesize=20&AgenttypeId=2&keyword=prompt&sort=time_asc&agent_id=agent-demo&severity=HIGH&status=active
```

### 4.2 列表响应与 Chain 字段

HTTP 200，顶层：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `capturedAt` | string(datetime) | 本次读取时间，不是攻击发生时间 |
| `source` | string | 固定 `runtime-attack-chains` |
| `list` | Chain[] | 当前页基础列表，空结果为 `[]` |
| `chains` | Chain[] | `list` 的兼容副本，当前仍包含 steps/evidence 以兼容旧页面 |
| `items` | Chain[] | `list` 的兼容副本，空页时可能省略 |
| `total` | integer | 匹配总量，值为 0 时当前实现会省略 |
| `page` / `page_size` / `pagesize` | integer | 页码 / 页大小 |
| `warning` | string | 可选，匹配总量为 0 时提示未持久化；筛选无匹配也会出现此提示 |

Chain 字段使用 camelCase，与 Detection 不同：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 攻击链 ID，详情路径使用此值 |
| `traceId` / `sessionId` | string | 关联上下文 |
| `agentId` | string | Agent 实例 ID |
| `agentTypeId` / `agentTypeName` | integer / string | Agent 类型 ID / 名称，可选 |
| `agent` | string | Agent 显示名称，缺失回退 ID |
| `runtime` | string | 固定 `runtime-detection`，不能用于识别 Agent 类型 |
| `category` | string | 原始 attack_type |
| `risk` | string | 小写风险等级 |
| `status` | string | 展示值：contained/blocked/mitigated → blocked；其余 → pending |
| `startedAt` / `endedAt` | string(datetime) | 链开始 / 结束时间 |
| `summary` | string | 服务端按 ID、类型和状态拼接的摘要，不是额外的模型分析 |
| `stepCount` / `evidenceCount` | integer | 步骤数 / 证据行数 |
| `sources` | string[] | 来源集合 |
| `steps` | Node[] | 完整步骤，当前列表也返回，见 4.4 |
| `evidence` | ChainEvidence[] | 完整证据行，见 4.4 |
| `detectionId` / `decisionId` | string | 可选，关联检测 / 决策 ID |
| `builderVersion` / `policyVersion` / `evaluationJobId` | string | 可选，构建器版本、策略版本、评估任务 ID |

响应节选（省略兼容 chains/items、步骤、证据等字段）：

```json
{
  "capturedAt": "2026-09-02T08:05:00Z",
  "source": "runtime-attack-chains",
  "list": [
    {
      "id": "chain-demo-001",
      "agent": "Demo Agent",
      "runtime": "runtime-detection",
      "category": "prompt_injection",
      "risk": "high",
      "status": "pending",
      "startedAt": "2026-09-02T08:00:00Z",
      "endedAt": "2026-09-02T08:01:00Z",
      "stepCount": 2,
      "evidenceCount": 2,
      "detectionId": "det-demo-001"
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 20,
  "pagesize": 20
}
```

### 4.3 详情请求与响应

`GET /api/v1/attack-chains/{attack_chain_id}`

路径参数必填，从列表 `id` 取值。

```http
GET /api/v1/attack-chains/chain-demo-001
```

HTTP 200：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `attack_chain` | object | 原始存储字段，见下文；身份和状态判断优先使用它 |
| `chain` | Chain | 与列表相同的页面对象，包含完整步骤和证据 |
| `events` | object[] | 原始链事件关联：`attack_chain_id, event_id, sequence, relation?, event` |
| `nodes` | Node[] | 与 chain.steps 相同，用于绘图 |
| `edges` | Edge[] | 按相邻步骤生成的顺序连线 |
| `evidence` | ChainEvidence[] | 与 chain.evidence 相同 |
| `detections` | object[] | 由链的 detection_id 查到的原始 RuntimeDetection，不是该会话所有检测 |
| `decision` | object | 由链 decision_id 查到的决策；缺失时为零值对象，不一定是 null |
| `responses` | object[] 或 null | 决策关联的实际响应动作 |
| `response` | object | responses 第一条；无动作时为零值对象，不代表最新动作 |

`attack_chain` 字段：`attack_chain_id`、`agent_id`、可选 `agent_name/session_id/trace_id`、`attack_type`、`severity`、`status`（原始 active/contained）、`start_time`、`end_time`，以及可选 `detection_id/decision_id/builder_version/policy_version/evaluation_job_id`。除时间外均为字符串，时间为 datetime 字符串。

`events[].event` 是原始 BehaviorEvent，主要包括数字主键 `id`、`timestamp`、`event_type`、`source`、进程字段 `agent_pid/agent_executable/actor_pid/actor_executable`、`outcome/detail`；可选上下文 `canonical_agent_id/agent_name/session_id/trace_id`、行为信息 `event_source/event_category/tool_name/target/operation/severity/attributes` 等。此处 `event.event_id` 是可选的外部字符串标识，与外层数字 `event_id` 不同。

`detections[]` 与 2.3 的原始对应字段相近，但没有页面兼容字段 `type/description/created_at`，可能包含 `evaluation_job_id`，severity 也未在此转换为小写。不要将两种对象假定为完全相同的 DTO。

决策对象主要字段：`decision_id/detection_id/agent_id/decision/policy_id/mode`（string）、`risk_score/confidence`（number）、`would_block`（boolean）、`created_at`（datetime），以及可选名称、上下文、`reason/enforcement_point/idempotency_key/source/policy_version`。

响应动作字段：`response_id/decision_id/action_type/status`（string）、`rollback_supported`（boolean）、`executed_at`（datetime），可选 `executor/target/result`（string）。是否真正阻断应结合动作状态和原始 outcome 判断，不能只看风险等级、would_block 或图上的标签。

### 4.4 图节点、连线与证据

| 对象 | 字段及类型 |
| --- | --- |
| Node | `id` string；`order` integer；`occurredAt` datetime；`title/stage/kind/severity/actor/prompt/tool/resource/evidence/decision` string；`stack` string[] 或 null；`sourceEventId/source/traceId/sessionId` string |
| Edge | `id/source/target` string；`order` integer |
| ChainEvidence | `key` string；`index` integer；`occurredAt` datetime；`stage/agent/tool/resource/decision/evidence/sourceEventId/source` string |

Node.kind 当前取 `entry/agent/llm/tool/mcp/data/network/defense`。Node.id、sourceEventId 都来自原始数据库事件数字主键的字符串形式。当前转换未填充 prompt 和 stack，不能据此假定已采集到提示词与调用栈。

Node.evidence 是 target 或 detail 的截断摘要；完整内容查看 events。Edge 仅连接前后相邻节点，表示展示顺序，不是已验证的因果关系。原始事件顺序按关联 sequence，再按 timestamp 排列。

## 5. 错误与当前接入注意事项

| HTTP 状态 | 说明 / 典型响应 |
| --- | --- |
| 200 | 成功；列表无匹配仍是 200 |
| 401 | Token 缺失或错误，`{"error":"unauthorized"}` |
| 404 | 事件详情不存在：`{"error":"detection not found"}`；链不存在：`{"error":"attack chain not found"}` |
| 405 | 不支持的方法，部分返回纯文本 `method not allowed` |
| 500 | 数据库等内部错误，通常 `{"error":"..."}` |
| 503 | `{"error":"audit store unavailable"}` 或网关 Token 未配置 |

成功响应为 JSON。鉴权、404/405 等错误可能由 http.Error/http.NotFound 输出，Content-Type 与正文不完全统一，客户端不能无条件 JSON.parse。

当前限制：

1. 非法分页值通常回退默认值，超大 page_size 截断为上限；非法时间被当作未传入，不返回 400。未知查询参数也会静默忽略。
2. 不混用页码与 offset/limit。检测 offset 仅正数覆盖，链 offset 可为 0；链在 limit 覆盖后仍回显原 page_size，可能造成分页元数据与实际长度不一致。
3. 检测按 source 筛选时会再读取最多 5000 条进行内存重筛和计数，超过该量时 total 可能不完整；历史来源推断在 SQL 与页面转换间也有差异。
4. 检测 summary 除 total 外只代表当前页。攻击链 total=0 和空 items 被省略，前端应暂时使用 `total ?? 0` 与 `chains ?? []`。
5. 攻击链列表逐条读取详情（N+1 查询），并返回完整证据，尚不是轻量基础列表；详情读取异常可能被跳过，使步骤数看似为 0。
6. 攻击链默认排序已增加 `attack_chain_id` 次级排序，分页边界更稳定；两类接口在持续写入时仍不是快照分页。
7. 自动刷新和手动刷新均调用同一个 GET。刷新不会产生新检测或攻击链；缺数据时应检查采集、检测和持久化链路，不能前端补造数据。

## 6. 本次增强后的统一契约

本次已复用以上四个路径完成参数和列表兼容增强：保留已有响应字段，同时新增统一 `list`、`pagesize` 和 Agent 类型字段。旧客户端继续读取 `items`、`detections`、`chains`、`page_size` 即可。

### 6.1 两类列表统一参数

| 参数 | 目标约定 |
| --- | --- |
| `page` | 正整数，默认 1 |
| `pagesize` | 正整数；事件默认 200、最大 1000，链默认 100、最大 200；兼容 page_size/pageSize |
| `keyword` | 字面子串搜索；事件沿用 2.1 字段；链搜索 ID、Agent ID/名称、session、trace、attack_type |
| `sort` | `time_desc`（默认）/ `time_asc`；事件按 last_seen_at，链按 start_time；同时间按主键同向排序 |
| `AgenttypeId` | 正整数，兼容规范名 agent_type_id；按 Agent 类型 ID 筛选，不按名称猜测 |
| `agent_id` | 可选，实例 ID；与类型筛选同时出现时取 AND |
| `start_time/end_time` | RFC3339，保留区间相交语义；起始晚于结束返回 400 |

多个分页别名同时传入时按 `page_size`、`pageSize`、`pagesize` 的顺序取值；建议调用方只发送一个。非法或非正的 Agent 类型 ID 按未筛选处理，以保持现有查询的容错行为。

Agent 类型下拉数据可复用现有 `GET /api/v1/agent-governance/agent-types`，取类型记录的 `id`，不是 `type_key` 或 Agent 实例 ID。后端通过检测/链的 agent_id 关联 `agents.agent_type_id`，再关联 `agent_types`；需明确历史记录按“当前类型”查询，未知类型不应误命中指定类型。

### 6.2 列表字段

统一分页外壳示例（实际接口还会保留各自的兼容字段）：

```json
{
  "list": [],
  "total": 0,
  "page": 1,
  "pagesize": 20
}
```

事件 list 单项：`detection_id, agent_id, agent_name, agent_type_id, agent_type_name, detection_type, category, severity, status, title, first_seen_at, last_seen_at, event_count, source`。

攻击链 list 单项：`attack_chain_id, agent_id, agent_name, agent_type_id, agent_type_name, attack_type, severity, status, start_time, end_time, step_count, evidence_count, detection_id`。

事件 list 使用现有 Detection 页面字段；攻击链 list 使用现有 Chain camelCase 字段，并新增 `agentId`、`agentTypeId`、`agentTypeName`。未知类型会省略类型字段；列表仍保留 steps/evidence 以兼容当前桌面页面。点击行后用对应主键请求详情，加载证据与图结构。

### 6.3 验收与后续优化

- 两个列表都在数据库层完成关键词、类型、时间、排序、分页和总量计算；不在当前页前端过滤后假装全量筛选。
- page=1/2 无意外重复；相同时间有稳定次级排序；空结果固定 list=[]、total=0，超出末页不报错。
- 对两个不同 Agent 类型准备样本，验证 AgenttypeId 单独筛选及与 agent_id 组合的结果。
- 验证关键词、正/倒序、时间边界、无效参数和不存在 ID 的错误响应。
- 列表 ID 能查询到一致的详情；原始 event_id、detection_id、attack_chain_id 不混用。
- 新增契约与旧 items/detections/chains 调用方兼容。攻击链列表目前仍逐项读取详情，后续可拆分为轻量 list 与按需 detail，减少 N+1 查询。

## 7. 实现依据

- [路由与鉴权](../../internal/gateway/api.go)：路由注册、tokenAuth。
- [检测列表与详情](../../internal/gateway/runtime_events.go)：runtimeDetectionFilterFromQuery、handleRuntimeDetectionsList、handleRuntimeDetections、响应 DTO。
- [通用分页与时间解析](../../internal/gateway/unified_runtime_api.go)：requestPage、parseAPITime。
- [攻击链列表与详情](../../internal/gateway/page_inventory_api.go)：backendAttackChains、handleAttackChainDetail、pageChainStepsFromRuntime。
- [检测数据库查询](../../internal/audit/runtime_detections.go)：runtimeDetectionWhereClause、runtimeDetectionOrderBy。
- [攻击链数据库查询及决策模型](../../internal/audit/runtime_decisions.go)：runtimeAttackChainWhereClause、ListRuntimeAttackChains、GetRuntimeAttackChainDetail。
- [Agent 类型接口](../../internal/gateway/agent_governance_api.go)：handleGovernanceAgentTypes。
