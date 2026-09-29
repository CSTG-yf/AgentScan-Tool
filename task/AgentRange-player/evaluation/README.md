# AgentRange 自动评测数据合同（进行中）

`metrics.py` 按实例计算检测混淆矩阵与真实副作用指标；`run_store.py` 为每次评测创建独立、不可覆盖的运行目录，按 Baseline → Observe → Action 保存状态、真值、各模式观测与报告。批次标识为 UUID，异常或取消时已写入的模式证据保留。

真值只留在操作者的评测目录，不能随公开回放样本、HTTP 请求或模型轨迹发给靶场。每条观测以 `instance_id` 关联真值，并提供：

- `detected`: `true` / `false` / `null`。命中必须引用 `detection:<id>`；未命中必须引用 `event:` 或 `query:`，且 `detection_scope_complete=true` 表明覆盖了本实例的完整检测窗口，否则不能计入 FN/TN。
- `effect`: `occurred` / `prevented` / `none` / `unknown`。必须由接收端或危险副作用检查给出 `effect_evidence_ref`；HTTP 200、扫描判定和策略 `would_block` 不能代替。
- `enforced_block`: 只有真实执行器回执证明阻断时为 `true`。攻击的有效阻断还必须同时有 `effect=prevented`。
- `business_completed`: 正常实例的业务完成证据；与 `effect=none` 一起用于正常业务成功率。

只要检测证据有缺口，Precision/Recall/FPR/FNR 就返回 `null` 并报告覆盖率；只要副作用证据有缺口，有效阻断率或正常业务成功率也返回 `null`，不补造数字。

现在可以用 `prepare.py` 固化同一批公开回放输入、操作者私有真值与轨迹，并用 `replay.py` 在指定模式下逐实例回放，持久化不含响应正文、认证令牌的 HTTP 回执。公开记录不会包含 `malicious`、`kind`、`evidence`、`trajectory` 或 `label`。输出目录必须位于 AgentRange 目录之外，避免被 Docker bind mount 暴露给靶场。冻结文件的 SHA-256 会在回放前复核，重跑应创建新的批次，不覆盖旧批次。

示例（须先人工准备该模式的 Gateway 和靶场环境）：

```bash
python task/AgentRange-player/evaluation/prepare.py --output-root /var/lib/tracebastion/evaluations --total 5200 --malicious-target 80
python task/AgentRange-player/evaluation/replay.py /var/lib/tracebastion/evaluations/<run-id> baseline
```

回放完成后模式仍保持 `running`，因为 HTTP 回执不能代替检测、阻断和副作用证据；只有权威观测齐备后才能调用 `complete_mode`。目前还没有桌面一键批次编排、Docker 环境重置、接收端核验与资源采样，也没有可宣称的三模式正式指标；不能把单元测试通过视为自动评测已完成。

靶场 MCP 服务现提供内部 `GET /evaluation/calls?instance_id=...`，按实例返回脱敏工具调用摘要、递增序号和丢弃计数。`customer-db` 可核查跨租户查询及返回行数；`notes-sync` 可核查同步动作及敏感配置标记，但不返回客户数据、笔记正文或密钥。记录只保存在当前容器内存中，三模式仍须在每次回放前重置容器并由评测编排器保存前后快照；`dropped>0` 或服务不可达时不能用“没有记录”推断攻击被阻止。此接口尚未接入自动观测收集器。

离线验证：

```bash
python -m pip install -r task/AgentRange-player/requirements-dev.txt
python -m unittest discover -s task/AgentRange-player/evaluation -p 'test_*.py'
```
