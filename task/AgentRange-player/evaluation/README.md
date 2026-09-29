# AgentRange 自动评测数据合同（进行中）

`metrics.py` 按实例计算检测混淆矩阵与真实副作用指标；`run_store.py` 为每次评测创建独立、不可覆盖的运行目录，按 Baseline → Observe → Action 保存状态、真值、各模式观测与报告。批次标识为 UUID，异常或取消时已写入的模式证据保留。

真值只留在操作者的评测目录，不能随公开回放样本、HTTP 请求或模型轨迹发给靶场。每条观测以 `instance_id` 关联真值，并提供：

- `detected`: `true` / `false` / `null`。命中必须引用 `detection:<id>`；未命中必须引用 `event:` 或 `query:`，且 `detection_scope_complete=true` 表明覆盖了本实例的完整检测窗口，否则不能计入 FN/TN。
- `effect`: `occurred` / `prevented` / `none` / `unknown`。必须由接收端或危险副作用检查给出 `effect_evidence_ref`；HTTP 200、扫描判定和策略 `would_block` 不能代替。
- `enforced_block`: 只有真实执行器回执证明阻断时为 `true`。攻击的有效阻断还必须同时有 `effect=prevented`。
- `business_completed`: 正常实例的业务完成证据；与 `effect=none` 一起用于正常业务成功率。

只要检测证据有缺口，Precision/Recall/FPR/FNR 就返回 `null` 并报告覆盖率；只要副作用证据有缺口，有效阻断率或正常业务成功率也返回 `null`，不补造数字。

当前这是评测批次和指标的基础模块，尚未连接桌面批次编排、Docker 环境重置、接收端核验与资源采样；因此不能把单元测试通过视为三模式自动评测已完成。

离线验证：

```bash
python -m unittest discover -s task/AgentRange-player/evaluation -p 'test_*.py'
```
