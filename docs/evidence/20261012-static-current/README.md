# 当前靶场资产与风险识别实测（2026-10-12）

本轮对 `task/AgentRange-player-full` 的源码与部署配置执行真实静态扫描。没有启动攻击工具或重新运行运行时回放。源文件哈希为 `9414b66e8ba7deef52f0ff1461ad7e1ed816f1fe22300fdef32843f62b242f35`，与本轮独立冻结真值匹配。

执行代码版本、扫描器与规则文件指纹、配置哈希、开始和结束时间在 [static-run.json](static-run.json) 中。未使用运行镜像，镜像字段明确记录 `not_applicable:static_source_scan`。本轮标签依据 Compose、Skill 文件、MCP Tool 声明和风险源码复核，在调用扫描器前固定，未从扫描结果生成。

| 指标 | 分子 / 分母 | 结果 | 目标 | 达标 |
| --- | --- | --- | --- | --- |
| 资产盘点准确率 | 27 / 27 | 100% | ≥99% | 是 |
| 资产盘点漏报率 | 10 / 37 | 27.03% | <5% | 否 |
| 风险识别准确率 | 13 / 13 | 100% | ≥95% | 是 |
| 风险识别召回率 | 13 / 13 | 100% | ≥95% | 是 |
| 风险识别漏报率 | 0 / 13 | 0% | <5% | 是 |

资产 TP=27、FP=0、FN=10；风险 TP=13、FP=0、FN=0。因此，资产风险识别能力整体为 **未达标**。

| 类型 | 预期 | 发现 | 漏报 |
| --- | --- | --- | --- |
| Agent | 1 | 1 | 0 |
| Model | 1 | 1 | 0 |
| MCP | 8 | 8 | 0 |
| Skill | 7 | 7 | 0 |
| Tool | 10 | 0 | 10 |
| 基础设施（框架、数据库、网络、端口） | 10 | 10 | 0 |
| Plugin | 无样本 | 未评测 | 未评测 |

10 项漏报均为 MCP 独立工具：query、get_pr、search、query_metric、sync_note、隐藏的 debug_exec、run_test、read_file、run、lookup。当前扫描器发现 MCP 服务，没有输出独立 Tool 资产。隐藏后门的风险检测与独立工具资产发现是两种不同结果：即使 MCP 级风险命中，也不能据此认为工具资产已被盘点。

风险以 `(rule_id, asset_id)` 为识别单位。同一风险在多个源码行命中只计一项。本轮 13 项命中包括恶意 Skill 风险 1 项、恶意 MCP 风险 6 项、危险配置风险 6 项。结果仅代表本轮已标注的数据集。

## 证据与导入

- [原始扫描](static-scan.json)、[评分结果与漏报列表](static-eval.json)、[执行记录](static-run.json)、[源文件校验清单](source-manifest.json)。
- [看板导入文件](evaluation.json)：通过“能力评测 → 导入评测报告”即可导入，不依赖编译期 JSON。
- [冻结真值](../../../integration/agentrange_contracts/static-ground-truth-20261012.yaml) 包含 37 项资产及源码依据、13 项风险身份、覆盖范围与限制。

本机桌面标准数据目录中的 `evaluation_runs`、`evaluation_instances`、`evaluation_metrics`、`evaluation_artifacts` 已保存本轮独立静态批次。另保存“历史运行时 + 当前靶场静态复测”汇总视图，保留 2026-10-09 的运行时结果；汇总说明明确区分两次执行的时间和代码版本，不表示一次新的三模式评测。

复现命令：

```bash
python -m integration.static_run \
  --truth integration/agentrange_contracts/static-ground-truth-20261012.yaml \
  --output-dir bench/runs/static-rerun-20261012
```

需要 Python 3.12 和 PyYAML。靶场源文件变化后，必须重新独立复核真值，旧哈希不匹配时运行器拒绝评分。6 项证据转换与静态评测测试通过，实际看板已核对五项指标及 10 项 FN 明细。
