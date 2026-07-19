# 交付物与证据索引

实施基线为仓库 `task/DefenseClaw_AgentRange靶场改造实施计划书_v1.0.docx`；
机器可检查的需求追踪矩阵位于 `integration/requirements.yaml`，最终报告将每项
FR/NFR 标记为 `not-implemented`、`implemented-awaiting-evidence` 或
`evidence-ready`。证据齐全仅表示对应文件已生成，性能与检测阈值是否通过仍以
benchmark 原始结果为准。

| 工作包 | 主要交付物 | 验证入口 |
|---|---|---|
| M0 | `contracts/` 资产、场景、Schema、统计口径 | `pytest contracts -q` |
| M1 | `static_inventory.py`、taxonomy、Finding/edges | `make static-scan` |
| M2 | OpsPilot 四阶段 client、Langflow guard、JSONL 证据 | `pytest opspilot-app integration -q` |
| M3 | `runtime_rules.yaml` 攻击/良性夹具 | `make rules` |
| M4 | `attack_chain.py`、DAG、raw_ref | `make attack-chain` |
| M5 | `policy.yaml`、scope/egress/mode 契约 | `pytest integration/test_policy_contract.py -q` |
| M6 | 三模式 benchmark 与原始 JSON | `make benchmark-summary` |
| M7 | Windows/Linux 脚本、Demo、最终报告 | `make report` |

正式提交前应保留以下生成物：

- `integration/reports/static-scan.json`
- `integration/reports/rule-contract.json`
- `integration/reports/*-events.jsonl`
- `integration/reports/attack-chains.json`
- `bench/results/baseline.json`、`observe.json`、`action.json`、`summary.json`
- `integration/reports/final-report.json` 与 `final-report.md`

当前验证约束：不运行 Go 测试，不新增 CI/CD 或 GitHub 测试。Go 核心改造只允许
执行 `gofmt`、构建和受控 HTTP 烟雾；构建工具或依赖不可用时必须标为未测试。
