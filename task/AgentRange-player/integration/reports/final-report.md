# AgentRange security validation report

Generated: 2026-08-04T08:03:23.629701+00:00

## Static inventory and risk

- Asset coverage: 1.0
- Required risk recall: 1.0
- Findings: 22 (HIGH/CRITICAL: 17)

## Runtime attack chains

- Chains: 13
- Blocked chains: 13
- Sequence types: sensitive_file_read_to_sync_or_egress

## Acceptance

- FAIL: recall_gte_0_95
- PASS: fpr_lt_0_05
- PASS: inspect_p95_lt_1000ms
- PASS: normal_success_rate_1
- PASS: cpu_increment_lte_5pct

## Plan traceability

- Evidence-ready: 10; implemented awaiting evidence: 2; not implemented: 0
- FR-01 [implemented-awaiting-evidence]: 通用 inspect 接口与模式语义
- FR-02 [implemented-awaiting-evidence]: 身份与租户授权
- FR-03 [evidence-ready]: OpsPilot 四阶段适配
- FR-04 [evidence-ready]: Langflow 入站保护
- FR-05 [evidence-ready]: 运行时行为规则
- FR-06 [evidence-ready]: 模式、策略与故障处理
- FR-07 [evidence-ready]: 统一事件与证据
- FR-08 [evidence-ready]: 静态资产与风险盘点
- FR-09 [evidence-ready]: 攻击链还原
- FR-10 [evidence-ready]: Benchmark 与报告
- NFR-01 [evidence-ready]: 性能与可用性
- NFR-02 [evidence-ready]: 可维护性与兼容性

## Evidence index

- `bench/results/action.json`
- `bench/results/baseline.json`
- `bench/results/observe.json`
- `bench/results/summary.json`
- `integration/reports/attack-chains.json`
- `integration/reports/final-report.json`
- `integration/reports/final-report.md`
- `integration/reports/langflow-events.jsonl`
- `integration/reports/opspilot-events.jsonl`
- `integration/reports/p1-C2-D-observe.json`
- `integration/reports/p2-C2-D-action.json`
- `integration/reports/p3-C2-D-observe-runner.json`
- `integration/reports/p4-C2-D-observe-events.jsonl`
- `integration/reports/p5-resume-C2-D-action.json`
- `integration/reports/pytest-results.xml`
- `integration/reports/rule-contract.json`
- `integration/reports/smoke-C2-D.json`
- `integration/reports/static-scan.json`

## Degradation and boundaries

- Missing mode reports remain explicit in benchmark.missing_modes.
- Inspection network failures are recorded as invalid instances and integration-fail-open/closed decisions.
- No detection evidence is sourced from /admin/trajectories.
- Full benchmark action recall is 65.00%; C1 Langflow scenarios remain outside the current OpsPilot runtime closure.
