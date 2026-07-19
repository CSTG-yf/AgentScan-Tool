# AgentRange security validation report

Generated: 2026-07-19T02:36:47.358444+00:00

## Static inventory and risk

- Asset coverage: 1.0
- Required risk recall: 1.0
- Findings: 22 (HIGH/CRITICAL: 17)

## Runtime attack chains

- Chains: 0
- Blocked chains: 0
- Sequence types: not-run

## Acceptance

- Benchmark summary not generated.

## Plan traceability

- Evidence-ready: 8; implemented awaiting evidence: 4; not implemented: 0
- FR-01 [implemented-awaiting-evidence]: 通用 inspect 接口与模式语义
- FR-02 [implemented-awaiting-evidence]: 身份与租户授权
- FR-03 [evidence-ready]: OpsPilot 四阶段适配
- FR-04 [evidence-ready]: Langflow 入站保护
- FR-05 [evidence-ready]: 运行时行为规则
- FR-06 [evidence-ready]: 模式、策略与故障处理
- FR-07 [evidence-ready]: 统一事件与证据
- FR-08 [evidence-ready]: 静态资产与风险盘点
- FR-09 [evidence-ready]: 攻击链还原
- FR-10 [implemented-awaiting-evidence]: Benchmark 与报告
- NFR-01 [implemented-awaiting-evidence]: 性能与可用性
- NFR-02 [evidence-ready]: 可维护性与兼容性

## Evidence index

- `integration/reports/attack-chains.json`
- `integration/reports/final-report.json`
- `integration/reports/final-report.md`
- `integration/reports/pytest-results.xml`
- `integration/reports/rule-contract.json`
- `integration/reports/static-scan.json`

## Degradation and boundaries

- Missing mode reports remain explicit in benchmark.missing_modes.
- Inspection network failures are recorded as invalid instances and integration-fail-open/closed decisions.
- No detection evidence is sourced from /admin/trajectories.
