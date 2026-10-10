# AgentRange DefenseClaw Report

Generated: 2026-09-30T03:07:40.431532+00:00

## Static Inventory

- Asset coverage: 1.0
- Required risk recall: 1.0
- Findings: 21 (HIGH/CRITICAL: 16)

- Local labeled asset precision/recall: 1.0 / 1.0
- Local labeled risk precision/recall: 1.0 / 1.0
- Static evaluation scope: local_frozen_fixture

## Runtime Evidence

- Events: 99285
- Sessions: 5200
- Attack chains: 5200
- Blocked chains: 80
- Decisions: {"allow": 98878, "block": 407}
- Severities: {"NONE": 98878, "CRITICAL": 407}

## Benchmark

- Confirmed blocks / false positives: 80 / 0
- Normal business successes: 5120 / 5120
- Unavailable inspections: 0
- End-to-end / inspection p95: 554.515 / 140.0 ms
- Per-container CPU p95 increment: 0.67 percentage points

- PASS: recall_gte_0_95
- PASS: precision_gte_0_95
- PASS: fpr_lt_0_05
- PASS: normal_success_rate_1
- PASS: e2e_p95_lt_1000ms
- PASS: inspect_p95_lt_1000ms
- PASS: inspect_latency_coverage_1
- PASS: inspect_unavailable_eq_0
- PASS: cpu_increment_lte_5pct
- PASS: host_gateway_cpu_p95_lte_5pct
- PASS: combined_defense_cpu_p95_lte_5pct
- PASS: evidence_complete

### Benchmark Provenance

- Comparable mode set: True
- Runtime events and chains are scoped to this action replay and its observed instance IDs.

## Representative Chains

- `chain:C1-A-102`: blocked, langflow_ingress_or_framework_exploit; evidence `audit.db:9e1d8247-21b7-43f3-a8aa-efa25c70bced`
  - Tool/path: `/api/v1/validate/code`
- `chain:C2-A-146`: blocked, identity_scope_or_cross_tenant_access; evidence `audit.db:ea003182-6210-4b48-a165-b088abccc453`
  - Tool/path: `/v1/chat/completions`
  - Reported call site: `api.app.run_stub_agent:313` (client_reported)
- `chain:C2-B-1515`: blocked, agent_tool_activity; evidence `audit.db:bda910b2-a728-4939-a9b9-df05297d90be`
  - Tool/path: `lookup` `/mcp-threat-intel/mcp`
  - Reported call site: `api.app.call_mcp:370` (client_reported)
- `chain:C2-C-1610`: blocked, runtime_observation; evidence `audit.db:5af0f2cf-3ea1-4a37-8380-fb803e257c00`
  - Tool/path: `/v1/chat/completions`
  - Reported call site: `api.app.run_stub_agent:313` (client_reported)
- `chain:B-OPS-1`: allowed, agent_tool_activity; evidence `none`
- `chain:B-OPS-1001`: allowed, agent_tool_activity; evidence `none`

## Plan Traceability

- Evidence-ready: 12; implemented awaiting evidence: 0; not implemented: 0
- FR-01 [evidence-ready]: 通用 inspect 接口与 observe/action 模式语义
- FR-02 [evidence-ready]: 身份与租户授权
- FR-03 [evidence-ready]: OpsPilot 非侵入式运行时适配
- FR-04 [evidence-ready]: Langflow 入站保护
- FR-05 [evidence-ready]: 运行时行为规则
- FR-06 [evidence-ready]: 模式、策略与故障处理
- FR-07 [evidence-ready]: 统一事件与证据
- FR-08 [evidence-ready]: 静态资产与风险盘点
- FR-09 [evidence-ready]: 攻击链还原
- FR-10 [evidence-ready]: Benchmark 与最终报告
- NFR-01 [evidence-ready]: 性能与可用性
- NFR-02 [evidence-ready]: 可维护性与兼容性

## Evidence Files

- `bench/runs/20260930-f87d578-v1/full-pair/action/attack-chains.json`
- `bench/runs/20260930-f87d578-v1/full-pair/action/host-gateway.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/action/observations.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/action/replay-process.json`
- `bench/runs/20260930-f87d578-v1/full-pair/action/resources.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/action/run.json`
- `bench/runs/20260930-f87d578-v1/full-pair/action/runtime-events.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/action/summary.json`
- `bench/runs/20260930-f87d578-v1/full-pair/baseline/host-gateway.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/baseline/observations.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/baseline/replay-process.json`
- `bench/runs/20260930-f87d578-v1/full-pair/baseline/resources.jsonl`
- `bench/runs/20260930-f87d578-v1/full-pair/baseline/run.json`
- `integration/reports/rule-contract.json`
- `integration/reports/static-eval.json`
- `integration/reports/static-scan.json`

## Notes

- Runtime evidence is read from DefenseClaw audit.db exports, not from AgentRange source modifications.
- AgentRange remains an unmodified traffic source; generated reports live in DefenseClaw project-side directories.
- Plan traceability checks repository artifact paths only; evidence-ready is not a hidden-set result.
- Runtime and benchmark evidence is limited to the selected action/baseline pair.
