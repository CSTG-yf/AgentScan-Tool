# AgentRange DefenseClaw Report

Generated: 2026-09-30T08:05:57.562009+00:00

## Static Inventory

- Discovered assets: 27
- Inferred asset edges: 33
- Findings: 21 (HIGH/CRITICAL: 16)

- Local labeled asset precision/recall: 1.0 / 1.0
- Local labeled risk precision/recall: 1.0 / 1.0
- Static evaluation scope: local_frozen_fixture

## Runtime Evidence

- Events: 99221
- Sessions: 5200
- Attack chains: 5200
- Blocked chains: 80
- Decisions: {"allow": 98795, "block": 405, "inspect_unavailable": 21}
- Severities: {"NONE": 98795, "CRITICAL": 405, "WARN": 21}

## Benchmark

- Confirmed blocks / false positives: 80 / 0
- Normal business successes: 5120 / 5120
- Unavailable inspections: 21
- End-to-end / inspection p95: 548.939 / 121.0 ms
- Per-container CPU p95 increment: 1.59 percentage points

- PASS: recall_gte_0_95
- PASS: precision_gte_0_95
- PASS: fpr_lt_0_05
- PASS: normal_success_rate_1
- PASS: e2e_p95_lt_1000ms
- PASS: inspect_p95_lt_1000ms
- PASS: inspect_latency_coverage_1
- WAIT/FAIL: inspect_unavailable_eq_0
- PASS: cpu_increment_lte_5pct
- PASS: host_gateway_cpu_p95_lte_5pct
- PASS: combined_defense_cpu_p95_lte_5pct
- PASS: evidence_complete

### Benchmark Provenance

- Comparable mode set: True
- Runtime events and chains are scoped to this action replay and its observed instance IDs.

## Representative Chains

- `chain:C1-A-102`: blocked, langflow_ingress_or_framework_exploit; evidence `audit.db:3d1f47b0-fed5-4861-a530-cb6595dd4b8f`
  - Tool/path: `/api/v1/validate/code`
- `chain:C2-A-146`: blocked, identity_scope_or_cross_tenant_access; evidence `audit.db:c87c81f4-f2dd-43d1-aafe-144b9096dc60`
  - Tool/path: `/v1/chat/completions`
  - Reported call site: `api.app.run_stub_agent:313` (client_reported)
- `chain:C2-B-1515`: blocked, agent_tool_activity; evidence `audit.db:a9c63fd5-1bc8-4800-a215-56401345af8d`
  - Tool/path: `lookup` `/mcp-threat-intel/mcp`
  - Reported call site: `api.app.call_mcp:370` (client_reported)
- `chain:C2-C-1610`: blocked, runtime_observation; evidence `audit.db:2be569c5-ff77-434c-ae86-aa23d48920d1`
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

- `bench/runs/20260930-68a661f-v2/full-pair/action/attack-chains.json`
- `bench/runs/20260930-68a661f-v2/full-pair/action/host-gateway.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/action/observations.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/action/replay-process.json`
- `bench/runs/20260930-68a661f-v2/full-pair/action/resources.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/action/run.json`
- `bench/runs/20260930-68a661f-v2/full-pair/action/runtime-events.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/action/summary.json`
- `bench/runs/20260930-68a661f-v2/full-pair/baseline/host-gateway.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/baseline/observations.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/baseline/replay-process.json`
- `bench/runs/20260930-68a661f-v2/full-pair/baseline/resources.jsonl`
- `bench/runs/20260930-68a661f-v2/full-pair/baseline/run.json`
- `integration/reports/rule-contract.json`
- `integration/reports/static-eval.json`
- `integration/reports/static-scan.json`

## Notes

- Runtime evidence is read from DefenseClaw audit.db exports, not from AgentRange source modifications.
- AgentRange remains an unmodified traffic source; generated reports live in DefenseClaw project-side directories.
- Plan traceability checks repository artifact paths only; evidence-ready is not a hidden-set result.
- Runtime and benchmark evidence is limited to the selected action/baseline pair.
