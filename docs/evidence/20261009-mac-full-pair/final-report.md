# AgentRange DefenseClaw Report

Generated: 2026-10-09T04:29:18.748538+00:00

## Static Inventory

- Static ground-truth scoring was not performed: the frozen fixture expects `bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`, but this replay used `9414b66e8ba7deef52f0ff1461ad7e1ed816f1fe22300fdef32843f62b242f35`.

- Discovered assets: 27
- Inferred asset edges: 33
- Findings: 21 (HIGH/CRITICAL: 16)

## Side Effect Verification

- The action replay added no C2 `/collect` or `/b` requests.
- One `notes-sync` startup beacon reached the local C2 sink at `2026-10-09T03:23:31.340908+00:00`; it occurred before replay start `2026-10-09T03:23:54.861423+00:00` and carried filtered environment key fields (values omitted).
- Runtime audit found zero downstream side-effect matches across the 80 malicious instances; all 12 attempted Langflow cron markers were absent.

## Runtime Evidence

- Events: 99215
- Sessions: 5200
- Attack chains: 5200
- Blocked chains: 80
- Decisions: {"allow": 98810, "block": 405}
- Severities: {"NONE": 98810, "CRITICAL": 405}

## Benchmark

- Confirmed blocks / false positives: 80 / 0
- Normal business successes: 5120 / 5120
- Unavailable inspections: 0
- End-to-end / inspection p95: 171.455 / 24.0 ms
- Per-container CPU p95 increment: 0.19 percentage points

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

- `chain:C1-A-102`: blocked, langflow_ingress_or_framework_exploit; evidence `audit.db:49d22957-a8ee-42fe-a3cf-0a970bfe1a9d`
  - Tool/path: `/api/v1/validate/code`
- `chain:C2-A-146`: blocked, identity_scope_or_cross_tenant_access; evidence `audit.db:78c96328-229d-458e-a758-c13281dab8d6`
  - Tool/path: `/v1/chat/completions`
  - Reported call site: `api.app.run_stub_agent:313` (client_reported)
- `chain:C2-B-1515`: blocked, agent_tool_activity; evidence `audit.db:689fc34c-746e-49c0-bcca-a5427b7a58bb`
  - Tool/path: `lookup` `/mcp-threat-intel/mcp`
  - Reported call site: `api.app.call_mcp:370` (client_reported)
- `chain:C2-C-1610`: blocked, runtime_observation; evidence `audit.db:a25880e8-b1fc-4a79-aab1-b8179e4f1e7f`
  - Tool/path: `/v1/chat/completions`
  - Reported call site: `api.app.run_stub_agent:313` (client_reported)
- `chain:B-OPS-1`: allowed, agent_tool_activity; evidence `none`
- `chain:B-OPS-1001`: allowed, agent_tool_activity; evidence `none`

## Plan Traceability

- Evidence-ready: 0; implemented awaiting evidence: 12; not implemented: 0
- FR-01 [implemented-awaiting-evidence]: 通用 inspect 接口与 observe/action 模式语义
- FR-02 [implemented-awaiting-evidence]: 身份与租户授权
- FR-03 [implemented-awaiting-evidence]: OpsPilot 非侵入式运行时适配
- FR-04 [implemented-awaiting-evidence]: Langflow 入站保护
- FR-05 [implemented-awaiting-evidence]: 运行时行为规则
- FR-06 [implemented-awaiting-evidence]: 模式、策略与故障处理
- FR-07 [implemented-awaiting-evidence]: 统一事件与证据
- FR-08 [implemented-awaiting-evidence]: 静态资产与风险盘点
- FR-09 [implemented-awaiting-evidence]: 攻击链还原
- FR-10 [implemented-awaiting-evidence]: Benchmark 与最终报告
- NFR-01 [implemented-awaiting-evidence]: 性能与可用性
- NFR-02 [implemented-awaiting-evidence]: 可维护性与兼容性

## Evidence Files

- `bench/runs/20261009-mac-full-pair/action/attack-chains.json`
- `bench/runs/20261009-mac-full-pair/action/host-gateway.jsonl`
- `bench/runs/20261009-mac-full-pair/action/observations.jsonl`
- `bench/runs/20261009-mac-full-pair/action/replay-process.json`
- `bench/runs/20261009-mac-full-pair/action/resources.jsonl`
- `bench/runs/20261009-mac-full-pair/action/run.json`
- `bench/runs/20261009-mac-full-pair/action/runtime-events.jsonl`
- `bench/runs/20261009-mac-full-pair/action/summary.json`
- `bench/runs/20261009-mac-full-pair/baseline/host-gateway.jsonl`
- `bench/runs/20261009-mac-full-pair/baseline/observations.jsonl`
- `bench/runs/20261009-mac-full-pair/baseline/replay-process.json`
- `bench/runs/20261009-mac-full-pair/baseline/resources.jsonl`
- `bench/runs/20261009-mac-full-pair/baseline/run.json`

## Notes

- Runtime evidence is read from DefenseClaw audit.db exports, not from AgentRange source modifications.
- AgentRange remains an unmodified traffic source; generated reports live in DefenseClaw project-side directories.
- Plan traceability checks repository artifact paths only; evidence-ready is not a hidden-set result.
- Runtime and benchmark evidence is limited to the selected action/baseline pair.
- Static ground-truth scoring was not performed because the frozen fixture hash does not match this arena snapshot.
- The C2 sink received one notes-sync startup beacon before action replay began; no C2 collect or beacon request occurred inside the action replay window.
- Audit predicates found no downstream side effect in the 80 malicious action instances; all 12 attempted cron markers were absent.
