# Runtime Closure Checklist

This checklist tracks the work required to turn the current AgentRange / DefenseClaw integration into a defensible competition submission.

Last updated: 2026-08-04.

## P0: Connect the Gateway

Status: completed.

Evidence:

- Host Gateway health endpoint: `http://172.30.224.1:18970/health`.
- Container-reachable Gateway base: `http://172.30.224.1:18970`.
- AgentRange `.env` contains `DEFENSECLAW_API_BASE` and a masked runtime token.
- C2-D container-origin `inspect/tool` request returns `action=block`, `mode=action`, and finding evidence for `.env` access.

## P1: C2-D Observe Minimal Closure

Status: completed.

Evidence:

- Report: `integration/reports/p3-C2-D-observe-runner.json`.
- Business traffic is not interrupted in observe mode.
- Evidence contains `mode=observe` and `raw_action=block` / `would_block=true` for C2-D.

## P2: C2-D Action Minimal Closure

Status: completed.

Evidence:

- Report: `integration/reports/p2-C2-D-action.json`.
- Resume smoke report: `integration/reports/p5-resume-C2-D-action.json`.
- C2-D returns HTTP 403 with `DEFENSECLAW_BLOCKED`.
- Verdict has `mode=action`, not `integration-fail-closed`.
- Block occurs before the sensitive read or sync/exfiltration side effect.

## P3: Harden Runner Blocked Semantics

Status: completed.

Evidence:

- `scenario-runner/runner.py` only counts real `DEFENSECLAW_BLOCKED` action verdicts as runtime blocks.
- Observe metrics use evidence `would_block` or `raw_action=block` for detection.
- 5xx, timeout, and network failures remain invalid instances.
- Long benchmark token expiry is handled by refreshing OpsPilot JWT once on HTTP 401 and replaying `/run`.
- Focused tests passed: `12 passed in 0.92s` on 2026-08-04.

## P4: Generate Attack Chains

Status: completed.

Evidence:

- Clean C2-D event slice: `integration/reports/p4-C2-D-observe-events.jsonl`.
- Attack chains: `integration/reports/attack-chains.json`.
- Final report runtime summary: 13 attack chains, 13 blocked chains.

## P5: Run Full Three-Mode Benchmark

Status: completed with explicit gap.

Evidence:

- Baseline: `bench/results/baseline.json`.
- Observe: `bench/results/observe.json`.
- Action: `bench/results/action.json`.
- Summary: `bench/results/summary.json`.

Latest action metrics:

- Total: 5200.
- Valid: 5200.
- Invalid: 0.
- TP: 52.
- FP: 0.
- TN: 5120.
- FN: 28.
- Precision: 1.0.
- Recall: 0.65.
- FPR: 0.0.
- Normal success rate: 1.0.
- Inspect p95: 10.326 ms.
- CPU increment: 3.04%.

Acceptance:

- FAIL: Recall >= 95%.
- PASS: FPR < 5%.
- PASS: inspect p95 < 1000 ms.
- PASS: normal success rate = 100%.
- PASS: CPU increment <= 5%.

Boundary:

- The current runtime closure covers OpsPilot/C2 behavior well, including C2-D minimal closure.
- The remaining 28 false negatives are C1 Langflow scenarios outside the current OpsPilot runtime closure.
- Achieving full benchmark Recall >= 95% requires implementing the C1 Langflow runtime closure, or explicitly scoping the submission to OpsPilot/C2.

## P6: Refresh Final Report and Dashboard

Status: completed.

Evidence:

- Final report JSON: `integration/reports/final-report.json`.
- Final report Markdown: `integration/reports/final-report.md`.
- Dashboard data: `dashboard/data.js`.
- Evidence index includes current JSONL, attack chains, final reports, and all three benchmark result JSONs plus `summary.json`.
- Failed and boundary items are explicit; the Recall gap is not reported as passed.

## Remaining Strategic Work

The technical closure through P6 is complete, but the project still has one strategic decision:

1. If the submission is scoped to AgentRange OpsPilot/C2, keep the explicit boundary and explain that C1 Langflow is outside the current runtime closure.
2. If the submission must satisfy full benchmark Recall >= 95%, implement C1 Langflow connector/mode/evidence/runner closure and rerun observe/action/summary/final-report/dashboard.