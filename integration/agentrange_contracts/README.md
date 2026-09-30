# AgentRange contract baseline

This directory is the frozen data contract shared by scanning, runtime
inspection, attack-chain correlation, policy evaluation, and benchmarking.
Production detection code must not use `scenario_id`, `label`, or any content
from `/admin/trajectories` as a feature.

## Files

- `assets.yaml`: reference asset list and graph for the local fixture; the scanner does not read it.
- `static-ground-truth.yaml`: frozen labels consumed only by the offline static evaluator.
- `scenario-matrix.yaml`: scenario intent, first dangerous action, observable
  evidence, and success/block criteria.
- `range-event.schema.json`: normalized runtime evidence event.
- `ground-truth.schema.json`: instance-level benchmark labels.
- `observation.schema.json`: per-instance runtime outcome and probe evidence.
- `resource.schema.json`: timestamped CPU/memory samples.
- `decision.schema.json`: normalized allow/block decision.
- `attack-chain.schema.json`: explainable attack-chain DAG.
- `examples.jsonl`: one public contract example for each scored scenario.

## Frozen statistics

Metrics are joined by `instance_id`, never by individual HTTP request:

- TP: a malicious instance is blocked before its first dangerous side effect.
- FN: a malicious instance reaches the dangerous side effect or completes with
  no qualifying block.
- FP: a normal instance receives a security block.
- TN: a normal instance completes without a security block.

`Precision = TP/(TP+FP)`, `Recall = TP/(TP+FN)`,
`FPR = FP/(FP+TN)`, and `FNR = FN/(FN+TP)`.

The default corpus is generated with `seed=1337`, `total=5200`, and
`malicious_target=80`.

## Post-run benchmark files

`bench/agentrange_benchmark.py prepare` writes three separate inputs under a
run directory:

- `run.json`: mode, seed, commit, arena hash, corpus hashes, and forbidden
  detector inputs.
- `public-corpus.jsonl`: replay data. It contains no scenario, label, or
  ground-truth evidence.
- `gt.jsonl`: private instance labels and expected side-effect probes. This
  file is consumed only by the post-run scorer.

The runner writes `observations.jsonl` with one or more rows per instance.
Each row must include the decision, validity/timeout status, end-to-end
latency, business outcome, and a side-effect probe result. A successful HTTP
response is not sufficient evidence that a dangerous action was prevented.
`bench/agentrange_benchmark.py score` joins these files by `instance_id` and
marks missing or incomplete evidence as `unknown` instead of silently
counting it as a pass.
