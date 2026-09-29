# AgentRange local evaluation (2026-09-29)

This is a local evaluation against the public `AgentRange-player-full` arena,
not an official hidden-set result. The arena SHA-256 manifest is
`bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`.
Ground truth was used by the offline scorer, not the online detector.

| Measure | Pooled retry full action | Earlier full matched-rate pair | Earlier natural-rate action | 1,000-event matched-rate pair |
| --- | ---: | ---: | ---: | ---: |
| Events / attacks | 5,200 / 80 | 5,200 / 80 | 5,200 / 80 | 1,000 / 16 |
| True positives / false negatives / unknown | 80 / 0 / 0 | 80 / 0 / 0 | 80 / 0 / 0 | 16 / 0 / 0 |
| False positives | 0 | 0 | 0 | 0 |
| Normal business successes | 5,120 / 5,120 | 5,120 / 5,120 | 5,120 / 5,120 | 984 / 984 |
| Inspection p95 | 128 ms (5,200/5,200) | 157 ms (5,200/5,200) | 175 ms | 115 ms |
| End-to-end p95 | 548.247 ms | 955.270 ms | 1,003.966 ms | 861.870 ms |
| Per-container CPU p95 increment | Unverified against same code | 1.45 percentage points | Unverified | 1.14 percentage points |
| Host Gateway plus defense containers CPU p95 | 4.240% | 4.867% | Unverified | Unverified |
| Inspection unavailable events / affected instances | 8 / 6 | 1,582 / 1,190 | Unmeasured | Unmeasured |

The earlier full pair uses the same 5,200-event public corpus and semantic
ground truth (seed 1337, 80 attacks, arena hash above) in baseline and action,
both capped at 1.5 events/second. Measured throughput ratio is 1.000 and all
19 containers match. Only benchmark scripts, tests, and documentation changed
between that baseline and its paired action commit; detector and sidecar runtime
code did not. Both replays exited 0 with 5,200 valid observations and
no timeouts. The action audit join found all 5,200 instances, and every attack
had enforced-block and side-effect evidence. The host Gateway sample covers
the replay from 2.002 seconds after start to 0.556 seconds before finish;
the combined CPU report aligns all 1,213 Docker snapshots with host samples.
Host Gateway CPU p95 is 4.285% and combined defense CPU p95 is 4.867%; the
combined instantaneous maximum is 8.175%. The detection, business, latency,
evidence, and CPU gates pass, but the new `inspect_unavailable_eq_0` availability
gate fails. The competition document does not specify a CPU
aggregation statistic, so a local p95 pass is not an official CPU verdict.

An earlier full matched-rate action replay against the same baseline exited 0
with 5,200 valid observations, but one C2-C attack was `unknown`: the nested
LLM proxy returned a block while transient container-to-host `Network is
unreachable` errors prevented its sidecar audit event from arriving. That run
had 79 confirmed true positives, one unknown, 5,199/5,200 inspection latency
samples, end-to-end p95 996.053 ms, and per-container CPU increment 1.28
percentage points. Its host sampler started 239 seconds late, so host CPU
p95 4.373% and combined CPU p95 5.066% are partial-window observations,
not acceptance results. The second run supplies complete evidence but the
first run shows that audit delivery and CPU margin are sensitive to the local
environment. The sidecars currently fail open when inspection is unavailable;
that transport failure remains an operational risk beyond the scored sample.
Rejoining mode-less failed-inspection audit rows found 1,580 unavailable
events affecting 1,151 instances in that run. The stricter action scorer still
requires a sidecar-enforced block; an HTTP or nested response claiming `block`
without that audit evidence remains `unknown`.

A separate 1,000-event action probe raised all four sidecar inspection timeouts
from 250 to 350 ms at 1.5 events/second. It still had 253 unavailable events
affecting 197 instances, while end-to-end p95 rose to 1,099.623 ms and
combined defense CPU p95 was 5.004%. Gateway inspection records exist for
251/253 unavailable attempts, but the sidecar retries failed checks after
response delivery with the same event ID. Those records cannot establish
whether the original attempt reached the Gateway or only its retry did. The
experiment did not improve the overall gate and the sidecars were restored to 250 ms.
Its ignored run is `bench/runs/20260929-timeout350-rate150-1k/action`.

With a pooled Gateway HTTP connection, the same 1,000-event, 1.5-event/second
action replay at 250 ms had 3 unavailable inspections, 16/16 confirmed blocks,
984/984 normal successes, 539.809 ms end-to-end p95, and 4.203% combined CPU
p95. Raising only the timeout to 400 ms left 1 unavailable inspection and
541.990 ms end-to-end p95. Prewarming four connections per sidecar still left
1 unavailable inspection, so that extra startup behavior was removed.

The pooled-retry candidate kept connection reuse and retried an unanswered inspect
request once using the same runtime event ID, within a 400 ms total deadline.
Its matched-input 1,000-event action replay had 16/16 confirmed blocks,
0 false positives, 984/984 normal successes, 0 unavailable inspections,
109 ms inspection p95, 562.734 ms end-to-end p95, and 4.205% combined CPU
p95. It is at `bench/runs/20260929-pooled-retry400-rate150-1k/action`.
The pooled-retry 5,200-event action replay subsequently confirmed 80/80 blocks,
0 false positives, 5,120/5,120 normal successes, 548.247 ms end-to-end p95,
and 4.240% combined defense CPU p95. Eight inspections were unavailable across
six benign instances, so the availability gate still failed. Its scorer reports
a 0.38-point CPU increment against an older full baseline, but that baseline
ran before the connection-pool changes and does not establish a same-code CPU
comparison. The run is at
`bench/runs/20260929-pooled-retry400-full-rate150-v1/action`.

A diagnostic replay on the same 1,000-event corpus found one unavailable
inspection. Gateway timing logs tied a failed request to 508 ms spent recording
the runtime event, almost entirely in repeated Agent identity updates, before
the rule scan began. Startup also revisited roughly 770,000 audit rows even
though only 34 lacked a canonical Agent ID. The current candidate limits that
backfill to unbound rows, skips unnecessary alias lookup for explicit Agent
identity, and writes the Agent and aliases in one transaction. Its same-input
1,000-event action replay confirmed 16/16 blocks, 0 false positives,
984/984 normal successes, 0 unavailable inspections, 554.221 ms end-to-end
p95, 124 ms inspection p95, and 4.147% combined defense CPU p95. The diagnostic
and candidate runs are at `bench/runs/20260929-diagnostic-backfill-1k-v1/action`
and `bench/runs/20260929-agent-tx-rate150-1k/action`. The latter has complete
host and container CPU samples, but no same-code baseline. A new 5,200-event
action replay and matched-rate, same-code baseline are still required.

The earlier natural-rate action replay had an end-to-end p95 that exceeded
the local 1,000 ms gate by 3.966 ms, even though its inspection p95 is below
that gate. Its older CPU baseline ran at a different rate (action/baseline
throughput ratio 0.359), so the scorer marks that CPU comparison
`throughput_mismatch` and does not claim a pass.

The matched-rate pair used identical 1,000-event inputs and a 1.2-event/second
cap in both modes. Baseline and action took 834.6 and 834.8 seconds respectively
(measured throughput ratio 1.000). The same 19-container topology was present;
only the sidecars' inspection bypass differed. CPU increment is the largest
per-container difference between action and baseline CPU p95, with the LLM
proxy contributing the maximum 1.14 percentage points. Both replays exited 0,
and the action observations were joined with audit and side-effect evidence
before scoring.

The frozen local static fixture reports 27/27 assets and 13/13 risk pairs,
with no false positives or misses. It covers this arena hash only and does not
measure unseen assets or attack variants. Current Python-focused tests pass
(43 tests); the targeted Go AgentRange rule test also passes. The broad Go
gateway test package has unrelated Windows-only failures in WSL/bash, Unix
permission, and symlink-dependent cases.

Raw observations, resource samples, audit databases, and generated reports are
kept under ignored local run directories. The latest score is at
`bench/runs/20260929-full-rate150-v2/action/summary.json`, paired with
`bench/runs/20260929-full-rate150-v1/baseline`. The earlier matched-rate action
is at `bench/runs/20260929-full-rate150-v1/action`. Older scores remain at
`bench/runs/20260929-full-v6/action` and
`bench/runs/20260929-cpu-rate120-1k/{baseline,action}`. Do not combine the
older observe results under `bench/results/` with this arena hash.
