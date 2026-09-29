# AgentRange local evaluation (updated 2026-09-30)

This is a local evaluation against the public `AgentRange-player-full` arena,
not an official hidden-set result. The arena SHA-256 manifest is
`bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`.
Ground truth was used by the offline scorer, not the online detector.

The latest 1,200 ms inspection-deadline action and baseline both exited 0 with
5,200 valid observations (seed 1337, 80 attacks) at 1.5 events/second. They
used commit `fb5a190`, identical public corpus, semantic truth and arena
hashes, and the same 19-container topology. Measured throughput ratio was
1.000; only the four sidecars' inspection bypass differed. The action audit
join covered all 5,200 instances, with 80/80 confirmed blocks, zero false
positives, 5,120/5,120 normal business successes, and zero unavailable
inspections. Inspection p95 was 100 ms and end-to-end p95 was 450.383 ms.
The largest per-container CPU p95 increase was 0.87 percentage points at the
LLM proxy. Host Gateway CPU p95 was 2.574% of logical host capacity, and
combined Gateway plus defense-container CPU p95 was 3.132%. Host and Docker
sample windows were complete; all local scorer acceptance gates passed. This
is a public-arena local result, not an official hidden-set score. The paired
evidence is at `bench/runs/20260930-probe1200-cache-full-rate150-v1/{action,baseline}`.
Four sidecars were returned to `DC_BYPASS_INSPECTION=0` after baseline.
The scoped audit export contains 99,237 events grouped into exactly 5,200
instance chains, including the same 80 blocked instances as the scored action
observations. The local report and dashboard are at
`bench/runs/20260930-probe1200-cache-full-rate150-v1/final-report.{json,md}`
and `dashboard.html`; their evidence index points to this paired replay and the
static fixture artifacts, not the historical `bench/results` summary. These
large generated files remain in the ignored local run directory.

The same 1,200 ms candidate first completed a 1,000-event action check with
16/16 blocks, no false positives, 984/984 normal successes, zero unavailable
inspections, 465.274 ms end-to-end p95, and 3.123% combined defense CPU p95.
It is at `bench/runs/20260930-probe1200-cache-rate150-1k/action`.

Earlier experiments are retained below for comparison.

| Measure | Agent transaction full pair | Pooled retry full action | Earlier full matched-rate pair | Earlier natural-rate action | 1,000-event matched-rate pair |
| --- | ---: | ---: | ---: | ---: | ---: |
| Events / attacks | 5,200 / 80 | 5,200 / 80 | 5,200 / 80 | 5,200 / 80 | 1,000 / 16 |
| True positives / false negatives / unknown | 80 / 0 / 0 | 80 / 0 / 0 | 80 / 0 / 0 | 80 / 0 / 0 | 16 / 0 / 0 |
| False positives | 0 | 0 | 0 | 0 | 0 |
| Normal business successes | 5,120 / 5,120 | 5,120 / 5,120 | 5,120 / 5,120 | 5,120 / 5,120 | 984 / 984 |
| Inspection p95 | 145 ms (5,200/5,200) | 128 ms (5,200/5,200) | 157 ms (5,200/5,200) | 175 ms | 115 ms |
| End-to-end p95 | 667.005 ms | 548.247 ms | 955.270 ms | 1,003.966 ms | 861.870 ms |
| Per-container CPU p95 increment | 1.08 percentage points | Unverified against same code | 1.45 percentage points | Unverified | 1.14 percentage points |
| Host Gateway plus defense containers CPU p95 | 5.015% | 4.240% | 4.867% | Unverified | Unverified |
| Inspection unavailable events / affected instances | 33 / 24 | 8 / 6 | 1,582 / 1,190 | Unmeasured | Unmeasured |

The agent transaction action and baseline each exited 0 with 5,200 valid
observations, identical commit, arena, public corpus, seed, and semantic truth
hashes. The measured throughput ratio was 1.001, all 19 containers matched,
and the host and container CPU windows were complete. Per-container CPU p95
increment passed the local 5-point gate, while 33 unavailable inspections and
5.015% combined defense CPU p95 failed their local gates. The action audit join
covered all 5,200 instances; the 33 unavailable events affected 24 benign
instances. This pair used the pre-cache Gateway binary and is retained at
`bench/runs/20260929-agent-tx-full-rate150-v1/{action,baseline}`.

The new audit-cache Gateway alone completed a matched-input 1,000-event action
replay at 1.5 events/second with 16/16 confirmed blocks, no false positives,
984/984 normal successes, one unavailable LLM inspection, 477.825 ms
end-to-end p95, 97 ms inspection p95, and 3.800% combined defense CPU p95.
The unavailable inspection reached the sidecar's 400 ms deadline while the
Gateway had a concurrent slow secondary audit write. That run is at
`bench/runs/20260929-cache-rate150-1k/action`.

With the OpsPilot call-site probe and a 600 ms sidecar inspection deadline,
the same 1,000-event input had 16/16 confirmed blocks, no false positives,
984/984 normal successes, zero unavailable inspections, 464.968 ms end-to-end
p95, 95 ms inspection p95, and 3.657% combined defense CPU p95. The host and
container sample windows were complete. A separate 10-event smoke replay
confirmed bounded `api.app` call-site frames in sidecar audit records, marked
`client_reported`; those frames do not enter the block decision. The candidate
run is `bench/runs/20260929-probe600-rate150-1k/action`. These two short runs
do not isolate the probe from the timeout change, and neither has a same-code
CPU baseline or full-sample acceptance result.

The 600 ms probe candidate then completed a 5,200-event action replay with
80/80 confirmed blocks, no false positives, 5,120/5,120 normal successes,
466.875 ms end-to-end p95, 101 ms inspection p95, and 3.328% combined defense
CPU p95. Audit coverage was complete, but three inspections timed out at the
600 ms deadline across three instances (one attack and two benign). Gateway
audit records for the matching inspections arrived around or shortly after the
sidecar deadline. This run fails the local zero-unavailable gate and is retained
at `bench/runs/20260929-probe600-cache-full-rate150-v1/action`. The later
1,200 ms full pair is reported above.

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
host and container CPU samples, but no same-code baseline; the full pair above
supplies that comparison for the pre-cache Gateway.

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
(56 tests); targeted audit and Gateway runtime Go tests also pass. The broad Go
gateway test package has unrelated Windows-only failures in WSL/bash, Unix
permission, and symlink-dependent cases.

Raw observations, resource samples, audit databases, and generated reports are
kept under ignored local run directories. The latest completed paired score is at
`bench/runs/20260930-probe1200-cache-full-rate150-v1/action/summary.json`, paired with
`bench/runs/20260930-probe1200-cache-full-rate150-v1/baseline`. The earlier matched-rate action
is at `bench/runs/20260929-full-rate150-v1/action`. Older scores remain at
`bench/runs/20260929-full-v6/action` and
`bench/runs/20260929-cpu-rate120-1k/{baseline,action}`. Do not combine the
older observe results under `bench/results/` with this arena hash.
