# AgentRange local evaluation (2026-09-29)

This is a local evaluation against the public `AgentRange-player-full` arena,
not an official hidden-set result. The arena SHA-256 manifest is
`bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`.
Ground truth was used by the offline scorer, not the online detector.

| Measure | Full action replay | Matched-rate pair |
| --- | ---: | ---: |
| Events / attacks | 5,200 / 80 | 1,000 / 16 |
| True positives / false negatives | 80 / 0 | 16 / 0 |
| False positives / unknown | 0 / 0 | 0 / 0 |
| Normal business successes | 5,120 / 5,120 | 984 / 984 |
| Inspection p95 | 175 ms | 115 ms |
| End-to-end p95 | 1,003.966 ms | 861.870 ms |
| CPU increment | Unverified | 1.14 percentage points |

The full action replay used the natural replay rate. Its end-to-end p95 exceeds
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
(36 tests); the targeted Go AgentRange rule test also passes. The broad Go
gateway test package has unrelated Windows-only failures in WSL/bash, Unix
permission, and symlink-dependent cases.

Raw observations, resource samples, audit databases, and generated reports are
kept under ignored local run directories. The scores above can be regenerated
with `bench/benchmark.py score`, using
`bench/runs/20260929-full-v6/action` or the paired
`bench/runs/20260929-cpu-rate120-1k/{baseline,action}` directories.
