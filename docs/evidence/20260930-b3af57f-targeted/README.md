# AgentRange inspection availability: targeted follow-up

Source change: `b3af57f` on branch `揭榜赛作品`.

## Previous observed failure

The last complete action replay used detector source `68a661f`, not this change. Its [scored summary](../20260930-68a661f-action/summary.json) reports 21 unavailable inspections in five instances. All 21 sidecar events give `<urlopen error timed out>`; the four sidecars use a 1,200 ms inspection timeout. Counts by instance are `B-OPS-857: 7`, `B-RD-896: 8`, `B-SEC-910: 4`, `C2-C-856: 1`, and `C2-D-895: 1`. Several Gateway audit records for these instances appear only after the sidecar timeouts. Gateway host samples in the same windows show roughly 80-95% of one logical processor. These observations support a queueing diagnosis, but do not prove a unique cause.

## Focused change and test

`internal/detection/engine.go` previously held one mutex while evaluating every completed inspection event. It now uses 64 session-keyed lock shards, falling back to trace, canonical agent, then event ID when earlier keys are absent. This keeps a same-session retry ordered while allowing unrelated sessions to evaluate concurrently.

```powershell
go test ./internal/detection -run TestInspectionEvaluationUsesSessionScopedLocks -count=1 -v
```

Result on 2026-09-30: `PASS`; the focused test took 0.29 seconds. It holds two independent evaluations open at once, starts a concurrent retry of one event, and checks that the event is evaluated only once after completion. `go test -race` was unavailable because this Windows Go environment has CGO disabled and no C compiler.

## Isolated HTTP probe

A newly built Gateway ran with an isolated audit database and `gateway.api_port=18971`; the existing service on `18970` was left running. Its inspect responses reported `mode=action`. The probe sent 16 benign requests to each of `/api/v1/inspect/request`, `/response`, `/tool`, and `/tool-response`, with unique session/event IDs, eight concurrent HTTP workers, keep-alive connections and a 1,200 ms client timeout. All 64 responses were HTTP 200 with `X-DefenseClaw-Runtime-Status: recorded` and action mode. No timeout or unavailable response occurred in this sample.

| Inspect endpoint | Requests | Recorded | Client p95 | Client max |
| --- | ---: | ---: | ---: | ---: |
| request | 16 | 16 | 109 ms | 109 ms |
| response | 16 | 16 | 63 ms | 63 ms |
| tool | 16 | 16 | 109 ms | 109 ms |
| tool-response | 16 | 16 | 94 ms | 94 ms |

Client latency includes local HTTP transport, Gateway inspection, and durable runtime recording. The isolated process was stopped after the probe and the original `18970` listener remained active.

The historical full-run score remains 11/12. This follow-up records only the focused tests above; no paired CPU sample or other-metric regression check was run.
