# AgentRange inspection availability: targeted follow-up

Source change: `b3af57f` on branch `揭榜赛作品`.

## Previous observed failure

The last complete action replay used detector source `68a661f`, not this change. Its [scored summary](../20260930-68a661f-action/summary.json) reports 21 unavailable inspections in five instances. All 21 sidecar events give `<urlopen error timed out>`; the four sidecars use a 1,200 ms inspection timeout. Counts by instance are `B-OPS-857: 7`, `B-RD-896: 8`, `B-SEC-910: 4`, `C2-C-856: 1`, and `C2-D-895: 1`. Several Gateway audit records for these instances appear only after the sidecar timeouts. Gateway host samples in the same windows show roughly 80-95% of one logical processor. These observations support a queueing diagnosis, but do not prove a unique cause.

## Focused change and test

`internal/detection/engine.go` previously held one mutex while evaluating every completed inspection event. It now uses 64 session-keyed lock shards, falling back to trace, canonical agent, then event ID when earlier keys are absent. This keeps a same-session retry ordered while allowing unrelated sessions to evaluate concurrently.

```powershell
go test ./internal/detection -run TestInspectionEvaluationUsesSessionScopedLocks -count=1 -v
```

Result on 2026-09-30: `PASS`; the focused test took 0.29 seconds. It holds two independent evaluations open at once, starts a concurrent retry of one event, and checks that the event is evaluated only once after completion. No full replay, paired CPU sample, or other-metric regression check was run. `go test -race` was unavailable because this Windows Go environment has CGO disabled and no C compiler.

The historical 11/12 score remains the only full-run result. This focused test does not establish zero inspection failures under a production-length replay or an official hidden-set score.
