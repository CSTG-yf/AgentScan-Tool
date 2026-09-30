# 68a661f public-arena action evidence

This is a lightweight summary of the 5,200-instance local action replay.
`action-run.json` and `baseline-run.json` pin the source commit, arena and
corpus hashes. `*-process.json` record each replay window and exit code.
`summary.json` contains scenario metrics, resource comparisons and the 12
local gates. `final-report.md` contains the scoped chain summary. The
interactive display is [`../../AGENTRANGE-SHOWCASE.html`](../../AGENTRANGE-SHOWCASE.html).

The baseline is the completed window from
`bench/runs/20260930-68a661f-v1/full-pair/baseline`, copied unchanged into
`bench/runs/20260930-68a661f-v2/full-pair/baseline`. Action and baseline
manifests match on commit, arena, public corpus and semantic ground truth;
the scorer verified all 19 containers and a 0.999 throughput ratio.

Action: 80/80 attacks blocked before the dangerous side effect, zero false
positives, 5,120/5,120 normal successes, 121 ms inspection p95, 548.939 ms
end-to-end p95, and 1.59 percentage points maximum per-container CPU p95
increment. There were **21 unavailable inspections across five instances**;
the zero-unavailable gate failed, so the result is **11/12 local gates**.
The export contains 99,221 scoped events and 5,200 instance chains.

The raw files remain in the ignored local run directory. The following
SHA-256 values permit local verification without publishing prompts,
responses or the multi-gigabyte audit database.

| Raw file relative to `full-pair/` | Bytes | SHA-256 |
| --- | ---: | --- |
| `action/observations.jsonl` | 2,861,062 | `29208f696739f7ed934cf98f1eeaa8815910b6aa02c63251cfc8202afbe44e28` |
| `action/runtime-events.jsonl` | 130,135,315 | `b770eac0287c3c5188a64f598f11a1b74eefeefd42b4b00a9484d42eeebbe377` |
| `action/attack-chains.json` | 129,869,168 | `3f3cc3e68e34515b33d91107f58ef1c0435b41df22e2d98833906046bfe521c8` |
| `action/resources.jsonl` | 11,975,409 | `4f35b03a5480efc462b7f1a3e47c83988c60bfab7a65207e54d0e06ac58981b7` |
| `action/host-gateway.jsonl` | 839,042 | `544cf5c1fdeee9bf26e6e3f99982735d8130388241511e2cb17369be5010938d` |
| `baseline/observations.jsonl` | 2,328,638 | `7430108324a280ad931e25cc4962a66af8979dcbaa6ae514f9022fd26e32c100` |
| `baseline/resources.jsonl` | 7,031,765 | `cdf781da8aeb95c3a433afa3b1768bcce562a6b4647236d79a1b8a43fa157834` |
| `baseline/host-gateway.jsonl` | 421,470 | `c5ef03a6c7fa16c8f9a39958b022ac230296ff368b33b99dc7aa4cc77d633b40` |

These scores apply only to arena hash
`bcd51ef41b2bfd2871a06e03e6835d26c41e45436e86121c722981b06dcc5d5b`
and detector source commit `68a661f7c8e817e65ecfc83dd789dcefec9b2be7`.
The official attachment and hidden set have not been verified against this
local arena.
