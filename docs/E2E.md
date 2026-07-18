# Local End-to-End Testing

DefenseClaw end-to-end checks run manually on a prepared Linux or macOS host.
The repository does not provide hosted CI/CD jobs or a GitHub Actions runner.
Use the focused profile that matches the services and credentials available on
the host.

## Prerequisites

| Dependency | Purpose |
|------------|---------|
| Go 1.25+ | Build the DefenseClaw gateway |
| Node.js 20+ | Build the OpenClaw extension |
| Python 3.12+ and `uv` | CLI and test helpers |
| Docker 24+ with Compose | Local Splunk verification |
| `jq` | Shell-script JSON processing |
| OpenClaw | Full-stack and live-agent checks |

Live-agent profiles additionally require provider credentials and any agent
CLI being exercised. Keep secrets in the local environment or
`~/.defenseclaw/.env`; do not commit them.

## Full-stack harness

Install and initialize a disposable local instance, then run the core profile:

```bash
make install
defenseclaw init
E2E_PROFILE=core bash scripts/test-e2e-full-stack.sh
```

The `core` profile covers stack health, skill and MCP scanning, block/allow
enforcement, quarantine and restore, watcher scans, CodeGuard, status and
doctor commands, AIBOM, policy commands, the skill API, and local Splunk
verification.

For real model and agent interactions, run the credentialed profile:

```bash
export ANTHROPIC_API_KEY=...
export E2E_PROFILE=full-live
export E2E_REQUIRE_GUARDRAIL=true
bash scripts/test-e2e-full-stack.sh
```

Optional live behavior is controlled by the `E2E_REQUIRE_*` and
`E2E_ENABLE_*` variables declared near the top of
`scripts/test-e2e-full-stack.sh`. Use a run-specific identifier when multiple
operators share a host:

```bash
export DEFENSECLAW_RUN_ID="manual-$(date -u +%Y%m%dT%H%M%SZ)"
```

## Connector harness

The connector harness has two layers:

- `contract` feeds golden payloads through installed hook entrypoints and does
  not require an LLM.
- `live` drives installed upstream agents and requires the corresponding
  credentials.

Run one connector and operating-system cell at a time:

```bash
bash scripts/live-connector-e2e/run.sh --layer contract --connector codex
bash scripts/live-connector-e2e/run.sh --layer live --connector codex
```

Where all required agents are installed, `--connector all` runs every
available cell. Set `DC_E2E_LOG_DIR` to choose where diagnostic logs are
staged.

## Sandbox checks

Sandbox lifecycle tests require a dedicated Linux host with root access and
namespace support:

```bash
sudo make sandbox-test
```

Do not run privileged sandbox checks on a shared workstation. The sandbox
scripts create users, service definitions, namespaces, and temporary policy
state.

## Useful focused checks

```bash
bash scripts/test-e2e-tool-block.sh
bash scripts/test-e2e-sandbox-policy-diff.sh
bash scripts/test-e2e-custom-provider.sh
```

Platform-specific entrypoints include `scripts/test-e2e-mac.sh` and
`scripts/test-e2e-spark.sh`.

## Local services and troubleshooting

The full-stack harness can use the local Splunk Compose configuration under
`bundles/splunk_local_bridge/compose/`. Useful diagnostics are:

```bash
defenseclaw-gateway status
tail -50 ~/.defenseclaw/gateway.log
docker ps -a --filter name=splunk
```

OpenClaw configuration and authentication persist unless the operator removes
them. Test-created skills, plugins, quarantine objects, and temporary files
are run-scoped and cleaned by the harness. Review staged logs before manually
deleting state after a failure.
