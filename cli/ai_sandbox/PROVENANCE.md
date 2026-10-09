# Managed sandbox runtime provenance

The runtime in this directory was supplied by the user in
`temp.rar` as `ai-sandbox-kit/ai_sandbox/`. Its source notes identify
`D:\langgraph-agent`, commit `c6d5295`, as the origin. The supplied
`pyproject.toml` declares `Proprietary`; this import does not change that
declaration or relicense the files under the repository's Apache-2.0 license.

The integration adds a fail-closed CLI gate in
`defenseclaw.commands.cmd_sandbox`. The original runtime's `null` backend
remains available to its library callers but is never accepted by that CLI.
