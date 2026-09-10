# TraceBastion Desktop

TraceBastion Desktop is the Windows control plane for the existing gateway,
AI discovery, policy engine, evidence store, and AgentRange runtime.
The desktop shell does not replace those components: it packages and
orchestrates them behind one signed application entry point.

Download the current Windows x64 installer from
[GitHub Releases](https://github.com/CSTG-yf/AgentScan-Tool/releases/latest).
The installer is currently unsigned, so Windows SmartScreen may require an
explicit operator confirmation until code signing is configured.

## Architecture

- **UI:** React + TypeScript + Ant Design, bundled by Vite.
- **Desktop host:** Tauri 2/Rust. Only typed commands are exposed to the webview.
- **Gateway:** the existing Go gateway process (its internal executable name is
  retained for upgrade compatibility).
- **Range:** the existing Docker Compose AgentRange checkout and adapter.
- **Process guard:** a separate LocalSystem Windows service. The UI itself
  remains unelevated; fixed UAC entry points install/remove the service and
  apply validated policy to a protected machine-wide data directory. The
  service reloads that policy and writes append-only JSONL audit evidence
  there.

There are two command-control paths:

1. Instrumented agents call the existing `/api/v1/inspect/tool` hook. A denied
   command is stopped before it starts.
2. The Windows process guard listens for process-create events. If a child
   executable matches an enabled rule and its ancestry resolves to a known
   Agent PID, the service records evidence and terminates the configured Agent
   process tree. This is a fallback for agents without a hook integration.

The process guard is opt-in and starts in `observe` mode. Applying system policy
requires administrator privileges. Windows may execute the helper without a UAC
prompt when the application already has those privileges. Install, apply, and
uninstall wait for the helper to exit before reporting completion; cancellation,
launch failure, a nonzero exit code, and an execution timeout are reported as
errors. The UI remains responsive while waiting and suppresses duplicate clicks.

## Agent file blacklist and activity Trace

Policy v2 adds absolute monitoring roots under `fileGuard.auditRoots` and
sensitive file or directory rules under `fileGuard.blacklist`. Applying the
policy with elevation enables successful Windows File System auditing and adds
a success-audit SACL to each configured path. The LocalSystem service consumes
Security events 4663 (an access right was actually used) and 4660 (deletion),
then attributes the PID to a known Agent process tree.

On a blacklist match the service writes SQLite Trace and JSONL evidence and
leaves the Agent process running. Saved v2 file rules using the former
`terminateAgentTree` action are migrated to `returnEmptyContent` when loaded.
Trace is stored in the protected machine-wide data directory; it includes Agent
launches, child commands, file reads, writes, creates, deletes, and blacklist
outcomes.
Default retention is 30 days with a 256 MB database cap. Operators configure
the feature in Policy Center and query it from the Activity Trace page.

Claude Code and Codex synchronous `PreToolUse` hooks now redirect supported
blacklisted reads to an empty substitute file. The original file is never
truncated or overwritten. The Gateway checks the rewritten tool input through
the existing inspection pipeline before returning `updatedInput` with an allow
decision; other policy denials still take precedence. `file_read_empty` audit
events record that a rewrite was issued, not a claim that the Agent executed it.

Enable the policy, file blacklist, and `enforce` mode in Policy Center, and
enable the connector's hooks in `action` mode. Desktop-launched Gateways receive
the UI policy path through `DEFENSECLAW_FILE_GUARD_POLICY`; policy edits are read
on each supported request. Standalone Gateways can set that environment variable
explicitly; Windows otherwise uses `%ProgramData%\DefenseClaw\process-guard.json`.
Restart an already-running Gateway after upgrading to receive the new path.

Supported inputs are `Read`/`read_file` with `file_path` or `path`, and a single
literal `cat PATH` or `Get-Content [-LiteralPath|-Path] PATH` through
`Bash`/`shell`/`shell_command`/`exec_command`. Quoted paths and relative paths
resolved against the hook working directory are supported. Shell commands read
the substitute normally, producing zero content bytes; native Read may display
its standard empty-file notice. Pipelines, command arrays, multiple files,
shell expansions, arbitrary scripts, MCP tools, remote/WSL agents, and direct
system calls are outside this first adapter's coverage. Use a local Gateway
running as the same user as the Agent so the substitute is accessible.

Codex requires **0.153.4 or newer** (the verified rewrite-capable release), with
its version refreshed by connector discovery/setup in `agent_discovery.json`.
An older or unknown version receives a denied individual read and an upgrade
diagnostic; the Agent process is not terminated. A policy parse failure or an
invalid substitute likewise denies the read rather than returning real content.
Do not configure multiple hooks to rewrite the same input: the Agent's hook
protocol uses the last completed rewrite. See the
[Claude Code hook contract](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)
and [Codex 0.153.4 implementation](https://github.com/openai/codex/blob/rust-v0.153.4/codex-rs/hooks/src/events/pre_tool_use.rs).

Windows object access auditing reports after access occurred, so this backend
cannot replace content already returned by a direct filesystem read. The audit
backend records this capability boundary and never terminates the Agent for a
file blacklist match. Full filesystem coverage requires a signed Minifilter.
Directory-change APIs are not used to infer reads because they do not reliably
identify the process that accessed a file.

## Agent runtime knowledge base

The structured catalog at `knowledge/agent-runtime-catalog.json` records common
Agent launch commands, dedicated Windows process image names, related host
processes, and frequently spawned command processes with risk metadata. The
desktop host uses it as the source of truth for local Agent process identity and
exposes it through the read-only `get_agent_runtime_catalog` command.

Generic hosts such as `node.exe`, `python.exe`, `code.exe`, `wsl.exe`, and
`docker.exe` are context hints only and are never treated as Agent roots by
basename. The contract is
`contracts/agent-runtime-catalog.schema.json`; maintenance and source rules are
documented in `knowledge/README.md`.

## Local development

Prerequisites on Windows 10/11 x64:

- Node.js 20.19+ (Node.js 22.12+ recommended)
- pnpm 10+
- Rust stable with the MSVC target
- Visual Studio Build Tools (Desktop development with C++)
- Microsoft Edge WebView2
- Go 1.24+ when rebuilding the gateway sidecar
- A Docker Compose-compatible container runtime when running the optional AgentRange lab

```powershell
cd desktop
pnpm install
pnpm dev
```

Build the web UI only:

```powershell
pnpm build
```

Build the Windows desktop installer:

```powershell
.\scripts\build.ps1
```

The script is intentionally repeatable. After modifying the source, rerun it
to rebuild the frontend, Go gateway, and Tauri NSIS installer. It fails when Go
is unavailable so a stale or incomplete gateway cannot silently ship. For a
local shell-only experiment, `-AllowMissingGateway` may reuse an existing
development gateway resource.

The interactive NSIS installer includes a **Choose Install Location** page and
defaults to `%ProgramFiles%\TraceBastion Desktop`. Browse to any suitable local
destination before selecting **Install**. Because the process guard is a
LocalSystem service, installation remains machine-wide and requires elevation.

For unattended deployment, pass an absolute destination with NSIS `/D`. `/D`
must be the final argument, including when the path contains spaces:

```powershell
& ".\dist\TraceBastion-Desktop-Setup-x64.exe" /S /D=D:\Security Tools\TraceBastion
```

An upgrade retains the destination recorded by the previous installation.

## Windows process-guard acceptance test

From an elevated PowerShell session, run:

```powershell
.\scripts\test-process-guard.ps1
```

The test builds a dedicated fixture Agent, applies a temporary `cmd.exe`
blacklist rule, verifies that the LocalSystem service terminates the fixture
tree, and restores the previous machine policy and service state in `finally`.

The file guard has a separate end-to-end acceptance test. It backs up and
restores the machine audit policy, applies a temporary SACL and blacklist,
starts a fixture Agent that reads the sensitive file, verifies that the Agent
keeps running and evidence is recorded, and removes the temporary service and
files:

```powershell
.\scripts\test-file-guard.ps1
```

To validate the packaged NSIS installer, bundled gateway, Windows service, and
stable uninstall cleanup from an elevated PowerShell session, run:

```powershell
.\scripts\test-installer.ps1 -InstallDir "D:\TraceBastion-Installer-Test"
```

The acceptance test verifies that the selected destination is recorded in the
Windows uninstall registry entry, exercises the bundled gateway and process
guard service from that directory, and confirms uninstall removes it cleanly.

## Upgrade compatibility

The Windows service key, application identifier, internal executable names,
and existing machine data directory retain their legacy values. Keeping these
non-user-facing identifiers stable lets an installed version upgrade without
creating a second service, losing policy, or orphaning evidence. Product UI,
window titles, installer display names, and documentation use TraceBastion.

## Contracts

The JSON Schemas under `contracts/` define the boundary between UI, desktop
host, gateway, range adapter, and elevated process guard. Breaking changes must
update the schema version and receive a migration.
