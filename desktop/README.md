# DefenseClaw Desktop

DefenseClaw Desktop is the Windows control plane for the existing DefenseClaw
gateway, AI discovery, policy engine, evidence store, and AgentRange runtime.
The desktop shell does not replace those components: it packages and
orchestrates them behind one signed application entry point.

## Architecture

- **UI:** React + TypeScript + Ant Design, bundled by Vite.
- **Desktop host:** Tauri 2/Rust. Only typed commands are exposed to the webview.
- **Gateway:** the existing Go `defenseclaw-gateway` process.
- **Range:** the existing Docker Compose AgentRange checkout and adapter.
- **Process guard:** a separate LocalSystem Windows service. The UI itself
  remains unelevated; fixed UAC entry points install/remove the service and
  apply validated policy to `%ProgramData%\DefenseClaw`. The service reloads
  that policy and writes append-only JSONL audit evidence there.

There are two command-control paths:

1. Instrumented agents call the existing `/api/v1/inspect/tool` hook. A denied
   command is stopped before it starts.
2. The Windows process guard listens for process-create events. If a child
   executable matches an enabled rule and its ancestry resolves to a known
   Agent PID, the service records evidence and terminates the configured Agent
   process tree. This is a fallback for agents without a hook integration.

The process guard is opt-in and starts in `observe` mode. Switching to `enforce`
requires elevation and explicit operator confirmation.

## Local development

Prerequisites on Windows 10/11 x64:

- Node.js 20.19+ (Node.js 22.12+ recommended)
- pnpm 10+
- Rust stable with the MSVC target
- Visual Studio Build Tools (Desktop development with C++)
- Microsoft Edge WebView2
- Go 1.24+ when rebuilding the gateway sidecar
- Docker Desktop when running AgentRange

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

## Windows process-guard acceptance test

From an elevated PowerShell session, run:

```powershell
.\scripts\test-process-guard.ps1
```

The test builds a dedicated fixture Agent, applies a temporary `cmd.exe`
blacklist rule, verifies that the LocalSystem service terminates the fixture
tree, and restores the previous machine policy and service state in `finally`.

To validate the packaged NSIS installer, bundled gateway, Windows service, and
stable uninstall cleanup from an elevated PowerShell session, run:

```powershell
.\scripts\test-installer.ps1
```

## Contracts

The JSON Schemas under `contracts/` define the boundary between UI, desktop
host, gateway, range adapter, and elevated process guard. Breaking changes must
update the schema version and receive a migration.
