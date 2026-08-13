# Desktop architecture and security boundaries

## Product boundary

The deliverable is a Windows x64 desktop product with one visible application
entry point and an NSIS `Setup.exe`. The installed product may contain signed
sidecars and runtime resources; “one EXE” does not mean embedding Docker images
or executing every existing language runtime inside a single process.

The desktop application owns lifecycle, status, configuration, and evidence
navigation. The existing Go gateway remains authoritative for policy inspection,
AI discovery, alerts, and audit data. AgentRange remains Docker-based and is
attached through the existing non-invasive adapter.

## Privilege model

| Component | Default privilege | Responsibility |
| --- | --- | --- |
| React webview | standard user | display and operator input only |
| Tauri host | standard user | typed IPC, fixed executable orchestration, loopback API client |
| Go gateway | standard user | policy, discovery, hooks, audit and evidence |
| Windows process guard service | LocalSystem/admin service | process-create subscription and approved termination |

The Tauri host never accepts a raw shell command from the UI. Every operation is
a typed command with fixed executable and argument templates. The elevated
service accepts only versioned policy objects and process actions tied to an
event it observed itself.

## Agent command enforcement

### Hook path (preferred)

Supported Agent connectors send the tool name and command to
`/api/v1/inspect/tool`. The gateway evaluates policy before execution and returns
allow, alert, or block. This path can inspect arguments without collecting a
system-wide command-line history.

### Windows process guard path (fallback)

The service consumes process-create events, normalizes the child executable
basename, and walks PPID ancestry against the current Agent inventory. A rule is
eligible only when all of these checks succeed:

1. The policy and exact-basename rule are enabled.
2. The child belongs to a known Agent process tree.
3. PID plus creation time still match the observed process identity.
4. The Agent root is not Windows-protected or on an internal safety allowlist.

In observe mode the service writes an audit event only. In enforce mode it first
requests graceful termination, waits the configured grace period, and then
terminates the Agent job/process tree. Failure to open a protected process is an
audited, non-fatal outcome.

Exact executable matching is the v1 rule boundary. Argument substring/regex
matching would require explicit command-line collection, redaction, retention,
and consent controls and is therefore not silently enabled.

## Release boundary

The repeatable release pipeline must eventually produce:

- `TraceBastion-Desktop-Setup-x64.exe`
- a signed `TraceBastion Desktop.exe`
- a signed Go gateway sidecar
- the elevated process guard service
- an offline WebView2 bootstrap strategy
- a version manifest and checksums

Clean-machine acceptance requires Windows 10/11 x64 without Go, Python, Node,
or Rust installed. Docker Desktop remains an explicit prerequisite only for the
AgentRange feature.
