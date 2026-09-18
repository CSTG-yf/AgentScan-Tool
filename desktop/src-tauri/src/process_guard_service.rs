use std::env;
use std::path::{Path, PathBuf};

const SERVICE_NAME: &str = "DefenseClawProcessGuard";
const SERVICE_DISPLAY_NAME: &str = "TraceBastion Agent Process Guard";
const SERVICE_MARKER: &str = "process-guard.installed";

pub fn default_paths() -> (PathBuf, PathBuf) {
    #[cfg(target_os = "linux")]
    let root = PathBuf::from("/etc/defenseclaw");
    #[cfg(target_os = "linux")]
    return (
        root.join("process-guard.json"),
        PathBuf::from("/var/log/defenseclaw/process-guard.jsonl"),
    );
    #[cfg(not(target_os = "linux"))]
    let root = env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("DefenseClaw");
    #[cfg(not(target_os = "linux"))]
    return (
        root.join("process-guard.json"),
        root.join("audit").join("process-guard.jsonl"),
    );
}

fn service_marker_path() -> PathBuf {
    let (policy, _) = default_paths();
    policy
        .parent()
        .unwrap_or_else(|| {
            Path::new(if cfg!(target_os = "linux") {
                "/var/lib/defenseclaw"
            } else {
                r"C:\ProgramData\DefenseClaw"
            })
        })
        .join(SERVICE_MARKER)
}

fn file_audit_manifest_path() -> PathBuf {
    let (policy, _) = default_paths();
    policy
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\ProgramData\DefenseClaw"))
        .join("file-audit-paths.json")
}

pub(crate) fn gateway_client_manifest_path() -> PathBuf {
    let (policy, _) = default_paths();
    policy
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\ProgramData\DefenseClaw"))
        .join("gateway-client.json")
}

pub fn apply_policy(source: &Path) -> Result<(), String> {
    let policy = crate::process_guard::load_and_validate_policy(source)?;
    configure_file_auditing(&policy)?;
    let (destination, _) = default_paths();
    let parent = destination
        .parent()
        .ok_or_else(|| "system policy path has no parent".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create policy directory {}: {error}", parent.display()))?;
    let raw = serde_json::to_vec_pretty(&policy)
        .map_err(|error| format!("serialize process guard policy: {error}"))?;
    std::fs::write(&destination, raw)
        .map_err(|error| format!("write system policy {}: {error}", destination.display()))?;
    let _ = write_gateway_client_manifest(source);
    Ok(())
}

fn write_gateway_client_manifest(policy_source: &Path) -> Result<(), String> {
    let Some(config_dir) = policy_source.parent() else {
        return Ok(());
    };
    let home = config_dir.join("defenseclaw-home");
    let token = read_gateway_token(&home)
        .unwrap_or_else(|| "defenseclaw-desktop-agentrange-token".to_owned());
    let port = read_gateway_port(&home).unwrap_or(18_970);
    let manifest = serde_json::json!({
        "host": "127.0.0.1",
        "port": port,
        "token": token,
    });
    let path = gateway_client_manifest_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            format!(
                "create gateway manifest directory {}: {error}",
                parent.display()
            )
        })?;
    }
    let raw = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| format!("serialize gateway client manifest: {error}"))?;
    std::fs::write(&path, raw)
        .map_err(|error| format!("write gateway client manifest {}: {error}", path.display()))
}

fn read_gateway_token(home: &Path) -> Option<String> {
    let env_text = std::fs::read_to_string(home.join(".env")).ok()?;
    env_text.lines().find_map(|line| {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let (key, value) = line.split_once('=')?;
        if key.trim() != "DEFENSECLAW_GATEWAY_TOKEN" {
            return None;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn read_gateway_port(home: &Path) -> Option<u16> {
    let config_text = std::fs::read_to_string(home.join("config.yaml")).ok()?;
    config_text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "api_port" {
            return None;
        }
        value.trim().parse::<u16>().ok()
    })
}

#[cfg(windows)]
fn configure_file_auditing(policy: &crate::models::GuardPolicy) -> Result<(), String> {
    use std::collections::BTreeSet;
    use std::process::Command;

    let paths = policy
        .file_guard
        .audit_roots
        .iter()
        .chain(
            policy
                .file_guard
                .blacklist
                .iter()
                .filter(|rule| rule.enabled)
                .map(|rule| &rule.path),
        )
        .map(|path| path.trim().to_owned())
        .collect::<BTreeSet<_>>();
    crate::windows_process::enable_security_privilege()?;
    clear_configured_file_auditing()?;
    if paths.is_empty() {
        return Ok(());
    }
    let status = Command::new("auditpol.exe")
        .args([
            "/set",
            "/subcategory:{0CCE921D-69AE-11D9-BED3-505054503030}",
            "/success:enable",
        ])
        .status()
        .map_err(|error| format!("launch auditpol: {error}"))?;
    if !status.success() {
        return Err(format!(
            "auditpol failed with exit code {:?}",
            status.code()
        ));
    }
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$target = $env:DEFENSECLAW_AUDIT_PATH
while (-not (Test-Path -LiteralPath $target)) {
  $parent = Split-Path -Parent $target
  if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $target) { throw 'No existing parent for audit path' }
  $target = $parent
}
$item = Get-Item -LiteralPath $target -Force
$acl = Get-Acl -LiteralPath $target -Audit
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.Security.AccessControl.FileSystemRights]'ReadData,WriteData,AppendData,CreateFiles,CreateDirectories,Delete,DeleteSubdirectoriesAndFiles'
$inheritance = if ($item.PSIsContainer) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $rights, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AuditFlags]::Success)
$exists = $acl.Audit | Where-Object {
  $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $sid -and
  $_.AuditFlags -eq [System.Security.AccessControl.AuditFlags]::Success -and
  $_.FileSystemRights -eq $rights -and
  $_.InheritanceFlags -eq $inheritance -and
  $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
}
if ($null -eq $exists) {
  $acl.AddAuditRule($rule)
  Set-Acl -LiteralPath $target -AclObject $acl
  Write-Output $target
}
"#;
    let mut added_paths = BTreeSet::new();
    for path in paths {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                SCRIPT,
            ])
            .env("DEFENSECLAW_AUDIT_PATH", &path)
            .output()
            .map_err(|error| format!("launch PowerShell SACL configuration: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "configure audit SACL for {path}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let added = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !added.is_empty() {
            added_paths.insert(added);
            let manifest = serde_json::to_vec_pretty(&added_paths)
                .map_err(|error| format!("serialize file audit manifest: {error}"))?;
            std::fs::write(file_audit_manifest_path(), manifest)
                .map_err(|error| format!("write file audit manifest: {error}"))?;
        }
    }
    let manifest = serde_json::to_vec_pretty(&added_paths)
        .map_err(|error| format!("serialize file audit manifest: {error}"))?;
    std::fs::write(file_audit_manifest_path(), manifest)
        .map_err(|error| format!("write file audit manifest: {error}"))?;
    Ok(())
}

#[cfg(windows)]
fn clear_configured_file_auditing() -> Result<(), String> {
    use std::process::Command;

    let manifest_path = file_audit_manifest_path();
    if !manifest_path.is_file() {
        return Ok(());
    }
    crate::windows_process::enable_security_privilege()?;
    let raw = std::fs::read_to_string(&manifest_path)
        .map_err(|error| format!("read file audit manifest: {error}"))?;
    let paths: Vec<String> = serde_json::from_str(&raw)
        .map_err(|error| format!("parse file audit manifest: {error}"))?;
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$target = $env:DEFENSECLAW_AUDIT_PATH
if (-not (Test-Path -LiteralPath $target)) { exit 0 }
$item = Get-Item -LiteralPath $target -Force
$acl = Get-Acl -LiteralPath $target -Audit
$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
$rights = [System.Security.AccessControl.FileSystemRights]'ReadData,WriteData,AppendData,CreateFiles,CreateDirectories,Delete,DeleteSubdirectoriesAndFiles'
$inheritance = if ($item.PSIsContainer) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule($sid, $rights, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AuditFlags]::Success)
$acl.RemoveAuditRuleSpecific($rule)
Set-Acl -LiteralPath $target -AclObject $acl
"#;
    for path in paths {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                SCRIPT,
            ])
            .env("DEFENSECLAW_AUDIT_PATH", &path)
            .output()
            .map_err(|error| format!("launch PowerShell SACL cleanup: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "remove audit SACL from {path}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    match std::fs::remove_file(&manifest_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("remove file audit manifest: {error}")),
    }
}

#[cfg(all(not(windows), not(target_os = "linux")))]
fn configure_file_auditing(_policy: &crate::models::GuardPolicy) -> Result<(), String> {
    Err("Windows file auditing is available only on Windows".to_owned())
}

#[cfg(target_os = "linux")]
fn configure_file_auditing(policy: &crate::models::GuardPolicy) -> Result<(), String> {
    // Process enforcement is fully supported. File access replacement requires
    // the managed Agent proxy; persist the roots for that component and expose
    // the limitation in audit rather than pretending that inotify can replace bytes.
    let manifest = policy
        .file_guard
        .audit_roots
        .iter()
        .chain(
            policy
                .file_guard
                .blacklist
                .iter()
                .filter(|rule| rule.enabled)
                .map(|rule| &rule.path),
        )
        .collect::<Vec<_>>();
    let path = file_audit_manifest_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create Linux file monitor directory: {error}"))?;
    }
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| format!("write Linux file monitor manifest: {error}"))
}

#[cfg(not(windows))]
fn clear_configured_file_auditing() -> Result<(), String> {
    Ok(())
}

#[cfg(windows)]
mod windows {
    use std::env;
    use std::error::Error;
    use std::ffi::OsString;
    use std::fs;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use serde::Deserialize;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, Result};
    use wmi::WMIConnection;

    use super::{default_paths, SERVICE_DISPLAY_NAME, SERVICE_NAME};

    define_windows_service!(ffi_service_main, service_main);

    #[derive(Deserialize)]
    #[serde(rename = "Win32_ProcessStartTrace", rename_all = "PascalCase")]
    struct ProcessStartTrace {
        process_id: u32,
        parent_process_id: u32,
        process_name: String,
    }

    pub fn dispatch() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let _ = run_service();
    }

    fn run_service() -> Result<()> {
        let stopping = Arc::new(AtomicBool::new(false));
        let handler_flag = Arc::clone(&stopping);
        let event_handler = move |event| match event {
            ServiceControl::Stop => {
                handler_flag.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let (policy, audit) = default_paths();
        match crate::windows_process::enable_debug_privilege() {
            Ok(()) => {
                let _ = crate::process_guard::audit_service_event(
                    &audit,
                    "debugPrivilegeEnabled",
                    "SeDebugPrivilege enabled for LocalSystem process enforcement",
                );
            }
            Err(error) => {
                let _ = crate::process_guard::audit_service_event(
                    &audit,
                    "debugPrivilegeUnavailable",
                    &format!("continuing with token-default process access; {error}"),
                );
            }
        }
        let file_policy = policy.clone();
        let file_audit = audit.clone();
        let file_stopping = Arc::clone(&stopping);
        std::thread::spawn(move || {
            if let Err(error) = crate::file_activity::run_until(&file_policy, &file_audit, || {
                file_stopping.load(Ordering::Acquire)
            }) {
                let _ = crate::process_guard::audit_service_event(
                    &file_audit,
                    "fileMonitorFailed",
                    &error,
                );
            }
        });
        let (event_tx, event_rx) =
            mpsc::channel::<std::result::Result<ProcessStartTrace, String>>();
        std::thread::spawn(move || {
            let connection = match WMIConnection::new() {
                Ok(connection) => connection,
                Err(error) => {
                    let _ = event_tx.send(Err(format!("initialize WMI: {error}")));
                    return;
                }
            };
            let events = match connection.notification::<ProcessStartTrace>() {
                Ok(events) => events,
                Err(error) => {
                    let _ = event_tx.send(Err(format!("subscribe process events: {error}")));
                    return;
                }
            };
            for event in events {
                let result = event.map_err(|error| format!("receive process event: {error}"));
                if event_tx.send(result).is_err() {
                    return;
                }
            }
        });

        let mut wmi_failed = false;
        while !stopping.load(Ordering::Acquire) {
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(event)) => {
                    let _ = crate::process_guard::handle_process_start(
                        &policy,
                        &audit,
                        event.process_id,
                        event.parent_process_id,
                        event.process_name,
                    );
                }
                Ok(Err(_)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    wmi_failed = true;
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
        if wmi_failed && !stopping.load(Ordering::Acquire) {
            let _ = crate::process_guard::run_until(&policy, &audit, || {
                stopping.load(Ordering::Acquire)
            });
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }

    pub fn start() -> std::result::Result<(), Box<dyn Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )?;
        if service.query_status()?.current_state == ServiceState::Running {
            return Ok(());
        }
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&str>(&[])?;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = service.query_status()?;
            if status.current_state == ServiceState::Running {
                return Ok(());
            }
            if status.current_state == ServiceState::Stopped || Instant::now() >= deadline {
                return Err(std::io::Error::other(format!(
                    "process guard failed to start: state={:?}, exit={:?}",
                    status.current_state, status.exit_code
                ))
                .into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn stop() -> std::result::Result<(), Box<dyn Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        service.stop()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let status = service.query_status()?;
            if status.current_state == ServiceState::Stopped {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("timed out waiting for process guard service to stop".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn install() -> std::result::Result<(), Box<dyn Error>> {
        let (policy_path, audit_path) = default_paths();
        if let Some(parent) = policy_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = audit_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !policy_path.exists() {
            let default_policy =
                crate::policy_defaults::default_policy_json().map_err(std::io::Error::other)?;
            fs::write(&policy_path, default_policy)?;
        }

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: env::current_exe()?,
            launch_arguments: vec![OsString::from("--process-guard-service")],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let service_access = ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::DELETE;
        let service = match manager.open_service(SERVICE_NAME, service_access) {
            Ok(service) => {
                service.change_config(&service_info)?;
                service
            }
            Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
                manager.create_service(&service_info, service_access)?
            }
            Err(error) => return Err(Box::new(error)),
        };
        service.set_description(
            "Monitors known AI Agent process trees and enforces TraceBastion security rules.",
        )?;
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&str>(&[])?;
        }
        fs::write(super::service_marker_path(), b"1\n")?;
        Ok(())
    }

    pub fn uninstall() -> std::result::Result<(), Box<dyn Error>> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = match manager.open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            Ok(service) => Some(service),
            Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
                None
            }
            Err(error) => return Err(Box::new(error)),
        };
        let service_existed = service.is_some();
        if let Some(service) = service {
            service.delete()?;
            if service.query_status()?.current_state != ServiceState::Stopped {
                service.stop()?;
            }
            drop(service);
        }
        if service_existed {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
                    Err(windows_service::Error::Winapi(error))
                        if error.raw_os_error() == Some(1060) =>
                    {
                        break;
                    }
                    Err(error) => return Err(Box::new(error)),
                    Ok(_) if Instant::now() >= deadline => {
                        return Err("timed out waiting for process guard service deletion".into());
                    }
                    Ok(_) => std::thread::sleep(Duration::from_millis(100)),
                }
            }
        }
        super::clear_configured_file_auditing().map_err(std::io::Error::other)?;
        match fs::remove_file(super::service_marker_path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Box::new(error)),
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use windows::{dispatch, install, start, stop, uninstall};

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    const UNIT_PATH: &str = "/etc/systemd/system/defenseclaw-process-guard.service";

    fn systemctl(args: &[&str]) -> Result<(), String> {
        let status = Command::new("systemctl")
            .args(args)
            .status()
            .map_err(|error| format!("launch systemctl: {error}"))?;
        status
            .success()
            .then_some(())
            .ok_or_else(|| format!("systemctl {} failed with status {status}", args.join(" ")))
    }

    pub fn dispatch() -> Result<(), String> {
        let (policy, audit) = super::default_paths();
        crate::process_guard::run_console(&policy, &audit)
    }

    pub fn start() -> Result<(), String> {
        systemctl(&["start", "defenseclaw-process-guard.service"])
    }
    pub fn stop() -> Result<(), String> {
        systemctl(&["stop", "defenseclaw-process-guard.service"])
    }

    pub fn install() -> Result<(), String> {
        let (policy, audit) = super::default_paths();
        if let Some(parent) = policy.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if let Some(parent) = audit.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if !policy.exists() {
            fs::write(&policy, crate::policy_defaults::default_policy_json()?)
                .map_err(|error| format!("write default policy: {error}"))?;
        }
        let executable = std::env::current_exe().map_err(|error| error.to_string())?;
        let unit = format!("[Unit]\nDescription=TraceBastion Agent Process Guard\nAfter=network.target\n\n[Service]\nType=simple\nExecStart={} --process-guard-service\nRestart=on-failure\nRestartSec=2\nNoNewPrivileges=true\nProtectSystem=strict\nReadWritePaths=/etc/defenseclaw /var/log/defenseclaw /var/lib/defenseclaw\n\n[Install]\nWantedBy=multi-user.target\n", executable.display());
        fs::write(UNIT_PATH, unit).map_err(|error| format!("write systemd unit: {error}"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "defenseclaw-process-guard.service"])?;
        fs::create_dir_all("/var/lib/defenseclaw").map_err(|e| e.to_string())?;
        fs::write(super::service_marker_path(), b"1\n").map_err(|e| e.to_string())
    }

    pub fn uninstall() -> Result<(), String> {
        let _ = systemctl(&["disable", "--now", "defenseclaw-process-guard.service"]);
        match fs::remove_file(UNIT_PATH) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("remove systemd unit: {error}")),
        }
        systemctl(&["daemon-reload"])?;
        let _ = fs::remove_file(super::service_marker_path());
        Ok(())
    }

    pub fn is_installed() -> bool {
        Path::new(UNIT_PATH).is_file()
    }
    pub fn is_running() -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", "defenseclaw-process-guard.service"])
            .status()
            .is_ok_and(|s| s.success())
    }
}

#[cfg(target_os = "linux")]
pub use linux::{dispatch, install, start, stop, uninstall};

#[cfg(target_os = "linux")]
pub fn service_status() -> (bool, bool) {
    (linux::is_installed(), linux::is_running())
}

#[cfg(windows)]
pub fn service_status() -> (bool, bool) {
    use std::process::Command;
    let output = Command::new("sc.exe")
        .args(["query", SERVICE_NAME])
        .output()
        .ok();
    let installed = output.as_ref().is_some_and(|o| o.status.success());
    let running = output
        .as_ref()
        .is_some_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"));
    (installed, running)
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn start() -> Result<(), String> {
    Err("Windows service startup is available only on Windows".to_owned())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn stop() -> Result<(), String> {
    Err("Windows service stop is available only on Windows".to_owned())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn dispatch() -> Result<(), String> {
    Err("Windows service mode is available only on Windows".to_owned())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn install() -> Result<(), String> {
    Err("Windows service installation is available only on Windows".to_owned())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn uninstall() -> Result<(), String> {
    Err("Windows service removal is available only on Windows".to_owned())
}

#[cfg(all(not(windows), not(target_os = "linux")))]
pub fn service_status() -> (bool, bool) {
    (false, false)
}
