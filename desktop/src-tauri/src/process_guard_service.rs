use std::env;
use std::path::{Path, PathBuf};

const SERVICE_NAME: &str = "DefenseClawProcessGuard";
const SERVICE_DISPLAY_NAME: &str = "DefenseClaw Agent Process Guard";
const DEFAULT_POLICY: &str = include_str!("../../contracts/process-guard.default.json");
const SERVICE_MARKER: &str = "process-guard.installed";

pub fn default_paths() -> (PathBuf, PathBuf) {
    let root = env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("DefenseClaw");
    (
        root.join("process-guard.json"),
        root.join("audit").join("process-guard.jsonl"),
    )
}

fn service_marker_path() -> PathBuf {
    let (policy, _) = default_paths();
    policy
        .parent()
        .unwrap_or_else(|| Path::new(r"C:\ProgramData\DefenseClaw"))
        .join(SERVICE_MARKER)
}

pub fn apply_policy(source: &Path) -> Result<(), String> {
    let policy = crate::process_guard::load_and_validate_policy(source)?;
    let (destination, _) = default_paths();
    let parent = destination
        .parent()
        .ok_or_else(|| "system policy path has no parent".to_owned())?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create policy directory {}: {error}", parent.display()))?;
    let raw = serde_json::to_vec_pretty(&policy)
        .map_err(|error| format!("serialize process guard policy: {error}"))?;
    std::fs::write(&destination, raw)
        .map_err(|error| format!("write system policy {}: {error}", destination.display()))
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

    use super::{default_paths, DEFAULT_POLICY, SERVICE_DISPLAY_NAME, SERVICE_NAME};

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

    pub fn install() -> std::result::Result<(), Box<dyn Error>> {
        let (policy_path, audit_path) = default_paths();
        if let Some(parent) = policy_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = audit_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !policy_path.exists() {
            fs::write(&policy_path, DEFAULT_POLICY)?;
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
            "Monitors child processes of known AI Agents and enforces explicit DefenseClaw rules.",
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
        match fs::remove_file(super::service_marker_path()) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Box::new(error)),
        }
        Ok(())
    }
}

#[cfg(windows)]
pub use windows::{dispatch, install, uninstall};

#[cfg(not(windows))]
pub fn dispatch() -> Result<(), String> {
    Err("Windows service mode is available only on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn install() -> Result<(), String> {
    Err("Windows service installation is available only on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn uninstall() -> Result<(), String> {
    Err("Windows service removal is available only on Windows".to_owned())
}
