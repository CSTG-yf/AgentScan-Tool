#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let mode = arguments.next();
    match mode.as_deref().and_then(std::ffi::OsStr::to_str) {
        #[cfg(target_os = "linux")]
        Some("--empty-fuse-daemon") => {
            let Some(mountpoint) = arguments.next() else {
                std::process::exit(2);
            };
            if defenseclaw_desktop_lib::run_empty_fuse_daemon(std::path::Path::new(&mountpoint))
                .is_err()
            {
                std::process::exit(1);
            }
            return;
        }
        #[cfg(target_os = "linux")]
        Some("--run-controlled-agent") => {
            let Some(policy) = arguments.next() else {
                std::process::exit(2);
            };
            let remaining = arguments.collect::<Vec<_>>();
            let Some((program, agent_arguments)) = remaining.split_first() else {
                std::process::exit(2);
            };
            match defenseclaw_desktop_lib::run_controlled_agent(
                std::path::Path::new(&policy),
                program,
                agent_arguments,
            ) {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
        }
        Some("--process-guard-service") => {
            let _ = defenseclaw_desktop_lib::process_guard_service::dispatch();
            return;
        }
        Some("--start-process-guard") => {
            if defenseclaw_desktop_lib::process_guard_service::start().is_err() {
                std::process::exit(1);
            }
            return;
        }
        Some("--stop-process-guard") => {
            if defenseclaw_desktop_lib::process_guard_service::stop().is_err() {
                std::process::exit(1);
            }
            return;
        }
        Some("--install-process-guard") => {
            if defenseclaw_desktop_lib::process_guard_service::install().is_err() {
                std::process::exit(1);
            }
            return;
        }
        Some("--uninstall-process-guard") => {
            if defenseclaw_desktop_lib::process_guard_service::uninstall().is_err() {
                std::process::exit(1);
            }
            return;
        }
        Some("--apply-process-guard-policy") => {
            let Some(path) = arguments.next() else {
                std::process::exit(2);
            };
            if defenseclaw_desktop_lib::process_guard_service::apply_policy(std::path::Path::new(
                &path,
            ))
            .is_err()
            {
                std::process::exit(1);
            }
            return;
        }
        _ => {}
    }
    defenseclaw_desktop_lib::run();
}
