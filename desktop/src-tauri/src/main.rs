#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    let mut arguments = std::env::args().skip(1);
    match arguments.next().as_deref() {
        Some("--process-guard-service") => {
            let _ = defenseclaw_desktop_lib::process_guard_service::dispatch();
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
