mod commands;
mod desktop_settings;
mod file_activity;
mod gateway_ownership;
mod knowledge;
mod models;
mod platform;
mod policy_defaults;
#[cfg(target_os = "linux")]
mod resource_opener;
pub mod process_guard;
pub mod process_guard_service;
mod trace_store;
#[cfg(target_os = "linux")]
mod wsl_pdf;
#[path = "platform/windows/process.rs"]
mod windows_process;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// `app.handle()` and `window.app_handle()` come from this trait.
use tauri::Manager;

#[cfg(target_os = "linux")]
pub fn run_empty_fuse_daemon(mountpoint: &std::path::Path) -> Result<(), String> {
    platform::linux::empty_fuse::serve(mountpoint)
}

#[cfg(target_os = "linux")]
pub fn run_controlled_agent(
    policy_path: &std::path::Path,
    program: &std::ffi::OsStr,
    arguments: &[std::ffi::OsString],
) -> Result<std::process::ExitStatus, String> {
    platform::linux::controlled_agent::run(policy_path, program, arguments)
}

/// Set while the `ExitRequested` handler waits for the gateway stop, so the
/// `app.exit` it issues afterwards is not read as a fresh exit request (which
/// would try to prevent the exit again, forever).
static EXIT_APPROVED: AtomicBool = AtomicBool::new(false);

/// How long the exit path waits for the gateway stop to finish before exiting
/// anyway. Kept equal to `commands::lifecycle::EXIT_JOIN_TIMEOUT`, which is
/// itself above the helper's own stop timeout so the stop gets to record its
/// outcome.
const EXIT_WAIT: Duration = Duration::from_secs(13);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .manage(commands::jobs::ChangeStreamController::default())
        .setup(|app| {
            commands::tray::initialize(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::evaluations::evaluation_request,
            commands::evaluations::scan_range_assets,
            commands::evaluations::import_bundled_static_evaluation,
            commands::evaluations::import_bundled_runtime_evaluations,
            commands::environment::get_environment_snapshot,
            commands::agents::get_agents,
            commands::agents::get_connector_profiles,
            commands::agents::trigger_agent_scan,
            commands::agents::get_agent_detail,
            commands::agents::export_agents_report_pdf,
            commands::agents::export_page_report_pdf,
            commands::report_export::select_export_directory,
            commands::report_export::export_text_file_to_directory,
            commands::agent_governance::agent_governance_get,
            commands::agent_governance::agent_governance_post,
            commands::agent_governance::agent_governance_patch,
            commands::agent_governance::agent_governance_put,
            commands::agent_governance::agent_governance_delete,
            commands::runtime_detection_settings::runtime_detection_settings_request,
            commands::knowledge::get_agent_runtime_catalog,
            commands::audit::get_process_guard_audit,
            commands::trace::get_agent_trace,
            commands::audit::get_gateway_audit,
            commands::events::get_runtime_security_summary,
            commands::events::get_runtime_detection_agent_type_summaries,
            commands::events::get_runtime_security_agents,
            commands::events::get_runtime_detections,
            commands::events::get_runtime_detection_detail,
            commands::events::get_runtime_detection_events,
            commands::events::get_runtime_events_timeline,
            commands::events::get_runtime_events,
            commands::events::get_runtime_event_detail,
            commands::events::get_runtime_event_summary,
            commands::events::get_runtime_event_agents,
            commands::events::get_runtime_event_facets,
            commands::audit::get_audit_events,
            commands::audit::get_audit_event_detail,
            commands::audit::get_audit_event_summary,
            commands::audit::get_audit_event_agents,
            commands::audit::get_audit_event_facets,
            commands::attack_chains::get_attack_chains,
            commands::attack_chains::get_attack_chain_detail,
            commands::attack_chains::get_attack_chain_agent_type_summaries,
            commands::runtime_decisions::get_runtime_decisions,
            commands::runtime_decisions::get_runtime_decision_detail,
            commands::runtime_decisions::get_runtime_security_mode,
            commands::runtime_decisions::set_runtime_security_mode,
            commands::runtime_decisions::block_runtime_detection,
            commands::runtime_decisions::enforce_runtime_decision,
            commands::runtime_decisions::get_runtime_enforcements,
            commands::runtime_decisions::get_runtime_enforcement,
            commands::runtime_decisions::delete_runtime_enforcement,
            commands::runtime_decisions::rollback_runtime_enforcement,
            commands::policy::get_guard_policy,
            commands::policy::save_guard_policy,
            commands::settings::get_scan_schedule_settings,
            commands::settings::save_scan_schedule_settings,
            commands::settings::get_static_resource_scan_settings,
            commands::settings::save_static_resource_scan_settings,
            commands::settings::get_privacy_settings,
            commands::settings::save_privacy_settings,
            commands::settings::get_notification_settings,
            commands::settings::save_notification_settings,
            commands::settings::get_storage_settings,
            commands::settings::get_version_settings,
            commands::settings::run_diagnostics,
            commands::settings::export_diagnostics,
            commands::static_assets::get_static_resource_agents,
            commands::static_assets::get_static_resource_summary,
            commands::static_assets::get_static_resources,
            commands::static_assets::get_static_resource_detail,
            commands::static_assets::get_static_resource_findings,
            commands::static_assets::get_static_resource_content,
            commands::static_assets::get_static_resource_relations,
            commands::static_assets::trigger_static_resource_scan,
            commands::static_assets::trigger_static_resource_rescan,
            commands::static_assets::get_scan_status,
            commands::static_assets::get_static_resource_scans,
            commands::static_assets::export_static_resource_text_report,
            commands::static_assets::update_static_resource_status,
            commands::static_assets::reveal_static_resource_path,
            commands::guard_service::install_process_guard,
            commands::guard_service::start_process_guard,
            commands::guard_service::stop_process_guard,
            commands::guard_service::apply_process_guard_policy,
            commands::guard_service::uninstall_process_guard,
            commands::lifecycle::ensure_gateway_ready,
            commands::lifecycle::start_gateway,
            commands::lifecycle::stop_gateway,
            commands::lifecycle::get_gateway_exit_state,
            commands::lifecycle::clear_gateway_exit_state,
            commands::gateway_settings::get_gateway_settings,
            commands::gateway_settings::set_gateway_settings,
            commands::range::get_range_status,
            commands::range::set_range_root,
            commands::range::set_range_mode,
            commands::range::start_range,
            commands::range::stop_range,
            commands::range::get_range_replay_status,
            commands::range::start_range_replay,
            commands::range::stop_range_replay,
            commands::static_scan::get_static_scan,
            commands::jobs::create_event_replay_job,
            commands::jobs::create_attack_chain_rebuild_job,
            commands::jobs::get_scan_schedules,
            commands::jobs::update_scan_schedule,
            commands::jobs::create_scan_job,
            commands::jobs::get_scan_jobs,
            commands::jobs::get_scan_job,
            commands::jobs::cancel_scan_job,
            commands::jobs::get_changes,
            commands::jobs::start_change_stream,
            commands::jobs::stop_change_stream,
        ])
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                // Background mode: hide instead of closing. The gateway keeps
                // serving hooks, and the tray icon is both the way back and
                // the way to really quit.
                //
                // A close request that arrives while the window is *already*
                // hidden is not a window close at all (a hidden window cannot
                // be closed by the user), so it is treated as a real exit —
                // that is what makes the tray's "quit and stop" work without
                // a separate flag to keep in sync.
                let background = desktop_settings::read_gateway_settings(window.app_handle())
                    .keep_running_on_close;
                let visible = window.is_visible().unwrap_or(false);
                if background && visible {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        });

    // Built and ran explicitly (instead of `run(context)`) because only the
    // run callback exposes `RunEvent::ExitRequested`, which is where the
    // desktop stops the gateway it started.
    let app = builder
        .build(tauri::generate_context!())
        .expect("failed to build TraceBastion Desktop");

    app.run(move |app_handle, event| {
        // `ExitRequested` is `#[non_exhaustive]`, so the `..` arm is required
        // even though these are currently the only fields.
        if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
            // `Some(code)` means an explicit `app.exit(..)` — the tray's
            // "quit and stop", or the restart path — where teardown was
            // already handled. Only a user-initiated exit (window close or
            // menu Quit) has `code == None` and must stop the gateway here.
            if let commands::lifecycle::ExitRequestDisposition::HandleExit =
                commands::lifecycle::exit_request_disposition(code)
            {
                // Always block this exit: the teardown thread below calls
                // `exit(0)` itself, and that call arrives as `Some(0)`, which
                // this branch ignores. Preventing the exit unconditionally also
                // covers a *second* user-initiated request (a repeated window
                // close, an OS shutdown broadcast) arriving while the first
                // teardown is still running — letting that one through would
                // kill the process before the daemon was stopped.
                api.prevent_exit();
                if EXIT_APPROVED.swap(true, Ordering::SeqCst) {
                    return;
                }
                let app_handle = app_handle.clone();
                std::thread::spawn(move || {
                    let handle = commands::lifecycle::begin_gateway_shutdown(&app_handle);
                    let stopped =
                        commands::lifecycle::finish_gateway_shutdown(handle, EXIT_WAIT);
                    if !stopped {
                        eprintln!(
                            "TraceBastion: gateway shutdown did not confirm within {EXIT_WAIT:?}; \
                             see gateway-exit-state.json in the desktop config directory"
                        );
                    }
                    app_handle.exit(0);
                });
            }
        }
    });
}
