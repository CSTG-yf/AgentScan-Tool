mod commands;
mod file_activity;
mod knowledge;
mod models;
mod policy_defaults;
pub mod process_guard;
pub mod process_guard_service;
mod trace_store;
mod windows_process;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            commands::environment::get_environment_snapshot,
            commands::agents::get_agent_processes,
            commands::knowledge::get_agent_runtime_catalog,
            commands::audit::get_process_guard_audit,
            commands::trace::get_agent_trace,
            commands::audit::get_gateway_audit,
            commands::policy::get_guard_policy,
            commands::policy::save_guard_policy,
            commands::guard_service::install_process_guard,
            commands::guard_service::apply_process_guard_policy,
            commands::guard_service::uninstall_process_guard,
            commands::lifecycle::start_gateway,
            commands::lifecycle::stop_gateway,
            commands::range::get_range_status,
            commands::range::set_range_root,
            commands::range::set_range_mode,
            commands::range::start_range,
            commands::range::stop_range,
            commands::range::get_range_replay_status,
            commands::range::start_range_replay,
            commands::range::stop_range_replay,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run TraceBastion Desktop");
}
