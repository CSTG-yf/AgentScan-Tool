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
            commands::agents::get_agents,
            commands::agents::get_agent_detail,
            commands::agents::export_agents_report_pdf,
            commands::agent_governance::agent_governance_get,
            commands::agent_governance::agent_governance_post,
            commands::agent_governance::agent_governance_patch,
            commands::agent_governance::agent_governance_put,
            commands::agent_governance::agent_governance_delete,
            commands::knowledge::get_agent_runtime_catalog,
            commands::audit::get_process_guard_audit,
            commands::trace::get_agent_trace,
            commands::audit::get_gateway_audit,
            commands::events::get_runtime_security_summary,
            commands::events::get_runtime_security_agents,
            commands::events::get_runtime_detections,
            commands::events::get_runtime_detection_detail,
            commands::events::get_runtime_detection_events,
            commands::events::get_runtime_events_timeline,
            commands::attack_chains::get_attack_chains,
            commands::runtime_decisions::get_runtime_decisions,
            commands::runtime_decisions::get_runtime_decision_detail,
            commands::runtime_decisions::get_runtime_security_mode,
            commands::runtime_decisions::set_runtime_security_mode,
            commands::runtime_decisions::block_runtime_detection,
            commands::runtime_decisions::enforce_runtime_decision,
            commands::runtime_decisions::get_runtime_enforcements,
            commands::runtime_decisions::get_runtime_enforcement,
            commands::runtime_decisions::delete_runtime_enforcement,
            commands::policy::get_guard_policy,
            commands::policy::save_guard_policy,
            commands::settings::get_scan_schedule_settings,
            commands::settings::save_scan_schedule_settings,
            commands::settings::get_static_resource_scan_settings,
            commands::settings::save_static_resource_scan_settings,
            commands::static_assets::get_static_resource_agents,
            commands::static_assets::get_static_resource_summary,
            commands::static_assets::get_static_resources,
            commands::static_assets::get_static_resource_detail,
            commands::static_assets::get_static_resource_findings,
            commands::static_assets::get_static_resource_content,
            commands::static_assets::get_static_resource_relations,
            commands::static_assets::trigger_static_resource_scan,
            commands::static_assets::trigger_static_resource_rescan,
            commands::static_assets::get_static_resource_scans,
            commands::static_assets::update_static_resource_status,
            commands::static_assets::reveal_static_resource_path,
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
