//! Desktop-level gateway/window preferences that the *Rust* side must be
//! able to read on its own.
//!
//! The frontend already keeps a few preferences in `localStorage`
//! (`tracebastion.gatewayStartup`), which is fine for UI-only state. The
//! "keep the gateway running after the window closes" choice is different:
//! the close handler and the exit handler in `lib.rs` have to make their
//! decision while no webview is running, so it must live in a file the
//! backend owns.
//!
//! The file is the existing `desktop-settings.json` in the app config
//! directory, shared with the AgentRange settings written by
//! `commands::range`; unknown fields are preserved with `serde(flatten)` so
//! those writers never clobber these values (and vice versa).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Manager;

/// Name of the settings file inside the app config directory.
const DESKTOP_SETTINGS_FILE: &str = "desktop-settings.json";

/// Default for "keep running in the background". Off by default: the
/// documented requirement is "stop the gateway on exit *or* explicitly offer
/// a keep-running option", and a silently surviving listener is the bug this
/// setting exists to make a choice instead of an accident.
pub(crate) const DEFAULT_KEEP_RUNNING_ON_CLOSE: bool = false;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub(crate) struct GatewayDesktopSettings {
    /// When true, closing the window hides it to the tray and the gateway
    /// keeps serving hooks. When false, closing the window stops the gateway
    /// and exits.
    pub(crate) keep_running_on_close: bool,
}

impl Default for GatewayDesktopSettings {
    fn default() -> Self {
        Self {
            keep_running_on_close: DEFAULT_KEEP_RUNNING_ON_CLOSE,
        }
    }
}

/// Everything `desktop-settings.json` currently holds. Untouched keys are
/// round-tripped as-is so writing this setting cannot drop another writer's
/// fields (`agentrangeRoot`, `rangeMode`, ...).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
struct DesktopSettingsDocument {
    #[serde(flatten)]
    other: BTreeMap<String, serde_json::Value>,
    gateway: Option<GatewayDesktopSettings>,
}

pub(crate) fn settings_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|directory| directory.join(DESKTOP_SETTINGS_FILE))
        .map_err(|error| format!("resolve desktop settings path: {error}"))
}

fn read_document(app: &tauri::AppHandle) -> DesktopSettingsDocument {
    let Ok(path) = settings_path(app) else {
        return DesktopSettingsDocument::default();
    };
    let Ok(raw) = fs::read_to_string(path) else {
        return DesktopSettingsDocument::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

/// Reads the persisted gateway preference, falling back to the default when
/// the file is missing, unreadable or simply predates the setting.
pub(crate) fn read_gateway_settings(app: &tauri::AppHandle) -> GatewayDesktopSettings {
    read_document(app).gateway.unwrap_or_default()
}

/// Persists the gateway preference while leaving other keys intact.
pub(crate) fn write_gateway_settings(
    app: &tauri::AppHandle,
    settings: &GatewayDesktopSettings,
) -> Result<(), String> {
    let path = settings_path(app)?;
    let mut document = read_document(app);
    document.gateway = Some(settings.clone());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let serialized =
        serde_json::to_vec_pretty(&document).map_err(|error| format!("encode settings: {error}"))?;
    fs::write(&path, serialized).map_err(|error| format!("write {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_keeps_the_gateway_stoppable() {
        assert!(!DEFAULT_KEEP_RUNNING_ON_CLOSE);
        let settings = GatewayDesktopSettings::default();
        assert!(!settings.keep_running_on_close);
    }

    #[test]
    fn gateway_settings_round_trip_camel_case() {
        let raw = r#"{"gateway":{"keepRunningOnClose":true}}"#;
        let document: DesktopSettingsDocument = serde_json::from_str(raw).unwrap();
        let gateway = document.gateway.expect("gateway block parses");
        assert!(gateway.keep_running_on_close);
    }

    #[test]
    fn unknown_keys_survive_a_settings_write() {
        // This is the regression that matters: the AgentRange writers own
        // other keys in the same file and must not lose them when the
        // gateway preference is saved.
        let raw = r#"{"agentrangeRoot":"C:\\range","rangeMode":"observe"}"#;
        let mut document: DesktopSettingsDocument = serde_json::from_str(raw).unwrap();
        document.gateway = Some(GatewayDesktopSettings {
            keep_running_on_close: true,
        });
        let encoded = serde_json::to_string(&document).unwrap();
        assert!(encoded.contains("agentrangeRoot"));
        assert!(encoded.contains("C:\\\\range") || encoded.contains(r"C:\\range"));
        assert!(encoded.contains("rangeMode"));
        assert!(encoded.contains("keepRunningOnClose"));
    }

    #[test]
    fn missing_gateway_block_reads_as_default() {
        let document: DesktopSettingsDocument = serde_json::from_str("{}").unwrap();
        assert!(document.gateway.is_none());
    }
}
