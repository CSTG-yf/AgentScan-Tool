//! Tauri commands for the desktop-level gateway preferences.
//!
//! Kept separate from `commands::settings` (which proxies scan scheduling to
//! the Gateway) because these values live in the desktop's own settings file
//! and are read by the Rust close/exit handlers, not by the Go Gateway.

use crate::commands::tray;
use crate::desktop_settings::{self, GatewayDesktopSettings};

#[tauri::command]
pub fn get_gateway_settings(app: tauri::AppHandle) -> GatewayDesktopSettings {
    desktop_settings::read_gateway_settings(&app)
}

#[tauri::command]
pub fn set_gateway_settings(
    app: tauri::AppHandle,
    settings: GatewayDesktopSettings,
) -> Result<GatewayDesktopSettings, String> {
    // The tray icon is the only way back to a hidden window and the only way to
    // stop a daemon that outlives the desktop, so it is *created* (or shown)
    // before the preference is stored: a stored "true" whose icon never made it
    // into the notification area would hide the window on the next close with
    // no way to bring it back, which is exactly the dead end §5.3 warns about.
    // `set_enabled` reports the real error instead of assuming the icon exists.
    tray::set_enabled(&app, settings.keep_running_on_close)?;

    desktop_settings::write_gateway_settings(&app, &settings)?;
    Ok(desktop_settings::read_gateway_settings(&app))
}
