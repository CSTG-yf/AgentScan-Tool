//! Tray icon that keeps a gateway-running desktop reachable.
//!
//! The desktop offers a "keep the gateway running after the window closes"
//! preference (`desktop_settings::GatewayDesktopSettings`). §5.3 of the
//! competition landing plan allows that option only if the user can still
//! control the surviving gateway, so the option comes with this tray icon:
//!
//! * **打开主界面** — shows and focuses the hidden main window.
//! * **退出并停止网关** — stops the desktop-managed gateway and exits.
//!
//! The icon is created **once**, either at startup (preference already on) or
//! when the settings toggle turns the preference on, and nothing here retries,
//! deletes or rebuilds it afterwards. An earlier version did retry with
//! `NIM_ADD`/`NIM_DELETE` and a rebuilt window; on the machine where that was
//! tried (2026-09-29) the notification area answered every `Shell_NotifyIcon`
//! call with `ERROR_ACCESS_DENIED` — for this app *and* for an unrelated Tauri
//! app, in the same session and at the same integrity level — so the retries
//! could not work and only churned the shell's state. The measurements and the
//! traps that made three earlier conclusions wrong are written down in
//! `docs/cn_docs/优化点/08-关闭桌面端后网关仍在后台运行.md` §6.6: if a tray
//! problem has to be diagnosed again, read that first.

use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent, TrayIconId};
use tauri::{AppHandle, Manager};

use crate::commands::lifecycle;
use crate::desktop_settings;

/// Stable identifier so `set_gateway_settings` can flip tray visibility
/// without holding a handle in application state.
pub(crate) const TRAY_ID: &str = "tracebastion-gateway-tray";
const MENU_OPEN: &str = "tracebastion-tray-open";
const MENU_QUIT: &str = "tracebastion-tray-quit";
const MAIN_WINDOW_LABEL: &str = "main";
const TOOLTIP: &str = "TraceBastion Desktop · 网关仍在后台运行";
const TRAY_LOG_FILE: &str = "tray.log";

/// Creates the tray icon when the preference is already on.
///
/// Called from the Tauri `setup` hook. A machine whose notification area refuses
/// the icon must not stop the security console from starting, so a failure is
/// reported (console + `tray.log`) and the app carries on.
pub(crate) fn initialize(app: &AppHandle) {
    if !desktop_settings::read_gateway_settings(app).keep_running_on_close {
        return;
    }
    if let Err(error) = build_tray(app) {
        report_tray_failure(app, &error);
    }
}

/// Shows the tray icon, creating it the first time it is needed.
///
/// Errors are *returned*, not only logged: the icon is the only way back to a
/// hidden window and the only way to stop a surviving daemon, so
/// `set_gateway_settings` must refuse to store "keep running after close" when
/// the icon could not be created.
pub(crate) fn set_enabled(app: &AppHandle, enabled: bool) -> Result<(), String> {
    let existing = app.tray_by_id(&TrayIconId::new(TRAY_ID));
    if !enabled {
        if let Some(tray) = existing {
            let _ = tray.set_visible(false);
        }
        return Ok(());
    }
    match existing {
        Some(tray) => tray
            .set_visible(true)
            .map_err(|error| tray_failure(app, "显示托盘图标失败", error)),
        None => build_tray(app),
    }
}

/// Builds the tray icon (menu, icon image, handlers) and leaves it visible.
///
/// `Ok` only means the icon was registered with Tauri. The tray backend
/// discards `Shell_NotifyIcon`'s return value, so a shell that refuses the icon
/// looks exactly like a success from here — which is why the tray is created
/// once and nothing polls it (see the module docs).
fn build_tray(app: &AppHandle) -> Result<(), String> {
    // `MenuId` compares against `&str` directly (`impl PartialEq<&str> for
    // &MenuId` in muda), so the handlers below need no parsing.
    let open_item = MenuItem::with_id(app, MENU_OPEN, "打开主界面", true, None::<&str>)
        .map_err(|error| tray_failure(app, "创建托盘菜单项失败", error))?;
    let separator = PredefinedMenuItem::separator(app)
        .map_err(|error| tray_failure(app, "创建托盘分隔线失败", error))?;
    let quit_item = MenuItem::with_id(app, MENU_QUIT, "退出并停止网关", true, None::<&str>)
        .map_err(|error| tray_failure(app, "创建托盘菜单项失败", error))?;
    let menu = Menu::with_items(app, &[&open_item, &separator, &quit_item])
        .map_err(|error| tray_failure(app, "创建托盘菜单失败", error))?;
    let icon = tauri::image::Image::from_bytes(include_bytes!("../../icons/32x32.png"))
        .map_err(|error| tray_failure(app, "解码托盘图标失败", error))?;

    TrayIconBuilder::with_id(TRAY_ID.to_string())
        .icon(icon)
        .tooltip(TOOLTIP)
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(move |tray_app, event| {
            let id = event.id();
            if id == MENU_OPEN {
                show_main_window(tray_app);
            } else if id == MENU_QUIT {
                quit_and_stop_gateway(tray_app);
            }
        })
        .on_tray_icon_event(|tray, event| {
            // Left-click is the conventional "bring the window back".
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)
        .map_err(|error| tray_failure(app, "创建托盘图标失败", error))?;
    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Tray "退出并停止网关": stop first, then exit with an explicit code so the
/// `ExitRequested` handler knows the teardown already happened and does not
/// repeat it.
///
/// The stop runs off the event-loop thread: the helper can take seconds to
/// terminate the daemon, and blocking the main thread would freeze the tray and
/// any window still on screen while it happens.
fn quit_and_stop_gateway(app: &AppHandle) {
    let app_handle = app.clone();
    std::thread::spawn(move || {
        let handle = lifecycle::begin_gateway_shutdown(&app_handle);
        let stopped = lifecycle::finish_gateway_shutdown(handle, lifecycle::EXIT_JOIN_TIMEOUT);
        if !stopped {
            report_tray_failure(
                &app_handle,
                "退出前未能确认 Gateway 已停止，详情见 gateway-exit-state.json",
            );
        }
        app_handle.exit(0);
    });
}

/// Formats a tray failure, reports it and hands it back to the caller so the
/// same text can also reach the settings UI.
fn tray_failure(app: &AppHandle, context: &str, error: impl std::fmt::Display) -> String {
    let message = format!("{context}：{error}");
    report_tray_failure(app, &message);
    message
}

/// Reports a tray problem to the console and to the tray diagnostic log.
fn report_tray_failure(app: &AppHandle, message: &str) {
    eprintln!("TraceBastion tray: {message}");
    append_tray_log(app, message);
}

/// Appends one failure line to `tray.log` next to `desktop-settings.json`.
///
/// Only **failures** are recorded. A packaged build has no console, and the tray
/// backend reports success even when the shell refused the icon, so the absence
/// of a line does *not* mean the icon is on screen — it only means nothing was
/// reported. Diagnosing "icon missing" from here needs the main-thread Win32
/// error codes described in `docs/cn_docs/优化点/08-*.md` §6.6; do not add that
/// back casually, and never read an error code on a thread that just wrote this
/// file (`CreateFileW(OPEN_ALWAYS)` leaves `ERROR_ALREADY_EXISTS` in the
/// caller's last-error slot even when it succeeds).
fn append_tray_log(app: &AppHandle, message: &str) {
    let Ok(settings) = desktop_settings::settings_path(app) else {
        return;
    };
    let Some(directory) = settings.parent() else {
        return;
    };
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let line = format!("[{seconds}] {message}\n");

    let _ = std::fs::create_dir_all(directory);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join(TRAY_LOG_FILE))
    {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
    }
}
