//! Best-effort ownership checks for the bundled Go Gateway daemon.
//!
//! The desktop app launches `defenseclaw-gateway` as a *detached* daemon
//! (see `internal/daemon/proc_windows.go`), so the daemon deliberately
//! outlives the process that started it. That is what keeps hooks alive
//! across desktop restarts, but it also means a daemon from an earlier
//! session — or one started by hand from a *different* DefenseClaw home —
//! can still be listening on the desktop API port.
//!
//! Before the desktop silently reuses "an already healthy daemon" it must
//! know whether that daemon is really its own. The authoritative record is
//! the daemon's own PID file (`<home>/gateway.pid`, written by
//! `internal/daemon`), which carries the executable path and a per-process
//! start identity. Everything here is best-effort: a "no" answer must never
//! delete state or kill a process, it only lets the caller report the
//! conflict instead of taking over someone else's daemon.

use std::path::Path;

use serde::Deserialize;

#[cfg(windows)]
use std::os::windows::process::CommandExt;
#[cfg(windows)]
use std::process::Command;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Mirrors the `pidInfo` JSON written by `internal/daemon/daemon.go`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct GatewayPidInfo {
    #[serde(default)]
    pub(crate) pid: u32,
    #[serde(default)]
    pub(crate) executable: String,
    #[serde(default)]
    pub(crate) start_identity: String,
}

/// Reads and parses `<home>/gateway.pid`.
///
/// A missing file is a normal "nothing to own" state and yields `None`; a
/// malformed file also yields `None` because we cannot attribute the daemon
/// to this home, which is exactly what the caller needs to know. Older
/// daemons may have written a bare PID number, which is tolerated for
/// liveness checks but cannot prove ownership (no executable/identity).
pub(crate) fn read_pid_info(home: &Path) -> Option<GatewayPidInfo> {
    let raw = std::fs::read_to_string(home.join("gateway.pid")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(info) = serde_json::from_str::<GatewayPidInfo>(trimmed) {
        return (info.pid > 0).then_some(info);
    }
    trimmed
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0)
        .map(|pid| GatewayPidInfo {
            pid,
            ..GatewayPidInfo::default()
        })
}

/// File names the bundled gateway can have; `commands::lifecycle::gateway_binary`
/// resolves the sidecar under exactly these names.
const GATEWAY_BINARY_NAMES: &[&str] = &["defenseclaw-gateway.exe", "defenseclaw-gateway"];

/// True when the recorded executable is a gateway binary.
///
/// The PID file records `os.Executable()` of the *daemon*, which is the
/// bundled sidecar path (under the app's resources directory or, on Linux,
/// the app data directory) — **not** a path inside the DefenseClaw home. So
/// "is the executable under `home`" is the wrong question and would reject
/// every genuine daemon; what is worth checking is that the recorded binary
/// is still a gateway rather than an unrelated process that reused the PID.
///
/// What actually ties a daemon to this home is the PID file's *location*: the
/// daemon derives it from `DEFENSECLAW_HOME` (`internal/daemon/daemon.go`,
/// `pidFile: filepath.Join(dataDir, PIDFileName)`), so a parseable PID file
/// under the desktop home can only have been written by a daemon that was
/// started for that home.
pub(crate) fn executable_looks_like_gateway(executable: &str) -> bool {
    let trimmed = executable.trim();
    if trimmed.is_empty() {
        return false;
    }
    let name = Path::new(trimmed)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    GATEWAY_BINARY_NAMES
        .iter()
        .any(|candidate| name == candidate.to_ascii_lowercase())
}

/// Returns true only when the daemon recorded in `<home>/gateway.pid` is
/// provably this desktop's own.
///
/// Ownership needs all three of:
///
/// 1. a parseable PID file **in this home** (that is what binds the daemon to
///    the desktop's config/database — a daemon started for another home writes
///    its PID file there instead);
/// 2. a live process whose start identity still matches, so a reused PID does
///    not make a stale file look alive;
/// 3. a recorded executable that is still a gateway binary.
///
/// A PID file that records no executable (a legacy or hand-written bare PID)
/// fails (3) and is therefore *not* owned: the desktop reports the conflict
/// instead of guessing, which is the conservative direction — a wrong "owned"
/// would stop or adopt someone else's daemon.
pub(crate) fn recorded_daemon_is_owned(home: &Path) -> bool {
    owned_daemon_pid(home).is_some()
}

/// The PID of the daemon this home owns, if any.
///
/// Reads the PID file once so a caller can never see a torn view between "is
/// it ours" and "which PID is it" (for example after a restart replaced the
/// file between the two questions).
pub(crate) fn owned_daemon_pid(home: &Path) -> Option<u32> {
    let info = read_pid_info(home)?;
    if !executable_looks_like_gateway(&info.executable) {
        return None;
    }
    verify_live_recorded_process(&info).then_some(info.pid)
}

/// Liveness check for the recorded daemon, mirroring the daemon's own
/// `verifyProcess` semantics: the PID must still be running (not a zombie
/// kernel object) and, when both sides recorded one, the start identity must
/// still match. A mismatch means the PID was reused by an unrelated process,
/// so the PID file is stale and must not be trusted.
pub(crate) fn verify_live_recorded_process(info: &GatewayPidInfo) -> bool {
    if info.pid == 0 {
        return false;
    }
    let Some(live_identity) = process_start_identity(info.pid) else {
        return false;
    };
    let recorded_identity = info.start_identity.trim();
    if recorded_identity.is_empty() {
        // Older daemons could not always determine a start identity
        // (`internal/daemon`: "not fatal — falling back to
        // executable-only matching"), so a live PID plus the executable name
        // check is the strongest evidence available.
        return true;
    }
    recorded_identity == live_identity
}

/// PID currently holding a `LISTENING` TCP socket on `port`, best-effort.
///
/// Only used to make a conflict report actionable ("PID 1234 is holding
/// 18970"). Parsing `netstat` is locale-independent for the state column
/// because that value comes from the IP Helper API, and the port match is
/// anchored with a leading colon so `:18970` never matches `:189700`.
#[cfg(windows)]
pub(crate) fn port_listener_pid(port: u16) -> Option<u32> {
    let mut command = Command::new("netstat.exe");
    command.args(["-ano", "-p", "TCP"]);
    command.creation_flags(CREATE_NO_WINDOW);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!(":{port}");
    for line in text.lines() {
        let mut columns = line.split_whitespace();
        if columns.next() != Some("TCP") {
            continue;
        }
        let Some(local) = columns.next() else { continue };
        if columns.next().is_none() {
            continue;
        }
        if columns.next() != Some("LISTENING") {
            continue;
        }
        if !local.ends_with(&needle) {
            continue;
        }
        if let Some(pid) = columns.next().and_then(|value| value.parse::<u32>().ok()) {
            return Some(pid);
        }
    }
    None
}

#[cfg(not(windows))]
pub(crate) fn port_listener_pid(_port: u16) -> Option<u32> {
    None
}

/// Opaque per-process identity (process creation time), used to detect a
/// stale PID file. Mirrors `processStartIdentity` in
/// `internal/daemon/proc_windows.go` so both sides agree on "same process":
/// returns `None` when the PID is dead or cannot be queried.
#[cfg(windows)]
pub(crate) fn process_start_identity(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let queried = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user);
        CloseHandle(handle);
        if queried == 0 {
            return None;
        }
        Some(filetime_nanos(&creation).to_string())
    }
}

#[cfg(not(windows))]
pub(crate) fn process_start_identity(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // Unix: `/proc/<pid>` stat start time would be the analogue; the desktop
    // ships for Windows, so fall back to "process is openable" only.
    std::fs::metadata(format!("/proc/{pid}")).ok().map(|_| String::new())
}

/// Whether the PID is still running, using the exit code rather than merely
/// being openable: a terminated process whose kernel object is still
/// referenced stays openable, which the daemon had to work around too.
#[cfg(windows)]
pub(crate) fn process_is_running(pid: u32) -> bool {
    // STILL_ACTIVE, as documented for GetExitCodeProcess. Mirrors
    // internal/daemon/proc_windows.go.
    const STILL_ACTIVE: u32 = 259;
    if pid == 0 {
        return false;
    }
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code: u32 = 0;
        let queried = GetExitCodeProcess(handle, &mut code);
        CloseHandle(handle);
        if queried == 0 {
            // Handle opened but the exit code is unavailable: treat as alive
            // so a transient query failure never drops a live daemon.
            return true;
        }
        code == STILL_ACTIVE
    }
}

#[cfg(not(windows))]
pub(crate) fn process_is_running(pid: u32) -> bool {
    process_start_identity(pid).is_some()
}

/// Combines a 100-ns FILETIME pair into the same decimal nanosecond string
/// the Go side produces, because both sides compare these strings verbatim.
///
/// Mirrors `golang.org/x/sys/windows.Filetime.Nanoseconds()` exactly: rebase
/// the 1601-01-01 tick count onto the Unix epoch *before* scaling by 100. A
/// missing rebase would produce a different number for the same process, so
/// every genuine daemon would look like a PID reuse and neither reuse nor
/// shutdown would ever match.
#[cfg(windows)]
fn filetime_nanos(value: &FILETIME) -> i64 {
    let ticks = ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64;
    // 100-ns intervals between 1601-01-01 and 1970-01-01.
    const EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    ((ticks as i64) - EPOCH_TICKS) * 100
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temporary_home(name: &str) -> std::path::PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "defenseclaw-gateway-ownership-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).expect("create temporary home");
        directory
    }

    #[test]
    fn missing_pid_file_is_not_owned() {
        let home = temporary_home("missing");
        assert!(read_pid_info(&home).is_none());
        assert!(!recorded_daemon_is_owned(&home));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn malformed_pid_file_is_not_owned() {
        let home = temporary_home("malformed");
        fs::write(home.join("gateway.pid"), "{not json").unwrap();
        assert!(read_pid_info(&home).is_none());
        assert!(!recorded_daemon_is_owned(&home));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn legacy_bare_pid_parses_but_proves_no_ownership() {
        let home = temporary_home("legacy");
        fs::write(home.join("gateway.pid"), "4242\n").unwrap();
        let info = read_pid_info(&home).expect("bare pid parses");
        assert_eq!(info.pid, 4242);
        assert!(info.executable.is_empty());
        // No executable recorded: ownership cannot be proven, so the desktop
        // must not claim the daemon as its own.
        assert!(!recorded_daemon_is_owned(&home));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn foreign_binary_name_is_not_owned() {
        // An unrelated process that happens to have reused the recorded PID
        // is rejected by the executable-name sanity check.
        let home = temporary_home("foreign");
        let outside = std::env::temp_dir().join("some-other-home").join("some-other-daemon.exe");
        assert!(!executable_looks_like_gateway(
            &outside.to_string_lossy()
        ));
        assert!(!executable_looks_like_gateway(""));
        assert!(!executable_looks_like_gateway("   "));
        assert!(!executable_looks_like_gateway("defenseclaw-gateway-helper.exe"));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn gateway_binary_names_are_recognized_anywhere_on_disk() {
        // The recorded executable is the bundled sidecar (resources dir, or
        // Linux app-data install dir), i.e. deliberately *not* under the home;
        // only the file name matters here.
        assert!(executable_looks_like_gateway(
            "C:\\Program Files\\TraceBastion\\resources\\defenseclaw-gateway.exe"
        ));
        assert!(executable_looks_like_gateway("defenseclaw-gateway.exe"));
        assert!(executable_looks_like_gateway("/usr/local/bin/defenseclaw-gateway"));
        // Windows paths are case-insensitive in practice.
        assert!(executable_looks_like_gateway(
            "C:\\APPS\\DEFENSECLAW-GATEWAY.EXE"
        ));
    }

    #[test]
    fn live_gateway_in_this_home_is_owned() {
        // The test process itself stands in for the daemon: the PID file is
        // in "our" home, the PID is alive and the recorded executable is a
        // gateway binary, which is the shape of a genuinely desktop-owned
        // daemon.
        let home = temporary_home("owned");
        let info = GatewayPidInfo {
            pid: std::process::id(),
            executable: "C:\\apps\\TraceBastion\\resources\\defenseclaw-gateway.exe".to_owned(),
            start_identity: String::new(),
        };
        fs::write(
            home.join("gateway.pid"),
            serde_json::to_vec(&serde_json::json!({
                "pid": info.pid,
                "executable": info.executable,
                "start_time": 0,
                "start_identity": info.start_identity,
            }))
            .unwrap(),
        )
        .unwrap();
        assert!(recorded_daemon_is_owned(&home));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn same_pid_without_a_gateway_executable_is_not_owned() {
        let home = temporary_home("not-gateway");
        fs::write(
            home.join("gateway.pid"),
            format!(
                r#"{{"pid":{},"executable":"C:\\tools\\notepad.exe","start_identity":""}}"#,
                std::process::id()
            ),
        )
        .unwrap();
        assert!(!recorded_daemon_is_owned(&home));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn start_identity_mismatch_is_not_owned() {
        let info = GatewayPidInfo {
            pid: std::process::id(),
            executable: "defenseclaw-gateway.exe".to_owned(),
            start_identity: "definitely-not-the-live-identity".to_owned(),
        };
        assert!(!verify_live_recorded_process(&info));
    }

    #[test]
    fn live_process_without_recorded_identity_still_counts_as_live() {
        let info = GatewayPidInfo {
            pid: std::process::id(),
            executable: String::new(),
            start_identity: String::new(),
        };
        assert!(verify_live_recorded_process(&info));
    }

    #[test]
    fn dead_pid_is_not_live() {
        let info = GatewayPidInfo {
            pid: 0,
            executable: String::new(),
            start_identity: String::new(),
        };
        assert!(!verify_live_recorded_process(&info));
    }

    /// Verbatim record captured from a live desktop-managed daemon
    /// (`<home>\gateway.pid`), used because the whole feature hinges on
    /// reading the Go writer's format exactly:
    ///
    /// * `executable` is the bundled sidecar under `target\...\resources`, so
    ///   it is **not** inside the home — an earlier revision that required
    ///   that could never recognize its own daemon;
    /// * the extra `start_time` key must not break the parse;
    /// * `start_identity` is a rebased Unix-epoch nanosecond string, not raw
    ///   1601-epoch FILETIME ticks (see the arithmetic test below).
    const LIVE_PID_RECORD: &str = r#"{"pid":15912,"executable":"E:\\project\\competition\\AgentScan-Tool\\desktop\\src-tauri\\target\\debug\\resources\\defenseclaw-gateway.exe","start_time":1790644162,"start_identity":"1790644162471831100"}"#;

    #[test]
    fn live_daemon_record_parses_and_looks_like_a_gateway() {
        let info: GatewayPidInfo =
            serde_json::from_str(LIVE_PID_RECORD).expect("live record parses");
        assert_eq!(info.pid, 15912);
        assert_eq!(info.start_identity, "1790644162471831100");
        assert!(
            executable_looks_like_gateway(&info.executable),
            "the bundled sidecar path must be recognized: {}",
            info.executable
        );
        // The recorded executable lives outside any home by design.
        assert!(info.executable.contains("resources"));
    }

    /// The identity strings are compared verbatim against Go's, so the epoch
    /// rebase in `filetime_nanos` is load-bearing: without it every genuine
    /// daemon looks like a reused PID and neither reuse nor stop-on-exit ever
    /// matches. Rebuild the live record's instant from raw FILETIME ticks.
    #[cfg(windows)]
    #[test]
    fn filetime_nanos_reproduces_the_live_go_identity() {
        const EPOCH_TICKS: u64 = 116_444_736_000_000_000;
        const LIVE_IDENTITY: &str = "1790644162471831100";
        let unix_nanos: i64 = LIVE_IDENTITY.parse().expect("identity is an i64");
        let ticks = (unix_nanos / 100) as u64 + EPOCH_TICKS;
        let filetime = FILETIME {
            dwLowDateTime: (ticks & 0xFFFF_FFFF) as u32,
            dwHighDateTime: (ticks >> 32) as u32,
        };
        assert_eq!(filetime_nanos(&filetime).to_string(), LIVE_IDENTITY);
        // Guard the specific mistake this test exists for: a missing rebase
        // would report the raw 1601-epoch tick count instead.
        assert_ne!(
            filetime_nanos(&filetime).to_string(),
            (ticks * 100).to_string()
        );
    }
}
