use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::windows_process::ProcessInfo;

fn clock_ticks_per_second() -> u64 {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks > 0 {
        ticks as u64
    } else {
        100
    }
}

fn boot_time_seconds() -> Option<u64> {
    fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

fn parse_stat(raw: &str) -> Option<(u32, String, u32, u64)> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    let pid = raw[..open].trim().parse().ok()?;
    let name = raw[open + 1..close].to_owned();
    let fields = raw[close + 1..].split_whitespace().collect::<Vec<_>>();
    // fields[0] is state (field 3), fields[1] is PPID (field 4), and
    // fields[19] is starttime (field 22), measured in clock ticks after boot.
    let ppid = fields.get(1)?.parse().ok()?;
    let start_ticks = fields.get(19)?.parse().ok()?;
    Some((pid, name, ppid, start_ticks))
}

fn read_process(
    path: &Path,
    boot_time: u64,
    ticks_per_second: u64,
    now: u64,
) -> Option<ProcessInfo> {
    let raw = fs::read_to_string(path.join("stat")).ok()?;
    let (pid, stat_name, ppid, creation_ticks) = parse_stat(&raw)?;
    let name = fs::read_to_string(path.join("comm"))
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or(stat_name);
    let started_epoch = boot_time.saturating_add(creation_ticks / ticks_per_second);
    let started_at =
        chrono::DateTime::from_timestamp(started_epoch as i64, 0).map(|value| value.to_rfc3339());
    Some(ProcessInfo {
        pid,
        ppid,
        name,
        creation_ticks,
        started_at,
        uptime_sec: now.saturating_sub(started_epoch),
    })
}

pub fn snapshot() -> Result<Vec<ProcessInfo>, String> {
    let boot_time =
        boot_time_seconds().ok_or_else(|| "read Linux boot time from /proc/stat".to_owned())?;
    let ticks_per_second = clock_ticks_per_second();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("read system clock: {error}"))?
        .as_secs();
    let entries = fs::read_dir("/proc").map_err(|error| format!("read /proc: {error}"))?;
    let mut processes = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        })
        .filter_map(|entry| read_process(&entry.path(), boot_time, ticks_per_second, now))
        .collect::<Vec<_>>();
    processes.sort_by_key(|process| process.pid);
    Ok(processes)
}

pub fn terminate_verified(pid: u32, expected_creation_ticks: u64) -> Result<(), String> {
    let current = snapshot()?
        .into_iter()
        .find(|process| process.pid == pid)
        .ok_or_else(|| format!("process {pid} already exited"))?;
    if expected_creation_ticks == 0 || current.creation_ticks != expected_creation_ticks {
        return Err(format!("process identity changed for PID {pid}"));
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "SIGTERM({pid}) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_stat, snapshot};

    #[test]
    fn parses_proc_stat_with_spaces_and_parentheses_in_name() {
        let mut fields = vec!["S", "7"];
        fields.extend(std::iter::repeat_n("0", 17));
        fields.extend(["12345", "0", "0"]);
        let raw = format!("42 (agent (worker)) {}", fields.join(" "));
        let parsed = parse_stat(&raw).unwrap();
        assert_eq!(
            (parsed.0, parsed.1.as_str(), parsed.2, parsed.3),
            (42, "agent (worker)", 7, 12345)
        );
    }

    #[test]
    fn snapshot_contains_current_process() {
        let processes = snapshot().unwrap();
        assert!(processes
            .iter()
            .any(|process| process.pid == std::process::id()));
    }
}
