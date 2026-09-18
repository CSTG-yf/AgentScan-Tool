#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub creation_ticks: u64,
    pub started_at: Option<String>,
    pub uptime_sec: u64,
}

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::mem::size_of;

    use chrono::{DateTime, Utc};

    use super::ProcessInfo;

    type Handle = *mut c_void;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const PROCESS_TERMINATE: u32 = 0x0001;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const TOKEN_ADJUST_PRIVILEGES: u32 = 0x0020;
    const TOKEN_QUERY: u32 = 0x0008;
    const SE_PRIVILEGE_ENABLED: u32 = 0x0000_0002;
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
    const MAX_PATH: usize = 260;
    const WINDOWS_TO_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

    #[repr(C)]
    struct ProcessEntry32W {
        size: u32,
        usage: u32,
        process_id: u32,
        default_heap_id: usize,
        module_id: u32,
        thread_count: u32,
        parent_process_id: u32,
        priority_class_base: i32,
        flags: u32,
        exe_file: [u16; MAX_PATH],
    }

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Luid {
        low_part: u32,
        high_part: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct LuidAndAttributes {
        luid: Luid,
        attributes: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct TokenPrivileges {
        privilege_count: u32,
        privileges: [LuidAndAttributes; 1],
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> Handle;
        fn Process32FirstW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: Handle, entry: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(access: u32, inherit_handle: i32, process_id: u32) -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> u32;
        fn SetLastError(code: u32);
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: u32,
            token_handle: *mut Handle,
        ) -> i32;
        fn LookupPrivilegeValueW(system_name: *const u16, name: *const u16, luid: *mut Luid)
            -> i32;
        fn AdjustTokenPrivileges(
            token_handle: Handle,
            disable_all_privileges: i32,
            new_state: *const TokenPrivileges,
            buffer_length: u32,
            previous_state: *mut TokenPrivileges,
            return_length: *mut u32,
        ) -> i32;
    }

    struct OwnedHandle(Handle);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 as isize != -1 {
                // SAFETY: this wrapper exclusively owns a valid Windows handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    fn utf16_name(buffer: &[u16]) -> String {
        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(buffer.len());
        String::from_utf16_lossy(&buffer[..end])
    }

    fn timing(pid: u32) -> (u64, Option<String>, u64) {
        // SAFETY: OpenProcess is called with query-only access and a concrete PID.
        let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if raw.is_null() {
            return (0, None, 0);
        }
        let process = OwnedHandle(raw);
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        // SAFETY: pointers reference initialized FileTime values and the handle
        // stays valid throughout the call.
        let ok =
            unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) };
        if ok == 0 {
            return (0, None, 0);
        }
        let ticks = (u64::from(creation.high) << 32) | u64::from(creation.low);
        if ticks <= WINDOWS_TO_UNIX_EPOCH_100NS {
            return (ticks, None, 0);
        }
        let unix_seconds = (ticks - WINDOWS_TO_UNIX_EPOCH_100NS) / 10_000_000;
        let started_at =
            DateTime::<Utc>::from_timestamp(unix_seconds as i64, 0).map(|value| value.to_rfc3339());
        let uptime_sec = Utc::now().timestamp().saturating_sub(unix_seconds as i64) as u64;
        (ticks, started_at, uptime_sec)
    }

    /// Enables SeDebugPrivilege in the current process token. Administrator or
    /// LocalSystem context is still required; this only activates a privilege
    /// already granted to the token.
    fn enable_privilege(name: &str) -> Result<(), String> {
        let mut raw_token = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a valid pseudo handle and raw_token
        // points to writable storage for the returned token handle.
        let opened = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut raw_token,
            )
        };
        if opened == 0 || raw_token.is_null() {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            return Err(format!("OpenProcessToken failed with Windows error {code}"));
        }
        let token = OwnedHandle(raw_token);

        let privilege_name = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut luid = Luid::default();
        // SAFETY: privilege_name is NUL terminated and luid is writable.
        if unsafe { LookupPrivilegeValueW(std::ptr::null(), privilege_name.as_ptr(), &mut luid) }
            == 0
        {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            return Err(format!(
                "LookupPrivilegeValueW({name}) failed with Windows error {code}"
            ));
        }

        let state = TokenPrivileges {
            privilege_count: 1,
            privileges: [LuidAndAttributes {
                luid,
                attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: token is valid and state has the documented single-entry
        // TOKEN_PRIVILEGES layout. Previous-state output is not requested.
        unsafe { SetLastError(0) };
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &state,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        // AdjustTokenPrivileges can report success while setting
        // ERROR_NOT_ALL_ASSIGNED, so both values must be checked.
        // SAFETY: GetLastError has no preconditions.
        let code = unsafe { GetLastError() };
        if adjusted == 0 {
            return Err(format!(
                "AdjustTokenPrivileges({name}) failed with Windows error {code}"
            ));
        }
        if code == ERROR_NOT_ALL_ASSIGNED {
            return Err(format!("{name} is not assigned to the current token"));
        }
        Ok(())
    }

    pub fn enable_debug_privilege() -> Result<(), String> {
        enable_privilege("SeDebugPrivilege")
    }

    pub fn enable_security_privilege() -> Result<(), String> {
        enable_privilege("SeSecurityPrivilege")
    }

    pub fn snapshot() -> Result<Vec<ProcessInfo>, String> {
        // SAFETY: a system-wide process snapshot does not require a PID.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if raw.is_null() || raw as isize == -1 {
            return Err("CreateToolhelp32Snapshot failed".to_owned());
        }
        let snapshot = OwnedHandle(raw);
        let mut entry = ProcessEntry32W {
            size: size_of::<ProcessEntry32W>() as u32,
            usage: 0,
            process_id: 0,
            default_heap_id: 0,
            module_id: 0,
            thread_count: 0,
            parent_process_id: 0,
            priority_class_base: 0,
            flags: 0,
            exe_file: [0; MAX_PATH],
        };
        // SAFETY: entry is a correctly sized PROCESSENTRY32W buffer.
        let mut has_entry = unsafe { Process32FirstW(snapshot.0, &mut entry) } != 0;
        let mut processes = Vec::new();
        while has_entry {
            let (creation_ticks, started_at, uptime_sec) = timing(entry.process_id);
            processes.push(ProcessInfo {
                pid: entry.process_id,
                ppid: entry.parent_process_id,
                name: utf16_name(&entry.exe_file),
                creation_ticks,
                started_at,
                uptime_sec,
            });
            entry.exe_file.fill(0);
            entry.size = size_of::<ProcessEntry32W>() as u32;
            // SAFETY: the snapshot and output buffer remain valid.
            has_entry = unsafe { Process32NextW(snapshot.0, &mut entry) } != 0;
        }
        Ok(processes)
    }

    pub fn terminate_verified(pid: u32, expected_creation_ticks: u64) -> Result<(), String> {
        let access = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
        // SAFETY: access is limited to query and terminate for the observed PID.
        let raw = unsafe { OpenProcess(access, 0, pid) };
        if raw.is_null() {
            return Err(format!("OpenProcess({pid}) denied"));
        }
        let process = OwnedHandle(raw);
        let mut creation = FileTime::default();
        let mut exit = FileTime::default();
        let mut kernel = FileTime::default();
        let mut user = FileTime::default();
        // SAFETY: pointers and process handle are valid for the duration.
        let timing_ok =
            unsafe { GetProcessTimes(process.0, &mut creation, &mut exit, &mut kernel, &mut user) };
        if timing_ok == 0 {
            return Err(format!("GetProcessTimes({pid}) failed"));
        }
        let actual_ticks = (u64::from(creation.high) << 32) | u64::from(creation.low);
        if expected_creation_ticks == 0 || actual_ticks != expected_creation_ticks {
            return Err(format!("process identity changed for PID {pid}"));
        }
        // SAFETY: identity was checked immediately above and the same handle is used.
        if unsafe { TerminateProcess(process.0, 0xDC01) } == 0 {
            return Err(format!("TerminateProcess({pid}) failed"));
        }
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use super::ProcessInfo;

    #[cfg(target_os = "linux")]
    pub fn snapshot() -> Result<Vec<ProcessInfo>, String> {
        crate::platform::linux::process::snapshot()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn snapshot() -> Result<Vec<ProcessInfo>, String> {
        Ok(Vec::new())
    }

    #[cfg(target_os = "linux")]
    pub fn terminate_verified(pid: u32, expected_creation_ticks: u64) -> Result<(), String> {
        crate::platform::linux::process::terminate_verified(pid, expected_creation_ticks)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn terminate_verified(_pid: u32, _expected_creation_ticks: u64) -> Result<(), String> {
        Err("process termination is not supported on this platform".to_owned())
    }

    pub fn enable_debug_privilege() -> Result<(), String> {
        Err("SeDebugPrivilege is available only on Windows".to_owned())
    }

    pub fn enable_security_privilege() -> Result<(), String> {
        Err("SeSecurityPrivilege is available only on Windows".to_owned())
    }
}

pub use platform::{
    enable_debug_privilege, enable_security_privilege, snapshot, terminate_verified,
};
