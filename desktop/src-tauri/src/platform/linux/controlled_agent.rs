use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

fn os_error(operation: &str) -> String {
    format!("{operation}: {}", std::io::Error::last_os_error())
}

fn write_id_maps(uid: u32, gid: u32) -> Result<(), String> {
    match fs::write("/proc/self/setgroups", "deny\n") {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("disable namespace setgroups: {error}")),
    }
    fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
        .map_err(|error| format!("configure namespace uid map: {error}"))?;
    fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
        .map_err(|error| format!("configure namespace gid map: {error}"))
}

fn enter_private_namespace() -> Result<(), String> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) } != 0 {
        return Err(os_error("create user and mount namespaces"));
    }
    write_id_maps(uid, gid)?;
    let root = CString::new("/").unwrap();
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(os_error("make mount propagation private"));
    }
    Ok(())
}

fn bind_mount(source: &Path, target: &Path) -> Result<(), String> {
    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| "FUSE source path contains a NUL byte".to_owned())?;
    let target_text = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| "protected path contains a NUL byte".to_owned())?;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target_text.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(os_error(&format!(
            "bind empty FUSE file over {}",
            target.display()
        )));
    }
    Ok(())
}

fn protected_files(policy_path: &Path) -> Result<Vec<PathBuf>, String> {
    let policy = crate::process_guard::load_and_validate_policy(policy_path)?;
    if !policy.file_guard.enabled {
        return Ok(Vec::new());
    }
    let mut paths = Vec::new();
    for rule in policy.file_guard.blacklist.iter().filter(|rule| {
        rule.enabled
            && rule.action == "returnEmptyContent"
            && rule
                .access
                .iter()
                .any(|access| matches!(access.as_str(), "read" | "any"))
    }) {
        let path = PathBuf::from(&rule.path);
        if rule.match_kind == "exact" {
            if path.is_file() {
                paths.push(path);
            }
            continue;
        }
        if rule.match_kind == "subtree" && path.is_dir() {
            collect_regular_files(&path, &mut paths)?;
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn collect_regular_files(directory: &Path, output: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "enumerate protected directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("read protected directory entry: {error}"))?;
        let file_type = entry.file_type().map_err(|error| {
            format!("inspect protected path {}: {error}", entry.path().display())
        })?;
        if file_type.is_dir() {
            collect_regular_files(&entry.path(), output)?;
        } else if file_type.is_file() {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn wait_for_fuse(empty_file: &Path, child: &mut Child) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if empty_file.is_file() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("inspect FUSE daemon status: {error}"))?
        {
            return Err(format!("empty-file FUSE daemon exited early: {status}"));
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err("timed out waiting for empty-file FUSE mount".to_owned())
}

fn cleanup(runtime: &Path, fuse: &mut Child) {
    let mountpoint = runtime.join("fuse");
    if let Ok(path) = CString::new(mountpoint.as_os_str().as_bytes()) {
        unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
    }
    let _ = fuse.kill();
    let _ = fuse.wait();
    let _ = fs::remove_dir_all(runtime);
}

pub fn run(
    policy_path: &Path,
    program: &OsStr,
    arguments: &[OsString],
) -> Result<ExitStatus, String> {
    let paths = protected_files(policy_path)?;
    enter_private_namespace()?;

    let runtime = std::env::temp_dir().join(format!(
        "tracebastion-agent-{}-{}",
        unsafe { libc::getuid() },
        std::process::id()
    ));
    let mountpoint = runtime.join("fuse");
    fs::create_dir_all(&mountpoint)
        .map_err(|error| format!("create controlled Agent runtime: {error}"))?;

    let executable =
        std::env::current_exe().map_err(|error| format!("resolve launcher: {error}"))?;
    let mut fuse = Command::new(executable)
        .arg("--empty-fuse-daemon")
        .arg(&mountpoint)
        .spawn()
        .map_err(|error| format!("start empty-file FUSE daemon: {error}"))?;
    let empty_file = mountpoint.join("empty");
    if let Err(error) = wait_for_fuse(&empty_file, &mut fuse) {
        cleanup(&runtime, &mut fuse);
        return Err(error);
    }

    for path in &paths {
        if let Err(error) = bind_mount(&empty_file, path) {
            cleanup(&runtime, &mut fuse);
            return Err(error);
        }
    }

    let status = Command::new(program)
        .args(arguments)
        .env("TRACEBASTION_CONTROLLED", "1")
        .env("TRACEBASTION_FILE_GUARD", "fuse-namespace")
        .status()
        .map_err(|error| {
            format!(
                "start controlled Agent {}: {error}",
                program.to_string_lossy()
            )
        });
    cleanup(&runtime, &mut fuse);
    status
}
