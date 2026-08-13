use std::process::Command;
use std::thread;
use std::time::Duration;

fn main() {
    // Give the service time to observe this parent before it creates the
    // blacklisted child. This binary is an acceptance-test fixture only.
    thread::sleep(Duration::from_millis(1_500));
    let mut arguments = std::env::args().skip(1);
    if arguments.next().as_deref() == Some("--read-file") {
        let path = arguments.next().expect("missing fixture file path");
        let _ = std::fs::read(path).expect("failed to read fixture file");
        thread::sleep(Duration::from_secs(30));
        return;
    }
    let mut child = Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "ping -n 30 127.0.0.1 >nul"])
        .spawn()
        .expect("failed to start cmd.exe fixture child");
    let _ = child.wait();
    thread::sleep(Duration::from_secs(30));
}
