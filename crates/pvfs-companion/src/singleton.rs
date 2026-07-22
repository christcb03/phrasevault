//! Singleton-per-user companion (doc 14; requested 2026-07-21 after PVOS M3.5
//! live testing): a menu-bar app and a CLI `serve` ran side by side, both
//! holding FDs on the conventional socket — the later bind orphaned the first
//! and which copy answered was luck. On launch the companion now **takes
//! over**: detect an existing instance (live socket + pidfile), kill the stale
//! copy, rebind the socket, and keep serving the stable web relay port.
//!
//! The pidfile (`<socket>.pid`, 0600) is written after a successful bind. A
//! pidfile whose process is gone is stale and ignored; a live pid is only
//! killed while the socket file it advertised still exists (so a recycled pid
//! after a clean shutdown is never targeted).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use crate::proto::{AgentRequest, AgentResponse};

/// What `take_over` found and did — for the serve banner.
pub struct TakeoverReport {
    /// The previous instance's pid, when one was killed.
    pub killed: Option<i32>,
    /// A live instance answered on the socket but left no pidfile (a
    /// pre-singleton build): it could not be killed and was orphaned.
    pub orphaned: bool,
}

/// The conventional pidfile next to the socket.
pub fn pidfile_path(socket: &Path) -> PathBuf {
    socket.with_extension("pid")
}

/// Is a companion actually answering on `socket`? Bounded by short timeouts so
/// a hung instance (holding the bind but not serving) reads as dead.
fn probe_alive(socket: &Path) -> bool {
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(socket) else {
        return false;
    };
    let t = Some(Duration::from_secs(2));
    if stream.set_read_timeout(t).is_err() || stream.set_write_timeout(t).is_err() {
        return false;
    }
    if pvfs_proto::write_msg(&mut stream, &AgentRequest::ApiVersion).is_err() {
        return false;
    }
    matches!(
        pvfs_proto::read_msg::<_, AgentResponse>(&mut stream),
        Ok(Some(AgentResponse::ApiVersion { .. }))
    )
}

fn read_pidfile(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 0)
}

fn pid_alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

/// Wait for `pid` to die, up to `for_at_most`.
fn wait_dead(pid: i32, for_at_most: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < for_at_most {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    !pid_alive(pid)
}

/// Make this process the only companion on `socket`: kill a previous instance
/// (SIGTERM, escalating to SIGKILL after 5 s), clear the stale socket file, and
/// report what happened. Call before binding.
pub fn take_over(socket: &Path) -> TakeoverReport {
    let mut report = TakeoverReport {
        killed: None,
        orphaned: false,
    };
    let pidfile = pidfile_path(socket);
    let me = std::process::id() as i32;
    let previous = read_pidfile(&pidfile).filter(|&p| p != me);

    // Only target a pid while the socket file it advertised still exists — a
    // clean shutdown removes neither today, but a *missing* socket means there
    // is nothing to take over and the pidfile is just stale.
    if socket.exists() {
        match previous {
            Some(pid) if pid_alive(pid) => {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
                if !wait_dead(pid, Duration::from_secs(5)) {
                    let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
                    wait_dead(pid, Duration::from_secs(1));
                }
                report.killed = Some(pid);
            }
            _ => {
                // No (usable) pidfile. If something still answers, it's an
                // older build we cannot locate to kill — rebinding orphans it.
                if probe_alive(socket) {
                    report.orphaned = true;
                }
            }
        }
    }
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(&pidfile);
    report
}

/// Record this process as the instance serving `socket` (call after binding).
pub fn write_pidfile(socket: &Path) -> std::io::Result<PathBuf> {
    let path = pidfile_path(socket);
    let mut f = std::fs::File::create(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(std::process::id().to_string().as_bytes())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pidfile_round_trip_is_private_and_names_this_process() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        let path = write_pidfile(&socket).unwrap();
        assert_eq!(path, socket.with_extension("pid"));
        assert_eq!(read_pidfile(&path), Some(std::process::id() as i32));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn takeover_clears_a_stale_socket_and_dead_pidfile_without_killing() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        // A dead instance: socket file present, nobody listening, pidfile
        // naming a pid that cannot exist.
        std::fs::write(&socket, b"").unwrap();
        std::fs::write(pidfile_path(&socket), i32::MAX.to_string()).unwrap();
        let report = take_over(&socket);
        assert!(report.killed.is_none());
        assert!(!report.orphaned);
        assert!(!socket.exists());
        assert!(!pidfile_path(&socket).exists());
    }

    #[test]
    fn takeover_never_targets_itself() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        std::fs::write(&socket, b"").unwrap();
        write_pidfile(&socket).unwrap();
        // Our own pid in the pidfile must be skipped, not SIGTERMed.
        let report = take_over(&socket);
        assert!(report.killed.is_none());
        assert!(!socket.exists());
    }

    #[test]
    fn takeover_with_nothing_present_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("c.sock");
        let report = take_over(&socket);
        assert!(report.killed.is_none() && !report.orphaned);
    }
}
