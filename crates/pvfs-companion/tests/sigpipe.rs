//! The SIGPIPE filter contract for the query commands (`status | grep -q`,
//! `origins | head`): an early-exiting pipe reader must end the process
//! quietly via SIGPIPE, never a println! panic on EPIPE. The serve paths
//! re-ignore SIGPIPE instead — that side is asserted by code review, not
//! here, since it needs a vault and a client mid-disconnect.

use std::os::unix::process::ExitStatusExt;
use std::process::{ChildStdin, Command, Stdio};

/// A pipe write end whose read end is ALREADY closed, built with std only:
/// give `true` a piped stdin, keep the write end, wait for it to exit. Every
/// later write to this end raises SIGPIPE — no race with the reader.
fn closed_pipe() -> ChildStdin {
    let mut reader = Command::new("true")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn true");
    let w = reader.stdin.take().expect("stdin pipe");
    reader.wait().expect("true exits");
    w
}

#[test]
fn early_reader_exit_is_a_quiet_sigpipe_death() {
    let out = Command::new(env!("CARGO_BIN_EXE_pvfs-companion"))
        .arg("--help") // a deterministic printer: needs no vault or socket
        .stdout(Stdio::from(closed_pipe()))
        .stderr(Stdio::piped())
        .output()
        .expect("run pvfs-companion");
    // Killed by SIGPIPE (13; a shell reports rc 141) — not a panic exit.
    assert_eq!(
        out.status.signal(),
        Some(13),
        "want death by SIGPIPE, got {:?} (stderr: {})",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "wanted a silent death, stderr said: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
