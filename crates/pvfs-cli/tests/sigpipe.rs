//! The SIGPIPE filter contract: an early-exiting pipe reader (`pvfs ls |
//! head -1`, `pvfs stat X | grep -q Y`) must end the CLI quietly via SIGPIPE —
//! never the "failed printing to stdout: Broken pipe" panic observed on the
//! 2026-08-10 presubuntu smoke run (F3 replica stat check).

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
    let out = Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .arg("--help") // a deterministic printer: needs no forest or daemon
        .stdout(Stdio::from(closed_pipe()))
        .stderr(Stdio::piped())
        .output()
        .expect("run pvfs");
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
