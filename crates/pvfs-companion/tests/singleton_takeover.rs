//! Singleton-per-user takeover, end to end with real processes (doc 14 §2;
//! requested 2026-07-21 after the PVOS M3.5 dual-instance failure): a first
//! `serve` answers on the socket and records its pidfile; a second
//! `pvfs-companion restart` kills it, rebinds the socket, and answers in its
//! place — exactly the "take over, don't sit alongside" posture.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use pvfs_companion::{request, AgentRequest, AgentResponse};

const PASS: &str = "test-passphrase";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_pvfs-companion")
}

/// Poll `cond` for up to `secs` seconds.
fn wait_for(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(secs) {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

fn agent_answers(socket: &Path) -> bool {
    matches!(
        request(socket, &AgentRequest::ApiVersion),
        Ok(AgentResponse::ApiVersion { .. })
    )
}

fn init_vault(vault: &Path) {
    use std::io::Write;
    let phrase = pvfs_core::identity::generate_mnemonic().unwrap().to_string();
    let mut child = Command::new(bin())
        .args(["init", "--vault"])
        .arg(vault)
        .arg("--passphrase")
        .env("PVFS_COMPANION_PASSPHRASE", PASS)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(phrase.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "vault init failed");
}

/// `serve` (or `restart` — same flags) as a real child process: passphrase
/// vault unlocked from the env, prompts forced to deny, ephemeral web port so
/// parallel test runs never collide.
fn spawn_agent(cmd: &str, vault: &Path, socket: &Path) -> Child {
    Command::new(bin())
        .args([cmd, "--vault"])
        .arg(vault)
        .arg("--socket")
        .arg(socket)
        .args(["--prompt", "deny", "--web-port", "0"])
        .env("PVFS_COMPANION_PASSPHRASE", PASS)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

fn read_pid(pidfile: &Path) -> Option<u32> {
    std::fs::read_to_string(pidfile).ok()?.trim().parse().ok()
}

#[test]
fn restart_takes_over_from_a_running_serve() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("companion.vault");
    let socket: PathBuf = dir.path().join("companion.sock");
    let pidfile = pvfs_companion::pidfile_path(&socket);
    init_vault(&vault);

    // First instance: up, answering, pidfile names it.
    let mut first = spawn_agent("serve", &vault, &socket);
    assert!(
        wait_for(15, || agent_answers(&socket)),
        "first serve never answered"
    );
    assert_eq!(read_pid(&pidfile), Some(first.id()), "pidfile names serve 1");

    // Reap the first child the moment it dies, so the takeover's liveness
    // probe (kill 0) sees a dead process, not a zombie awaiting its parent.
    let reaper = std::thread::spawn(move || {
        let status = first.wait();
        (first.id(), status)
    });

    // Second instance via the explicit affordance: it must kill the first,
    // rebind, and answer — never sit alongside it.
    let mut second = spawn_agent("restart", &vault, &socket);
    // reaper returning proves serve 1 is dead; SIGTERM (15) proves it was the
    // takeover that killed it, not a crash.
    let (first_pid, first_status) = reaper.join().unwrap();
    let status = first_status.unwrap();
    assert_eq!(status.signal(), Some(15), "killed by takeover SIGTERM: {status:?}");
    assert!(
        wait_for(15, || read_pid(&pidfile) == Some(second.id())),
        "pidfile flips to serve 2"
    );
    assert_ne!(first_pid, second.id());
    assert!(
        wait_for(15, || agent_answers(&socket)),
        "second serve answers after takeover"
    );

    let _ = second.kill();
    let _ = second.wait();
}

// `ExitStatus::signal()` needs the unix extension trait in scope.
use std::os::unix::process::ExitStatusExt;
