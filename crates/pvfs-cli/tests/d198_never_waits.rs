//! PVOS D198 — the CLI never waits on a question nobody can see. D186's
//! promotion hung ~9 minutes: Ansible ran `pvfs --json fleet notify
//! 2>/dev/null` under a pseudo-terminal on a box with no notify settings, and
//! the CLI asked for a webhook URL on the redirected stderr.

use pvfs_core::Engine;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory, removed when dropped (this crate has no tempfile).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d198-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A forest with no notify settings — what a newly promoted owner has.
fn fresh_forest() -> (Scratch, std::path::PathBuf) {
    let s = Scratch::new();
    let data = s.0.join("data");
    let (engine, _mnemonic) = Engine::init_unbound(&data).unwrap();
    engine.close().unwrap();
    (s, data)
}

#[test]
fn a_json_query_with_nothing_configured_answers_null() {
    let (_s, data) = fresh_forest();
    let out = Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .arg("--data-dir")
        .arg(&data)
        .args(["--json", "fleet", "notify"])
        .env_remove("PVFS_DATA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "null");
}

/// Ansible's shape: stdin a pseudo-terminal whose other end stays open with
/// nothing typed, stderr redirected. `script` (util-linux) gives the child a
/// pty; our piped stdin to `script` stays open and silent, like the ssh
/// channel. Before D198 this waited forever; it must now end at once with
/// the "missing … pass it as an argument" error.
#[test]
fn a_terminal_nobody_watches_is_not_asked() {
    let Ok(script) = which("script") else {
        eprintln!("SKIP: no `script` (util-linux) on this host");
        return;
    };
    let (_s, data) = fresh_forest();
    let cmd = format!(
        "{} --data-dir {} fleet notify 2>/dev/null; echo \"rc=$?\"",
        env!("CARGO_BIN_EXE_pvfs"),
        data.display()
    );
    let mut child = Command::new(script)
        .args(["-q", "-e", "-c", &cmd, "/dev/null"])
        .env_remove("PVFS_DATA_DIR")
        .stdin(Stdio::piped()) // held open, never written: nobody types
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            panic!("pvfs fleet notify waited on a question nobody could see (killed after 20 s)");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rc=") && !stdout.contains("rc=0"), "want a quick non-zero exit, got: {stdout}");
}

fn which(bin: &str) -> Result<std::path::PathBuf, ()> {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
        .ok_or(())
}
