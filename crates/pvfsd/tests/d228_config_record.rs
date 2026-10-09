//! PVOS D228 — pvfsd says what it is at start: `pvfs.daemon.config` with
//! the forest, its role, its jobs, its regions and its listener.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pvfs_core::Engine;

#[test]
fn the_daemon_logs_its_config_at_start() {
    let home = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    // A mount: the forest lives in `<dir>/.pvfs`, as `pvfs forest init --mount` makes it.
    let (e, _) = Engine::init(&pvfs_core::mount::state_dir(dir.path())).unwrap();
    let forest = e.identity.forest_id.clone();
    e.close().unwrap();
    let sock = home.path().join("d.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_pvfsd"))
        .args(["--mount", &dir.path().display().to_string(), "--socket", &sock.display().to_string(), "--listen", "127.0.0.1:0"])
        .env("PVFS_LOG_FORMAT", "json")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env_remove("JOURNAL_STREAM")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (mut found, mut seen) = (None, Vec::new());
    while Instant::now() < deadline {
        let Some(Ok(line)) = lines.next() else { break };
        if line.contains("\"pvfs.daemon.config\"") {
            found = Some(line);
            break;
        }
        seen.push(line);
    }
    let _ = child.kill();
    let _ = child.wait();
    let line = found.unwrap_or_else(|| panic!("no pvfs.daemon.config record; the daemon said:\n{}", seen.join("\n")));
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    let f = &v["fields"];
    assert_eq!(f["forest"], forest.as_str(), "{line}");
    assert_eq!(f["role"], "owner");
    assert_eq!(f["jobs"], "none");
    assert_eq!(f["regions"], "none");
    assert_eq!(f["listen"], "127.0.0.1:0");
    // The record splits the sentence's "pvfsd: " prefix into `component`.
    assert_eq!(v["component"], "pvfsd");
    let msg = v["msg"].as_str().unwrap();
    assert!(msg.starts_with(&format!("forest {} as owner — jobs none; regions none", &forest[..8])), "{msg}");
    assert!(msg.ends_with("network: 127.0.0.1:0"), "{msg}");
    // Not the listener's own phrase: the smoke tests and the fleet plays find
    // the real listener (port and pin) by "listening on".
    assert!(!msg.contains("listening on"), "{msg}");
}
