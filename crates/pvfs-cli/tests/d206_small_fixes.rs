//! PVOS D206 — `pvfs serve enable|disable` bare never waits on a script and
//! names every job; `pvfs region ls` shows a receiving region's tuning.

use pvfs_core::serve::JOB_NAMES;
use pvfs_core::{sync, Engine, NodeSpec, TYPE_FOLDER};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory, removed when dropped (this crate has no tempfile).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d206-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pvfs(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pvfs"))
        .args(args)
        .env_remove("PVFS_DATA_DIR")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

#[test]
fn bare_serve_enable_and_disable_refuse_at_once_naming_every_job() {
    let s = Scratch::new();
    let data = s.0.join("data");
    let (engine, _mnemonic) = Engine::init_unbound(&data).unwrap();
    engine.close().unwrap();
    let d = data.to_str().unwrap();
    for verb in ["enable", "disable"] {
        let t = Instant::now();
        let out = pvfs(&["--data-dir", d, "serve", verb]);
        assert!(t.elapsed() < Duration::from_secs(20), "serve {verb} bare must not wait for an answer");
        assert_eq!(out.status.code(), Some(2), "serve {verb} bare off a terminal is bad input");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains(&format!("which job to {verb}?")), "{err}");
        for job in JOB_NAMES {
            assert!(err.contains(job), "the refusal should name {job}:\n{err}");
        }
        assert!(!err.contains("required arguments were not provided"), "no longer clap's refusal:\n{err}");
    }
    assert!(pvfs_core::serve::load_jobs(&data).unwrap().is_empty(), "nothing changed");
    // and a named job still works as before
    let out = pvfs(&["--data-dir", d, "serve", "enable", "receive"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(pvfs_core::serve::load_jobs(&data).unwrap(), ["receive"]);
}

fn catalogue_region(e: &mut Engine, label: &str) -> String {
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: label.into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    r
}

#[test]
fn region_ls_shows_each_receiving_regions_tuning() {
    let s = Scratch::new();
    let data = s.0.join("data");
    let (mut e, _mn) = Engine::init(&data).unwrap();
    let defaults = catalogue_region(&mut e, "library");
    let tuned = catalogue_region(&mut e, "library2");
    let quiet = catalogue_region(&mut e, "staging");
    sync::set_region_receive(e.data_dir(), &defaults, true).unwrap();
    sync::set_region_receive(e.data_dir(), &tuned, true).unwrap();
    sync::set_region_receive_parallel(e.data_dir(), &tuned, 3).unwrap();
    sync::set_region_receive_streams(e.data_dir(), &tuned, 6).unwrap();
    e.close().unwrap();
    let d = data.to_str().unwrap();

    let out = pvfs(&["--data-dir", d, "region", "ls"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    let line = |id: &str| text.lines().find(|l| l.starts_with(id)).unwrap_or_else(|| panic!("no {id} in:\n{text}")).to_string();
    let (p, st) = (sync::RECEIVE_PARALLEL_DEFAULT, sync::RECEIVE_STREAMS_DEFAULT);
    assert!(line(&defaults).ends_with(&format!("\treceives {p}×{st}")), "{}", line(&defaults));
    assert!(line(&tuned).ends_with("\treceives 3×6"), "{}", line(&tuned));
    assert!(!line(&quiet).contains("receives"), "{}", line(&quiet));

    let out = pvfs(&["--json", "--data-dir", d, "region", "ls"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
    let row = |id: &str| rows.iter().find(|r| r["region"] == id).unwrap().clone();
    assert_eq!(row(&defaults)["receive_parallel"], p);
    assert_eq!(row(&defaults)["receive_streams"], st);
    assert_eq!(row(&tuned)["receive_parallel"], 3);
    assert_eq!(row(&tuned)["receive_streams"], 6);
    assert_eq!(row(&tuned)["receives"], true);
    assert!(row(&quiet)["receive_parallel"].is_null());
    assert!(row(&quiet)["receive_streams"].is_null());
    assert_eq!(row(&quiet)["receives"], false);
}
