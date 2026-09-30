//! PVOS D203 — `pvfs serve enable|disable` take their job from `JOB_NAMES`,
//! so the help names every job the daemon runs, each with what it does. The
//! help listed 7 of the 11 by hand (D71 W1).

use pvfs_core::serve::{job_summary, JOB_NAMES};
use pvfs_core::Engine;
use std::process::{Command, Output, Stdio};

/// A scratch directory, removed when dropped (this crate has no tempfile).
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let p = std::env::temp_dir().join(format!("pvfs-d203-{}-{nanos}", std::process::id()));
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
fn the_help_names_every_job_and_what_it_does() {
    for verb in ["enable", "disable"] {
        let out = pvfs(&["serve", verb, "--help"]);
        assert!(out.status.success(), "serve {verb} --help failed");
        let help = String::from_utf8_lossy(&out.stdout);
        for job in JOB_NAMES {
            assert!(help.contains(&format!("- {job}:")), "serve {verb} --help lacks {job}:\n{help}");
            assert!(help.contains(job_summary(job).unwrap()), "serve {verb} --help lacks what {job} does:\n{help}");
        }
        let out = pvfs(&["serve", verb, "-h"]);
        let short = String::from_utf8_lossy(&out.stdout);
        let names = format!("[possible values: {}]", JOB_NAMES.join(", "));
        assert!(short.contains(&names), "serve {verb} -h lacks {names}:\n{short}");
    }
}

#[test]
fn an_unknown_job_is_refused_before_anything_runs() {
    let out = pvfs(&["serve", "enable", "defrag"]);
    assert_eq!(out.status.code(), Some(2), "an unknown job must exit 2, as BadInput did");
    let err = String::from_utf8_lossy(&out.stderr);
    for job in JOB_NAMES {
        assert!(err.contains(job), "the refusal should name {job}:\n{err}");
    }
}

#[test]
fn a_known_job_still_lands_in_serve_jobs() {
    let s = Scratch::new();
    let data = s.0.join("data");
    let (engine, _mnemonic) = Engine::init_unbound(&data).unwrap();
    engine.close().unwrap();
    let d = data.to_str().unwrap();

    let out = pvfs(&["--data-dir", d, "serve", "enable", "receive"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(pvfs_core::serve::load_jobs(&data).unwrap(), ["receive"]);

    let out = pvfs(&["--data-dir", d, "serve", "disable", "receive"]);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(pvfs_core::serve::load_jobs(&data).unwrap().is_empty());
}
