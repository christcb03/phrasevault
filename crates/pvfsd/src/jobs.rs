//! P5 — the serve-job runner (doc 18 §2). This stage (P5.0) is the skeleton:
//! the runner thread, `serve.jobs` loading, SIGHUP reload, and the live
//! status surface (`ClientMsg::ServeStatus`). Job *bodies* land one phase at
//! a time (doc 18 §5) — an enabled job reports `"idle"` until its phase does.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pvfs_core::{serve, PvfsError};
use pvfs_proto::ServeJobWire;

/// How often the runner wakes to notice shutdown and reload flags.
const RUNNER_POLL: Duration = Duration::from_millis(250);

/// The runner's shared state: one row per known job, snapshotted for
/// `ServeStatus` replies.
pub struct JobsState {
    data_dir: PathBuf,
    rows: Mutex<Vec<ServeJobWire>>,
}

impl JobsState {
    /// Read `serve.jobs` and build the initial rows. A missing file is a
    /// valid empty config; a corrupt one refuses daemon start — better loud
    /// at startup than a box silently running zero jobs.
    pub fn load(data_dir: PathBuf) -> Result<JobsState, PvfsError> {
        let s = JobsState {
            data_dir,
            rows: Mutex::new(Vec::new()),
        };
        s.reload()?;
        Ok(s)
    }

    /// Re-read the config (SIGHUP). Run history (`last_ok`/`last_error`)
    /// survives a reload; enabled/state reflect the new file.
    pub fn reload(&self) -> Result<(), PvfsError> {
        let enabled = serve::load_jobs(&self.data_dir)?;
        let mut rows = self.rows.lock().unwrap();
        let old = std::mem::take(&mut *rows);
        *rows = serve::JOB_NAMES
            .iter()
            .map(|name| {
                let en = enabled.iter().any(|j| j == name);
                let prev = old.iter().find(|r| r.name == *name);
                ServeJobWire {
                    name: (*name).to_string(),
                    enabled: en,
                    state: if en { "idle" } else { "disabled" }.to_string(),
                    last_ok_ms: prev.and_then(|p| p.last_ok_ms),
                    last_error: prev.and_then(|p| p.last_error.clone()),
                }
            })
            .collect();
        Ok(())
    }

    pub fn snapshot(&self) -> Vec<ServeJobWire> {
        self.rows.lock().unwrap().clone()
    }
}

/// The runner loop. Polls `reload` (set by SIGHUP) and `shutdown` (set by
/// SIGTERM/SIGINT); a failed reload keeps the previous config and logs — a
/// running fleet box must not lose its jobs to a half-edited file.
pub fn run(state: Arc<JobsState>, shutdown: &AtomicBool, reload: &AtomicBool) {
    while !shutdown.load(Ordering::SeqCst) {
        if reload.swap(false, Ordering::SeqCst) {
            if let Err(e) = state.reload() {
                eprintln!("pvfsd: serve.jobs reload failed (config kept): {e}");
            }
        }
        std::thread::sleep(RUNNER_POLL);
    }
}
