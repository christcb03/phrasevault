//! P5 — the serve-job supervisor (doc 18 §2). P5.0 built the skeleton (config,
//! SIGHUP reload, status rows); P5.1 makes it a real supervisor: continuous
//! jobs run on their own threads, watched, restarted with backoff, stopped
//! promptly on disable or shutdown. First body: `follow` — the F5.4 loop from
//! `pvfs-client` (shared with `pvfs replica follow`).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pvfs_client::follow::{self, FollowEvent};
use pvfs_core::{serve, PvfsError};
use pvfs_proto::ServeJobWire;

/// How often the supervisor wakes to notice shutdown/reload and reconcile.
const RUNNER_POLL: Duration = Duration::from_millis(250);
/// The follow job's long-poll window — short so disable/shutdown are honored
/// within seconds (the CLI's ad-hoc follower uses a longer one).
const FOLLOW_POLL_MS: u64 = 5_000;
/// How long after a fatal job error before the supervisor tries again.
const FATAL_RETRY: Duration = Duration::from_secs(60);

/// Jobs that run as their own long-lived thread (the rest fire per tick —
/// none yet; P5.2+).
const CONTINUOUS: [&str; 1] = ["follow"];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The supervisor's shared state: one row per known job, snapshotted for
/// `ServeStatus` replies and updated by job threads as they work.
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

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
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

    fn with_row(&self, name: &str, f: impl FnOnce(&mut ServeJobWire)) {
        let mut rows = self.rows.lock().unwrap();
        if let Some(r) = rows.iter_mut().find(|r| r.name == name) {
            f(r);
        }
    }

    fn set_state(&self, name: &str, state: &str) {
        self.with_row(name, |r| r.state = state.to_string());
    }

    /// A successful pass: running, stamped, error cleared.
    fn mark_ok(&self, name: &str) {
        self.with_row(name, |r| {
            r.state = "running".into();
            r.last_ok_ms = Some(now_ms());
            r.last_error = None;
        });
    }

    /// A transient failure: the job retries by itself.
    fn mark_retry(&self, name: &str, reason: &str) {
        self.with_row(name, |r| {
            r.state = "backoff".into();
            r.last_error = Some(reason.to_string());
        });
    }

    /// A fatal failure: the thread exited; the supervisor retries later.
    fn mark_fatal(&self, name: &str, reason: &str) {
        self.with_row(name, |r| {
            r.state = "error".into();
            r.last_error = Some(reason.to_string());
        });
    }

    fn row(&self, name: &str) -> Option<ServeJobWire> {
        self.rows.lock().unwrap().iter().find(|r| r.name == name).cloned()
    }
}

/// A continuous job's thread and its stop flag.
struct Managed {
    stop: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<()>,
}

fn spawn_continuous(name: &str, state: &Arc<JobsState>) -> Managed {
    let stop = Arc::new(AtomicBool::new(false));
    let handle = match name {
        "follow" => {
            let st = Arc::clone(state);
            let flag = Arc::clone(&stop);
            std::thread::spawn(move || {
                st.set_state("follow", "running");
                let data_dir = st.data_dir().clone();
                let cb_state = Arc::clone(&st);
                let r = follow::run(&data_dir, FOLLOW_POLL_MS, &flag, |ev| match ev {
                    FollowEvent::Connected { .. } => cb_state.set_state("follow", "running"),
                    FollowEvent::CaughtUp { .. } => cb_state.mark_ok("follow"),
                    FollowEvent::Retrying { reason } => cb_state.mark_retry("follow", &reason),
                });
                match r {
                    // stopped on request — back to the config-described state
                    Ok(()) => st.set_state(
                        "follow",
                        if st.row("follow").is_some_and(|r| r.enabled) {
                            "idle"
                        } else {
                            "disabled"
                        },
                    ),
                    // not a replica / no identity: the supervisor retries later
                    Err(e) => st.mark_fatal("follow", &e.to_string()),
                }
            })
        }
        other => unreachable!("no continuous body for job {other}"),
    };
    Managed { stop, handle }
}

/// The supervisor loop. Polls `reload` (SIGHUP) and `shutdown` (SIGTERM/INT);
/// reconciles configured jobs against live threads each tick; a failed reload
/// keeps the previous config and logs — a running fleet box must not lose its
/// jobs to a half-edited file.
pub fn run(state: Arc<JobsState>, shutdown: &AtomicBool, reload: &AtomicBool) {
    let mut running: HashMap<String, Managed> = HashMap::new();
    let mut draining: Vec<Managed> = Vec::new();
    let mut retry_at: HashMap<String, Instant> = HashMap::new();

    while !shutdown.load(Ordering::SeqCst) {
        if reload.swap(false, Ordering::SeqCst) {
            if let Err(e) = state.reload() {
                eprintln!("pvfsd: serve.jobs reload failed (config kept): {e}");
            }
        }

        // join stopped threads that have finished draining
        draining.retain(|m| !m.handle.is_finished());

        for name in CONTINUOUS {
            let enabled = state.row(name).map(|r| r.enabled).unwrap_or(false);
            let live = running
                .get(name)
                .map(|m| !m.handle.is_finished())
                .unwrap_or(false);
            if enabled && !live {
                // clean up a finished thread; fatal exits wait out the backoff
                if let Some(m) = running.remove(name) {
                    let fatal = state.row(name).map(|r| r.state == "error").unwrap_or(false);
                    let _ = m.handle.join();
                    if fatal {
                        retry_at.insert(name.to_string(), Instant::now() + FATAL_RETRY);
                    }
                }
                let ready = retry_at.get(name).map_or(true, |t| Instant::now() >= *t);
                if ready {
                    retry_at.remove(name);
                    running.insert(name.to_string(), spawn_continuous(name, &state));
                }
            } else if !enabled {
                if let Some(m) = running.remove(name) {
                    // signal and drain; the shared loop honors the flag
                    // within its poll window
                    m.stop.store(true, Ordering::SeqCst);
                    draining.push(m);
                }
                retry_at.remove(name);
            }
        }

        std::thread::sleep(RUNNER_POLL);
    }

    // shutdown: stop everything, then wait for the threads
    for m in running.values() {
        m.stop.store(true, Ordering::SeqCst);
    }
    for m in &draining {
        m.stop.store(true, Ordering::SeqCst);
    }
    for (_, m) in running {
        let _ = m.handle.join();
    }
    for m in draining {
        let _ = m.handle.join();
    }
}
