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
use pvfs_client::watch::{self, WatchEvent};
use pvfs_core::{serve, PvfsError};
use pvfs_proto::ServeJobWire;

/// How often the supervisor wakes to notice shutdown/reload and reconcile.
const RUNNER_POLL: Duration = Duration::from_millis(250);
/// The follow job's long-poll window — short so disable/shutdown are honored
/// within seconds (the CLI's ad-hoc follower uses a longer one).
const FOLLOW_POLL_MS: u64 = 5_000;
/// How long after a fatal job error before the supervisor tries again.
const FATAL_RETRY: Duration = Duration::from_secs(60);

/// Jobs that run as their own long-lived thread.
const CONTINUOUS: [&str; 2] = ["follow", "watch"];
/// Jobs that run as short passes — on a content nudge (a follow fold, a
/// fetching sync) or a safety interval, whichever comes first. A pass also
/// runs once at daemon start, catching up after downtime. `tier` (owner) is
/// interval-only for now — commit-driven nudges are a doc 18 §6 follow-up.
const PERIODIC: [&str; 4] = ["sync", "export", "tier", "evict"];
const SYNC_INTERVAL: Duration = Duration::from_secs(300);
const EXPORT_INTERVAL: Duration = Duration::from_secs(300);
const TIER_INTERVAL: Duration = Duration::from_secs(300);
const EVICT_INTERVAL: Duration = Duration::from_secs(300);

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
    /// Content changed (a follow fold): the consuming passes should run soon.
    nudge_sync: AtomicBool,
    nudge_export: AtomicBool,
    /// A fold may carry the mover's retirements — evict follows content too.
    nudge_evict: AtomicBool,
    /// Punch H: the daemon's own commits (write-through ingest) wake the mover.
    nudge_tier: AtomicBool,
}

impl JobsState {
    /// Read `serve.jobs` and build the initial rows. A missing file is a
    /// valid empty config; a corrupt one refuses daemon start — better loud
    /// at startup than a box silently running zero jobs.
    pub fn load(data_dir: PathBuf) -> Result<JobsState, PvfsError> {
        let s = JobsState {
            data_dir,
            rows: Mutex::new(Vec::new()),
            nudge_sync: AtomicBool::new(false),
            nudge_export: AtomicBool::new(false),
            nudge_evict: AtomicBool::new(false),
            nudge_tier: AtomicBool::new(false),
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

    /// Content changed — run the content-consuming passes soon.
    fn nudge_content(&self) {
        self.nudge_sync.store(true, Ordering::SeqCst);
        self.nudge_export.store(true, Ordering::SeqCst);
        self.nudge_evict.store(true, Ordering::SeqCst);
    }

    fn take_nudge(&self, name: &str) -> bool {
        match name {
            "sync" => self.nudge_sync.swap(false, Ordering::SeqCst),
            "export" => self.nudge_export.swap(false, Ordering::SeqCst),
            "evict" => self.nudge_evict.swap(false, Ordering::SeqCst),
            "tier" => self.nudge_tier.swap(false, Ordering::SeqCst),
            _ => false,
        }
    }

    /// Punch H: called by the daemon's commit path — new content on the
    /// owner should migrate without waiting out the interval.
    pub(crate) fn nudge_tier(&self) {
        self.nudge_tier.store(true, Ordering::SeqCst);
    }

    /// A completed pass: back to idle, stamped; issues (per-file failures or
    /// a failed pass) land in `last_error` until a clean pass clears them.
    fn mark_pass(&self, name: &str, issue: Option<String>) {
        self.with_row(name, |r| {
            r.state = "idle".into();
            if issue.is_none() {
                r.last_ok_ms = Some(now_ms());
            }
            r.last_error = issue;
        });
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
                    FollowEvent::CaughtUp { .. } => {
                        cb_state.mark_ok("follow");
                        // fresh content — the consuming passes should run now
                        cb_state.nudge_content();
                    }
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
        "watch" => {
            let st = Arc::clone(state);
            let flag = Arc::clone(&stop);
            std::thread::spawn(move || {
                st.set_state("watch", "running");
                let data_dir = st.data_dir().clone();
                let cb = Arc::clone(&st);
                let r = watch::run(&data_dir, 3600, 2000, &flag, |ev| match ev {
                    WatchEvent::Ingested(_, a, c, rm) => {
                        cb.mark_ok("watch");
                        if a + c + rm > 0 {
                            // local ingest = new content: views, placed
                            // subtrees, the mover — all should wake
                            cb.nudge_content();
                            cb.nudge_tier();
                        }
                    }
                    WatchEvent::ScanError(e) => cb.mark_retry("watch", &e),
                    WatchEvent::Watching(_) => cb.set_state("watch", "running"),
                });
                match r {
                    Ok(()) => st.set_state(
                        "watch",
                        if st.row("watch").is_some_and(|r| r.enabled) {
                            "idle"
                        } else {
                            "disabled"
                        },
                    ),
                    Err(e) => st.mark_fatal("watch", &e.to_string()),
                }
            })
        }
        other => unreachable!("no continuous body for job {other}"),
    };
    Managed { stop, handle }
}

/// One sync pass: fetch missing bytes for every `sync`-placed subtree.
/// Nothing placed is a clean no-op — the job idles until placement exists.
fn sync_pass(state: &JobsState) -> Result<(u64, Vec<(String, String)>), PvfsError> {
    let data_dir = state.data_dir().clone();
    let roots = pvfs_core::sync::load_placement(&data_dir)?;
    if roots.is_empty() {
        return Ok((0, Vec::new()));
    }
    let mut engine = pvfs_core::Engine::open(&data_dir)?;
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let r = pvfs_client::fetch::sync_pull(&mut engine, &mut fetcher, &roots);
    engine.close()?;
    r
}

/// One export pass: re-run every kept-fresh export (`pvfs export
/// --keep-fresh`), fetching first where the entry asked for it.
fn export_pass(state: &JobsState) -> Result<u64, PvfsError> {
    let data_dir = state.data_dir().clone();
    let entries = pvfs_core::serve::load_exports(&data_dir)?;
    if entries.is_empty() {
        return Ok(0);
    }
    let mut engine = pvfs_core::Engine::open(&data_dir)?;
    let mut fetcher: Option<pvfs_client::fetch::Fetcher> = None;
    let mut exported = 0u64;
    for e in &entries {
        if e.fetch {
            let f = fetcher.get_or_insert_with(|| pvfs_client::fetch::Fetcher::new(&data_dir));
            // per-file fetch failures are the export's skips, not a pass error
            let _ = pvfs_client::fetch::sync_pull(&mut engine, f, std::slice::from_ref(&e.node));
        }
        let spec = pvfs_core::ExportSpec {
            mode: pvfs_core::ExportMode::parse(&e.mode)?,
            prune: e.prune,
        };
        let report = engine.export_tree(&e.node, &e.dest, &spec)?;
        exported += report.exported as u64;
    }
    engine.close()?;
    Ok(exported)
}

fn spawn_pass(name: &str, state: &Arc<JobsState>) -> Managed {
    let stop = Arc::new(AtomicBool::new(false)); // passes are short; uniform bookkeeping
    let st = Arc::clone(state);
    let handle = match name {
        "sync" => std::thread::spawn(move || {
            st.set_state("sync", "running");
            match sync_pass(&st) {
                Ok((fetched, failed)) => {
                    let issue = failed.first().map(|(label, e)| {
                        format!("{} fetch failures (first: {label} — {e})", failed.len())
                    });
                    st.mark_pass("sync", issue);
                    if fetched > 0 {
                        // new bytes landed — refresh the export views now
                        st.nudge_export.store(true, Ordering::SeqCst);
                    }
                }
                Err(e) => st.mark_pass("sync", Some(e.to_string())),
            }
        }),
        "export" => std::thread::spawn(move || {
            st.set_state("export", "running");
            match export_pass(&st) {
                Ok(_) => st.mark_pass("export", None),
                Err(e) => st.mark_pass("export", Some(e.to_string())),
            }
        }),
        "tier" => std::thread::spawn(move || {
            st.set_state("tier", "running");
            let r = (|| -> Result<Option<pvfs_client::fetch::TierReport>, PvfsError> {
                let mut engine = pvfs_core::Engine::open(st.data_dir())?;
                let mut fetcher = pvfs_client::fetch::Fetcher::new(st.data_dir());
                let r = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher);
                engine.close()?;
                r
            })();
            match r {
                // None = nothing placed central — a clean idle pass
                Ok(report) => {
                    let issue = report.and_then(|t| {
                        t.failed.first().map(|(label, e)| {
                            format!("{} migrations failed (first: {label} — {e})", t.failed.len())
                        })
                    });
                    st.mark_pass("tier", issue);
                }
                Err(e) => st.mark_pass("tier", Some(e.to_string())),
            }
        }),
        "evict" => std::thread::spawn(move || {
            st.set_state("evict", "running");
            let r = (|| -> Result<pvfs_core::sync::EvictReport, PvfsError> {
                let engine = pvfs_core::Engine::open(st.data_dir())?;
                let r = pvfs_core::sync::evict_pass(&engine);
                engine.close()?;
                r
            })();
            match r {
                // held-back files (no other live location) are expected, not
                // errors — the next mover pass unblocks them
                Ok(_) => st.mark_pass("evict", None),
                Err(e) => st.mark_pass("evict", Some(e.to_string())),
            }
        }),
        other => unreachable!("no pass body for job {other}"),
    };
    Managed { stop, handle }
}

fn interval(name: &str) -> Duration {
    match name {
        "sync" => SYNC_INTERVAL,
        "export" => EXPORT_INTERVAL,
        "tier" => TIER_INTERVAL,
        _ => EVICT_INTERVAL,
    }
}

/// The supervisor loop. Polls `reload` (SIGHUP) and `shutdown` (SIGTERM/INT);
/// reconciles configured jobs against live threads each tick; a failed reload
/// keeps the previous config and logs — a running fleet box must not lose its
/// jobs to a half-edited file.
pub fn run(state: Arc<JobsState>, shutdown: &AtomicBool, reload: &AtomicBool) {
    let mut running: HashMap<String, Managed> = HashMap::new();
    let mut draining: Vec<Managed> = Vec::new();
    let mut retry_at: HashMap<String, Instant> = HashMap::new();
    let mut next_due: HashMap<String, Instant> = HashMap::new();
    let jobs_file = serve::jobs_path(state.data_dir());
    let mtime_of = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last_mtime = mtime_of(&jobs_file);

    while !shutdown.load(Ordering::SeqCst) {
        // punch A: `serve enable` takes effect within a tick — the runner
        // notices the file change itself; SIGHUP stays as a manual trigger.
        let m = mtime_of(&jobs_file);
        if m != last_mtime {
            last_mtime = m;
            reload.store(true, Ordering::SeqCst);
        }
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

        for name in PERIODIC {
            let enabled = state.row(name).map(|r| r.enabled).unwrap_or(false);
            if !enabled {
                next_due.remove(name);
                continue;
            }
            let live = running
                .get(name)
                .map(|m| !m.handle.is_finished())
                .unwrap_or(false);
            if live {
                continue; // a set nudge stays set; consumed after this pass ends
            }
            if let Some(m) = running.remove(name) {
                let _ = m.handle.join();
            }
            let due = next_due.get(name).map_or(true, |t| Instant::now() >= *t);
            if state.take_nudge(name) || due {
                next_due.insert(name.to_string(), Instant::now() + interval(name));
                running.insert(name.to_string(), spawn_pass(name, &state));
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
