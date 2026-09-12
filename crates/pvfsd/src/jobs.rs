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
const PERIODIC: [&str; 9] = ["sync", "export", "tier", "evict", "reclaim", "resolve", "catalogue", "health", "receive"];
/// How many intervals a pass may overrun before it is called stalled. Three is
/// slack enough for a genuinely long pass (a big tier run) without letting a
/// hang hide for hours.
const STALL_FACTOR: u64 = 3;

/// D98 — how many tier passes before the unfetchable memory is re-tested.
/// At the 300s interval that is roughly two hours: long enough to stop the
/// hammering, short enough that a repaired catalog recovers on its own.
const UNFETCHABLE_RECHECK_PASSES: u64 = 24;

const SYNC_INTERVAL: Duration = Duration::from_secs(300);
const EXPORT_INTERVAL: Duration = Duration::from_secs(300);
const TIER_INTERVAL: Duration = Duration::from_secs(300);
/// The watcher's own safety-net reconcile — the cadence a quiet `watch` keeps.
/// Passed to `watch::run` AND used as its stall baseline, so the two cannot
/// drift apart again.
pub const WATCH_RECONCILE: Duration = Duration::from_secs(3600);
const EVICT_INTERVAL: Duration = Duration::from_secs(300);
/// D129 — a catalogue region's head moves at most once per watch pass on
/// its box, so a minute keeps the fleet's view within a pass of live.
const CATALOGUE_INTERVAL: Duration = Duration::from_secs(60);
/// D131 — a fleet poll every two minutes: "ten hours unnoticed" becomes
/// "four minutes" (two misses) without paging on a daemon's own restart.
const HEALTH_INTERVAL: Duration = Duration::from_secs(120);
/// D133 — the mover's cadence on the new model, `tier`'s.
const RECEIVE_INTERVAL: Duration = Duration::from_secs(300);

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
    /// When the runner started — the baseline for a job that has NEVER
    /// completed a pass, which is exactly the case a first-run hang produces.
    started_ms: u64,
    /// Content changed (a follow fold): the consuming passes should run soon.
    nudge_sync: AtomicBool,
    nudge_export: AtomicBool,
    /// A fold may carry the mover's retirements — evict follows content too.
    nudge_evict: AtomicBool,
    /// Punch H: the daemon's own commits (write-through ingest) wake the mover.
    nudge_tier: AtomicBool,
    /// D81 — when each job's CURRENT pass began; absent means none in flight.
    /// Local to the daemon: `ServeJobWire` is on the wire and this is not worth
    /// a proto bump, since it only ever feeds `state` and `last_error`.
    pass_started: Mutex<std::collections::HashMap<String, u64>>,
    /// How long each job's last completed pass took — the baseline a stall is
    /// judged against.
    pass_dur: Mutex<std::collections::HashMap<String, u64>>,
    /// D98 — nodes the mover has established that nobody holds, carried across
    /// passes because a `Fetcher` lives for exactly one.
    ///
    /// Cleared every `UNFETCHABLE_RECHECK_PASSES`, so a location repaired by a
    /// scan, a rebind, or an operator is picked up again without a restart —
    /// the memory bounds the noise, it must not become a permanent blindfold.
    tier_unfetchable: Mutex<std::collections::HashSet<String>>,
    tier_passes: std::sync::atomic::AtomicU64,
}

impl JobsState {
    /// Read `serve.jobs` and build the initial rows. A missing file is a
    /// valid empty config; a corrupt one refuses daemon start — better loud
    /// at startup than a box silently running zero jobs.
    pub fn load(data_dir: PathBuf) -> Result<JobsState, PvfsError> {
        let s = JobsState {
            data_dir,
            rows: Mutex::new(Vec::new()),
            started_ms: now_ms(),
            nudge_sync: AtomicBool::new(false),
            nudge_export: AtomicBool::new(false),
            nudge_evict: AtomicBool::new(false),
            nudge_tier: AtomicBool::new(false),
            pass_started: Mutex::new(std::collections::HashMap::new()),
            pass_dur: Mutex::new(std::collections::HashMap::new()),
            tier_unfetchable: Mutex::new(std::collections::HashSet::new()),
            tier_passes: std::sync::atomic::AtomicU64::new(0),
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
                    // D123 — a job that was just disabled has no current
                    // error to report; a job that stays as it was keeps its.
                    last_error: if !en && prev.is_some_and(|p| p.enabled) {
                        None
                    } else {
                        prev.and_then(|p| p.last_error.clone())
                    },
                }
            })
            .collect();
        Ok(())
    }

    pub fn snapshot(&self) -> Vec<ServeJobWire> {
        // D78 — a job that has been "running" for far longer than its own
        // interval is STALLED, and must say so.
        //
        // `running` with a healthy-looking row is how this hid: production
        // feederbox sat 6.4 hours past its last completed pass, and a lab box
        // 40+ minutes, both reporting `running` with no error while doing
        // nothing at all. The underlying cause was a socket read that could
        // never end (fixed separately), but the REPORTING is the part that let
        // it go unnoticed — and the next cause will be different.
        //
        // Derived at read time rather than tracked, so nothing has to remember
        // to set it.
        let now = now_ms();
        self.rows
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .map(|mut r| {
                let since = r.last_ok_ms.unwrap_or(self.started_ms);
                // D81 — a pass IN FLIGHT far past this job's own typical
                // duration is the sharp signal; time since the last completed
                // pass is the blunt one, and for a continuous watcher it is
                // mostly a measure of how quiet the library has been.
                let in_flight = self.pass_started.lock().unwrap().get(&r.name).copied();
                let typical = self.pass_dur.lock().unwrap().get(&r.name).copied();
                if r.state == "running" {
                    if let Some(started) = in_flight {
                        if let Some(why) =
                            pass_stalled_reason(started, now, typical, stall_floor(&r.name))
                        {
                            r.state = "stalled".into();
                            r.last_error = Some(why);
                            return r;
                        }
                    }
                }
                if let Some(why) = stalled_reason(
                    &r.state,
                    since,
                    now,
                    interval(&r.name),
                    stall_floor(&r.name),
                ) {
                    // D100 — `overdue`, not `stalled`. See `stalled_reason`:
                    // this branch has no evidence the job is wedged, only that
                    // no pass has finished lately, and on a library this size
                    // that is the normal state of a healthy long pass.
                    r.state = "overdue".into();
                    r.last_error = Some(why);
                }
                r
            })
            .collect()
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

    /// A pass has begun (D81). What makes "wedged" distinguishable from
    /// "quiet": a watcher waiting for its next reconcile has no pass in flight.
    fn mark_pass_start(&self, name: &str) {
        self.pass_started
            .lock()
            .unwrap()
            .insert(name.to_string(), now_ms());
    }

    /// A pass has ended; remember how long this job's passes take.
    fn mark_pass_end(&self, name: &str) {
        if let Some(start) = self.pass_started.lock().unwrap().remove(name) {
            self.pass_dur
                .lock()
                .unwrap()
                .insert(name.to_string(), now_ms().saturating_sub(start));
        }
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
            // D123 — a pass that ends after its job was disabled does not
            // resurrect the row: `disabled` stands (the reload wrote it), and
            // a pass cut short has no error worth reporting either.
            if issue.is_none() {
                r.last_ok_ms = Some(now_ms());
            }
            if r.enabled {
                r.state = "idle".into();
                r.last_error = issue;
            } else {
                r.state = "disabled".into();
                r.last_error = None;
            }
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
                let r = watch::run(&data_dir, WATCH_RECONCILE.as_secs(), 2000, &flag, |ev| match ev {
                    WatchEvent::PassStarted => cb.mark_pass_start("watch"),
                    WatchEvent::Ingested(ref folder, a, c, rm, un) => {
                        cb.mark_pass_end("watch");
                        cb.mark_ok("watch");
                        // D111 — SAY WHAT THE PASS DID. This job is how the
                        // fleet actually scans, and it reported its numbers to
                        // nobody: the counts went into the status row's
                        // liveness bookkeeping and were then dropped. So the
                        // one place a scan can now take files out of the tree
                        // (D105) was the one place with no record of it, and
                        // "how many did that unlink?" could only be answered
                        // by diffing the forest before and after.
                        if a + c + rm + un > 0 {
                            eprintln!(
                                "pvfsd: watch ingested {folder}: \
                                 +{a} changed {c} removed {rm} unlinked {un}"
                            );
                        }
                        if a + c + rm > 0 {
                            // local ingest = new content: views, placed
                            // subtrees, the mover — all should wake
                            cb.nudge_content();
                            cb.nudge_tier();
                        }
                    }
                    // D81 — a clean pass with nothing to do is progress.
                    WatchEvent::Quiet => {
                        cb.mark_pass_end("watch");
                        cb.mark_ok("watch");
                    }
                    WatchEvent::ScanError(e) => {
                        cb.mark_pass_end("watch");
                        cb.mark_retry("watch", &e);
                    }
                    WatchEvent::Watching(..) => cb.set_state("watch", "running"),
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
fn sync_pass(
    state: &JobsState,
    cancel: Arc<AtomicBool>,
) -> Result<(u64, Vec<(String, String)>), PvfsError> {
    let data_dir = state.data_dir().clone();
    let roots = pvfs_core::sync::load_placement(&data_dir)?;
    if roots.is_empty() {
        return Ok((0, Vec::new()));
    }
    let mut engine = pvfs_core::Engine::open(&data_dir)?;
    // D102 — `sync` gets the SAME memory `tier` has. It never did: this
    // Fetcher was built bare, so D98's "stop asking a question already
    // answered nowhere" did not apply to it. Enabling `sync` on the
    // production holder brought the whole not_found retry storm straight back
    // through a job that had never been given the fix — the sibling-gap shape
    // this project keeps finding. D122: one constructor carries it, so the
    // next sibling cannot miss it.
    let mut fetcher = pvfs_client::fetch::Fetcher::with_memory(&engine, &data_dir);
    fetcher.set_cancel(cancel);
    let r = pvfs_client::fetch::sync_pull(&mut engine, &mut fetcher, &roots);
    fetcher.persist_learned(&engine);
    let is_replica = engine.is_replica();
    engine.close()?;
    // F5.5: advertise fetched copies for `sync --advertise` subtrees — the
    // same shared pass as the CLI; per-file skips ride the job status, a
    // pass-level failure (e.g. no pin yet) is the job's error.
    if r.is_ok() {
        let mut route_pair = pvfs_client::advertise::replica_route(&data_dir, is_replica)?;
        let route = route_pair
            .as_mut()
            .map(|(c, s)| (&mut *c, &**s as &dyn Fn(&[u8; 32]) -> Vec<u8>));
        pvfs_client::advertise::advertise_pass(&data_dir, route)?;
    }
    r
}

/// One export pass: re-run every kept-fresh export (`pvfs export
/// --keep-fresh`), fetching first where the entry asked for it.
fn export_pass(state: &JobsState, cancel: Arc<AtomicBool>) -> Result<u64, PvfsError> {
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
            let f = fetcher.get_or_insert_with(|| {
                let mut f = pvfs_client::fetch::Fetcher::with_memory(&engine, &data_dir);
                f.set_cancel(Arc::clone(&cancel));
                f
            });
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
    // This flag used to be bookkeeping only — "passes are short" — and no pass
    // ever received it. That held for sync/evict/reclaim and was badly wrong
    // for `tier`, which moves hundreds of GB across a WAN. On 2026-08-24 a
    // signalled daemon closed both listeners and then sat for the better part
    // of an hour finishing a 14.7GB fetch, serving nothing the whole time.
    // The mover now gets the flag and honours it (D83).
    let stop = Arc::new(AtomicBool::new(false));
    let st = Arc::clone(state);
    // D123 — every pass gets the flag; the runner sets it when the job is
    // disabled mid-pass (and at shutdown, as before).
    let cancel = Arc::clone(&stop);
    let handle = match name {
        "sync" => std::thread::spawn(move || {
            st.set_state("sync", "running");
            match sync_pass(&st, cancel) {
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
            match export_pass(&st, cancel) {
                Ok(_) => st.mark_pass("export", None),
                Err(e) => st.mark_pass("export", Some(e.to_string())),
            }
        }),
        "tier" => {
            let cancel = Arc::clone(&stop);
            std::thread::spawn(move || {
            st.set_state("tier", "running");
            let r = (|| -> Result<Option<pvfs_client::fetch::TierReport>, PvfsError> {
                let mut engine = pvfs_core::Engine::open(st.data_dir())?;
                let mut fetcher = pvfs_client::fetch::Fetcher::new(st.data_dir());
                fetcher.set_cancel(cancel);
                // D98 — carry what we already know is nowhere into this pass,
                // and periodically forget it so a repaired catalog recovers.
                let n = st
                    .tier_passes
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    // D99 — the FIRST pass of a daemon lifetime reads what
                    // earlier runs learned. Held only in memory, this set died
                    // with every restart, and the pass that followed spent
                    // eight hours re-asking ~24k holders a question already
                    // answered "nobody". n == 0 also satisfies the periodic
                    // clear below, so it must be handled first or a restart
                    // would wipe the very memory it should be loading.
                    let known = engine.unfetchable_load().unwrap_or_default();
                    let mut mem = st.tier_unfetchable.lock().unwrap();
                    mem.extend(known.iter().cloned());
                    fetcher.seed_unfetchable(mem.iter().cloned());
                } else if n.is_multiple_of(UNFETCHABLE_RECHECK_PASSES) {
                    // periodic amnesia, so a repaired catalog gets a fresh
                    // hearing — now clearing the durable copy too, or the
                    // next restart would resurrect what we just forgave.
                    st.tier_unfetchable.lock().unwrap().clear();
                    let _ = engine.unfetchable_clear();
                } else {
                    fetcher.seed_unfetchable(
                        st.tier_unfetchable.lock().unwrap().iter().cloned(),
                    );
                }
                let r = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher);
                // Persist only what THIS pass newly learned (D122: the fetcher
                // knows what it was seeded with), and carry it in the job's
                // own memory for the passes until the next amnesia.
                let learned = fetcher.persist_learned(&engine);
                st.tier_unfetchable.lock().unwrap().extend(learned);
                engine.close()?;
                r
            })();
            match r {
                // None = nothing placed central — a clean idle pass
                Ok(report) => {
                    // D83 — a CANCELLED pass reports no verdict. Its `failed`
                    // list is mostly its own abandoned fetches, and recording
                    // those makes an orderly stop look like a broken mover.
                    let issue = report.and_then(|t| {
                        if t.cancelled {
                            return None;
                        }
                        t.failed.first().map(|(label, e)| {
                            format!("{} migrations failed (first: {label} — {e})", t.failed.len())
                        })
                    });
                    st.mark_pass("tier", issue);
                }
                Err(e) => st.mark_pass("tier", Some(e.to_string())),
            }
            })
        }
        // D71 W2/W3: the holder tidies its own filesystem after a delete. The
        // mount retires the link from whatever box the user is on; the box
        // that owns the BYTES moves them to the trash. The owner never reaches
        // across NFS to delete something on the NAS.
        // D127 (doc 26 §7.3) — resolve the merged view's conflicts and
        // redundancies for the draining regions THIS box owns: the losing copy
        // goes to that region's trash; nothing on a library region is touched.
        "health" => std::thread::spawn(move || {
            st.set_state("health", "running");
            // D142 — the record BEFORE this poll, so what changed can be told.
            let prev = pvfs_client::health::FleetHealth::load(st.data_dir()).ok().flatten();
            match pvfs_client::health::poll_fleet(st.data_dir(), &cancel) {
                Ok(mut rec) => {
                    for (pin, r) in rec.down() {
                        eprintln!(
                            "pvfsd: health: {} ({}) not answering since {} — {}",
                            &pin[..8],
                            r.addr,
                            r.unreachable_since_ms.unwrap_or(0),
                            r.last.error.as_deref().unwrap_or("no detail")
                        );
                    }
                    // D135 — act on silence for the peers this box supervises.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    match pvfs_client::supervise::act_on_down(st.data_dir(), &mut rec, now) {
                        Ok(done) => {
                            for (pin, a) in &done {
                                eprintln!("pvfsd: supervise: sent start to {} → rc {} {:?}", &pin[..8], a.rc, a.output);
                            }
                            if !done.is_empty() {
                                if let Err(e) = rec.save(st.data_dir()) {
                                    eprintln!("pvfsd: supervise: record not saved: {e}");
                                }
                            }
                            // D142 — tell a person, on transitions only; a
                            // failure to notify never fails the pass.
                            match pvfs_client::notify::emit(st.data_dir(), prev.as_ref(), &rec, now) {
                                Ok(sent) => {
                                    for l in &sent {
                                        eprintln!("pvfsd: notify: {l}");
                                    }
                                }
                                Err(e) => eprintln!("pvfsd: notify: {e}"),
                            }
                            st.mark_pass("health", None)
                        }
                        Err(e) => st.mark_pass("health", Some(e.to_string())),
                    }
                }
                Err(e) => st.mark_pass("health", Some(e.to_string())),
            }
        }),
        "catalogue" => std::thread::spawn(move || {
            st.set_state("catalogue", "running");
            let r = pvfs_client::catalogue::fetch_pass(st.data_dir(), &cancel);
            match r {
                Ok(rep) => {
                    for (region, seq, n) in &rep.fetched {
                        eprintln!("pvfsd: catalogue {} at head {seq}: {n} rows", &region[..8]);
                    }
                    for (region, why) in &rep.failed {
                        eprintln!("pvfsd: catalogue {}: {why}", &region[..8]);
                    }
                    st.mark_pass("catalogue", None)
                }
                Err(e) => st.mark_pass("catalogue", Some(e.to_string())),
            }
        }),
        "receive" => std::thread::spawn(move || {
            st.set_state("receive", "running");
            let r = pvfs_client::receive::receive_pass(
                st.data_dir(),
                &pvfs_core::media::Rules::default(),
                false,
                pvfs_client::receive::MIN_FREE_BYTES,
                &cancel,
            );
            match r {
                Ok(rep) => {
                    for (p, h, _) in &rep.received {
                        eprintln!("pvfsd: received {p} ({}) into the library (doc 26 §7.3)", &h[..8]);
                    }
                    for p in &rep.skipped_no_space {
                        eprintln!("pvfsd: receive: no space for {p}");
                    }
                    for (p, why) in &rep.failed {
                        eprintln!("pvfsd: receive: {p}: {why}");
                    }
                    st.mark_pass("receive", None)
                }
                Err(e) => st.mark_pass("receive", Some(e.to_string())),
            }
        }),
        "resolve" => std::thread::spawn(move || {
            st.set_state("resolve", "running");
            let r = (|| -> Result<(pvfs_core::ResolveReport, u64), PvfsError> {
                let mut engine = pvfs_core::Engine::open(st.data_dir())?;
                let r = engine.resolve_conflicts(&pvfs_core::media::Rules::default(), false, &cancel)?;
                // D133 — then free what retention allows.
                let purged: u64 = engine.purge_draining_trash()?.iter().map(|(_, p)| p.removed).sum();
                engine.close()?;
                Ok((r, purged))
            })();
            match r {
                Ok((rep, purged)) => {
                    if !rep.trashed.is_empty() {
                        eprintln!("pvfsd: resolve trashed {} losing copies", rep.trashed.len());
                    }
                    if purged > 0 {
                        eprintln!("pvfsd: resolve purged {purged} trash buckets past retention");
                    }
                    st.mark_pass("resolve", None)
                }
                Err(e) => st.mark_pass("resolve", Some(e.to_string())),
            }
        }),
        "reclaim" => std::thread::spawn(move || {
            st.set_state("reclaim", "running");
            let r = (|| -> Result<pvfs_core::sync::TrashPurge, PvfsError> {
                let engine = pvfs_core::Engine::open(st.data_dir())?;
                let r = pvfs_core::sync::reclaim_pass(&engine, st.data_dir(), &cancel);
                engine.close()?;
                r
            })();
            match r {
                Ok(_) => st.mark_pass("reclaim", None),
                Err(e) => st.mark_pass("reclaim", Some(e.to_string())),
            }
        }),
        "evict" => std::thread::spawn(move || {
            st.set_state("evict", "running");
            let r = (|| -> Result<pvfs_core::sync::EvictReport, PvfsError> {
                // F5.5: retract de-placed advertised copies before the
                // classic pass — never delete under a live advertisement.
                let probe = pvfs_core::Engine::open(st.data_dir())?;
                let is_replica = probe.is_replica();
                probe.close()?;
                let mut route_pair =
                    pvfs_client::advertise::replica_route(st.data_dir(), is_replica)?;
                let route = route_pair
                    .as_mut()
                    .map(|(c, s)| (&mut *c, &**s as &dyn Fn(&[u8; 32]) -> Vec<u8>));
                let _ = pvfs_client::advertise::retract_pass(st.data_dir(), route)?;
                let mut engine = pvfs_core::Engine::open(st.data_dir())?;
                let r = pvfs_core::sync::evict_pass(&mut engine, &cancel);
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

/// Is a job that claims to be `running` actually stuck?
///
/// Pure so it can be tested: the bug this exists to catch is a job reporting
/// `running` forever, and a stall detector that is itself never exercised is
/// the same failure one level up.
///
/// `since` is the last COMPLETED pass, or the runner's start for a job that has
/// never finished one — which is exactly the shape a first-run hang produces.
/// A pass that is RUNNING RIGHT NOW and has taken far longer than this job's
/// passes normally take (D81).
///
/// `stalled_reason` measures time since the last COMPLETED pass, which is the
/// right question for an interval job and the wrong one for a continuous
/// watcher: an idle watcher legitimately completes nothing for a whole
/// reconcile. Keying its threshold off the reconcile interval instead — as I
/// first did — pushed the alarm out to three HOURS, so the wedge I had just
/// been debugging would have gone unreported for an afternoon.
///
/// What actually distinguishes "wedged" from "quiet" is whether a pass is in
/// flight. A watcher waiting for the next reconcile has none; a watcher stuck
/// on a socket that never returns has one, and it is old. The threshold comes
/// from the job's own observed pass duration, so a fleet with a 27,000-file
/// library and one with 2,000 are each judged against themselves.
pub fn pass_stalled_reason(
    started_ms: u64,
    now_ms: u64,
    typical_ms: Option<u64>,
    floor: Duration,
) -> Option<String> {
    let running_for = now_ms.saturating_sub(started_ms);
    let limit = typical_ms
        .map(|t| t.saturating_mul(STALL_FACTOR))
        .unwrap_or(0)
        .max(floor.as_millis() as u64);
    if running_for <= limit {
        return None;
    }
    Some(match typical_ms {
        Some(t) => format!(
            "a pass has been running {}s; this job's passes normally take {}s — it is stuck, not working",
            running_for / 1000,
            t / 1000
        ),
        None => format!(
            "the first pass has been running {}s and has never completed",
            running_for / 1000
        ),
    })
}

/// The floor under `pass_stalled_reason`, so a job whose passes are quick is
/// not flagged for a momentary hiccup.
pub const PASS_STALL_FLOOR: Duration = Duration::from_secs(300);

/// D85 — how long THIS job may legitimately run before silence is suspicious.
///
/// The floor only bites when a job has never completed a pass, because
/// `typical` is learned from completions. For most jobs that is fine: they
/// finish in seconds, so a first pass over five minutes really is stuck.
///
/// For two jobs it was badly wrong, and they are the two that matter most:
///
/// * `tier` moves hundreds of GB across a WAN. A real pass is hours.
/// * `watch` now hashes what it finds unhashed (D85), so a first pass over a
///   grown library is bounded by reading the whole library — measured at
///   roughly 110 files/hour against ~67 TB, which is DAYS.
///
/// Both therefore reported `stalled` permanently while working perfectly, and
/// a detector that cries wolf on healthy work is worse than none — it is
/// exactly the false alarm that would make D83's monitoring untrustworthy the
/// day it ships. The comment on `interval()` already said it: a job's stall
/// threshold has to be derived from what that job actually does.
pub fn stall_floor(name: &str) -> Duration {
    match name {
        "tier" => Duration::from_secs(6 * 3600),
        // D133 — a receive pass can move a night's downloads, like tier.
        "receive" => Duration::from_secs(6 * 3600),
        "watch" => Duration::from_secs(36 * 3600),
        _ => PASS_STALL_FLOOR,
    }
}

pub fn stalled_reason(
    state: &str,
    since_ms: u64,
    now_ms: u64,
    every: Duration,
    floor: Duration,
) -> Option<String> {
    if state != "running" {
        return None;
    }
    // D96 — the floor applies HERE too, not only to the in-flight check.
    //
    // D85 added `stall_floor` because tier and watch legitimately run for hours
    // or days, and wired it into `pass_stalled_reason`. But that one only fires
    // when a pass is in flight; execution then falls through to THIS blunt
    // check, which was still judging by `interval * 3`. For tier that is 300s
    // * 3 = 15 minutes against passes its own documentation calls "hours", so
    // the wolf-crying D85 set out to stop carried straight on through the
    // fallback — seen on the live holder as tier "stalled" at 34 min and watch
    // at 464 min, both while working perfectly.
    let limit = ((every.as_millis() as u64).saturating_mul(STALL_FACTOR))
        .max(floor.as_millis() as u64);
    let waited = now_ms.saturating_sub(since_ms);
    if waited <= limit {
        return None;
    }
    // D100 — say what is OBSERVED, and stop asserting what is not known.
    //
    // This check sees one thing: no pass has completed for a while. It cannot
    // see whether the job is working, because nothing reports progress WITHIN a
    // pass. Claiming "the pass is stuck, not working" turned that single
    // observation into a diagnosis, and the diagnosis was wrong every time it
    // fired on the live holder — three times, against a `watch` steadily
    // writing sidecars and a `tier` steadily fetching.
    //
    // The state is `overdue`, not `stalled`. `stalled` is reserved for
    // `pass_stalled_reason`, which HAS evidence: a pass in flight far past this
    // job's own measured typical duration.
    //
    // The real fix is a progress signal — files hashed, bytes moved — plumbed
    // out of `scan_routed` and `tier_pass` so a long pass that is advancing can
    // be told from one that is wedged. That is a cross-crate change to core's
    // API and belongs in its own milestone; this one stops the lying.
    Some(format!(
        "no pass has completed in {} min (interval is {}s) — overdue, which is \
         not the same as stuck: nothing here reports progress within a pass",
        waited / 60_000,
        every.as_secs()
    ))
}

fn interval(name: &str) -> Duration {
    match name {
        "sync" => SYNC_INTERVAL,
        "reclaim" => EVICT_INTERVAL,
        // D127 — resolution runs on the evict cadence: what it trashes is what
        // a scan then drops, and there is no hurry a conflict cannot wait.
        "resolve" => EVICT_INTERVAL,
        "catalogue" => CATALOGUE_INTERVAL,
        "health" => HEALTH_INTERVAL,
        "receive" => RECEIVE_INTERVAL,
        "export" => EXPORT_INTERVAL,
        "tier" => TIER_INTERVAL,
        // D81 — `watch` is CONTINUOUS: inotify-driven, with a reconcile as the
        // safety net. It had no arm here, so it fell through to 300s and the
        // detector policed a 15-minute deadline against an HOURLY cadence.
        // A job's stall threshold has to be derived from what that job actually
        // does, or the detector measures a number nobody chose.
        "watch" => WATCH_RECONCILE,
        _ => EVICT_INTERVAL,
    }
}

/// The supervisor loop. Polls `reload` (SIGHUP) and `shutdown` (SIGTERM/INT);
/// reconciles configured jobs against live threads each tick; a failed reload
/// keeps the previous config and logs — a running fleet box must not lose its
/// jobs to a half-edited file.
pub fn run(
    state: Arc<JobsState>,
    shutdown: &AtomicBool,
    reload: &AtomicBool,
    daemon: Option<Arc<crate::Daemon>>,
) {
    let mut running: HashMap<String, Managed> = HashMap::new();
    let mut draining: Vec<Managed> = Vec::new();
    let mut retry_at: HashMap<String, Instant> = HashMap::new();
    let mut next_due: HashMap<String, Instant> = HashMap::new();
    let jobs_file = serve::jobs_path(state.data_dir());
    let mtime_of = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();
    let mut last_mtime = mtime_of(&jobs_file);
    // P7.2b (doc 20 §2.4): keep region heads attested at rest. Gated on the
    // regions dir existing (created lazily by the first region write), so
    // region-free forests never pay the transient open.
    const HEADS_EVERY: Duration = Duration::from_secs(60);
    let mut heads_at = Instant::now() + HEADS_EVERY;

    while !shutdown.load(Ordering::SeqCst) {
        if Instant::now() >= heads_at {
            heads_at = Instant::now() + HEADS_EVERY;
            if state.data_dir().join("regions").exists() {
                // through the daemon's own engine — never a second one
                if let Some(d) = &daemon {
                    let _ = d.commit_region_heads();
                }
            }
        }
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
                let ready = retry_at.get(name).is_none_or(|t| Instant::now() >= *t);
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
                // D123 — a disabled job STOPS: a live pass gets its flag and
                // drains, exactly as a continuous job does. Before this the
                // pass ran to its natural end — hours, for a sync over a
                // backlog — and then wrote `idle` onto a disabled row.
                if let Some(m) = running.remove(name) {
                    m.stop.store(true, Ordering::SeqCst);
                    draining.push(m);
                }
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
            let due = next_due.get(name).is_none_or(|t| Instant::now() >= *t);
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
