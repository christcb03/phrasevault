//! The P1 watcher, shared (punch E, doc 18 §2 as-built note resolved): live
//! indexing of bound folders + scheduled reconciliation, drivable as the
//! daemon's `watch` job or the CLI's foreground `pvfs serve watch`. One
//! implementation, two drivers — the follow/fetch pattern.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use pvfs_core::{Engine, PvfsError};

/// How soon a failed pass tries again, and the ceiling it backs off to.
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);
/// A file deferred as "still being written" needs a pass AFTER it settles —
/// the last write is also the last inotify event, so nothing else would.
const SETTLE_RECHECK: Duration = Duration::from_secs(20);

/// Progress callbacks: stdout lines in the CLI, status rows in pvfsd.
pub enum WatchEvent {
    /// A scan pass ingested changes:
    /// (folder_id, added, changed, removed, unlinked).
    ///
    /// D111 — `unlinked` is the fifth field because D105 made a scan able to
    /// take a file OUT OF THE TREE, not merely retire its location, and this
    /// event is the only thing the daemon's watch job reports. Without it the
    /// operation that changes the shape of the forest is the one operation
    /// nobody can see: `removed` counts retired locations, and a node dropped
    /// from the tree looks identical to a location going away on a box that
    /// still holds a copy elsewhere.
    Ingested(String, u64, u64, u64, u64),
    /// A scan pass failed; the loop keeps watching.
    ScanError(String),
    /// A scan pass has BEGUN (D81) — what lets the daemon tell a wedged
    /// watcher from a quiet one.
    PassStarted,
    /// A scan pass completed and found nothing to do.
    ///
    /// D81 — a pass that finds nothing IS a completed pass, and used to say so
    /// to no one: `Ingested` was the only progress signal and it is filtered to
    /// passes that changed something. So an idle watcher marked no progress for
    /// up to a whole reconcile interval and the stall detector called it stuck.
    Quiet,
    /// Watching started: (folders watched here, bindings skipped as another
    /// machine's). The second number matters — on a replica it is normal for
    /// most of the forest's bindings to belong elsewhere, and "watching 0"
    /// with no explanation reads like a broken watcher (D71 W1).
    Watching(usize, usize),
}

/// Run the watcher until `stop` is set. Holds `serve.lock` in the data dir —
/// a second watcher on the same forest errors instead of double-scanning.
pub fn run(
    data_dir: &Path,
    reconcile_secs: u64,
    debounce_ms: u64,
    stop: &std::sync::Arc<AtomicBool>,
    mut notify_cb: impl FnMut(WatchEvent),
) -> Result<(), PvfsError> {
    // D86 — liveness, not existence.
    //
    // This used to be `create_new`, so the LOCK WAS THE FILE: any watcher that
    // died without unlinking it — a crash, an OOM kill, the `kill -9` it takes
    // to roll a daemon that will not stand down — left the next one refusing to
    // start, forever, with "delete the file if stale". The box then looks
    // rolled and healthy while doing NO scanning at all, which is exactly what
    // the NAS holder did after its swap: `watch error`, a lock file dated two
    // days earlier, and nothing hashing.
    //
    // An flock is released by the KERNEL when the holder dies, so a stale lock
    // cannot exist — the same reason `writer.lock` is one. The file is now just
    // somewhere to hang the lock; whether it already exists means nothing.
    let lock_path = data_dir.join("serve.lock");
    let lock_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| PvfsError::io("open serve.lock", e))?;
    let _lock = nix::fcntl::Flock::lock(lock_file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| PvfsError::BadInput {
            field: "watch".into(),
            reason: format!(
                "another watcher IS running and holds {} ({e}) — this is liveness, \
                 not a leftover file, so deleting it will not help",
                lock_path.display()
            ),
        })?;
    let result = (|| {
        let mut engine = Engine::open(data_dir)?;
        // D86 — the same flag the loop below checks, handed to the engine so a
        // pass ALREADY RUNNING can be abandoned. Without this the loop condition
        // is only consulted between passes, and a pass is a whole library: the
        // NAS holder ignored SIGTERM for hours, which is why it could not be
        // rolled.
        engine.set_cancel(std::sync::Arc::clone(stop));
        // D71 W4: on a replica the catalog writes go to the owner's daemon —
        // this box has no local writer. If the owner is unreachable the
        // watcher starts anyway and each pass reports the failure, because a
        // scan is idempotent and the NEXT pass repairs it with nobody
        // involved. A failed pass DROPS the route so the following one
        // reconnects (see the Err arm) — an owner restart would otherwise
        // wedge this box permanently.
        let is_replica = engine.is_replica();
        let mut route = crate::advertise::replica_route(data_dir, is_replica).unwrap_or(None);
        // initial reconciliation
        notify_cb(WatchEvent::PassStarted);
        match scan_pass(&mut engine, &mut route) {
            Ok(reports) => {
                for r in &reports {
                    notify_cb(WatchEvent::Ingested(
                        r.folder_id.clone(),
                        r.stats.added,
                        r.stats.changed,
                        r.stats.removed,
                        r.stats.unlinked,
                    ));
                }
            }
            Err(e) => notify_cb(WatchEvent::ScanError(e.to_string())),
        }

        let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
        let mut watcher = notify::recommended_watcher(tx).map_err(|e| PvfsError::BadInput {
            field: "watcher".into(),
            reason: e.to_string(),
        })?;
        let mut watching = 0usize;
        // THIS machine's bindings only (D71 W1). A binding made on another box
        // names a directory that does not exist here, so registering a watch on
        // it fails — which used to abort the whole watcher on any replica.
        let local = engine.local_bindings()?;
        let elsewhere = engine.bindings()?.len() - local.len();
        for b in local {
            if !b.auto_index {
                continue;
            }
            let path = pvfs_core::storage::uri_to_path(&b.source_uri)?;
            notify::Watcher::watch(
                &mut watcher,
                &path,
                if b.recursive {
                    notify::RecursiveMode::Recursive
                } else {
                    notify::RecursiveMode::NonRecursive
                },
            )
            .map_err(|e| PvfsError::BadInput {
                field: "watcher".into(),
                reason: format!("{}: {e}", path.display()),
            })?;
            watching += 1;
        }
        notify_cb(WatchEvent::Watching(watching, elsewhere));

        let debounce = Duration::from_millis(debounce_ms);
        let reconcile_every = Duration::from_secs(reconcile_secs.max(1));
        let mut dirty_since: Option<Instant> = None;
        let mut last_reconcile = Instant::now();
        // A failed pass must come back SOON, not at the next reconcile — that
        // is an hour on the daemon, which is no kind of autocorrect. A scan is
        // idempotent, so retrying is free of consequence; back off so a
        // genuinely stuck forest does not spin.
        let mut retry_at: Option<Instant> = None;
        let mut backoff = RETRY_MIN;

        while !stop.load(Ordering::SeqCst) {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(_) => dirty_since = Some(Instant::now()),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            let due_debounce = dirty_since
                .map(|t| t.elapsed() >= debounce)
                .unwrap_or(false);
            let due_reconcile = last_reconcile.elapsed() >= reconcile_every;
            let due_retry = retry_at.is_some_and(|t| Instant::now() >= t);
            if due_debounce || due_reconcile || due_retry {
                dirty_since = None;
                last_reconcile = Instant::now();
                notify_cb(WatchEvent::PassStarted);
                match scan_pass(&mut engine, &mut route) {
                    Ok(reports) => {
                        retry_at = None;
                        backoff = RETRY_MIN;
                        // D71 W6: files still being written were deferred, not
                        // dropped. Nothing will re-trigger us once the copy
                        // stops (the last inotify event is the last write), so
                        // schedule the pass that will pick them up.
                        if reports.iter().any(|r| r.stats.settling > 0) {
                            retry_at = Some(Instant::now() + SETTLE_RECHECK);
                        }
                        let mut said_something = false;
                        for r in reports.iter().filter(|r| {
                            r.stats.added + r.stats.changed + r.stats.removed + r.stats.unlinked
                                > 0
                        }) {
                            said_something = true;
                            notify_cb(WatchEvent::Ingested(
                                r.folder_id.clone(),
                                r.stats.added,
                                r.stats.changed,
                                r.stats.removed,
                                r.stats.unlinked,
                            ));
                        }
                        // The pass ran cleanly either way — say so, so progress
                        // does not depend on the library happening to change.
                        if !said_something {
                            notify_cb(WatchEvent::Quiet);
                        }
                    }
                    Err(e) => {
                        // Loud, and self-correcting: say so, then come back
                        // shortly rather than waiting out the reconcile.
                        notify_cb(WatchEvent::ScanError(e.to_string()));
                        // DROP THE ROUTE so the next pass reconnects.
                        //
                        // The connection was opened once at startup, and an
                        // owner restart kills it — which happens on every
                        // upgrade. Retrying against a dead socket cannot
                        // succeed no matter how patient we are, and because
                        // the failure text says "closed" it is classified
                        // transient and retried forever. The lab wedged
                        // exactly this way: the owner restarted twice, and the
                        // ingest box never catalogued another file until its
                        // OWN daemon was restarted.
                        //
                        // Reconnecting is cheap and idempotent, so pay it on
                        // any failure rather than trying to tell "the owner is
                        // busy" from "the socket is gone" through a string.
                        route = None;
                        retry_at = Some(Instant::now() + backoff);
                        backoff = (backoff * 2).min(RETRY_MAX);
                    }
                }
            }
        }
        engine.close()
    })();
    // Drop the flock first, then tidy the file away. Order matters: unlinking
    // while still holding it would let a second watcher create a NEW file and
    // take a lock on it, and two watchers would scan the same forest.
    drop(_lock);
    let _ = std::fs::remove_file(&lock_path);
    result
}

/// One reconcile pass, with a replica's writes routed to the owner.
///
/// Failure policy (D71 W4, Chris: *fail loudly, but autocorrect, and only ask
/// for intervention when that isn't possible*):
///
/// * **Transient** — the owner is unreachable, the database is busy, an I/O
///   blip. The pass fails LOUDLY and nothing else happens, because the next
///   pass fixes it by itself: a scan is idempotent by URI, so a half-applied
///   pass is simply redone. Nobody is asked for anything.
/// * **Permanent** — the catalog refuses a file for a reason retrying cannot
///   change. That ONE file is quarantined with its reason, the rest of the pass
///   continues (one bad file never stops the line), and the report says a human
///   is needed. Retrying that forever would be a loop, not a repair.
fn scan_pass(
    engine: &mut Engine,
    route: &mut Option<(crate::Client, crate::advertise::BoxedSign)>,
) -> Result<Vec<pvfs_core::ScanReport>, PvfsError> {
    // Reconnect if a previous pass dropped the route (see the Err arm above).
    // A replica with no route cannot write anything it finds, so failing to
    // reconnect must surface as the pass failing — not as a silent local scan.
    if route.is_none() && engine.is_replica() {
        *route = crate::advertise::replica_route(engine.data_dir(), true)?;
    }
    match route {
        Some((client, sign)) => {
            let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &**sign;
            let mut w =
                crate::advertise::RoutedScanWriter::new(engine.data_dir(), client, signer);
            let reports = engine.scan_routed(None, Some(&mut w), pvfs_core::WATCH_SETTLE_MS)?;
            // Read-your-writes — the same F5.0 precedent `advertise` follows.
            // A routed write lands in the OWNER's log, and this box does not
            // see it until the tail is folded here. Skip this and the next
            // pass cannot find the folder it just created, so it makes a
            // second one: the D71 lab produced two `Season 03` nodes exactly
            // this way before the catch-up was added.
            if reports.iter().any(|r| {
                r.stats.added + r.stats.changed + r.stats.removed + r.stats.unlinked > 0
            }) {
                crate::advertise::catch_up(engine.data_dir(), client);
            }
            Ok(reports)
        }
        None => engine.scan_routed(None, None, pvfs_core::WATCH_SETTLE_MS),
    }
}
