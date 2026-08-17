//! The P1 watcher, shared (punch E, doc 18 §2 as-built note resolved): live
//! indexing of bound folders + scheduled reconciliation, drivable as the
//! daemon's `watch` job or the CLI's foreground `pvfs serve watch`. One
//! implementation, two drivers — the follow/fetch pattern.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use pvfs_core::{Engine, PvfsError};

/// Progress callbacks: stdout lines in the CLI, status rows in pvfsd.
pub enum WatchEvent {
    /// A scan pass ingested changes: (folder_id, added, changed, removed).
    Ingested(String, u64, u64, u64),
    /// A scan pass failed; the loop keeps watching.
    ScanError(String),
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
    stop: &AtomicBool,
    mut notify_cb: impl FnMut(WatchEvent),
) -> Result<(), PvfsError> {
    let lock_path = data_dir.join("serve.lock");
    let _lock = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|e| PvfsError::BadInput {
            field: "watch".into(),
            reason: format!(
                "another watcher may be running ({}): {e} — delete the file if stale",
                lock_path.display()
            ),
        })?;
    let result = (|| {
        let mut engine = Engine::open(data_dir)?;
        // D71 W4: on a replica the catalog writes go to the owner's daemon —
        // this box has no local writer. The route is opened once and reused
        // for every pass; if the owner is unreachable the watcher starts
        // anyway and each pass reports the failure, because a scan is
        // idempotent and the NEXT pass repairs it with nobody involved.
        let is_replica = engine.is_replica();
        let mut route = crate::advertise::replica_route(data_dir, is_replica).unwrap_or(None);
        // initial reconciliation
        match scan_pass(&mut engine, &mut route) {
            Ok(reports) => {
                for r in &reports {
                    notify_cb(WatchEvent::Ingested(
                        r.folder_id.clone(),
                        r.stats.added,
                        r.stats.changed,
                        r.stats.removed,
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
            if due_debounce || due_reconcile {
                dirty_since = None;
                last_reconcile = Instant::now();
                match scan_pass(&mut engine, &mut route) {
                    Ok(reports) => {
                        for r in reports
                            .iter()
                            .filter(|r| r.stats.added + r.stats.changed + r.stats.removed > 0)
                        {
                            notify_cb(WatchEvent::Ingested(
                                r.folder_id.clone(),
                                r.stats.added,
                                r.stats.changed,
                                r.stats.removed,
                            ));
                        }
                    }
                    Err(e) => notify_cb(WatchEvent::ScanError(e.to_string())),
                }
            }
        }
        engine.close()
    })();
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
    match route {
        Some((client, sign)) => {
            let signer: &dyn Fn(&[u8; 32]) -> Vec<u8> = &**sign;
            let mut w = crate::advertise::RoutedScanWriter::new(client, signer);
            let reports = engine.scan_routed(None, Some(&mut w))?;
            // Read-your-writes — the same F5.0 precedent `advertise` follows.
            // A routed write lands in the OWNER's log, and this box does not
            // see it until the tail is folded here. Skip this and the next
            // pass cannot find the folder it just created, so it makes a
            // second one: the D71 lab produced two `Season 03` nodes exactly
            // this way before the catch-up was added.
            if reports
                .iter()
                .any(|r| r.stats.added + r.stats.changed + r.stats.removed > 0)
            {
                crate::advertise::catch_up(engine.data_dir(), client);
            }
            Ok(reports)
        }
        None => engine.scan(None),
    }
}
