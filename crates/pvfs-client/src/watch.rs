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
    /// Watching started: how many bound folders have live watches.
    Watching(usize),
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
        // initial reconciliation
        match engine.scan(None) {
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
        for b in engine.bindings()? {
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
        notify_cb(WatchEvent::Watching(watching));

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
                match engine.scan(None) {
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
