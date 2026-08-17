//! D71 — the positional probe must not manufacture a phantom rebuild.
//!
//! `index.db` (the applied mark) and `log.db` (the tail) are separate WAL
//! databases, and **SQLite cannot commit across databases atomically when any
//! of them is in WAL mode**. A writer that has just folded event N therefore
//! publishes the mark and the log event in two separate commits, and another
//! connection opening in between sees the mark lead the tail by one — which
//! `startup_check` read as "the log was truncated" and answered with a full
//! replay of the entire projection.
//!
//! Found live on the D69 lab: the fleet owner replayed its whole 59,365-event
//! log every ~25 s, forever, for as long as a serve job wrote beside the
//! daemon, with the mark ahead by EXACTLY 1 every time. Diagnosed only after
//! `full_rebuild` was made to state its reason and then print the two numbers
//! — the bare "rebuilding the index" line reads like the one-time upgrade
//! path, which is what hid this.
//!
//! HONEST LIMIT: `concurrent_writes_do_not_trigger_a_phantom_rebuild` below is
//! a cheap guard, NOT a reproduction — it passes against the unfixed code too,
//! because the visibility window is microseconds wide and a test cannot lean on
//! hitting it. The fix is proven on the lab, where the condition recurs on its
//! own several times a minute (D71 §3c). Do not read a green run here as
//! evidence the bug is gone.
//!
//! `pending_changes` is the rebuild sentinel: it is local observation, never
//! folded from events, and `full_rebuild` drops it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use pvfs_core::{Engine, NodeSpec, TYPE_FOLDER};

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

/// Drop a marker that only a full rebuild removes.
fn plant_sentinel(data_dir: &std::path::Path) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO pending_changes
         (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
         VALUES ('d71-sentinel', 'file:///d71', 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();
}

fn sentinel_alive(data_dir: &std::path::Path) -> bool {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM pending_changes WHERE file_id = 'd71-sentinel'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

/// Cheap guard (see HONEST LIMIT above): opens that race a live writer must
/// not rebuild. Green here is necessary, not sufficient.
#[test]
fn concurrent_writes_do_not_trigger_a_phantom_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    // Enough log to make a rebuild obvious, and to widen the commit window.
    for i in 0..60 {
        engine.add_node(&root, folder(&format!("f{i}"))).unwrap();
    }
    engine.close().unwrap();

    plant_sentinel(dir.path());
    assert!(sentinel_alive(dir.path()), "sentinel must start alive");

    // A writer committing continuously — the live daemon in miniature.
    let stop = Arc::new(AtomicBool::new(false));
    let writer_dir = dir.path().to_path_buf();
    let writer_stop = stop.clone();
    let writer = std::thread::spawn(move || {
        let mut e = Engine::open(&writer_dir).unwrap();
        let root = e.identity.root_node_id.clone();
        let mut n = 0;
        while !writer_stop.load(Ordering::SeqCst) {
            // A transient Busy against the concurrent opens is ordinary lock
            // contention, not the subject of this test — retry and carry on.
            if e.add_node(&root, folder(&format!("w{n}"))).is_ok() {
                n += 1;
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        e.close().unwrap();
        n
    });

    // Transient opens straddling those commits — the serve jobs in miniature.
    std::thread::sleep(std::time::Duration::from_millis(50));
    for _ in 0..25 {
        let e = Engine::open(dir.path()).unwrap();
        e.close().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    stop.store(true, Ordering::SeqCst);
    let written = writer.join().unwrap();
    assert!(written > 0, "the writer must actually have committed");

    assert!(
        sentinel_alive(dir.path()),
        "a projection rebuild happened while a writer was live — the applied \
         mark led the not-yet-visible log tail and was read as a truncated log"
    );
}

/// The check keeps its teeth: a genuinely short log IS a rebuild. Without this
/// the fix above could be "just stop checking", which would let a truncated or
/// swapped log pass silently.
#[test]
fn an_applied_mark_genuinely_past_the_log_still_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    for i in 0..5 {
        engine.add_node(&root, folder(&format!("f{i}"))).unwrap();
    }
    engine.close().unwrap();

    plant_sentinel(dir.path());
    // Shove the applied mark past the real tail, the way a truncated log looks.
    {
        let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        conn.execute("UPDATE applied_marks SET seq = seq + 500", [])
            .unwrap();
    }

    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();

    assert!(
        !sentinel_alive(dir.path()),
        "an applied mark past the log tail must still force a full rebuild"
    );
}
