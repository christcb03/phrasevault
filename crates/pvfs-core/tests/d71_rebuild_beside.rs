//! D71 — a rebuild is built BESIDE the live cache, then swapped in one commit.
//!
//! `full_rebuild` used to drop the live tables and replay into them. For the
//! whole replay — minutes on a large forest — every reader, including the
//! daemon's read views, saw an EMPTY cache and answered from it. And a process
//! that died mid-replay left that half-built cache behind as the real one.
//!
//! Now the replay lands in a scratch database and the result is copied into the
//! live one inside a single transaction: readers see the old cache throughout
//! and the new one after one commit, never a partial. A failure or a crash
//! leaves only the scratch.

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

fn node_count(data_dir: &std::path::Path) -> i64 {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM nodes", [], |r| r.get(0))
        .unwrap_or(-1)
}

/// Force a rebuild WITHOUT changing the schema version, so the live cache stays
/// readable (and comparable) the whole way through.
fn force_rebuild_next_open(data_dir: &std::path::Path) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.execute("UPDATE applied_marks SET seq = seq + 500", [])
        .unwrap();
}

/// THE property: a rebuild that FAILS must leave the live cache exactly as it
/// was. Under the old drop-then-replay this was impossible — the tables were
/// already gone before the failure could be discovered.
#[test]
fn a_failed_rebuild_leaves_the_live_cache_intact() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    for i in 0..8 {
        engine.add_node(&root, folder(&format!("f{i}"))).unwrap();
    }
    engine.close().unwrap();

    let before = node_count(dir.path());
    assert!(before > 8, "the fixture must have folded some nodes");

    // Tamper an event so the replay cannot succeed, and force the rebuild.
    {
        let log = rusqlite::Connection::open(dir.path().join("log.db")).unwrap();
        let seq: i64 = log
            .query_row("SELECT MIN(seq) FROM events WHERE seq > 1", [], |r| r.get(0))
            .unwrap();
        log.execute(
            "UPDATE events SET body = ?1 WHERE seq = ?2",
            rusqlite::params![b"not a valid event body".to_vec(), seq],
        )
        .unwrap();
    }
    force_rebuild_next_open(dir.path());

    // The open must fail — a bad log is never silently accepted.
    let opened = Engine::open(dir.path());
    assert!(opened.is_err(), "a tampered log must refuse to replay");

    assert_eq!(
        node_count(dir.path()),
        before,
        "a failed rebuild destroyed the live cache — it must be built beside it"
    );
    // And the scratch must not be left lying around as if it were real.
    assert!(
        !dir.path().join("index.rebuild").exists(),
        "the scratch projection must be cleared"
    );
}

/// A successful rebuild still produces the right answer — building beside must
/// not change WHAT is built, only where.
#[test]
fn a_successful_rebuild_still_produces_the_same_cache() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    for i in 0..8 {
        engine.add_node(&root, folder(&format!("f{i}"))).unwrap();
    }
    engine.close().unwrap();
    let before = node_count(dir.path());

    force_rebuild_next_open(dir.path());
    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();

    assert_eq!(node_count(dir.path()), before, "the rebuilt cache must match");
    assert!(!dir.path().join("index.rebuild").exists());
}

/// Readers must never observe a partial cache while a rebuild runs.
///
/// Cheap guard, honestly labelled: on a small fixture the replay is fast, so
/// this samples a narrow window and would not reliably catch a regression on
/// its own. It is here because it costs nothing and it FAILS LOUDLY on the old
/// drop-then-replay behaviour, which emptied the tables for the whole replay.
#[test]
fn readers_never_see_a_partial_cache_during_a_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    for i in 0..150 {
        engine.add_node(&root, folder(&format!("f{i}"))).unwrap();
    }
    engine.close().unwrap();
    let full = node_count(dir.path());

    let stop = Arc::new(AtomicBool::new(false));
    let seen_low = Arc::new(AtomicBool::new(false));
    let rd = dir.path().to_path_buf();
    let rstop = stop.clone();
    let rlow = seen_low.clone();
    let reader = std::thread::spawn(move || {
        while !rstop.load(Ordering::SeqCst) {
            let n = node_count(&rd);
            // -1 = the table is missing entirely; anything under `full` is a
            // half-built cache being served as if it were real.
            if n >= 0 && n < full {
                rlow.store(true, Ordering::SeqCst);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    });

    force_rebuild_next_open(dir.path());
    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();

    stop.store(true, Ordering::SeqCst);
    reader.join().unwrap();

    assert!(
        !seen_low.load(Ordering::SeqCst),
        "a reader saw a partially-built cache during a rebuild"
    );
    assert_eq!(node_count(dir.path()), full);
}
