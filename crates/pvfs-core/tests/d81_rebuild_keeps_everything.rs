//! D81 — a rebuild must not quietly lose a table.
//!
//! A rebuild replays into a scratch database and copies a HAND-MAINTAINED list
//! of tables back over the live one. Three folded-from-events tables were
//! missing from that list — `media_quality`, `recovery_keys`, `secure_blobs` —
//! so every replay silently emptied quality, recovery-phrase custody and the
//! encrypted-content ledger.
//!
//! Found in production, not here: feederbox replayed 24,586 `MediaQuality`
//! events, finished with `unknown_events: 0` — it had decoded every one — and a
//! `media_quality` table with zero rows. The owner, same log, had 24,585.

use pvfs_core::projection::MAIN_OBJECTS;

/// Every table the schema creates must be one a rebuild carries over.
///
/// This is the test that would have caught it the day the table was added, and
/// the reason the next one cannot go missing the same way.
#[test]
fn rebuild_copies_every_table() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = pvfs_core::Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    engine.close().unwrap();

    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    assert!(!tables.is_empty(), "the schema must create tables");

    let missing: Vec<&String> = tables
        .iter()
        .filter(|t| !MAIN_OBJECTS.contains(&t.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these tables exist but a rebuild would DROP them and never copy them \
         back, emptying them silently on every replay: {missing:?}"
    );
}

/// And nothing in the list may name a table that does not exist — a typo there
/// fails the copy for every rebuild, not just the one table.
#[test]
fn the_copy_list_names_no_table_that_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = pvfs_core::Engine::init(dir.path()).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    engine.close().unwrap();

    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .unwrap();
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    let phantom: Vec<&&str> = MAIN_OBJECTS
        .iter()
        .filter(|t| !tables.iter().any(|x| x == *t))
        .collect();
    assert!(phantom.is_empty(), "named but not created: {phantom:?}");
}
