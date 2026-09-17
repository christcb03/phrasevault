//! D162 — an operator's `SQLITE_TMPDIR` wins: set, the engine changes
//! nothing. Its own test binary, because the setting is process-wide.
use pvfs_core::engine::Engine;
use rusqlite::Connection;

#[test]
fn an_operators_sqlite_tmpdir_is_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let theirs = tmp.path().join("theirs");
    std::fs::create_dir_all(&theirs).unwrap();
    std::env::set_var("SQLITE_TMPDIR", &theirs);
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let (_engine, _mn) = Engine::init(&data).unwrap();
    assert!(!data.join("sqlite-tmp").exists(), "no directory made");
    let c = Connection::open_in_memory().unwrap();
    let mut st = c.prepare("PRAGMA temp_store_directory").unwrap();
    let set: Vec<String> = st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect();
    assert!(set.iter().all(|s| s.is_empty()), "SQLite's own setting untouched: {set:?}");
}
