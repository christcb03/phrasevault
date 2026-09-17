//! D162 — SQLite's scratch files go beside the database. The NAS's receive
//! job failed "database or disk is full" (2026-09-16) because the merged
//! view's sort spilled into the QNAP's 64 MB RAM `/tmp`. The first engine a
//! process opens points SQLite's process-wide temp directory at
//! `<data_dir>/sqlite-tmp`, on the catalogue's own disk.
use pvfs_core::engine::Engine;
use rusqlite::Connection;

fn temp_store_directory(conn: &Connection) -> Vec<String> {
    let mut st = conn.prepare("PRAGMA temp_store_directory").unwrap();
    st.query_map([], |r| r.get::<_, String>(0)).unwrap().map(Result::unwrap).collect()
}

#[test]
fn the_first_engine_points_sqlite_scratch_at_its_data_dir_and_a_big_sort_spills_there() {
    assert!(std::env::var_os("SQLITE_TMPDIR").is_none(), "this test needs SQLite's own default to start from");
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    let (_engine, _mn) = Engine::init(&data).unwrap();

    let scratch = data.join("sqlite-tmp");
    assert!(scratch.is_dir(), "made beside index.db");
    // Process-wide: any connection reads the same setting.
    let other = Connection::open_in_memory().unwrap();
    assert_eq!(temp_store_directory(&other), [scratch.to_string_lossy().into_owned()]);

    // A second engine elsewhere does not move it (the first open decides).
    let data2 = tmp.path().join("data2");
    std::fs::create_dir_all(&data2).unwrap();
    let (_e2, _m2) = Engine::init(&data2).unwrap();
    assert_eq!(temp_store_directory(&other), [scratch.to_string_lossy().into_owned()]);
    assert!(!data2.join("sqlite-tmp").exists());

    // The real thing: a sort bigger than the page cache opens its spill file
    // there. SQLite unlinks a temp file as soon as it opens it, so look at
    // this process's open files while the sorted statement is mid-read.
    #[cfg(target_os = "linux")]
    {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(
            "PRAGMA cache_size = -64;
             CREATE TABLE t(b BLOB);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 40000)
             INSERT INTO t SELECT randomblob(200) FROM n;",
        )
        .unwrap();
        let mut st = c.prepare("SELECT b FROM t ORDER BY b").unwrap();
        let mut rows = st.query([]).unwrap();
        assert!(rows.next().unwrap().is_some());
        let links: Vec<String> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let spill: Vec<&String> = links.iter().filter(|l| l.contains("etilqs_")).collect();
        assert!(!spill.is_empty(), "the sort spilled to a temp file: {links:?}");
        assert!(spill.iter().all(|l| l.starts_with(&*scratch.to_string_lossy())), "and only under sqlite-tmp: {spill:?}");
    }
}
