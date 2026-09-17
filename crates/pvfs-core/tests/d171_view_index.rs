//! D171 — the view mount's questions of `region_entries` are answered from
//! an index. The table's key leads with the region, and the view asks by
//! path (and by hash) across EVERY region: each `stat` through feederbox's
//! mount scanned all 72k rows — 13 ms, 30 s to list Movies with attributes.
//! And the indexes arrive IN PLACE: the rows are not in the log, so an
//! upgrade that replayed would come back without them.

use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, LOCAL_PATH_FOR_HASH_SQL, MERGED_VIEW_SQL, TYPE_FOLDER, VIEW_ENTRY_SQL};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

fn library(tmp: &Path) -> (Engine, String) {
    let lib = tmp.join("lib");
    for rel in [
        "Movies/A (2001)/a.mkv",
        "Movies/B (2002)/b.mkv",
        "Movies/B (2002)/extras/x.mkv",
        "Movies!/odd.mkv",       // '!' sorts before '/'
        "Movies0/odd.mkv",       // '0' is the byte after '/'
        "Moviesé/odd.mkv",       // and a multi-byte name after both
        "TV/Show/s1/e1.mkv",
    ] {
        write(&lib, rel, rel.as_bytes());
    }
    let (mut e, _) = Engine::init(tmp.join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let r = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.region_mark_as(&r, "catalogue", None).unwrap();
    e.bind_folder(
        &r,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&r), None, 0).unwrap();
    (e, r)
}

fn plan(conn: &rusqlite::Connection, sql: &str, args: &[&str]) -> String {
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let rows: Vec<String> = stmt
        .query_map(rusqlite::params_from_iter(args), |r| r.get::<_, String>(3))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    rows.join(" | ")
}

fn names(list: Vec<pvfs_core::ViewEntry>) -> Vec<String> {
    list.into_iter().map(|e| e.rel_path).collect()
}

#[test]
fn a_listing_is_a_range_and_says_what_it_said_before() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, _) = library(tmp.path());
    assert_eq!(names(e.merged_view("").unwrap()), ["Movies", "Movies!", "Movies0", "Moviesé", "TV"]);
    assert_eq!(names(e.merged_view("Movies").unwrap()), ["Movies/A (2001)", "Movies/B (2002)"]);
    assert_eq!(names(e.merged_view("/Movies/").unwrap()), ["Movies/A (2001)", "Movies/B (2002)"]);
    assert_eq!(names(e.merged_view("Movies/B (2002)").unwrap()), ["Movies/B (2002)/b.mkv", "Movies/B (2002)/extras"]);
    assert_eq!(names(e.merged_view("Movies!").unwrap()), ["Movies!/odd.mkv"]);
    assert_eq!(names(e.merged_view("Movies0").unwrap()), ["Movies0/odd.mkv"]);
    assert_eq!(names(e.merged_view("Moviesé").unwrap()), ["Moviesé/odd.mkv"]);
    assert!(e.merged_view("Movie").unwrap().is_empty(), "a prefix of a name is not a folder");
    assert!(e.merged_view("Nothing").unwrap().is_empty());
}

#[test]
fn every_question_the_mount_asks_is_answered_from_an_index() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, _) = library(tmp.path());
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    let by_path = plan(&conn, VIEW_ENTRY_SQL, &["Movies/A (2001)/a.mkv"]);
    assert!(by_path.contains("idx_region_entries_path") && !by_path.contains("SCAN e"), "{by_path}");
    let listing = plan(&conn, MERGED_VIEW_SQL, &["Movies/", "Movies0"]);
    assert!(listing.contains("idx_region_entries_path") && !listing.contains("SCAN e"), "{listing}");
    let by_hash = plan(&conn, LOCAL_PATH_FOR_HASH_SQL, &["00"]);
    assert!(by_hash.contains("idx_region_entries_hash") && !by_hash.contains("SCAN e"), "{by_hash}");
}

#[test]
fn a_v18_cache_gains_the_indexes_in_place_and_keeps_its_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let (e, r) = library(tmp.path());
    let data_dir = e.data_dir().to_path_buf();
    let before = names(e.merged_view("Movies").unwrap());
    e.close().unwrap();
    {
        // what a box on the previous binary looks like — and a sentinel a replay would not bring back
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        conn.execute_batch(
            "DROP INDEX idx_region_entries_path;
             DROP INDEX idx_region_entries_hash;
             UPDATE projection_meta SET v = '18' WHERE k = 'schema_version';",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO region_entries (region_id, rel_path, kind, size_bytes, mtime_ms, changed_ms, content_hash, quality, seen_at)
             VALUES (?1, 'Movies/Sentinel (1999)', 'dir', 0, 0, 0, NULL, NULL, 0)",
            [&r],
        )
        .unwrap();
    }
    let e = Engine::open(&data_dir).unwrap();
    let mut after = names(e.merged_view("Movies").unwrap());
    assert!(after.contains(&"Movies/Sentinel (1999)".to_string()), "the rows were kept: migrated, not replayed");
    after.retain(|p| p != "Movies/Sentinel (1999)");
    assert_eq!(after, before);
    e.close().unwrap();
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    let have: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_region_entries_path', 'idx_region_entries_hash')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(have, 2);
    let v: String = conn.query_row("SELECT v FROM projection_meta WHERE k = 'schema_version'", [], |r| r.get(0)).unwrap();
    assert_eq!(v, pvfs_core::projection::SCHEMA_VERSION.to_string());
}
