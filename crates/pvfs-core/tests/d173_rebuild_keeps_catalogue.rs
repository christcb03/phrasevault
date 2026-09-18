//! D173 — what the NAS lost on 2026-09-17 at 9:40 PM EDT, and must not again:
//! a fold lock held by another process made the daemon replay its projection;
//! the replay dropped the catalogue rows and the snapshot record (neither is
//! in the log); the next publish counted from 1 and the owner refused it
//! ("head seq 1 does not advance … (at 6)") — for hours.

use std::path::Path;

use pvfs_core::{projection, BindSpec, Engine, HashPolicy, NodeSpec, PvfsError, TYPE_FOLDER};

fn write(root: &Path, rel: &str, bytes: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, bytes).unwrap();
}

/// A forest cataloguing `lib`, scanned twice: head 2, three rows.
fn catalogued(tmp: &Path) -> (std::path::PathBuf, String, std::path::PathBuf) {
    let lib = tmp.join("lib");
    write(&lib, "Movies/A (2001)/a.mkv", b"aaa");
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
    write(&lib, "Movies/B (2002)/b.mkv", b"bbbb");
    e.scan_routed(Some(&r), None, 0).unwrap();
    let st = status(&e, &r);
    assert_eq!((st.head_seq, st.held_seq, st.entries), (2, Some(2), 5), "premise: head 2, five rows (three folders, two files)");
    let data_dir = e.data_dir().to_path_buf();
    e.close().unwrap();
    (data_dir, r, lib)
}

fn status(e: &Engine, r: &str) -> pvfs_core::CatalogueStatus {
    e.catalogue_status().unwrap().into_iter().find(|s| s.region == r).expect("the region")
}

#[test]
fn a_rebuild_keeps_the_catalogue_and_the_next_head_still_advances() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, r, lib) = catalogued(tmp.path());

    {
        // an unclean shutdown with no live writer is one of the roads to
        // `full_rebuild` (doc 10 §9.3); the open below takes it
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        projection::meta_set(&conn, "clean_shutdown", "0").unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pending_changes (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
             VALUES ('d173-replayed', 'file:///d173', 0, 0, 0, 0, 0)",
            [],
        )
        .unwrap();
    }
    let mut e = Engine::open(&data_dir).unwrap();
    {
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM pending_changes WHERE file_id = 'd173-replayed'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0, "premise: the open really replayed (a log-derived table came back without the planted row)");
    }
    let st = status(&e, &r);
    assert_eq!(st.entries, 5, "the rows survived the replay — they are not in the log");
    assert_eq!(st.held_seq, Some(2), "and so did the record of what this box published");
    assert_eq!(e.region_snapshots(&r).unwrap().last().map(|s| s.seq), Some(2));
    assert!(e.view_entry("Movies/B (2002)/b.mkv").unwrap().is_some());

    // nothing changed: nothing is published; something changed: head 3, not 1
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert_eq!(status(&e, &r).head_seq, 2);
    write(&lib, "Movies/C (2003)/c.mkv", b"ccccc");
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert_eq!(status(&e, &r).head_seq, 3, "the head advanced from the attested 2");
    e.close().unwrap();
}

#[test]
fn a_publish_counts_up_from_the_head_the_log_attests_even_with_its_own_record_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, r, lib) = catalogued(tmp.path());
    {
        // what the replay used to leave behind
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        conn.execute("DELETE FROM region_snapshots WHERE region_id = ?1", [&r]).unwrap();
    }
    let mut e = Engine::open(&data_dir).unwrap();
    assert!(e.region_snapshots(&r).unwrap().is_empty(), "premise: no record of what was published");
    // The catalogue is as the attested head describes it: no new head.
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert_eq!(status(&e, &r).head_seq, 2, "an unchanged catalogue publishes nothing — judged against the attested head");
    // Changed: the next head is 3, not 1 (which the log would refuse).
    write(&lib, "Movies/C (2003)/c.mkv", b"ccccc");
    e.scan_routed(Some(&r), None, 0).unwrap();
    assert_eq!(status(&e, &r).head_seq, 3);
    assert_eq!(e.region_snapshots(&r).unwrap().last().map(|s| s.seq), Some(3));
    e.close().unwrap();
}

#[test]
fn a_fold_lock_held_by_another_process_does_not_cost_the_cache() {
    std::env::set_var("PVFS_STARTUP_FOLD_WAIT_MS", "1000");
    let tmp = tempfile::tempdir().unwrap();
    let (data_dir, r, _lib) = catalogued(tmp.path());
    {
        // the cache is BEHIND the log (a fold is due at the next open), and
        // it carries something a replay would not bring back
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        projection::applied_set(&conn, "", 0, "").unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO pending_changes (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
             VALUES ('d173-sentinel', 'file:///d173', 0, 0, 0, 0, 0)",
            [],
        )
        .unwrap();
    }
    let alive = || -> bool {
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        conn.query_row("SELECT COUNT(*) FROM pending_changes WHERE file_id = 'd173-sentinel'", [], |r| r.get::<_, i64>(0))
            .unwrap()
            > 0
    };

    let held = projection::hold_fold_lock_for_test(&data_dir).expect("the lock, as another process would hold it");
    let started = std::time::Instant::now();
    let refused = Engine::open(&data_dir);
    assert!(
        matches!(refused, Err(PvfsError::Busy { .. })),
        "an open that cannot fold gives up: {:?}",
        refused.map(|_| ())
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(30), "and does not hang");
    assert!(alive(), "the cache was NOT thrown away and replayed");
    drop(held);

    let e = Engine::open(&data_dir).expect("with the lock free, the open folds and succeeds");
    assert!(alive(), "a fold is not a replay either");
    assert_eq!(status(&e, &r).entries, 5);
    e.close().unwrap();
}
