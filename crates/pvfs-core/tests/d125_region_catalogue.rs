//! D125 (doc 26 phases 1-2) — checklist items 0 and 1: the spike and schema 16.
//!
//! A catalogue region has NO event log. Its head is the hash of its last
//! published manifest, and `commit_region_heads` has to source `(seq, hash)`
//! from `region_snapshots` instead of opening a log file that does not exist.
//! Doc 26 §10 said: if that needs more than a kind column and two branches,
//! stop and reconsider. It needed a kind column and two branches.

use pvfs_core::{Engine, NodeSpec, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FOLDER.into(),
            label: label.into(),
            payload: Vec::new(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

/// Item 1 — schema 16 migrates in place. Same discipline as `d71_migrations`:
/// a sentinel in a projection-only table proves no replay happened, and the
/// premise is checked (the column really is gone) rather than trusted.
#[test]
fn a_v15_cache_migrates_to_v16_without_replaying() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    folder(&mut e, &root, "Media");
    e.close().unwrap();

    let db = dir.path().join("index.db");
    {
        let c = rusqlite::Connection::open(&db).unwrap();
        // Rebuilt rather than `DROP COLUMN`: SQLite edits the stored CREATE text
        // in place and trips on the commas inside the DDL's own comments
        // ("incomplete input"). A real v15 table is exactly this shape anyway.
        c.execute_batch(
            "CREATE TABLE regions_v15 (
               node_id TEXT NOT NULL PRIMARY KEY, marked_at INTEGER NOT NULL,
               state_root TEXT, baseline_seq INTEGER NOT NULL DEFAULT 0,
               baseline_log TEXT NOT NULL DEFAULT '', parent_log TEXT NOT NULL DEFAULT '',
               log_file TEXT, committed_seq INTEGER NOT NULL DEFAULT 0,
               committed_head TEXT NOT NULL DEFAULT '');
             INSERT INTO regions_v15 SELECT node_id, marked_at, state_root, baseline_seq,
               baseline_log, parent_log, log_file, committed_seq, committed_head FROM regions;
             DROP TABLE regions;
             ALTER TABLE regions_v15 RENAME TO regions;
             DROP TABLE region_entries;
             DROP TABLE region_snapshots;
             UPDATE projection_meta SET v = '15' WHERE k = 'schema_version';
             INSERT OR REPLACE INTO pending_changes
               (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
               VALUES ('d125-sentinel', 'file:///x', 0, 0, 0, 0, 0);",
        )
        .unwrap();
        let has_kind: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('regions') WHERE name = 'kind'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_kind, 0, "the rewind must really produce a v15 shape");
    }

    let e = Engine::open(dir.path()).expect("a v15 cache must open");
    e.close().unwrap();

    let c = rusqlite::Connection::open(&db).unwrap();
    let v: String = c
        .query_row("SELECT v FROM projection_meta WHERE k='schema_version'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(v, "18");
    let sentinel: i64 = c
        .query_row("SELECT COUNT(*) FROM pending_changes WHERE file_id='d125-sentinel'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(sentinel, 1, "an additive bump must migrate in place, not drop and replay");
    for t in ["region_entries", "region_snapshots", "region_fetched"] {
        let n: i64 = c
            .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1", [t], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "{t} must exist after the migration");
    }
    // Layout parity with a fresh cache: the newest column (`drains`, D127) is
    // the LAST both ways.
    let last: String = c
        .query_row(
            "SELECT name FROM pragma_table_info('regions') ORDER BY cid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(last, "drains", "migrated column order must match the fresh DDL — full_rebuild copies positionally");
}

/// Item 0 — the spike. A catalogue region with a published snapshot gets that
/// snapshot's (seq, hash) committed as its SubRegionHead; no log file is ever
/// opened for it. A log region beside it is untouched.
#[test]
fn a_catalogue_region_commits_its_manifest_hash_as_its_head() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let cat = folder(&mut e, &root, "Library");
    let log = folder(&mut e, &root, "Photos");
    e.region_mark_as(&cat, "catalogue", None).unwrap();
    e.region_mark(&log).unwrap();
    e.close().unwrap();

    // Give the catalogue region a published snapshot by hand: the spike proves
    // the head commitment works on the row shape alone, before the scan and
    // manifest (items 2-5) exist to produce one.
    let fake_hash = "ab".repeat(32);
    {
        let c = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        c.execute(
            "INSERT INTO region_snapshots (region_id, seq, manifest_hash, entries, published_at)
             VALUES (?1, 7, ?2, 41, 0)",
            rusqlite::params![cat, fake_hash],
        )
        .unwrap();
        // Prove the premise: the catalogue region has no log file.
        let lf: Option<String> = c
            .query_row("SELECT log_file FROM regions WHERE node_id=?1", [&cat], |r| r.get(0))
            .unwrap();
        assert!(lf.is_none(), "a catalogue region must have no event log: {lf:?}");
    }

    let mut e = Engine::open(dir.path()).expect("startup_check must not try to open a log for a catalogue region");
    let n = e.commit_region_heads().unwrap();
    assert!(n >= 1, "the catalogue region's head was due and must have been committed (got {n})");

    let info = e.region_info(&cat).unwrap().expect("region row");
    assert_eq!(info.committed_seq, 7, "the SNAPSHOT seq is the head seq");
    assert_eq!(info.committed_head, fake_hash, "the MANIFEST hash is the head hash");

    // The log region was not disturbed by the branch: nothing written to it,
    // so nothing to attest — it stays at (0, '').
    let li = e.region_info(&log).unwrap().expect("region row");
    assert_eq!(li.committed_seq, 0);
    assert_eq!(li.committed_head, "");

    // Idempotent: nothing changed, so a second call commits nothing.
    assert_eq!(e.commit_region_heads().unwrap(), 0);
    e.close().unwrap();
}

/// Guard — unmarking a catalogue region is refused, not silently done. Without
/// this, `region_log_tip` returns (0, genesis) for a region with no log, and
/// unmark would commit a bogus final head and discard the catalogue.
#[test]
fn unmarking_a_catalogue_region_is_refused_and_a_log_region_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let cat = folder(&mut e, &root, "Library");
    let log = folder(&mut e, &root, "Photos");
    e.region_mark_as(&cat, "catalogue", None).unwrap();
    e.region_mark(&log).unwrap();
    let err = e.region_unmark(&cat).expect_err("a catalogue region must not unmark");
    assert!(
        matches!(err, pvfs_core::PvfsError::Forbidden { .. }),
        "refused as Forbidden, not as some other failure: {err:?}"
    );
    assert!(e.region_info(&cat).unwrap().is_some(), "and it is still a region");
    e.region_unmark(&log).expect("a log region unmarks exactly as before");
    e.close().unwrap();
}
