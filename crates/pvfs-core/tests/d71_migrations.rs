//! D71 — projection migrations: an additive schema bump must not cost a replay.
//!
//! Dropping all 19 projection tables to fill one new column costs the entire
//! log. On the D69 fleet owner that is 59,365 events; on the production media
//! library it is minutes of that box being unavailable, which is what makes a
//! fleet upgrade a maintenance window instead of a rolling restart.
//!
//! A migration is only ever an optimisation: refusing is always safe, because
//! `full_rebuild` is the fallback and is always correct. These tests pin both
//! doors — that the fast one produces exactly what the slow one would, and
//! that the slow one still exists.
//!
//! `pending_changes` is the sentinel: local observation, never folded from
//! events, dropped by `full_rebuild` and untouched by a migration.

use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn folder_spec(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

fn bind_spec(dir: &Path) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&std::fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

fn plant_sentinel(data_dir: &Path) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO pending_changes
         (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
         VALUES ('d71-mig', 'file:///d71', 0, 0, 0, 0, 0)",
        [],
    )
    .unwrap();
}

fn sentinel_alive(data_dir: &Path) -> bool {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM pending_changes WHERE file_id = 'd71-mig'",
        [],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

/// Rewind the cache to v7: undo what the versions after it added, and set the
/// version back — what a box still running a much older binary looks like.
///
/// **This used to drop only `folder_bindings.bound_by` (v8) and relabel the
/// cache v7.** That is a v14 shape wearing a v7 label, and it hid a hard
/// failure for three weeks: a REAL v7 cache also has no `links.label` (v10),
/// so `create_schema`'s `idx_links_label` — which joined `INDEX_SCHEMA` with
/// D72 on 2026-08-19 — fails on it before the migration ladder is ever
/// reached. Every test here passed while the daemon could not open such a
/// forest at all.
///
/// Still not a complete v7 (the tables v12 and v14 added are left in place,
/// since `CREATE TABLE IF NOT EXISTS` makes their absence uninteresting), but
/// it now reproduces the one difference that the DDL cannot paper over.
fn rewind_to_v7(data_dir: &Path) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_links_label;
         ALTER TABLE links DROP COLUMN label;
         ALTER TABLE folder_bindings DROP COLUMN bound_by;
         UPDATE projection_meta SET v = '7' WHERE k = 'schema_version';",
    )
    .unwrap();
}

/// A cache old enough that the current DDL will not apply to it must still
/// OPEN — and must still take the cheap door.
///
/// The regression: `create_schema` ran with `?` at the top of the open path,
/// so `no such column: label` reached the caller as an error. `pvfsd` exited 1
/// and systemd restart-looped it, which reads as a corrupt forest rather than
/// as one wanting its migration. Found 2026-09-08 when the pipeline's daemon
/// stage ran for the first time since 14 August.
///
/// The sentinel is the point: opening must MIGRATE, not replay. Falling back
/// to a rebuild would also "work", and on a 241k-event forest it is minutes of
/// a box being unavailable — the exact cost D71's ladder exists to avoid.
#[test]
fn a_cache_the_current_ddl_cannot_extend_still_migrates() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, folder_spec("library")).unwrap();
    engine.close().unwrap();

    rewind_to_v7(dir.path());
    // Prove the premise rather than trusting the helper: the column the DDL
    // indexes is genuinely gone.
    {
        let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        let has_label: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('links') WHERE name = 'label'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(has_label, 0, "the rewind must actually remove links.label");
    }
    plant_sentinel(dir.path());

    let engine = Engine::open(dir.path()).expect("a v7 cache must open, not error");
    assert!(
        sentinel_alive(dir.path()),
        "it must migrate in place — a rebuild here is the slow door for no reason"
    );
    // The tree is intact and the DDL finished: the index the failure was about
    // exists now.
    let kids = engine.children(&root).unwrap();
    assert!(
        kids.iter().any(|c| c.node.id == f),
        "the tree survived the open"
    );
    engine.close().unwrap();

    let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
    let idx: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_links_label'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, 1, "the deferred DDL must be applied after the migration");
}

#[test]
fn an_additive_bump_migrates_in_place_instead_of_replaying() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, folder_spec("library")).unwrap();
    let src = tempfile::tempdir().unwrap();
    engine.bind_folder(&f, bind_spec(src.path())).unwrap();
    let me = engine.device_pubkey();
    engine.close().unwrap();

    rewind_to_v7(dir.path());
    plant_sentinel(dir.path());

    // Opening on the current binary must take the cheap door.
    let engine = Engine::open(dir.path()).unwrap();
    assert!(
        sentinel_alive(dir.path()),
        "an additive bump must migrate in place, not drop and replay the cache"
    );

    // …and produce exactly what a replay would: correct attribution.
    let bindings = engine.local_bindings().unwrap();
    assert_eq!(bindings.len(), 1, "the binding must still be this machine's");
    assert_eq!(bindings[0].folder_id, f);
    assert_eq!(bindings[0].bound_by, me, "bound_by filled from the log");
    engine.close().unwrap();
}

/// The migrated cache must equal the rebuilt one — otherwise the fast door is
/// a silent divergence rather than an optimisation.
#[test]
fn the_migrated_cache_matches_a_full_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let mut expected = Vec::new();
    for n in 0..3 {
        let f = engine.add_node(&root, folder_spec(&format!("d{n}"))).unwrap();
        let src = tempfile::tempdir().unwrap();
        engine.bind_folder(&f, bind_spec(src.path())).unwrap();
        // keep the dir alive for the whole test
        std::mem::forget(src);
        expected.push(f);
    }
    engine.close().unwrap();

    rewind_to_v7(dir.path());
    let e = Engine::open(dir.path()).unwrap();
    let migrated: Vec<(String, Vec<u8>)> = e
        .bindings()
        .unwrap()
        .into_iter()
        .map(|b| (b.folder_id, b.bound_by))
        .collect();
    e.close().unwrap();

    // Force the slow door and compare.
    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e = Engine::open(dir.path()).unwrap();
    let rebuilt: Vec<(String, Vec<u8>)> = e
        .bindings()
        .unwrap()
        .into_iter()
        .map(|b| (b.folder_id, b.bound_by))
        .collect();
    e.close().unwrap();

    assert_eq!(migrated, rebuilt, "the fast door must not diverge");
    assert_eq!(migrated.len(), expected.len());
    assert!(migrated.iter().all(|(_, by)| !by.is_empty()));
}

/// Equal VALUES are not enough: a migrated table must be structurally identical
/// to a freshly created one.
///
/// `ALTER TABLE ... ADD COLUMN` appends at the end, so the first version of the
/// v7→v8 migration produced the right values in the wrong column ORDER. Every
/// named query was happy; the rebuild swap, which copies positionally, was not
/// — it failed on a live 82k-event forest with
/// `NOT NULL constraint failed: folder_bindings.bound_by`.
#[test]
fn a_migrated_table_has_the_same_column_layout_as_a_fresh_one() {
    let layout = |data_dir: &Path| -> Vec<(i64, String)> {
        let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
        let mut stmt = conn
            .prepare("SELECT cid, name FROM pragma_table_info('folder_bindings') ORDER BY cid")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        rows
    };

    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, folder_spec("lib")).unwrap();
    let src = tempfile::tempdir().unwrap();
    engine.bind_folder(&f, bind_spec(src.path())).unwrap();
    engine.close().unwrap();

    rewind_to_v7(dir.path());
    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();
    let migrated = layout(dir.path());

    std::fs::remove_file(dir.path().join("index.db")).unwrap();
    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();
    let fresh = layout(dir.path());

    assert_eq!(
        migrated, fresh,
        "the migrated table's columns must be in the same order as a fresh one"
    );
}

/// A version this binary does not know how to migrate must still rebuild — the
/// fallback is what lets migrations be conservative.
#[test]
fn an_unmigratable_version_still_rebuilds() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine.add_node(&root, folder_spec("x")).unwrap();
    engine.close().unwrap();

    plant_sentinel(dir.path());
    {
        let conn = rusqlite::Connection::open(dir.path().join("index.db")).unwrap();
        // No step is registered for v1.
        conn.execute("UPDATE projection_meta SET v = '1' WHERE k = 'schema_version'", [])
            .unwrap();
    }

    let e = Engine::open(dir.path()).unwrap();
    e.close().unwrap();
    assert!(
        !sentinel_alive(dir.path()),
        "no registered migration must fall back to a full rebuild"
    );
}
