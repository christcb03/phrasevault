//! D181 — `projection_plan`: what opening a forest under this build will do to
//! its projection, told BEFORE it is done. A roll reads it to decide whether a
//! running view mount of the older build may stay up (PVOS D181 §8,
//! guardrail 1): an in-place migration may run under it, a rebuild may not.
//!
//! Every case is checked against what `Engine::open` then actually does — the
//! plan is only worth anything if it is the decision the open makes. The
//! D71 sentinel (`pending_changes`: local, never folded, dropped by a rebuild,
//! untouched by a migration) tells the two doors apart.

use std::path::Path;

use pvfs_core::projection::{projection_plan, ProjectionPlan, SCHEMA_VERSION};
use pvfs_core::{Engine, NodeSpec, PvfsError, TYPE_FOLDER};

fn forest() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "x".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.close().unwrap();
    dir
}

fn sql(data_dir: &Path, batch: &str) {
    rusqlite::Connection::open(data_dir.join("index.db")).unwrap().execute_batch(batch).unwrap();
}

fn plant_sentinel(data_dir: &Path) {
    sql(
        data_dir,
        "INSERT OR REPLACE INTO pending_changes
         (file_id, uri, old_size, old_mtime, new_size, new_mtime, detected_at)
         VALUES ('d181-plan', 'file:///d181', 0, 0, 0, 0, 0)",
    );
}

fn sentinel_alive(data_dir: &Path) -> bool {
    rusqlite::Connection::open(data_dir.join("index.db"))
        .unwrap()
        .query_row("SELECT COUNT(*) FROM pending_changes WHERE file_id = 'd181-plan'", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap_or(0)
        > 0
}

/// The previous schema's shape: v18 had no `idx_region_entries_path` /
/// `idx_region_entries_hash` (the v18 → v19 step adds them).
fn rewind_to_v18(data_dir: &Path) {
    sql(
        data_dir,
        "DROP INDEX IF EXISTS idx_region_entries_path;
         DROP INDEX IF EXISTS idx_region_entries_hash;
         DROP TABLE IF EXISTS region_provisional;
         UPDATE projection_meta SET v = '18' WHERE k = 'schema_version';",
    );
}

#[test]
fn no_forest_and_a_current_forest() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(projection_plan(empty.path()), ProjectionPlan::NoForest);
    let dir = forest();
    assert_eq!(projection_plan(dir.path()), ProjectionPlan::Current { version: SCHEMA_VERSION });
}

#[test]
fn an_additive_step_is_planned_in_place_and_the_open_migrates() {
    let dir = forest();
    plant_sentinel(dir.path());
    rewind_to_v18(dir.path());
    match projection_plan(dir.path()) {
        ProjectionPlan::InPlace { from, steps } => {
            assert_eq!(from, 18);
            // PVOS D183 added v19 → v20 (region_provisional): two steps now.
            assert_eq!(steps, vec!["idx_region_entries_path; idx_region_entries_hash", "region_provisional"]);
        }
        other => panic!("expected an in-place plan, got {other:?}"),
    }
    // Planning changed nothing: still v18 on disk.
    assert_eq!(pvfs_core::projection::on_disk_schema_version(dir.path()), Some(18));
    Engine::open(dir.path()).unwrap().close().unwrap();
    assert!(sentinel_alive(dir.path()), "the plan said in place — the open must not have replayed");
    assert_eq!(projection_plan(dir.path()), ProjectionPlan::Current { version: SCHEMA_VERSION });
}

#[test]
fn a_version_with_no_step_is_planned_as_a_rebuild_and_the_open_replays() {
    let dir = forest();
    plant_sentinel(dir.path());
    sql(dir.path(), "UPDATE projection_meta SET v = '1' WHERE k = 'schema_version';");
    match projection_plan(dir.path()) {
        ProjectionPlan::Rebuild { from, why } => {
            assert_eq!(from, 1);
            assert!(why.contains("no in-place step from v1"), "{why}");
        }
        other => panic!("expected a rebuild plan, got {other:?}"),
    }
    Engine::open(dir.path()).unwrap().close().unwrap();
    assert!(!sentinel_alive(dir.path()), "the plan said rebuild — the open must have replayed");
}

#[test]
fn events_folded_as_unknown_that_this_build_reads_force_a_rebuild() {
    let dir = forest();
    plant_sentinel(dir.path());
    rewind_to_v18(dir.path());
    sql(
        dir.path(),
        "INSERT OR REPLACE INTO projection_meta (k, v) VALUES ('unknown_events', '3');
         INSERT OR REPLACE INTO projection_meta (k, v) VALUES ('unknown_event_kinds', 'NodeCreated');",
    );
    match projection_plan(dir.path()) {
        ProjectionPlan::Rebuild { from, why } => {
            assert_eq!(from, 18);
            assert!(why.contains("3 event(s)") && why.contains("NodeCreated"), "{why}");
        }
        other => panic!("expected a rebuild plan, got {other:?}"),
    }
    Engine::open(dir.path()).unwrap().close().unwrap();
    assert!(!sentinel_alive(dir.path()), "the open must have taken the slow door too");
}

#[test]
fn a_newer_schema_is_planned_as_newer_and_the_open_refuses() {
    let dir = forest();
    let newer = SCHEMA_VERSION + 1;
    sql(dir.path(), &format!("UPDATE projection_meta SET v = '{newer}' WHERE k = 'schema_version';"));
    assert_eq!(projection_plan(dir.path()), ProjectionPlan::Newer { found: newer });
    assert!(matches!(Engine::open(dir.path()), Err(PvfsError::SchemaVersion { .. })));
}
