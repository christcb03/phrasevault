//! D71 W1 — a binding belongs to the machine that made it.
//!
//! A binding is a forest-wide catalog record naming a directory that exists on
//! exactly ONE box. Before this, `scan(None)` and the watcher walked every
//! binding in the forest, so any replica died on the first binding belonging to
//! another machine. Proven on the D69 lab, where the ingest box could not run
//! the `watch` job at all:
//!
//! ```text
//! scan error: bound directory not found: file:///srv/sim/nas-data2/Media
//! error: invalid input for watcher: /srv/sim/nas-data2/Media: No such file or directory
//! ```
//!
//! The fix is attribution, NOT "skip anything missing" — a binding that IS this
//! machine's and whose directory has vanished must still raise, because that is
//! the unmounted-NAS guard that stops a scan soft-removing every location under
//! it. `missing_local_directory_still_raises` pins that distinction.

use std::fs;
use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

/// A device key that is definitely not ours.
const OTHER_MACHINE: &[u8] = b"\x02another-box-device-key-------";

fn new_forest() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _m) = Engine::init(dir.path()).unwrap();
    (dir, engine)
}

fn add_folder(engine: &mut Engine, label: &str) -> String {
    let root = engine.identity.root_node_id.clone();
    engine
        .add_node(
            &root,
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

fn spec(dir: &Path) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

/// Re-attribute a binding to another machine in the projection, the way a
/// replica sees a binding the owner made. The projection is a pure cache of the
/// log, so this is the same shape a synced `FolderBound` from another device
/// folds into — without standing up a second box in a unit test.
fn reattribute(data_dir: &Path, folder: &str, device: &[u8]) {
    let conn = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    let n = conn
        .execute(
            "UPDATE folder_bindings SET bound_by = ?1 WHERE folder_id = ?2",
            rusqlite::params![device, folder],
        )
        .unwrap();
    assert_eq!(n, 1, "the binding row must exist to re-attribute it");
}

#[test]
fn local_bindings_exclude_other_machines() {
    let (data, mut engine) = new_forest();
    let mine = add_folder(&mut engine, "mine");
    let theirs = add_folder(&mut engine, "theirs");
    let src_a = tempfile::tempdir().unwrap();
    let src_b = tempfile::tempdir().unwrap();
    engine.bind_folder(&mine, spec(src_a.path())).unwrap();
    engine.bind_folder(&theirs, spec(src_b.path())).unwrap();
    engine.close().unwrap();

    reattribute(data.path(), &theirs, OTHER_MACHINE);
    let engine = Engine::open(data.path()).unwrap();

    // The forest view is unchanged — an operator still sees the whole fleet.
    assert_eq!(engine.bindings().unwrap().len(), 2);

    // The machine view is only ours.
    let local = engine.local_bindings().unwrap();
    assert_eq!(local.len(), 1);
    assert_eq!(local[0].folder_id, mine);

    // And the listing marks which is which rather than hiding the foreign one.
    let rows = engine.binding_listing().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().find(|r| r.binding.folder_id == mine).unwrap().is_local);
    assert!(!rows.iter().find(|r| r.binding.folder_id == theirs).unwrap().is_local);
    engine.close().unwrap();
}

/// THE lab regression: another machine's bound directory does not exist here,
/// and that must not stop this box scanning its own.
#[test]
fn scan_all_skips_foreign_bindings_whose_directories_are_absent() {
    let (data, mut engine) = new_forest();
    let mine = add_folder(&mut engine, "mine");
    let theirs = add_folder(&mut engine, "theirs");
    let src_mine = tempfile::tempdir().unwrap();
    let src_theirs = tempfile::tempdir().unwrap();
    fs::write(src_mine.path().join("ep.mkv"), b"bytes").unwrap();
    engine.bind_folder(&mine, spec(src_mine.path())).unwrap();
    engine.bind_folder(&theirs, spec(src_theirs.path())).unwrap();
    engine.close().unwrap();

    reattribute(data.path(), &theirs, OTHER_MACHINE);
    // The other box's directory is not on this machine at all.
    fs::remove_dir_all(src_theirs.path()).unwrap();

    let mut engine = Engine::open(data.path()).unwrap();
    let reports = engine
        .scan(None)
        .expect("a foreign binding must not fail this machine's scan");
    assert_eq!(reports.len(), 1, "only this machine's binding is scanned");
    assert_eq!(reports[0].folder_id, mine);
    assert_eq!(reports[0].stats.added, 1);
    engine.close().unwrap();
}

/// Naming a foreign binding explicitly is a clear error, not a silent no-op —
/// the caller asked for something this box cannot do.
#[test]
fn scanning_a_foreign_binding_by_name_explains_why_not() {
    let (data, mut engine) = new_forest();
    let theirs = add_folder(&mut engine, "theirs");
    let src = tempfile::tempdir().unwrap();
    engine.bind_folder(&theirs, spec(src.path())).unwrap();
    engine.close().unwrap();

    reattribute(data.path(), &theirs, OTHER_MACHINE);
    let mut engine = Engine::open(data.path()).unwrap();

    let err = engine.scan(Some(&theirs)).unwrap_err().to_string();
    assert!(
        err.contains("another machine"),
        "the error must say whose it is, got: {err}"
    );
    engine.close().unwrap();
}

/// The guard this fix must NOT weaken: our own binding whose directory has
/// vanished (an unmounted NAS) still raises, so a scan never mass-removes the
/// locations under it.
#[test]
fn missing_local_directory_still_raises() {
    let (data, mut engine) = new_forest();
    let mine = add_folder(&mut engine, "mine");
    let src = tempfile::tempdir().unwrap();
    fs::write(src.path().join("ep.mkv"), b"bytes").unwrap();
    engine.bind_folder(&mine, spec(src.path())).unwrap();
    engine.scan(None).unwrap();
    engine.close().unwrap();

    fs::remove_dir_all(src.path()).unwrap();
    let mut engine = Engine::open(data.path()).unwrap();

    let err = engine.scan(None).unwrap_err().to_string();
    assert!(
        err.contains("bound directory"),
        "an unmounted local source must surface, got: {err}"
    );
    engine.close().unwrap();
}

/// The upgrade is free: attribution was always in the signed log, so dropping
/// the projection and replaying back-fills `bound_by` with no migration code.
#[test]
fn a_rebuild_backfills_attribution_from_the_log() {
    let (data, mut engine) = new_forest();
    let mine = add_folder(&mut engine, "mine");
    let src = tempfile::tempdir().unwrap();
    engine.bind_folder(&mine, spec(src.path())).unwrap();
    let me = engine.device_pubkey();
    engine.close().unwrap();

    // Wipe the projection entirely — the log is the only source left.
    fs::remove_file(data.path().join("index.db")).unwrap();
    let engine = Engine::open(data.path()).unwrap();

    let local = engine.local_bindings().unwrap();
    assert_eq!(local.len(), 1, "attribution survived a full rebuild");
    assert_eq!(local[0].folder_id, mine);
    assert_eq!(local[0].bound_by, me);
    engine.close().unwrap();
}
