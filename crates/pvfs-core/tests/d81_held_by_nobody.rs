//! D81 — the third kind of orphan: a file the catalog claims that nobody holds.
//!
//! `list_orphans` finds nodes with no live LINK. `orphaned_local_locations`
//! finds bytes with no live NODE. Neither finds a node still sitting in the
//! tree, still shown to anyone browsing it, whose every location has been
//! retired — the residue of a file deleted outside PVFS. Production had 22 of
//! them and nothing that would have named one.
//!
//! It is a REPORT, not a sweep. A scan cannot tell a deliberate deletion from
//! an accident from an unavailable volume — D81 4a-ii's case matrix — so
//! unlinking automatically would be inferring intent from a filesystem diff,
//! which is the mistake this milestone exists to stop making.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

fn rig() -> (tempfile::TempDir, Engine, String, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let lib = tmp.path().join("lib");
    std::fs::create_dir_all(lib.join("TV/Show")).unwrap();
    std::fs::write(lib.join("TV/Show/keep.mkv"), vec![1u8; 2048]).unwrap();
    std::fs::write(lib.join("TV/Show/gone.mkv"), vec![2u8; 4096]).unwrap();

    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "Media".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine.bind_folder(&media, spec(&lib)).unwrap();
    engine.scan(Some(&media)).unwrap();
    (tmp, engine, media, lib)
}

/// A healthy library reports nothing.
#[test]
fn a_library_whose_files_are_all_present_reports_nothing() {
    let (_t, engine, _m, _l) = rig();
    assert!(engine.files_held_by_nobody().unwrap().is_empty());
    engine.close().unwrap();
}

/// Delete a file outside PVFS: the node survives, holding nothing, and says so.
#[test]
fn a_file_deleted_outside_pvfs_is_named() {
    let (_t, mut engine, media, lib) = rig();
    std::fs::remove_file(lib.join("TV/Show/gone.mkv")).unwrap();
    engine.scan(Some(&media)).unwrap();

    let held = engine.files_held_by_nobody().unwrap();
    assert_eq!(held.len(), 1, "exactly the deleted one: {held:?}");
    assert_eq!(held[0].1, "gone.mkv");

    // And it is STILL IN THE TREE — which is the point. Anyone browsing the
    // catalog is being shown a file that does not exist anywhere.
    let still_listed = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .any(|e| e.node.node_type == TYPE_FILE && e.node.label == "gone.mkv");
    assert!(
        still_listed,
        "the node survives the file — that is exactly why this needs reporting"
    );
    engine.close().unwrap();
}

/// A file that merely MOVED is not missing — it is held, elsewhere.
///
/// The distinction the whole report depends on: if a relocation showed up here
/// it would be worse than useless, because the obvious response to this list is
/// to forget what is on it.
#[test]
fn a_moved_file_is_not_reported_as_missing() {
    let (_t, mut engine, media, lib) = rig();
    std::fs::create_dir_all(lib.join("TV/Show/Season 02")).unwrap();
    std::fs::rename(
        lib.join("TV/Show/gone.mkv"),
        lib.join("TV/Show/Season 02/gone.mkv"),
    )
    .unwrap();
    engine.scan(Some(&media)).unwrap();

    assert!(
        engine.files_held_by_nobody().unwrap().is_empty(),
        "it moved; somebody still holds it. Reporting a move as a missing file \
         would invite forgetting a file that is perfectly fine"
    );
    engine.close().unwrap();
}

/// Reporting is not sweeping: nothing is unlinked without being asked.
#[test]
fn the_report_changes_nothing_by_itself() {
    let (_t, mut engine, media, lib) = rig();
    std::fs::remove_file(lib.join("TV/Show/gone.mkv")).unwrap();
    engine.scan(Some(&media)).unwrap();

    let before = engine.files_held_by_nobody().unwrap().len();
    let again = engine.files_held_by_nobody().unwrap().len();
    assert_eq!(before, 1);
    assert_eq!(
        again, 1,
        "reading the report twice must not change what it says — it is a \
         report, and a report that acts is a sweep"
    );
    engine.close().unwrap();
}
