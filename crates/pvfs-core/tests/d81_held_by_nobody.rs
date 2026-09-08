//! D81 — the third kind of orphan: a file the catalog claims that nobody holds.
//!
//! `list_orphans` finds nodes with no live LINK. `orphaned_local_locations`
//! finds bytes with no live NODE. Neither finds a node still sitting in the
//! tree, still shown to anyone browsing it, whose every location has been
//! retired — the residue of a file deleted outside PVFS. Production had 22 of
//! them and nothing that would have named one.
//!
//! It WAS a report, not a sweep, on the reasoning that a scan cannot tell a
//! deliberate deletion from an accident from an unavailable volume (D81
//! 4a-ii's case matrix), so unlinking would be inferring intent from a
//! filesystem diff.
//!
//! **D105 answers that objection with D81's own tool.** The unavailable-volume
//! case is exactly what `verify_root_marker` was added for — Chris's
//! suggestion, in this same milestone — and `scan_binding` calls it before the
//! removal loop runs. On a mount PROVEN live, a file that is gone is gone, and
//! requiring a second manual step only asks the operator to confirm what the
//! marker established. Unlink is a soft remove on an append-only log, so the
//! act is reversible and nothing is destroyed.
//!
//! `files_held_by_nobody` therefore reports a SMALLER set now: what remains is
//! residue this scan could not adjudicate — a root whose marker is missing, a
//! box that has not scanned, or the backlog from before D105 (production had
//! 1,849 such nodes from one folder, doc 24 section 18).

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

/// D105 — delete a file from a mount whose marker verifies, and the scan
/// finishes the job: the node leaves the tree and there is nothing left to
/// report. Before D105 it survived here "holding nothing", waiting for a
/// manual `missing --forget` that nobody ran.
#[test]
fn a_file_deleted_outside_pvfs_is_swept_on_a_proven_mount() {
    let (_t, mut engine, media, lib) = rig();
    std::fs::remove_file(lib.join("TV/Show/gone.mkv")).unwrap();
    engine.scan(Some(&media)).unwrap();

    let held = engine.files_held_by_nobody().unwrap();
    assert!(
        held.is_empty(),
        "the scan proved the mount and removed it; nothing should be left to \
         report: {held:?}"
    );

    // And it is OUT OF THE TREE. Before D105 the node survived the file and
    // anyone browsing the catalog was shown something that existed nowhere.
    let still_listed = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .any(|e| e.node.node_type == TYPE_FILE && e.label == "gone.mkv");
    assert!(
        !still_listed,
        "a file deleted from a proven mount must not still be listed"
    );
    // The one that stayed is untouched.
    assert!(engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .any(|e| e.node.node_type == TYPE_FILE && e.label == "keep.mkv"));
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

/// Reading a report must still never change it. The property survives D105 —
/// what changed is what the scan does, not what the reader does.
#[test]
fn the_report_changes_nothing_by_itself() {
    let (_t, mut engine, media, lib) = rig();
    std::fs::remove_file(lib.join("TV/Show/gone.mkv")).unwrap();
    engine.scan(Some(&media)).unwrap();

    let before = engine.files_held_by_nobody().unwrap().len();
    let again = engine.files_held_by_nobody().unwrap().len();
    assert_eq!(
        before, again,
        "reading the report twice must not change what it says — it is a \
         report, and a report that acts is a sweep"
    );
    engine.close().unwrap();
}
