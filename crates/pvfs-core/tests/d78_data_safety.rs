//! D74/D78 — the fixes that were only ever verified by hand.
//!
//! Every one of these was found by something going wrong on real data, and
//! several were mis-diagnosed at least once before the real cause surfaced.
//! None of them had a regression test until now, which meant the next
//! occurrence would have looked exactly as puzzling as the first.

use pvfs_core::sync::{verify_central_marker, write_central_marker, CENTRAL_MARKER};

/// A central store must PROVE it is the central store.
///
/// A central directory is usually a MOUNT. When the mount is absent the
/// mountpoint is still a perfectly good local directory — so the mover wrote
/// to it, reported "migrated into the central store", and the catalog recorded
/// bytes as safely central that were on the owner's own small disk.
/// Demonstrated on the lab: 16MB onto a VM root filesystem, every message
/// saying success.
#[test]
fn an_empty_unmarked_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = verify_central_marker(dir.path()).unwrap_err().to_string();
    assert!(
        err.contains("marker"),
        "an empty unmarked dir is the UNMOUNTED case and must be refused: {err}"
    );
}

#[test]
fn a_marked_directory_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    write_central_marker(dir.path(), "/srv/pvfs/media/.pvfs").unwrap();
    assert!(dir.path().join(CENTRAL_MARKER).exists());
    assert!(verify_central_marker(dir.path()).is_ok());
}

/// ADOPTION, and why it cannot simply pass on a missing marker.
///
/// Stores set up before the marker existed have none — refusing those would
/// break every existing forest on upgrade. But "no marker" is ALSO exactly what
/// an unmounted mountpoint looks like. The discriminator is CONTENT: an absent
/// mount is empty; a real library is not.
#[test]
fn a_non_empty_unmarked_store_is_adopted_not_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("existing-library-file.mkv"), b"x").unwrap();

    assert!(
        verify_central_marker(dir.path()).is_ok(),
        "a store that predates the marker but HOLDS the library is adopted"
    );
    assert!(
        dir.path().join(CENTRAL_MARKER).exists(),
        "and is marked once, so the next pass is unambiguous"
    );
}

/// The distinction that matters, stated as one test: same absence of a marker,
/// opposite answers, decided only by whether anything is there.
#[test]
fn empty_versus_non_empty_is_the_whole_discriminator() {
    let unmounted = tempfile::tempdir().unwrap();
    let real = tempfile::tempdir().unwrap();
    std::fs::write(real.path().join("Movie.mkv"), b"x").unwrap();

    assert!(
        verify_central_marker(unmounted.path()).is_err(),
        "empty + unmarked ⇒ probably an unmounted mount ⇒ REFUSE"
    );
    assert!(
        verify_central_marker(real.path()).is_ok(),
        "non-empty + unmarked ⇒ a store predating the marker ⇒ adopt"
    );
}

/// The marker must not be counted as content when deciding emptiness —
/// otherwise a store PVFS marked itself would look "non-empty" forever after,
/// and the unmounted case would stop being detectable.
#[test]
fn the_marker_alone_does_not_make_a_store_look_occupied() {
    let dir = tempfile::tempdir().unwrap();
    write_central_marker(dir.path(), "/some/forest").unwrap();
    std::fs::remove_file(dir.path().join(CENTRAL_MARKER)).unwrap();

    // Back to bare: this is the unmounted shape again and must refuse.
    assert!(
        verify_central_marker(dir.path()).is_err(),
        "a directory holding ONLY a marker, once that marker is gone, is empty"
    );
}

// ---------------------------------------------------------------------------
// The repair that could not repair.
// ---------------------------------------------------------------------------

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn bind_spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

/// A scan must reconcile LOCATIONS, not just nodes.
///
/// `scan_state` remembers that a uri was scanned, so a matching size+mtime
/// returned "unchanged" WITHOUT asking whether the location was still live.
/// After a pass wrongly retired 27,562 locations, a re-scan of the same 27,562
/// files reported every one of them unchanged and repaired NOTHING — the
/// catalog could not find bytes that were sitting right there, and rescanning,
/// the obvious remedy, was a no-op.
///
/// This is the whole failure in miniature: index a file, retire its location,
/// re-scan, and insist the location comes back.
#[test]
fn a_rescan_restores_a_location_that_was_retired() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("lib");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("ep.mkv"), vec![7u8; 2048]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
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
    engine.bind_folder(&media, bind_spec(&src)).unwrap();

    let first = engine.scan_routed(Some(&media), None, 0).unwrap();
    assert_eq!(first[0].stats.added, 1, "first scan indexes the file");

    // Find the node and its location, then retire it — exactly what the buggy
    // drain did to an entire library.
    let kids = engine.children(&media).unwrap();
    let tv = &kids[0];
    let file_id = if tv.node.node_type == TYPE_FOLDER {
        engine.children(&tv.node.id).unwrap()[0].node.id.clone()
    } else {
        tv.node.id.clone()
    };
    let locs = engine.locations(&file_id).unwrap();
    assert_eq!(locs.len(), 1, "one location to begin with");
    engine.remove_location(&file_id, &locs[0]).unwrap();
    assert!(
        engine.locations(&file_id).unwrap().is_empty(),
        "the catalog can no longer find bytes that are still on disk"
    );

    // THE REPAIR. Before the fix this reported "unchanged" and fixed nothing.
    let again = engine.scan_routed(Some(&media), None, 0).unwrap();
    assert_eq!(
        engine.locations(&file_id).unwrap().len(),
        1,
        "a re-scan MUST restore the location — otherwise the obvious remedy for \
         a lost location is a no-op, which is how 26,729 files stayed unfindable \
         through a full rescan"
    );
    assert_eq!(
        again[0].stats.added, 1,
        "and it reports the repair rather than calling it unchanged"
    );
    engine.close().unwrap();
}
