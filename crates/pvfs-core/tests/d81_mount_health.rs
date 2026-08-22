//! D81 4d — a bound root must PROVE the volume is there before pruning it.
//!
//! Chris: "can we have a file that the system looks for to verify the mount
//! itself is healthy… as long as that file is readable we can assume the mount
//! is there for the purposes of a scan, if that file isn't readable just report
//! a possible mount issue and don't change any files."
//!
//! The existing guard checks the bound PATH exists. That catches an unmounted
//! volume only when the mountpoint vanishes with it. A volume that mounts EMPTY
//! — or whose mountpoint directory outlives the unmount, which is the normal
//! case — passes, and then every tracked location under it stats as gone and
//! the deletion pass retires the lot. Same shape as the D74 drain that stranded
//! 26,729 files.

use pvfs_core::sync::{verify_root_marker, write_root_marker, ROOT_MARKER};
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

/// THE DANGEROUS CASE: present, empty, unmarked. That is an absent mount.
#[test]
fn an_empty_unmarked_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = verify_root_marker(dir.path()).unwrap_err().to_string();
    assert!(err.contains(ROOT_MARKER), "{err}");
    assert!(
        err.to_lowercase().contains("unmounted"),
        "it must name the thing that is actually wrong: {err}"
    );
}

/// A marked root is fine even when empty — a staging dir legitimately empties
/// itself every time the mover drains it.
#[test]
fn a_marked_root_is_fine_when_empty() {
    let dir = tempfile::tempdir().unwrap();
    write_root_marker(dir.path(), "forest-1").unwrap();
    assert!(
        verify_root_marker(dir.path()).is_ok(),
        "feederbox's staging root is empty every time it drains; refusing that \
         would stop ingest dead"
    );
}

/// Roots that predate the marker are adopted, not refused — content is the
/// discriminator, exactly as for central stores.
#[test]
fn a_non_empty_unmarked_root_is_adopted() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Movie.mkv"), b"x").unwrap();
    assert!(verify_root_marker(dir.path()).is_ok());
    assert!(
        dir.path().join(ROOT_MARKER).exists(),
        "and marked once, so the next pass is unambiguous"
    );
}

/// End to end: the volume goes away, and the scan REFUSES rather than
/// retiring every location on it.
#[test]
fn a_vanished_volume_stops_the_scan_instead_of_emptying_the_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let vol = dir.path().join("Data_ext");
    std::fs::create_dir_all(vol.join("Movies/Cold (1998)")).unwrap();
    std::fs::write(vol.join("Movies/Cold (1998)/cold.mkv"), vec![1u8; 2048]).unwrap();

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
    engine.bind_folder(&media, spec(&vol)).unwrap();
    engine.scan(Some(&media)).unwrap();

    let file = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;
    assert_eq!(engine.locations(&file).unwrap().len(), 1);

    // The volume unmounts. On a real box the mountpoint DIRECTORY remains —
    // that is the case the path check cannot see.
    std::fs::remove_dir_all(&vol).unwrap();
    std::fs::create_dir_all(&vol).unwrap();

    let err = engine.scan(Some(&media)).unwrap_err().to_string();
    assert!(
        err.contains(ROOT_MARKER),
        "the scan must refuse, naming the marker: {err}"
    );
    assert_eq!(
        engine.locations(&file).unwrap().len(),
        1,
        "AND CHANGE NOTHING — the catalog still knows where the bytes are, \
         which is the whole point: the volume is missing, not the library"
    );
    engine.close().unwrap();
}

/// A directory SKELETON is not a library.
///
/// Found on the NAS, not in a test: a root whose files had all moved away still
/// had its empty `Movies/` tree, and `read_dir().next().is_some()` called that
/// a real library and adopted it. An unmounted mountpoint keeps whatever
/// directory structure was created on it, so directories are not evidence of
/// anything — and adopting one lets the next scan retire every location under
/// it, which is the whole failure this guard exists to prevent.
#[test]
fn an_empty_directory_tree_is_not_evidence_of_a_library() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("Movies/Some Title (2001)")).unwrap();
    std::fs::create_dir_all(dir.path().join("TV/A Show/Season 01")).unwrap();

    let err = verify_root_marker(dir.path()).unwrap_err().to_string();
    assert!(
        err.to_lowercase().contains("unmounted"),
        "a skeleton with no files in it is exactly what an absent mount looks \
         like: {err}"
    );
    assert!(
        !dir.path().join(ROOT_MARKER).exists(),
        "and it must NOT be adopted and marked — that would bless the skeleton \
         permanently"
    );
}

/// One file anywhere beneath it, however deep, is enough.
#[test]
fn a_single_file_deep_in_the_tree_is_enough_to_adopt() {
    let dir = tempfile::tempdir().unwrap();
    let deep = dir.path().join("TV/A Show/Season 01");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("ep.mkv"), b"x").unwrap();

    assert!(
        verify_root_marker(dir.path()).is_ok(),
        "a real library that predates the marker must still be adopted, and its \
         files may be several levels down"
    );
    assert!(dir.path().join(ROOT_MARKER).exists());
}
