//! D105 — a file deleted from a mount PROVEN live leaves the tree.
//!
//! The scan used to stop at the location, because it could not tell a
//! deliberate deletion from an unmounted volume — so `pvfs missing` reported
//! the residue and waited for `--forget`. But `scan_binding` calls
//! `verify_root_marker` first, which is the check Chris asked for in D81
//! precisely so that difference could be told. Once the mount is proven, a
//! second manual step only asks the operator to confirm what the marker
//! already established.
//!
//! What that omission cost: one folder unlinked, locations correctly retired,
//! and 1,849 node records left behind for a fortnight (doc 24 §18).

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn setup(dir: &std::path::Path) -> (Engine, String, std::path::PathBuf) {
    let lib = dir.join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("keep.mkv"), vec![1u8; 2048]).unwrap();
    std::fs::write(lib.join("gone.mkv"), vec![2u8; 2048]).unwrap();

    let (mut e, _mn) = Engine::init(&dir.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let folder = e
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
    e.bind_folder(
        &folder,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&folder), None, 0).unwrap();
    (e, folder, lib)
}

fn names(e: &Engine, folder: &str) -> Vec<String> {
    e.children(&folder.to_string())
        .unwrap()
        .into_iter()
        .filter(|c| c.node.node_type == TYPE_FILE)
        .map(|c| c.label)
        .collect()
}

/// The whole point: delete a file, and it leaves the tree — no second step.
#[test]
fn a_deleted_file_leaves_the_tree() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, folder, lib) = setup(dir.path());
    assert_eq!(names(&e, &folder).len(), 2, "both indexed to begin with");

    std::fs::remove_file(lib.join("gone.mkv")).unwrap();
    let reports = e.scan_routed(Some(&folder), None, 0).unwrap();

    let left = names(&e, &folder);
    assert_eq!(left, vec!["keep.mkv".to_string()], "the deleted file is out of the tree");
    let unlinked: u64 = reports.iter().map(|r| r.stats.unlinked).sum();
    assert_eq!(unlinked, 1, "and it is REPORTED as unlinked, not silently gone");

    // And it is out of the WALK too, not merely absent from one listing —
    // that distinction is the whole of the islands problem (doc 24 section 18).
    let walked: Vec<String> = e
        .walk(&e.identity.root_node_id.clone())
        .unwrap()
        .into_iter()
        .filter(|w| w.node.node_type == TYPE_FILE)
        .map(|w| w.label)
        .collect();
    assert_eq!(walked, vec!["keep.mkv".to_string()]);
    e.close().unwrap();
}

/// The safety rule. A file this box no longer holds but ANOTHER box still does
/// stays in the tree — losing a local copy is not the file being deleted.
/// Without this, one box evicting its copy would delete the file for everyone.
#[test]
fn a_file_another_box_still_holds_stays() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, folder, lib) = setup(dir.path());

    let id = e
        .children(&folder.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.label == "gone.mkv")
        .unwrap()
        .node
        .id;
    // a second holder, as a replica's scan would have recorded
    e.add_location(&id, &format!("pvfs-host://{}/elsewhere/gone.mkv", "ab".repeat(32)))
        .unwrap();

    std::fs::remove_file(lib.join("gone.mkv")).unwrap();
    let reports = e.scan_routed(Some(&folder), None, 0).unwrap();

    let mut left = names(&e, &folder);
    left.sort();
    assert_eq!(
        left,
        vec!["gone.mkv".to_string(), "keep.mkv".to_string()],
        "still held elsewhere, so it stays in the tree"
    );
    let unlinked: u64 = reports.iter().map(|r| r.stats.unlinked).sum();
    assert_eq!(unlinked, 0, "and nothing was unlinked");
    e.close().unwrap();
}
