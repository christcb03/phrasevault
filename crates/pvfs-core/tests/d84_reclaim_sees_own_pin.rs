//! D84 — reclaim must see the locations THIS box actually wrote.
//!
//! `orphaned_local_locations` tested `uri LIKE 'file://%'`. A replica records
//! its locations pin-qualified (D75/D81), so on the holder — the only box that
//! has the bytes — the sweep matched nothing. Measured live: 34 collision
//! losers sat on the NAS, reclaim ran, and moved 0 of them, because every one
//! was written `pvfs-host://<own pin>/…`.
//!
//! The owner this test was written for holds no media at all, which is why
//! nobody noticed.

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE};

fn file_node(e: &mut Engine, parent: &str, label: &str, size: u64) -> String {
    e.add_node(
        &parent.to_string(),
        NodeSpec {
            node_type: TYPE_FILE.into(),
            label: label.into(),
            payload: FilePayload {
                content_hash: String::new(),
                size_bytes: size,
                mime_type: "video/x-matroska".into(),
                original_name: label.into(),
            }
            .encode(),
            is_temp: false,
            creation_nonce: None,
        },
    )
    .unwrap()
}

/// A host-implicit `file://` orphan is found — the behaviour that already
/// worked, kept honest.
#[test]
fn a_plain_file_uri_orphan_is_found() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = dir.path().join("gone.mkv");
    std::fs::write(&bytes, vec![b'a'; 512]).unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "gone.mkv", 512);
    e.add_location(&id, &pvfs_core::storage::path_to_uri(&bytes).unwrap())
        .unwrap();
    // unlink it: a live location whose node has no live link IS the orphan
    let link = e
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == id)
        .unwrap()
        .link_id;
    e.remove_link(&link).unwrap();

    let orphans = e.orphaned_local_locations().unwrap();
    assert!(
        orphans.iter().any(|(n, p)| *n == id && p == &bytes),
        "a file:// orphan must still be found: {orphans:?}"
    );
    e.close().unwrap();
}

/// A node that is STILL LINKED is never an orphan, whatever its uri form —
/// this is the guard that stops a sweep trashing the live library.
#[test]
fn a_linked_node_is_never_an_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = dir.path().join("keep.mkv");
    std::fs::write(&bytes, vec![b'a'; 512]).unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "keep.mkv", 512);
    e.add_location(&id, &pvfs_core::storage::path_to_uri(&bytes).unwrap())
        .unwrap();

    let orphans = e.orphaned_local_locations().unwrap();
    assert!(
        !orphans.iter().any(|(n, _)| *n == id),
        "a node still in the tree must never be swept"
    );
    e.close().unwrap();
}

/// ANOTHER holder's pin is not ours to sweep. Trashing bytes on a box we are
/// not is the one outcome worse than leaving an orphan.
#[test]
fn another_holders_pin_is_never_swept() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = file_node(&mut e, &root, "elsewhere.mkv", 512);
    let foreign = "aa".repeat(32);
    e.add_location(&id, &format!("pvfs-host://{foreign}/srv/other/elsewhere.mkv"))
        .unwrap();
    let link = e
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == id)
        .unwrap()
        .link_id;
    e.remove_link(&link).unwrap();

    let orphans = e.orphaned_local_locations().unwrap();
    assert!(
        !orphans.iter().any(|(n, _)| *n == id),
        "another box's bytes are not ours to trash: {orphans:?}"
    );
    e.close().unwrap();
}
