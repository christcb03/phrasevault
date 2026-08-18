//! D71 W2 — a delete mirrors to the holder's filesystem, via the trash.
//!
//! The mount retires the link (routed, from whatever box the user is on); the
//! box that actually owns the bytes tidies its own filesystem. The owner never
//! reaches across NFS to delete on the NAS — a holder reclaims its own.
//!
//! Conservative by construction, and these tests pin each guard: only
//! tree-layout roots, only when the node has no live link left, and always to
//! the trash rather than to `unlink`.

use std::fs;

use pvfs_core::{Engine, NodeSpec, TYPE_FILE};

fn file_node(engine: &mut Engine, parent: &String, label: &str, size: u64) -> String {
    engine
        .add_node(
            parent,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: label.into(),
                payload: pvfs_core::FilePayload {
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

/// A node that still hangs in the tree has not been deleted — whatever
/// happened to one of its locations, its bytes stay put.
#[test]
fn a_still_linked_node_is_never_reclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = file_node(&mut engine, &root, "ep.mkv", 5);
    assert!(
        engine.node_is_linked(&f).unwrap(),
        "freshly added ⇒ linked ⇒ alive"
    );
    engine.close().unwrap();
}

/// Once the last link is retired the node is gone, which is what tells the
/// holder its bytes may be reclaimed.
#[test]
fn retiring_the_last_link_makes_a_node_unlinked() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = file_node(&mut engine, &root, "ep.mkv", 5);

    let link = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == f)
        .unwrap()
        .link_id;
    engine.remove_link(&link).unwrap();

    assert!(
        !engine.node_is_linked(&f).unwrap(),
        "no live link ⇒ deleted ⇒ the holder may reclaim"
    );
    engine.close().unwrap();
}

/// With no tree-layout root configured the pass does nothing at all: a
/// node-addressed store stays `evict`'s territory.
#[test]
fn reclaim_is_inert_without_a_tree_root() {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _mn) = Engine::init(dir.path()).unwrap();
    let rep = pvfs_core::sync::reclaim_pass(&engine, dir.path()).unwrap();
    assert_eq!(rep.removed, 0);
    engine.close().unwrap();
}

/// The reclaim never destroys: bytes go to the trash, recoverable by a move
/// back, because after `evict` this is the only copy.
#[test]
fn reclaimed_bytes_go_to_the_trash_not_to_unlink() {
    let nas = tempfile::tempdir().unwrap();
    let episode = nas.path().join("Media/TV/Show/Season 01/ep.mkv");
    fs::create_dir_all(episode.parent().unwrap()).unwrap();
    fs::write(&episode, b"the only copy").unwrap();

    let moved = pvfs_core::sync::move_to_trash(nas.path(), &episode).unwrap();
    assert!(!episode.exists());
    assert_eq!(fs::read(&moved).unwrap(), b"the only copy");

    // Restoring is a move back — that is the entire point of the guard.
    fs::create_dir_all(episode.parent().unwrap()).unwrap();
    fs::rename(&moved, &episode).unwrap();
    assert_eq!(fs::read(&episode).unwrap(), b"the only copy");
}

/// A path still claimed by a LIVE node is never reclaimed, even when a dead
/// node also references it.
///
/// This is the rename shape: the successor inherits the old node's locations
/// and the old node is retired, so for a moment one file is referenced by both
/// a dead node and a live one. Without this guard the sweep would trash the
/// bytes the surviving node depends on — turning a rename into data loss.
#[test]
fn a_path_a_live_node_still_claims_is_never_reclaimed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let old = file_node(&mut engine, &root, "before.mkv", 10);
    let new = file_node(&mut engine, &root, "after.mkv", 10);
    let uri = "file:///nas/Media/Show/before.mkv";
    engine.add_location(&old, uri).unwrap();
    engine.add_location(&new, uri).unwrap(); // the successor inherits it

    // Retire the old node, exactly as a rename does.
    let link = engine
        .children(&root)
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == old)
        .unwrap()
        .link_id;
    engine.remove_link(&link).unwrap();
    assert!(!engine.node_is_linked(&old).unwrap());
    assert!(engine.node_is_linked(&new).unwrap());

    let orphans = engine.orphaned_local_locations().unwrap();
    assert!(
        !orphans.iter().any(|(_, p)| p.to_string_lossy().contains("before.mkv")),
        "the surviving node still needs those bytes — never reclaim them"
    );
    engine.close().unwrap();
}
