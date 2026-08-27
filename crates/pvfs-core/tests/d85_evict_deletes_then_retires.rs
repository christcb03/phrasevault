//! D85 — evict frees space in ONE step, in the safe order.
//!
//! Chris: *"remember the timing issue where removing the location first means
//! it doesn't know where to remove the file from, so they have to be done in
//! the same step. Have the daemon delete the file and then remove the location
//! from the node."*
//!
//! Evict used to act only on locations SOMEONE ELSE had already retired, which
//! split the job across two boxes. In this fleet the second box never ran — the
//! holder's `tier` is `pull_only` and never retires, and the owner does not run
//! `tier` at all — so evict idled while the ingest box grew to 558 GB.

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE};

fn staged(dir: &std::path::Path, body: &[u8]) -> (Engine, String, std::path::PathBuf) {
    let staging = dir.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let f = staging.join("ep.mkv");
    std::fs::write(&f, body).unwrap();

    let (mut e, _mn) = Engine::init(&dir.join("forest")).unwrap();
    let root = e.identity.root_node_id.clone();
    let id = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "ep.mkv".into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: body.len() as u64,
                    mime_type: "video/x-matroska".into(),
                    original_name: "ep.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    e.add_location(&id, &pvfs_core::storage::path_to_uri(&f).unwrap())
        .unwrap();
    // declare the staging root: this box says its copies here are disposable
    let sroot = pvfs_core::storage::path_to_uri(&staging).unwrap();
    pvfs_core::sync::set_staging_root(e.data_dir(), &root, &sroot, true).unwrap();
    (e, id, f)
}

fn holder_copy(e: &mut Engine, id: &str) {
    e.add_location(&id.to_string(), &format!("pvfs-host://{}/share/Media/ep.mkv", "ab".repeat(32)))
        .unwrap();
}

/// THE POINT: the file goes AND the location goes, in one pass, without anyone
/// having retired anything first.
#[test]
fn it_deletes_the_file_and_then_retires_the_location() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, id, path) = staged(dir.path(), b"the-bytes");
    holder_copy(&mut e, &id);

    let r = pvfs_core::sync::evict_pass(&mut e).unwrap();
    assert_eq!(r.evicted, 1, "skipped: {:?}", r.skipped);
    assert!(!path.exists(), "the local copy must be gone");
    let left = e.locations(&id).unwrap();
    assert!(
        !left.iter().any(|u| u.contains("staging")),
        "and its location must be retired in the SAME pass: {left:?}"
    );
    assert!(
        left.iter().any(|u| u.starts_with("pvfs-host://ab")),
        "the holder's copy must still be recorded"
    );
    e.close().unwrap();
}

/// Held nowhere else is never evicted. This is the guard that stops the pass
/// deleting the only copy of something.
#[test]
fn the_only_copy_is_never_evicted() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, id, path) = staged(dir.path(), b"the-bytes");
    // no holder copy added

    let r = pvfs_core::sync::evict_pass(&mut e).unwrap();
    assert_eq!(r.evicted, 0);
    assert!(path.exists(), "the only copy must survive");
    assert!(!e.locations(&id).unwrap().is_empty());
    e.close().unwrap();
}

/// A root that never declared itself draining keeps everything. Silence is not
/// consent for a pass whose job is deleting.
#[test]
fn an_undeclared_root_is_never_drained() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, id, path) = staged(dir.path(), b"the-bytes");
    holder_copy(&mut e, &id);
    // withdraw the declaration
    let root = e.identity.root_node_id.clone();
    let sroot = pvfs_core::storage::path_to_uri(&dir.path().join("staging")).unwrap();
    pvfs_core::sync::set_staging_root(e.data_dir(), &root, &sroot, false).unwrap();

    let r = pvfs_core::sync::evict_pass(&mut e).unwrap();
    assert_eq!(r.evicted, 0, "no declaration, no draining");
    assert!(path.exists());
    e.close().unwrap();
}

/// An arr's replacement lands at the SAME path. If the bytes on disk are not
/// the bytes the catalog recorded, they are a NEW file — and evicting them
/// destroys an upgrade before it is ever catalogued.
#[test]
fn a_replacement_at_the_same_path_is_never_evicted() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, id, path) = staged(dir.path(), b"the-bytes");
    holder_copy(&mut e, &id);
    // the arr overwrites with a bigger encode
    std::fs::write(&path, b"a-much-larger-replacement-encode").unwrap();

    let r = pvfs_core::sync::evict_pass(&mut e).unwrap();
    assert_eq!(r.evicted, 0, "size disagrees, so these are not the migrated bytes");
    assert!(path.exists(), "an uncatalogued upgrade must survive");
    e.close().unwrap();
}
