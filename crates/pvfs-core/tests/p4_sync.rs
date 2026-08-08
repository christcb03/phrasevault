//! F3 sync-store tests — doc 17 §6: hash-verified ingest, existence-is-record
//! locations, placement round-trip.

use std::io::Write as _;

use pvfs_core::{sync, Engine, FilePayload, NodeSpec, PvfsError, TYPE_FILE, TYPE_FOLDER};

fn new_forest() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _m) = Engine::init(dir.path()).unwrap();
    (dir, engine)
}

fn file_spec(label: &str, bytes: &[u8], hashed: bool) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FILE.into(),
        label: label.into(),
        payload: FilePayload {
            content_hash: if hashed {
                blake3::hash(bytes).to_hex().to_string()
            } else {
                String::new()
            },
            size_bytes: bytes.len() as u64,
            mime_type: "application/octet-stream".into(),
            original_name: label.into(),
        }
        .encode(),
        is_temp: false,
        creation_nonce: None,
    }
}

// verified ingest publishes atomically; the read path synthesizes the location
#[test]
fn sync_store_roundtrip_and_synthesized_location() {
    let (_dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let file = engine
        .add_node(&root, file_spec("movie.mkv", b"movie-bytes", true))
        .unwrap();

    // pointer without bytes: nothing readable, listed as missing
    assert!(engine.readable_path(&file).unwrap().is_none());
    let missing = engine.missing_bytes(&root).unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].1, "movie.mkv");

    // stream + commit
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"movie-bytes").unwrap();
    engine.sync_commit(sink).unwrap();

    // the store IS the record: location synthesized, reads verify end-to-end
    let locs = engine.locations(&file).unwrap();
    assert!(locs.iter().any(|u| u.starts_with("pvfs-sync:///")), "{locs:?}");
    assert!(engine.readable_path(&file).unwrap().is_some());
    let mut out = Vec::new();
    engine.cat(&file, None, &mut out).unwrap();
    assert_eq!(out, b"movie-bytes");
    assert!(engine.missing_bytes(&root).unwrap().is_empty());
}

// wrong bytes never land; a lazy (unhashed) node falls back to its size
#[test]
fn sync_commit_verifies_hash_and_size() {
    let (_dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();

    let hashed = engine
        .add_node(&root, file_spec("a.bin", b"expected", true))
        .unwrap();
    let mut sink = engine.sync_begin(&hashed).unwrap();
    sink.write_all(b"EVIL-bytes").unwrap();
    let err = engine.sync_commit(sink).unwrap_err();
    assert!(matches!(err, PvfsError::Integrity { .. }), "{err:?}");
    assert!(engine.readable_path(&hashed).unwrap().is_none(), "no bad bytes land");

    let lazy = engine
        .add_node(&root, file_spec("b.bin", b"12345", false))
        .unwrap();
    let mut sink = engine.sync_begin(&lazy).unwrap();
    sink.write_all(b"123").unwrap(); // truncated vs size 5
    assert!(engine.sync_commit(sink).is_err(), "size mismatch refused");
    let mut sink = engine.sync_begin(&lazy).unwrap();
    sink.write_all(b"12345").unwrap();
    engine.sync_commit(sink).unwrap();
    let mut out = Vec::new();
    engine.cat(&lazy, None, &mut out).unwrap();
    assert_eq!(out, b"12345");
}

// dropping an uncommitted sink leaves nothing behind
#[test]
fn abandoned_sink_cleans_up() {
    let (dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let file = engine
        .add_node(&root, file_spec("c.bin", b"data", true))
        .unwrap();
    {
        let mut sink = engine.sync_begin(&file).unwrap();
        sink.write_all(b"half").unwrap();
    } // dropped uncommitted
    let store_dir = dir.path().join("synced");
    let leftovers: Vec<_> = walkdir_files(&store_dir);
    assert!(leftovers.is_empty(), "no partial files: {leftovers:?}");
}

fn walkdir_files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walkdir_files(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// placement is a plain deployment file with set/unset semantics
#[test]
fn placement_roundtrip() {
    let (dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let a = engine.add_node(&root, folder("a")).unwrap();
    let b = engine.add_node(&root, folder("b")).unwrap();

    assert!(sync::load_placement(dir.path()).unwrap().is_empty());
    sync::set_placement(dir.path(), &a, true).unwrap();
    sync::set_placement(dir.path(), &b, true).unwrap();
    assert_eq!(sync::load_placement(dir.path()).unwrap(), vec![a.clone(), b.clone()]);
    sync::set_placement(dir.path(), &a, true).unwrap(); // idempotent re-place
    assert_eq!(sync::load_placement(dir.path()).unwrap().len(), 2);
    sync::set_placement(dir.path(), &a, false).unwrap(); // back to pointer
    assert_eq!(sync::load_placement(dir.path()).unwrap(), vec![b]);
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}
