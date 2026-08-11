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

// kill -9 mid-fetch never runs the sink's Drop; the startup sweep removes the
// leftover tmp but nothing else in the store (2026-08-11 chaos finding)
#[test]
fn startup_sweep_removes_orphaned_tmps() {
    let (dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();
    let file = engine
        .add_node(&root, file_spec("d.bin", b"data-bytes", true))
        .unwrap();

    // simulate the kill: an in-flight sink whose Drop never runs
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"half").unwrap();
    std::mem::forget(sink);
    let orphans = walkdir_files(&dir.path().join("synced"));
    assert_eq!(orphans.len(), 1, "orphan tmp on disk: {orphans:?}");

    // committed bytes and non-tmp names must survive the sweep
    let kept = engine
        .add_node(&root, file_spec("keep.bin", b"keep-bytes", true))
        .unwrap();
    let mut s = engine.sync_begin(&kept).unwrap();
    s.write_all(b"keep-bytes").unwrap();
    let published = engine.sync_commit(s).unwrap();
    let stray_dir = dir.path().join("synced").join("zz");
    std::fs::create_dir_all(&stray_dir).unwrap();
    let stray = stray_dir.join("notes.txt");
    std::fs::write(&stray, b"not a fetch tmp").unwrap();

    assert_eq!(sync::sweep_orphan_tmps(dir.path()).unwrap(), 1);
    assert!(!orphans[0].exists(), "orphan tmp removed");
    assert!(published.exists(), "committed store file untouched");
    assert!(stray.exists(), "non-tmp name untouched");

    // a fresh in-flight tmp begun after the sweep is untouched and commits
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"data").unwrap();
    assert_eq!(walkdir_files(&dir.path().join("synced")).len(), 3, "new tmp present");
    sink.write_all(b"-bytes").unwrap();
    engine.sync_commit(sink).unwrap();
    let mut out = Vec::new();
    engine.cat(&file, None, &mut out).unwrap();
    assert_eq!(out, b"data-bytes");

    // a forest that never synced (no store dir) sweeps to a clean zero
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(sync::sweep_orphan_tmps(empty.path()).unwrap(), 0);
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

// F5.1 (doc 17 §7.2): pvfs-host:// resolves only under the owning pin
#[test]
fn host_qualified_locations_resolve_by_pin() {
    use pvfs_core::storage::{host_pin, host_uri, parse_host_uri};

    let (dir, mut engine) = new_forest();
    let root = engine.identity.root_node_id.clone();

    // this instance's pin (normally minted by `pvfsd --listen`)
    let pin = "ab".repeat(32);
    std::fs::create_dir_all(dir.path().join("nettls")).unwrap();
    std::fs::write(dir.path().join("nettls/pin"), format!("{pin}\n")).unwrap();
    assert_eq!(host_pin(dir.path()).as_deref(), Some(pin.as_str()));

    // real bytes + a host-qualified location naming OUR pin
    let bytes_dir = tempfile::tempdir().unwrap();
    let path = bytes_dir.path().join("clip.bin");
    std::fs::write(&path, b"clip-bytes").unwrap();
    let uri = host_uri(&pin, &std::fs::canonicalize(&path).unwrap()).unwrap();
    let (p, pth) = parse_host_uri(&uri).unwrap();
    assert_eq!(p, pin);
    assert!(pth.ends_with("clip.bin"));

    let file = engine
        .add_node(&root, file_spec("clip.bin", b"clip-bytes", true))
        .unwrap();
    engine.add_location(&file, &uri).unwrap();
    let mut out = Vec::new();
    engine.cat(&file, None, &mut out).unwrap();
    assert_eq!(out, b"clip-bytes", "own pin resolves locally");

    // a FOREIGN pin never resolves here — the file counts as missing
    let foreign = engine
        .add_node(&root, file_spec("faraway.bin", b"remote!", true))
        .unwrap();
    let foreign_uri = host_uri(&"cd".repeat(32), &std::fs::canonicalize(&path).unwrap()).unwrap();
    engine.add_location(&foreign, &foreign_uri).unwrap();
    assert!(engine.readable_path(&foreign).unwrap().is_none());
    let missing = engine.missing_bytes(&root).unwrap();
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].1, "faraway.bin");
    // stat degrades to unavailable, never errors
    let st = engine.stat_node(&foreign).unwrap();
    assert!(st.locations.iter().all(|l| !l.exists));
}
