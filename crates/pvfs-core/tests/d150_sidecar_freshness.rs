//! D150 — a sidecar older than its file is not trusted.
//!
//! D91's exact-size check refuses a sidecar when an arr's upgrade changes the
//! size, which is nearly always. What it let through is a SAME-size
//! replacement: an in-place tag edit (`mkvpropedit` rewrites a header without
//! changing the length), or another encode that matches to the byte. The scan
//! then took the old file's hash from the sidecar. Chris, 2026-09-14: "will it
//! think the already existing manifest is correct or will it re-hash?"
//!
//! The rule: a sidecar is trusted only if it is not older than its file's
//! mtime. Every writer lays one down after the bytes are final, and
//! `write_manifest_sidecar` never leaves one dated before its file — which is
//! what keeps a file dated in the future from being re-hashed forever.

use pvfs_core::sync;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Over SWARM_CHUNK, so there is more than one chunk hash to get wrong.
const SIZE: usize = 9 * 1024 * 1024;

fn set_mtime(p: &Path, t: SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(p)
        .unwrap()
        .set_modified(t)
        .unwrap();
}

fn mtime(p: &Path) -> SystemTime {
    std::fs::metadata(p).unwrap().modified().unwrap()
}

/// A file and a sidecar written for exactly these bytes.
fn file_with_sidecar(dir: &Path, byte: u8) -> (std::path::PathBuf, String) {
    let f = dir.join("ep.mkv");
    std::fs::write(&f, vec![byte; SIZE]).unwrap();
    let (whole, chunks) = sync::hash_with_manifest(&f).unwrap();
    sync::write_manifest_sidecar(&f, Some(&whole), &chunks).unwrap();
    (f, whole)
}

/// Rewrite the file's bytes in place at the same length, the way a tag editor
/// does, with the sidecar left an hour behind (so no filesystem's timestamp
/// granularity can make them look simultaneous).
fn edit_in_place(f: &Path, byte: u8) {
    let side = sync::manifest_sidecar_path(f);
    set_mtime(&side, SystemTime::now() - Duration::from_secs(3600));
    std::fs::write(f, vec![byte; SIZE]).unwrap();
}

#[test]
fn a_same_size_edit_in_place_is_not_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let (f, whole) = file_with_sidecar(dir.path(), 7);
    let size = SIZE as u64;
    assert_eq!(
        sync::sidecar_hashes(&f, size).map(|(w, _)| w),
        Some(whole.clone()),
        "a sidecar written after its file is the record it is meant to be"
    );

    edit_in_place(&f, 8);
    assert!(
        sync::sidecar_hashes(&f, size).is_none(),
        "same size, but the file changed after the sidecar was written — the \
         old hash would go into the catalog"
    );
    assert!(sync::sidecar_whole_hash(&f, size).is_none());
    assert!(sync::sidecar_chunks(&f).is_empty(), "the backfill must not carry stale chunks either");
}

#[test]
fn a_rewritten_sidecar_is_trusted_again() {
    let dir = tempfile::tempdir().unwrap();
    let (f, _) = file_with_sidecar(dir.path(), 7);
    edit_in_place(&f, 8);
    let (fresh, chunks) = sync::hash_with_manifest(&f).unwrap();
    sync::write_manifest_sidecar(&f, Some(&fresh), &chunks).unwrap();
    assert_eq!(
        sync::sidecar_whole_hash(&f, SIZE as u64),
        Some(fresh),
        "the scan re-hashed and wrote a new record; the next one must use it"
    );
}

#[test]
fn a_file_dated_in_the_future_keeps_its_sidecar_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("ep.mkv");
    std::fs::write(&f, vec![5u8; SIZE]).unwrap();
    set_mtime(&f, SystemTime::now() + Duration::from_secs(86_400));
    let (whole, chunks) = sync::hash_with_manifest(&f).unwrap();
    sync::write_manifest_sidecar(&f, Some(&whole), &chunks).unwrap();

    assert!(
        mtime(&sync::manifest_sidecar_path(&f)) >= mtime(&f),
        "the writer must not leave a sidecar dated before its file"
    );
    assert_eq!(
        sync::sidecar_whole_hash(&f, SIZE as u64),
        Some(whole),
        "otherwise this file is re-hashed on every pass, forever"
    );
}

fn bind(engine: &mut Engine, lib: &Path) -> String {
    let root = engine.identity.root_node_id.clone();
    let folder = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: "M".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    engine
        .bind_folder(
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
    folder
}

fn hash_of(engine: &Engine, folder: &str) -> String {
    engine
        .children(&folder.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.node_type == TYPE_FILE)
        .map(|c| pvfs_core::FilePayload::decode(&c.node.payload).unwrap().content_hash)
        .expect("a file node")
}

/// End to end, the way the NAS would meet it: a library scanned once (the
/// sidecar is written), the file then edited in place at the same size, and a
/// scan into a fresh forest. It must record the NEW bytes' hash.
#[test]
fn a_scan_rehashes_a_same_size_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    let f = lib.join("ep.mkv");
    std::fs::write(&f, vec![7u8; SIZE]).unwrap();

    let (mut a, _mn) = Engine::init(&dir.path().join("fa")).unwrap();
    let fa = bind(&mut a, &lib);
    a.scan_routed(Some(&fa), None, 0).unwrap();
    let old = hash_of(&a, &fa);
    a.close().unwrap();
    assert!(sync::manifest_sidecar_path(&f).exists(), "on_add leaves the record (D103)");

    edit_in_place(&f, 8);
    let (new, _) = sync::hash_with_manifest(&f).unwrap();
    assert_ne!(old, new);

    let (mut b, _mn) = Engine::init(&dir.path().join("fb")).unwrap();
    let fb = bind(&mut b, &lib);
    b.scan_routed(Some(&fb), None, 0).unwrap();
    let got = hash_of(&b, &fb);
    b.close().unwrap();
    assert_eq!(got, new, "the scan took the edited file's hash from a stale sidecar");
}
