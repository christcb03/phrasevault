//! D71 W6 — identity by content, not by path; and don't catalogue a file that
//! is still being written.
//!
//! Chris's rule: *files with the same name and exact size are really the same
//! file even living in different folders, so it doesn't have to re-catalogue,
//! just change the pointer location.*
//!
//! Without it a file that moves is a NEW file — which is why a copy migrated to
//! the NAS would be catalogued twice, and why letting Sonarr reorganise folders
//! would duplicate a library.
//!
//! The settle rule is measured, not defensive: Sonarr COPIES into the library
//! (every sampled file on feederbox has link count 1, because its source and
//! destination are different filesystems from its own view), so a 5.8 GB import
//! grows under its final name for minutes. Identity is by EXACT SIZE, so
//! cataloguing a half-copied file records a wrong size and mis-identifies it
//! forever after.

use std::fs;
use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &Path) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

fn folder(engine: &mut Engine, parent: &String, label: &str) -> String {
    engine
        .add_node(
            parent,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: label.into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap()
}

/// Make a file old enough that the scan considers it settled. std's
/// `FileTimes` keeps this dependency-free.
fn aged(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    let f = fs::File::options().write(true).open(path).unwrap();
    let old = std::time::SystemTime::now() - std::time::Duration::from_secs(120);
    f.set_times(fs::FileTimes::new().set_modified(old)).unwrap();
}

/// THE rule: the same name and exact size in a different folder is the same
/// file — a location, not a new node.
#[test]
fn a_moved_file_gets_a_location_not_a_second_node() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let a = folder(&mut engine, &root, "shelf-a");
    let src_a = tempfile::tempdir().unwrap();
    aged(&src_a.path().join("Show - s01e01.mkv"), b"the same bytes");
    engine.bind_folder(&a, spec(src_a.path())).unwrap();
    engine.scan(Some(&a)).unwrap();

    let files = engine
        .walk(&root)
        .unwrap()
        .into_iter()
        .filter(|e| e.node.label.ends_with(".mkv"))
        .count();
    assert_eq!(files, 1, "one file so far");

    // The same file turns up somewhere else entirely.
    let b = folder(&mut engine, &root, "shelf-b");
    let src_b = tempfile::tempdir().unwrap();
    aged(&src_b.path().join("Show - s01e01.mkv"), b"the same bytes");
    engine.bind_folder(&b, spec(src_b.path())).unwrap();
    let rep = engine.scan(Some(&b)).unwrap();

    assert_eq!(rep[0].stats.relocated, 1, "recognised, not re-catalogued");
    assert_eq!(rep[0].stats.added, 0, "no new node may be created");

    let files = engine
        .walk(&root)
        .unwrap()
        .into_iter()
        .filter(|e| e.node.label.ends_with(".mkv"))
        .count();
    assert_eq!(files, 1, "still ONE file node, now with two locations");
    engine.close().unwrap();
}

/// The upgrade case, which is the normal one: same name, DIFFERENT size
/// (720p → 1080p) is a genuinely different file and must not be merged.
#[test]
fn same_name_different_size_is_a_real_upgrade() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let a = folder(&mut engine, &root, "sd");
    let src_a = tempfile::tempdir().unwrap();
    aged(&src_a.path().join("Show - s01e01.mkv"), b"720p");
    engine.bind_folder(&a, spec(src_a.path())).unwrap();
    engine.scan(Some(&a)).unwrap();

    let b = folder(&mut engine, &root, "hd");
    let src_b = tempfile::tempdir().unwrap();
    aged(
        &src_b.path().join("Show - s01e01.mkv"),
        b"1080p, which is bigger",
    );
    engine.bind_folder(&b, spec(src_b.path())).unwrap();
    let rep = engine.scan(Some(&b)).unwrap();

    assert_eq!(rep[0].stats.relocated, 0, "different size is NOT the same file");
    assert_eq!(rep[0].stats.added, 1, "the upgrade is its own node");
    engine.close().unwrap();
}

/// Ambiguity refuses. Two candidates are not evidence of anything — sidecars
/// are exactly where a name+size rule would otherwise invent nonsense.
///
/// Note how this state has to be BUILT: with W6 active you cannot reach it by
/// scanning, because the first duplicate is merged on sight. It arises from a
/// catalog written before W6 existed, or from direct API use — which is what
/// the guard is for, and why the fixture adds the nodes directly.
#[test]
fn an_ambiguous_match_refuses_and_makes_a_new_node() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let payload = |size: u64| {
        pvfs_core::FilePayload {
            content_hash: String::new(),
            size_bytes: size,
            mime_type: "image/jpeg".into(),
            original_name: "poster.jpg".into(),
        }
        .encode()
    };
    for shelf in ["show-a", "show-b"] {
        let f = folder(&mut engine, &root, shelf);
        engine
            .add_node(
                &f,
                NodeSpec {
                    node_type: pvfs_core::TYPE_FILE.into(),
                    label: "poster.jpg".into(),
                    payload: payload(3),
                    is_temp: false,
                    creation_nonce: None,
                },
            )
            .unwrap();
    }

    let c = folder(&mut engine, &root, "show-c");
    let src_c = tempfile::tempdir().unwrap();
    aged(&src_c.path().join("poster.jpg"), b"art");
    engine.bind_folder(&c, spec(src_c.path())).unwrap();
    let rep = engine.scan(Some(&c)).unwrap();

    assert_eq!(
        rep[0].stats.relocated, 0,
        "two candidates is not a match — refuse rather than guess"
    );
    assert_eq!(rep[0].stats.added, 1);
    engine.close().unwrap();
}

/// A file still being written is DEFERRED, not catalogued and not dropped —
/// otherwise its half-size is recorded and identity is wrong forever after.
#[test]
fn a_file_still_being_written_is_deferred_then_taken() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = folder(&mut engine, &root, "library");
    let src = tempfile::tempdir().unwrap();
    engine.bind_folder(&f, spec(src.path())).unwrap();

    // Fresh mtime = Sonarr is still copying. The window is the WATCHER's, not
    // every scan's — a one-shot scan indexes what is on disk now.
    fs::write(src.path().join("growing.mkv"), b"first half").unwrap();
    let rep = engine
        .scan_routed(Some(&f), None, pvfs_core::WATCH_SETTLE_MS)
        .unwrap();
    assert_eq!(rep[0].stats.settling, 1, "still moving — must not be catalogued");
    assert_eq!(rep[0].stats.added, 0);

    // The copy finishes and the file stops changing.
    aged(&src.path().join("growing.mkv"), b"first half and second half");
    let rep = engine
        .scan_routed(Some(&f), None, pvfs_core::WATCH_SETTLE_MS)
        .unwrap();
    assert_eq!(rep[0].stats.settling, 0);
    assert_eq!(rep[0].stats.added, 1, "deferred, never dropped");
    engine.close().unwrap();
}
