//! D85 — a scan fills the hashes it finds empty.
//!
//! Chris: *"We setup PVFS to lazy hash when adding a large library like this.
//! It seems that isn't very useful since it can't serve the files properly in a
//! swarm which is the whole point of the file system... It should also hash any
//! newly found or known but unhashed files on each scan."*
//!
//! An unhashed file has no chunk manifest, so the swarm refuses it and a mount
//! cannot stream it — measured through FUSE, **115.8 s to read 1 MB unhashed
//! against 0.10 s hashed**. Lazy hashing left the library permanently in its
//! least useful state.
//!
//! Making the SCAN fill them is what removes the need for a bulk backfill tool:
//! it converges (each file hashed once, skipped after), and an interrupted pass
//! simply resumes on the next one.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path, policy: HashPolicy) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: policy,
    }
}

fn library(root: &std::path::Path, n: usize) -> std::path::PathBuf {
    let media = root.join("Media");
    std::fs::create_dir_all(&media).unwrap();
    for i in 1..=n {
        std::fs::write(media.join(format!("ep{i:02}.mkv")), vec![b'a' + i as u8; 512 + i]).unwrap();
    }
    media
}

fn unhashed_count(e: &Engine, folder: &str) -> usize {
    e.walk(&folder.to_string())
        .unwrap()
        .entries
        .iter()
        .filter(|x| x.node.node_type == pvfs_core::TYPE_FILE)
        .filter(|x| e.needs_hash(&x.node.id).unwrap_or(false))
        .count()
}

/// A library that was left unhashed must be filled by a later scan — the state
/// 97.8% of the production library was in, and still the state of the 27,050
/// files the holder is working through.
///
/// D94 — this used to reach that state via `lazy`, which is now gone precisely
/// because it was the default and left libraries like this. `Never` is how you
/// ask for an unhashed node on purpose, and re-binding `on_add` is the
/// migration the real fleet is doing: bind a library that was never hashed, and
/// the next pass fills it.
#[test]
fn a_later_scan_fills_hashes_an_unhashed_bind_left_empty() {
    let dir = tempfile::tempdir().unwrap();
    let media = library(&dir.path().join("lib"), 5);
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
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

    // bound NEVER: nothing is hashed, which is the state the library starts in
    let bare = spec(&media, HashPolicy::Never);
    let uri = bare.source_uri.clone();
    e.scan_unbound(&folder, &uri, &bare, &mut None, 0).unwrap();
    assert_eq!(unhashed_count(&e, &folder), 5, "a `never` bind hashes nothing");

    // scan again as on_add — the pass fills what it finds empty
    let again = spec(&media, HashPolicy::OnAdd);
    e.scan_unbound(&folder, &uri, &again, &mut None, 0).unwrap();
    assert_eq!(
        unhashed_count(&e, &folder),
        0,
        "a scan must fill every empty hash it meets"
    );
    e.close().unwrap();
}

/// It CONVERGES: once filled, a further scan changes nothing. Without this the
/// pass would re-mint successors forever and the node ids would never settle.
#[test]
fn a_second_pass_over_hashed_files_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let media = library(&dir.path().join("lib"), 3);
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
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
    let sp = spec(&media, HashPolicy::OnAdd);
    let uri = sp.source_uri.clone();
    e.scan_unbound(&folder, &uri, &sp, &mut None, 0).unwrap();
    assert_eq!(unhashed_count(&e, &folder), 0);

    let ids_before: Vec<String> = e
        .walk(&folder)
        .unwrap()
        .entries
        .iter()
        .filter(|x| x.node.node_type == pvfs_core::TYPE_FILE)
        .map(|x| x.node.id.clone())
        .collect();

    e.scan_unbound(&folder, &uri, &sp, &mut None, 0).unwrap();
    let ids_after: Vec<String> = e
        .walk(&folder)
        .unwrap()
        .entries
        .iter()
        .filter(|x| x.node.node_type == pvfs_core::TYPE_FILE)
        .map(|x| x.node.id.clone())
        .collect();
    assert_eq!(ids_before, ids_after, "an already-hashed file must not be re-minted");
    e.close().unwrap();
}

/// `never` still means never — an explicit opt-out has to keep working, or the
/// policy is not a policy.
#[test]
fn never_still_means_never() {
    let dir = tempfile::tempdir().unwrap();
    let media = library(&dir.path().join("lib"), 3);
    let (mut e, _mn) = Engine::init(&dir.path().join("forest")).unwrap();
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
    let sp = spec(&media, HashPolicy::Never);
    let uri = sp.source_uri.clone();
    e.scan_unbound(&folder, &uri, &sp, &mut None, 0).unwrap();
    e.scan_unbound(&folder, &uri, &sp, &mut None, 0).unwrap();
    assert_eq!(unhashed_count(&e, &folder), 3, "`never` must not be overridden by the fill");
    e.close().unwrap();
}
