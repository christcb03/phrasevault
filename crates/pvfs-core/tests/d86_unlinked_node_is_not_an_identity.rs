//! A node that is no longer in the tree cannot own a file on disk.
//!
//! D84's collision pass unlinks a losing duplicate but leaves its LOCATIONS
//! active. The scan then kept resolving the file on disk to that dead node —
//! `scan_state` remembered the mapping, and the location really was live — so
//! every pass tried to fill its hash, and every pass was refused: rights are
//! inherited from the parent the node no longer has.
//!
//! Measured on feederbox: 2 files, 1,070 refusals in 24 hours, each one having
//! first re-read and re-hashed the whole file (606 MB for one of them). The
//! refusal was correct; arriving at it after the read was not, and neither was
//! leaving the file effectively absent from the tree.
//!
//! So an unlinked node is treated as a MISS. The identity path only matches
//! linked nodes, which is precisely the node that should have had the location
//! all along.

use pvfs_core::{BindSpec, Engine, FilePayload, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

fn media(engine: &mut Engine) -> String {
    let root = engine.identity.root_node_id.clone();
    engine
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
        .unwrap()
}

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

/// Unlink the node the scan already knows about, leaving its location live.
fn unlink(e: &mut Engine, parent: &str, id: &str) {
    let link = e
        .children(&parent.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.id == id)
        .expect("child to unlink")
        .link_id;
    e.remove_link(&link).unwrap();
}

fn hashed(e: &Engine, id: &str) -> bool {
    let n = e.node(&id.to_string()).unwrap().unwrap();
    FilePayload::decode(&n.payload)
        .map(|p| !p.content_hash.is_empty())
        .unwrap_or(false)
}

/// The production shape: a loser holding the live location, a winner in the
/// tree. The file must end up on the winner, not stuck on the loser.
#[test]
fn a_file_rehomes_onto_the_duplicate_that_won() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("ep.mkv"), vec![9u8; 4096]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();
    engine.scan(Some(&m)).unwrap();

    // The node the first scan made — this becomes the LOSER.
    let loser = engine
        .children(&m)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "ep.mkv")
        .expect("scanned file")
        .node
        .id;

    // A duplicate that stays in the tree, exactly as a collision winner would.
    let winner = file_node(&mut engine, &m, "ep.mkv", 4096);
    assert_ne!(winner, loser);
    unlink(&mut engine, &m, &loser);

    engine.scan(Some(&m)).unwrap();

    // Exactly one live `ep.mkv` — the file re-homed, it did not fork again.
    let live: Vec<_> = engine
        .children(&m)
        .unwrap()
        .into_iter()
        .filter(|c| c.label == "ep.mkv")
        .collect();
    assert_eq!(live.len(), 1, "one live ep.mkv, not a third node");
    // Filling a hash RE-IDENTIFIES the node (the id is content-derived), so the
    // node holding the location is the winner's successor, not the winner's
    // original id. What matters is that it descends from the linked node and
    // not from the unlinked one.
    let now = live[0].node.id.clone();
    assert_ne!(now, loser, "never the unlinked node");
    assert!(
        !engine.locations(&now).unwrap().is_empty(),
        "the live node holds the file's location"
    );
    assert!(
        hashed(&engine, &now),
        "a linked node can be written, so the scan filled its hash"
    );
    engine.close().unwrap();
}

/// With no winner to inherit it, the file is re-catalogued rather than left in
/// limbo — and the unlinked node's bytes are never read on the way there.
///
/// The orphan is built by hand precisely so it is UNHASHED: a scanned one would
/// have been hashed while it was still linked, and could not show whether the
/// second pass had touched it.
#[test]
fn with_no_winner_the_file_is_recatalogued_and_the_orphan_is_never_read() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("library");
    std::fs::create_dir_all(&lib).unwrap();
    let bytes = lib.join("ep.mkv");
    std::fs::write(&bytes, vec![4u8; 2048]).unwrap();
    let uri = pvfs_core::storage::path_to_uri(&std::fs::canonicalize(&bytes).unwrap()).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let m = media(&mut engine);
    engine.bind_folder(&m, spec(&lib)).unwrap();

    // An unhashed node holding the live location, then cut out of the tree —
    // the state D84's collision pass leaves behind.
    let orphan = file_node(&mut engine, &m, "ep.mkv", 2048);
    engine.add_location(&orphan, &uri).unwrap();
    unlink(&mut engine, &m, &orphan);
    assert!(!hashed(&engine, &orphan), "precondition: unhashed");

    engine.scan(Some(&m)).unwrap();

    let back = engine
        .children(&m)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "ep.mkv")
        .expect("the file is in the tree again");
    assert_ne!(
        back.node.id, orphan,
        "on a node that is linked, not the unlinked one"
    );
    assert!(
        hashed(&engine, &back.node.id),
        "and it is hashed, so the swarm can serve it"
    );
    assert!(
        !hashed(&engine, &orphan),
        "the orphan's bytes were never read — the guard runs BEFORE the hash"
    );
    engine.close().unwrap();
}
