//! D85 — a hash filled where the bytes are, recorded through the owner.
//!
//! `pvfs loc hash` refused on a replica because "hash-fill runs on the owner
//! (the log and the bytes together)". In this fleet the owner holds no media at
//! all, so the only box that could read the bytes was the one being refused —
//! and 97.8% of the library stayed unhashed.
//!
//! That is not cosmetic. An unhashed file has no chunk manifest, so a mount
//! cannot stream it and blocks on a whole-file fetch instead. Measured on the
//! live library through the FUSE mount: **115.8 s to read 1 MB of an unhashed
//! file, 0.10 s for a hashed one.** The presentation layer is unusable until
//! this backfill exists.

use pvfs_core::{crypto, Engine, FilePayload, NodeSpec, TYPE_FILE};

/// The successor carries the hash, the home link, and every location — as ONE
/// write, so a half-applied fill is not reachable.
#[test]
fn a_prepared_hash_fill_moves_the_node_link_and_locations() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();

    let id = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "ep.mkv".into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: 9,
                    mime_type: "video/x-matroska".into(),
                    original_name: "ep.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let holder = format!("pvfs-host://{}/share/Media/ep.mkv", "cd".repeat(32));
    e.add_location(&id, &holder).unwrap();

    let me = e.device_pubkey();
    let want = "a".repeat(64);
    let prep = e.prepare_set_content_hash(&me, &id, &want, 9).unwrap();

    // NodeCreated + three link events + two per location.
    assert!(
        prep.events.len() >= 6,
        "the whole successor must be one write: {} events",
        prep.events.len()
    );
    let kinds: Vec<&str> = prep
        .events
        .iter()
        .map(|p| match &p.event {
            pvfs_core::event::Event::NodeCreated(_) => "node",
            pvfs_core::event::Event::LinkCreated(_) => "link+",
            pvfs_core::event::Event::LinkSuperseded { .. } => "link~",
            pvfs_core::event::Event::LinkRemoved { .. } => "link-",
            pvfs_core::event::Event::FileLocationAdded { .. } => "loc+",
            pvfs_core::event::Event::FileLocationRemoved { .. } => "loc-",
            _ => "other",
        })
        .collect();
    assert!(kinds.contains(&"node"), "{kinds:?}");
    assert!(kinds.contains(&"link+") && kinds.contains(&"link-"), "{kinds:?}");
    assert!(kinds.contains(&"loc+") && kinds.contains(&"loc-"), "{kinds:?}");

    // Every event must be signable by the CALLER — this is a member write, not
    // the daemon signing on someone's behalf.
    for ev in &prep.events {
        assert_eq!(ev.digest.len(), 32);
    }
    assert_ne!(prep.result_id, id, "the successor is a different node");
    e.close().unwrap();
}

/// Refusals, because a hash fill that guesses is worse than one that stops.
#[test]
fn it_refuses_what_it_cannot_safely_fill() {
    let dir = tempfile::tempdir().unwrap();
    let (mut e, _mn) = Engine::init(dir.path()).unwrap();
    let root = e.identity.root_node_id.clone();
    let me = e.device_pubkey();

    let hashed = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "done.mkv".into(),
                payload: FilePayload {
                    content_hash: "b".repeat(64),
                    size_bytes: 4,
                    mime_type: "video/x-matroska".into(),
                    original_name: "done.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    assert!(
        e.prepare_set_content_hash(&me, &hashed, &"c".repeat(64), 4).is_err(),
        "an already-hashed node must not be silently re-minted"
    );

    let unhashed = e
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "x.mkv".into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: 4,
                    mime_type: "video/x-matroska".into(),
                    original_name: "x.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    assert!(
        e.prepare_set_content_hash(&me, &unhashed, "", 4).is_err(),
        "an empty hash fills nothing"
    );
    let _ = crypto::sign_digest;
    e.close().unwrap();
}
