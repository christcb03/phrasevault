//! F5.6 (doc 17 §7.7): the mover attests. An unhashed lazy-pointer file
//! (the arr hook's `pvfs add` + `loc add --here` shape) gains its
//! hash-fill successor + attestation DURING migration — verified from
//! the real bytes, owner-signed — so the central copy lands under the
//! attested id and consumers can stream + verify from then on.

use std::io::Write as _;

use pvfs_core::{Engine, FilePayload, NodeSpec, TYPE_FILE};

#[test]
fn tier_attests_unhashed_ingest() {
    let cfg = tempfile::tempdir().unwrap();
    std::env::set_var("XDG_CONFIG_HOME", cfg.path());

    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    // The hook's exact output: file node with NO content hash, one
    // foreign-pin location; bytes reachable via the sync store.
    let file = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "episode.mkv".into(),
                payload: FilePayload {
                    content_hash: String::new(),
                    size_bytes: 9,
                    mime_type: "video/x-matroska".into(),
                    original_name: "episode.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    let edge_pin = "2d".repeat(32);
    engine
        .add_location(&file, &format!("pvfs-host://{edge_pin}/mnt/local/episode.mkv"))
        .unwrap();
    let mut sink = engine.sync_begin(&file).unwrap();
    sink.write_all(b"real-bits").unwrap();
    engine.sync_commit(sink).unwrap();

    let store = tempfile::tempdir().unwrap();
    pvfs_core::sync::set_central(engine.data_dir(), &root, store.path(), false).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let report = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher)
        .unwrap()
        .expect("placement exists");
    assert_eq!(report.migrated, 1, "failed: {:?}", report.failed);

    // The old id is gone from the tree; the attested successor stands.
    let kids = engine.children(&root).unwrap();
    let successor = kids
        .iter()
        .find(|c| c.node.label == "episode.mkv")
        .expect("the file is still in the tree");
    assert_ne!(successor.node.id, file, "a successor replaced the lazy pointer");
    let payload = FilePayload::decode(&successor.node.payload).unwrap();
    assert_eq!(
        payload.content_hash,
        blake3::hash(b"real-bits").to_hex().to_string(),
        "hash filled from the REAL bytes"
    );
    assert!(
        engine.attested_manifest_root(&successor.node.id).unwrap().is_some(),
        "chunk manifest attested — the mount can stream this now"
    );

    // The central copy lives under the NEW id; its location rides the
    // successor; the edge row was retired (central live).
    let new_id = successor.node.id.clone();
    assert!(
        store.path().join(&new_id[..2]).join(&new_id).is_file(),
        "store is node-addressed under the attested id"
    );
    let locs = engine.locations(&new_id).unwrap();
    assert!(
        locs.iter().any(|u| u.starts_with("file://") && u.contains(&new_id[..2])),
        "store row on the successor: {locs:?}"
    );
    assert!(
        !locs.iter().any(|u| u.contains(&edge_pin)),
        "edge copy retired after the central landed: {locs:?}"
    );

    // Idempotence: a second pass is satisfied, nothing re-migrates.
    let report2 = pvfs_client::fetch::tier_pass(&mut engine, &mut fetcher)
        .unwrap()
        .unwrap();
    assert_eq!(report2.satisfied, 1);
    assert_eq!(report2.migrated, 0);

    // And hash_node on an already-hashed file is a stable no-op.
    assert_eq!(engine.hash_node(&new_id).unwrap(), new_id);
}
