//! D71 — `evict` must not delete a REPLACEMENT.
//!
//! A retired location row says "the copy that was here has been migrated". It
//! does not say the path is now free. Sonarr's upgrade writes the replacement
//! at exactly the same path — quality is not in the filename — so between that
//! write and the next scan the retired row points at NEW bytes.
//!
//! Found on the lab, not in review: a 1080p replacement was deleted this way,
//! silently, while the 720p copy sat on the NAS. The upgrade was destroyed
//! before it was ever catalogued. Size is the cheapest honest check, and it is
//! the same signal W6 uses for identity.

use std::fs;

use pvfs_core::{Engine, NodeSpec, TYPE_FILE};

#[test]
fn the_catalog_size_is_what_tells_a_replacement_from_the_evicted_copy() {
    let dir = tempfile::tempdir().unwrap();
    let (mut engine, _mn) = Engine::init(dir.path()).unwrap();
    let root = engine.identity.root_node_id.clone();

    let f = engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FILE.into(),
                label: "ep.mkv".into(),
                payload: pvfs_core::FilePayload {
                    content_hash: String::new(),
                    size_bytes: 900_000, // the 720p copy the catalog knows
                    mime_type: "video/x-matroska".into(),
                    original_name: "ep.mkv".into(),
                }
                .encode(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();

    assert_eq!(engine.payload_size_of(&f).unwrap(), Some(900_000));

    // The replacement on disk is a different size, which is exactly how evict
    // now tells "this is not the copy I migrated" and leaves it alone.
    let staging = dir.path().join("ep.mkv");
    fs::write(&staging, vec![0u8; 1_800_000]).unwrap();
    let on_disk = fs::metadata(&staging).unwrap().len();
    assert_ne!(
        engine.payload_size_of(&f).unwrap().unwrap(),
        on_disk,
        "a size mismatch is the signal that saves the upgrade"
    );
    engine.close().unwrap();
}
