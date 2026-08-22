//! D81 — a measurement follows its file across attestation.
//!
//! Found by the lab run, not by any test here. Attestation mints a SUCCESSOR
//! node (the id is derived from the payload, and hashing changes the payload),
//! and `media_quality` is keyed by node id. Locations were carried across
//! deliberately; quality was not — so every file the mover attested silently
//! lost whatever the probe or the arrs had measured about it.
//!
//! At production scale that is the whole backfill coming apart one migration at
//! a time: 24,585 measurements, each stranded on a superseded node the moment
//! its file moved into the store.

use pvfs_core::media::MediaQuality;
use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

#[test]
fn quality_survives_the_successor_node_that_attestation_mints() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(lib.join("Movies/Title (2020)")).unwrap();
    std::fs::write(lib.join("Movies/Title (2020)/t.mkv"), vec![5u8; 4096]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
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
    engine.bind_folder(&media, spec(&lib)).unwrap();
    engine.scan(Some(&media)).unwrap();

    let id = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;

    let measured = MediaQuality {
        width: 1920,
        height: 1080,
        bit_depth: 10,
        hdr: "PQ".into(),
        bitrate: 8_000_000,
        video_codec: "hevc".into(),
        duration_s: 5400,
        decoded_ok: Some(true),
    };
    engine.set_media_quality(&id, &measured, "probe").unwrap();

    // Attest: this is what the mover does on migration, and it mints a NEW id.
    let new_id = engine.hash_node(&id).unwrap();
    assert_ne!(new_id, id, "attestation must produce a successor");

    let (carried, source) = engine
        .media_quality(&new_id)
        .unwrap()
        .expect("the successor must carry the measurement — otherwise every \
                 migration quietly discards what the probe learned");
    assert_eq!(carried.width, 1920);
    assert_eq!(carried.height, 1080);
    assert_eq!(carried.bit_depth, 10);
    assert_eq!(carried.hdr, "PQ");
    assert_eq!(carried.duration_s, 5400);
    assert_eq!(
        carried.decoded_ok,
        Some(true),
        "including the expensive one — a deep decode must not have to be redone \
         because the file was migrated"
    );
    assert_eq!(source, "probe", "and where it came from, unchanged");
    engine.close().unwrap();
}

/// A file nobody measured stays unmeasured — attestation must not invent one.
#[test]
fn attestation_does_not_invent_a_measurement() {
    let dir = tempfile::tempdir().unwrap();
    let lib = dir.path().join("lib");
    std::fs::create_dir_all(&lib).unwrap();
    std::fs::write(lib.join("t.mkv"), vec![6u8; 2048]).unwrap();

    let (mut engine, _mn) = Engine::init(dir.path().join("forest").as_path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let media = engine
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
    engine.bind_folder(&media, spec(&lib)).unwrap();
    engine.scan(Some(&media)).unwrap();
    let id = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id;

    let new_id = engine.hash_node(&id).unwrap();
    assert!(
        engine.media_quality(&new_id).unwrap().is_none(),
        "nothing measured it, so nothing is known — carrying forward must not \
         become manufacturing"
    );
    engine.close().unwrap();
}
