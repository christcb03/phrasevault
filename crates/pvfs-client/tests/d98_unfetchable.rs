//! D98 — the mover stops asking a question already answered "nowhere".
//!
//! A `not_found` from every holder is not a busy peer, it is a stale catalog
//! entry: the bytes are not somewhere slow, they are nowhere, and nothing in
//! the fleet can satisfy it until the CATALOG changes. Re-asking next pass asks
//! the same peers the same question.
//!
//! Measured on the live holder: 317 such nodes, 29,093 attempts, ~92 apiece.
//! The mover was not broken — it was shouting, and every genuine failure was
//! buried among identical lines.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

#[test]
fn a_node_known_to_be_nowhere_is_not_re_attempted() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("local");
    let store = tmp.path().join("store");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::create_dir_all(&store).unwrap();
    std::fs::write(src.join("ep.mkv"), vec![7u8; 4096]).unwrap();

    let (mut engine, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
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
    engine
        .bind_folder(
            &media,
            BindSpec {
                source_uri: format!("file://{}", src.display()),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::OnAdd,
            },
        )
        .unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();

    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &store, false).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let id = engine
        .children(&media)
        .unwrap()
        .into_iter()
        .find(|c| c.node.label == "ep.mkv")
        .expect("scanned")
        .node
        .id;

    // Take the bytes away WITHOUT telling the catalog — exactly the shape of a
    // retired mount: the location still says the file is there, and it is not.
    std::fs::remove_file(src.join("ep.mkv")).unwrap();

    // A pass that already knows this node is nowhere must not ask again. It is
    // counted, not reported as a failure: a stale catalog entry is a thing to
    // fix once, not news every 300 seconds.
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    fetcher.seed_unfetchable([id.clone()]);
    let report = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, false)
        .unwrap()
        .expect("something is placed central");
    assert_eq!(report.unfetchable, 1, "the known-nowhere node was skipped");
    assert!(
        report.failed.is_empty(),
        "and NOT re-reported as a failure — that is the noise being removed: {:?}",
        report.failed
    );
    assert_eq!(report.migrated, 0, "nothing could be migrated, correctly");

    // The memory must not become a blindfold: a fetcher without it tries again,
    // which is what lets a repaired catalog recover (the daemon re-tests
    // periodically for the same reason).
    let mut fresh = pvfs_client::fetch::Fetcher::new(&data_dir);
    let again = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fresh, false)
        .unwrap()
        .expect("still placed central");
    assert_eq!(
        again.unfetchable, 0,
        "an unseeded pass has no memory and must attempt it"
    );
    assert_eq!(
        again.failed.len(),
        1,
        "and that attempt fails honestly, once: {:?}",
        again.failed
    );
    engine.close().unwrap();
}
