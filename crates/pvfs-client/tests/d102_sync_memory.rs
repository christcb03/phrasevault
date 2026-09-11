//! D102 — `sync` gets the memory `tier` has.
//!
//! `sync_pass` built its `Fetcher` bare, and `sync_pull` never consulted the
//! unfetchable set, so D98's "stop asking a question already answered nowhere"
//! covered `tier` alone. Enabling `sync` on the production holder brought the
//! whole not_found retry storm back through a job that had never been given
//! the fix — found by watching a deploy, not by a test.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

/// D132 — a throwaway config dir for this binary, so no test here reads the
/// box's real instance registry (`XDG_CONFIG_HOME/pvfs/instances`). Set once
/// per process; every test in the file shares it, which is all the isolation
/// they need. The dir is deliberately leaked: the process is the lifetime.
fn isolate_config() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let dir = tempfile::tempdir().expect("config tempdir");
        std::env::set_var("XDG_CONFIG_HOME", dir.path());
        std::mem::forget(dir);
    });
}

#[test]
fn sync_skips_and_records_what_is_nowhere() {
    isolate_config();
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

    let id = engine
        .children(&media)
        .unwrap()
        .into_iter()
        .find(|c| c.node.label == "ep.mkv")
        .expect("scanned")
        .node
        .id;

    // Bytes gone without telling the catalog — the retired-mount shape.
    std::fs::remove_file(src.join("ep.mkv")).unwrap();

    // A seeded fetcher must SKIP it: no attempt, so no failure reported.
    let mut seeded = pvfs_client::fetch::Fetcher::new(&data_dir);
    seeded.seed_unfetchable([id.clone()]);
    let (fetched, failed) =
        pvfs_client::fetch::sync_pull(&mut engine, &mut seeded, std::slice::from_ref(&media)).unwrap();
    assert_eq!(fetched, 0);
    assert!(
        failed.is_empty(),
        "a node already known to be nowhere must not be re-reported every pass: {failed:?}"
    );

    // An UNSEEDED fetcher has no memory and must attempt it — otherwise the
    // skip above would be indistinguishable from sync doing nothing at all.
    let mut fresh = pvfs_client::fetch::Fetcher::new(&data_dir);
    let (_f, failed) =
        pvfs_client::fetch::sync_pull(&mut engine, &mut fresh, std::slice::from_ref(&media)).unwrap();
    assert_eq!(failed.len(), 1, "no memory yet, so it must attempt it once");

    // NOT asserted: that this attempt RECORDED the node. With no instance
    // registered the fetch never reaches a holder, so it fails with "no
    // reachable source" — which D98 deliberately does not cache, because that
    // wording also means an operator has not finished setup and caching it
    // would hide the very thing they need to see. Proving the recording half
    // needs a live peer answering not_found, the same gap D98's marking path
    // has. Left named rather than asserted loosely enough to pass.
    engine.close().unwrap();
}
