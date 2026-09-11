//! D122 item 6 — a quarantined copy is not a central copy. Before this, a
//! library copy caught serving the wrong bytes still counted as "satisfied",
//! so the mover planned nothing and the bad bytes stayed the library's only
//! copy. Now the pass wants a good copy brought in.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

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

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

#[test]
fn a_quarantined_library_copy_does_not_satisfy_the_mover() {
    isolate_config();
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");
    let rel = "Movies/Bad Copy (2001)/bad.mkv";
    std::fs::create_dir_all(warm.join("Movies/Bad Copy (2001)")).unwrap();
    std::fs::write(warm.join(rel), vec![7u8; 6000]).unwrap();

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
    engine.bind_folder(&media, spec(&warm)).unwrap();
    engine.scan_routed(Some(&media), None, 0).unwrap();
    let data_dir = engine.data_dir().to_path_buf();
    pvfs_core::sync::set_central(&data_dir, &media, &warm, true).unwrap();
    pvfs_core::sync::set_central_tree(&data_dir, &media, true).unwrap();

    let file = engine
        .walk(&media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == TYPE_FILE)
        .map(|e| e.node.id)
        .expect("the scan catalogued the file");
    let uri = engine.locations(&file).unwrap().remove(0);
    assert!(uri.starts_with("file://"), "{uri}");

    // Premise: with a healthy library copy the pass is satisfied.
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let before = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("a central placement exists");
    assert_eq!((before.satisfied, before.planned.len()), (1, 0));

    // The copy is caught serving the wrong bytes (what D99's marking records).
    let c = rusqlite::Connection::open(data_dir.join("index.db")).unwrap();
    c.execute(
        "INSERT INTO location_quarantine (file_id, uri, reason, detected_at) VALUES (?1, ?2, 'test: id mismatch', 0)",
        rusqlite::params![file, uri],
    )
    .unwrap();

    // THE POINT: it no longer satisfies; the mover wants a good copy in.
    let mut fetcher = pvfs_client::fetch::Fetcher::new(&data_dir);
    let after = pvfs_client::fetch::tier_pass_opts(&mut engine, &mut fetcher, true)
        .unwrap()
        .expect("a central placement exists");
    assert_eq!(after.satisfied, 0, "a quarantined copy is not a central copy");
    assert!(!after.planned.is_empty(), "the pass plans to bring a good copy: {after:?}");
}
