//! D78 — adopting a store must not steal the folder's binding.
//!
//! The bug, in production: `pvfs place … central --to <dir>` bound the placed
//! folder on the OWNER so it could index the store's existing contents. But
//! bindings are keyed `folder_id PRIMARY KEY` — one row per folder, fleet-wide
//! — and a LOGGED binding beats a machine's local one by design ("a local row
//! for it would be this box shadowing the fleet").
//!
//! So the ingest box's binding to /mnt/local/Media vanished from its own view,
//! its watcher scanned nothing, and it reported `running` with no error while
//! new downloads went uncatalogued. It was only noticed because Chris asked for
//! an unrelated explanation of the layout.
//!
//! Adoption is a ONE-SHOT index. It has no business claiming the binding.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

/// Indexing a store must leave the binding table untouched.
#[test]
fn adopting_a_store_leaves_no_binding_behind() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    std::fs::create_dir_all(store.join("TV").join("Show").join("Season 01")).unwrap();
    std::fs::write(
        store.join("TV/Show/Season 01/ep.mkv"),
        vec![0u8; 4096],
    )
    .unwrap();

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

    assert!(engine.bindings().unwrap().is_empty(), "clean slate");

    let sp = spec(&store);
    let uri = sp.source_uri.clone();
    let stats = engine
        .scan_unbound(&media, &uri, &sp, &mut None, 0)
        .unwrap();

    assert_eq!(stats.added, 1, "the store's existing file is indexed");
    assert!(
        engine.bindings().unwrap().is_empty(),
        "indexing a store must NOT create a binding — a logged one shadows \
         every replica's local binding for the same folder, which is how the \
         ingest box's watcher was silently switched off"
    );
    engine.close().unwrap();
}

/// The property that made the bug possible, pinned so it cannot surprise
/// anyone again: one folder has ONE binding, and the second bind replaces the
/// first rather than sitting alongside it.
#[test]
fn a_folder_has_exactly_one_binding_fleet_wide() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();

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

    engine.bind_folder(&media, spec(&a)).unwrap();
    assert_eq!(engine.bindings().unwrap().len(), 1);

    // A second bind of the SAME folder is refused rather than silently
    // replacing the first — which is what makes `scan_unbound` necessary.
    let second = engine.bind_folder(&media, spec(&b));
    assert!(
        second.is_err(),
        "binding an already-bound folder must be refused, not silently taken over"
    );
    let rows = engine.bindings().unwrap();
    assert_eq!(rows.len(), 1, "still exactly one");
    assert!(
        rows[0].source_uri.ends_with("/a"),
        "and it is still the FIRST one: {}",
        rows[0].source_uri
    );
    engine.close().unwrap();
}
