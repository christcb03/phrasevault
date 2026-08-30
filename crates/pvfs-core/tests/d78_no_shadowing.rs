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
        hash_policy: HashPolicy::OnAdd,
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

/// SUPERSEDED BEHAVIOUR, KEPT AS A TEST OF THE PROPERTY THAT MATTERED.
///
/// D78 pinned "one folder has ONE binding", because a second bind silently
/// REPLACING the first is what switched off feederbox's watcher. The refusal
/// was the fix available at the time; it was never the point.
///
/// D81 removes the one-binding limit — Chris needs `Data` and `Data_ext` as
/// roots of one library — and in doing so makes the original bug impossible by
/// construction rather than by refusal: a second bind now sits ALONGSIDE the
/// first, so there is nothing left to be shadowed. This test therefore asserts
/// the property D78 cared about (the first root survives a second bind) rather
/// than the mechanism it used to get it (refusal).
#[test]
fn a_second_bind_never_displaces_the_first() {
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

    // A second bind of the SAME folder now ADDS a root (D81). What must never
    // happen — then or now — is the first one quietly ceasing to be scanned.
    engine
        .bind_folder(&media, spec(&b))
        .expect("a second root is a supported topology, not an error");
    let rows = engine.bindings().unwrap();
    assert_eq!(rows.len(), 2, "both roots, not one replacing the other");
    assert!(
        rows.iter().any(|r| r.source_uri.ends_with("/a")),
        "THE ORIGINAL BUG: the first root must still be there — its
         disappearance is what silently stopped feederbox indexing: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r.source_uri.ends_with("/b")),
        "{rows:?}"
    );
    engine.close().unwrap();
}
