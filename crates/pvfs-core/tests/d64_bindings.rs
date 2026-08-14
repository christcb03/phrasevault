//! D64 — the enrollment listing: live bindings joined with placement state
//! into their doc-21 kinds (in-place / migrate / mirror).

use std::fs;
use std::path::Path;

use pvfs_core::{BindKind, BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn new_forest() -> (tempfile::TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let (engine, _m) = Engine::init(dir.path()).unwrap();
    (dir, engine)
}

fn add_folder(engine: &mut Engine, label: &str) -> String {
    let root = engine.identity.root_node_id.clone();
    engine
        .add_node(
            &root,
            NodeSpec {
                node_type: TYPE_FOLDER.into(),
                label: label.into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap()
}

fn spec(dir: &Path) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

#[test]
fn listing_joins_placement_into_kinds() {
    let (data, mut engine) = new_forest();
    let inplace = add_folder(&mut engine, "inplace");
    let staging = add_folder(&mut engine, "staging");
    let photos = add_folder(&mut engine, "photos");

    let src_a = tempfile::tempdir().unwrap();
    let src_b = tempfile::tempdir().unwrap();
    let src_c = tempfile::tempdir().unwrap();
    let store_m = tempfile::tempdir().unwrap();
    let store_k = tempfile::tempdir().unwrap();

    engine.bind_folder(&inplace, spec(src_a.path())).unwrap();
    engine.bind_folder(&staging, spec(src_b.path())).unwrap();
    pvfs_core::sync::set_central(data.path(), &staging, store_m.path(), false).unwrap();
    engine.bind_folder(&photos, spec(src_c.path())).unwrap();
    pvfs_core::sync::set_central(data.path(), &photos, store_k.path(), true).unwrap();

    // A placed subtree that was never bound is placement, not an enrollment.
    let placed_only = add_folder(&mut engine, "placed-only");
    pvfs_core::sync::set_central(data.path(), &placed_only, store_m.path(), false).unwrap();

    let rows = engine.binding_listing().unwrap();
    assert_eq!(rows.len(), 3, "placement-only nodes must not appear");

    let row = |id: &str| rows.iter().find(|r| r.binding.folder_id == id).unwrap();

    let r = row(&inplace);
    assert_eq!(r.kind, BindKind::InPlace);
    assert_eq!(r.store, None);
    assert_eq!(r.folder_path.as_deref(), Some("/inplace"));

    let r = row(&staging);
    assert_eq!(r.kind, BindKind::Migrate);
    assert_eq!(r.store.as_deref(), Some(store_m.path()));
    assert_eq!(r.folder_path.as_deref(), Some("/staging"));

    let r = row(&photos);
    assert_eq!(r.kind, BindKind::Mirror);
    assert_eq!(r.store.as_deref(), Some(store_k.path()));
    assert_eq!(r.folder_path.as_deref(), Some("/photos"));

    // Unbind ends the enrollment; its placement row alone must not revive it.
    engine.unbind_folder(&staging).unwrap();
    let rows = engine.binding_listing().unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.binding.folder_id != staging));

    engine.close().unwrap();
}
