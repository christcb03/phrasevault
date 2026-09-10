//! D124 item 1 — a binding root is a prefix, not a LIKE pattern. `_` and `%`
//! are wildcards to LIKE, and the NAS binds `…/Data_ext/Media`: a sibling
//! root differing only at the `_` matched the wrong binding's policy.
//!
//! The lookup that used LIKE is `policy_for_uri`, consulted when a pending
//! change is resolved by replacement — so that is the path exercised here.

use pvfs_core::{BindSpec, Engine, FilePayload, HashPolicy, NodeSpec, ResolveAction, TYPE_FILE, TYPE_FOLDER};

fn folder(e: &mut Engine, parent: &str, label: &str) -> String {
    e.add_node(
        &parent.to_string(),
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

fn spec(dir: &std::path::Path, policy: HashPolicy) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: policy,
    }
}

fn file_hash(e: &Engine, folder: &str, label: &str) -> String {
    e.children(&folder.to_string())
        .unwrap()
        .into_iter()
        .find(|c| c.node.node_type == TYPE_FILE && c.label == label)
        .map(|c| FilePayload::decode(&c.node.payload).unwrap().content_hash)
        .unwrap_or_else(|| panic!("no file {label} under {folder}"))
}

#[test]
fn a_sibling_root_differing_only_at_an_underscore_keeps_its_own_policy() {
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data_ext"); // `_` is a LIKE wildcard
    let cold = tmp.path().join("DataXext"); // and this would match it
    std::fs::create_dir_all(&warm).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    std::fs::write(warm.join("w.mkv"), b"warm-bytes").unwrap();
    std::fs::write(cold.join("c.mkv"), b"cold-bytes").unwrap();

    let (mut e, _mn) = Engine::init(tmp.path().join("forest").as_path()).unwrap();
    let root = e.identity.root_node_id.clone();
    // The hashing binding is created FIRST, so a wildcard match would find
    // it first among equal-length roots.
    let a = folder(&mut e, &root, "Warm");
    e.bind_folder(&a, spec(&warm, HashPolicy::OnAdd)).unwrap();
    let b = folder(&mut e, &root, "Cold");
    e.bind_folder(&b, spec(&cold, HashPolicy::Never)).unwrap();
    e.scan_routed(None, None, 0).unwrap();
    assert!(!file_hash(&e, &a, "w.mkv").is_empty(), "on_add hashes");
    assert!(file_hash(&e, &b, "c.mkv").is_empty(), "never does not");

    // Change the cold file; the resolution asks `policy_for_uri` for ITS
    // binding's policy — `never`, from `DataXext`, not `on_add` from the
    // look-alike `Data_ext`.
    std::fs::write(cold.join("c.mkv"), b"cold-bytes-but-longer").unwrap();
    let r = e.scan_routed(Some(&b), None, 0).unwrap();
    assert_eq!(r[0].stats.changed, 1);
    let old = e
        .children(&b)
        .unwrap()
        .into_iter()
        .find(|c| c.label == "c.mkv")
        .unwrap()
        .node
        .id;
    let new = e.resolve(&old, ResolveAction::Replace).unwrap();
    let hash = FilePayload::decode(&e.node(&new).unwrap().unwrap().payload)
        .unwrap()
        .content_hash;
    assert!(hash.is_empty(), "the replacement must follow the cold root's `never`, got {hash}");
}
