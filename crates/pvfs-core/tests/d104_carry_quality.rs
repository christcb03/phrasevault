//! D104 — carrying MediaQuality across a re-genesis.
//!
//! A fresh forest mints new node ids (they cover a random `creation_nonce`, so
//! they cannot reproduce — doc 24 §16). Everything keyed by the old id is
//! stranded, and `MediaQuality` is the expensive case: 24,585 measurements on
//! the production forest, none of them recoverable from the bytes.
//!
//! Path is the join key, because path is what a re-genesis preserves — the
//! *arrs and the mount already address that way.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn library(root: &std::path::Path) -> std::path::PathBuf {
    let lib = root.join("lib");
    std::fs::create_dir_all(lib.join("TV")).unwrap();
    std::fs::write(lib.join("TV/ep1.mkv"), vec![1u8; 2048]).unwrap();
    std::fs::write(lib.join("TV/ep2.mkv"), vec![2u8; 4096]).unwrap();
    lib
}

fn build(dir: &std::path::Path, lib: &std::path::Path) -> (Engine, String) {
    let (mut e, _mn) = Engine::init(dir).unwrap();
    let root = e.identity.root_node_id.clone();
    let folder = e
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
    e.bind_folder(
        &folder,
        BindSpec {
            source_uri: format!("file://{}", lib.display()),
            recursive: true,
            auto_index: true,
            extensions: String::new(),
            hash_policy: HashPolicy::OnAdd,
        },
    )
    .unwrap();
    e.scan_routed(Some(&folder), None, 0).unwrap();
    (e, folder)
}

fn file_id(e: &Engine, folder: &str, label: &str) -> String {
    e.walk(&folder.to_string())
        .unwrap()
        .into_iter()
        .find(|w| w.node.node_type == TYPE_FILE && w.label == label)
        .expect("file present")
        .node
        .id
}

#[test]
fn quality_survives_a_re_genesis_even_though_ids_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());

    // OLD forest, with a measurement on one of the two files.
    let (mut old, of) = build(&dir.path().join("old"), &lib);
    let old_ep1 = file_id(&old, &of, "ep1.mkv");
    let q = pvfs_core::media::MediaQuality {
        width: 3840,
        height: 2160,
        ..Default::default()
    };
    old.set_media_quality(&old_ep1, &q, "arr").unwrap();
    let carried_from = old.quality_by_path().unwrap();
    old.close().unwrap();

    assert_eq!(carried_from.len(), 1, "only the measured file is carried");
    let (path, _) = carried_from.iter().next().unwrap();
    assert!(path.ends_with("ep1.mkv"), "keyed by tree path: {path}");

    // NEW forest over the same bytes.
    let (mut new, nf) = build(&dir.path().join("new"), &lib);
    let new_ep1 = file_id(&new, &nf, "ep1.mkv");
    assert_ne!(
        new_ep1, old_ep1,
        "the premise: a fresh genesis does NOT reproduce node ids"
    );
    assert!(
        new.media_quality(&new_ep1).unwrap().is_none(),
        "and so the measurement did not come across on its own"
    );

    // A dry run reports and writes nothing.
    let (would, _, _) = new.carry_quality(&carried_from, true).unwrap();
    assert_eq!(would, 1);
    assert!(new.media_quality(&new_ep1).unwrap().is_none(), "dry run must not write");

    let (carried, kept, unmatched) = new.carry_quality(&carried_from, false).unwrap();
    assert_eq!((carried, kept, unmatched), (1, 0, 0));
    let got = new.media_quality(&new_ep1).unwrap().expect("carried");
    assert_eq!(got.0.height, 2160, "the measurement itself came across");
    assert_eq!(got.0.width, 3840);
    assert_eq!(got.1, "arr", "and its provenance with it");

    // Idempotent: running it again keeps what is here rather than re-signing.
    let (carried, kept, _) = new.carry_quality(&carried_from, false).unwrap();
    assert_eq!((carried, kept), (0, 1), "a second run must be a no-op");
    new.close().unwrap();
}

/// A path the new forest has no file for is REPORTED, not silently dropped —
/// that residue is the thing a re-genesis exists to surface.
#[test]
fn a_path_the_new_forest_lacks_is_counted_as_unmatched() {
    let dir = tempfile::tempdir().unwrap();
    let lib = library(dir.path());
    let (mut new, _nf) = build(&dir.path().join("new"), &lib);

    let mut from = std::collections::BTreeMap::new();
    from.insert(
        "Media/TV/gone.mkv".to_string(),
        (pvfs_core::media::MediaQuality::default(), "arr".to_string()),
    );
    let (carried, kept, unmatched) = new.carry_quality(&from, false).unwrap();
    assert_eq!((carried, kept, unmatched), (0, 0, 1));
    new.close().unwrap();
}
