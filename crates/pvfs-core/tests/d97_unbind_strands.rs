//! D97 — unbinding a root strands every location beneath it, permanently.
//!
//! `unbind_folder` records `FolderUnboundRoot` and touches no locations, and
//! the scan reconciles ONLY under a bound prefix — it builds its candidate set
//! from `binding.source_uri`. So the moment a root is unbound, every location
//! beneath it falls outside every prefix and nothing examines it again.
//!
//! In the field: 79 locations survived D80's NFS unmount, and a week later the
//! mover was still trying to fetch from a mount that no longer existed, 92
//! attempts apiece, burying real failures in 29,093 identical lines.
//!
//! `locations_under_root` is what lets `unbind` say so before doing it.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FOLDER};

fn write_file(path: &Path, contents: &[u8]) {
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).unwrap();
    }
    fs::File::create(path).unwrap().write_all(contents).unwrap();
}

fn folder(label: &str) -> NodeSpec {
    NodeSpec {
        node_type: TYPE_FOLDER.into(),
        label: label.into(),
        payload: Vec::new(),
        is_temp: false,
        creation_nonce: None,
    }
}

#[test]
fn unbind_can_say_what_it_strands_before_it_does_it() {
    let data = tempfile::tempdir().unwrap();
    let lib = tempfile::tempdir().unwrap();
    write_file(&lib.path().join("a.mkv"), b"aaa");
    write_file(&lib.path().join("sub/b.mkv"), b"bbb");

    let (mut engine, _mn) = Engine::init(data.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, folder("library")).unwrap();
    engine
        .bind_folder(
            &f,
            BindSpec {
                source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(lib.path()).unwrap())
                    .unwrap(),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::Never,
            },
        )
        .unwrap();
    engine.scan(Some(&f)).unwrap();

    let src = engine.bindings_for(&f).unwrap()[0].source_uri.clone();
    let found = engine.locations_under_root(&src).unwrap();
    assert_eq!(found.len(), 2, "both files' locations are under this root");

    // A location somewhere else entirely must NOT be swept up — this is the
    // difference between "what this unbind strands" and "everything".
    let other = tempfile::tempdir().unwrap();
    write_file(&other.path().join("elsewhere.mkv"), b"ccc");
    let g = engine.add_node(&root, folder("other")).unwrap();
    engine
        .bind_folder(
            &g,
            BindSpec {
                source_uri: pvfs_core::storage::path_to_uri(
                    &fs::canonicalize(other.path()).unwrap(),
                )
                .unwrap(),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::Never,
            },
        )
        .unwrap();
    engine.scan(Some(&g)).unwrap();
    assert_eq!(
        engine.locations_under_root(&src).unwrap().len(),
        2,
        "another root's locations are not this root's problem"
    );

    // And retiring one takes it out of the answer: `unbind` must not offer to
    // retire what is already retired.
    let (id, uri) = found[0].clone();
    engine.remove_location(&id, &uri).unwrap();
    assert_eq!(
        engine.locations_under_root(&src).unwrap().len(),
        1,
        "only LIVE locations are stranded; a retired one is already handled"
    );

    // The point of the whole exercise: unbind does not touch them, so without
    // being told, they are simply lost to every automatic pass.
    engine.unbind_folder(&f, Some(&src)).unwrap();
    assert_eq!(
        engine.locations_under_root(&src).unwrap().len(),
        1,
        "unbind leaves them exactly where they were — which is the bug this warns about"
    );
    assert!(
        engine.bindings_for(&f).unwrap().is_empty(),
        "and the binding really is gone, so nothing reconciles them now"
    );
    engine.close().unwrap();
}

/// The half that would silently report nothing.
///
/// A replica records its locations PIN-QUALIFIED (`pvfs-host://<pin>/path`,
/// D75), not host-implicit. Matching only the bare `file://` prefix would make
/// this report zero on exactly the fleet shape where the leak bites hardest —
/// which is the same mistake D81 had to fix in the scan's removal loop.
#[test]
fn a_pin_qualified_location_counts_too() {
    let data = tempfile::tempdir().unwrap();
    let lib = tempfile::tempdir().unwrap();
    write_file(&lib.path().join("a.mkv"), b"aaa");

    // give this box a transport pin, so its own locations are pin-qualified
    let pin = "a".repeat(64);
    fs::create_dir_all(data.path().join("nettls")).unwrap();
    fs::write(data.path().join("nettls/pin"), &pin).unwrap();

    let (mut engine, _mn) = Engine::init(data.path()).unwrap();
    let root = engine.identity.root_node_id.clone();
    let f = engine.add_node(&root, folder("library")).unwrap();
    let canon = fs::canonicalize(lib.path()).unwrap();
    let src = pvfs_core::storage::path_to_uri(&canon).unwrap();
    engine
        .bind_folder(
            &f,
            BindSpec {
                source_uri: src.clone(),
                recursive: true,
                auto_index: true,
                extensions: String::new(),
                hash_policy: HashPolicy::Never,
            },
        )
        .unwrap();
    engine.scan(Some(&f)).unwrap();

    // record the SAME file pin-qualified, as a replica would
    let id = engine
        .children(&f)
        .unwrap()
        .into_iter()
        .find(|c| c.node.label == "a.mkv")
        .expect("scanned")
        .node
        .id;
    let host = pvfs_core::storage::host_uri(&pin, &canon.join("a.mkv")).unwrap();
    engine.add_location(&id, &host).unwrap();

    let found = engine.locations_under_root(&src).unwrap();
    assert!(
        found.iter().any(|(_, u)| u == &host),
        "the pin-qualified location must be counted: {found:?}"
    );
    assert_eq!(found.len(), 2, "both forms of the same root, counted once each");
    engine.close().unwrap();
}
