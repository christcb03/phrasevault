//! D71 W4 — a replica enrolls its own directory.
//!
//! `bind` has no write-through wire op (unlike `add`/`loc add`/`unlink`), so a
//! replica could not create a binding at all — which meant the ingest box, the
//! one machine that must scan its library, was the one machine that could not
//! say it had one. W1 attributed bindings to a machine; only the owner could
//! make one; and an owner's binding is the owner's, so the ingest box would
//! never watch it.
//!
//! A replica's binding is therefore per-machine deployment state in
//! `bindings.local`, beside `placement` — the rule this codebase already
//! states for this class of fact. Chris chose this over a `PROTO_VERSION`
//! bump, which would have made every binding change a fleet-wide upgrade.

use std::fs;
use std::path::Path;

use pvfs_core::{BindSpec, Engine, HashPolicy};

fn spec(dir: &Path) -> BindSpec {
    BindSpec {
        source_uri: pvfs_core::storage::path_to_uri(&fs::canonicalize(dir).unwrap()).unwrap(),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::OnAdd,
    }
}

/// Stand up an owner, then a replica of it on this machine.
fn owner_and_replica() -> (tempfile::TempDir, tempfile::TempDir, String) {
    let owner_dir = tempfile::tempdir().unwrap();
    let (mut owner, _mn) = Engine::init(owner_dir.path()).unwrap();
    let root = owner.identity.root_node_id.clone();
    let folder = owner
        .add_node(
            &root,
            pvfs_core::NodeSpec {
                node_type: pvfs_core::TYPE_FOLDER.into(),
                label: "library".into(),
                payload: Vec::new(),
                is_temp: false,
                creation_nonce: None,
            },
        )
        .unwrap();
    owner.close().unwrap();

    // A replica is the owner's state plus the replica marker — enough for the
    // engine to take its read-only path, which is what this test is about.
    let rep_dir = tempfile::tempdir().unwrap();
    for f in ["index.db", "log.db", "device.key"] {
        let src = owner_dir.path().join(f);
        if src.exists() {
            fs::copy(&src, rep_dir.path().join(f)).unwrap();
        }
    }
    fs::write(pvfs_core::replica::marker_path(rep_dir.path()), b"1").unwrap();
    (owner_dir, rep_dir, folder)
}

#[test]
fn a_replica_can_bind_its_own_directory() {
    let (_owner, rep, folder) = owner_and_replica();
    let src = tempfile::tempdir().unwrap();

    let mut e = Engine::open(rep.path()).unwrap();
    assert!(e.is_replica(), "the fixture must actually be a replica");
    e.bind_folder(&folder, spec(src.path()))
        .expect("a replica must be able to enroll a directory it holds");
    e.close().unwrap();

    // It is deployment state, not a log event.
    assert!(
        rep.path().join("bindings.local").exists(),
        "the enrollment belongs in the local deployment file"
    );

    let e = Engine::open(rep.path()).unwrap();
    let local = e.local_bindings().unwrap();
    assert_eq!(local.len(), 1, "the replica scans its own binding");
    assert_eq!(local[0].folder_id, folder);
    assert!(
        e.is_local_binding(&local[0]),
        "this machine's own binding must read as local"
    );
    assert!(e.binding_for(&folder).unwrap().is_some());
    e.close().unwrap();
}

/// A replica's scan must be ROUTED. Asked to scan with no route it says so
/// once, naming the fix, instead of walking the library and quarantining every
/// file with the same reason — the cause is the configuration, not the files.
///
/// The routed path itself is proven end to end against a live daemon on the
/// fleet, not here: it needs an owner to talk to.
#[test]
fn a_replica_scan_without_a_route_says_so_once() {
    let (_owner, rep, folder) = owner_and_replica();
    let src = tempfile::tempdir().unwrap();
    fs::write(src.path().join("ep.mkv"), b"bytes").unwrap();

    let mut e = Engine::open(rep.path()).unwrap();
    e.bind_folder(&folder, spec(src.path())).unwrap();
    let err = e.scan(None).unwrap_err().to_string();
    e.close().unwrap();

    assert!(
        err.contains("routed to the owner"),
        "expected the one clear configuration error, got: {err}"
    );
}

#[test]
fn unbinding_a_local_binding_removes_it() {
    let (_owner, rep, folder) = owner_and_replica();
    let src = tempfile::tempdir().unwrap();

    let mut e = Engine::open(rep.path()).unwrap();
    e.bind_folder(&folder, spec(src.path())).unwrap();
    e.unbind_folder(&folder, None).unwrap();
    assert!(e.binding_for(&folder).unwrap().is_none());
    assert!(e.local_bindings().unwrap().is_empty());
    e.close().unwrap();
}

/// The local file survives a projection rebuild — it is not derived from the
/// log, so a rebuild must not silently un-enrol this machine's library.
#[test]
fn a_local_binding_survives_a_projection_rebuild() {
    let (_owner, rep, folder) = owner_and_replica();
    let src = tempfile::tempdir().unwrap();

    let mut e = Engine::open(rep.path()).unwrap();
    e.bind_folder(&folder, spec(src.path())).unwrap();
    e.close().unwrap();

    fs::remove_file(rep.path().join("index.db")).unwrap();
    let e = Engine::open(rep.path()).unwrap();
    assert_eq!(
        e.local_bindings().unwrap().len(),
        1,
        "a rebuild must not drop this machine's enrollment"
    );
    e.close().unwrap();
}
