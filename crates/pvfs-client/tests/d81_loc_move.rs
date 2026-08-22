//! D81 4e — `pvfs loc move`: moving bytes between roots, through PVFS.
//!
//! Chris: "maybe we need a way to move files between swarm location with a
//! cli-type command (and later a gui file explorer in PVOS)".
//!
//! The value is not convenience. A hand-move leaves the catalog to INFER what
//! happened from a filesystem diff, and a diff cannot tell "moved" from
//! "deleted" from "the volume is unavailable". Told directly, there is nothing
//! to infer — and the ordering can be guaranteed instead of hoped for.

use pvfs_core::{BindSpec, Engine, HashPolicy, NodeSpec, TYPE_FILE, TYPE_FOLDER};

fn spec(dir: &std::path::Path) -> BindSpec {
    BindSpec {
        source_uri: format!("file://{}", dir.display()),
        recursive: true,
        auto_index: true,
        extensions: String::new(),
        hash_policy: HashPolicy::Lazy,
    }
}

struct Rig {
    _tmp: tempfile::TempDir,
    engine: Engine,
    media: String,
    warm: std::path::PathBuf,
    cold: std::path::PathBuf,
}

fn rig() -> Rig {
    let tmp = tempfile::tempdir().unwrap();
    let warm = tmp.path().join("Data");
    let cold = tmp.path().join("Data_ext");
    std::fs::create_dir_all(warm.join("Movies/Old Title (1997)")).unwrap();
    std::fs::create_dir_all(&cold).unwrap();
    std::fs::write(
        warm.join("Movies/Old Title (1997)/old.mkv"),
        vec![7u8; 5000],
    )
    .unwrap();
    // The cold volume is mounted and real (4d) — an empty unmarked root is
    // refused, which is exactly what an absent mount looks like.
    pvfs_core::sync::write_root_marker(&cold, "test-forest").unwrap();

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
    engine.bind_folder(&media, spec(&cold)).unwrap();
    engine.scan(Some(&media)).unwrap();
    Rig { _tmp: tmp, engine, media, warm, cold }
}

fn the_file(r: &Rig) -> String {
    r.engine
        .walk(&r.media)
        .unwrap()
        .into_iter()
        .find(|e| e.node.node_type == TYPE_FILE)
        .unwrap()
        .node
        .id
}

#[test]
fn a_dry_run_plans_the_move_and_moves_nothing() {
    let mut r = rig();
    let id = the_file(&r);
    let cold = r.cold.clone();
    let rep = pvfs_client::relocate::move_to_root(&mut r.engine, &id, &cold, true).unwrap();

    assert_eq!(rep.moved, 1);
    assert!(
        rep.planned.iter().any(|p| p.contains("WOULD MOVE")),
        "{:?}",
        rep.planned
    );
    assert!(
        r.warm.join("Movies/Old Title (1997)/old.mkv").exists(),
        "a dry run touches nothing"
    );
    assert!(!r.cold.join("Movies/Old Title (1997)/old.mkv").exists());
    r.engine.close().unwrap();
}

/// The whole point: bytes move, the catalog follows, and the old location goes.
#[test]
fn the_bytes_move_and_the_catalog_follows() {
    let mut r = rig();
    let id = the_file(&r);
    let cold = r.cold.clone();
    let rep = pvfs_client::relocate::move_to_root(&mut r.engine, &id, &cold, false).unwrap();
    assert_eq!(rep.moved, 1, "failed: {:?}", rep.failed);

    assert!(
        r.cold.join("Movies/Old Title (1997)/old.mkv").exists(),
        "the bytes are on the cold volume"
    );
    assert!(
        !r.warm.join("Movies/Old Title (1997)/old.mkv").exists(),
        "and gone from the warm one"
    );

    let locs = r.engine.locations(&id).unwrap();
    assert_eq!(locs.len(), 1, "exactly one live location: {locs:?}");
    assert!(
        locs[0].contains("Data_ext"),
        "and it is the new one — no stale claim left behind: {locs:?}"
    );
    r.engine.close().unwrap();
}

/// Moving it again is a no-op, not an error and not a second copy.
#[test]
fn moving_to_where_it_already_is_does_nothing() {
    let mut r = rig();
    let id = the_file(&r);
    let cold = r.cold.clone();
    pvfs_client::relocate::move_to_root(&mut r.engine, &id, &cold, false).unwrap();
    let again = pvfs_client::relocate::move_to_root(&mut r.engine, &id, &cold, false).unwrap();

    assert_eq!(again.moved, 0);
    assert_eq!(again.skipped, 1, "already there is not work");
    assert!(again.failed.is_empty());
    assert_eq!(r.engine.locations(&id).unwrap().len(), 1);
    r.engine.close().unwrap();
}

/// A destination nothing is bound to would put bytes where no scan will ever
/// look, which is indistinguishable from losing them.
#[test]
fn a_destination_that_is_not_a_root_is_refused() {
    let mut r = rig();
    let id = the_file(&r);
    let nowhere = r._tmp.path().join("somewhere-else");
    std::fs::create_dir_all(&nowhere).unwrap();

    let err = pvfs_client::relocate::move_to_root(&mut r.engine, &id, &nowhere, false)
        .unwrap_err()
        .to_string();
    assert!(err.contains("not a root"), "{err}");
    assert!(
        err.contains("Data"),
        "and it must LIST the roots, so the answer is in the error: {err}"
    );
    assert!(
        r.warm.join("Movies/Old Title (1997)/old.mkv").exists(),
        "nothing moved"
    );
    r.engine.close().unwrap();
}

/// A whole title moves as one thing — that is the unit anyone actually moves.
#[test]
fn a_folder_moves_every_file_under_it() {
    let mut r = rig();
    let dir = r.warm.join("Movies/Old Title (1997)");
    std::fs::write(dir.join("old.en.srt"), vec![1u8; 300]).unwrap();
    std::fs::write(dir.join("poster.jpg"), vec![2u8; 900]).unwrap();
    r.engine.scan(Some(&r.media)).unwrap();

    let title = r
        .engine
        .walk(&r.media)
        .unwrap()
        .into_iter()
        .find(|e| e.label == "Old Title (1997)")
        .unwrap()
        .node
        .id;
    let cold = r.cold.clone();
    let rep = pvfs_client::relocate::move_to_root(&mut r.engine, &title, &cold, false).unwrap();

    assert_eq!(rep.moved, 3, "film, subtitle and artwork: {:?}", rep.failed);
    for f in ["old.mkv", "old.en.srt", "poster.jpg"] {
        assert!(
            r.cold.join("Movies/Old Title (1997)").join(f).exists(),
            "{f} should have moved with the title"
        );
    }
    r.engine.close().unwrap();
}
